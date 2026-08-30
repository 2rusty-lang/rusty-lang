//! `inspect_mod` — the shallow AST-level taint-propagation pass described in
//! `rfcs/0003-taint-check.md`, run over a single `mod` item's contents.
//!
//! # Why not a single `syn::visit::Visit` walker (unlike `capability-attr`)
//!
//! `capability-attr`'s `BodyInspector` accumulates a single "maximum
//! observed level" per category — order doesn't matter, so a plain
//! `syn::visit::Visit` walk is enough. Taint propagation is inherently
//! order-dependent (a variable is only tainted *after* the `let` that
//! taints it, and only until a sanitizer clears it), so this module instead
//! walks each function body's statements in source order by hand
//! ([`walk_block`]), threading a `tainted: HashMap<binding, label>` through
//! them, and uses small scoped [`syn::visit::Visit`] finders
//! ([`find_tainted_label`], [`find_sink_violations`]) only for the
//! order-independent sub-question "does this expression reference a
//! tainted binding / call a sink function", evaluated against a snapshot of
//! `tainted` at that point in the statement sequence.
//!
//! # Two passes over the `mod`
//!
//! 1. [`inspect_mod`] first scans every top-level `fn` in the mod for
//!    `#[taint_sink(label, policy = "...")]` and `#[taint_sanitizer]`, so a
//!    sink or sanitizer can be declared anywhere in the mod regardless of
//!    item order (matching the guide-level example, where `log_debug` is
//!    declared after `handle_login` calls it).
//! 2. It then walks each `fn`'s body, seeding `tainted` from that
//!    function's own `#[sensitive(label)]` parameters.
//!
//! # Shallow-tracking scope, stated plainly (see also `rfcs/0003`'s
//! Drawbacks and `docs/adr/ADR-0003`)
//!
//! Taint propagates through three shapes: direct reassignment
//! (`let x = y;`), a method call on a tainted receiver (`let x =
//! y.method();` — the guide example's own shape), and — conservatively —
//! any other function call with a tainted argument (`let x = some_fn(y);`
//! taints `x` too, under the same label as `y`).
//!
//! This crate picked *conservative* over *permissive* for the plain-call
//! case, one of `rfcs/0003-taint-check.md`'s own explicitly unresolved
//! questions, because the permissive alternative (arbitrary calls never
//! propagate) makes `#[taint_sanitizer]` meaningless: if nothing
//! propagates through a call by default, marking one function as "clears
//! the taint" changes nothing observable. Conservative propagation is what
//! gives `#[taint_sanitizer]` a real job — it is the *only* way to stop a
//! tainted value from continuing to taint everything it flows through.
//!
//! This still does **not** propagate through `format!`/string
//! concatenation (no call site to attach a taint check to), or across
//! closures, threads, or module boundaries outside this `mod`. This is a
//! deliberate, documented reduction, not an oversight — see the
//! crate-level docs' honest scope statement.

use std::collections::{HashMap, HashSet};

use path_match::path_last_segment;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Expr, ExprCall, FnArg, Item, ItemFn, ItemMod, Pat, Stmt};

use crate::parser;

/// One taint violation: a value carrying `label` reached a
/// `#[taint_sink(label, policy)]` call without passing through a
/// `#[taint_sanitizer]` first.
#[derive(Debug, Clone)]
pub struct Violation {
    /// The taint label that reached the sink.
    pub label: String,
    /// The sink function's name.
    pub sink_fn: String,
    /// The sink's declared policy string.
    pub policy: String,
    /// The span of the offending call, for `compile_error!` spanning (the
    /// macro path) or `line:column` rendering (the CLI path — see
    /// [`crate::error`]).
    pub span: proc_macro2::Span,
}

struct SinkInfo {
    label: String,
    policy: String,
}

/// Run the taint-propagation pass over `item_mod`'s contents.
///
/// `declared_labels` are the labels named in the enclosing
/// `#[taint_check(labels = [...])]` — a `#[taint_sink]` naming a label
/// outside this list is itself a parse error (a typo'd or undeclared
/// label), returned as `Err` rather than silently ignored.
///
/// # Errors
///
/// Returns `Err` if a `#[sensitive(...)]` / `#[taint_sink(...)]` attribute
/// fails to parse, or if a `#[taint_sink]` names a label not present in
/// `declared_labels`.
pub fn inspect_mod(item_mod: &ItemMod, declared_labels: &[String]) -> syn::Result<Vec<Violation>> {
    let Some((_, items)) = &item_mod.content else {
        return Ok(Vec::new());
    };

    let mut sinks: HashMap<String, SinkInfo> = HashMap::new();
    let mut sanitizers: HashSet<String> = HashSet::new();

    for item in items {
        let Item::Fn(f) = item else { continue };
        for attr in &f.attrs {
            if parser::is_taint_sink(attr) {
                let sink = parser::parse_taint_sink_attr(attr)?;
                if !declared_labels.iter().any(|l| l == &sink.label) {
                    return Err(syn::Error::new_spanned(
                        attr,
                        format!(
                            "#[taint_sink] declares label `{}`, which is not one of this scope's \
                             #[taint_check(labels = [...])]",
                            sink.label
                        ),
                    ));
                }
                sinks.insert(
                    f.sig.ident.to_string(),
                    SinkInfo {
                        label: sink.label,
                        policy: sink.policy,
                    },
                );
            }
            if parser::is_taint_sanitizer(attr) {
                sanitizers.insert(f.sig.ident.to_string());
            }
        }
    }

    let mut violations = Vec::new();
    for item in items {
        let Item::Fn(f) = item else { continue };
        violations.extend(inspect_fn(f, &sinks, &sanitizers)?);
    }
    Ok(violations)
}

fn inspect_fn(
    f: &ItemFn,
    sinks: &HashMap<String, SinkInfo>,
    sanitizers: &HashSet<String>,
) -> syn::Result<Vec<Violation>> {
    let mut tainted: HashMap<String, String> = HashMap::new();
    for arg in &f.sig.inputs {
        let FnArg::Typed(pt) = arg else { continue };
        for attr in &pt.attrs {
            if parser::is_sensitive(attr) {
                let label = parser::parse_sensitive_attr(attr)?;
                if let Some(name) = pat_ident_name(&pt.pat) {
                    tainted.insert(name, label);
                }
            }
        }
    }

    let mut violations = Vec::new();
    walk_block(&f.block, &mut tainted, sinks, sanitizers, &mut violations);
    Ok(violations)
}

fn pat_ident_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => pat_ident_name(&pt.pat),
        _ => None,
    }
}

fn walk_block(
    block: &Block,
    tainted: &mut HashMap<String, String>,
    sinks: &HashMap<String, SinkInfo>,
    sanitizers: &HashSet<String>,
    violations: &mut Vec<Violation>,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Local(local) => {
                let Some(init) = &local.init else { continue };
                violations.extend(find_sink_violations(&init.expr, tainted, sinks));

                let Some(name) = pat_ident_name(&local.pat) else {
                    continue;
                };
                match classify_init(&init.expr, tainted, sanitizers) {
                    Some(label) => {
                        tainted.insert(name, label);
                    }
                    None => {
                        tainted.remove(&name);
                    }
                }
            }
            Stmt::Expr(expr, _) => {
                violations.extend(find_sink_violations(expr, tainted, sinks));
            }
            Stmt::Macro(_) | Stmt::Item(_) => {}
        }
    }
}

/// Does `expr` (the initializer of a `let`) carry taint forward, and under
/// which label? See this module's doc comment for exactly which shapes
/// propagate.
fn classify_init(
    expr: &Expr,
    tainted: &HashMap<String, String>,
    sanitizers: &HashSet<String>,
) -> Option<String> {
    match expr {
        Expr::Path(_) => find_tainted_label(expr, tainted),
        Expr::MethodCall(mc) => find_tainted_label(&mc.receiver, tainted),
        Expr::Reference(r) => classify_init(&r.expr, tainted, sanitizers),
        Expr::Paren(p) => classify_init(&p.expr, tainted, sanitizers),
        Expr::Call(call) => {
            let is_sanitizer = call_ident_name(call).is_some_and(|name| sanitizers.contains(&name));
            if is_sanitizer {
                // Explicitly sanitized — the new binding is clean
                // regardless of whether the arguments were tainted.
                None
            } else {
                // Conservative default for any other call: if an argument
                // is tainted, the result is presumed tainted too, under
                // the same label — see this module's doc comment for why
                // this crate picked conservative over permissive.
                call.args
                    .iter()
                    .find_map(|arg| find_tainted_label(arg, tainted))
            }
        }
        _ => None,
    }
}

/// The called function's trailing path segment name — `log_debug`,
/// `self::log_debug`, and `super::log_debug` all resolve to `"log_debug"`,
/// so a sink/sanitizer declared in this mod is recognized by name however
/// its call site chooses to qualify the path (see `path_match`'s crate
/// docs).
fn call_ident_name(call: &ExprCall) -> Option<String> {
    if let Expr::Path(p) = call.func.as_ref() {
        path_last_segment(&p.path)
    } else {
        None
    }
}

struct PathFinder<'a> {
    tainted: &'a HashMap<String, String>,
    found: Option<String>,
}

impl<'ast> Visit<'ast> for PathFinder<'_> {
    fn visit_expr_path(&mut self, expr_path: &'ast syn::ExprPath) {
        if self.found.is_none() {
            if let Some(ident) = expr_path.path.get_ident() {
                if let Some(label) = self.tainted.get(&ident.to_string()) {
                    self.found = Some(label.clone());
                }
            }
        }
        syn::visit::visit_expr_path(self, expr_path);
    }
}

/// Does `expr` reference (anywhere within it) a binding currently in
/// `tainted`? Returns the first matching label found.
fn find_tainted_label(expr: &Expr, tainted: &HashMap<String, String>) -> Option<String> {
    let mut finder = PathFinder {
        tainted,
        found: None,
    };
    finder.visit_expr(expr);
    finder.found
}

struct SinkCallFinder<'a> {
    tainted: &'a HashMap<String, String>,
    sinks: &'a HashMap<String, SinkInfo>,
    violations: Vec<Violation>,
}

impl<'ast> Visit<'ast> for SinkCallFinder<'_> {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Some(name) = call_ident_name(call) {
            if let Some(sink) = self.sinks.get(&name) {
                for arg in &call.args {
                    if let Some(label) = find_tainted_label(arg, self.tainted) {
                        if label == sink.label {
                            self.violations.push(Violation {
                                label,
                                sink_fn: name.clone(),
                                policy: sink.policy.clone(),
                                span: call.span(),
                            });
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// Find every call to a registered sink within `expr` whose argument still
/// carries that sink's label, per the current `tainted` snapshot.
fn find_sink_violations(
    expr: &Expr,
    tainted: &HashMap<String, String>,
    sinks: &HashMap<String, SinkInfo>,
) -> Vec<Violation> {
    let mut finder = SinkCallFinder {
        tainted,
        sinks,
        violations: Vec::new(),
    };
    finder.visit_expr(expr);
    finder.violations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(src: &str, labels: &[&str]) -> Vec<Violation> {
        let module: ItemMod = syn::parse_str(&format!("mod scope {{ {src} }}")).unwrap();
        let labels: Vec<String> = labels.iter().map(ToString::to_string).collect();
        inspect_mod(&module, &labels).unwrap()
    }

    #[test]
    fn direct_flow_to_sink_is_a_violation() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                log_debug(password);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].label, "password");
        assert_eq!(violations[0].sink_fn, "log_debug");
        assert_eq!(violations[0].policy, "no_sensitive");
    }

    #[test]
    fn one_level_indirect_flow_via_method_call_is_a_violation() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let echoed = password.to_string();
                log_debug(&echoed);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].sink_fn, "log_debug");
    }

    #[test]
    fn sanitizer_clears_taint_before_sink() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let clean = redact(password);
                log_debug(&clean);
            }
            #[taint_sanitizer]
            fn redact(s: &str) -> String { "[REDACTED]".to_string() }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn untainted_value_reaching_sink_is_not_a_violation() {
        let violations = inspect(
            r#"
            fn handle_login() {
                log_debug("hello");
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn arbitrary_call_propagates_taint_conservative_default() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let wrapped = wrap(password);
                log_debug(&wrapped);
            }
            fn wrap(s: &str) -> String { s.to_string() }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].sink_fn, "log_debug");
    }

    #[test]
    fn sanitizer_is_the_only_thing_that_stops_conservative_propagation() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let wrapped = wrap(password);
                let clean = redact(wrapped);
                log_debug(&clean);
            }
            fn wrap(s: &str) -> String { s.to_string() }
            #[taint_sanitizer]
            fn redact(s: String) -> String { "[REDACTED]".to_string() }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn sink_label_not_in_declared_labels_is_an_error() {
        let module: ItemMod = syn::parse_str(
            r#"
            mod scope {
                #[taint_sink(password, policy = "no_sensitive")]
                fn log_debug(msg: &str) {}
            }
            "#,
        )
        .unwrap();
        let err = inspect_mod(&module, &["session_token".to_string()]).unwrap_err();
        assert!(err.to_string().contains("password"));
    }

    #[test]
    fn qualified_sink_call_path_is_still_recognized() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                self::log_debug(password);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].sink_fn, "log_debug");
    }

    #[test]
    fn empty_mod_body_produces_no_violations() {
        let module: ItemMod = syn::parse_str("mod scope;").unwrap();
        assert!(inspect_mod(&module, &["password".to_string()])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn direct_reassignment_to_a_bare_path_propagates_taint() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let copy = password;
                log_debug(copy);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn type_annotated_let_still_tracks_taint() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let copy: &str = password;
                log_debug(copy);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn reference_and_paren_wrapped_initializers_still_track_taint() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let r = &password;
                let p = (password);
                log_debug(r);
                log_debug(p);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn a_literal_initializer_does_not_taint_the_new_binding() {
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let x = 42;
                log_debug(x);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn destructuring_pattern_is_not_tracked_a_documented_gap() {
        // `pat_ident_name` only recognizes a bare (optionally type-annotated)
        // identifier — a tuple/destructuring pattern yields no binding name,
        // so neither half of the tuple is tracked. A real scope limitation,
        // not a crash.
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let (a, _b) = (password, password);
                log_debug(a);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn call_through_a_non_path_callee_is_not_recognized_as_a_sink() {
        // `(f)(password)` — the callee is a parenthesized expression, not a
        // bare path, so `call_ident_name` can't resolve it to a registered
        // sink. No crash, no false violation — a documented limitation.
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let f = log_debug;
                (f)(password);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert!(violations.is_empty());
    }
}
