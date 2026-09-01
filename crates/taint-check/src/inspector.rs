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
//!
//! # Crate-wide mode (`fn_defs`) — see [`crate::crate_scan`]
//!
//! Every function here threads a [`TaintContext`] instead of bare
//! sinks/sanitizers maps. [`TaintContext::fn_defs`] is empty for the
//! macro/single-mod CLI path (this module's own [`inspect_mod`]) — with
//! nothing to resolve, [`classify_call`] always falls through to the
//! conservative default above, so single-mod behavior is unchanged byte
//! for byte from before this was added. [`crate::crate_scan`] instead
//! builds a [`TaintContext`] with every function found crate-wide, which
//! upgrades [`classify_call`] from a blanket assumption to a real,
//! depth-bounded interprocedural summary — see that module's docs for what
//! "cross-binding" precisely means here and its own scope limits.

use std::collections::{HashMap, HashSet};

use path_match::path_last_segment;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Block, Expr, ExprCall, FnArg, Item, ItemFn, ItemMod, Pat, Stmt};

use crate::parser;

/// A depth-bounded interprocedural summary in [`classify_call`] stops
/// recursing past this many nested calls, to guarantee termination even if
/// [`TaintContext::fn_defs`] contains a long call chain — a cycle is caught
/// earlier, by the `visiting` guard, but a long *acyclic* chain still needs
/// a hard stop.
const MAX_INTERPROCEDURAL_DEPTH: usize = 8;

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
    /// The span of the specific tainted argument expression at the call
    /// site (a sub-span of `span`) — `taint-refactor` needs this to target
    /// exactly the value that needs sanitizing, not the whole call.
    pub arg_span: proc_macro2::Span,
}

pub(crate) struct SinkInfo {
    pub(crate) label: String,
    pub(crate) policy: String,
}

/// Everything a taint walk needs to resolve a call: is it a sink, a
/// sanitizer, or (crate-wide mode only) a function whose own body can be
/// summarized. See this module's own doc comment for how an empty
/// `fn_defs` keeps single-mod behavior unchanged.
pub(crate) struct TaintContext<'a> {
    pub(crate) sinks: &'a HashMap<String, SinkInfo>,
    pub(crate) sanitizers: &'a HashSet<String>,
    pub(crate) fn_defs: &'a HashMap<String, &'a ItemFn>,
}

/// Parse a single `fn`'s `#[taint_sink(...)]`/`#[taint_sanitizer]`
/// attributes (if any) into `sinks`/`sanitizers`, validating a sink's label
/// against `declared_labels`. Shared by [`register_sinks_and_sanitizers`]
/// (single-mod) and [`crate::crate_scan`] (crate-wide) so both register a
/// function's own attributes identically.
///
/// # Errors
///
/// Returns `Err` if a `#[taint_sink(...)]` attribute fails to parse, or
/// names a label not present in `declared_labels`.
pub(crate) fn register_fn_sink_or_sanitizer(
    f: &ItemFn,
    declared_labels: &[String],
    sinks: &mut HashMap<String, SinkInfo>,
    sanitizers: &mut HashSet<String>,
) -> syn::Result<()> {
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
    Ok(())
}

/// Register every `#[taint_sink(...)]`/`#[taint_sanitizer]` found among
/// `items`' direct `fn` children (single-mod scope — see
/// [`crate::crate_scan`] for the crate-wide equivalent).
///
/// # Errors
///
/// See [`register_fn_sink_or_sanitizer`].
pub(crate) fn register_sinks_and_sanitizers(
    items: &[Item],
    declared_labels: &[String],
    sinks: &mut HashMap<String, SinkInfo>,
    sanitizers: &mut HashSet<String>,
) -> syn::Result<()> {
    for item in items {
        if let Item::Fn(f) = item {
            register_fn_sink_or_sanitizer(f, declared_labels, sinks, sanitizers)?;
        }
    }
    Ok(())
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
    register_sinks_and_sanitizers(items, declared_labels, &mut sinks, &mut sanitizers)?;

    let empty_fn_defs = HashMap::new();
    let ctx = TaintContext {
        sinks: &sinks,
        sanitizers: &sanitizers,
        fn_defs: &empty_fn_defs,
    };

    let mut violations = Vec::new();
    for item in items {
        let Item::Fn(f) = item else { continue };
        violations.extend(inspect_fn_with_ctx(f, &ctx)?);
    }
    Ok(violations)
}

/// Run the taint-propagation pass over a single function, against a
/// pre-built [`TaintContext`]. `pub(crate)` — [`crate::crate_scan`] calls
/// this directly with a crate-wide context; [`inspect_mod`] is the public,
/// single-mod-scoped entry point everything else uses.
///
/// # Errors
///
/// Returns `Err` if a `#[sensitive(...)]` attribute fails to parse.
pub(crate) fn inspect_fn_with_ctx(f: &ItemFn, ctx: &TaintContext) -> syn::Result<Vec<Violation>> {
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
    let mut visiting = HashSet::new();
    walk_block(&f.block, &mut tainted, ctx, &mut visiting, &mut violations);
    Ok(violations)
}

pub(crate) fn pat_ident_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => pat_ident_name(&pt.pat),
        _ => None,
    }
}

fn walk_block(
    block: &Block,
    tainted: &mut HashMap<String, String>,
    ctx: &TaintContext,
    visiting: &mut HashSet<String>,
    violations: &mut Vec<Violation>,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Local(local) => {
                let Some(init) = &local.init else { continue };
                violations.extend(find_sink_violations(
                    &init.expr,
                    tainted,
                    ctx.sinks,
                    ctx.sanitizers,
                ));

                let Some(name) = pat_ident_name(&local.pat) else {
                    continue;
                };
                match classify_init(&init.expr, tainted, ctx, visiting, violations) {
                    Some(label) => {
                        tainted.insert(name, label);
                    }
                    None => {
                        tainted.remove(&name);
                    }
                }
            }
            Stmt::Expr(expr, _) => {
                violations.extend(find_sink_violations(
                    expr,
                    tainted,
                    ctx.sinks,
                    ctx.sanitizers,
                ));
            }
            Stmt::Macro(_) | Stmt::Item(_) => {}
        }
    }
}

/// Does `expr` (the initializer of a `let`) carry taint forward, and under
/// which label? See this module's doc comment for exactly which shapes
/// propagate. Any violation found *inside* an interprocedural summary
/// (see [`classify_call`]) is appended to `violations`.
fn classify_init(
    expr: &Expr,
    tainted: &HashMap<String, String>,
    ctx: &TaintContext,
    visiting: &mut HashSet<String>,
    violations: &mut Vec<Violation>,
) -> Option<String> {
    match expr {
        Expr::Path(_) => find_tainted_label(expr, tainted),
        Expr::MethodCall(mc) => find_tainted_label(&mc.receiver, tainted),
        Expr::Reference(r) => classify_init(&r.expr, tainted, ctx, visiting, violations),
        Expr::Paren(p) => classify_init(&p.expr, tainted, ctx, visiting, violations),
        Expr::Call(call) => classify_call(call, tainted, ctx, visiting, violations),
        _ => None,
    }
}

/// Classify a function call as a `let` initializer: sanitized (clears
/// taint), interprocedurally resolved (precise — see below), or
/// unresolved (conservative default, same as before crate-wide mode
/// existed).
///
/// "Cross-binding" tracking (`crate::crate_scan`) means specifically this:
/// when the callee is resolvable in [`TaintContext::fn_defs`], this
/// recursively re-walks *its* body with a fresh `tainted` map seeded only
/// from the parameter position that received the tainted argument
/// (bounded by [`MAX_INTERPROCEDURAL_DEPTH`] and a `visiting` cycle guard),
/// collecting any violation found inside it and checking whether its tail
/// expression (the final, no-semicolon expression only — an explicit early
/// `return` is a documented, unhandled shape) still carries the label. A
/// callee that can't be resolved this way (external crate, std lib,
/// dynamic dispatch, cycle, or depth limit) falls back to the same
/// conservative default `classify_init` always used — this can only ever
/// *add* precision, never remove the existing safety net.
fn classify_call(
    call: &ExprCall,
    tainted: &HashMap<String, String>,
    ctx: &TaintContext,
    visiting: &mut HashSet<String>,
    violations: &mut Vec<Violation>,
) -> Option<String> {
    let callee_name = call_ident_name(call)?;
    if ctx.sanitizers.contains(&callee_name) {
        return None;
    }

    let (arg_index, label) = call
        .args
        .iter()
        .enumerate()
        .find_map(|(i, arg)| find_tainted_label(arg, tainted).map(|l| (i, l)))?;

    if visiting.len() < MAX_INTERPROCEDURAL_DEPTH && !visiting.contains(&callee_name) {
        if let Some(&callee_fn) = ctx.fn_defs.get(&callee_name) {
            visiting.insert(callee_name.clone());
            let propagates = summarize_fn(callee_fn, arg_index, &label, ctx, visiting, violations);
            visiting.remove(&callee_name);
            return if propagates { Some(label) } else { None };
        }
    }

    // Unresolved callee, a cycle, or the depth limit: conservative default.
    Some(label)
}

/// Re-walk `f`'s body with a fresh `tainted` map seeded from the parameter
/// at `arg_index` (the position that received the tainted argument at the
/// call site), appending any violation found inside `f` to `violations`,
/// and returning whether `f`'s tail expression still carries `label`.
fn summarize_fn(
    f: &ItemFn,
    arg_index: usize,
    label: &str,
    ctx: &TaintContext,
    visiting: &mut HashSet<String>,
    violations: &mut Vec<Violation>,
) -> bool {
    let Some(FnArg::Typed(pt)) = f.sig.inputs.iter().nth(arg_index) else {
        return false;
    };
    let Some(param_name) = pat_ident_name(&pt.pat) else {
        return false;
    };

    let mut callee_tainted = HashMap::new();
    callee_tainted.insert(param_name, label.to_string());

    walk_block(&f.block, &mut callee_tainted, ctx, visiting, violations);

    tail_expr_carries_label(&f.block, &callee_tainted, label, ctx, visiting, violations)
}

/// `true` if `block`'s tail expression (its final statement, with no
/// trailing semicolon) still carries `label`, per the exact same
/// sanitizer-aware, interprocedurally-capable rules [`classify_init`] uses
/// for a `let` initializer — "does this function's return value carry
/// taint forward" is the same question as "does this let-binding carry
/// taint forward", just asked about the implicit return slot instead of a
/// named one. An explicit early `return expr;` is not tracked — see
/// [`classify_call`]'s doc comment.
fn tail_expr_carries_label(
    block: &Block,
    tainted: &HashMap<String, String>,
    label: &str,
    ctx: &TaintContext,
    visiting: &mut HashSet<String>,
    violations: &mut Vec<Violation>,
) -> bool {
    match block.stmts.last() {
        Some(Stmt::Expr(expr, None)) => {
            classify_init(expr, tainted, ctx, visiting, violations).as_deref() == Some(label)
        }
        _ => false,
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

/// `true` if `expr` is (optionally through `&`/`(...)`) a direct call to a
/// registered sanitizer — `redact(password)`, `&redact(password)`,
/// `(redact(password))`. Deliberately narrow and purely structural (no
/// interprocedural resolution): it exists only to stop
/// [`SinkCallFinder`]'s otherwise-correct "any tainted path anywhere in
/// this argument" conservatism from misfiring on the one shape that's
/// unambiguously already sanitized inline. It does not, and should not,
/// replace that broader check for anything else — an argument built via
/// `format!`, string concatenation, or any other shape still needs the
/// broad, conservative `find_tainted_label` scan below it.
fn is_directly_sanitized(expr: &Expr, sanitizers: &HashSet<String>) -> bool {
    match expr {
        Expr::Reference(r) => is_directly_sanitized(&r.expr, sanitizers),
        Expr::Paren(p) => is_directly_sanitized(&p.expr, sanitizers),
        Expr::Call(call) => call_ident_name(call).is_some_and(|name| sanitizers.contains(&name)),
        _ => false,
    }
}

struct SinkCallFinder<'a> {
    tainted: &'a HashMap<String, String>,
    sinks: &'a HashMap<String, SinkInfo>,
    sanitizers: &'a HashSet<String>,
    violations: Vec<Violation>,
}

impl<'ast> Visit<'ast> for SinkCallFinder<'_> {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Some(name) = call_ident_name(call) {
            if let Some(sink) = self.sinks.get(&name) {
                for arg in &call.args {
                    if is_directly_sanitized(arg, self.sanitizers) {
                        continue;
                    }
                    if let Some(label) = find_tainted_label(arg, self.tainted) {
                        if label == sink.label {
                            self.violations.push(Violation {
                                label,
                                sink_fn: name.clone(),
                                policy: sink.policy.clone(),
                                span: call.span(),
                                arg_span: arg.span(),
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
/// carries that sink's label, per the current `tainted` snapshot — except
/// an argument that is itself a direct, inline sanitizer call (see
/// [`is_directly_sanitized`]).
fn find_sink_violations(
    expr: &Expr,
    tainted: &HashMap<String, String>,
    sinks: &HashMap<String, SinkInfo>,
    sanitizers: &HashSet<String>,
) -> Vec<Violation> {
    let mut finder = SinkCallFinder {
        tainted,
        sinks,
        sanitizers,
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
    fn sanitizer_clears_taint_when_called_directly_inline_at_the_sink_call() {
        // Regression test: `log_debug(redact(password))` — no intermediate
        // `let` — used to still be flagged, because `find_sink_violations`
        // checked a sink's arguments via the broad, sanitizer-unaware
        // "any tainted path anywhere in this expression" scan
        // (`find_tainted_label`), unlike `classify_init`'s sanitizer-aware
        // handling for `let`-bound values. `is_directly_sanitized` closes
        // that gap without weakening the broad scan for anything else.
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                log_debug(redact(password));
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
    fn a_sink_call_referencing_a_sanitizer_by_name_without_calling_it_is_still_a_violation() {
        // `is_directly_sanitized` must not fire on anything looser than an
        // actual call — passing the tainted value straight through
        // (`log_debug(password)`) is still a real violation even though a
        // sanitizer named `redact` exists elsewhere in scope.
        let violations = inspect(
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                log_debug(password);
            }
            #[taint_sanitizer]
            fn redact(s: &str) -> String { "[REDACTED]".to_string() }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
            &["password"],
        );
        assert_eq!(violations.len(), 1);
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

    fn parse_fn(src: &str) -> ItemFn {
        syn::parse_str(src).unwrap()
    }

    #[test]
    fn interprocedural_summary_detects_a_sink_reached_inside_a_resolved_callee() {
        let wrapper = parse_fn(
            r"fn wrapper(p: &str) {
                log_debug(p);
            }",
        );
        let sink = parse_fn(r"fn log_debug(msg: &str) {}");
        let mut fn_defs: HashMap<String, &ItemFn> = HashMap::new();
        fn_defs.insert("wrapper".to_string(), &wrapper);
        fn_defs.insert("log_debug".to_string(), &sink);

        let mut sinks = HashMap::new();
        sinks.insert(
            "log_debug".to_string(),
            SinkInfo {
                label: "password".to_string(),
                policy: "no_sensitive".to_string(),
            },
        );
        let sanitizers = HashSet::new();
        let ctx = TaintContext {
            sinks: &sinks,
            sanitizers: &sanitizers,
            fn_defs: &fn_defs,
        };

        let caller = parse_fn(
            r"fn handle_login(#[sensitive(password)] password: &str) {
                let x = wrapper(password);
            }",
        );
        let violations = inspect_fn_with_ctx(&caller, &ctx).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].sink_fn, "log_debug");
    }

    #[test]
    fn interprocedural_summary_detects_taint_surviving_into_the_return_value() {
        let identity = parse_fn(r"fn identity(p: &str) -> &str { p }");
        let mut fn_defs: HashMap<String, &ItemFn> = HashMap::new();
        fn_defs.insert("identity".to_string(), &identity);

        let mut sinks = HashMap::new();
        sinks.insert(
            "log_debug".to_string(),
            SinkInfo {
                label: "password".to_string(),
                policy: "no_sensitive".to_string(),
            },
        );
        let sanitizers = HashSet::new();
        let ctx = TaintContext {
            sinks: &sinks,
            sanitizers: &sanitizers,
            fn_defs: &fn_defs,
        };

        let caller = parse_fn(
            r"fn handle_login(#[sensitive(password)] password: &str) {
                let copy = identity(password);
                log_debug(copy);
            }",
        );
        let violations = inspect_fn_with_ctx(&caller, &ctx).unwrap();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn interprocedural_summary_respects_a_sanitizer_inside_the_callee() {
        let wrapper = parse_fn(
            r"fn wrapper(p: &str) -> String {
                redact(p)
            }",
        );
        let mut fn_defs: HashMap<String, &ItemFn> = HashMap::new();
        fn_defs.insert("wrapper".to_string(), &wrapper);

        let mut sinks = HashMap::new();
        sinks.insert(
            "log_debug".to_string(),
            SinkInfo {
                label: "password".to_string(),
                policy: "no_sensitive".to_string(),
            },
        );
        let mut sanitizers = HashSet::new();
        sanitizers.insert("redact".to_string());
        let ctx = TaintContext {
            sinks: &sinks,
            sanitizers: &sanitizers,
            fn_defs: &fn_defs,
        };

        let caller = parse_fn(
            r"fn handle_login(#[sensitive(password)] password: &str) {
                let clean = wrapper(password);
                log_debug(&clean);
            }",
        );
        let violations = inspect_fn_with_ctx(&caller, &ctx).unwrap();
        assert!(violations.is_empty());
    }

    #[test]
    fn interprocedural_summary_does_not_infinitely_recurse_on_a_cycle() {
        let a = parse_fn(r"fn a(p: &str) { b(p); }");
        let b = parse_fn(r"fn b(p: &str) { a(p); }");
        let mut fn_defs: HashMap<String, &ItemFn> = HashMap::new();
        fn_defs.insert("a".to_string(), &a);
        fn_defs.insert("b".to_string(), &b);

        let sinks = HashMap::new();
        let sanitizers = HashSet::new();
        let ctx = TaintContext {
            sinks: &sinks,
            sanitizers: &sanitizers,
            fn_defs: &fn_defs,
        };

        let caller = parse_fn(
            r"fn handle_login(#[sensitive(password)] password: &str) {
                let x = a(password);
            }",
        );
        // No sinks registered at all — this test only asserts termination
        // (a cycle must not hang or overflow the stack), not any specific
        // violation outcome.
        let violations = inspect_fn_with_ctx(&caller, &ctx).unwrap();
        assert!(violations.is_empty());
    }
}
