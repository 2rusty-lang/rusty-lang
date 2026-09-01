//! Heuristic taint-attribute generation.
//!
//! For a top-level `mod` with **zero** existing taint-related attributes
//! anywhere inside it, tag `#[sensitive]` params, `#[taint_sink]`/
//! `#[taint_sanitizer]` functions (by [`crate::heuristics`]'s naming
//! keywords), and — only if anything was found — the mod itself with
//! `#[taint_check(labels = [...])]`.
//!
//! **The "never touch curated code" rule is load-bearing here.** A mod
//! that already has even one taint attribute is assumed to be a human's
//! deliberate, reviewed choice about what is and isn't tracked — this pass
//! skips it entirely rather than filling in what it thinks is missing,
//! which could just as easily contradict a decision already made (e.g. a
//! parameter a human decided *not* to tag as sensitive).
//!
//! **Scope: top-level mods only, this pass** — see [`crate::capability_gen`]'s
//! module docs for why nesting is out of scope for the same reason
//! (`source_edit::apply_edits` doesn't support overlapping edits, and a
//! nested mod's edit would overlap its parent's).
//!
//! # The other shape: a file with no inline `mod` at all
//!
//! `taint-check --crate`/`taint-refactor`'s primary layout is multiple
//! files joined by `mod foo;` (not `mod foo { ... }`) — a `mod foo;`-
//! resolved file's own top-level items already *are* that mod's direct
//! children (see `crates/taint-check/src/crate_scan.rs`'s module docs).
//! [`scan_file_scope`] and [`plan_for_fn`] are that layout's counterpart to
//! [`generate`] above: same detection, same "any existing taint attribute
//! anywhere means hands off" rule, but scanning `file.items` directly
//! instead of one mod's children, and returning per-function plans instead
//! of one combined mod-rewrite — [`crate::top_level`] is what turns those
//! into edits, because it has to interleave them with
//! [`crate::capability_gen`]'s edits on the very same functions.

use std::collections::HashSet;

use source_edit::{parse_attribute, print_item, span_byte_range, SourceEdit};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, File, FnArg, Item, ItemFn, ItemMod, Pat};

use crate::heuristics::{looks_like_sanitizer, looks_like_sink, sensitive_label_for_param};

/// One generated set of taint attributes, reported back for `--report`.
///
/// Scoped to a single mod, or — for [`scan_file_scope`] — a whole file
/// standing in for one, so `--report` can show what was added without a
/// human diffing the file.
pub struct TaintSuggestion {
    /// The mod's name.
    pub mod_name: String,
    /// Every taint label detected in this mod, in first-seen order.
    pub labels: Vec<String>,
    /// `(fn_name, param_name, label)` for every generated `#[sensitive]`.
    pub sensitive_params: Vec<(String, String, String)>,
    /// `(fn_name, label)` for every generated `#[taint_sink]`.
    pub sinks: Vec<(String, String)>,
    /// Function names that got a generated `#[taint_sanitizer]`.
    pub sanitizers: Vec<String>,
}

/// `true` if `attr` is any of the four taint-related attributes this crate
/// generates (`#[taint_check(...)]`, `#[sensitive(...)]`,
/// `#[taint_sink(...)]`, `#[taint_sanitizer]`).
fn is_taint_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("taint_check")
        || taint_check::parser::is_sensitive(attr)
        || taint_check::parser::is_taint_sink(attr)
        || taint_check::parser::is_taint_sanitizer(attr)
}

struct HasTaintAttr(bool);

impl<'ast> Visit<'ast> for HasTaintAttr {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if is_taint_attr(attr) {
            self.0 = true;
        }
        syn::visit::visit_attribute(self, attr);
    }
}

fn already_annotated(m: &ItemMod) -> bool {
    let mut checker = HasTaintAttr(false);
    checker.visit_item_mod(m);
    checker.0
}

/// `true` if any top-level `fn` in `file` (or any of its parameters)
/// already carries a taint attribute — the file-scope equivalent of
/// [`already_annotated`]'s "curated, hands off entirely" rule.
fn any_top_level_fn_already_annotated(file: &File) -> bool {
    file.items.iter().any(|item| {
        let Item::Fn(f) = item else { return false };
        f.attrs.iter().any(is_taint_attr)
            || f.sig.inputs.iter().any(|arg| match arg {
                FnArg::Typed(pt) => pt.attrs.iter().any(is_taint_attr),
                FnArg::Receiver(r) => r.attrs.iter().any(is_taint_attr),
            })
    })
}

/// What [`plan_for_fn`] found for one top-level function.
///
/// Detection only, no edit yet — see [`crate::top_level`], which builds
/// the actual edit alongside any `#[capability(...)]` the same function
/// also needs.
pub struct FnTaintPlan {
    /// `(param_name, label)` for every param that should get
    /// `#[sensitive(label)]`.
    pub sensitive_params: Vec<(String, String)>,
    /// The label this function's `#[taint_sink(label, ...)]` should use,
    /// if it looks like a sink (and not a sanitizer — see
    /// [`looks_like_sanitizer`]'s doc comment on why that check comes
    /// first).
    pub sink_label: Option<String>,
    /// Whether this function should get a bare `#[taint_sanitizer]`.
    pub is_sanitizer: bool,
}

/// Just the labels `file`'s top-level functions would contribute, in
/// first-seen order, without the full [`TaintSuggestion`] bookkeeping.
///
/// A label found in one file of a `taint-generate` invocation needs to be
/// visible to sink/sanitizer detection in every other file of that same
/// run — a sink can legitimately live in a different file than the
/// sensitive parameter reaching it, which is the entire point of
/// `taint-check --crate`'s cross-file registry (see
/// `crates/taint-check/src/crate_scan.rs`'s module docs). `crate::cli`
/// uses this to build that shared registry before calling
/// [`crate::top_level::generate`] on each file. Returns an empty `Vec` for
/// an already-annotated file, same as [`scan_file_scope`].
#[must_use]
pub fn find_labels(file: &File) -> Vec<String> {
    if any_top_level_fn_already_annotated(file) {
        return Vec::new();
    }

    let mut labels: Vec<String> = Vec::new();
    let mut seen_labels: HashSet<String> = HashSet::new();
    for item in &file.items {
        let Item::Fn(f) = item else { continue };
        for arg in &f.sig.inputs {
            let FnArg::Typed(pt) = arg else { continue };
            let Some(param_name) = pat_ident_name(&pt.pat) else {
                continue;
            };
            if let Some(label) = sensitive_label_for_param(&param_name) {
                if seen_labels.insert(label.to_string()) {
                    labels.push(label.to_string());
                }
            }
        }
    }
    labels
}

/// Scan `file`'s top-level functions (no inline `mod` wrapper) for
/// heuristically sensitive parameters.
///
/// Reports the same summary [`generate`] would for an inline mod —
/// `mod_name` is supplied by the caller (typically inferred from the
/// file's own name, since there is no `mod` item in this file to name it).
/// Returns `None` if the file already has any taint attribute anywhere in
/// its top-level functions, or if nothing heuristically sensitive was
/// found in this file alone (see [`find_labels`] for the batch-wide,
/// cross-file version sink detection actually needs).
///
/// This does **not** generate the `#[taint_check(labels = [...])]`
/// attribute itself: that belongs on the `mod foo;` declaration in
/// whichever file declares this one as a submodule, a different file this
/// function was never given. The caller is expected to report that as a
/// manual step — see `crate::cli`'s `--report` output.
#[must_use]
pub fn scan_file_scope(file: &File, mod_name: &str) -> Option<TaintSuggestion> {
    if any_top_level_fn_already_annotated(file) {
        return None;
    }

    let labels = find_labels(file);
    if labels.is_empty() {
        return None;
    }

    let mut sensitive_params = Vec::new();
    for item in &file.items {
        let Item::Fn(f) = item else { continue };
        for arg in &f.sig.inputs {
            let FnArg::Typed(pt) = arg else { continue };
            let Some(param_name) = pat_ident_name(&pt.pat) else {
                continue;
            };
            if let Some(label) = sensitive_label_for_param(&param_name) {
                sensitive_params.push((f.sig.ident.to_string(), param_name, label.to_string()));
            }
        }
    }
    let primary_label = labels[0].clone();

    let mut sinks = Vec::new();
    let mut sanitizers = Vec::new();
    for item in &file.items {
        let Item::Fn(f) = item else { continue };
        let fn_name = f.sig.ident.to_string();
        if looks_like_sanitizer(&fn_name) {
            sanitizers.push(fn_name);
        } else if looks_like_sink(&fn_name) {
            sinks.push((fn_name, primary_label.clone()));
        }
    }

    Some(TaintSuggestion {
        mod_name: mod_name.to_string(),
        labels,
        sensitive_params,
        sinks,
        sanitizers,
    })
}

/// Second pass, called once per top-level `fn` after [`scan_file_scope`]
/// returned `Some`.
///
/// Reports what taint attributes (if any) this specific function needs.
/// `primary_label` is [`scan_file_scope`]'s returned
/// `TaintSuggestion::labels[0]`, the same convention [`generate`] uses for
/// naming a sink's policy label.
#[must_use]
pub fn plan_for_fn(f: &ItemFn, primary_label: &str) -> Option<FnTaintPlan> {
    let mut sensitive_params = Vec::new();
    for arg in &f.sig.inputs {
        let FnArg::Typed(pt) = arg else { continue };
        let Some(param_name) = pat_ident_name(&pt.pat) else {
            continue;
        };
        if let Some(label) = sensitive_label_for_param(&param_name) {
            sensitive_params.push((param_name, label.to_string()));
        }
    }

    let fn_name = f.sig.ident.to_string();
    let is_sanitizer = looks_like_sanitizer(&fn_name);
    let sink_label =
        (!is_sanitizer && looks_like_sink(&fn_name)).then(|| primary_label.to_string());

    if sensitive_params.is_empty() && !is_sanitizer && sink_label.is_none() {
        return None;
    }

    Some(FnTaintPlan {
        sensitive_params,
        sink_label,
        is_sanitizer,
    })
}

fn pat_ident_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => pat_ident_name(&pt.pat),
        _ => None,
    }
}

/// Scan `file`'s top-level mods and generate taint attributes for every one
/// that has no taint-related attribute at all yet and contains at least
/// one heuristically sensitive parameter.
#[must_use]
pub fn generate(source: &str, file: &File) -> (Vec<SourceEdit>, Vec<TaintSuggestion>) {
    let mut edits = Vec::new();
    let mut suggestions = Vec::new();

    for item in &file.items {
        let Item::Mod(m) = item else { continue };
        if already_annotated(m) {
            continue;
        }
        let Some((_, children)) = &m.content else {
            continue; // `mod foo;` (external file) — single-file pass only.
        };

        let mut labels: Vec<String> = Vec::new();
        let mut seen_labels: HashSet<String> = HashSet::new();
        let mut sensitive_params = Vec::new();

        for child in children {
            let Item::Fn(f) = child else { continue };
            for arg in &f.sig.inputs {
                let FnArg::Typed(pt) = arg else { continue };
                let Some(param_name) = pat_ident_name(&pt.pat) else {
                    continue;
                };
                if let Some(label) = sensitive_label_for_param(&param_name) {
                    if seen_labels.insert(label.to_string()) {
                        labels.push(label.to_string());
                    }
                    sensitive_params.push((f.sig.ident.to_string(), param_name, label.to_string()));
                }
            }
        }

        if labels.is_empty() {
            continue; // nothing to generate for this mod.
        }
        let primary_label = labels[0].clone();

        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();
        let mut new_mod = m.clone();
        let Some((_, new_children)) = new_mod.content.as_mut() else {
            continue; // unreachable: `new_mod` is a clone of `m`, checked `Some` above.
        };

        for child in new_children.iter_mut() {
            let Item::Fn(f) = child else { continue };
            let fn_name = f.sig.ident.to_string();

            for arg in &mut f.sig.inputs {
                let FnArg::Typed(pt) = arg else { continue };
                let Some(param_name) = pat_ident_name(&pt.pat) else {
                    continue;
                };
                if let Some(label) = sensitive_label_for_param(&param_name) {
                    if let Ok(attr) = parse_attribute(&format!("#[sensitive({label})]")) {
                        pt.attrs.push(attr);
                    }
                }
            }

            if looks_like_sanitizer(&fn_name) {
                if let Ok(attr) = parse_attribute("#[taint_sanitizer]") {
                    f.attrs.push(attr);
                    sanitizers.push(fn_name);
                }
            } else if looks_like_sink(&fn_name) {
                if let Ok(attr) = parse_attribute(&format!(
                    "#[taint_sink({primary_label}, policy = \"no_sensitive\")]"
                )) {
                    f.attrs.push(attr);
                    sinks.push((fn_name, primary_label.clone()));
                }
            }
        }

        let labels_list = labels.join(", ");
        if let Ok(taint_check_attr) =
            parse_attribute(&format!("#[taint_check(labels = [{labels_list}])]"))
        {
            new_mod.attrs.push(taint_check_attr);
        }

        let (start, end) = span_byte_range(source, m.span());
        edits.push(SourceEdit {
            start,
            end,
            replacement: print_item(&Item::Mod(new_mod)),
        });
        suggestions.push(TaintSuggestion {
            mod_name: m.ident.to_string(),
            labels,
            sensitive_params,
            sinks,
            sanitizers,
        });
    }

    (edits, suggestions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_sensitive_sink_and_taint_check_for_an_eligible_mod() {
        let source = r"
mod auth {
    fn authenticate(password: &str) {
        log_debug(password);
    }
    fn log_debug(msg: &str) {}
}
";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file);
        assert_eq!(edits.len(), 1);
        assert_eq!(suggestions.len(), 1);

        let s = &suggestions[0];
        assert_eq!(s.mod_name, "auth");
        assert_eq!(s.labels, vec!["password".to_string()]);
        assert_eq!(s.sensitive_params.len(), 1);
        assert_eq!(s.sinks.len(), 1);
        assert!(s.sanitizers.is_empty());

        let rewritten = &edits[0].replacement;
        assert!(rewritten.contains("#[taint_check(labels = [password])]"));
        assert!(rewritten.contains("#[sensitive(password)]"));
        assert!(rewritten.contains("#[taint_sink(password, policy = \"no_sensitive\")]"));
    }

    #[test]
    fn generates_a_sanitizer_attribute_by_name() {
        let source = r"
mod auth {
    fn authenticate(password: &str) {}
    fn redact_value(s: &str) -> String { s.to_string() }
}
";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file);
        assert_eq!(suggestions[0].sanitizers, vec!["redact_value".to_string()]);
        assert!(edits[0].replacement.contains("#[taint_sanitizer]"));
    }

    #[test]
    fn skips_a_mod_with_no_sensitive_looking_parameters() {
        let source = "mod plain {\n    fn add(a: i32, b: i32) -> i32 { a + b }\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file);
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn never_touches_a_mod_that_already_has_any_taint_attribute() {
        let source = r"
mod auth {
    fn handle_login(#[sensitive(password)] password: &str) {}
    fn unrelated(token: &str) {}
}
";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file);
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn skips_an_external_mod_declaration() {
        let source = "mod other;\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file);
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn scan_file_scope_finds_labels_in_a_file_with_no_inline_mod() {
        // The `mod foo;` layout `taint-check --crate` is built for: this
        // file's own top-level items already are that mod's children.
        let source = r"
fn handle_login(password: &str) {
    crate::logging::log_debug(password);
}
";
        let file: File = syn::parse_str(source).unwrap();
        let suggestion = scan_file_scope(&file, "auth").unwrap();
        assert_eq!(suggestion.mod_name, "auth");
        assert_eq!(suggestion.labels, vec!["password".to_string()]);
        assert_eq!(suggestion.sensitive_params.len(), 1);
    }

    #[test]
    fn scan_file_scope_returns_none_with_no_sensitive_params() {
        let source = "fn add(a: i32, b: i32) -> i32 { a + b }\n";
        let file: File = syn::parse_str(source).unwrap();
        assert!(scan_file_scope(&file, "helpers").is_none());
    }

    #[test]
    fn scan_file_scope_skips_a_file_already_carrying_any_taint_attribute() {
        let source = "fn handle_login(#[sensitive(password)] password: &str) {}\nfn unrelated(token: &str) {}\n";
        let file: File = syn::parse_str(source).unwrap();
        assert!(scan_file_scope(&file, "auth").is_none());
    }

    #[test]
    fn plan_for_fn_reports_a_sensitive_param_and_a_sink() {
        let sink: File = syn::parse_str("fn log_debug(msg: &str) {}").unwrap();
        let Item::Fn(sink_fn) = &sink.items[0] else {
            panic!("expected a fn");
        };
        let plan = plan_for_fn(sink_fn, "password").unwrap();
        assert_eq!(plan.sink_label, Some("password".to_string()));
        assert!(!plan.is_sanitizer);
        assert!(plan.sensitive_params.is_empty());

        let auth: File = syn::parse_str("fn handle_login(password: &str) {}").unwrap();
        let Item::Fn(auth_fn) = &auth.items[0] else {
            panic!("expected a fn");
        };
        let plan = plan_for_fn(auth_fn, "password").unwrap();
        assert_eq!(
            plan.sensitive_params,
            vec![("password".to_string(), "password".to_string())]
        );
    }

    #[test]
    fn plan_for_fn_prefers_sanitizer_over_sink_on_a_name_collision() {
        // `redact_value` doesn't collide with the sink keyword list, but
        // this documents the precedence `crate::heuristics` already
        // states: sanitizer intent is checked first.
        let file: File =
            syn::parse_str("fn redact_value(s: &str) -> String { s.to_string() }").unwrap();
        let Item::Fn(f) = &file.items[0] else {
            panic!("expected a fn");
        };
        let plan = plan_for_fn(f, "password").unwrap();
        assert!(plan.is_sanitizer);
        assert_eq!(plan.sink_label, None);
    }

    #[test]
    fn plan_for_fn_returns_none_for_a_plain_function() {
        let file: File = syn::parse_str("fn add(a: i32, b: i32) -> i32 { a + b }").unwrap();
        let Item::Fn(f) = &file.items[0] else {
            panic!("expected a fn");
        };
        assert!(plan_for_fn(f, "password").is_none());
    }
}
