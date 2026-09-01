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

use std::collections::HashSet;

use source_edit::{parse_attribute, print_item, span_byte_range, SourceEdit};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, File, FnArg, Item, ItemMod, Pat};

use crate::heuristics::{looks_like_sanitizer, looks_like_sink, sensitive_label_for_param};

/// One generated set of taint attributes for a single mod, reported back
/// so `--report` can show what was added without a human diffing the file.
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

struct HasTaintAttr(bool);

impl<'ast> Visit<'ast> for HasTaintAttr {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if attr.path().is_ident("taint_check")
            || taint_check::parser::is_sensitive(attr)
            || taint_check::parser::is_taint_sink(attr)
            || taint_check::parser::is_taint_sanitizer(attr)
        {
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
}
