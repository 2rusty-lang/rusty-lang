//! Combined `#[capability(...)]` and taint-attribute generation for
//! top-level functions.
//!
//! [`crate::capability_gen`] and [`crate::taint_gen::scan_file_scope`]/
//! `plan_for_fn` both ever touch the exact same set of items — a file's
//! top-level `fn`s — which is nothing new for either pass alone, but
//! *combining* them is: two independent [`source_edit::SourceEdit`]s over
//! the same function's span is exactly the overlap `source_edit::apply_edits`
//! doesn't support (it assumes non-overlapping spans; see that crate's own
//! docs). This module exists to be the one place that builds a single edit
//! per function, applying both attribute sets to one cloned copy before
//! splicing it in.
//!
//! [`crate::capability_gen::generate`] and [`crate::taint_gen::generate`]
//! (the inline-mod pass) don't have this problem with each other: one only
//! ever touches top-level `fn`s, the other only ever touches an
//! `Item::Mod`, so their edits can never collide — see
//! `crate::capability_gen`'s own module docs for that reasoning. Neither
//! of those two is used for the top-level-function case; this module
//! replaces both for it.

use source_edit::{parse_attribute, print_item, span_byte_range, SourceEdit};
use syn::spanned::Spanned;
use syn::{Attribute, File, FnArg, Item, ItemFn};

use crate::capability_gen::{self, CapabilitySuggestion};
use crate::taint_gen::{self, TaintSuggestion};

/// Everything [`generate`] found and did for one file's top-level `fn`s.
pub struct TopLevelResult {
    /// The edits to splice in (one per changed function).
    pub edits: Vec<SourceEdit>,
    /// Every `#[capability(...)]` generated, for `--report`.
    pub capability_suggestions: Vec<CapabilitySuggestion>,
    /// The taint-attribute summary for this file, if anything was
    /// generated — see [`taint_gen::scan_file_scope`].
    pub taint_suggestion: Option<TaintSuggestion>,
    /// `true` if this file had at least one top-level `fn` eligible for
    /// `#[capability(...)]` generation (not already annotated) that got
    /// skipped because `capability_extern_name` was `None` — see
    /// `crate::manifest`.
    pub capability_generation_skipped: bool,
}

/// Generate both `#[capability(...)]` and taint attributes for `file`'s
/// top-level functions, combining both onto one edit per changed function.
///
/// `mod_name` is used only for [`TaintSuggestion::mod_name`] (there's no
/// `mod` item here to name it from); `capability_extern_name` is
/// [`crate::manifest::capability_attr_extern_name`]'s result for this
/// file. `batch_primary_label`, if given, is used for sink/sanitizer
/// detection only when `file` has no sensitive parameters of its own to
/// supply one — a sink can legitimately live in a different file than the
/// label reaching it; see [`taint_gen::find_labels`]'s docs.
#[must_use]
pub fn generate(
    source: &str,
    file: &File,
    mod_name: &str,
    capability_extern_name: Option<&str>,
    batch_primary_label: Option<&str>,
) -> TopLevelResult {
    let taint_suggestion = taint_gen::scan_file_scope(file, mod_name);
    let primary_label = taint_suggestion
        .as_ref()
        .map(|s| s.labels[0].clone())
        .or_else(|| batch_primary_label.map(ToString::to_string));

    let capability_generation_skipped = capability_extern_name.is_none()
        && file.items.iter().any(|item| {
            let Item::Fn(f) = item else { return false };
            !f.attrs.iter().any(capability_gen::is_capability_attr)
        });

    let mut edits = Vec::new();
    let mut capability_suggestions = Vec::new();

    for item in &file.items {
        let Item::Fn(f) = item else { continue };

        let capability_plan = capability_gen::plan_for_fn(f, capability_extern_name);
        let taint_plan = primary_label
            .as_deref()
            .and_then(|label| taint_gen::plan_for_fn(f, label));

        if capability_plan.is_none() && taint_plan.is_none() {
            continue;
        }

        let mut new_fn = f.clone();

        if let Some(plan) = capability_plan {
            if let Ok(attr) = parse_attribute(&plan.attr_text) {
                new_fn.attrs.push(attr);
            }
            capability_suggestions.push(CapabilitySuggestion {
                fn_name: plan.fn_name,
                rendered_attribute: plan.rendered,
            });
        }

        if let Some(plan) = taint_plan {
            for (param_name, label) in &plan.sensitive_params {
                if let Some(attrs) = param_attrs_mut(&mut new_fn, param_name) {
                    if let Ok(attr) = parse_attribute(&format!("#[sensitive({label})]")) {
                        attrs.push(attr);
                    }
                }
            }
            if plan.is_sanitizer {
                if let Ok(attr) = parse_attribute("#[taint_sanitizer]") {
                    new_fn.attrs.push(attr);
                }
            } else if let Some(label) = &plan.sink_label {
                if let Ok(attr) = parse_attribute(&format!(
                    "#[taint_sink({label}, policy = \"no_sensitive\")]"
                )) {
                    new_fn.attrs.push(attr);
                }
            }
        }

        let (start, end) = span_byte_range(source, f.span());
        edits.push(SourceEdit {
            start,
            end,
            replacement: print_item(&Item::Fn(new_fn)),
        });
    }

    TopLevelResult {
        edits,
        capability_suggestions,
        taint_suggestion,
        capability_generation_skipped,
    }
}

/// The mutable `attrs` of `f`'s parameter named `param_name`, by matching
/// [`taint_gen`]'s own `pat_ident_name`-equivalent pattern-to-name logic
/// inline (no `Pat::Type`/`Pat::Ident` helper is exported from that
/// private-to-the-crate module, and duplicating just the match here is
/// simpler than exporting one for a single caller).
fn param_attrs_mut<'f>(f: &'f mut ItemFn, param_name: &str) -> Option<&'f mut Vec<Attribute>> {
    f.sig.inputs.iter_mut().find_map(|arg| {
        let FnArg::Typed(pt) = arg else { return None };
        let ident = match pt.pat.as_ref() {
            syn::Pat::Ident(pi) => &pi.ident,
            _ => return None,
        };
        (ident == param_name).then_some(&mut pt.attrs)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_capability_and_taint_attributes_on_the_same_function() {
        let source = r"
fn handle_login(password: &str) {
    crate::logging::log_debug(password);
}
";
        let file: File = syn::parse_str(source).unwrap();
        let result = generate(source, &file, "auth", Some("capability_attr"), None);

        assert_eq!(result.edits.len(), 1);
        assert_eq!(result.capability_suggestions.len(), 1);
        let suggestion = result.taint_suggestion.unwrap();
        assert_eq!(suggestion.mod_name, "auth");
        assert_eq!(suggestion.labels, vec!["password".to_string()]);
        assert!(!result.capability_generation_skipped);

        let rewritten = &result.edits[0].replacement;
        assert!(rewritten.contains("#[capability_attr::capability("));
        assert!(rewritten.contains("#[sensitive(password)]"));
    }

    #[test]
    fn a_sink_function_with_no_batch_label_gets_only_its_capability_attribute() {
        let source = "fn log_debug(msg: &str) {\n    println!(\"{msg}\");\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        // No sensitive param in this file, and no batch-wide label
        // supplied either, so there's no label to tag the sink with.
        let result = generate(source, &file, "logging", Some("capability_attr"), None);
        assert_eq!(result.edits.len(), 1);
        assert!(result.taint_suggestion.is_none());
        assert!(result.edits[0]
            .replacement
            .contains("#[capability_attr::capability("));
        assert!(!result.edits[0].replacement.contains("taint_sink"));
    }

    #[test]
    fn a_sink_function_uses_the_batch_wide_label_when_its_own_file_has_none() {
        // The realistic multi-file layout: `password` is only ever a
        // sensitive param in `auth.rs`, but `log_debug` lives in a
        // separate `logging.rs` with no sensitive params of its own — the
        // batch-wide label (as `crate::cli` would compute it across both
        // files in one `taint-generate` invocation) is what lets this
        // file's sink still get tagged.
        let source = "fn log_debug(msg: &str) {\n    println!(\"{msg}\");\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let result = generate(
            source,
            &file,
            "logging",
            Some("capability_attr"),
            Some("password"),
        );
        assert!(result.taint_suggestion.is_none()); // this file found no label of its own
        assert!(result.edits[0]
            .replacement
            .contains("#[taint_sink(password, policy = \"no_sensitive\")]"));
    }

    #[test]
    fn a_files_own_label_takes_priority_over_the_batch_wide_one() {
        let source = "fn handle_login(token: &str) {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let result = generate(
            source,
            &file,
            "auth",
            Some("capability_attr"),
            Some("password"),
        );
        let suggestion = result.taint_suggestion.unwrap();
        assert_eq!(suggestion.labels, vec!["token".to_string()]);
    }

    #[test]
    fn reports_capability_generation_skipped_without_an_extern_name() {
        let source = "fn plain() {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let result = generate(source, &file, "m", None, None);
        assert!(result.capability_suggestions.is_empty());
        assert!(result.capability_generation_skipped);
    }

    #[test]
    fn does_not_report_skipped_when_there_is_nothing_to_generate() {
        let source = "#[capability(alloc(none), io(none), ptr(none))]\nfn plain() {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let result = generate(source, &file, "m", None, None);
        assert!(!result.capability_generation_skipped);
    }

    #[test]
    fn produces_no_edits_for_an_already_curated_file() {
        let source = "#[capability(alloc(none), io(none), ptr(none))]\nfn handle_login(#[sensitive(password)] password: &str) {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let result = generate(source, &file, "auth", Some("capability_attr"), None);
        assert!(result.edits.is_empty());
        assert!(result.taint_suggestion.is_none());
        assert!(result.capability_suggestions.is_empty());
    }
}
