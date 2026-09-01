//! Deterministic `#[capability(...)]` generation.
//!
//! For every top-level `fn` with no existing `#[capability(...)]`, run
//! `capability_core::inspector::inspect_body` on its block and write an
//! attribute matching exactly what was detected.
//!
//! Unlike [`crate::taint_gen`], nothing here is a guess — the same body
//! inspector `capability-attr`'s own proc-macro uses to *verify* a
//! declared capability set is used here to *construct* one from scratch,
//! so the generated attribute is definitionally correct for the body as it
//! stands today (it will need updating if the body later changes, same as
//! any hand-written one would).
//!
//! **Scope: top-level functions only, this pass** — a function nested
//! inside a `mod` is left to [`crate::taint_gen`] instead (which rewrites
//! an eligible mod's entire span in one piece); generating independent,
//! overlapping edits inside the same mod in the same run is exactly what
//! `source_edit::apply_edits` documents as unsupported.
//!
//! # A generated attribute only compiles if the target crate depends on
//! `rusty-capability-attr`
//!
//! `#[capability(...)]` is a real proc-macro attribute, not an inert
//! marker — writing it into a crate that doesn't depend on
//! `rusty-capability-attr` produces code that fails with `cannot find
//! attribute 'capability' in this scope` (confirmed by dogfooding this
//! tool against `rusty-taint-check`'s own source, which has no such
//! dependency). [`crate::manifest::capability_attr_extern_name`] resolves
//! the real extern crate name from the target file's nearest `Cargo.toml`
//! before this pass runs at all; [`plan_for_fn`] takes that as `None`/
//! `Some(name)` and refuses to generate anything without it. When present,
//! the attribute is written fully qualified (`#[name::capability(...)]`)
//! rather than bare, so it never depends on a `use` this pass didn't also
//! insert.

use capability_core::render_capability_args;
use source_edit::{parse_attribute, print_item, span_byte_range, SourceEdit};
use syn::spanned::Spanned;
use syn::{Attribute, File, Item, ItemFn};

/// `true` if `attr` is `#[capability(...)]`, bare or qualified.
///
/// Matches on the last path segment (`#[capability(...)]` or
/// `#[some_crate::capability(...)]`) so a previous run's own qualified
/// output is still recognized as "already curated" on a second run.
#[must_use]
pub fn is_capability_attr(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "capability")
}

/// One generated `#[capability(...)]` — reported back so `--report` can
/// show what was added and why, without a human having to diff the file.
pub struct CapabilitySuggestion {
    /// The function's name.
    pub fn_name: String,
    /// The rendered attribute arguments, e.g. `"alloc(heap), io(display),
    /// ptr(none)"`.
    pub rendered_attribute: String,
}

/// One planned `#[capability(...)]` for a single function.
///
/// Detection only, no edit yet. `attr_text` is the fully qualified
/// attribute ready to splice in, e.g.
/// `"#[rusty_capability_attr::capability(alloc(none), io(display),
/// ptr(none))]"`.
pub struct CapabilityPlan {
    /// The function's name.
    pub fn_name: String,
    /// The rendered attribute arguments alone (no `#[...]`), e.g.
    /// `"alloc(heap), io(display), ptr(none)"`.
    pub rendered: String,
    /// The full, fully qualified attribute text.
    pub attr_text: String,
}

/// Detect what `#[capability(...)]` `f` needs, without constructing an edit.
///
/// Returns `None` if `f` already has one (bare or qualified) or if
/// `extern_name` is `None` (the target crate doesn't depend on
/// `rusty-capability-attr` — see the module docs).
#[must_use]
pub fn plan_for_fn(f: &ItemFn, extern_name: Option<&str>) -> Option<CapabilityPlan> {
    let extern_name = extern_name?;
    if f.attrs.iter().any(is_capability_attr) {
        return None;
    }

    let detected = capability_core::inspector::inspect_body(&f.block);
    let rendered = render_capability_args(&detected);
    let attr_text = format!("#[{extern_name}::capability({rendered})]");
    Some(CapabilityPlan {
        fn_name: f.sig.ident.to_string(),
        rendered,
        attr_text,
    })
}

/// Scan `file`'s top-level functions and generate a `#[capability(...)]`
/// for every one that doesn't already have one.
///
/// Unless `extern_name` is `None`, in which case nothing is generated at
/// all — see the module docs.
#[must_use]
pub fn generate(
    source: &str,
    file: &File,
    extern_name: Option<&str>,
) -> (Vec<SourceEdit>, Vec<CapabilitySuggestion>) {
    let mut edits = Vec::new();
    let mut suggestions = Vec::new();

    for item in &file.items {
        let Item::Fn(f) = item else { continue };
        let Some(plan) = plan_for_fn(f, extern_name) else {
            continue;
        };
        let Ok(attr) = parse_attribute(&plan.attr_text) else {
            continue;
        };

        let mut new_fn = f.clone();
        new_fn.attrs.push(attr);

        let (start, end) = span_byte_range(source, f.span());
        edits.push(SourceEdit {
            start,
            end,
            replacement: print_item(&Item::Fn(new_fn)),
        });
        suggestions.push(CapabilitySuggestion {
            fn_name: plan.fn_name,
            rendered_attribute: plan.rendered,
        });
    }

    (edits, suggestions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_matching_attribute_for_an_unannotated_fn() {
        let source = "fn log_message(msg: &str) {\n    println!(\"{msg}\");\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file, Some("capability_attr"));
        assert_eq!(edits.len(), 1);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].fn_name, "log_message");
        assert_eq!(
            suggestions[0].rendered_attribute,
            "alloc(none), io(display), ptr(none)"
        );
        assert!(edits[0]
            .replacement
            .contains("#[capability_attr::capability(alloc(none), io(display), ptr(none))]"));
    }

    #[test]
    fn skips_a_function_that_already_has_a_capability_attribute() {
        let source = "#[capability(alloc(any), io(any), ptr(any))]\nfn wild() {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file, Some("capability_attr"));
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn skips_a_function_that_already_has_a_qualified_capability_attribute() {
        // A second run must recognize its own first-run output as curated.
        let source =
            "#[capability_attr::capability(alloc(any), io(any), ptr(any))]\nfn wild() {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file, Some("capability_attr"));
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn generates_nothing_without_an_extern_name() {
        // The target crate doesn't depend on `rusty-capability-attr` — see
        // `crate::manifest` — so nothing is generated, not a bare
        // (non-compiling) `#[capability(...)]`.
        let source = "fn log_message(msg: &str) {\n    println!(\"{msg}\");\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file, None);
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn detects_heap_allocation() {
        let source = "fn make_vec() -> Vec<u8> {\n    Vec::new()\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (_, suggestions) = generate(source, &file, Some("capability_attr"));
        assert_eq!(
            suggestions[0].rendered_attribute,
            "alloc(heap), io(none), ptr(none)"
        );
    }

    #[test]
    fn ignores_a_fn_nested_inside_a_mod() {
        let source = "mod inner {\n    fn helper() {}\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file, Some("capability_attr"));
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn preserves_the_original_span_boundaries_of_other_items() {
        let source = "fn a() {}\nfn b() {\n    println!(\"hi\");\n}\nfn c() {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, _) = generate(source, &file, Some("capability_attr"));
        // Two of the three functions (a, c) do no I/O/alloc, so all three
        // get an edit, but each edit's original span must match exactly
        // that one function's own text.
        assert_eq!(edits.len(), 3);
        let (start, end) = (edits[1].start, edits[1].end);
        assert_eq!(&source[start..end], "fn b() {\n    println!(\"hi\");\n}");
    }
}
