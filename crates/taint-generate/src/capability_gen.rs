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

use capability_core::render_capability_args;
use source_edit::{parse_attribute, print_item, span_byte_range, SourceEdit};
use syn::spanned::Spanned;
use syn::{File, Item};

/// One generated `#[capability(...)]` — reported back so `--report` can
/// show what was added and why, without a human having to diff the file.
pub struct CapabilitySuggestion {
    /// The function's name.
    pub fn_name: String,
    /// The rendered attribute arguments, e.g. `"alloc(heap), io(display),
    /// ptr(none)"`.
    pub rendered_attribute: String,
}

/// Scan `file`'s top-level functions and generate a `#[capability(...)]`
/// for every one that doesn't already have one.
#[must_use]
pub fn generate(source: &str, file: &File) -> (Vec<SourceEdit>, Vec<CapabilitySuggestion>) {
    let mut edits = Vec::new();
    let mut suggestions = Vec::new();

    for item in &file.items {
        let Item::Fn(f) = item else { continue };
        if f.attrs.iter().any(|a| a.path().is_ident("capability")) {
            continue; // already curated — never touch it.
        }

        let detected = capability_core::inspector::inspect_body(&f.block);
        let rendered = render_capability_args(&detected);
        let Ok(attr) = parse_attribute(&format!("#[capability({rendered})]")) else {
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
            fn_name: f.sig.ident.to_string(),
            rendered_attribute: rendered,
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
        let (edits, suggestions) = generate(source, &file);
        assert_eq!(edits.len(), 1);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].fn_name, "log_message");
        assert_eq!(
            suggestions[0].rendered_attribute,
            "alloc(none), io(display), ptr(none)"
        );
        assert!(edits[0]
            .replacement
            .contains("#[capability(alloc(none), io(display), ptr(none))]"));
    }

    #[test]
    fn skips_a_function_that_already_has_a_capability_attribute() {
        let source = "#[capability(alloc(any), io(any), ptr(any))]\nfn wild() {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file);
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn detects_heap_allocation() {
        let source = "fn make_vec() -> Vec<u8> {\n    Vec::new()\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (_, suggestions) = generate(source, &file);
        assert_eq!(
            suggestions[0].rendered_attribute,
            "alloc(heap), io(none), ptr(none)"
        );
    }

    #[test]
    fn ignores_a_fn_nested_inside_a_mod() {
        let source = "mod inner {\n    fn helper() {}\n}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, suggestions) = generate(source, &file);
        assert!(edits.is_empty());
        assert!(suggestions.is_empty());
    }

    #[test]
    fn preserves_the_original_span_boundaries_of_other_items() {
        let source = "fn a() {}\nfn b() {\n    println!(\"hi\");\n}\nfn c() {}\n";
        let file: File = syn::parse_str(source).unwrap();
        let (edits, _) = generate(source, &file);
        // Two of the three functions (a, c) do no I/O/alloc, so all three
        // get an edit, but each edit's original span must match exactly
        // that one function's own text.
        assert_eq!(edits.len(), 3);
        let (start, end) = (edits[1].start, edits[1].end);
        assert_eq!(&source[start..end], "fn b() {\n    println!(\"hi\");\n}");
    }
}
