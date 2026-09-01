//! Surgical source rewriting: replace exactly one [`syn::Item`]'s byte span
//! with a re-printed, mutated version of itself, leaving the rest of the
//! file byte-identical.
//!
//! `taint-generate` and `taint-refactor` both need to add an attribute (or
//! insert a call) to one specific `fn`/`mod` inside a real source file
//! without disturbing anything else in it. A full `syn::parse_file` +
//! `prettyplease::unparse` round-trip of the *whole file* would work, but
//! it silently reformats every other item and strips blank-line structure
//! wherever `syn` doesn't preserve it — an unacceptable side effect for a
//! tool whose entire job is "add one attribute, touch nothing else". This
//! crate instead: (1) locates the exact byte range of the *one* item being
//! changed via [`span_byte_range`] (using [`proc_macro2`]'s `span-locations`
//! line/column data, since this always runs outside a real proc-macro), (2)
//! re-prints just that mutated item alone via `prettyplease`
//! ([`print_item`]), and (3) splices it back into the original text
//! ([`apply_edits`]). Everything outside a changed item's own span is
//! untouched; the changed item itself may come out less indented than its
//! surrounding context if it was nested (`prettyplease` always prints from
//! column zero) — recommend running `cargo fmt` after applying edits.

#![warn(missing_docs)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

use proc_macro2::Span;
use syn::parse::Parser;
use syn::{Attribute, Item};

/// One pending replacement: swap the original source's `[start, end)` byte
/// range for `replacement`.
#[derive(Debug, Clone)]
pub struct SourceEdit {
    /// Start byte offset (inclusive) in the *original* source.
    pub start: usize,
    /// End byte offset (exclusive) in the *original* source.
    pub end: usize,
    /// The text to put in that range's place.
    pub replacement: String,
}

/// Convert a 1-indexed line number and 0-indexed, char-counted column
/// (`proc_macro2::LineColumn`'s own convention) into a byte offset.
///
/// Assumes LF (`\n`) line endings, matching every file this workspace's own
/// tooling writes.
#[must_use]
pub fn byte_offset(source: &str, line: usize, column: usize) -> usize {
    let mut offset = 0usize;
    for (idx, line_str) in source.split('\n').enumerate() {
        if idx + 1 == line {
            let prefix_len: usize = line_str.chars().take(column).map(char::len_utf8).sum();
            return offset + prefix_len;
        }
        offset += line_str.len() + 1; // the '\n' that `split` consumed
    }
    source.len()
}

/// The `[start, end)` byte range `span` covers in `source`.
#[must_use]
pub fn span_byte_range(source: &str, span: Span) -> (usize, usize) {
    let start = span.start();
    let end = span.end();
    (
        byte_offset(source, start.line, start.column),
        byte_offset(source, end.line, end.column),
    )
}

/// Pretty-print `item` alone (wrapped in a bare, attribute-less
/// [`syn::File`]) via `prettyplease`, trimmed of its trailing newline so
/// callers can splice it directly into a [`SourceEdit::replacement`].
#[must_use]
pub fn print_item(item: &Item) -> String {
    let file = syn::File {
        shebang: None,
        attrs: Vec::new(),
        items: vec![item.clone()],
    };
    prettyplease::unparse(&file)
        .trim_end_matches('\n')
        .to_string()
}

/// Parse a single standalone `#[...]` outer attribute from `text`.
///
/// `syn::Attribute` has no direct [`syn::parse::Parse`] impl of its own
/// (an attribute is only ever parsed as part of something else) — this is
/// the `Attribute::parse_outer`-based equivalent of `syn::parse_str` for
/// exactly this one node type, since generating one from a formatted
/// string (`format!("#[{name}({args})]")`) is how every caller in this
/// workspace builds a new attribute to insert.
///
/// # Errors
///
/// Returns `Err` if `text` isn't a single valid `#[...]` attribute.
pub fn parse_attribute(text: &str) -> syn::Result<Attribute> {
    let mut attrs = Attribute::parse_outer.parse_str(text)?;
    if attrs.len() != 1 {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("expected exactly one attribute, got {}", attrs.len()),
        ));
    }
    Ok(attrs.remove(0))
}

/// Apply every edit to `source`, returning the rewritten text.
///
/// Edits are applied from the highest byte offset to the lowest so that
/// earlier edits' offsets stay valid as later (already-applied) ones shift
/// the text around them. Overlapping edits are not supported — callers
/// must ensure each targets a disjoint span (true by construction here:
/// every caller in this workspace produces at most one edit per top-level
/// item).
#[must_use]
pub fn apply_edits(source: &str, edits: &[SourceEdit]) -> String {
    let mut ordered: Vec<&SourceEdit> = edits.iter().collect();
    ordered.sort_by(|a, b| b.start.cmp(&a.start));

    let mut result = source.to_string();
    for edit in ordered {
        result.replace_range(edit.start..edit.end, &edit.replacement);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::spanned::Spanned;

    #[test]
    fn byte_offset_finds_start_of_a_later_line() {
        let source = "fn a() {}\nfn b() {}\n";
        assert_eq!(byte_offset(source, 2, 0), 10);
    }

    #[test]
    fn byte_offset_handles_a_mid_line_column() {
        let source = "fn a() {}\nfn b() {}\n";
        assert_eq!(byte_offset(source, 2, 3), 13);
    }

    #[test]
    fn span_byte_range_covers_exactly_the_item_text() {
        let source = "fn a() {}\nfn b() {}\n";
        let file: syn::File = syn::parse_str(source).unwrap();
        let second = &file.items[1];
        let (start, end) = span_byte_range(source, second.span());
        assert_eq!(&source[start..end], "fn b() {}");
    }

    #[test]
    fn print_item_renders_valid_rust_with_no_trailing_blank_line() {
        let item: Item = syn::parse_quote! {
            fn hello() {
                println!("hi");
            }
        };
        let rendered = print_item(&item);
        assert!(rendered.starts_with("fn hello"));
        assert!(!rendered.ends_with('\n'));
    }

    #[test]
    fn parse_attribute_parses_a_single_outer_attribute() {
        let attr = parse_attribute("#[capability(alloc(none), io(none), ptr(none))]").unwrap();
        assert!(attr.path().is_ident("capability"));
    }

    #[test]
    fn parse_attribute_rejects_malformed_text() {
        assert!(parse_attribute("not an attribute").is_err());
    }

    #[test]
    fn apply_edits_replaces_the_targeted_item_and_nothing_else() {
        let source = "fn a() {}\nfn b() {}\nfn c() {}\n";
        let file: syn::File = syn::parse_str(source).unwrap();
        let (start, end) = span_byte_range(source, file.items[1].span());
        let rewritten = apply_edits(
            source,
            &[SourceEdit {
                start,
                end,
                replacement: "fn b() { /* patched */ }".to_string(),
            }],
        );
        assert_eq!(
            rewritten,
            "fn a() {}\nfn b() { /* patched */ }\nfn c() {}\n"
        );
    }

    #[test]
    fn apply_edits_handles_multiple_disjoint_edits_in_one_pass() {
        let source = "fn a() {}\nfn b() {}\nfn c() {}\n";
        let file: syn::File = syn::parse_str(source).unwrap();
        let (a_start, a_end) = span_byte_range(source, file.items[0].span());
        let (c_start, c_end) = span_byte_range(source, file.items[2].span());
        let rewritten = apply_edits(
            source,
            &[
                SourceEdit {
                    start: a_start,
                    end: a_end,
                    replacement: "fn a() { /* one */ }".to_string(),
                },
                SourceEdit {
                    start: c_start,
                    end: c_end,
                    replacement: "fn c() { /* two */ }".to_string(),
                },
            ],
        );
        assert_eq!(
            rewritten,
            "fn a() { /* one */ }\nfn b() {}\nfn c() { /* two */ }\n"
        );
    }
}
