//! Renders a [`Violation`](crate::lattice::Violation) as a real
//! `compile_error!(...)` token stream, so a capability violation surfaces
//! exactly like any other `rustc` compile error — same terminal output, same
//! IDE red-squiggle behavior, no separate lint pass to opt into.

use proc_macro2::TokenStream;
use quote::quote_spanned;

use crate::lattice::Violation;

/// Build the `compile_error!(...)` token stream for `violation`, spanned at
/// `fn_ident` so the error underlines the function's name.
pub fn emit_violation(fn_ident: &syn::Ident, violation: &Violation) -> TokenStream {
    let msg = format!(
        "capability violation in `{fn_ident}`: body uses {cat}({detected}) but only {cat}({declared}) is declared — add `{cat}({detected})` to #[capability(...)] (or remove the operation that requires it)",
        cat = violation.category,
        detected = violation.detected,
        declared = violation.declared,
    );
    quote_spanned! { fn_ident.span() => compile_error!(#msg); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proc_macro2::Span;

    #[test]
    fn message_names_the_function_and_both_levels() {
        let ident = syn::Ident::new("quiet_fn", Span::call_site());
        let violation = Violation {
            category: "alloc",
            declared: "None".to_string(),
            detected: "Heap".to_string(),
        };
        let rendered = emit_violation(&ident, &violation).to_string();
        assert!(rendered.contains("compile_error"));
        assert!(rendered.contains("quiet_fn"));
        assert!(rendered.contains("alloc"));
        assert!(rendered.contains("Heap"));
        assert!(rendered.contains("None"));
    }
}
