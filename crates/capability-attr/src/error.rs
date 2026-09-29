//! Renders a [`Violation`](capability_core::Violation) as a real
//! `compile_error!(...)` token stream, so a capability violation surfaces
//! exactly like any other `rustc` compile error — same terminal output, same
//! IDE red-squiggle behavior, no separate lint pass to opt into.

use capability_core::Violation;
use proc_macro2::TokenStream;
use quote::quote_spanned;

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

/// Same as [`emit_violation`], but phrased for a mod-level ceiling
/// violation ([RFC 0008](../../../rfcs/0008-capability-mod-and-crate-level.md)),
/// where `violation.declared` is already a rendered ceiling (e.g. a full
/// `io(...)` set), not a single `category(level)` snippet someone could
/// literally paste back in — unlike a function-level violation, the fix
/// isn't "add this one level to your own declaration".
pub fn emit_ceiling_violation(fn_ident: &syn::Ident, violation: &Violation) -> TokenStream {
    let msg = format!(
        "capability violation in `{fn_ident}`: body uses {cat}({detected}), which the enclosing mod's ceiling does not permit ({cat}({declared})) — widen the mod's #[capability(...)] ceiling, or give this function its own, more permissive #[capability(...)]",
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

    #[test]
    fn ceiling_message_names_the_function_and_suggests_widening_the_ceiling() {
        let ident = syn::Ident::new("export_receipt", Span::call_site());
        let violation = Violation {
            category: "io",
            declared: "network: yes, filesystem: no, display: no, process: no, any: no".to_string(),
            detected: "Filesystem".to_string(),
        };
        let rendered = emit_ceiling_violation(&ident, &violation).to_string();
        assert!(rendered.contains("compile_error"));
        assert!(rendered.contains("export_receipt"));
        assert!(rendered.contains("Filesystem"));
        assert!(rendered.contains("filesystem: no"));
        assert!(rendered.contains("ceiling"));
    }
}
