//! `taint-check-macros` — the `#[taint_check(labels = [...])]` proc-macro
//! attribute.
//!
//! This crate is deliberately thin: all real parsing, inspection, and
//! rendering logic lives in [`taint_check`] (the `rusty-taint-check`
//! crate), reused verbatim here and by that crate's own standalone CLI.
//! This split exists because a `proc-macro = true` lib can only export
//! macro entry points — the shared AST-inspection logic can't live in the
//! same crate as both the macro and a normal CLI binary target. See
//! `docs/adr/ADR-0001` / `docs/adr/ADR-0003` for the full reasoning (the
//! same one `serde`/`serde_derive` and `thiserror`/`thiserror-impl` split
//! for).
//!
//! # Why only `#[taint_check]` is a real `#[proc_macro_attribute]`
//!
//! `#[sensitive(label)]`, `#[taint_sink(label, policy = "...")]`, and
//! `#[taint_sanitizer]` are *not* separately registered macros here. This
//! macro receives the entire annotated `mod` as tokens before rustc tries
//! to resolve any attribute nested inside it, inspects those three helper
//! attributes for its own bookkeeping ([`taint_check::inspector`]), then
//! re-emits the `mod` with all three stripped
//! ([`taint_check::rewrite::strip_helper_attrs`]). rustc never sees them
//! post-expansion, so it never needs to resolve them as attributes in
//! their own right — the same "consume custom syntax, re-emit plain Rust"
//! move `#[async_trait]`-style macros make.

// `cargo_common_metadata` inspects every workspace member's `Cargo.toml`
// reachable from this crate's own dependency graph — see `capability-attr`'s
// own `src/lib.rs` for the same carve-out; this crate hits the identical
// workspace-wide check.
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

use proc_macro::TokenStream;
use syn::Item;

/// Declare a `mod`'s taint labels, and verify at compile time that no
/// `#[sensitive(label)]`-marked value reaches a `#[taint_sink(label, ...)]`
/// call without first passing through a `#[taint_sanitizer]`.
///
/// # Syntax
///
/// ```text
/// #[taint_check(labels = [password, session_token])]
/// mod auth {
///     fn handle_login(#[sensitive(password)] password: &str) { .. }
///
///     #[taint_sink(password, policy = "no_sensitive")]
///     fn log_debug(msg: &str) { .. }
///
///     #[taint_sanitizer]
///     fn redact(s: &str) -> String { .. }
/// }
/// ```
///
/// Only applies to `mod` items — see the crate-level docs of
/// `rusty-taint-check` for why. See that crate's docs for the full
/// shallow-tracking scope statement (what propagates and what doesn't).
#[proc_macro_attribute]
pub fn taint_check(args: TokenStream, item: TokenStream) -> TokenStream {
    let labels = match taint_check::parser::parse_taint_check_args(args.into()) {
        Ok(parsed) => parsed.labels,
        Err(e) => return e.into_compile_error().into(),
    };

    let mut item_mod = match syn::parse::<Item>(item) {
        Ok(Item::Mod(m)) => m,
        Ok(other) => {
            return syn::Error::new_spanned(&other, taint_check::FN_SCOPE_ERROR)
                .into_compile_error()
                .into();
        }
        Err(e) => return e.into_compile_error().into(),
    };

    let violations = match taint_check::inspector::inspect_mod(&item_mod, &labels) {
        Ok(v) => v,
        Err(e) => return e.into_compile_error().into(),
    };

    if let Some(violation) = violations.first() {
        return taint_check::error::emit_violation(violation).into();
    }

    taint_check::rewrite::strip_helper_attrs(&mut item_mod);
    quote::quote! { #item_mod }.into()
}
