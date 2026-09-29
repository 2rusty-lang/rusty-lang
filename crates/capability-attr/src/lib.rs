//! `capability-attr` — Layer 2 (side-effect / capability safety) typed
//! capability declarations for Rust.
//!
//! # The problem this solves
//!
//! Rust's safety model is binary: a function is `safe` or `unsafe`. Real
//! systems code spans a spectrum `unsafe` collapses into one signal —
//! reading a bounded buffer and writing an arbitrary raw pointer are both
//! just "unsafe" to the compiler, even though their risk profiles are
//! wildly different. `#[capability(...)]` gives that spectrum a
//! machine-readable, compiler-enforced structure: a function declares the
//! allocation/I/O/raw-pointer scope it needs, and this crate verifies the
//! function body doesn't exceed it.
//!
//! ```compile_fail
//! # use capability_attr::capability;
//! // COMPILE ERROR: body allocates on the heap, but only `alloc(none)` was
//! // declared.
//! #[capability(alloc(none), io(none), ptr(none))]
//! fn quiet_fn() {
//!     let _buf: Vec<u8> = Vec::new();
//! }
//! # fn main() {}
//! ```
//!
//! ```
//! # use capability_attr::capability;
//! // Compiles clean — every operation in the body is within what was
//! // declared.
//! #[capability(alloc(heap), io(display), ptr(none))]
//! fn log_message(msg: &str) {
//!     let buf: Vec<u8> = msg.bytes().collect();
//!     println!("{}", buf.len());
//! }
//! # fn main() { log_message("hi"); }
//! ```
//!
//! This is orthogonal to `unsafe`, not a replacement for it: `unsafe`
//! remains the programmer's memory-safety promise (Layer 1, unchanged);
//! `#[capability(...)]` is the compiler's side-effect-scope promise
//! (Layer 2, this crate). See the companion [`sensitive-ifc`] crate for
//! Layer 3 (semantic/policy safety — does this function leak a credential,
//! not just "does it do I/O").
//!
//! # Phased scope
//!
//! This is a direct, workspace-local implementation of Phase 1 from
//! `docs/aisecurity/capability-rfc-updated.md`, requiring no `rustc`
//! changes, no nightly compiler — a `syn`/`quote`-based proc-macro attribute
//! that (1) parses declared capabilities from the attribute's arguments,
//! (2) walks the annotated item's body with a [`syn::visit::Visit`]
//! walker ([`capability_core::inspector::BodyInspector`]) to detect actual
//! capability usage, and (3) emits a real `compile_error!(...)` when
//! detected capabilities exceed declared ones
//! ([`capability_core::check_subset`]/[`capability_core::check_ceiling`] /
//! [`error::emit_violation`]/[`error::emit_ceiling_violation`]).
//!
//! **Scoped to function and `mod` items.** Function-level was this
//! crate's original Phase 1 scope; mod-level ceilings
//! ([RFC 0008](https://github.com/2rusty-lang/rusty-lang/blob/main/rfcs/0008-capability-mod-and-crate-level.md))
//! extend it — see [`capability`]'s own doc comment for both syntaxes.
//! Trait/impl-level declarations with hierarchical narrowing (a trait's
//! declaration bounding every `impl`) remain out of scope: that needs
//! tracking capability state *across* multiple macro-expansion sites,
//! which a single `#[proc_macro_attribute]` invocation cannot do by
//! itself, unlike mod-level (one invocation already sees every function
//! directly inside the mod it's attached to). Crate-level declarations
//! also exist now, but live in `taint-check`'s declared-vs-derived check
//! ([RFC 0007](https://github.com/2rusty-lang/rusty-lang/blob/main/rfcs/0007-capability-manifest.md)),
//! not this macro — a proc-macro fundamentally cannot see "the whole
//! crate" (it only ever receives the one item it's attached to), so
//! crate-level was never buildable as an attribute at all.
//!
//! - **Phase 1 (this crate, stable Rust today):** function- and mod-level
//!   declaration + body-inspection + subset-check, described above.
//! - **Phase 2 (deferred, not built this pass):** custom Clippy lints
//!   (`declare_lint!`) for cross-function capability-flow checking. The
//!   RFC frames this as "Phase 2" but it needs Clippy's internal lint
//!   infrastructure — effectively nightly-adjacent in practice, not as
//!   "stable" as this phase despite the RFC's own phase numbering.
//! - **Phase 3 (deferred, not built this pass):** MIR-level analysis via
//!   `rustc_private` — nightly-only, out of scope for this crate entirely.
//!
//! # Vocabulary — see `capability-core`'s `vocabulary` module docs
//!
//! The capability vocabulary implemented here (`alloc`/`io`/`ptr`) is
//! deliberately reduced from the RFC's five categories and reshaped for
//! general-purpose userspace Rust (not embedded firmware) — see
//! [`capability_core::vocabulary`]'s
//! module-level doc comment for the full reasoning, including why
//! `register(...)`/`interrupt(...)` are dropped entirely rather than
//! stubbed, and why `io(process)` exists (with no RFC equivalent) and
//! outranks `io(network)` in this crate's risk ordering. That vocabulary
//! lives in `capability-core` now, shared with `taint-generate` — see
//! `docs/adr/ADR-0005-generate-and-refactor.md`.
//!
//! # Honest scope statement
//!
//! **What this crate catches:** a function declaring `alloc(none)` that
//! calls `Vec::new`/`Box::new`/etc.; a function declaring `io(none)` that
//! calls `println!`/touches `std::fs`/`std::net`/spawns a `Command`; a
//! function declaring `ptr(none)` that dereferences a raw pointer for a
//! read or write. All are real `compile_error!(...)`s produced by this
//! crate today — see `tests/ui/fail/*.rs` and their checked-in `.stderr`
//! snapshots for real compiler output, not a description.
//!
//! **What this crate does NOT catch:** capability usage inside a function
//! called *by* the annotated function (cross-function flow — Phase 2/3);
//! usage hidden behind a macro that itself expands to an allocating/IO
//! call (AST-level detection only sees the macro invocation, not its
//! expansion, unless the macro name itself is recognized — see
//! [`capability_core::inspector`]); a raw pointer write's actual address
//! range (Phase 1 has no PAC-style address verification, so every
//! detected write is conservatively classified `ptr(write, any)`, never
//! `ptr(write, bounded)` — see [`capability_core::PtrBound`]).
//!
//! # Relationship to OS-level MAC (AppArmor/SELinux)
//!
//! `#[capability(...)]` is a compile-time check, and it only covers code built
//! with the attribute applied. It is layered with, not a substitute for,
//! OS-level mandatory access control (AppArmor/SELinux): it cannot see a
//! compromised binary, a dependency that never used the attribute, or any
//! process on the host not built from this workspace. Keep (or add) an
//! AppArmor/SELinux profile for the resulting binary exactly as you would
//! without this crate. See `docs/adr/ADR-0002-position-vs-os-level-mac.md`.

#![warn(missing_docs)]
// `cargo_common_metadata` inspects every workspace member's `Cargo.toml`
// reachable from this crate's own dependency graph (confirmed live under
// packages/offline-ops, SPEC-00034 T6: fires on all sibling crates, not
// just this one's), so it's carved out here rather than silently left
// un-denied or "fixed" by editing unrelated crates' manifests out of scope.
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope — see SPEC-00034 T6 / SPEC-00052 T0b"
)]

use proc_macro::TokenStream;
use syn::{Item, ItemFn, ItemMod};

mod error;
mod parser;

/// `true` if `attr` is `#[capability(...)]`, bare or qualified — matches
/// on the last path segment, same convention `taint-generate`'s own
/// `capability_gen::is_capability_attr` uses, so a function that already
/// carries its own declaration is recognized as "curated" and left to its
/// own independent expansion rather than double-checked against an
/// enclosing mod's ceiling.
fn is_capability_attr(attr: &syn::Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "capability")
}

/// Declare a function's allocation/I/O/raw-pointer capability scope, and
/// verify at compile time that the function body does not exceed it.
///
/// Applied to a `mod` instead, declares a shared ceiling that every
/// function inside it with no explicit declaration of its own is checked
/// against automatically (`rfcs/0008-capability-mod-and-crate-level.md`).
///
/// # Syntax
///
/// Function-level (same single-level shape as Phase 1; the `io` category
/// list has since widened beyond this crate's original, narrower scope):
///
/// ```text
/// #[capability(alloc(<none|heap|any>), io(<none|display|filesystem|registry|serial|usb|bluetooth|network|device|process|any>), ptr(<none|read|any|write, bounded|write, any>))]
/// ```
///
/// Any category may be omitted; an omitted category defaults to its most
/// restrictive level (`none`) — see [`parser::parse_capability_args`] and
/// [`capability_core::CapabilitySet::alloc_or_none`] and friends.
///
/// Mod-level (RFC 0008), same attribute, set-valued `io`:
///
/// ```text
/// #[capability(alloc(<level>), io(network: <yes|no>, filesystem: <yes|no>, registry: <yes|no>, serial: <yes|no>, usb: <yes|no>, bluetooth: <yes|no>, display: <yes|no>, device: <yes|no>, process: <yes|no>, any: <yes|no>), ptr(<level>))]
/// mod name { ... }
/// ```
///
/// An omitted `io` sub-category defaults to `no` (not permitted) — see
/// [`parser::parse_capability_ceiling_args`] and
/// [`capability_core::CapabilityCeiling`]. `alloc`/`ptr` keep the same
/// single-level grammar as the function-level form.
///
/// See the crate-level docs for the full worked compile-passing and
/// compile-failing examples.
///
/// `#[cfg(not(tarpaulin_include))]`: this function's own body, [`expand_fn`],
/// and [`expand_mod`] all take a real `proc_macro::TokenStream`, which
/// panics ("procedural macro API is used outside of a procedural macro")
/// if constructed anywhere but an active macro invocation — confirmed
/// empirically, not assumed. `cargo test`'s coverage instrumentation runs
/// in that excluded context, so these three functions are structurally
/// unreachable by it. Real correctness coverage for this code path comes
/// from `tests/ui.rs`'s `trybuild` fixtures instead, which compile this
/// macro for real, as a genuinely separate process `cargo-tarpaulin` does
/// not (and cannot) instrument — see `tests/ui/{pass,fail}/*.rs`.
#[cfg(not(tarpaulin_include))]
#[proc_macro_attribute]
pub fn capability(args: TokenStream, item: TokenStream) -> TokenStream {
    if let Ok(func) = syn::parse::<ItemFn>(item.clone()) {
        return expand_fn(args, &func);
    }

    match syn::parse::<ItemMod>(item) {
        Ok(item_mod) => expand_mod(args, &item_mod),
        Err(e) => syn::Error::new(
            e.span(),
            "#[capability] can only be applied to a function or `mod` item — crate-level \
             declarations live in `taint-check`'s declared-vs-derived check, not this macro \
             (see rfcs/0007-capability-manifest.md and rfcs/0008-capability-mod-and-crate-level.md); \
             trait/impl-level declarations remain out of scope",
        )
        .into_compile_error()
        .into(),
    }
}

/// See [`capability`]'s doc comment for why this is
/// `#[cfg(not(tarpaulin_include))]` — it takes a real
/// `proc_macro::TokenStream`, confirmed unconstructable outside an active
/// macro invocation.
#[cfg(not(tarpaulin_include))]
fn expand_fn(args: TokenStream, func: &ItemFn) -> TokenStream {
    let declared = match parser::parse_capability_args(args.into()) {
        Ok(caps) => caps,
        Err(e) => return e.into_compile_error().into(),
    };

    let detected = capability_core::inspector::inspect_body(&func.block);

    if let Some(violation) = capability_core::check_subset(&detected, &declared) {
        return error::emit_violation(&func.sig.ident, &violation).into();
    }

    quote::quote! { #func }.into()
}

/// Expand a mod-level `#[capability(...)]` (RFC 0008): every top-level
/// `fn` directly inside `item_mod` that carries no `#[capability(...)]` of
/// its own is derived and checked against the mod's declared ceiling. A
/// `fn` that already has its own declaration is left completely alone —
/// it was already checked (or will be, by its own independent macro
/// expansion) against its own, precise declaration, not the ceiling.
///
/// Scope, matching `taint-generate`'s existing `capability_gen`
/// precedent: only direct `Item::Fn` children — a nested `mod` is not
/// recursed into, and needs its own ceiling if one is wanted.
///
/// See [`capability`]'s doc comment for why this is
/// `#[cfg(not(tarpaulin_include))]` — it takes a real
/// `proc_macro::TokenStream`, confirmed unconstructable outside an active
/// macro invocation.
#[cfg(not(tarpaulin_include))]
fn expand_mod(args: TokenStream, item_mod: &ItemMod) -> TokenStream {
    let ceiling = match parser::parse_capability_ceiling_args(args.into()) {
        Ok(c) => c,
        Err(e) => return e.into_compile_error().into(),
    };

    let Some((_, items)) = &item_mod.content else {
        // `mod foo;` (external file) — this invocation's tokens are just
        // the declaration; there's nothing here to walk.
        return quote::quote! { #item_mod }.into();
    };

    for item in items {
        let Item::Fn(f) = item else { continue };
        if f.attrs.iter().any(is_capability_attr) {
            continue;
        }

        let detected = capability_core::inspector::inspect_body(&f.block);
        if let Some(violation) = capability_core::check_ceiling(&detected, &ceiling) {
            return error::emit_ceiling_violation(&f.sig.ident, &violation).into();
        }
    }

    quote::quote! { #item_mod }.into()
}

#[cfg(test)]
mod is_capability_attr_tests {
    use super::is_capability_attr;

    #[test]
    fn recognizes_a_bare_attribute() {
        let attr: syn::Attribute = syn::parse_quote!(#[capability(alloc(none))]);
        assert!(is_capability_attr(&attr));
    }

    #[test]
    fn recognizes_a_fully_qualified_attribute() {
        let attr: syn::Attribute = syn::parse_quote!(#[capability_attr::capability(alloc(none))]);
        assert!(is_capability_attr(&attr));
    }

    #[test]
    fn rejects_an_unrelated_attribute() {
        let attr: syn::Attribute = syn::parse_quote!(#[must_use]);
        assert!(!is_capability_attr(&attr));
    }
}
