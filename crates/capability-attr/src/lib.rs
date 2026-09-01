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
//! # Phased scope (this crate implements Phase 1 only, function-level only)
//!
//! This is a direct, workspace-local implementation of Phase 1 from
//! `docs/aisecurity/capability-rfc-updated.md`, requiring no `rustc`
//! changes, no nightly compiler — a `syn`/`quote`-based proc-macro attribute
//! that (1) parses declared capabilities from the attribute's arguments,
//! (2) walks the annotated function's body with a [`syn::visit::Visit`]
//! walker ([`capability_core::inspector::BodyInspector`]) to detect actual
//! capability usage, and (3) emits a real `compile_error!(...)` when
//! detected capabilities exceed declared ones
//! ([`capability_core::check_subset`] / [`error::emit_violation`]).
//!
//! **Scoped to function items only, this pass.** The RFC also describes
//! module/trait/impl/crate-level declarations with hierarchical narrowing
//! (a module's declaration bounds every function inside it, a trait's
//! declaration bounds every `impl`). That requires tracking capability
//! state *across* multiple macro-expansion sites, which a single
//! `#[proc_macro_attribute]` invocation cannot see by itself — it is real,
//! valuable, and explicitly deferred (see this workspace's
//! `spec/SPEC-00045-*.md`), not attempted here.
//!
//! - **Phase 1 (this crate, stable Rust today):** function-level
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
//! this project's real target (`git.git`, a userspace CLI tool, not
//! embedded firmware) — see [`capability_core::vocabulary`]'s
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
use syn::ItemFn;

mod error;
mod parser;

/// Declare a function's allocation/I/O/raw-pointer capability scope, and
/// verify at compile time that the function body does not exceed it.
///
/// # Syntax
///
/// ```text
/// #[capability(alloc(<none|heap|any>), io(<none|display|filesystem|network|process|any>), ptr(<none|read|any|write, bounded|write, any>))]
/// ```
///
/// Any category may be omitted; an omitted category defaults to its most
/// restrictive level (`none`) — see [`parser::CapabilitySet::alloc_or_none`]
/// and friends. See the crate-level docs for the full worked
/// compile-passing and compile-failing examples.
#[proc_macro_attribute]
pub fn capability(args: TokenStream, item: TokenStream) -> TokenStream {
    let declared = match parser::parse_capability_args(args.into()) {
        Ok(caps) => caps,
        Err(e) => return e.into_compile_error().into(),
    };

    let func = match syn::parse::<ItemFn>(item) {
        Ok(f) => f,
        Err(e) => {
            return syn::Error::new(
                e.span(),
                "#[capability] can only be applied to a function item in this crate's current \
                 (function-level-only, Phase 1) scope — see this crate's module docs for the \
                 deferred module/trait/impl-level support",
            )
            .into_compile_error()
            .into();
        }
    };

    let detected = capability_core::inspector::inspect_body(&func.block);

    if let Some(violation) = capability_core::check_subset(&detected, &declared) {
        return error::emit_violation(&func.sig.ident, &violation).into();
    }

    quote::quote! { #func }.into()
}
