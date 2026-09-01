//! `capability-core` — the capability vocabulary, body-usage inspector, and
//! declared-vs-detected subset check shared between `capability-attr` (the
//! `#[capability(...)]` proc-macro) and `taint-generate` (auto-writes a
//! `#[capability(...)]` matching a function's *actual*, detected usage).
//!
//! Extracted from `capability-attr`'s own private modules — none of this
//! was ever public API (a `proc-macro = true` crate can only export its
//! macro entry points to begin with, the same reason `path-match` was
//! extracted earlier), so moving it here changes no compatibility
//! guarantee. See `docs/adr/ADR-0005-generate-and-refactor.md`.
//!
//! - [`vocabulary`] — [`vocabulary::CapabilitySet`] and its three
//!   category types ([`vocabulary::AllocLevel`], [`vocabulary::IoLevel`],
//!   [`vocabulary::PtrLevel`]/[`vocabulary::PtrBound`]).
//! - [`inspector`] — [`inspector::BodyInspector`]/[`inspector::inspect_body`],
//!   the `syn::visit::Visit` walker that detects actual capability usage in
//!   a function body.
//! - [`lattice`] — [`lattice::Violation`]/[`lattice::check_subset`], the
//!   declared-vs-detected comparison `capability-attr` uses to decide
//!   whether to emit a `compile_error!`.

#![warn(missing_docs)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

pub mod inspector;
pub mod lattice;
pub mod render;
pub mod vocabulary;

pub use lattice::{check_subset, Violation};
pub use render::render_capability_args;
pub use vocabulary::{AllocLevel, CapabilitySet, IoLevel, PtrBound, PtrLevel};
