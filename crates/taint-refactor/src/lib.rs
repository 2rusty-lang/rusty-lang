//! `taint-refactor` — given `taint-check`'s whole-crate scan
//! ([`taint_check::crate_scan`]), generates an applyable patch for every
//! occurrence of a `(label, sink)` violation pattern found anywhere in the
//! crate: a placeholder `#[taint_sanitizer]` plus a rewritten call site.
//!
//! **Read [`patch`]'s module docs before using this crate — it generates
//! actual code, not just structural attributes, and the generated
//! sanitizer is a naive placeholder that must be reviewed before being
//! trusted.** See `docs/adr/ADR-0005-generate-and-refactor.md` for the
//! decision to build this at all despite that risk.
//!
//! Reuses `taint-check`'s own module-resolution and interprocedural
//! tracking (`taint_check::crate_scan::scan_crate`) rather than
//! re-implementing whole-crate scanning here — the same registry that
//! finds a violation is what finding *every* occurrence of the same
//! pattern for the "refactor the whole crate" behavior depends on.

#![warn(missing_docs)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

pub mod cli;
pub mod patch;
