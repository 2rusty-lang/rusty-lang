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
//!
//! # Relationship to OS-level MAC (AppArmor/SELinux)
//!
//! Applying this tool's patches can make `taint-check` pass; it does not make
//! the process safe at runtime. The check it satisfies is source-level and
//! compile-time only, and the sanitizer it generates is a placeholder. Both
//! are layered with, not a substitute for, OS-level mandatory access control
//! (AppArmor/SELinux), which covers what they cannot — a compromised binary,
//! a dependency that never used the attributes, any process on the host not
//! built from this workspace. Keep (or add) an AppArmor/SELinux profile for
//! the resulting binary exactly as you would without this crate. See
//! `docs/adr/ADR-0002-position-vs-os-level-mac.md`.

#![warn(missing_docs)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

pub mod cli;
pub mod patch;
