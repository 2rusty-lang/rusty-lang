//! `taint-generate` — auto-writes `#[capability(...)]` and
//! `#[sensitive(...)]`/`#[taint_sink(...)]`/`#[taint_sanitizer]`/
//! `#[taint_check(labels = [...])]` directly into source files, for
//! functions/mods that have no existing annotation of that kind.
//!
//! # Two very different kinds of "generate"
//!
//! [`capability_gen`] is **deterministic**: it runs the exact same
//! `capability_core::inspector::inspect_body` that `capability-attr`'s own
//! proc-macro uses to *verify* a declared capability set, and writes an
//! attribute matching what was actually detected. There is no guessing —
//! the generated attribute is correct for the body as it stands.
//!
//! [`taint_gen`] is **heuristic**: there is no way to derive from a
//! function body alone that a parameter is a password or that a function
//! is a logging sink. It matches parameter/function names against a small,
//! fixed keyword list ([`heuristics`]) — a real, stated trade-off that will
//! both miss real cases and flag false ones. Every generated taint
//! attribute is a starting point, not a verified fact; review before
//! trusting it, same as this workspace already asks for every other
//! detection limit it documents.
//!
//! # The safety invariant both passes share
//!
//! Neither pass ever touches a `fn`/`mod` that already carries *any*
//! annotation of the kind it's about to generate — a mod with one
//! `#[sensitive(...)]` already in it is skipped entirely by [`taint_gen`],
//! not partially filled in. Curated code, even partially curated code, is
//! off-limits. See `docs/adr/ADR-0005-generate-and-refactor.md`.
//!
//! # Writing to disk without reformatting the whole file
//!
//! Both passes hand their proposed changes to `rusty-source-edit`, which
//! replaces only the exact byte span of the one item being changed and
//! leaves everything else in the file untouched — see that crate's own
//! docs for why a naive full-file `syn`+`prettyplease` round-trip would be
//! the wrong tool here.

#![warn(missing_docs)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

pub mod capability_gen;
pub mod cli;
pub mod heuristics;
pub mod taint_gen;
