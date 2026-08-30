//! Real trybuild UI tests for `#[taint_check(...)]` — proves the positive
//! case (a sanitized flow compiles clean) and both negative cases from
//! `rfcs/0003-taint-check.md`'s guide-level example (a direct flow, and a
//! one-level-indirect flow through a `let`) produce a real
//! `compile_error!(...)`, not just a description of one.
//!
//! Run `TRYBUILD=overwrite cargo test -p rusty-taint-check-macros --test ui`
//! to regenerate the checked-in `.stderr` snapshots after an intentional
//! error-message wording change.

#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/pass/*.rs");
    t.compile_fail("tests/ui/fail/*.rs");
}
