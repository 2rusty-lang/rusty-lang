//! Real trybuild UI tests for `#[capability(...)]` — proves both the
//! positive case (declared capabilities cover actual body usage, compiles
//! clean) and the negative case (undeclared capability usage produces a
//! real `compile_error!(...)`, not just a description of one).
//!
//! Run `TRYBUILD=overwrite cargo test -p capability-attr --test ui` to
//! regenerate the checked-in `.stderr` snapshots after an intentional
//! error-message wording change.

// `cargo_common_metadata` inspects every workspace member's `Cargo.toml`
// reachable from this crate's own dependency graph — see src/lib.rs's own
// carve-out doc comment for the full explanation (SPEC-00052 T0b). This
// integration test file is its own crate root, so it needs its own copy.
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope — see SPEC-00034 T6 / SPEC-00052 T0b"
)]

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/pass/*.rs");
    t.compile_fail("tests/ui/fail/*.rs");
}
