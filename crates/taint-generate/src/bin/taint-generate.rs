//! `taint-generate` CLI entry point — see `taint_generate::cli` for the
//! real logic; this is deliberately just an exit-code adapter around it.

#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

// `#[cfg(not(tarpaulin_include))]`: `cargo test` never executes a
// `[[bin]]` target's own `main` — only `#[test]` functions run. The real
// logic this forwards to (`taint_generate::cli::run`) is already
// exhaustively unit-tested; getting coverage credit for this literal line
// would need spawning the compiled binary as a subprocess
// (`CARGO_BIN_EXE_taint-generate`), a pattern this workspace doesn't
// otherwise use, for a one-line adapter.
#[cfg(not(tarpaulin_include))]
#[capability_attr::capability(alloc(none), io(none), ptr(none))]
fn main() {
    std::process::exit(taint_generate::cli::run(std::env::args()));
}
