//! `taint-generate` CLI entry point — see `taint_generate::cli` for the
//! real logic; this is deliberately just an exit-code adapter around it.

#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

fn main() {
    std::process::exit(taint_generate::cli::run(std::env::args()));
}
