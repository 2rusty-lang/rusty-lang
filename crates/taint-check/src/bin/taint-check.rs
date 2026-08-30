//! `taint-check` CLI entry point — see `taint_check::cli` for the real
//! logic; this is deliberately just an exit-code adapter around it.

// This bin target is its own crate root — see `taint_check`'s own
// `src/lib.rs` for the full explanation of this workspace-wide carve-out.
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

fn main() {
    std::process::exit(taint_check::cli::run(std::env::args()));
}
