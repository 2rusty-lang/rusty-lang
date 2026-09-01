# rusty-taint-refactor

[![crates.io](https://img.shields.io/crates/v/rusty-taint-refactor.svg)](https://crates.io/crates/rusty-taint-refactor)
[![docs.rs](https://docs.rs/rusty-taint-refactor/badge.svg)](https://docs.rs/rusty-taint-refactor)

Given one taint violation found by
[`rusty-taint-check`](../taint-check)'s whole-crate scan, re-scans the
entire crate for every occurrence of the same `(label, sink)` pattern and
generates an applyable patch for each: a placeholder `#[taint_sanitizer]`
plus a rewritten call site.

**This is the riskiest tool in the `rusty` workspace — read this whole
README before using it.** It generates actual code with security
implications, not just a structural attribute.

## Usage

```sh
cargo install rusty-taint-refactor
taint-refactor --crate src/lib.rs              # writes patches directly
taint-refactor --dry-run --crate src/lib.rs    # preview, writes nothing
taint-refactor --report --crate src/lib.rs     # summary of what changed
```

```rust,ignore
// before
fn handle_login(#[sensitive(password)] password: &str) {
    log_debug(password);
}
#[taint_sink(password, policy = "no_sensitive")]
fn log_debug(msg: &str) { println!("{msg}"); }

// after
fn handle_login(#[sensitive(password)] password: &str) {
    log_debug(__taint_refactor_redact_password(password));
}
#[taint_sink(password, policy = "no_sensitive")]
fn log_debug(msg: &str) { println!("{msg}"); }

#[taint_sanitizer]
fn __taint_refactor_redact_password(v: &str) -> String {
    "[REDACTED]".to_string()
}
```

## You must review the output

- **The generated sanitizer is a naive, fixed-string placeholder.** It has
  no idea whether `"[REDACTED]"` is the right redaction for this value or
  context. Replace it with real logic before trusting it.
- **Wrapping a value can change its type.** The example above needs a `&`
  added at the call site once you review it (`log_debug` takes `&str`, the
  placeholder returns `String`) — confirmed directly while building this
  tool, not a hypothetical. Re-run `cargo build`/`cargo test` after
  applying a patch.
- **Nested `mod { ... }` violations are skipped, not guessed at** —
  reported in `--report`'s output as skipped, not silently dropped. See
  `crates/taint-refactor/src/patch.rs`'s module docs for why.

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang),
`rfcs/0006-taint-refactor.md`, and
`docs/adr/ADR-0005-generate-and-refactor.md` for the design background.

Licensed under Apache-2.0.
