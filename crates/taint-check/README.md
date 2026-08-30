# rusty-taint-check

[![crates.io](https://img.shields.io/crates/v/rusty-taint-check.svg)](https://crates.io/crates/rusty-taint-check)
[![docs.rs](https://docs.rs/rusty-taint-check/badge.svg)](https://docs.rs/rusty-taint-check)

Phase 2 of `sensitive-ifc`'s Information Flow Control story: a shallow,
AST-level taint-propagation pass that catches classified data reaching a
forbidden sink through an intermediate variable, not just a direct
`Sensitive<T, L>` unwrap-and-use. This crate hosts the shared inspection
logic plus a standalone `taint-check` CLI; the companion
[`rusty-taint-check-macros`](../taint-check-macros) crate is the
`#[taint_check(...)]` proc-macro attribute built on top of it.

## CLI usage

```sh
cargo install rusty-taint-check
taint-check src/auth.rs
```

```rust,ignore
#[taint_check(labels = [password])]
mod auth {
    fn handle_login(#[sensitive(password)] password: &str) {
        let echoed = password.to_string();       // still tainted
        log_debug(&echoed);                        // flagged: reaches a sink
    }

    #[taint_sink(password, policy = "no_sensitive")]
    fn log_debug(msg: &str) { println!("{msg}"); }
}
```

```text
$ taint-check src/auth.rs
src/auth.rs:4:9: taint violation: `password` reaches `log_debug` (policy "no_sensitive") without passing through a #[taint_sanitizer] first
```

The CLI parses the target file with `syn`, outside the compiler — no
proc-macro dependency needed, so it can run in CI over files a crate
doesn't necessarily build against `rusty-taint-check-macros`.

## Scope

`#[taint_check]` (and the CLI's scan) recognizes the attribute on `mod`
items only. Taint propagates through a direct parameter, a `let`
reassignment, a method call on a tainted value, or (conservatively) any
other function call with a tainted argument — and clears once passed
through a `#[taint_sanitizer]`, the only thing that stops it. It does
**not** track flows through `format!`, closures, threads, or module
boundaries outside the annotated `mod` — see the crate's own module docs
for the full honest scope statement, and `rfcs/0003-taint-check.md` /
`docs/adr/ADR-0003-implement-taint-check-phase2.md` for the design
background.

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang).

Licensed under Apache-2.0.
