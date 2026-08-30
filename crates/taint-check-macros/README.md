# rusty-taint-check-macros

[![crates.io](https://img.shields.io/crates/v/rusty-taint-check-macros.svg)](https://crates.io/crates/rusty-taint-check-macros)
[![docs.rs](https://docs.rs/rusty-taint-check-macros/badge.svg)](https://docs.rs/rusty-taint-check-macros)

The `#[taint_check(labels = [...])]` proc-macro attribute: a thin wrapper
around [`rusty-taint-check`](../taint-check)'s AST-inspection logic that
turns a taint violation into a real `compile_error!(...)` at the offending
call site.

```rust,ignore
use taint_check_macros::taint_check;

#[taint_check(labels = [password])]
mod auth {
    fn handle_login(#[sensitive(password)] password: &str) {
        let echoed = password.to_string();       // still tainted
        log_debug(&echoed);                        // COMPILE ERROR: reaches a sink
    }

    #[taint_sink(password, policy = "no_sensitive")]
    fn log_debug(msg: &str) { println!("{msg}"); }
}
```

Only `#[taint_check]` itself is a real proc-macro attribute — it parses
`#[sensitive(...)]` / `#[taint_sink(...)]` / `#[taint_sanitizer]` as inert
helper markers, then strips them before re-emitting the `mod`, so rustc
never has to resolve them as attributes in their own right.

For the standalone CLI (no proc-macro dependency needed), see
[`rusty-taint-check`](../taint-check).

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang),
`rfcs/0003-taint-check.md`, and
`docs/adr/ADR-0003-implement-taint-check-phase2.md` for design background.

Licensed under Apache-2.0.
