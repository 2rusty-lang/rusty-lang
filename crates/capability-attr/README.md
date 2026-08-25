# rusty-capability-attr

[![crates.io](https://img.shields.io/crates/v/rusty-capability-attr.svg)](https://crates.io/crates/rusty-capability-attr)
[![docs.rs](https://docs.rs/rusty-capability-attr/badge.svg)](https://docs.rs/rusty-capability-attr)

Layer 2 (side-effect / capability safety) `#[capability(...)]` proc-macro
attribute for Rust: declares and enforces a function's allocation/IO/raw-pointer
scope at compile time, orthogonal to `unsafe`.

```rust,compile_fail
use capability_attr::capability;

// COMPILE ERROR: body allocates on the heap, but only `alloc(none)` was declared.
#[capability(alloc(none), io(none), ptr(none))]
fn quiet_fn() {
    let _buf: Vec<u8> = Vec::new();
}
```

```rust
use capability_attr::capability;

// Compiles clean — every operation in the body is within what was declared.
#[capability(alloc(heap), io(display), ptr(none))]
fn log_message(msg: &str) {
    let buf: Vec<u8> = msg.bytes().collect();
    println!("{}", buf.len());
}
```

`unsafe` remains the programmer's memory-safety promise (Layer 1, unchanged);
`#[capability(...)]` is the compiler's side-effect-scope promise layered on
top of it.

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang) and
`docs/aisecurity/capability-rfc-updated.md` for full design background.

Licensed under Apache-2.0.
