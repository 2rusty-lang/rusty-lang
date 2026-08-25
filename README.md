# rusty

[![CI](https://github.com/2rusty-lang/rusty-lang/actions/workflows/ci.yml/badge.svg)](https://github.com/2rusty-lang/rusty-lang/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Compile-time safety layers for Rust that sit orthogonal to `unsafe`: one
enforces a function's side-effect *capabilities* (allocation / I/O / raw
pointers), the other enforces *information flow* (classified data can't
accidentally leak through `Display`/serialization). Two independent crates,
one workspace.

## Crates

| Crate | Version | Docs | What it does |
| --- | --- | --- | --- |
| [`rusty-capability-attr`](crates/capability-attr) | [![crates.io](https://img.shields.io/crates/v/rusty-capability-attr.svg)](https://crates.io/crates/rusty-capability-attr) | [![docs.rs](https://docs.rs/rusty-capability-attr/badge.svg)](https://docs.rs/rusty-capability-attr) | `#[capability(alloc(..), io(..), ptr(..))]` proc-macro attribute — declares and enforces a function's allocation/IO/raw-pointer scope at compile time (Layer 2, side-effect safety). |
| [`rusty-sensitive-ifc`](crates/sensitive-ifc) | [![crates.io](https://img.shields.io/crates/v/rusty-sensitive-ifc.svg)](https://crates.io/crates/rusty-sensitive-ifc) | [![docs.rs](https://docs.rs/rusty-sensitive-ifc/badge.svg)](https://docs.rs/rusty-sensitive-ifc) | `Sensitive<T, L>` / `Redacted<T>` newtypes — type-system Information Flow Control, zero proc-macro (Layer 3, semantic/policy safety). |

Design background lives in `docs/aisecurity/capability-rfc-updated.md` and
`docs/aisecurity/ifc-rfc.md`.

## Building locally

Requires the pinned toolchain in `rust-toolchain.toml` (currently 1.88.0);
`rustup` will fetch it automatically.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Installing

```sh
cargo add rusty-capability-attr
cargo add rusty-sensitive-ifc
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
