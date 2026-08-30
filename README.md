# rusty

[![build: passing](https://img.shields.io/badge/build-passing-brightgreen.svg)](#building-locally)
[![tests: 77 passed](https://img.shields.io/badge/tests-77%20passed-brightgreen.svg)](#building-locally)
[![coverage: 86.41%](https://img.shields.io/badge/coverage-86.41%25-yellow.svg)](#building-locally)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> Build/test/coverage badges above reflect the last local `cargo build
> --workspace` / `cargo test --workspace` / `cargo tarpaulin --workspace` run
> (2026-08-30) and are static — there is no CI pipeline wired up, so they
> will not update automatically on future commits. Re-verify locally before
> trusting them.

Compile-time safety layers for Rust that sit orthogonal to `unsafe`: one
enforces a function's side-effect *capabilities* (allocation / I/O / raw
pointers), another enforces *information flow* at the type level (classified
data can't accidentally leak through `Display`/serialization), and a third
extends that tracking past the type system's own boundary with AST-level
taint propagation. Independent crates, one workspace.

## Crates

| Crate | Version | Docs | What it does |
| --- | --- | --- | --- |
| [`rusty-capability-attr`](crates/capability-attr) | [![crates.io](https://img.shields.io/crates/v/rusty-capability-attr.svg)](https://crates.io/crates/rusty-capability-attr) | [![docs.rs](https://docs.rs/rusty-capability-attr/badge.svg)](https://docs.rs/rusty-capability-attr) | `#[capability(alloc(..), io(..), ptr(..))]` proc-macro attribute — declares and enforces a function's allocation/IO/raw-pointer scope at compile time (Layer 2, side-effect safety). |
| [`rusty-sensitive-ifc`](crates/sensitive-ifc) | [![crates.io](https://img.shields.io/crates/v/rusty-sensitive-ifc.svg)](https://crates.io/crates/rusty-sensitive-ifc) | [![docs.rs](https://docs.rs/rusty-sensitive-ifc/badge.svg)](https://docs.rs/rusty-sensitive-ifc) | `Sensitive<T, L>` / `Redacted<T>` newtypes — type-system Information Flow Control, zero proc-macro (Layer 3, semantic/policy safety, Phase 1). |
| [`rusty-taint-check`](crates/taint-check) | [![crates.io](https://img.shields.io/crates/v/rusty-taint-check.svg)](https://crates.io/crates/rusty-taint-check) | [![docs.rs](https://docs.rs/rusty-taint-check/badge.svg)](https://docs.rs/rusty-taint-check) | Shared AST-inspection logic for `taint_check`'s label-propagation pass, plus the standalone `taint-check` CLI binary (Layer 3, Phase 2 — closes `sensitive-ifc`'s documented gap). |
| [`rusty-taint-check-macros`](crates/taint-check-macros) | [![crates.io](https://img.shields.io/crates/v/rusty-taint-check-macros.svg)](https://crates.io/crates/rusty-taint-check-macros) | [![docs.rs](https://docs.rs/rusty-taint-check-macros/badge.svg)](https://docs.rs/rusty-taint-check-macros) | `#[taint_check(labels = [...])]` proc-macro attribute — thin wrapper over `rusty-taint-check`, turns a taint violation into a real `compile_error!(...)`. |

`crates/path-match` is a fourth, internal-only workspace member
(`publish = false`) — small `syn::Path`-matching helpers shared between
`capability-attr` and `taint-check`, with no public API of its own.

Design background lives in `docs/aisecurity/capability-rfc-updated.md`,
`docs/aisecurity/ifc-rfc.md`, `rfcs/0003-taint-check.md`, and
`docs/adr/ADR-0003-implement-taint-check-phase2.md`.

## Taint-check CLI

```sh
cargo install rusty-taint-check
taint-check src/auth.rs   # exits nonzero if a violation is found
```

See [`crates/taint-check`'s README](crates/taint-check/README.md) for the
`#[taint_check(...)]` syntax and a worked example.

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
cargo add rusty-taint-check-macros
cargo install rusty-taint-check   # CLI binary only
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
