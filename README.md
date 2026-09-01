# rusty

[![build: passing](https://img.shields.io/badge/build-passing-brightgreen.svg)](#building-locally)
[![tests: 134 passed](https://img.shields.io/badge/tests-134%20passed-brightgreen.svg)](#building-locally)
[![coverage: 88.14%](https://img.shields.io/badge/coverage-88.14%25-yellow.svg)](#building-locally)
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
| [`rusty-taint-generate`](crates/taint-generate) | [![crates.io](https://img.shields.io/crates/v/rusty-taint-generate.svg)](https://crates.io/crates/rusty-taint-generate) | [![docs.rs](https://docs.rs/rusty-taint-generate/badge.svg)](https://docs.rs/rusty-taint-generate) | Auto-writes `#[capability(...)]` (deterministic) and taint attributes (heuristic) into unannotated source files. |
| [`rusty-taint-refactor`](crates/taint-refactor) | [![crates.io](https://img.shields.io/crates/v/rusty-taint-refactor.svg)](https://crates.io/crates/rusty-taint-refactor) | [![docs.rs](https://docs.rs/rusty-taint-refactor/badge.svg)](https://docs.rs/rusty-taint-refactor) | Generates an applyable patch (placeholder sanitizer + rewritten call site) for every occurrence of a taint violation found crate-wide. **Review its output before trusting it.** |

Three more workspace members are internal-only (published to crates.io
only so the crates above resolve their path dependencies there, with no
public-API/semver guarantee of their own): `crates/path-match`
(`syn::Path`-matching helpers shared by `capability-attr`/`taint-check`),
`crates/capability-core` (the capability vocabulary/inspector shared by
`capability-attr`/`taint-generate`), and `crates/source-edit` (surgical
single-item source rewriting shared by `taint-generate`/`taint-refactor`).

Design background lives in `docs/aisecurity/capability-rfc-updated.md`,
`docs/aisecurity/ifc-rfc.md`, `rfcs/0003-taint-check.md` through
`rfcs/0006-taint-refactor.md`, and `docs/adr/ADR-0003-implement-taint-check-phase2.md` /
`docs/adr/ADR-0005-generate-and-refactor.md`.

## Taint-check CLI

```sh
cargo install rusty-taint-check
taint-check src/auth.rs              # single file, exits nonzero on a violation
taint-check --crate src/lib.rs       # whole crate, cross-binding tracking
```

See [`crates/taint-check`'s README](crates/taint-check/README.md) for the
`#[taint_check(...)]` syntax and a worked example.

## Generating and fixing annotations

```sh
cargo install rusty-taint-generate rusty-taint-refactor
taint-generate src/auth.rs src/logging.rs      # populate missing attributes (sink/label may span files)
taint-check --crate src/lib.rs                 # find a violation
taint-refactor --dry-run --crate src/lib.rs    # preview a fix for every occurrence
```

Both tools default to writing changes directly; both support `--dry-run`
(preview, writes nothing) and `--report` (structured summary). See
[`crates/taint-generate`'s README](crates/taint-generate/README.md) and
[`crates/taint-refactor`'s README](crates/taint-refactor/README.md) —
**`taint-refactor` generates actual code with security implications and
must be reviewed before trusting its output.**

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
cargo install rusty-taint-check      # CLI binary only
cargo install rusty-taint-generate   # CLI binary only
cargo install rusty-taint-refactor   # CLI binary only
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
