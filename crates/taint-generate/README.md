# rusty-taint-generate

[![crates.io](https://img.shields.io/crates/v/rusty-taint-generate.svg)](https://crates.io/crates/rusty-taint-generate)
[![docs.rs](https://docs.rs/rusty-taint-generate/badge.svg)](https://docs.rs/rusty-taint-generate)

Auto-writes `#[capability(...)]` and `#[sensitive(...)]`/`#[taint_sink(...)]`/
`#[taint_sanitizer]`/`#[taint_check(labels = [...])]` directly into source
files, for functions/mods that have no existing annotation of that kind.

## Two very different kinds of "generate"

- **`#[capability(...)]` — deterministic.** Runs the exact same body
  inspector `capability-attr`'s own proc-macro uses to *verify* a declared
  capability set, and writes an attribute matching what was actually
  detected. Not a guess.
- **Taint attributes — heuristic.** There is no way to derive from a
  function body alone that a parameter is a password or that a function is
  a logging sink. This matches parameter/function names against a small,
  fixed keyword list — it will both miss real cases and flag false ones
  (a function named `handle_login` gets flagged as a sink candidate,
  because `"login"` contains `"log"`). **Review every generated taint
  attribute before trusting it.**

## Safety invariant

Neither pass ever touches a `fn`/`mod` that already carries *any*
annotation of the kind it's about to generate — a mod with one
`#[sensitive(...)]` already in it is skipped entirely, not partially
filled in.

## Usage

```sh
cargo install rusty-taint-generate
taint-generate src/auth.rs              # writes changes directly
taint-generate --dry-run src/auth.rs    # prints a before/after block, writes nothing
taint-generate --report src/auth.rs     # prints a summary of what was generated
taint-generate --dry-run --report src/auth.rs
```

Writing to disk is surgical, not a full-file reformat: only the exact byte
span of each changed `fn`/`mod` is replaced (via
[`rusty-source-edit`](../source-edit)) — everything else in the file is
untouched. Run `cargo fmt` afterward to normalize indentation on anything
that got rewritten.

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang) and
`docs/adr/ADR-0005-generate-and-refactor.md` for the design background.

Licensed under Apache-2.0.
