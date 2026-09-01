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
  detected. Not a guess. Only generated when the target crate's own
  `Cargo.toml` actually depends on `rusty-capability-attr` — this pass
  resolves the real extern crate name from the manifest and writes the
  attribute fully qualified (e.g. `#[rusty_capability_attr::capability(...)]`)
  rather than bare, and skips generation entirely (reported under
  `--report`) if the dependency isn't there, since a bare `#[capability(...)]`
  in a crate that doesn't depend on it fails to compile.
- **Taint attributes — heuristic.** There is no way to derive from a
  function body alone that a parameter is a password or that a function is
  a logging sink. This matches parameter/function names against a small,
  fixed keyword list — it will both miss real cases and flag false ones
  (a function named `handle_login` gets flagged as a sink candidate,
  because `"login"` contains `"log"`). **Review every generated taint
  attribute before trusting it.**

Both kinds run over **two different shapes of input**, matching the two
ways the rest of this workspace's taint tooling reads a `mod`:

- An inline `mod { ... }` block — the same shape `#[taint_check(...)]`
  itself expands for real, so generation there rewrites the whole mod in
  one piece.
- A file with no inline `mod` wrapper — the `mod foo;` multi-file layout
  `taint-check --crate`/`taint-refactor` are built for, where a file's own
  top-level items already stand in for that mod's children (see
  `crates/taint-check/src/crate_scan.rs`'s module docs). This pass can't
  reach the `#[taint_check(labels = [...])]` attribute itself in that case
  — it belongs on the `mod foo;` declaration in a *different* file this
  pass was never given — and `--report` prints a note telling you exactly
  where to add it by hand. **A label found in one file is visible to
  sink/sanitizer detection in every other file passed in the same
  invocation** (`taint-generate src/auth.rs src/logging.rs`, not one file
  at a time) — a sink can legitimately live in a different file than the
  sensitive parameter reaching it.

## Safety invariant

Neither pass ever touches a `fn`/`mod` that already carries *any*
annotation of the kind it's about to generate — a mod with one
`#[sensitive(...)]` already in it is skipped entirely, not partially
filled in. A previous run's own qualified `#[capability(...)]` output is
still recognized as curated on a later run.

## Usage

```sh
cargo install rusty-taint-generate
taint-generate src/auth.rs                    # writes changes directly
taint-generate src/auth.rs src/logging.rs     # multiple files share one label registry
taint-generate --dry-run src/auth.rs          # prints a before/after block, writes nothing
taint-generate --report src/auth.rs           # prints a summary of what was generated
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
