# rusty-source-edit

[![crates.io](https://img.shields.io/crates/v/rusty-source-edit.svg)](https://crates.io/crates/rusty-source-edit)
[![docs.rs](https://docs.rs/rusty-source-edit/badge.svg)](https://docs.rs/rusty-source-edit)

Internal-only surgical source rewriting: replace exactly one `syn::Item`'s
byte span with a re-printed, mutated version of itself via `prettyplease`,
leaving the rest of the file byte-identical. Shared by
[`taint-generate`](../taint-generate) and [`taint-refactor`](../taint-refactor)
so neither silently reformats a whole file just to add one attribute or one
call.

Published only so those crates resolve on crates.io — **no public-API or
semver guarantee of its own** (see
`docs/adr/ADR-0005-generate-and-refactor.md`).

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang) for
design background.

Licensed under Apache-2.0.
