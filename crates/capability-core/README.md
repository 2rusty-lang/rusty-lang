# rusty-capability-core

[![crates.io](https://img.shields.io/crates/v/rusty-capability-core.svg)](https://crates.io/crates/rusty-capability-core)
[![docs.rs](https://docs.rs/rusty-capability-core/badge.svg)](https://docs.rs/rusty-capability-core)

Internal-only: the capability vocabulary (`AllocLevel`, `IoLevel`,
`PtrLevel`/`PtrBound`, `CapabilitySet`, and the mod-/crate-level
`CapabilityCeiling`/`IoCeiling` — see
`rfcs/0008-capability-mod-and-crate-level.md`), the `syn::visit::Visit`-based
body-usage inspector, and the declared-vs-detected subset check shared by:

- [`capability-attr`](../capability-attr) — the `#[capability(...)]`
  proc-macro itself (function- and mod-level).
- [`taint-generate`](../taint-generate) — auto-writes a `#[capability(...)]`
  matching a function's real, detected usage instead of guessing one.
- [`taint-check`](../taint-check) — RFC 0007's crate-wide declared-vs-derived
  `--capabilities` check.

Published only so those crates resolve on crates.io — **no public-API or
semver guarantee of its own**. Extracted from `capability-attr`'s own
private modules, which a `proc-macro = true` crate could never expose to
begin with (see `docs/adr/ADR-0005-generate-and-refactor.md`).

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang),
`rfcs/0001-capability-attr.md`, `rfcs/0007-capability-manifest.md`, and
`rfcs/0008-capability-mod-and-crate-level.md` for design background.

Licensed under Apache-2.0.
