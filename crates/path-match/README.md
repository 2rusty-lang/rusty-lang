# rusty-path-match

[![crates.io](https://img.shields.io/crates/v/rusty-path-match.svg)](https://crates.io/crates/rusty-path-match)
[![docs.rs](https://docs.rs/rusty-path-match/badge.svg)](https://docs.rs/rusty-path-match)

Internal-only `syn::Path` matching helpers (trailing-segment / last-two-segment
/ marker-anywhere-in-path matching) shared by
[`capability-core`](../capability-core)'s body inspector (matching
`Vec::new(...)` and `std::vec::Vec::new(...)` as the same call) and
[`taint-check`](../taint-check)'s sink/sanitizer call-path detection
(`self::log_debug(...)`, `super::log_debug(...)`, and a bare `log_debug(...)`
call all resolve to the same function).

Published only so those crates resolve on crates.io — **no public-API or
semver guarantee of its own**. Extracted purely to de-duplicate private
helpers neither crate ever exposed (see
`docs/adr/ADR-0003-implement-taint-check-phase2.md`).

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang) for
design background.

Licensed under Apache-2.0.
