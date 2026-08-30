---
id: ADR-0003
title: Implement taint-check (Phase 2 IFC): CLI + proc-macro attribute system
status: accepted
date: 2026-08-30
supersedes: ADR-0001
superseded_by: null
---

# Context

`ADR-0001` deferred `taint-check` as a TODO, designed but not built, because
nothing was blocking on it yet — `sensitive-ifc`'s documented Phase 1 gap
(taint that survives `into_inner_explicitly()` is invisible to the type
system) was tracked but only backstopped by code review. That gap is now
being closed: this ADR records picking up exactly the design `ADR-0001`
already specified in `rfcs/0003-taint-check.md`.

# Decision

Build `taint-check` as `ADR-0001` designed it, with three refinements made
during implementation that weren't yet decided at design time:

- **Two new workspace crates**, not three despite `ADR-0001`'s "three
  crates, not one" phrasing (a slip in that ADR — its own bullet list only
  ever named two): `crates/taint-check` (ordinary lib + `[[bin]]` CLI) and
  `crates/taint-check-macros` (`proc-macro = true`, thin). Only
  `#[taint_check]` is a real `#[proc_macro_attribute]`; `#[sensitive(...)]`
  / `#[taint_sink(...)]` / `#[taint_sanitizer]` are inert markers that
  `#[taint_check]`'s expansion parses for its own bookkeeping and then
  strips before re-emitting the `mod` — so they never need registering as
  attribute macros in their own right, and rustc never has to resolve them
  post-expansion.
- **A third, unpublished shared crate**, `crates/path-match`
  (`rusty-path-match`, `publish = false`): the `syn::Path`-matching helpers
  `capability-attr`'s inspector already had privately (`path_to_string`,
  `path_last_two`, `path_has_segment`) were never public API — a
  `proc-macro = true` crate can only export its macro entry points to
  begin with — so extracting them cost no compatibility guarantee.
  `taint-check` uses the crate's one new addition,
  `path_last_segment`, to match a sink/sanitizer call by its trailing path
  segment (`self::log_debug`, `super::log_debug`, and bare `log_debug` all
  resolve the same), not just a single bare identifier.
- **Conservative, not permissive, propagation through an arbitrary function
  call.** `rfcs/0003-taint-check.md` left this an explicitly open question.
  Permissive (arbitrary calls never propagate) was tried first and
  rejected: it makes `#[taint_sanitizer]` inert; a sanitizer's job is to be
  the exception to a default that would otherwise keep propagating, and a
  default that already never propagates gives it nothing to except.
  Conservative propagation — `let x = some_fn(y);` taints `x` whenever `y`
  is tainted, unless `some_fn` is a registered `#[taint_sanitizer]` — is
  what makes the sanitizer attribute do real, observable work.

Everything else matches `ADR-0001`'s design as written: `#[taint_check]`
attaches to `mod` items only (a lone `fn` can't see a sibling sink
function); the CLI runs the identical inspector via `syn::parse_file`
outside the compiler; both crates replicate the workspace's
`[lints.clippy] all/pedantic/nursery/cargo = "deny"` block; `trybuild`
`tests/ui/{pass,fail}` fixtures with real, locally-generated `.stderr`
golden files back the macro; `rfcs/0003-taint-check.md`'s status moves
`proposed` → `accepted`.

# Consequences

Cost: `capability-attr` bumps `0.1.1` → `0.1.2` for a purely internal
refactor (switching to `path-match`, no behavior change) — a small,
otherwise-unmotivated churn on an already-published crate, taken to avoid
duplicating the same three helper functions a second time. Conservative
call-argument propagation is also a real false-positive surface: any
function call that merely *touches* a tainted argument (e.g. a logging
wrapper that takes `&str` and does nothing sensitive with it) now taints
its result too, unless explicitly sanitized — noisier than permissive
propagation would have been, accepted because the alternative silently
defeats `#[taint_sanitizer]` instead.

Buys: the gap `ADR-0001` left open (taint surviving
`into_inner_explicitly()`, uncaught until code review) is now caught by a
real `compile_error!` for the mod-scoped, one-level-indirect and
direct-flow cases the guide-level example describes, plus a standalone
`taint-check` CLI usable in CI without a proc-macro dependency. Still not
caught (unchanged from `rfcs/0003`'s own Drawbacks): taint through
closures, threads, trait-object dispatch, `format!`/string concatenation,
or across a module boundary outside the annotated `mod` — that remains
Phase 3 (MIR-level, nightly-only) territory.
