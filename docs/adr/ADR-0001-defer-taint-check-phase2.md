---
id: ADR-0001
title: Defer implementing the taint-check (Phase 2 IFC) proc-macro
status: accepted
date: 2026-08-24
supersedes: null
superseded_by: ADR-0003
---

# Context

`sensitive-ifc`'s own module docs describe a Phase 2: `#[taint_check]` /
`#[sensitive(label)]` / `#[taint_sink(...)]` proc-macro-driven AST taint
propagation, needed to catch taint that Phase 1's `Sensitive<T, L>` type
loses once a value is unwrapped via `into_inner_explicitly` (e.g. an
unwrapped credential formatted into a string and passed through an
intermediate variable before reaching a log call).

Both `capability-attr` and `sensitive-ifc` exist because Rust's `safe`/
`unsafe` split is a single binary label standing in for a much wider range
of actual risk, and disagreement over where that one label should sit can
stall real work for a decade. `allocator_api` (RFC 1398, 2015; tracking
issue rust-lang/rust#32838) is the concrete case: it lets `Vec<T>`,
`Box<T>`, and friends be generic over a custom allocator instead of the
global one — exactly what a `no_alloc`/bounded-allocator embedded target
needs. It has been nightly-only, unstabilized, for over ten years, in
large part because the `Allocator` trait's methods (`allocate`/`grow`/
`shrink`/`deallocate`) have never had settled agreement on whether they
should be `unsafe fn` (implementing the trait wrong can cause real memory
unsafety in every collection built on it) or safe `fn` (calling `.allocate()`
should stay as safe as calling `Vec::push`, matching how every other safe
abstraction hides its internal `unsafe` from callers). Once a trait like
this stabilizes its shape is effectively permanent, so the whole feature
sits blocked on resolving one yes/no question about one keyword.

`capability-attr`'s `alloc(...)` vocabulary is a way to jailbreak out of
that specific argument rather than resolve it. The question "should this
be safe or unsafe" only has to be asked at all because `unsafe` is
Rust's *only* machine-checked way to say "this needs extra scrutiny" —
it collapses allocation behavior, I/O, and raw-pointer access into one
undifferentiated flag, and "safe" narrowly means "the compiler can prove
the absence of undefined behavior," nothing more. A function can be
perfectly memory-safe and still allocate from the wrong pool, do I/O it
shouldn't, or leak a credential — none of which `unsafe`-or-not was ever
built to express. `#[capability(alloc(...), io(...), ptr(...))]` sits
orthogonal to the keyword: it doesn't argue `Allocator::allocate` should
be marked one way or the other, it lets a caller declare and enforce the
*actual* scope it's using, regardless of how (or whether) that upstream
debate ever resolves. `sensitive-ifc` applies the same move one layer up,
for data classification rather than side-effect scope. Neither crate is
waiting on `allocator_api`'s stabilization or on the field settling what
"unsafe" should mean; both sidestep the disagreement rather than pick a
side in it.

# Decision

Do not implement taint-check now. Track it as a TODO, designed in its own
RFC (`rfcs/0003-taint-check.md`) rather than folded into `sensitive-ifc`'s
existing RFC (`0002-sensitive-ifc.md`) after the fact. When picked up, it
ships as three crates, not one, because of a real Cargo constraint: a
`proc-macro = true` lib can only export macro entry points, so the shared
inspection logic can't live in the same crate as both the macro and a
standalone CLI (the same reason `serde`/`serde_derive` and
`thiserror`/`thiserror-impl` are split):

- `crates/taint-check` — ordinary lib, not a proc-macro. Attribute-argument
  parsing, the `syn::visit::Visit`-based inspector that tracks labeled
  bindings through local assignments, and the sink/sanitizer policy check.
  Also hosts the `[[bin]]` CLI target, since only this crate is unrestricted
  — the CLI parses a target file with `syn::parse_file` outside the
  compiler and runs the same inspector standalone, reporting violations
  instead of failing a build, for CI use without a proc-macro dependency.
- `crates/taint-check-macros` — `proc-macro = true`, thin: parses the
  attribute, calls into `taint-check`'s logic, turns violations into
  `compile_error!` token streams at the right span.

Both get the same `[lints.clippy] all/pedantic/nursery/cargo = "deny"` +
`[lints.rust] unexpected_cfgs` block `capability-attr`/`sensitive-ifc`
already hand-roll (can't use `[lints] workspace = true` alongside
overrides), `trybuild`-driven `tests/ui/{pass,fail}` fixtures with
committed `.stderr` golden files matching those two crates' existing test
shape, and an entry in the root `Cargo.toml`'s `[workspace] members`.
`rfcs/0003-taint-check.md`'s status moves `proposed` → `accepted` at the
point this is actually taken up.

# Consequences

Cost: `Sensitive<T, L>` (Phase 1, already shipped) stays exposed to its
documented gap — taint that survives past `into_inner_explicitly()` is not
compiler-caught until Phase 2 ships; catching it depends on code review in
the meantime.

