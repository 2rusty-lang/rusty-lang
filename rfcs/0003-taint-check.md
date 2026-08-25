---
feature: taint_check
start_date: 2026-08-24
status: proposed
tracking_issue:
---

# Summary

`taint-check` is a proc-macro attribute system — `#[taint_check(labels = [...])]`,
`#[sensitive(label)]`, `#[taint_sink(label, policy = "...")]`, `#[taint_sanitizer]` —
that extends `sensitive-ifc`'s type-level tracking with AST-level taint propagation,
catching classified data that reaches a forbidden sink through an intermediate
variable, not just a direct `Sensitive<T, L>` unwrap-and-use.

# Motivation

`sensitive-ifc` (`rfcs/0002-sensitive-ifc.md`) ships Phase 1: `Sensitive<T, L>` makes
it a compile error to `Display`/`format!`/serialize a classified value directly. It
has a documented gap, acknowledged in that RFC and in `docs/adr/ADR-0001`: once code
calls `into_inner_explicitly()`, the raw value is unwrapped and the type system loses
track of it. This compiles today and should not:

```rust,ignore
let msg = format!("{}", password.into_inner_explicitly());
log(msg); // credential reaches a log sink; Phase 1 cannot see this.
```

`taint_check` closes that gap without requiring a full MIR-level data-flow pass
(deferred as Phase 3, out of scope here): a proc-macro AST walk that tracks labeled
values through a function body — including through intermediate variables — and
flags any that reach a `#[taint_sink]` without passing through a `#[taint_sanitizer]`.

# Guide-level explanation

```rust,ignore
#[taint_check(labels = [password, session_token])]
mod auth {
    fn handle_login(#[sensitive(password)] password: &str) {
        let echoed = password.to_string();       // still tainted
        log_debug(&echoed);                        // COMPILE ERROR: reaches a sink
    }

    #[taint_sink(password, policy = "no_sensitive")]
    fn log_debug(msg: &str) { println!("{msg}"); }
}
```

`#[taint_check]` enables AST-level taint inspection for everything in its scope
(a function or a module). `#[sensitive(label)]` marks a value as carrying a
classification. `#[taint_sink(label, policy = "...")]` marks a function as a
forbidden destination for that label. `#[taint_sanitizer]` marks a function whose
output is no longer considered tainted (e.g. a redaction/masking helper) — passing
a labeled value through one clears the label before it reaches a sink.

This is a *shallow* AST-level pass, not full data-flow analysis: it catches direct
and one-level-indirect flows within its scope (assignment through a local variable,
as in `echoed` above), not taint carried across arbitrary indirection, closures
captured elsewhere, or flows that cross module boundaries outside `#[taint_check]`'s
scope.

# Reference-level explanation

- `#[taint_check]` is a `#[proc_macro_attribute]` applied to a `mod` or `fn` item.
  It parses its `labels = [...]` argument, then AST-walks (`syn::visit::Visit`) the
  annotated item looking for `#[sensitive(label)]`-marked bindings and tracing them
  through subsequent local-variable assignments within the same scope.
- Reaching a call to a function marked `#[taint_sink(label, policy = "...")]` with a
  value still carrying `label` is a `compile_error!` at that call site, naming the
  label and the sink's policy.
- Passing a tainted value through a function marked `#[taint_sanitizer]` clears the
  label from its return value going forward.
- This composes with, but does not replace, `sensitive-ifc` Phase 1: `Sensitive<T, L>`
  remains the boundary at which data enters classified tracking in the first place;
  `taint_check` extends tracking past the point where Phase 1's type-level guarantee
  ends (`into_inner_explicitly()`).
- Ships as its own crate — a lib exposing the proc-macros, plus a thin CLI binary
  that runs the same AST inspection standalone (e.g. over a target module/crate in
  CI, without requiring every caller to add the crate as a proc-macro dependency).

# Drawbacks

- Shallow AST tracking, not true data-flow: taint that crosses closures, threads,
  channels, trait-object dispatch, or module boundaries outside a `#[taint_check]`
  scope is not tracked and will not be caught.
- A proc-macro-driven pass adds another compile-time dependency and another place a
  macro-expansion error can be confusing to a contributor unfamiliar with it.
- Label policy strings (`policy = "no_sensitive"`) are free-form at this stage; no
  central registry enforces consistent policy naming across sinks yet.

# Rationale and alternatives

- Phase 3 (MIR-level, `rustc_private`, nightly-only) would close the shallow-tracking
  gap entirely, but is explicitly out of scope for a stable-Rust, workspace-local
  tool — the same reasoning `rfcs/0001-capability-attr.md` and `0002-sensitive-ifc.md`
  already apply to their own phase boundaries.
- Leaving the gap unaddressed (status quo, per `docs/adr/ADR-0001`) is the fallback
  if this RFC isn't accepted — code review remains the only backstop for taint that
  survives `into_inner_explicitly()`.
- An external static-analysis tool (e.g. a CodeQL query) could catch some of the same
  flows without touching the build, at the cost of not failing `cargo build` directly
  and requiring a separate CI step to be wired up and kept in sync with the codebase.

# Prior art

`sensitive-ifc` (`rfcs/0002-sensitive-ifc.md`) is the direct precedent this RFC
extends. `capability-attr` (`rfcs/0001-capability-attr.md`) established the pattern
of an AST-walking proc-macro attribute checking declared-vs-actual behavior at
compile time, which this RFC reuses for taint labels instead of capability scopes.
Broader prior art is the same as `sensitive-ifc`'s: language-level Information Flow
Control research (JIF, Flow Caml) and annotation-driven taint tracking as used by
static analyzers more generally.

# Unresolved questions

- Whether standard-library functions (`format!`, `to_string()`, arithmetic) should
  propagate taint conservatively (any tainted input taints the output) or
  permissively (only functions explicitly annotated propagate) — see the same open
  question already flagged for this design in `docs/adr/ADR-0001`'s context.
- How taint tracking should behave across generic functions, where the proc-macro
  cannot see monomorphized instantiations.
- Whether sink policy strings need a central registry/enum rather than free-form
  strings, once more than a couple of policies exist.

# Future possibilities

- A shared policy registry so `#[taint_sink(label, policy = "...")]` strings are
  checked against a known set rather than being free-form.
- Phase 3 (MIR-level, nightly-only) as a separate, later RFC if the shallow pass
  proves insufficient in practice.
