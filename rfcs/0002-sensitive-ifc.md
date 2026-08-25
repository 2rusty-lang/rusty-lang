---
feature: sensitive_ifc
start_date: 2026-08-24
status: accepted
tracking_issue:
---

# Summary

`sensitive-ifc` is a type-system Information Flow Control (IFC) crate: `Sensitive<T, L>`
and `Redacted<T>` newtypes that make it a compile error to accidentally `Display`,
`format!`, or serialize a value carrying a classification like "credential" or "secret".

# Motivation

Rust's borrow checker proves memory safety. A companion `#[capability(...)]` system
(`capability-attr`, this crate's sibling) can prove a function's declared side-effect scope
(allocation, I/O, raw-pointer access) isn't exceeded. Neither layer catches this:

```rust,ignore
// Memory safe. io(display) is accurately declared. Still wrong: a plaintext
// credential flows straight to a log sink.
fn log_auth_event(user: &str, password: &str) {
    println!("AUTH: user={user} password={password}");
}
```

The violation is in the *meaning* of the data, not its memory layout or declared side
effects. `password` carries a classification — "must never reach an unredacted output
sink" — that a plain `&str` can't express. This crate encodes that classification in the
type system, so the mistake above becomes a compile error instead of a runtime leak.

# Guide-level explanation

Wrap classified data in `Sensitive<T, L>` at the point it enters the program (e.g. reading
a credential from config or a request):

```rust,ignore
let password: Sensitive<String, Credential> = Sensitive::new(raw_password);

println!("{}", password); // COMPILE ERROR: Sensitive<T, L> does not implement Display.
log_auth_event(&password); // COMPILE ERROR if the callee expects an unwrapped &str.
```

To use the value, code must explicitly unwrap it (`into_inner_explicitly`), which is a
visible, greppable escape hatch rather than something that happens by accident — the
compile error is the point, and the explicit unwrap is where a reviewer's attention should
go.

# Reference-level explanation

- **Phase 1 (this crate, shipped):** pure type-system IFC. `Sensitive<T, L>` deliberately
  does not implement `fmt::Display` or `serde::Serialize`. Zero proc-macro, zero extra
  tooling, zero runtime cost — the enforcement is entirely a property of the type not
  implementing the traits that would leak it.
- **Phase 2 (not built, this RFC does not implement it):** `#[taint_check]` /
  `#[sensitive(label)]` / `#[taint_sink(...)]` proc-macro-driven AST taint propagation,
  to catch taint that Phase 1 loses once `into_inner_explicitly` is called (e.g.
  `let msg = format!("{}", pw.into_inner_explicitly()); log(msg);` compiles today because
  the value has already been unwrapped).
- **Phase 3 (not built, explicitly out of scope for this crate):** MIR-level full data-flow
  analysis via `rustc_private` (nightly-only).

**What this crate catches today:** accidental `Display`/`format!`/serialization of a value
still wrapped in `Sensitive<T, L>` — a straightforward compile error.

**What this crate does not catch today:** taint that survives past
`into_inner_explicitly` (the escape hatch is visible in code review, but not
compiler-enforced once called), taint carried through intermediate variables after
unwrapping, or any transformation performed outside the type's own API.

# Drawbacks

- Phase 1 alone cannot track taint once a value is deliberately unwrapped — it relies on
  code review to catch misuse past that point, not the compiler.
- Every call site that legitimately needs the raw value (e.g. to actually send it to an
  auth provider) must call the explicit-unwrap escape hatch, which is friction by design
  but is still friction.
- Adds a wrapper type through the codebase wherever classified data flows, which is a
  larger surface-area change than a lint or a convention.

# Rationale and alternatives

- Convention-only approaches (naming credentials `_secret`, code-review checklists) don't
  fail the build and drift silently; this crate's entire value proposition is making the
  common mistake (accidental `Display`/logging) a compile error instead.
- Full MIR-level data-flow IFC (Phase 3) would close the Phase 1 gap (taint surviving past
  unwrap) but requires nightly `rustc_private`, which this project explicitly wants to
  avoid for a stable-Rust, workspace-local tool; Phase 1 is the stable-Rust slice of that
  larger design that ships value today.
- Doing nothing leaves the `log_auth_event` example above compiling silently, which is
  exactly the failure mode this crate exists to prevent.

# Prior art

Information Flow Control has a long research history (JIF, Flow Caml, language-level
taint tracking in various security-typed languages). This crate takes the narrowest slice
of that idea that fits as a library-only, stable-Rust newtype wrapper, rather than a
language extension or compiler modification.

# Unresolved questions

- How Phase 2's taint propagation should compose with Phase 1's newtype boundary, so
  taint that crosses `into_inner_explicitly` isn't simply lost.
- Whether/how to integrate with `capability-attr` so an IFC violation and a capability
  violation surface through one consistent diagnostic path.

# Future possibilities

- Phase 2: proc-macro-driven AST taint propagation across intermediate variables.
- Phase 3: MIR-level data-flow analysis (nightly-only), tracked separately if pursued.
