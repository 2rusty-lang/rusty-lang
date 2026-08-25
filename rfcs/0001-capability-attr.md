---
feature: capability_attr
start_date: 2026-08-24
status: accepted
tracking_issue:
---

# Summary

`capability-attr` is a proc-macro attribute, `#[capability(alloc(..), io(..), ptr(..))]`,
that lets a function declare the allocation / I/O / raw-pointer scope it needs, and fails
the build with a real `compile_error!(...)` if the function body exceeds what it declared.

# Motivation

Rust's safety model is binary: a function is `safe` or `unsafe`. Real systems code spans
a spectrum that `unsafe` collapses into one signal — reading a bounded buffer and writing
an arbitrary raw pointer are both just "unsafe" to the compiler, even though their risk
profiles are wildly different. Reviewers and auditors are left re-deriving, by hand, what
side effects an `unsafe` (or even nominally safe) function actually performs.

`#[capability(...)]` gives that spectrum a machine-readable, compiler-enforced structure:
the declaration *is* the audit surface, and it can't silently drift from the implementation
because the macro checks it on every build.

# Guide-level explanation

A function opts in by declaring its capability scope:

```rust
#[capability(alloc(none), io(none), ptr(none))]
fn quiet_fn() {
    // COMPILE ERROR if this allocates, does I/O, or touches a raw pointer.
}

#[capability(alloc(heap), io(display), ptr(none))]
fn log_message(msg: &str) {
    let buf: Vec<u8> = msg.bytes().collect(); // heap alloc: declared, OK
    println!("{}", buf.len());                // io(display): declared, OK
}
```

The macro walks the function body (via a `syn::visit::Visit` walker) looking for actual
capability usage, and compares it against what was declared. Anything used-but-undeclared
becomes a `compile_error!` at the call site, with the specific violation named.

This is orthogonal to `unsafe`, not a replacement for it: `unsafe` remains the programmer's
memory-safety promise; `#[capability(...)]` is the compiler's side-effect-scope promise.
See the companion `sensitive-ifc` crate for the next layer up — semantic/policy safety
(does this function leak a credential, not just "does it do I/O").

# Reference-level explanation

- Declared capabilities are parsed from the attribute's arguments at macro-expansion time.
- `inspector::BodyInspector` walks the annotated function's body with `syn::visit::Visit`
  to detect actual capability usage (allocation calls, I/O calls, raw-pointer expressions).
- `lattice::check_subset` compares detected usage against declared scope; anything not a
  subset is a violation.
- `error::emit_violation` turns each violation into a `compile_error!(...)` at the relevant
  span, so failures point at the offending expression, not just the function signature.

This first pass is scoped to **function items only**. Module/trait/impl/crate-level
declarations with hierarchical narrowing (a module's declaration bounding every function
inside it, a trait's declaration bounding every `impl`) are out of scope for this phase —
that requires tracking capability state across multiple macro-expansion sites, which a
single per-function proc-macro invocation can't do on its own.

# Drawbacks

- Proc-macro-based detection is necessarily heuristic at the syntax level (via `syn`), not
  a true data-flow analysis — it can't see through arbitrary indirection (a helper function
  that allocates on the caller's behalf isn't attributed back to the caller).
- Adds a compile-time dependency (`syn`/`quote`/`proc-macro2`) and a small amount of build
  time to every crate that uses the attribute.
- False positives/negatives are possible at the boundary of what the AST walker recognizes
  as an "allocation" or "I/O" expression; the lattice is only as complete as the walker.

# Rationale and alternatives

- A full MIR-level or `rustc_private`-based analysis would catch more (e.g. allocation
  through indirection) but requires nightly Rust and internal compiler APIs, which this
  project explicitly wants to avoid for a workspace-local, stable-Rust tool.
- Doing nothing and relying on `unsafe` alone loses the finer-grained signal entirely —
  it can't distinguish "reads a slice" from "writes an arbitrary pointer."
- A purely convention-based approach (comments, code review checklists) doesn't fail the
  build, so it drifts silently as code changes; this crate's whole point is making the
  declaration compiler-enforced.

# Prior art

Effect systems and capability-based security research (e.g. object-capability models,
effect typing in languages like Koka) explore similar ground at the language-design level.
This crate takes a narrower, pragmatic slice of that idea that fits on top of stable Rust
via a proc-macro, rather than requiring a new type system or compiler.

# Unresolved questions

- How module/trait/impl/crate-level declarations should compose once implemented (Phase 2).
- Where the line sits between "AST-visible capability usage" and usage hidden behind a
  helper function call — whether/how to propagate declared capabilities through call
  graphs without a full data-flow pass.

# Future possibilities

- Phase 2: module/trait/impl/crate-level declarations with hierarchical narrowing.
- Optional integration with `sensitive-ifc` so a capability violation and an information-flow
  violation can be reported through one consistent diagnostic path.
