---
feature: capability_hierarchical_declarations
start_date: 2026-09-29
status: proposed
tracking_issue:
---

# Summary

Let `#[capability(...)]` be declared once on a `mod` or once for a whole
crate (via `[package.metadata.rusty.capabilities]`, the same location
[RFC 0007](0007-capability-manifest.md) already proposes), as a *ceiling*
that every function inside it is checked against automatically — whether
or not that function carries its own attribute. A function may still
declare its own, narrower `#[capability(...)]` to keep a precise,
individual tripwire; it inherits the enclosing ceiling only when it
doesn't. Alongside this, `io` moves from one risk-ordered scale to a
set-valued declaration, so a ceiling can permit `network` without silently
also blessing `filesystem` just because `filesystem` ranks lower today.

# Motivation

Function-level `#[capability(...)]` ([RFC 0001](0001-capability-attr.md))
is precise but has an adoption cost proportional to function count: every
function needs its own declaration, including ones a codebase's own shape
makes almost universal. A REST-handler-style web service is the concrete
case — nearly every handler makes an outbound HTTP call as a matter of
what it *is* (a REST method mapped to a network-facing endpoint), a
smaller number touch a database, and a smaller number still touch the
filesystem. Requiring `io(network)` on every single handler is not
precision, it's boilerplate that obscures the functions where I/O
actually is the exception worth a reader's attention — the "one that
still reads a file" is more useful to see clearly than the "hundred that
all say `io(network)`."

Two structural gaps stand in the way of fixing this the obvious way:

- **No way to declare intent above the function.** RFC 0007 proposes a
  *crate*-level declaration, but nothing between "one function" and "one
  crate" exists — a web service with a REST layer and a separate,
  narrower storage layer in the same crate has no way to give those two
  areas different baselines.
- **The vocabulary can't express "broad but not that broad."** `io` today
  is one risk-ordered scale (`none < display < filesystem < network <
  process < any`, see `capability-core`'s vocabulary docs). Declaring
  `io(network)` — the natural ceiling for the REST-handler case above —
  silently also permits `filesystem`, `display`, everything ranked below
  it. RFC 0007 already names this as an open drawback for its own
  crate-level proposal ("a crate that needs network but no filesystem
  cannot say so"), but the same imprecision is live *today*, at the
  function level, for any function whose own declared ceiling happens to
  rank above something it later, silently, starts doing (a function
  declared `io(network)` that later gains an unrelated `std::fs::read`
  call passes `check_subset` unchanged, since `filesystem < network`).
  This RFC's motivating case just makes the cost of that imprecision much
  larger, because a shared ceiling covers many functions with genuinely
  different needs, not one function's own single coherent purpose.

# Guide-level explanation

**Mod-level**, new in this RFC — same syntax as today's function-level
attribute, attached to a `mod` instead:

```rust
#[capability(alloc(heap), io(network: yes, filesystem: no), ptr(none))]
mod handlers {
    // No attribute needed — checked against the mod's ceiling.
    fn get_user(id: u64) -> User {
        http_client::get(&format!("/users/{id}")).json()
    }

    // Also no attribute — same ceiling covers this one too.
    fn list_orders(user: u64) -> Vec<Order> {
        http_client::get(&format!("/users/{user}/orders")).json()
    }

    // This one still wants its own, narrower tripwire — it never touches
    // I/O at all, and an explicit declaration keeps that visible and
    // enforced even as sibling functions change.
    #[capability(alloc(none), io(none), ptr(none))]
    fn validate_order(order: &Order) -> bool {
        order.total > 0 && !order.items.is_empty()
    }

    // COMPILE ERROR: `std::fs::write` needs `filesystem`, and the mod's
    // ceiling explicitly excludes it — this is exactly the boundary the
    // set-valued `io` below exists to keep visible.
    fn export_receipt(order: &Order) {
        std::fs::write("receipt.txt", order.to_string()).unwrap();
    }
}
```

**Crate-level**, extending RFC 0007's `[package.metadata.rusty.capabilities]`
with the same set-valued shape:

```toml
[package.metadata.rusty.capabilities]
alloc = "heap"
io = { network = "yes", filesystem = "no", process = "no" }
ptr = "none"
```

**Set-valued `io`.** Instead of one level, a ceiling declares each
category independently as permitted or not:

```
io(network: yes, filesystem: no, process: no, display: yes)
```

A category left unmentioned defaults to `no` (most restrictive — same
default-to-`none` principle RFC 0001 already uses for an omitted
function-level category). This is additive, not a breaking change to
existing syntax: a bare `io(<level>)` — the current single-level form —
keeps its current meaning at the **function** level, where one coherent
declaration per function has proven adequate in the four crates already
dogfooded ([ADR-0002](../docs/adr/ADR-0002-position-vs-os-level-mac.md)'s
scope). The set-valued form is required at mod- and crate-level, where a
declaration covers many functions with genuinely different needs — see
Unresolved Questions for why this RFC doesn't force the same change onto
function-level declarations.

**Resolution order** for a given function: its own explicit
`#[capability(...)]` if present (checked exactly as RFC 0001 already
does); otherwise the nearest enclosing `mod`'s ceiling; otherwise the
crate's ceiling; otherwise — same as today — nothing is declared and
nothing is checked. A function's own explicit declaration may be
*narrower* than what it inherits (as `validate_order` is, above) freely.
Whether it may be *wider* than an enclosing ceiling is deliberately left
open — see Unresolved Questions.

# Reference-level explanation

- **Mod-level attachment is mechanically proven already**, by
  `taint-check-macros`: a `#[proc_macro_attribute]` applied to a `mod`
  receives that mod's *entire* token tree — every nested item — in one
  invocation, which is exactly the visibility a mod-level ceiling needs.
  `capability-attr`'s own crate docs currently group mod-level in with
  crate/trait/impl-level under one "requires tracking capability state
  across multiple macro-expansion sites" deferral; that reasoning is
  accurate for crate-level (below) but not for mod-level, which needs no
  cross-invocation state at all — a single invocation already sees
  everything it needs to check.
- **`capability-attr` gains mod-item handling.** Where
  `capability::capability` today does `syn::parse::<ItemFn>(item)` and
  rejects anything else (`crates/capability-attr/src/lib.rs`), it would
  additionally accept `syn::parse::<ItemMod>(item)`: walk every nested
  `Item::Fn` (not recursing into a nested `mod`, matching
  `capability_gen`'s existing "top-level only, this pass" scope, extended
  one level), skip any that carry their own `#[capability(...)]`, run
  `capability_core::inspector::inspect_body` on the rest and check against
  the mod's declared ceiling with the new set-valued
  [`capability_core::check_subset`].
- **Crate-level reuses RFC 0007's machinery wholesale** — manifest
  parsing, the `taint-check --crate --capabilities` derivation pass
  (`capability_core::inspector::inspect_body` run over every function
  `crate_scan` finds), the `--update`/`--allow-widen`/draft-flag flow.
  This RFC only changes the *shape* of the value on both sides of that
  comparison (set-valued `io` instead of one level), not the
  declared-vs-derived mechanism itself.
- **`IoLevel` becomes a set.** `capability-core::vocabulary` currently
  represents `io` as one `enum IoLevel` ordered by `risk_level()`. A
  set-valued ceiling needs a `IoCapabilities { display: bool, filesystem:
  bool, network: bool, process: bool }`-shaped type (or equivalent
  bitset) instead, with `check_subset` becoming a per-flag subset check
  rather than a single ordinal comparison. Rendering
  (`capability_core::render_capability_args`, used by `taint-generate` to
  write suggested attributes) needs the equivalent update for whichever
  granularity (function vs. mod/crate) it's rendering for.
- **`taint-generate` gains a mod-aware mode.** Today's `capability_gen`
  only ever looks at top-level `fn`s (`crates/taint-generate/src/
  capability_gen.rs`'s own doc: "a function nested inside a `mod` is left
  to `crate::taint_gen` instead"). A mod-level ceiling changes what
  "needs a suggestion" means: instead of suggesting one attribute per
  function, it would suggest one ceiling for the mod (the union of every
  nested function's detected usage) plus flag which functions, if any,
  fall meaningfully below that union and might want to keep an explicit,
  narrower attribute of their own.

# Drawbacks

- **Coarser regression detection, by design.** A shared ceiling means a
  function can start doing something new without tripping anything, as
  long as it's still within what the ceiling already permits for a
  *different* function in the same mod. This is the real cost flagged in
  this same conversation before drafting the RFC: precision is being
  traded for reduced declaration burden, not gained for free. The
  per-function override exists specifically so anyone who wants the old,
  precise tripwire back on a specific function can keep it.
- **Two vocabularies, not one.** Function-level keeps the existing
  single-level `io(<level>)`; mod/crate-level requires the new set-valued
  form. A contributor has to know which applies where. An alternative
  (migrate function-level too) is discussed and rejected below, but the
  inconsistency itself is a real ongoing cost — two shapes of the same
  concept to teach and maintain parsers/renderers for.
- **`capability-attr` grows real complexity.** Accepting `ItemMod` roughly
  doubles what the macro's single entry point has to handle, and the
  set-valued `io` type change ripples through `capability-core`'s
  vocabulary, render, and lattice modules, plus every existing caller of
  the current `IoLevel` (`taint-generate`'s `capability_gen` and
  `top_level`, at minimum).
- **Same "derived is only as good as the detector" ceiling as RFC 0007.**
  A mod- or crate-level ceiling is exactly as blind to indirection
  (helper-function calls, trait objects, macro-expanded I/O) as the
  existing function-level detector — see this repo's own worked example
  of that gap. Widening the *scope* a declaration covers doesn't widen
  what the underlying detector can see.

# Rationale and alternatives

- **Set-valued `io` only at mod/crate level, not function level.**
  Considered making the vocabulary change uniform everywhere instead
  (cleaner, one shape to learn). Rejected for this RFC: it would be a
  breaking change to the crates already dogfooded with the current
  function-level syntax (`source-edit`, `taint-check-macros`,
  `taint-generate`, `taint-refactor`, `sensitive-ifc`, `taint-check`),
  for a problem that mostly bites at wider scope (one
  function usually has one coherent I/O purpose; a whole mod's declared
  ceiling covers many). Left as an explicit unresolved question below
  rather than closed, since the asymmetric quirk described in Motivation
  is real at function level too, just smaller in practice.
- **Mod-level as a real macro feature, not a lint or external tool.**
  Considered doing this the way RFC 0007's crate-level check works — an
  external `taint-check`-style CLI pass, not a proc-macro — to sidestep
  `capability-attr` growing more complexity. Rejected because mod-level,
  unlike crate-level, is not blocked by the "a proc-macro only sees its
  own item" wall (see Reference-level explanation) — building it as a
  real compile-time macro gets a real `compile_error!` at the actual
  call site during a normal `cargo build`, the same guarantee
  function-level declarations already give, rather than a separate CLI
  step someone has to remember to run.
- **Impact of not doing this:** the status quo stands — every function
  needing coverage needs its own explicit declaration, which is real
  friction in exactly the shape of codebase (many structurally-similar
  handler functions) where `#[capability(...)]` would otherwise be most
  worth adopting widely.

# Prior art

- **OS-level MAC (AppArmor/SELinux) is scoped to a whole process, not a
  function** — not by choice but because the OS genuinely cannot
  distinguish "this call stack may reach the network, that one may not"
  within one address space. This RFC's mod/crate ceiling is the same
  coarsening move, one level down from "whole binary" to "whole module,"
  for the same practical reason: not every unit of code review needs
  its own declaration to still be worth declaring something.
- **Capability inheritance / stack-based access control** (the historical
  Java `SecurityManager` model, `AccessController.doPrivileged`): a
  broader ambient permission set applies by default, and code can
  explicitly narrow (or, there, explicitly re-widen within a privileged
  block) for a specific operation. The narrowing half of that shape —
  not the re-widening half — is what this RFC's per-function override
  borrows.
- **[RFC 0007](0007-capability-manifest.md) itself** is the direct
  ancestor of the crate-level half of this proposal; this RFC is written
  as an extension of it (reusing its declared-vs-derived machinery)
  rather than a replacement, and inherits its drawbacks around the
  detector's blindness to indirection.

# Unresolved questions

- Should function-level declarations eventually adopt the same
  set-valued `io` shape, closing the asymmetric quirk that already
  exists there today? This RFC deliberately doesn't force that as part
  of adding mod/crate-level, to avoid a breaking change bundled with a
  purely additive feature — but the inconsistency it leaves behind (two
  vocabularies) is real, see Drawbacks.
- Can a function's own explicit declaration be *wider* than its enclosing
  ceiling, or is the ceiling a hard cap? The guide-level example only
  shows narrowing. Allowing widening needs the same
  `--allow-widen`-style friction RFC 0007 already applies to crate-level
  widening, shown at the point of the function's own declaration; not
  allowing it at all is simpler but means a function that genuinely needs
  more has to force a visible change to the *enclosing* declaration
  instead, which may be the more honest place for that diff to show up.
  Left open pending real usage.
- Does a mod-level ceiling apply to a nested `mod` inside it, or does
  each nested `mod` need its own? Given `capability_gen`'s existing
  "top-level only, this pass" precedent, this RFC's default assumption is
  "each `mod` needs its own, no automatic recursion" — but that's exactly
  the "hierarchical narrowing" `capability-attr`'s own docs describe as
  real and deferred, so it may be worth resolving alongside this RFC
  rather than after it.
- Interaction with RFC 0007's draft/widen flow when both a mod-level and
  a crate-level ceiling exist and disagree — which one does `--update`
  target, and does a crate-level `--allow-widen` implicitly also widen
  every mod ceiling beneath it, or does each need its own explicit
  sign-off?

# Future possibilities

- A `taint-generate` report mode that, given an existing codebase with
  many individually-attributed functions, suggests *collapsing* a set of
  near-identical function-level declarations in the same mod into one
  mod-level ceiling plus a small number of explicit per-function
  overrides — the reverse direction from today's "generate one per
  function" default, useful for exactly the REST-handler shape this RFC
  is motivated by.
- Extending the same set-valued treatment to `alloc`/`ptr` if real usage
  ever surfaces the same "broad but not that broad" need for them that
  `io` has today — not proposed here, since neither category has shown
  the same motivating pressure `io` has in a network-heavy codebase.
