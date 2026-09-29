---
feature: capability_manifest
start_date: 2026-09-20
status: proposed
tracking_issue:
---

# Summary

A crate declares its intended capability scope once, in `Cargo.toml`
(the **declared** scope). `taint-check` derives what the crate's code
actually does by running the existing capability body inspector over every
function in the crate (the **derived** scope), and compares the two. When
they differ, the build check fails, and an explicit `--update` mode
rewrites the declaration to match — after showing the diff, and with extra
friction when the change *widens* what the crate may do.

# Motivation

Today `#[capability(...)]` is per-function and only checks functions that
carry the attribute (`capability-attr` is function-level only), and
`taint-generate` writes those attributes from the same body detection a
later check would use, so a generated attribute always agrees with the
code it describes ([RFC 0004](0004-taint-generate.md)). Two gaps follow:

- **No statement of the crate's intent.** Nothing says "this crate never
  touches the network" in one reviewable place. The only way to learn it is
  to read every function's attribute.
- **No check that catches drift.** If a refactor adds an `io(network)` call
  to a crate that never had one, nothing compares the crate as a whole to
  what its authors meant.

A crate-level declaration is also the natural input for an OS-level
profile: a profile is per-binary, not per-function. This RFC does not
generate profiles (see Future possibilities); it builds the declared/
derived comparison a generator would rely on.

# Guide-level explanation

**Declared** scope lives in the crate's own manifest:

```toml
[package.metadata.rusty.capabilities]
alloc = "heap"
io    = "filesystem"
ptr   = "none"
```

Values are the existing `capability-core` levels (`alloc`: `none`/`heap`/
`any`; `io`: `none`/`display`/`filesystem`/`network`/`process`/`any`;
`ptr`: `none`/`read`/`write-bounded`/`write-any`/`any`, spelled here as
TOML strings; the exact spelling is part of this proposal) and mean "at most this
level", using the vocabulary's own risk ordering. Cargo ignores unknown
`package.metadata` keys, so this needs no Cargo change.

**Derived** scope is computed, never written by hand:

```sh
$ taint-check --crate src/lib.rs --capabilities
capabilities: derived scope exceeds declared scope
  io: declared filesystem, derived network
    src/sync.rs:41:13: `TcpStream::connect` (io: network) in fn `push_state`
exit status 1
```

The three outcomes:

| Derived vs declared | Meaning | Default result |
|---|---|---|
| derived ⊆ declared, equal | Aligned | pass |
| derived exceeds declared (**widened**) | Code does more than intended | **fail** |
| derived below declared (**headroom**) | Declaration is broader than needed | warning; **fail** under `--strict` |

Headroom matters because a generated profile would inherit an
over-broad declaration.

**Updating the declaration when it differs** is opt-in and always shows the
diff first:

```sh
$ taint-check --crate src/lib.rs --capabilities --update
  io: filesystem -> network        (WIDENS)
refusing to widen without --allow-widen

$ taint-check --crate src/lib.rs --capabilities --update --allow-widen
  io: filesystem -> network        (WIDENS)
updated Cargo.toml [package.metadata.rusty.capabilities]
```

- Narrowing (`--update` alone) is allowed: tightening the declaration to
  what the code does is the safe direction.
- Widening needs `--allow-widen`, so the change is deliberate and visible
  in the resulting `Cargo.toml` diff for review.
- `--update` never runs implicitly, and a plain check never writes.
- On a crate with no declaration, `--update` writes a **draft**
  (`draft = true`). `--capabilities` fails on a draft until a human reviews
  it and removes the flag. This keeps "derived, written down" from
  becoming "declared, reviewed" without anyone looking.

# Reference-level explanation

- **Derivation.** `taint-check`'s `crate_scan` walker already follows
  `mod foo;` to files and collects every function. For each function body,
  run `capability_core::inspector::inspect_body` (used today by
  `capability-attr` and `taint-generate`) and take the per-category
  maximum across the crate. This adds a `rusty-capability-core` dependency
  to `taint-check`; `taint-generate` already has it.
- **Declared parsing.** Read `[package.metadata.rusty.capabilities]` from
  the crate's nearest `Cargo.toml`. `taint-generate`'s `manifest.rs`
  already locates and parses that file (`toml` crate); the lookup can be
  shared.
- **Comparison.** Per category, compare `risk_level()`
  (`capability-core`). Report each offending call site with file, line
  and the capability it triggered, so a failure points at code, not just
  a level.
- **Writing.** `--update` must preserve the rest of `Cargo.toml`
  (comments, key order, formatting), the same principle
  `rusty-source-edit` applies to Rust source. This needs a
  format-preserving TOML editor (`toml_edit`), a new dependency, used only
  for writes. When widening, the previous value is left in an adjacent
  comment so the `Cargo.toml` diff shows both.
- **Exit codes.** Follow `taint-check`'s existing usage/violation split:
  0 pass, 1 declared scope violated (or draft), 2 usage error.
- **Scope of what "derived" means.** Exactly what
  `capability_core::inspector` detects, no more (see Drawbacks).
- **Relationship to OS-level MAC.** Per
  [ADR-0002](../docs/adr/ADR-0002-position-vs-os-level-mac.md), this is a
  compile-time, source-level check layered with, not a replacement for,
  AppArmor/SELinux. The implementation's README and crate docs must carry
  the same "Relationship to OS-level MAC" section as the other crates.

# Drawbacks

- **`--update` makes the declaration a snapshot.** If people run it
  whenever the check fails, the declared scope just mirrors the code and
  the check never catches anything. The `--allow-widen` friction, the
  draft flag, and the visible `Cargo.toml` diff reduce this; they don't
  remove it. It still depends on review of the diff.
- **Derived is only as good as the detector.** The inspector matches
  syntactic patterns in a function body; its own docs say it cannot see
  through function pointers, trait-object calls, or macros that expand to
  I/O. It matches path segments such as `fs`, `net`, `TcpStream` and
  `Command`, so a call imported by name (`use std::fs::read; read(p)`) has
  no `fs` segment and is likely missed (not yet verified by a test). A
  passing check therefore does not prove the crate never uses a
  capability.
- **Dependencies are not inspected.** Only the crate's own source is.
- **Ordering quirk.** Levels are a single risk-ordered scale, so declaring
  `io = "network"` also permits everything below it (`filesystem`,
  `display`). A crate that needs network but no filesystem cannot say so.
- **New dependencies:** `rusty-capability-core` and `toml_edit` in
  `taint-check`.

# Rationale and alternatives

- **In `taint-check`, not a new crate (v1).** The module walker and CLI
  already live there. The cost is that a capability check sits in a crate
  named for taint; a separate `capability-check` crate is cleaner naming
  and can be split out later.
- **Cargo metadata, not a new file or attribute.** A `capabilities.toml`
  is one more file to discover; a crate-root attribute
  (`#![capability(...)]`) would need a proc-macro to see the whole crate,
  which it cannot (a proc-macro only receives its own item's tokens; see
  RFC 0005). Metadata is read by ordinary tooling and reviewable in one
  place.
- **Fail on widening, warn on headroom.** Failing on both makes a
  declaration that is deliberately generous (a documented ceiling)
  impossible; `--strict` is there for crates that want it.
- **Not doing this:** per-function attributes remain the only capability
  statement, with no crate-wide intent and no drift detection.

# Prior art

- **Snapshot-test update flows** (`insta`'s review/accept, `expect-test`'s
  update mode): the same "compare, show diff, opt in to rewrite" shape,
  with the same known weakness that people accept diffs without reading
  them.
- **`cargo-deny` / `cargo-vet`:** policy declared in a checked-in file and
  enforced in CI.
- **AppArmor `aa-genprof` / `aa-logprof`:** derive a profile from observed
  runtime behavior. This RFC derives from source instead, which covers
  paths tests never ran but only sees what the static detector sees.

# Unresolved questions

- Do `network` and `process` really imply `filesystem`? A set-valued `io`
  (`io = ["filesystem", "network"]`) would fix the ordering quirk but
  changes the vocabulary.
- Where should `draft` live, and should `--strict` be the default in CI?
- Should `taint-generate` learn a `--manifest-draft` mode, or is `--update`
  in the checker enough?
- Should the derived scope exclude `#[cfg(test)]` code and `[dev-dependencies]`
  paths? Almost certainly, but the walker's current handling needs
  checking.
- A stronger detector (resolved paths instead of name segments) is a
  separate piece of work; how much of it is needed before the check is
  worth trusting?

# Future possibilities

- **A profile generator.** Emit a skeleton AppArmor profile, seccomp
  allowlist or Landlock ruleset from the declared scope, marked as a
  starting point to be tightened with runtime learning. Denials the
  static detector missed would surface as failures at runtime, which is
  the OS layer backstopping the source-level one.
- **A richer vocabulary** with paths, hosts/ports and executable names
  (`io(filesystem(read, "/etc/app/**"))`), extracted from literals where
  possible and declared by the author where not. Without it, generated
  profiles can only be coarse.
- **A signed manifest** shipped with the package, so the declared scope
  has the same trust root as a distro-shipped profile.
