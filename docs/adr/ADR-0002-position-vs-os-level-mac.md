---
id: ADR-0002
title: Position capability-attr/sensitive-ifc as complementary to OS-level MAC (AppArmor/SELinux), not a replacement
status: accepted
date: 2026-08-30
supersedes: null
superseded_by: null
---

# Context

`capability-attr` and `sensitive-ifc` both enforce policy at compile time,
inside a single Rust crate, before a binary exists. AppArmor and SELinux
enforce policy at runtime, at the process boundary, via the kernel's Linux
Security Modules (LSM) framework — independent of what language produced the
binary, and unaware of anything below the syscall layer.

Marketing and documentation content for these crates (blog post, slide deck,
video scripts — see the wwwsite `rust-nightly-capability-security` post)
repeatedly needs to state how this project relates to AppArmor/SELinux. Left
undecided, that's an easy place for the two framings to blur into each
other — "compile-time capability enforcement" and "OS-level mandatory access
control" sound similar enough that readers (and future contributors writing
docs) could reasonably assume one is meant to obsolete the other, or that
adopting `capability-attr` reduces the need for a runtime MAC profile. Both
readings are wrong and, taken seriously, would produce a weaker security
posture: dropping AppArmor/SELinux because "the Rust code already declares
its capabilities" ignores that a compile-time check only covers code compiled
with the macro applied — it says nothing about a compromised binary, a
dependency that bypassed the attribute, or any process on the same host not
built from this workspace at all.

This ADR exists because [[ADR-0001]] already documents *why* the compile-time
layer exists (the `unsafe`/safe binary is too coarse, and the language-level
fix — `allocator_api`, RFC 1398 — has been nightly-only for over a decade);
it does not say where that layer's authority ends. This one does.

# Decision

Documentation, marketing copy, and code comments for `capability-attr` and
`sensitive-ifc` MUST describe the relationship to AppArmor/SELinux (and OS
MAC generally) as **layered, not substitutive**:

- **Compile-time (this project):** catches a capability or classification
  violation in *code that was built with the attribute applied*, before the
  binary exists. Scope is intra-process and limited to what the macro can see
  at the AST — a function's declared `alloc`/`io`/`ptr` surface, or a
  `Sensitive<T, L>` value's flow through `Display`/serialization. It has no
  runtime component and enforces nothing about binaries it didn't compile.
- **Runtime, OS-enforced (AppArmor/SELinux):** catches what compile-time
  checking cannot reach at all — a compromised or malicious binary, a
  dependency that never used the attribute, a supply-chain-injected process,
  or simply any process on the host not built from this workspace. Enforced
  by the kernel regardless of source language or whether the binary was even
  built with source available.

Neither layer is optional because of the other. A project adopting
`capability-attr`/`sensitive-ifc` should keep (or add) an AppArmor/SELinux
profile for the resulting binary exactly as it would without these crates.
No README, blog post, slide, or code comment may state or imply that this
project is an alternative to, or reduces the need for, OS-level MAC.

# Consequences

Cost: every piece of explanatory content has to spend a sentence or two on
this distinction instead of the simpler (and more shareable) claim "compile-
time security for Rust." That's a real tax on how crisp the pitch can be.

Benefit: the project doesn't overclaim what a macro-driven, compile-time-only
mechanism can guarantee, which matters specifically because the target
audience includes AI-generated code review — a reviewer (human or model) who
believes `#[capability(...)]` coverage means a process is sandboxed will
under-scrutinize the actual runtime attack surface. Stating the boundary
explicitly is cheaper than the alternative: someone shipping a
`capability-attr`-annotated binary with no AppArmor/SELinux profile because
the marketing implied one covered the other.
