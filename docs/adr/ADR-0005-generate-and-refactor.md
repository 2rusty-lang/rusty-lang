---
id: ADR-0005
title: Auto-generate/populate attributes, crate-wide taint tracking, and auto-refactor
status: accepted
date: 2026-08-30
supersedes: null
superseded_by: null
---

# Context

`capability-attr` and `taint-check` only ever *verify* attributes a human
already wrote — they never decide where one belongs, and `#[taint_check]`'s
AST walk (macro and CLI alike) only ever saw one `mod`'s own direct
children. Three further capabilities were requested on top of that:
auto-writing annotations instead of only suggesting them, tracking taint
across function/module boundaries within one crate, and generating an
actual code patch once a violation is found — asked for and confirmed
directly, each a real escalation from this workspace's established
"verify what's declared, never guess or auto-write" posture.

# Decision

Build all three, with the scope and safety choices below made explicit
rather than left implicit.

**New crate `crates/capability-core`** (`rusty-capability-core`,
`publish = false`) — `capability-attr`'s private vocabulary
(`AllocLevel`/`IoLevel`/`PtrLevel`/`CapabilitySet`), body inspector, and
subset-check move here verbatim (never public API to begin with, the same
`path-match` reasoning `ADR-0003` already used), plus one new addition,
`render_capability_args` — the exact inverse of the existing parser, so
`taint-generate` can construct a `#[capability(...)]` from a detected
`CapabilitySet` rather than only checking one. `capability-attr` bumps
`0.1.2` → `0.1.3` for this internal-only switch.

**New crate `crates/source-edit`** (`rusty-source-edit`, `publish = false`)
— both new tools need to add exactly one attribute or rewrite exactly one
call site without reformatting the rest of a file. A full
`syn::parse_file` + `prettyplease::unparse` round-trip of the whole file
would silently strip comments and reformat everything else, so this crate
instead locates one item's byte span (via `proc-macro2`'s `span-locations`
line/column, mapped back through the original source text), re-prints
*only* the mutated item, and splices it back in place.

**New crate `crates/taint-generate`** (`rusty-taint-generate`) — writes
`#[capability(...)]` deterministically (from real `inspect_body` usage,
not a guess) for any unannotated top-level `fn`, and
`#[sensitive(...)]`/`#[taint_sink(...)]`/`#[taint_sanitizer]`/
`#[taint_check(labels = [...])]` heuristically (naming-keyword matching)
for any top-level `mod` with **zero** existing taint attributes anywhere
inside it — a mod already partway annotated is assumed curated and left
alone entirely, never filled in around the edges. Ships `--dry-run`
(preview, never writes) and `--report` (structured summary) alongside the
default-applies behavior that was explicitly requested.

**`crates/taint-check` extension: whole-crate, cross-binding tracking** —
`inspect_mod`/`walk_block`/`classify_init` now thread a `TaintContext`
(sinks, sanitizers, and a new, optional `fn_defs: HashMap<String,
&ItemFn>`) instead of two bare maps. Empty `fn_defs` — the existing macro/
single-file CLI path — is provably identical to the pre-`ADR-0005`
behavior, verified by re-running every existing test and `trybuild`
golden unchanged. New module `crate_scan.rs` follows `mod foo;`
declarations to their files (`lib.rs`/`main.rs`/`mod.rs` keep submodules
in the same directory, any other `foo.rs` in a `foo/` subdirectory —
`#[path = "..."]` overrides are not honored, a mod not found at its
conventional path is silently skipped) and builds one crate-wide registry,
new CLI mode `taint-check --crate <entry.rs>`. "Cross-binding" is scoped
precisely to its name: taint crossing from one binding into a *new*
binding created by an interprocedural, `let`-bound call
(`classify_init`'s `Expr::Call` arm now recurses into a resolvable
callee's own body, depth-bounded and cycle-guarded, instead of assuming
conservatively). A bare statement call with no binding, where the callee
itself reaches a sink internally, is a different, real gap left out on
purpose — a bound rather than an oversight.

**New crate `crates/taint-refactor`** (`rusty-taint-refactor`) — reuses
`taint_check::crate_scan::scan_crate` rather than re-scanning, groups
violations by `(label, sink_fn)`, and for every occurrence whose enclosing
function is a top-level item in its own file (the common multi-file
layout `--crate` mode targets) inserts a placeholder
`__taint_refactor_redact_<label>` sanitizer and rewrites the call site to
route through it. A violation nested inside an inline `mod { ... }` is
skipped, not guessed at — reaching a file-scope sanitizer from there needs
`self::`/`super::` qualification this pass does not attempt. Ships the
same `--dry-run`/`--report` flags as `taint-generate`.

# A real bug found and fixed along the way

Manually verifying `taint-refactor`'s own output against `taint-check`
surfaced a genuine, pre-existing correctness gap in `taint-check` itself —
present since `ADR-0003`, not introduced here, just never previously
exercised by any existing test or hand-written example:
`sink(sanitizer(tainted))`, called directly with no intermediate `let`,
was still flagged as a violation. `find_sink_violations`'s sink-argument
check used a broad, sanitizer-*unaware* "does this expression contain a
tainted path anywhere" scan (deliberately conservative, to catch
`format!`/arbitrary nesting), while only `classify_init`'s `let`-binding
path was sanitizer-aware. Fixed narrowly: `is_directly_sanitized` checks
whether a sink's argument is *itself*, after unwrapping `&`/`(...)`, a
direct call to a registered sanitizer, short-circuiting only that one
shape — the broad conservative scan is untouched for everything else. This
is exactly the shape `taint-refactor` generates, so the fix was load-
bearing for the feature actually working, not a nice-to-have caught along
the way.

# Consequences

Cost: two more unpublished internal crates (`capability-core`,
`source-edit`) alongside the existing `path-match`, each with no design
doc of its own beyond its own module comment (consistent with how
`path-match` was introduced). `taint-generate`'s heuristic half is a real,
stated false-positive/negative surface (documented with a concrete example
found while writing its own tests: `handle_login` false-matches the `log`
sink keyword via `"login"`). `taint-refactor` is the riskiest tool in the
workspace by a wide margin — it writes actual redaction logic a human must
review, its placeholder sanitizer's return type can break the call site's
own type-check (confirmed directly: `String` from `&str` needs a `&`
added back at the call site), and its own CLI output says so unmissably.

Buys: `capability-attr`'s scope-checked vocabulary and `taint-check`'s
whole-crate tracking are both now automatable from a cold start
(`taint-generate` on an unannotated crate) through a real fix
(`taint-refactor` on a found violation) without requiring a human to
hand-write every attribute and every sanitizer — while every generated
piece keeps the same "review before trusting" posture this workspace
already asks of its own detection limits.
