---
feature: taint_refactor
start_date: 2026-08-30
status: accepted
tracking_issue:
---

# Summary

`taint-refactor` is a CLI (`rusty-taint-refactor`) that, given one taint
violation found by `taint-check`'s whole-crate scan, re-scans the entire
crate for every occurrence of the same `(label, sink)` pattern and
generates an applyable patch for each: a placeholder `#[taint_sanitizer]`
function plus a rewritten call site routing the tainted value through it.

# Motivation

Finding a violation is only half the job; fixing it by hand, one call site
at a time, across a whole crate, is exactly the kind of mechanical,
repetitive work a tool should do instead of a person — provided the tool
is honest that it's proposing a starting point, not a verified fix.

# Guide-level explanation

```sh
taint-refactor --crate src/lib.rs              # writes patches directly
taint-refactor --dry-run --crate src/lib.rs    # preview, writes nothing
taint-refactor --report --crate src/lib.rs     # summary of what changed
```

Given a real violation:

```rust,ignore
fn handle_login(#[sensitive(password)] password: &str) {
    log_debug(password);
}
#[taint_sink(password, policy = "no_sensitive")]
fn log_debug(msg: &str) { println!("{msg}"); }
```

running `taint-refactor` produces:

```rust,ignore
fn handle_login(#[sensitive(password)] password: &str) {
    log_debug(__taint_refactor_redact_password(password));
}
#[taint_sink(password, policy = "no_sensitive")]
fn log_debug(msg: &str) { println!("{msg}"); }

#[taint_sanitizer]
fn __taint_refactor_redact_password(v: &str) -> String {
    "[REDACTED]".to_string()
}
```

Re-running `taint-check --crate` on the patched crate confirms the
violation is gone. **The generated sanitizer is a naive, fixed-string
placeholder — review and replace it with real redaction logic before
trusting it, and re-run `cargo build`/`cargo test` afterward: wrapping a
value in a call can change its type** (confirmed directly while building
this feature: the example above needs a `&` added at the call site, since
`log_debug` takes `&str` and the placeholder returns `String`).

# Reference-level explanation

- Reuses `taint_check::crate_scan::scan_crate` rather than re-implementing
  whole-crate scanning.
- Groups violations by `(label, sink_fn)` and, within each file, by which
  top-level function contains the violation's tainted-argument span
  (`Violation::arg_span`, added specifically for this crate).
- One sanitizer is generated per `(file, label)` pair and reused across
  every violation of that label in that file, never duplicated.
- **Scope: top-level functions only.** A violation whose enclosing
  function is nested inside an inline `mod { ... }` is skipped, not
  guessed at — routing to a file-scope sanitizer from inside a nested mod
  needs `self::`/`super::` qualification this pass does not attempt.
  Reported back via `PatchPlan::skipped`, not silently dropped.
- Rewriting uses the same span-based, whole-item-granularity mechanism as
  `taint-generate` (`rusty-source-edit`).

# Drawbacks

This is, by a wide margin, the riskiest tool in the workspace: it
generates actual code with security implications, not just a structural
attribute. Concretely:

- The placeholder sanitizer always redacts to a fixed string, regardless
  of the wrapped value's real type or the context it's used in — often
  wrong, always in need of review.
- Wrapping a value can change its type at the call site, breaking
  compilation until fixed by hand (confirmed directly, see above).
- This pass does not verify the patched crate still compiles — that is
  entirely the human reviewer's responsibility, stated as such in the
  crate's own docs and its CLI's `--report` output.

# Rationale and alternatives

- A "smarter" sanitizer that tries to preserve the original type (e.g.
  `&str -> &str` via a `'static` placeholder, or generic over `T:
  Display`) was considered and rejected for a first cut: it would look
  more finished than it is, understating the review this output always
  needs regardless of how polished the generated signature looks.
- Silently attempting nested-mod rewrites with a best-guess `super::`
  qualification was considered and rejected — getting that wrong
  compiles-but-is-wrong in a way that is much harder to notice than an
  explicit skip.

# Prior art

Builds directly on `taint-generate` (RFC `0004`) for the "generate,
review, apply" shape and `rusty-source-edit` for the rewrite mechanism;
no closer prior art exists elsewhere in this workspace.

# Unresolved questions

- Whether a smarter, type-aware sanitizer generation strategy is worth the
  added complexity once real-world usage shows the naive placeholder is
  too often wrong in the same specific ways.
- Whether nested-mod support is worth adding once the qualification logic
  can be gotten right with confidence.

# Future possibilities

- Nested-mod support once `self::`/`super::` qualification can be derived
  reliably from the violation's own position in the module tree.
- A `--sanitizer-template <file>` flag to supply a project-specific
  redaction pattern instead of the hard-coded placeholder.
