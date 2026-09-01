---
feature: taint_generate
start_date: 2026-08-30
status: accepted
tracking_issue:
---

# Summary

`taint-generate` is a CLI (`rusty-taint-generate`) that auto-writes
`#[capability(...)]` (deterministically, from real body-usage detection)
and `#[sensitive(...)]`/`#[taint_sink(...)]`/`#[taint_sanitizer]`/
`#[taint_check(labels = [...])]` (heuristically, from naming keywords)
directly into source files, for any function/mod that has none of that
kind of annotation yet.

# Motivation

`capability-attr` and `taint-check` only ever verify an attribute a human
already wrote. Bootstrapping either onto an existing, unannotated crate
means hand-writing every `#[capability(...)]` and every
`#[sensitive]`/`#[taint_sink]`/`#[taint_sanitizer]` one at a time. For the
capability side this is pure friction — the correct answer is entirely
computable from the function body already. For the taint side it can
never be fully automatic (deciding what counts as sensitive is a judgment
call), but a best-effort first pass, clearly labeled as such, is still
faster to review than starting from nothing.

# Guide-level explanation

```sh
taint-generate src/auth.rs              # writes changes directly
taint-generate --dry-run src/auth.rs    # preview, writes nothing
taint-generate --report src/auth.rs     # structured summary of what changed
```

Given:

```rust,ignore
fn log_message(msg: &str) {
    println!("{msg}");
}

mod auth {
    fn handle_login(password: &str) {
        log_debug(password);
    }
    fn log_debug(msg: &str) {}
}
```

running `taint-generate` on it produces:

```rust,ignore
#[capability(alloc(none), io(display), ptr(none))]
fn log_message(msg: &str) {
    println!("{msg}");
}

#[taint_check(labels = [password])]
mod auth {
    fn handle_login(#[sensitive(password)] password: &str) {
        log_debug(password);
    }
    #[taint_sink(password, policy = "no_sensitive")]
    fn log_debug(msg: &str) {}
}
```

The capability attribute is exactly correct — it was computed from the
function's actual body, not guessed. The taint attributes are a
best-effort starting point: `password` matched a keyword list, `log_debug`
matched a different one. **Review every generated taint attribute before
trusting it.**

# Reference-level explanation

- `capability_gen`: for every top-level `fn` lacking `#[capability(...)]`,
  runs `capability_core::inspector::inspect_body` and writes
  `capability_core::render_capability_args`'s output verbatim. Scoped to
  top-level functions only this pass — a nested function is left to
  `taint_gen`'s mod-level rewrite to avoid two independent, potentially
  overlapping edits inside the same mod.
- `taint_gen`: for every top-level `mod` with zero existing taint
  attributes anywhere inside it, matches parameter names against a fixed
  sensitive-keyword list, function names against fixed sink- and
  sanitizer-keyword lists (`heuristics.rs`), and — only if at least one
  sensitive parameter was found — tags the matches and the enclosing mod.
  A mod already partway annotated is skipped entirely, not filled in
  around the edges.
- Writing to disk is surgical (`rusty-source-edit`): only the exact byte
  span of each changed item is replaced; the rest of the file, including
  comments and blank-line structure, is untouched.

# Drawbacks

- The taint half is a real, unavoidable false-positive/negative surface.
  A concrete example found while writing this crate's own tests:
  `handle_login` false-matches the `log` sink keyword, because `"login"`
  contains `"log"`.
- Always-apply-by-default (no interactive confirmation) means a first run
  on an unfamiliar crate can add attributes to files the user didn't
  expect to change — mitigated by `--dry-run`, but that has to be reached
  for deliberately.

# Rationale and alternatives

- Suggest-only (never write) was considered and rejected — the user
  explicitly asked for auto-write, and `--dry-run` covers the
  suggest-only use case as an opt-in rather than the default.
- A config file for custom keyword lists was considered and deferred — the
  fixed lists in `heuristics.rs` are small enough to read in full, and a
  config surface adds real complexity for a first cut that hasn't yet
  proven the fixed lists are insufficient in practice.

# Prior art

`capability-attr`'s own body inspector (`capability_core::inspector`) is
the direct precedent for the deterministic half. The heuristic half has no
close analog elsewhere in this workspace — it's closer to a linter's
"did you mean" suggestion than to anything else here, deliberately kept
that modest.

# Unresolved questions

- Whether the keyword lists should ever become user-configurable.
- Whether nested-mod support is worth the added edit-overlap bookkeeping
  it would require.

# Future possibilities

- A `--labels-from <file>` flag to supply a project-specific keyword list
  instead of (or alongside) the built-in ones.
