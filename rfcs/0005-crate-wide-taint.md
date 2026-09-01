---
feature: crate_wide_taint
start_date: 2026-08-30
status: accepted
tracking_issue:
---

# Summary

`taint-check --crate <entry.rs>` extends `taint-check`'s taint-propagation
pass from a single `mod` to an entire crate: it follows `mod foo;`
declarations out to their files, builds one shared sink/sanitizer/function
registry, and additionally tracks a tainted value across a `let`-bound
call into a function defined anywhere else in the crate
("cross-binding" tracking).

# Motivation

`#[taint_check]` and the plain `taint-check <file.rs>` CLI form only ever
see one `mod`'s own direct children — a real Rust-language constraint for
the proc-macro (it only receives the tokens of the item it's attached to)
and a deliberate scope match for its CLI counterpart. A real crate's sink
functions (a logging module, say) are rarely declared in the same file as
every function that might call them. Without crate-wide visibility, a
sink declared in `src/logging.rs` is invisible to a violation in
`src/auth.rs`, even though both are part of the same crate and the same
`#[taint_check(labels = [...])]` scope conceptually applies to both.

# Guide-level explanation

```
src/lib.rs:
    #[taint_check(labels = [password])]
    mod auth;
    mod logging;

src/auth.rs:
    fn handle_login(#[sensitive(password)] password: &str) {
        let echoed = crate::logging::wrap(password);
        crate::logging::log_debug(&echoed);
    }

src/logging.rs:
    #[taint_sink(password, policy = "no_sensitive")]
    pub fn log_debug(msg: &str) { println!("{msg}"); }
    pub fn wrap(s: &str) -> String { s.to_string() }
```

```sh
$ taint-check --crate src/lib.rs
src/auth.rs:3:5: taint violation: `password` reaches `log_debug` ...
```

Neither `wrap` nor `log_debug` is visible from `auth.rs` alone — `wrap`'s
own body is examined to determine it passes its tainted parameter straight
through to its return value, and `log_debug`'s sink registration is found
in a completely different file. The plain, single-file
`taint-check <file.rs>` form is unaffected and unchanged.

# Reference-level explanation

- Module resolution (`crate_scan::resolve_files`) follows only `mod foo;`
  (not `mod foo { ... }`, already visible in its own file), using the
  standard rule: `lib.rs`/`main.rs`/`mod.rs` keep submodules in the same
  directory, any other `foo.rs` keeps them in a `foo/` subdirectory.
  `#[path = "..."]` overrides are not honored; a mod not found at either
  conventional path is silently skipped, not an error.
- `taint_check::inspector` is generalized to thread a `TaintContext`
  (sinks, sanitizers, and a new, optional `fn_defs: HashMap<String,
  &ItemFn>`) instead of two bare maps. With `fn_defs` empty — every
  existing macro and single-file CLI call site — behavior is unchanged
  byte for byte from before this RFC, verified by the full pre-existing
  test suite and `trybuild` goldens.
- "Cross-binding" is exactly what the name says: when `classify_init`
  encounters `let x = some_fn(tainted);` and `some_fn` resolves in
  `fn_defs`, it recursively re-walks `some_fn`'s body with a fresh
  `tainted` map seeded from the parameter that received the argument,
  bounded by a fixed recursion depth and a cycle guard, collecting any
  violation found inside and checking whether the tail expression still
  carries the label. An unresolvable callee (external crate, std lib,
  dynamic dispatch, cycle, depth limit) falls back to the existing
  conservative default — this can only ever add precision, never remove
  the pre-existing safety net.

# Drawbacks

- A bare statement call with no binding (`some_fn(tainted);`, where
  `some_fn` itself reaches a sink internally but isn't a registered sink
  itself) is not tracked — a real, different gap, excluded on purpose:
  "cross-binding" names exactly the case of a value crossing into a *new*
  binding, and this isn't that case.
- Function resolution is by simple name only; two functions sharing a name
  in different modules are indistinguishable to this pass (the same
  shallow-matching trade-off `path_last_segment` already made for sink/
  sanitizer names).
- Whole-crate scanning has a real, if generous, file-count safety cap.

# Rationale and alternatives

- Building a real interprocedural call graph with proper name resolution
  (crate-wide `DefId`s) would remove the name-collision caveat above, but
  requires `rustc_private` — explicitly out of scope for this stable-Rust,
  AST-only pass, same reasoning `rfcs/0003-taint-check.md` already applied
  to its own Phase 3 boundary.
- Extending tracking to bare statement calls (not just `let`-bound ones)
  was considered and deferred — it would require the interprocedural
  summary to report violations without a value ever needing to "cross a
  binding," which is a real, useful, but differently-scoped feature worth
  its own future RFC rather than silently folding into this one.

# Prior art

Direct extension of `rfcs/0003-taint-check.md`'s own design; no new prior
art beyond what that RFC already cites.

# Unresolved questions

- Whether cross-*crate* (workspace-wide) tracking is worth pursuing later
  — explicitly declined for this pass when the feature was requested.
- Whether `#[path = "..."]` support is common enough in practice to be
  worth adding.

# Future possibilities

- Bare-statement-call interprocedural tracking (see Rationale above).
- Cross-crate tracking across a Cargo workspace's own member crates.
