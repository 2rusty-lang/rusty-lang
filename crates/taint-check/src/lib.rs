//! `taint-check` — Phase 2 of `sensitive-ifc`'s Information Flow Control
//! story: a shallow, AST-level taint-propagation pass, plus the standalone
//! CLI that runs it outside the compiler.
//!
//! # The gap this closes
//!
//! [`sensitive-ifc`](../rusty_sensitive_ifc/index.html)'s `Sensitive<T, L>`
//! makes it a compile error to `Display`/`format!`/serialize a classified
//! value directly — but once code calls `into_inner_explicitly()`, the raw
//! value is unwrapped and the type system loses track of it:
//!
//! ```rust,ignore
//! let msg = format!("{}", password.into_inner_explicitly());
//! log(msg); // credential reaches a log sink; sensitive-ifc cannot see this.
//! ```
//!
//! `#[taint_check(labels = [...])]` (`taint-check-macros`, built on top of
//! this crate) and this crate's own `taint-check` CLI close that gap
//! without a full MIR-level data-flow pass: a `syn`-based AST walk that
//! tracks `#[sensitive(label)]`-marked bindings through a function body —
//! including through one level of intermediate variable — and flags any
//! that reach a `#[taint_sink(label, policy = "...")]` call without first
//! passing through a `#[taint_sanitizer]`. See `rfcs/0003-taint-check.md`
//! and `docs/adr/ADR-0003-implement-taint-check-phase2.md`.
//!
//! # Two ways to run this crate's inspection
//!
//! - **`taint-check-macros`' `#[taint_check]` proc-macro attribute** —
//!   fails `cargo build` with a real `compile_error!(...)` at the
//!   offending call site. Requires the annotated module to actually
//!   compile the crate.
//! - **This crate's own `taint-check` CLI binary** (`src/bin/taint-check.rs`,
//!   [`cli::run`]) — `syn::parse_file`s a target source file outside the
//!   compiler and runs the identical [`inspector::inspect_mod`] pass
//!   standalone, printing violations and exiting nonzero. No proc-macro
//!   dependency required — useful for a CI step that scans files a crate
//!   doesn't necessarily depend on `taint-check-macros` from.
//!
//! Both paths share every real line of inspection logic in this crate;
//! only [`error`]'s two renderers ([`error::emit_violation`] for
//! `compile_error!`, [`error::format_violation`] for CLI text) differ.
//!
//! # Scope decision: `mod` only, not bare `fn`
//!
//! `#[taint_check]` (and the CLI's file scan) only recognizes the
//! attribute on a `mod` item. A lone `fn` can't see a sink function
//! declared as a sibling item — exactly the guide-level example's shape,
//! where a source function and its sink are declared next to each other in
//! the same `mod`. This mirrors `capability-attr`'s own function-level-only
//! scope reduction: don't ship an attachment point that implies a guarantee
//! the pass can't actually provide.
//!
//! # Honest scope statement
//!
//! **What this crate catches:** a `#[sensitive(label)]` parameter passed
//! directly to a `#[taint_sink(label, ...)]` call; the same value passed
//! through exactly one intermediate `let` — either a straight reassignment
//! or a method call on the tainted value (the guide example's own
//! `password.to_string()` shape) — before reaching the sink; and clears
//! that tracking once the value passes through a registered
//! `#[taint_sanitizer]`.
//!
//! **What this crate does NOT catch:** taint through `format!`/string
//! concatenation (there's no call site to attach a check to); across
//! closures, threads, channels, or trait-object dispatch; or across a
//! module boundary outside the annotated `mod`. All of that is real Phase
//! 3 (MIR-level, nightly-only) territory, out of scope here — see
//! [`inspector`]'s module docs for exactly which AST shapes are and aren't
//! tracked, including why an arbitrary function call *does* conservatively
//! propagate taint by default (one of `rfcs/0003-taint-check.md`'s own
//! explicitly unresolved questions, resolved here in favor of the choice
//! that actually gives `#[taint_sanitizer]` something to do).
//!
//! One more concrete gap worth naming: sink/sanitizer calls are matched by
//! their *spelled* trailing path segment (`log_debug`, `self::log_debug`,
//! `super::log_debug` all match a `#[taint_sink]` fn named `log_debug`),
//! not by resolved definition — this crate runs before/outside real name
//! resolution, so it has no `DefId` to compare against. An import alias
//! defeats it:
//!
//! ```rust,ignore
//! use auth::log_debug as ld;
//! ld(password); // NOT caught — different spelling, same function
//! ```

#![warn(missing_docs)]
// `cargo_common_metadata` inspects every workspace member's `Cargo.toml`
// reachable from this crate's own dependency graph — see
// `capability-attr`'s and `sensitive-ifc`'s own `src/lib.rs` for the same
// carve-out; this crate hits the identical workspace-wide check.
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

pub mod cli;
pub mod error;
pub mod inspector;
pub mod parser;
pub mod rewrite;

/// Shared wording for "`#[taint_check]` was applied to something other
/// than a `mod` item".
///
/// Used identically by the CLI ([`cli`]) and by `taint-check-macros`'
/// proc-macro entry point, so both paths report the same scope limitation
/// in the same words.
pub const FN_SCOPE_ERROR: &str = "#[taint_check] can only be applied to a `mod` item in this crate's current (mod-only, Phase 2) scope — a lone `fn` can't see a sink function declared as a sibling item; see this crate's module docs for the full reasoning";
