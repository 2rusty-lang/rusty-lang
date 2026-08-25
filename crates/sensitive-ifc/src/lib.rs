//! `sensitive-ifc` — Layer 3 (semantic/policy safety) type-system Information
//! Flow Control for Rust.
//!
//! # The problem this solves
//!
//! Rust's borrow checker (Layer 1) proves memory safety. A companion
//! `#[capability(...)]` system ([`capability-attr`], the Layer 2 sibling
//! crate this one was scaffolded alongside — see this workspace's
//! `spec/SPEC-00045-*.md`) can prove a function's declared side-effect scope
//! (allocation, I/O, raw-pointer access) is not exceeded. Neither layer can
//! catch this:
//!
//! ```rust,ignore
//! // Layer 1: memory safe. Layer 2: io(display) is accurately declared.
//! // Layer 3: WRONG — a plaintext credential flows to a log sink.
//! fn log_auth_event(user: &str, password: &str) {
//!     println!("AUTH: user={user} password={password}");
//! }
//! ```
//!
//! The violation is in the *meaning* of the data, not its memory layout or
//! declared side effects. `password` carries a classification — "must never
//! reach an unredacted output sink" — that plain `&str` cannot express. This
//! crate encodes that classification in the type system, so the mistake
//! above becomes a compile error instead of a runtime leak.
//!
//! # Phased scope (this crate implements Phase 1 only)
//!
//! This is a direct, workspace-local implementation of Phase 1 from
//! `docs/aisecurity/ifc-rfc.md` (Information Flow Control RFC), adapted to
//! this project's real target: a Rust rewrite of `git.git` (a userspace CLI
//! tool, not embedded/bare-metal firmware — so, unlike the RFC's own
//! generic/healthcare framing, this crate ships `std`, not `no_std`; the
//! RFC's `Pii`/`Phi` example labels are dropped in favor of labels grounded
//! in `git.git`'s actual credential-handling attack surface, see below).
//!
//! - **Phase 1 (this crate, stable Rust today):** pure type-system IFC.
//!   [`Sensitive<T, L>`] deliberately does **not** implement [`fmt::Display`]
//!   or `serde::Serialize` — passing a sensitive value to `println!`,
//!   `format!`, or a JSON serializer is a compile error, not a runtime leak.
//!   Zero proc-macro, zero extra tooling, zero runtime cost.
//! - **Phase 2 (deferred, not built this pass):** `#[taint_check]` /
//!   `#[sensitive(label)]` / `#[taint_sink(...)]` proc-macro-driven AST taint
//!   propagation — catches taint that Phase 1 loses once
//!   [`Sensitive::into_inner_explicitly`] is called (e.g. `let msg =
//!   format!("{}", pw.into_inner_explicitly()); log(msg)`). See this
//!   workspace's `spec/SPEC-00045-*.md` for the deferred task.
//! - **Phase 3 (deferred, not built this pass):** MIR-level full data-flow
//!   analysis (nightly `rustc_private`), out of scope for this crate
//!   entirely.
//!
//! # Honest scope statement
//!
//! **What this crate catches:** accidental `Display`/`format!`/logging of a
//! value wrapped in [`Sensitive<T, L>`] — a straightforward compile error.
//!
//! **What this crate does NOT catch:** taint that survives past
//! [`Sensitive::into_inner_explicitly`] (the escape hatch is visible in code
//! review, but not compiler-enforced once called), taint through
//! intermediate variables after unwrapping, or any transformation performed
//! by a function this crate doesn't know about. That is Phase 2/3 territory.
//!
//! # Labels — grounded in `git.git`'s real attack surface, not generic
//! examples
//!
//! The RFC's own example labels (`Password`, `SessionToken`, `Pii`, `Phi`)
//! are generic/healthcare-framed. This crate's labels are instead grounded
//! in concrete `git.git` subsystems that a Rust rewrite would actually
//! touch:
//!
//! - [`Credential`] — plaintext username/password material handled by
//!   git's credential subsystem (`credential.c`'s helper protocol,
//!   `.netrc`, URL-embedded userinfo like `https://user:pass@host/repo`).
//! - [`AuthToken`] — bearer/OAuth/personal-access-token material used for
//!   HTTPS authentication (`http.c`/`remote-curl.c`'s `Authorization`
//!   header construction). Kept distinct from [`Credential`] because tokens
//!   are often longer-lived and higher blast-radius if leaked into a log.
//! - [`UntrustedRemoteInput`] — data received from a remote peer during
//!   `fetch`/`clone`/`push` (ref names, capability strings, pack-protocol
//!   responses in `connect.c`/`transport.c`) before it has been validated.
//!   This is a taint *source* label, not just a "must be redacted" label:
//!   the real-world risk is this data reaching command construction (e.g. a
//!   `credential.helper` or `GIT_SSH_COMMAND` invocation) unsanitized —
//!   the class of bug behind real historical git command-injection CVEs
//!   (e.g. submodule-URL argument injection).

#![warn(missing_docs)]
// `cargo_common_metadata` inspects every workspace member's `Cargo.toml`
// reachable from this crate's own dependency graph (confirmed live under
// packages/offline-ops, SPEC-00034 T6: fires on all sibling crates, not
// just this one's), so it's carved out here rather than silently left
// un-denied or "fixed" by editing unrelated crates' manifests out of scope.
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope — see SPEC-00034 T6 / SPEC-00052 T0b"
)]

use core::fmt;
use core::marker::PhantomData;

mod sealed {
    pub trait Sealed {}
}

/// Marker trait for taint labels.
///
/// Sealed — only the labels defined in this crate ([`Credential`],
/// [`AuthToken`], [`UntrustedRemoteInput`]) may be used as the `L`
/// parameter of [`Sensitive<T, L>`]; downstream crates cannot implement
/// this trait for their own types.
///
/// This is a deliberate scope decision for this pass: an open (non-sealed)
/// trait would let any crate mint its own label with no review, undermining
/// the "grounded in git.git's real attack surface, not generic examples"
/// goal above. Widening this to an open/extensible label set is exactly the
/// kind of change that belongs in a future phase, once real usage surfaces
/// a genuine need for it.
pub trait TaintLabel: sealed::Sealed {
    /// A short, human-readable name for this label, used in `Debug` output
    /// and future audit tooling (e.g. a Phase 2+ `cargo ifc-audit` report).
    fn label_name() -> &'static str;
}

/// Plaintext username/password credential material — from `git`'s
/// credential-helper protocol, `.netrc`, or URL-embedded userinfo.
pub struct Credential;

/// Bearer/OAuth/personal-access-token material used for HTTPS
/// authentication against a git remote.
pub struct AuthToken;

/// Data received from a remote git peer before it has been validated.
///
/// Covers ref names, capability strings, pack-protocol responses — a taint
/// *source*, tracked so it can be checked against sinks that build shell
/// commands (credential helpers, `GIT_SSH_COMMAND`) or file paths.
pub struct UntrustedRemoteInput;

impl sealed::Sealed for Credential {}
impl sealed::Sealed for AuthToken {}
impl sealed::Sealed for UntrustedRemoteInput {}

impl TaintLabel for Credential {
    fn label_name() -> &'static str {
        "credential"
    }
}
impl TaintLabel for AuthToken {
    fn label_name() -> &'static str {
        "auth_token"
    }
}
impl TaintLabel for UntrustedRemoteInput {
    fn label_name() -> &'static str {
        "untrusted_remote_input"
    }
}

/// A value carrying a taint label `L`.
///
/// The inner value is inaccessible without explicit unwrapping via
/// [`Sensitive::into_inner_explicitly`] or [`Sensitive::as_inner_explicitly`]
/// — both intentionally verbosely named so the "I am deliberately
/// discarding the sensitivity tracking here" moment is visible in a code
/// diff and in code review, not silent.
///
/// `Sensitive<T, L>` deliberately does **not** implement [`fmt::Display`] —
/// this is the actual enforcement mechanism (see the crate-level docs and
/// this crate's `tests/ui/` trybuild compile-fail tests for proof). `Debug`
/// **is** implemented, but always renders as `Sensitive([REDACTED])`
/// regardless of the wrapped value, so `log::debug!("{:?}", secret)` is
/// safe.
pub struct Sensitive<T, L: TaintLabel> {
    inner: T,
    _label: PhantomData<L>,
}

impl<T, L: TaintLabel> Sensitive<T, L> {
    /// Wrap a value with a taint classification.
    pub const fn new(value: T) -> Self {
        Self {
            inner: value,
            _label: PhantomData,
        }
    }

    /// Unwrap the inner value, discarding the taint label. This is the
    /// escape hatch — use only once the sensitivity has genuinely been
    /// handled (e.g. after hashing, redacting, or handing off to a sink
    /// that is documented to accept this label). The verbose name is
    /// deliberate: it should read as a decision, not an accessor.
    pub fn into_inner_explicitly(self) -> T {
        self.inner
    }

    /// Borrow the inner value without consuming `self`. Same escape-hatch
    /// caveat as [`Sensitive::into_inner_explicitly`].
    pub const fn as_inner_explicitly(&self) -> &T {
        &self.inner
    }

    /// Re-tag this value with a different label — use when passing through
    /// a function that changes the classification without removing it
    /// entirely (e.g. `Credential` narrowing to a more specific label).
    pub fn retag<L2: TaintLabel>(self) -> Sensitive<T, L2> {
        Sensitive {
            inner: self.inner,
            _label: PhantomData,
        }
    }
}

// CRITICAL: do NOT implement `fmt::Display` for `Sensitive<T, L>`. Its
// absence is the actual enforcement mechanism described above — see
// `tests/ui/sensitive_no_display.rs` for a real trybuild proof that
// `println!("{}", sensitive_value)` fails to compile.

impl<T, L: TaintLabel> fmt::Debug for Sensitive<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sensitive([REDACTED])")
    }
}

/// A value that was [`Sensitive<T, L>`] and has been explicitly redacted.
/// Safe to [`fmt::Display`]/[`fmt::Debug`]/log — it always renders as
/// `[REDACTED]`, never the wrapped value, regardless of `T`.
pub struct Redacted<T>(PhantomData<T>);

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redacted([REDACTED])")
    }
}

/// Convert a sensitive value into its redacted, safe-to-log form. This is
/// the official sanitizer for any display/log sink.
///
/// Unlike a `T: Default` based redaction (the RFC's own sketch relies on
/// `T::default()`, which is misleading for types where "default" isn't
/// obviously safe, e.g. `0u32` still being a real value), this
/// implementation deliberately discards `T` entirely — [`Redacted<T>`]
/// carries no data at all, only the type marker, so there is no wrapped
/// value that could ever leak through a future `Display`/`Debug` bug in
/// this crate.
pub fn redact<T, L: TaintLabel>(sensitive: Sensitive<T, L>) -> Redacted<T> {
    // Explicitly discard the inner value — do not retain it in any form.
    let _ = sensitive.into_inner_explicitly();
    Redacted(PhantomData)
}

/// Convenience alias of [`redact`] for `String`-backed sensitive values —
/// the common case for credentials/tokens read from a helper or config
/// file.
#[must_use]
pub fn redact_str<L: TaintLabel>(s: Sensitive<String, L>) -> Redacted<String> {
    redact(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_debug_is_always_redacted() {
        let pw: Sensitive<String, Credential> = Sensitive::new("hunter2".to_string());
        assert_eq!(format!("{pw:?}"), "Sensitive([REDACTED])");
    }

    #[test]
    fn sensitive_debug_redacts_regardless_of_label() {
        let token: Sensitive<&str, AuthToken> = Sensitive::new("ghp_realtoken123");
        assert_eq!(format!("{token:?}"), "Sensitive([REDACTED])");

        let remote: Sensitive<String, UntrustedRemoteInput> =
            Sensitive::new("refs/heads/../../etc/passwd".to_string());
        assert_eq!(format!("{remote:?}"), "Sensitive([REDACTED])");
    }

    #[test]
    fn into_inner_explicitly_returns_the_real_value() {
        let pw: Sensitive<String, Credential> = Sensitive::new("hunter2".to_string());
        assert_eq!(pw.into_inner_explicitly(), "hunter2");
    }

    #[test]
    fn as_inner_explicitly_borrows_without_consuming() {
        let pw: Sensitive<String, Credential> = Sensitive::new("hunter2".to_string());
        assert_eq!(pw.as_inner_explicitly(), "hunter2");
        // pw is still usable after the borrow.
        assert_eq!(format!("{pw:?}"), "Sensitive([REDACTED])");
    }

    #[test]
    fn retag_changes_the_label_type_only() {
        let pw: Sensitive<String, Credential> = Sensitive::new("hunter2".to_string());
        let retagged: Sensitive<String, AuthToken> = pw.retag();
        assert_eq!(retagged.into_inner_explicitly(), "hunter2");
    }

    #[test]
    fn redact_never_exposes_the_wrapped_value() {
        let pw: Sensitive<String, Credential> = Sensitive::new("hunter2".to_string());
        let r = redact(pw);
        assert_eq!(format!("{r}"), "[REDACTED]");
        assert_eq!(format!("{r:?}"), "Redacted([REDACTED])");
    }

    #[test]
    fn redact_str_convenience_wrapper() {
        let token: Sensitive<String, AuthToken> = Sensitive::new("ghp_realtoken123".to_string());
        let r = redact_str(token);
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn label_names_are_stable_for_audit_output() {
        assert_eq!(Credential::label_name(), "credential");
        assert_eq!(AuthToken::label_name(), "auth_token");
        assert_eq!(UntrustedRemoteInput::label_name(), "untrusted_remote_input");
    }

    /// Real trybuild compile-fail proof that `Sensitive<T, L>` does not
    /// implement `Display` — see `tests/ui/sensitive_no_display.rs` and its
    /// checked-in `.stderr` snapshot for the actual compiler output this
    /// asserts against.
    #[test]
    fn sensitive_does_not_implement_display_ui_test() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_no_display.rs");
    }
}
