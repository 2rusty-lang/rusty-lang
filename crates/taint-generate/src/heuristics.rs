//! Naming-keyword heuristics for the taint-generation half of this crate.
//!
//! **These are guesses, not detection.** Unlike the capability side (which
//! runs `capability_core::inspector::inspect_body` — a deterministic
//! analysis of what a function's body actually does), there is no way to
//! *derive* that a parameter is a password or that a function is a logging
//! sink from its body alone at this crate's AST-only level. Matching
//! against a short, fixed keyword list is a real, stated trade-off: it
//! will both miss real cases (a parameter named `creds`) and flag false
//! ones (a function named `write_report` that writes nothing sensitive).
//! Every generated taint attribute should be read as a starting point, not
//! a verified fact — this is exactly the same posture this workspace
//! already takes toward its own detection limits elsewhere, applied here
//! to generation instead.
//!
//! A concrete example of the false-positive risk, found while writing this
//! crate's own tests: a function named `handle_login` gets tagged as a
//! `#[taint_sink]` candidate, because `"login"` contains the substring
//! `"log"` — exactly the keyword meant to catch logging calls. A function
//! that *handles* a login is, if anything, more likely to be a taint
//! *source* than a sink. This is a real, checked-in limitation, not a bug
//! to fix by special-casing `"login"` — the next collision is always one
//! keyword away from a substring match this crude.

/// Case-insensitive substring keywords that mark a parameter name as
/// probably sensitive. The matched keyword itself becomes the taint label.
pub const SENSITIVE_PARAM_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "ssn",
    "credit_card",
    "private_key",
];

/// Case-insensitive substring keywords that mark a function name as
/// probably a taint sink (an output/egress point).
pub const SINK_FN_KEYWORDS: &[&str] = &[
    "log", "debug", "print", "send", "emit", "write", "publish", "export",
];

/// Case-insensitive substring keywords that mark a function name as
/// probably a taint sanitizer (a redaction/masking helper).
pub const SANITIZER_FN_KEYWORDS: &[&str] = &[
    "redact",
    "sanitize",
    "sanitise",
    "mask",
    "scrub",
    "anonymize",
    "hash",
    "encrypt",
    "obfuscate",
];

/// If `name` contains one of `keywords` (case-insensitively), return that
/// keyword.
fn first_matching_keyword(name: &str, keywords: &[&'static str]) -> Option<&'static str> {
    let lower = name.to_lowercase();
    keywords.iter().find(|kw| lower.contains(*kw)).copied()
}

/// Does `param_name` look like a sensitive parameter? Returns the matched
/// keyword, used verbatim as the taint label.
#[must_use]
pub fn sensitive_label_for_param(param_name: &str) -> Option<&'static str> {
    first_matching_keyword(param_name, SENSITIVE_PARAM_KEYWORDS)
}

/// Does `fn_name` look like a taint sink?
#[must_use]
pub fn looks_like_sink(fn_name: &str) -> bool {
    first_matching_keyword(fn_name, SINK_FN_KEYWORDS).is_some()
}

/// Does `fn_name` look like a taint sanitizer?
///
/// Checked before [`looks_like_sink`] by callers — the keyword lists don't
/// overlap, but sanitizer intent is the more specific, more confident
/// signal of the two.
#[must_use]
pub fn looks_like_sanitizer(fn_name: &str) -> bool {
    first_matching_keyword(fn_name, SANITIZER_FN_KEYWORDS).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_password_keyword_case_insensitively() {
        assert_eq!(sensitive_label_for_param("userPassword"), Some("password"));
        assert_eq!(sensitive_label_for_param("PASSWORD"), Some("password"));
    }

    #[test]
    fn matches_token_inside_a_longer_name() {
        assert_eq!(sensitive_label_for_param("session_token"), Some("token"));
    }

    #[test]
    fn a_plain_name_matches_nothing() {
        assert_eq!(sensitive_label_for_param("count"), None);
    }

    #[test]
    fn recognizes_sink_keywords() {
        assert!(looks_like_sink("log_debug"));
        assert!(looks_like_sink("send_metrics"));
        assert!(!looks_like_sink("compute_total"));
    }

    #[test]
    fn recognizes_sanitizer_keywords() {
        assert!(looks_like_sanitizer("redact_value"));
        assert!(looks_like_sanitizer("hash_password"));
        assert!(!looks_like_sanitizer("send_metrics"));
    }

    #[test]
    fn sink_and_sanitizer_keyword_lists_do_not_overlap() {
        for sink in SINK_FN_KEYWORDS {
            assert!(
                !SANITIZER_FN_KEYWORDS.contains(sink),
                "`{sink}` appears in both lists"
            );
        }
    }
}
