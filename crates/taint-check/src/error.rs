//! Renders an [`inspector::Violation`](crate::inspector::Violation) two
//! ways.
//!
//! A real `compile_error!(...)` token stream (the proc-macro path, same
//! convention as `capability-attr::error::emit_violation`) and a
//! plain-text `path:line:column: ...` line (the CLI path, for grepping /
//! CI log output).

use proc_macro2::TokenStream;
use quote::quote_spanned;

use crate::inspector::Violation;

fn message(violation: &Violation) -> String {
    format!(
        "taint violation: `{label}` reaches `{sink}` (policy \"{policy}\") without passing \
         through a #[taint_sanitizer] first",
        label = violation.label,
        sink = violation.sink_fn,
        policy = violation.policy,
    )
}

/// Build the `compile_error!(...)` token stream for `violation`, spanned at
/// the offending call site.
#[must_use]
pub fn emit_violation(violation: &Violation) -> TokenStream {
    let msg = message(violation);
    quote_spanned! { violation.span => compile_error!(#msg); }
}

/// Render `violation` as a single `path:line:column: ...` line for the CLI.
#[must_use]
pub fn format_violation(violation: &Violation, path: &str) -> String {
    let start = violation.span.start();
    format!(
        "{path}:{line}:{column}: {msg}",
        line = start.line,
        column = start.column + 1,
        msg = message(violation),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proc_macro2::Span;

    fn sample_violation() -> Violation {
        Violation {
            label: "password".to_string(),
            sink_fn: "log_debug".to_string(),
            policy: "no_sensitive".to_string(),
            span: Span::call_site(),
        }
    }

    #[test]
    fn compile_error_message_names_label_sink_and_policy() {
        let rendered = emit_violation(&sample_violation()).to_string();
        assert!(rendered.contains("compile_error"));
        assert!(rendered.contains("password"));
        assert!(rendered.contains("log_debug"));
        assert!(rendered.contains("no_sensitive"));
    }

    #[test]
    fn cli_message_includes_the_file_path() {
        let rendered = format_violation(&sample_violation(), "src/auth.rs");
        assert!(rendered.starts_with("src/auth.rs:"));
        assert!(rendered.contains("password"));
    }
}
