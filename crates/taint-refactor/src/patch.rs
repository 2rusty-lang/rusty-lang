//! Turn `taint-check`'s whole-crate violations into an applyable patch: a
//! placeholder `#[taint_sanitizer]` plus a rewritten call site for every
//! occurrence of the same `(label, sink)` pattern.
//!
//! **This is the riskiest tool in the `rusty` workspace.** It doesn't just
//! add a structural attribute (`taint-generate`'s job) — it invents actual
//! security-shaped code: a fixed-string redaction function it has no way
//! to know is *correct* for the type or context involved. Every generated
//! sanitizer is named `__taint_refactor_redact_<label>` specifically so it
//! stands out in a diff as generated, not written — and it MUST be
//! reviewed and, in almost every real case, replaced with real redaction
//! logic before being trusted. Re-run `cargo build`/`cargo test` after
//! applying a patch: wrapping a value in a call can change its type
//! (`&str` becomes `String`), and this pass doesn't verify the result
//! still compiles.
//!
//! # Scope: top-level functions only
//!
//! A violation whose enclosing function is nested inside an inline `mod {
//! ... }` block (rather than being a top-level item in its file) is
//! skipped, not guessed at — rewriting it correctly would require adding
//! `self::`/`super::` path qualification to reach a sanitizer inserted at
//! file scope, and getting that wrong silently would be worse than not
//! patching it at all. This covers the common multi-file crate layout
//! `taint-check --crate` is built for (`src/auth.rs`, `src/logging.rs`,
//! ...), where a violation's own function is already a top-level file item.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use source_edit::{apply_edits, print_item, span_byte_range, SourceEdit};
use syn::spanned::Spanned;
use syn::visit_mut::VisitMut;
use syn::{Expr, File, Item};

use taint_check::crate_scan::{scan_crate, CrateViolation};

/// One generated patch, reported back so `--report`/`--dry-run` can show
/// what was (or would be) done without a human diffing the file.
pub struct GeneratedPatch {
    /// The file the patch was applied to.
    pub path: PathBuf,
    /// The sink the tainted value was reaching.
    pub sink_fn: String,
    /// The taint label involved.
    pub label: String,
    /// The generated sanitizer's name (unique per `(path, label)`).
    pub sanitizer_name: String,
}

/// A violation whose enclosing function couldn't be found as a top-level
/// item in its own file — see this module's own "Scope" doc section.
pub struct SkippedViolation {
    /// The file the violation was found in.
    pub path: PathBuf,
    /// The sink the tainted value was reaching.
    pub sink_fn: String,
}

/// Everything [`generate_patches`] produced: the new full contents for
/// every file that got at least one patch, plus a record of what happened
/// (applied and skipped) for reporting.
pub struct PatchPlan {
    /// New full file contents, keyed by path — not yet written to disk.
    pub rewritten_sources: HashMap<PathBuf, String>,
    /// Every patch actually generated.
    pub patches: Vec<GeneratedPatch>,
    /// Every violation this pass declined to patch, and why (implicitly:
    /// not a top-level function — see this module's doc comment).
    pub skipped: Vec<SkippedViolation>,
}

/// Run `taint-check`'s whole-crate scan from `entry`, then generate a
/// patch for every violation whose enclosing function is a top-level item
/// in its own file.
///
/// # Errors
///
/// Returns `Err` with a human-readable message on a file-read failure or a
/// Rust-syntax parse failure (from the underlying scan, or from re-reading
/// a violated file to build its patch).
pub fn generate_patches(entry: &Path) -> Result<PatchPlan, String> {
    let violations = scan_crate(entry)?;

    let mut by_path: HashMap<PathBuf, Vec<CrateViolation>> = HashMap::new();
    for v in violations {
        by_path.entry(v.path.clone()).or_default().push(v);
    }

    let mut rewritten_sources = HashMap::new();
    let mut patches = Vec::new();
    let mut skipped = Vec::new();

    for (path, path_violations) in by_path {
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: could not read file: {e}", path.display()))?;
        let file: File = syn::parse_file(&source)
            .map_err(|e| format!("{}: not valid Rust: {e}", path.display()))?;

        let mut by_fn_index: HashMap<usize, Vec<&CrateViolation>> = HashMap::new();
        for v in &path_violations {
            match find_top_level_fn_index(&file, v.violation.arg_span) {
                Some(idx) => by_fn_index.entry(idx).or_default().push(v),
                None => skipped.push(SkippedViolation {
                    path: path.clone(),
                    sink_fn: v.violation.sink_fn.clone(),
                }),
            }
        }
        if by_fn_index.is_empty() {
            continue;
        }

        let mut edits = Vec::new();
        let mut sanitizer_for_label: HashMap<String, String> = HashMap::new();
        let mut new_fns_text = String::new();

        for (fn_index, fn_violations) in by_fn_index {
            let Item::Fn(original_fn) = &file.items[fn_index] else {
                continue;
            };
            let mut new_fn = original_fn.clone();

            for v in fn_violations {
                let label = &v.violation.label;
                let sanitizer_name = sanitizer_for_label
                    .entry(label.clone())
                    .or_insert_with(|| {
                        use std::fmt::Write as _;
                        let name = format!("__taint_refactor_redact_{label}");
                        let _ = write!(
                            new_fns_text,
                            "\n\n#[taint_sanitizer]\nfn {name}(v: &str) -> String {{\n    \"[REDACTED]\".to_string()\n}}\n"
                        );
                        name
                    })
                    .clone();

                let mut wrapper = WrapAtSpan {
                    target: v.violation.arg_span,
                    sanitizer_name: &sanitizer_name,
                    wrapped: false,
                };
                wrapper.visit_item_fn_mut(&mut new_fn);
                if wrapper.wrapped {
                    patches.push(GeneratedPatch {
                        path: path.clone(),
                        sink_fn: v.violation.sink_fn.clone(),
                        label: label.clone(),
                        sanitizer_name,
                    });
                }
            }

            let (start, end) = span_byte_range(&source, original_fn.span());
            edits.push(SourceEdit {
                start,
                end,
                replacement: print_item(&Item::Fn(new_fn)),
            });
        }

        if edits.is_empty() {
            continue;
        }
        let mut rewritten = apply_edits(&source, &edits);
        rewritten.push_str(&new_fns_text);
        rewritten_sources.insert(path, rewritten);
    }

    Ok(PatchPlan {
        rewritten_sources,
        patches,
        skipped,
    })
}

fn span_contains(outer: proc_macro2::Span, inner: proc_macro2::Span) -> bool {
    let (outer_start, outer_end) = (outer.start(), outer.end());
    let (inner_start, inner_end) = (inner.start(), inner.end());
    (outer_start.line, outer_start.column) <= (inner_start.line, inner_start.column)
        && (inner_end.line, inner_end.column) <= (outer_end.line, outer_end.column)
}

fn find_top_level_fn_index(file: &File, target: proc_macro2::Span) -> Option<usize> {
    file.items.iter().position(|item| match item {
        Item::Fn(f) => span_contains(f.span(), target),
        _ => false,
    })
}

struct WrapAtSpan<'a> {
    target: proc_macro2::Span,
    sanitizer_name: &'a str,
    wrapped: bool,
}

impl VisitMut for WrapAtSpan<'_> {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        if self.wrapped {
            return;
        }
        let (target_start, target_end) = (self.target.start(), self.target.end());
        let (expr_start, expr_end) = (expr.span().start(), expr.span().end());
        if (expr_start.line, expr_start.column) == (target_start.line, target_start.column)
            && (expr_end.line, expr_end.column) == (target_end.line, target_end.column)
        {
            let inner = expr.clone();
            let sanitizer_ident =
                syn::Ident::new(self.sanitizer_name, proc_macro2::Span::call_site());
            let wrapped: Expr = syn::parse_quote! { #sanitizer_ident(#inner) };
            *expr = wrapped;
            self.wrapped = true;
            return;
        }
        syn::visit_mut::visit_expr_mut(self, expr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusty-taint-refactor-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let full = self.0.join(relative);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, contents).unwrap();
            full
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn generates_a_sanitizer_and_rewrites_the_call_site() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            r"
            #[taint_check(labels = [password])]
            mod auth;
            ",
        );
        dir.write(
            "auth.rs",
            "fn handle_login(#[sensitive(password)] password: &str) {\n    log_debug(password);\n}\n#[taint_sink(password, policy = \"no_sensitive\")]\nfn log_debug(msg: &str) {}\n",
        );

        let plan = generate_patches(&lib).unwrap();
        assert_eq!(plan.patches.len(), 1);
        assert_eq!(plan.patches[0].sink_fn, "log_debug");
        assert_eq!(
            plan.patches[0].sanitizer_name,
            "__taint_refactor_redact_password"
        );
        assert!(plan.skipped.is_empty());

        let auth_path = dir.0.join("auth.rs");
        let rewritten = &plan.rewritten_sources[&auth_path];
        assert!(rewritten.contains("__taint_refactor_redact_password(password)"));
        assert!(rewritten.contains("#[taint_sanitizer]"));
        assert!(rewritten.contains("fn __taint_refactor_redact_password"));

        // The patched file must still parse as valid Rust.
        syn::parse_file(rewritten).unwrap();
    }

    #[test]
    fn reuses_one_sanitizer_across_multiple_violations_of_the_same_label() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            r"
            #[taint_check(labels = [password])]
            mod auth;
            ",
        );
        dir.write(
            "auth.rs",
            "fn handle_login(#[sensitive(password)] password: &str) {\n    log_debug(password);\n    log_error(password);\n}\n#[taint_sink(password, policy = \"no_sensitive\")]\nfn log_debug(msg: &str) {}\n#[taint_sink(password, policy = \"no_sensitive\")]\nfn log_error(msg: &str) {}\n",
        );

        let plan = generate_patches(&lib).unwrap();
        assert_eq!(plan.patches.len(), 2);
        let auth_path = dir.0.join("auth.rs");
        let rewritten = &plan.rewritten_sources[&auth_path];
        // Only one sanitizer fn should have been generated, reused twice.
        assert_eq!(
            rewritten
                .matches("fn __taint_refactor_redact_password")
                .count(),
            1
        );
        syn::parse_file(rewritten).unwrap();
    }

    #[test]
    fn skips_a_violation_nested_inside_an_inline_mod() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            "#[taint_check(labels = [password])]\nmod auth {\n    fn handle_login(#[sensitive(password)] password: &str) {\n        log_debug(password);\n    }\n    #[taint_sink(password, policy = \"no_sensitive\")]\n    fn log_debug(msg: &str) {}\n}\n",
        );

        let plan = generate_patches(&lib).unwrap();
        assert!(plan.patches.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].sink_fn, "log_debug");
    }

    #[test]
    fn a_clean_crate_produces_no_patches() {
        let dir = TempDir::new();
        let lib = dir.write("lib.rs", "fn plain() {}\n");
        let plan = generate_patches(&lib).unwrap();
        assert!(plan.patches.is_empty());
        assert!(plan.skipped.is_empty());
        assert!(plan.rewritten_sources.is_empty());
    }

    #[test]
    fn missing_entry_file_is_an_error() {
        assert!(generate_patches(Path::new("/nonexistent/lib.rs")).is_err());
    }
}
