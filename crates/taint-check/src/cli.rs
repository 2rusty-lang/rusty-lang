//! `taint-check <file.rs> [file2.rs ...]` or `taint-check --crate
//! <entry.rs>`.
//!
//! Runs [`crate::inspector`] outside the compiler, over one or more source
//! files parsed with [`syn::parse_file`], for CI use with no proc-macro
//! dependency (per `docs/adr/ADR-0001`'s original design and
//! `docs/adr/ADR-0003`'s decision to build it). `--crate <entry.rs>`
//! switches to [`crate::crate_scan`]'s whole-crate, cross-binding mode
//! instead of scanning each given file independently — see that module's
//! docs for what it does and does not track.
//!
//! Exit codes: `0` clean, `1` one or more violations found, `2` a usage or
//! parse error (bad path, file doesn't parse as Rust, malformed
//! attribute).

use std::collections::HashSet;
use std::path::Path;

use syn::Item;

use crate::inspector::{self, Violation};
use crate::{parser, FN_SCOPE_ERROR};

/// Parse `path` and run the taint-check inspection over every
/// `#[taint_check(labels = [...])]`-annotated `mod` found in it (at any
/// nesting depth).
///
/// # Errors
///
/// Returns `Err` with a human-readable message on a file-read failure, a
/// Rust-syntax parse failure, or a malformed taint-check attribute.
pub fn check_file(path: &str) -> Result<Vec<Violation>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("{path}: could not read file: {e}"))?;
    let file = syn::parse_file(&content).map_err(|e| format!("{path}: not valid Rust: {e}"))?;

    let mut violations = Vec::new();
    for item in &file.items {
        collect_from_item(item, &mut violations)?;
    }
    Ok(violations)
}

fn collect_from_item(item: &Item, violations: &mut Vec<Violation>) -> Result<(), String> {
    match item {
        Item::Mod(m) => {
            for attr in &m.attrs {
                if attr.path().is_ident("taint_check") {
                    let args = attr
                        .meta
                        .require_list()
                        .map_err(|e| e.to_string())?
                        .tokens
                        .clone();
                    let parsed = parser::parse_taint_check_args(args).map_err(|e| e.to_string())?;
                    let found =
                        inspector::inspect_mod(m, &parsed.labels).map_err(|e| e.to_string())?;
                    violations.extend(found);
                }
            }
            if let Some((_, items)) = &m.content {
                for inner in items {
                    collect_from_item(inner, violations)?;
                }
            }
            Ok(())
        }
        Item::Fn(f) => {
            if f.attrs.iter().any(|a| a.path().is_ident("taint_check")) {
                return Err(format!("{}: {FN_SCOPE_ERROR}", f.sig.ident));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn run_crate_mode(entry: &str) -> i32 {
    match crate::crate_scan::scan_crate(Path::new(entry)) {
        Ok(violations) => {
            for cv in &violations {
                println!(
                    "{}",
                    crate::error::format_violation(&cv.violation, &cv.path.display().to_string())
                );
            }
            i32::from(!violations.is_empty())
        }
        Err(message) => {
            eprintln!("{message}");
            2
        }
    }
}

/// Run the CLI over `args` (the process's own `argv`, `argv[0]` included —
/// matches `std::env::args()`'s shape). Prints violations to stdout,
/// errors to stderr, and returns the process exit code.
pub fn run<I: IntoIterator<Item = String>>(args: I) -> i32 {
    let args: Vec<String> = args.into_iter().collect();

    if args.get(1).map(String::as_str) == Some("--crate") {
        return args.get(2).map_or_else(
            || {
                eprintln!("usage: taint-check --crate <entry.rs>");
                2
            },
            |entry| run_crate_mode(entry),
        );
    }

    let paths: Vec<String> = args.into_iter().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: taint-check <file.rs> [file2.rs ...]");
        return 2;
    }

    let mut seen_paths: HashSet<String> = HashSet::new();
    let mut violation_count = 0usize;
    for path in paths {
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        match check_file(&path) {
            Ok(violations) => {
                for violation in &violations {
                    println!("{}", crate::error::format_violation(violation, &path));
                }
                violation_count += violations.len();
            }
            Err(message) => {
                eprintln!("{message}");
                return 2;
            }
        }
    }

    i32::from(violation_count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // No `tempfile` dev-dependency (the workspace's minimal-dependency
    // pattern) — a handful of uniquely-named files in `std::env::temp_dir()`
    // don't warrant adding one.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(contents: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusty-taint-check-test-{}-{}.rs",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }

        fn path_str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write_fixture(src: &str) -> TempFile {
        TempFile::new(src)
    }

    #[test]
    fn clean_file_has_no_violations() {
        let file = write_fixture(
            r#"
            #[taint_check(labels = [password])]
            mod scope {
                fn handle_login(#[sensitive(password)] password: &str) {
                    let clean = redact(password);
                    log_debug(&clean);
                }
                #[taint_sanitizer]
                fn redact(s: &str) -> String { "[REDACTED]".to_string() }
                #[taint_sink(password, policy = "no_sensitive")]
                fn log_debug(msg: &str) {}
            }
            "#,
        );
        let violations = check_file(&file.path_str()).unwrap();
        assert!(violations.is_empty());
    }

    #[test]
    fn violating_file_reports_line_and_column() {
        let file = write_fixture(
            "#[taint_check(labels = [password])]\nmod scope {\n    fn handle_login(#[sensitive(password)] password: &str) {\n        log_debug(password);\n    }\n    #[taint_sink(password, policy = \"no_sensitive\")]\n    fn log_debug(msg: &str) {}\n}\n",
        );
        let violations = check_file(&file.path_str()).unwrap();
        assert_eq!(violations.len(), 1);
        let rendered = crate::error::format_violation(&violations[0], &file.path_str());
        assert!(rendered.contains(":4:"));
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(check_file("/nonexistent/does-not-exist.rs").is_err());
    }

    #[test]
    fn run_with_no_args_returns_usage_exit_code() {
        assert_eq!(run(vec!["taint-check".to_string()]), 2);
    }

    #[test]
    fn run_exits_nonzero_on_violation() {
        let file = write_fixture(
            r#"
            #[taint_check(labels = [password])]
            mod scope {
                fn handle_login(#[sensitive(password)] password: &str) {
                    log_debug(password);
                }
                #[taint_sink(password, policy = "no_sensitive")]
                fn log_debug(msg: &str) {}
            }
            "#,
        );
        assert_eq!(run(vec!["taint-check".to_string(), file.path_str()]), 1);
    }

    #[test]
    fn run_deduplicates_repeated_paths() {
        let file = write_fixture("mod scope {}\n");
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                file.path_str(),
                file.path_str()
            ]),
            0
        );
    }

    #[test]
    fn run_reports_the_error_and_exits_with_usage_code_on_a_bad_path() {
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "/nonexistent/does-not-exist.rs".to_string()
            ]),
            2
        );
    }

    #[test]
    fn malformed_taint_check_attribute_is_an_error() {
        // `#[taint_check]` with no parenthesized argument list at all — not
        // just a wrong argument, but a shape `Attribute::meta::require_list`
        // itself rejects.
        let file = write_fixture("#[taint_check]\nmod scope {}\n");
        assert!(check_file(&file.path_str()).is_err());
    }

    #[test]
    fn taint_check_on_a_bare_fn_is_the_documented_scope_error() {
        let file = write_fixture(
            r"
            #[taint_check(labels = [password])]
            fn handle_login(password: &str) {}
            ",
        );
        let err = check_file(&file.path_str()).unwrap_err();
        assert!(err.contains("mod"));
    }

    #[test]
    fn crate_mode_with_no_entry_path_is_a_usage_error() {
        assert_eq!(
            run(vec!["taint-check".to_string(), "--crate".to_string()]),
            2
        );
    }

    #[test]
    fn crate_mode_finds_a_violation_via_the_real_binary_entry_point() {
        let file = write_fixture(
            r#"
            #[taint_check(labels = [password])]
            mod scope {
                fn handle_login(#[sensitive(password)] password: &str) {
                    log_debug(password);
                }
                #[taint_sink(password, policy = "no_sensitive")]
                fn log_debug(msg: &str) {}
            }
            "#,
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                file.path_str()
            ]),
            1
        );
    }

    #[test]
    fn crate_mode_reports_a_missing_entry_file_as_a_usage_error() {
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                "/nonexistent/lib.rs".to_string()
            ]),
            2
        );
    }

    #[test]
    fn non_mod_non_fn_top_level_items_are_ignored() {
        let file = write_fixture(
            r#"
            use std::fmt::Write as _;
            const _UNUSED: i32 = 1;
            #[taint_check(labels = [password])]
            mod scope {
                fn handle_login(#[sensitive(password)] password: &str) {
                    log_debug(password);
                }
                #[taint_sink(password, policy = "no_sensitive")]
                fn log_debug(msg: &str) {}
            }
            "#,
        );
        let violations = check_file(&file.path_str()).unwrap();
        assert_eq!(violations.len(), 1);
    }
}
