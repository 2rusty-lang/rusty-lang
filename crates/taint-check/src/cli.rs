//! `taint-check <file.rs> [file2.rs ...]` or `taint-check --crate
//! <entry.rs> [--capabilities [--update] [--allow-widen] [--strict]]`.
//!
//! Runs [`crate::inspector`] outside the compiler, over one or more source
//! files parsed with [`syn::parse_file`], for CI use with no proc-macro
//! dependency required of the target being scanned (per
//! `docs/adr/ADR-0001`'s original design and `docs/adr/ADR-0003`'s
//! decision to build it). `--crate <entry.rs>`
//! switches to [`crate::crate_scan`]'s whole-crate, cross-binding mode
//! instead of scanning each given file independently — see that module's
//! docs for what it does and does not track.
//!
//! `--crate <entry.rs> --capabilities` switches to a different check
//! entirely — [RFC 0007](../../../rfcs/0007-capability-manifest.md)'s
//! declared-vs-derived capability comparison, not taint tracking at all.
//! `--update` (optionally with `--allow-widen`) writes the derived scope
//! back to `[package.metadata.rusty.capabilities]`; `--strict` also fails
//! on headroom (a declared-but-unused permission), not just a widened
//! one. See [`crate::capability_manifest`], [`crate::capability_derive`],
//! [`crate::capability_check`], and [`crate::capability_update`].
//!
//! Exit codes (taint mode): `0` clean, `1` one or more violations found,
//! `2` a usage or parse error (bad path, file doesn't parse as Rust,
//! malformed attribute). Exit codes (`--capabilities` mode): `0` pass
//! (aligned, or `--update` wrote successfully), `1` declared scope
//! violated (or a draft, or no declaration exists at all without
//! `--update`), `2` a usage error.

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
#[capability_attr::capability(alloc(heap), io(filesystem), ptr(none))]
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

#[capability_attr::capability(alloc(none), io(none), ptr(none))]
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

#[capability_attr::capability(alloc(none), io(display), ptr(none))]
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

/// `--crate <entry.rs> --capabilities [--update] [--allow-widen] [--strict]`
/// — RFC 0007's declared-vs-derived capability check, not taint tracking.
#[capability_attr::capability(alloc(heap), io(filesystem), ptr(none))]
fn run_capabilities_mode(entry: &str, update: bool, allow_widen: bool, strict: bool) -> i32 {
    let entry_path = Path::new(entry);
    let Some(cargo_toml) = crate::capability_manifest::find_manifest(entry_path) else {
        eprintln!("{entry}: no Cargo.toml found in any ancestor directory");
        return 2;
    };

    let declared = match crate::capability_manifest::read_declared(&cargo_toml) {
        Ok(d) => d,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };

    let derived = match crate::capability_derive::derive_crate_scope(entry_path) {
        Ok(d) => d,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };

    if update {
        return run_capabilities_update(&cargo_toml, declared.as_ref(), &derived, allow_widen);
    }

    let Some(declared) = declared else {
        eprintln!(
            "capabilities: no [package.metadata.rusty.capabilities] declared in {} — run with --update to write one (as a draft)",
            cargo_toml.display()
        );
        return 1;
    };

    let report = crate::capability_check::check(&declared, &derived);
    print_capability_report(&report);
    i32::from(report.fails(strict))
}

#[capability_attr::capability(alloc(none), io(display), ptr(none))]
fn run_capabilities_update(
    cargo_toml: &Path,
    declared: Option<&crate::capability_manifest::DeclaredCapabilities>,
    derived: &crate::capability_derive::DerivedScope,
    allow_widen: bool,
) -> i32 {
    match crate::capability_update::apply_update(cargo_toml, declared, derived, allow_widen) {
        Ok(changes) if changes.is_empty() => {
            println!("capabilities: declaration already matches derived scope, nothing to update");
            0
        }
        Ok(changes) => {
            for c in &changes {
                let marker = if c.widens { "  (WIDENS)" } else { "" };
                println!("  {}: {} -> {}{marker}", c.category, c.from, c.to);
            }
            println!(
                "updated {} [package.metadata.rusty.capabilities]",
                cargo_toml.display()
            );
            0
        }
        Err(message) => {
            eprintln!("{message}");
            2
        }
    }
}

#[capability_attr::capability(alloc(none), io(display), ptr(none))]
fn print_capability_report(report: &crate::capability_check::CapabilityReport) {
    use crate::capability_check::Outcome;

    if report.draft {
        println!(
            "capabilities: declaration is a draft (draft = true) — review and remove the flag before this can pass"
        );
    }
    for r in &report.results {
        match r.outcome {
            Outcome::Aligned => {}
            Outcome::Widened => {
                if let Some(c) = &r.culprit {
                    println!(
                        "  {}: derived scope exceeds declared — {}:{}: in fn `{}`",
                        r.category,
                        c.path.display(),
                        c.line,
                        c.fn_name
                    );
                } else {
                    println!("  {}: derived scope exceeds declared", r.category);
                }
            }
            Outcome::Headroom => {
                println!("  {}: declared but never used (headroom)", r.category);
            }
        }
    }
    if report.has_widened() {
        println!("capabilities: derived scope exceeds declared scope");
    } else if report.has_headroom() {
        println!("capabilities: declared scope has unused headroom");
    } else if !report.draft {
        println!("capabilities: aligned");
    }
}

/// Run the CLI over `args` (the process's own `argv`, `argv[0]` included —
/// matches `std::env::args()`'s shape). Prints violations to stdout,
/// errors to stderr, and returns the process exit code.
#[capability_attr::capability(alloc(none), io(display), ptr(none))]
pub fn run<I: IntoIterator<Item = String>>(args: I) -> i32 {
    let args: Vec<String> = args.into_iter().collect();
    if args.get(1).map(String::as_str) == Some("--crate") {
        let mut entry: Option<&str> = None;
        let mut capabilities = false;
        let mut update = false;
        let mut allow_widen = false;
        let mut strict = false;
        for arg in &args[2..] {
            match arg.as_str() {
                "--capabilities" => capabilities = true,
                "--update" => update = true,
                "--allow-widen" => allow_widen = true,
                "--strict" => strict = true,
                other => entry = Some(other),
            }
        }
        let Some(entry) = entry else {
            eprintln!(
                "usage: taint-check --crate <entry.rs> [--capabilities [--update] [--allow-widen] [--strict]]"
            );
            return 2;
        };
        return if capabilities {
            run_capabilities_mode(entry, update, allow_widen, strict)
        } else {
            run_crate_mode(entry)
        };
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

    /// A throwaway crate directory (a real `Cargo.toml` alongside a
    /// `lib.rs`) — `--capabilities` needs a real manifest to find and
    /// read/write, unlike the bare single-file `TempFile` above.
    struct CapabilityCrateDir(PathBuf);

    impl CapabilityCrateDir {
        fn new(manifest: &str, lib_rs: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "rusty-taint-check-capabilities-cli-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
            std::fs::write(dir.join("lib.rs"), lib_rs).unwrap();
            Self(dir)
        }

        fn entry_path_str(&self) -> String {
            self.0.join("lib.rs").to_string_lossy().into_owned()
        }

        fn manifest_contents(&self) -> String {
            std::fs::read_to_string(self.0.join("Cargo.toml")).unwrap()
        }
    }

    impl Drop for CapabilityCrateDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn capabilities_mode_passes_when_declared_covers_derived() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"heap\"\nptr = \"none\"\n",
            "fn allocates() { let _v: Vec<u8> = Vec::new(); }\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
            ]),
            0
        );
    }

    #[test]
    fn capabilities_mode_fails_when_derived_widens_beyond_declared() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"none\"\n",
            "fn allocates() { let _v: Vec<u8> = Vec::new(); }\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
            ]),
            1
        );
    }

    #[test]
    fn capabilities_mode_headroom_only_fails_under_strict() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"heap\"\n",
            "fn pure_fn() {}\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
            ]),
            0
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
                "--strict".to_string(),
            ]),
            1
        );
    }

    #[test]
    fn capabilities_mode_with_no_declaration_at_all_fails_and_suggests_update() {
        let dir = CapabilityCrateDir::new("[package]\nname = \"demo\"\n", "fn pure_fn() {}\n");
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
            ]),
            1
        );
    }

    #[test]
    fn capabilities_update_writes_a_draft_on_a_crate_with_no_declaration() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n",
            "fn allocates() { let _v: Vec<u8> = Vec::new(); }\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
                "--update".to_string(),
            ]),
            0
        );
        assert!(dir.manifest_contents().contains("draft = true"));
        assert!(dir.manifest_contents().contains("alloc = \"heap\""));

        // The freshly-written draft still fails a plain check until reviewed.
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
            ]),
            1
        );
    }

    #[test]
    fn capabilities_update_refuses_to_widen_without_allow_widen() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"none\"\n",
            "fn allocates() { let _v: Vec<u8> = Vec::new(); }\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
                "--update".to_string(),
            ]),
            2
        );
        assert!(dir.manifest_contents().contains("alloc = \"none\""));
    }

    #[test]
    fn capabilities_update_widens_with_allow_widen() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"none\"\n",
            "fn allocates() { let _v: Vec<u8> = Vec::new(); }\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
                "--update".to_string(),
                "--allow-widen".to_string(),
            ]),
            0
        );
        assert!(dir.manifest_contents().contains("alloc = \"heap\""));
    }

    #[test]
    fn capabilities_mode_without_crate_flag_or_manifest_is_a_usage_error() {
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                "/nonexistent/lib.rs".to_string(),
                "--capabilities".to_string(),
            ]),
            2
        );
    }

    #[test]
    fn capabilities_mode_reports_a_malformed_manifest_as_a_usage_error() {
        let dir = CapabilityCrateDir::new(
            "[package\nname = \"demo\"\n", // invalid TOML: unterminated table header
            "fn pure_fn() {}\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
            ]),
            2
        );
    }

    #[test]
    fn capabilities_mode_reports_an_unparseable_entry_file_as_a_usage_error() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n",
            "fn broken( {\n", // invalid Rust
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
            ]),
            2
        );
    }

    #[test]
    fn capabilities_update_reports_nothing_to_change_when_already_aligned() {
        let dir = CapabilityCrateDir::new(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"none\"\nptr = \"none\"\n",
            "fn pure_fn() {}\n",
        );
        assert_eq!(
            run(vec![
                "taint-check".to_string(),
                "--crate".to_string(),
                dir.entry_path_str(),
                "--capabilities".to_string(),
                "--update".to_string(),
            ]),
            0
        );
    }

    #[test]
    fn print_capability_report_falls_back_when_a_widened_result_has_no_culprit() {
        // `check()` always attaches a culprit to a real `Widened` result —
        // this exercises the defensive fallback branch directly, for the
        // case that invariant doesn't hold (a hand-built report, not one
        // `check()` itself could ever produce).
        use crate::capability_check::{CapabilityReport, CategoryResult, Outcome};
        let report = CapabilityReport {
            results: vec![CategoryResult {
                category: "alloc".to_string(),
                outcome: Outcome::Widened,
                culprit: None,
            }],
            draft: false,
        };
        print_capability_report(&report);
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
