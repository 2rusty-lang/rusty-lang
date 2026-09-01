//! Whole-crate, cross-binding taint tracking — the `taint-check --crate
//! <entry.rs>` CLI mode (see `docs/adr/ADR-0005-generate-and-refactor.md`).
//!
//! [`inspect_mod`](crate::inspector::inspect_mod) and the `#[taint_check]`
//! proc-macro both see exactly one `mod`'s own direct children — a real
//! Rust-language constraint for the macro (a `#[proc_macro_attribute]`
//! only ever receives the tokens of the one item it's attached to), and a
//! deliberate scope match for the macro's CLI-single-file counterpart.
//! [`scan_crate`] lifts that limit for the CLI only: it follows `mod foo;`
//! declarations out to their files, builds one crate-wide sink/sanitizer/
//! function registry from everything it finds, and hands that to the
//! *same* internal per-function walk every other path already uses — the
//! wider registry alone means a sink declared in one file is now visible
//! to a call in a completely different one, and [`crate::inspector`]'s own
//! interprocedural summary (see that module's docs) additionally follows a
//! tainted value through a `let`-bound call into a function defined
//! anywhere else in the crate.
//!
//! # What "cross-binding" means here, precisely
//!
//! Exactly what the name says: taint crossing from one binding into a
//! *new* binding created by an interprocedural call's return value
//! (`let x = some_fn(tainted);`, where `some_fn` is defined elsewhere in
//! the crate). A bare statement call with no binding
//! (`some_fn(tainted);`, where `some_fn` itself calls a sink internally
//! but isn't a registered sink itself) is a different, real gap — no
//! *binding* is created there — left out of this pass on purpose rather
//! than silently mis-scoped under a name that doesn't cover it.
//!
//! # Module resolution — a real, stated subset of Rust's own rules
//!
//! Only `mod foo;` (not `mod foo { ... }`, which is already visible in its
//! parent file) is followed to another file, resolved the standard way:
//! `lib.rs`/`main.rs`/`mod.rs` keep their submodules in the same
//! directory; any other `foo.rs` keeps its submodules in a `foo/`
//! subdirectory. `#[path = "..."]` overrides are not honored — a mod that
//! can't be found at its conventional path is silently skipped (not an
//! error), since a missing file at this stage almost always means an
//! override this pass doesn't understand, not a broken crate. Total files
//! visited is capped at [`MAX_FILES`] as a safety bound against a
//! pathological or accidentally-cyclic `#[path]` setup.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use syn::{File, Item, ItemFn};

use crate::inspector::{self, SinkInfo, TaintContext, Violation};
use crate::parser;

/// Safety bound on how many files [`scan_crate`] will follow `mod foo;`
/// declarations into, regardless of how large the actual module tree is.
const MAX_FILES: usize = 500;

/// One violation found somewhere in the crate, together with its file.
///
/// Crate-wide mode has no single "current file" the way the single-file
/// CLI path does, so the path travels with each violation instead of
/// being implicit.
pub struct CrateViolation {
    /// The file the violation was found in.
    pub path: PathBuf,
    /// The violation itself.
    pub violation: Violation,
}

/// Follow `mod foo;` declarations from `entry` to build the crate's module
/// tree, then run the taint-propagation pass across every function found
/// anywhere in it, against one crate-wide registry.
///
/// Returns an empty `Vec` (not an error) if no `#[taint_check(labels =
/// [...])]` is found anywhere in the resolved tree — there is nothing to
/// scan against.
///
/// # Errors
///
/// Returns `Err` with a human-readable message on a file-read failure, a
/// Rust-syntax parse failure, or a malformed taint-check attribute.
pub fn scan_crate(entry: &Path) -> Result<Vec<CrateViolation>, String> {
    let files = resolve_files(entry)?;

    let mut declared_labels: Vec<String> = Vec::new();
    let mut seen_labels: HashSet<String> = HashSet::new();
    for (_, file) in &files {
        collect_declared_labels(&file.items, &mut declared_labels, &mut seen_labels);
    }
    if declared_labels.is_empty() {
        return Ok(Vec::new());
    }

    let mut sinks: HashMap<String, SinkInfo> = HashMap::new();
    let mut sanitizers: HashSet<String> = HashSet::new();
    let mut fn_defs: HashMap<String, &ItemFn> = HashMap::new();
    for (_, file) in &files {
        collect_all(
            &file.items,
            &declared_labels,
            &mut sinks,
            &mut sanitizers,
            &mut fn_defs,
        )
        .map_err(|e| e.to_string())?;
    }

    let ctx = TaintContext {
        sinks: &sinks,
        sanitizers: &sanitizers,
        fn_defs: &fn_defs,
    };

    let mut violations = Vec::new();
    for (path, file) in &files {
        collect_violations(&file.items, &ctx, path, &mut violations).map_err(|e| e.to_string())?;
    }
    Ok(violations)
}

fn submodule_dir(file_path: &Path) -> PathBuf {
    let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
    let is_root_style = matches!(
        file_path.file_name().and_then(|n| n.to_str()),
        Some("lib.rs" | "main.rs" | "mod.rs")
    );
    if is_root_style {
        parent.to_path_buf()
    } else {
        let stem = file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        parent.join(stem)
    }
}

fn resolve_files(entry: &Path) -> Result<Vec<(PathBuf, File)>, String> {
    let mut files = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue = vec![entry.to_path_buf()];

    while let Some(path) = queue.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        if files.len() >= MAX_FILES {
            break;
        }

        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: could not read file: {e}", path.display()))?;
        let file: File = syn::parse_file(&source)
            .map_err(|e| format!("{}: not valid Rust: {e}", path.display()))?;

        let dir = submodule_dir(&path);
        for item in &file.items {
            if let Item::Mod(m) = item {
                if m.content.is_none() {
                    let name = m.ident.to_string();
                    let as_file = dir.join(format!("{name}.rs"));
                    let as_dir_mod = dir.join(&name).join("mod.rs");
                    if as_file.is_file() {
                        queue.push(as_file);
                    } else if as_dir_mod.is_file() {
                        queue.push(as_dir_mod);
                    }
                    // Not found at either conventional path — likely a
                    // `#[path = "..."]` override, which this pass doesn't
                    // honor. Skipped, not an error (see module docs).
                }
            }
        }

        files.push((path, file));
    }

    Ok(files)
}

fn collect_declared_labels(items: &[Item], labels: &mut Vec<String>, seen: &mut HashSet<String>) {
    for item in items {
        let Item::Mod(m) = item else { continue };
        for attr in &m.attrs {
            if attr.path().is_ident("taint_check") {
                if let Ok(list) = attr.meta.require_list() {
                    if let Ok(parsed) = parser::parse_taint_check_args(list.tokens.clone()) {
                        for label in parsed.labels {
                            if seen.insert(label.clone()) {
                                labels.push(label);
                            }
                        }
                    }
                }
            }
        }
        if let Some((_, children)) = &m.content {
            collect_declared_labels(children, labels, seen);
        }
    }
}

fn collect_all<'a>(
    items: &'a [Item],
    declared_labels: &[String],
    sinks: &mut HashMap<String, SinkInfo>,
    sanitizers: &mut HashSet<String>,
    fn_defs: &mut HashMap<String, &'a ItemFn>,
) -> syn::Result<()> {
    for item in items {
        match item {
            Item::Fn(f) => {
                fn_defs.insert(f.sig.ident.to_string(), f);
                inspector::register_fn_sink_or_sanitizer(f, declared_labels, sinks, sanitizers)?;
            }
            Item::Mod(m) => {
                if let Some((_, children)) = &m.content {
                    collect_all(children, declared_labels, sinks, sanitizers, fn_defs)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn collect_violations(
    items: &[Item],
    ctx: &TaintContext,
    path: &Path,
    violations: &mut Vec<CrateViolation>,
) -> syn::Result<()> {
    for item in items {
        match item {
            Item::Fn(f) => {
                for violation in inspector::inspect_fn_with_ctx(f, ctx)? {
                    violations.push(CrateViolation {
                        path: path.to_path_buf(),
                        violation,
                    });
                }
            }
            Item::Mod(m) => {
                if let Some((_, children)) = &m.content {
                    collect_violations(children, ctx, path, violations)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
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
                "rusty-taint-check-crate-scan-{}-{}",
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
    fn finds_a_sink_declared_in_a_different_file_than_the_call_site() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            r"
            #[taint_check(labels = [password])]
            mod auth;
            mod logging;
            ",
        );
        dir.write(
            "auth.rs",
            r"
            fn handle_login(#[sensitive(password)] password: &str) {
                crate::logging::log_debug(password);
            }
            ",
        );
        dir.write(
            "logging.rs",
            r#"
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
        );

        let violations = scan_crate(&lib).unwrap();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation.sink_fn, "log_debug");
        assert!(violations[0].path.ends_with("auth.rs"));
    }

    #[test]
    fn interprocedural_summary_works_across_files_too() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            r"
            #[taint_check(labels = [password])]
            mod auth;
            mod helpers;
            ",
        );
        dir.write(
            "auth.rs",
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                let echoed = crate::helpers::wrap(password);
                log_debug(&echoed);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
        );
        dir.write(
            "helpers.rs",
            r"
            fn wrap(s: &str) -> String {
                s.to_string()
            }
            ",
        );

        let violations = scan_crate(&lib).unwrap();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn returns_empty_when_nothing_declares_taint_check() {
        let dir = TempDir::new();
        let lib = dir.write("lib.rs", "fn plain() {}\n");
        assert!(scan_crate(&lib).unwrap().is_empty());
    }

    #[test]
    fn resolves_mod_rs_style_submodules() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            r"
            #[taint_check(labels = [password])]
            mod auth;
            ",
        );
        dir.write(
            "auth/mod.rs",
            r#"
            fn handle_login(#[sensitive(password)] password: &str) {
                log_debug(password);
            }
            #[taint_sink(password, policy = "no_sensitive")]
            fn log_debug(msg: &str) {}
            "#,
        );

        let violations = scan_crate(&lib).unwrap();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn missing_entry_file_is_an_error() {
        assert!(scan_crate(Path::new("/nonexistent/lib.rs")).is_err());
    }
}
