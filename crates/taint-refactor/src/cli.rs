//! `taint-refactor [--dry-run] [--report] --crate <entry.rs>`.
//!
//! Default behavior writes every generated patch directly. `--dry-run`
//! prints the full rewritten contents of each affected file without
//! touching disk (a whole-file preview, not a line-level diff — the
//! sanitizer insertion changes enough of the file's structure that an
//! isolated before/after block per edit, like `taint-generate`'s, would be
//! less useful here). `--report` prints a summary of every patch applied
//! (or, with `--dry-run`, that would be applied) and every violation this
//! pass declined to patch. The flags compose.
//!
//! Exit codes: `0` ran cleanly (regardless of how many patches, if any,
//! it generated), `2` a usage or file error.

use std::path::Path;

use crate::patch::{self, PatchPlan};

fn print_report(plan: &PatchPlan) {
    for p in &plan.patches {
        println!(
            "{}: {} -> {} (label `{}`)",
            p.path.display(),
            p.sanitizer_name,
            p.sink_fn,
            p.label
        );
    }
    for s in &plan.skipped {
        println!(
            "{}: SKIPPED — violation reaching `{}` is nested inside an inline mod, not a \
             top-level function; not auto-patchable by this pass",
            s.path.display(),
            s.sink_fn
        );
    }
}

fn print_dry_run_preview(plan: &PatchPlan) {
    for (path, contents) in &plan.rewritten_sources {
        println!("=== {} (preview — not written) ===", path.display());
        println!("{contents}");
    }
}

/// Run the CLI over `args` (the process's own `argv`, `argv[0]` included).
/// Returns the process exit code.
pub fn run<I: IntoIterator<Item = String>>(args: I) -> i32 {
    let args: Vec<String> = args.into_iter().collect();

    let mut dry_run = false;
    let mut report = false;
    let mut entry: Option<&str> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--report" => report = true,
            "--crate" => {
                i += 1;
                entry = args.get(i).map(String::as_str);
            }
            _ => {}
        }
        i += 1;
    }

    let Some(entry) = entry else {
        eprintln!("usage: taint-refactor [--dry-run] [--report] --crate <entry.rs>");
        return 2;
    };

    let plan = match patch::generate_patches(Path::new(entry)) {
        Ok(plan) => plan,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };

    if report {
        print_report(&plan);
    }

    if plan.rewritten_sources.is_empty() {
        return 0;
    }

    if dry_run {
        print_dry_run_preview(&plan);
        return 0;
    }

    for (path, contents) in &plan.rewritten_sources {
        if let Err(e) = std::fs::write(path, contents) {
            eprintln!("{}: could not write file: {e}", path.display());
            return 2;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusty-taint-refactor-cli-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let full = self.0.join(relative);
            std::fs::write(&full, contents).unwrap();
            full
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn path_str(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn run_with_no_crate_flag_is_a_usage_error() {
        assert_eq!(run(vec!["taint-refactor".to_string()]), 2);
    }

    #[test]
    fn run_with_crate_flag_but_no_path_is_a_usage_error() {
        assert_eq!(
            run(vec!["taint-refactor".to_string(), "--crate".to_string()]),
            2
        );
    }

    #[test]
    fn missing_entry_file_is_an_error() {
        assert_eq!(
            run(vec![
                "taint-refactor".to_string(),
                "--crate".to_string(),
                "/nonexistent/lib.rs".to_string()
            ]),
            2
        );
    }

    #[test]
    fn dry_run_never_writes_the_file() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            r"
            #[taint_check(labels = [password])]
            mod auth;
            ",
        );
        let auth = dir.write(
            "auth.rs",
            "fn handle_login(#[sensitive(password)] password: &str) {\n    log_debug(password);\n}\n#[taint_sink(password, policy = \"no_sensitive\")]\nfn log_debug(msg: &str) {}\n",
        );
        let original = std::fs::read_to_string(&auth).unwrap();

        assert_eq!(
            run(vec![
                "taint-refactor".to_string(),
                "--dry-run".to_string(),
                "--crate".to_string(),
                path_str(&lib)
            ]),
            0
        );
        assert_eq!(std::fs::read_to_string(&auth).unwrap(), original);
    }

    #[test]
    fn run_writes_the_patch_by_default() {
        let dir = TempDir::new();
        let lib = dir.write(
            "lib.rs",
            r"
            #[taint_check(labels = [password])]
            mod auth;
            ",
        );
        let auth = dir.write(
            "auth.rs",
            "fn handle_login(#[sensitive(password)] password: &str) {\n    log_debug(password);\n}\n#[taint_sink(password, policy = \"no_sensitive\")]\nfn log_debug(msg: &str) {}\n",
        );

        assert_eq!(
            run(vec![
                "taint-refactor".to_string(),
                "--crate".to_string(),
                path_str(&lib)
            ]),
            0
        );
        let rewritten = std::fs::read_to_string(&auth).unwrap();
        assert!(rewritten.contains("__taint_refactor_redact_password"));
        syn::parse_file(&rewritten).unwrap();
    }

    #[test]
    fn a_clean_crate_leaves_files_untouched_and_exits_zero() {
        let dir = TempDir::new();
        let lib = dir.write("lib.rs", "fn plain() {}\n");
        assert_eq!(
            run(vec![
                "taint-refactor".to_string(),
                "--crate".to_string(),
                path_str(&lib)
            ]),
            0
        );
    }
}
