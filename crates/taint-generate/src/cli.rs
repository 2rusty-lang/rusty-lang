//! `taint-generate [--dry-run] [--report] <file.rs> [file2.rs ...]`.
//!
//! Default behavior writes generated attributes directly into each file.
//! `--dry-run` computes every change and prints a before/after block per
//! changed item without touching disk. `--report` prints a structured
//! summary of what was (or would be) generated. The two flags compose:
//! `--dry-run --report` shows both the diff and the summary without
//! writing anything.
//!
//! Exit codes: `0` ran cleanly (regardless of how much, if anything, it
//! generated), `2` a usage or file error (bad path, file doesn't parse as
//! Rust).

use source_edit::{apply_edits, SourceEdit};
use syn::File;

use crate::{capability_gen, taint_gen};

struct FileResult {
    source: String,
    edits: Vec<SourceEdit>,
    capability_suggestions: Vec<capability_gen::CapabilitySuggestion>,
    taint_suggestions: Vec<taint_gen::TaintSuggestion>,
}

fn process(path: &str) -> Result<FileResult, String> {
    let source =
        std::fs::read_to_string(path).map_err(|e| format!("{path}: could not read file: {e}"))?;
    let file: File =
        syn::parse_file(&source).map_err(|e| format!("{path}: not valid Rust: {e}"))?;

    let (mut edits, capability_suggestions) = capability_gen::generate(&source, &file);
    let (taint_edits, taint_suggestions) = taint_gen::generate(&source, &file);
    edits.extend(taint_edits);

    Ok(FileResult {
        source,
        edits,
        capability_suggestions,
        taint_suggestions,
    })
}

fn print_report(path: &str, result: &FileResult) {
    for s in &result.capability_suggestions {
        println!(
            "{path}: fn {} -> #[capability({})]",
            s.fn_name, s.rendered_attribute
        );
    }
    for s in &result.taint_suggestions {
        println!(
            "{path}: mod {} -> #[taint_check(labels = [{}])]",
            s.mod_name,
            s.labels.join(", ")
        );
        for (fn_name, param, label) in &s.sensitive_params {
            println!("{path}:   {fn_name}({param}) -> #[sensitive({label})]");
        }
        for (fn_name, label) in &s.sinks {
            println!("{path}:   {fn_name} -> #[taint_sink({label}, policy = \"no_sensitive\")]");
        }
        for fn_name in &s.sanitizers {
            println!("{path}:   {fn_name} -> #[taint_sanitizer]");
        }
    }
}

fn print_dry_run_diff(path: &str, result: &FileResult) {
    let mut ordered: Vec<&SourceEdit> = result.edits.iter().collect();
    ordered.sort_by_key(|e| e.start);
    for edit in ordered {
        println!("--- {path}");
        for line in result.source[edit.start..edit.end].lines() {
            println!("-{line}");
        }
        for line in edit.replacement.lines() {
            println!("+{line}");
        }
    }
}

/// Run the CLI over `args` (the process's own `argv`, `argv[0]` included).
/// Returns the process exit code.
pub fn run<I: IntoIterator<Item = String>>(args: I) -> i32 {
    let mut dry_run = false;
    let mut report = false;
    let mut paths = Vec::new();

    for arg in args.into_iter().skip(1) {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--report" => report = true,
            other => paths.push(other.to_string()),
        }
    }

    if paths.is_empty() {
        eprintln!("usage: taint-generate [--dry-run] [--report] <file.rs> [file2.rs ...]");
        return 2;
    }

    for path in &paths {
        let result = match process(path) {
            Ok(r) => r,
            Err(message) => {
                eprintln!("{message}");
                return 2;
            }
        };

        if report {
            print_report(path, &result);
        }

        if result.edits.is_empty() {
            continue;
        }

        if dry_run {
            print_dry_run_diff(path, &result);
        } else {
            let rewritten = apply_edits(&result.source, &result.edits);
            if let Err(e) = std::fs::write(path, rewritten) {
                eprintln!("{path}: could not write file: {e}");
                return 2;
            }
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempFile(PathBuf);

    impl TempFile {
        fn new(contents: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusty-taint-generate-test-{}-{}.rs",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }

        fn path_str(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }

        fn read(&self) -> String {
            std::fs::read_to_string(&self.0).unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn run_with_no_args_returns_usage_exit_code() {
        assert_eq!(run(vec!["taint-generate".to_string()]), 2);
    }

    #[test]
    fn run_writes_generated_attributes_by_default() {
        let file = TempFile::new("fn log_message(msg: &str) {\n    println!(\"{msg}\");\n}\n");
        assert_eq!(run(vec!["taint-generate".to_string(), file.path_str()]), 0);
        assert!(file
            .read()
            .contains("#[capability(alloc(none), io(display), ptr(none))]"));
    }

    #[test]
    fn dry_run_never_writes_the_file() {
        let file = TempFile::new("fn log_message(msg: &str) {\n    println!(\"{msg}\");\n}\n");
        let original = file.read();
        assert_eq!(
            run(vec![
                "taint-generate".to_string(),
                "--dry-run".to_string(),
                file.path_str()
            ]),
            0
        );
        assert_eq!(file.read(), original);
    }

    #[test]
    fn a_file_needing_no_changes_is_left_untouched() {
        let file = TempFile::new("#[capability(alloc(any), io(any), ptr(any))]\nfn f() {}\n");
        let original = file.read();
        assert_eq!(run(vec!["taint-generate".to_string(), file.path_str()]), 0);
        assert_eq!(file.read(), original);
    }

    #[test]
    fn missing_file_is_a_usage_error() {
        assert_eq!(
            run(vec![
                "taint-generate".to_string(),
                "/nonexistent/x.rs".to_string()
            ]),
            2
        );
    }
}
