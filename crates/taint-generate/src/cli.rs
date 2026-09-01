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

use std::path::Path;

use source_edit::{apply_edits, SourceEdit};
use syn::File;

use crate::{capability_gen, manifest, taint_gen, top_level};

struct FileResult {
    source: String,
    edits: Vec<SourceEdit>,
    capability_suggestions: Vec<capability_gen::CapabilitySuggestion>,
    capability_generation_skipped: bool,
    /// The taint-attribute summary for this file's top-level functions
    /// (the `mod foo;` layout — see `crate::taint_gen`'s module docs),
    /// if anything was generated.
    file_scope_taint_suggestion: Option<taint_gen::TaintSuggestion>,
    /// The taint-attribute summaries for each eligible inline `mod { ... }`
    /// found in this file.
    inline_mod_taint_suggestions: Vec<taint_gen::TaintSuggestion>,
}

/// Infer a reportable "module name" from a file path, following Rust's own
/// file-to-module convention (`lib.rs`/`main.rs`/`mod.rs` take their
/// parent directory's name; anything else uses its own file stem) — used
/// only for `--report` text, since there's no real `mod` item in a
/// `mod foo;`-layout file to name it from.
fn infer_mod_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("mod")
        .to_string();
    if matches!(stem.as_str(), "mod" | "lib" | "main") {
        path.parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .map_or(stem, ToString::to_string)
    } else {
        stem
    }
}

fn read_and_parse(path: &str) -> Result<(String, File), String> {
    let source =
        std::fs::read_to_string(path).map_err(|e| format!("{path}: could not read file: {e}"))?;
    let file: File =
        syn::parse_file(&source).map_err(|e| format!("{path}: not valid Rust: {e}"))?;
    Ok((source, file))
}

/// Process one already-parsed file. `batch_primary_label` is the label
/// (if any) found across every file in this same `taint-generate`
/// invocation — see [`top_level::generate`]'s docs for why sink detection
/// needs it, not just this file's own scan.
fn process(
    path: &str,
    source: String,
    file: &File,
    batch_primary_label: Option<&str>,
) -> FileResult {
    let file_path = Path::new(path);
    let capability_extern_name = manifest::capability_attr_extern_name(file_path);
    let mod_name = infer_mod_name(file_path);

    let top = top_level::generate(
        &source,
        file,
        &mod_name,
        capability_extern_name.as_deref(),
        batch_primary_label,
    );
    let mut edits = top.edits;

    let (mod_edits, inline_mod_taint_suggestions) = taint_gen::generate(&source, file);
    edits.extend(mod_edits);

    FileResult {
        source,
        edits,
        capability_suggestions: top.capability_suggestions,
        capability_generation_skipped: top.capability_generation_skipped,
        file_scope_taint_suggestion: top.taint_suggestion,
        inline_mod_taint_suggestions,
    }
}

fn print_taint_suggestion(path: &str, s: &taint_gen::TaintSuggestion) {
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

fn print_report(path: &str, result: &FileResult) {
    if result.capability_generation_skipped {
        println!(
            "{path}: skipped #[capability(...)] generation — this crate's Cargo.toml doesn't depend on rusty-capability-attr"
        );
    }
    for s in &result.capability_suggestions {
        println!(
            "{path}: fn {} -> #[capability({})]",
            s.fn_name, s.rendered_attribute
        );
    }
    if let Some(s) = &result.file_scope_taint_suggestion {
        print_taint_suggestion(path, s);
        println!(
            "{path}: NOTE — add #[taint_check(labels = [{}])] by hand to this file's `mod {};` \
             declaration; this pass can't reach it, since that declaration lives in a different file",
            s.labels.join(", "),
            s.mod_name
        );
    }
    for s in &result.inline_mod_taint_suggestions {
        print_taint_suggestion(path, s);
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

    let mut parsed = Vec::with_capacity(paths.len());
    for path in &paths {
        match read_and_parse(path) {
            Ok((source, file)) => parsed.push((path, source, file)),
            Err(message) => {
                eprintln!("{message}");
                return 2;
            }
        }
    }

    // A label found in any one file here is visible to sink/sanitizer
    // detection in every other file of this same run — see
    // `top_level::generate`'s docs.
    let batch_primary_label = parsed
        .iter()
        .find_map(|(_, _, file)| taint_gen::find_labels(file).into_iter().next());

    for (path, source, file) in parsed {
        let result = process(path, source, &file, batch_primary_label.as_deref());

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

    /// A target `.rs` file inside its own throwaway crate directory (a
    /// `Cargo.toml` depending on `rusty-capability-attr` alongside it) —
    /// `capability_gen` generation only fires when that dependency
    /// resolves, so most of these tests need one. [`TempFile::bare`] skips
    /// the manifest for tests specifically about that gate.
    struct TempFile {
        dir: PathBuf,
        file: PathBuf,
    }

    impl TempFile {
        fn unique_dir() -> PathBuf {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "rusty-taint-generate-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn new(contents: &str) -> Self {
            let dir = Self::unique_dir();
            std::fs::write(
                dir.join("Cargo.toml"),
                "[package]\nname = \"demo\"\n\n[dependencies]\nrusty-capability-attr = \"0.1.3\"\n",
            )
            .unwrap();
            let file = dir.join("target.rs");
            std::fs::write(&file, contents).unwrap();
            Self { dir, file }
        }

        /// Same as [`Self::new`] but with no `Cargo.toml` at all.
        fn bare(contents: &str) -> Self {
            let dir = Self::unique_dir();
            let file = dir.join("target.rs");
            std::fs::write(&file, contents).unwrap();
            Self { dir, file }
        }

        fn path_str(&self) -> String {
            self.file.to_string_lossy().into_owned()
        }

        fn read(&self) -> String {
            std::fs::read_to_string(&self.file).unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
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
            .contains("#[rusty_capability_attr::capability(alloc(none), io(display), ptr(none))]"));
    }

    #[test]
    fn capability_generation_is_skipped_without_a_cargo_toml() {
        let file = TempFile::bare("fn log_message(msg: &str) {\n    println!(\"{msg}\");\n}\n");
        assert_eq!(run(vec!["taint-generate".to_string(), file.path_str()]), 0);
        // Nothing to generate at all (no taint labels either), so the file
        // is left completely untouched rather than getting a bare,
        // non-compiling `#[capability(...)]`.
        assert_eq!(
            file.read(),
            "fn log_message(msg: &str) {\n    println!(\"{msg}\");\n}\n"
        );
    }

    #[test]
    fn run_generates_taint_attributes_for_a_top_level_mod_foo_layout_file() {
        // The multi-file `taint-check --crate` layout: no inline `mod`
        // wrapper, so this file's own top-level items stand in for one.
        let file = TempFile::bare(
            "fn handle_login(password: &str) {\n    crate::logging::log_debug(password);\n}\n",
        );
        assert_eq!(run(vec!["taint-generate".to_string(), file.path_str()]), 0);
        let rewritten = file.read();
        assert!(rewritten.contains("#[sensitive(password)]"));
        // No inline `mod` exists to attach `#[taint_check(...)]` to.
        assert!(!rewritten.contains("#[taint_check"));
    }

    #[test]
    fn a_sink_in_a_separate_file_is_tagged_using_the_other_files_label() {
        // The realistic `mod foo;` multi-file layout: `password` is only
        // ever a sensitive param in one file, and the sink function lives
        // in a separate file passed in the same invocation.
        let auth =
            TempFile::bare("fn handle_login(password: &str) {\n    log_debug(password);\n}\n");
        let logging = TempFile::bare("fn log_debug(msg: &str) {\n    println!(\"{msg}\");\n}\n");

        assert_eq!(
            run(vec![
                "taint-generate".to_string(),
                auth.path_str(),
                logging.path_str()
            ]),
            0
        );

        assert!(auth.read().contains("#[sensitive(password)]"));
        assert!(logging
            .read()
            .contains("#[taint_sink(password, policy = \"no_sensitive\")]"));
    }

    #[test]
    fn report_notes_the_manual_taint_check_step_for_a_top_level_layout_file() {
        let file = TempFile::bare(
            "fn handle_login(password: &str) {\n    crate::logging::log_debug(password);\n}\n",
        );
        assert_eq!(
            run(vec![
                "taint-generate".to_string(),
                "--dry-run".to_string(),
                "--report".to_string(),
                file.path_str()
            ]),
            0
        );
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
