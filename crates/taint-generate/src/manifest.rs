//! Resolving the real extern crate name for `rusty-capability-attr` from a
//! target file's nearest `Cargo.toml`.
//!
//! `#[capability(...)]` is a real proc-macro attribute — [`capability_gen`]
//! can only write one that compiles if the crate the target file belongs
//! to actually depends on `rusty-capability-attr`, and the name it must be
//! written under depends on how that dependency is declared: a plain
//! `rusty-capability-attr = "0.1.3"` line resolves in code as
//! `rusty_capability_attr` (Cargo's default hyphen-to-underscore rule), but
//! a renamed one (`capability_attr = { package = "rusty-capability-attr",
//! ... }`) resolves as whatever key was chosen. Guessing either name
//! wrong produces the exact same "cannot find attribute" failure this
//! module exists to prevent, so [`capability_attr_extern_name`] reads the
//! manifest instead of assuming.
//!
//! [`capability_gen`]: crate::capability_gen

use std::path::{Path, PathBuf};

/// The package this module looks for in `[dependencies]`.
const CAPABILITY_ATTR_PACKAGE: &str = "rusty-capability-attr";

/// Resolve the extern crate name `rusty-capability-attr` has in the crate
/// `target_file` belongs to, if any.
///
/// Walks up from `target_file`'s directory to find the nearest
/// `Cargo.toml`, and if `rusty-capability-attr` is a `[dependencies]` entry
/// there, returns the extern crate name that dependency resolves to in
/// code. Returns `None` if no `Cargo.toml` is found, it doesn't parse, or
/// the dependency isn't declared — in every case, the safe response is
/// "don't generate `#[capability(...)]` at all", not a guess.
#[must_use]
pub fn capability_attr_extern_name(target_file: &Path) -> Option<String> {
    let manifest_path = find_manifest(target_file)?;
    let contents = std::fs::read_to_string(&manifest_path).ok()?;
    let table: toml::Table = contents.parse().ok()?;
    let deps = table.get("dependencies")?.as_table()?;

    for (key, value) in deps {
        let package_name = value
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(|p| p.as_str())
            .unwrap_or(key.as_str());
        if package_name == CAPABILITY_ATTR_PACKAGE {
            return Some(key.replace('-', "_"));
        }
    }
    None
}

/// Search `start`'s directory, then every ancestor, for a `Cargo.toml`.
fn find_manifest(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_dir() {
        Some(start)
    } else {
        start.parent()
    };
    while let Some(d) = dir {
        let candidate = d.join("Cargo.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
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
                "rusty-taint-generate-manifest-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("src")).unwrap();
            Self(path)
        }

        fn write_manifest(&self, contents: &str) {
            std::fs::write(self.0.join("Cargo.toml"), contents).unwrap();
        }

        fn file_path(&self) -> PathBuf {
            self.0.join("src").join("lib.rs")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn finds_a_plain_string_dependency_by_default_extern_name() {
        let dir = TempDir::new();
        dir.write_manifest(
            "[package]\nname = \"demo\"\n\n[dependencies]\nrusty-capability-attr = \"0.1.3\"\n",
        );
        assert_eq!(
            capability_attr_extern_name(&dir.file_path()),
            Some("rusty_capability_attr".to_string())
        );
    }

    #[test]
    fn finds_a_path_dependency_with_no_rename() {
        let dir = TempDir::new();
        dir.write_manifest(
            "[package]\nname = \"demo\"\n\n[dependencies]\nrusty-capability-attr = { path = \"../capability-attr\", version = \"0.1.3\" }\n",
        );
        assert_eq!(
            capability_attr_extern_name(&dir.file_path()),
            Some("rusty_capability_attr".to_string())
        );
    }

    #[test]
    fn finds_a_renamed_dependency_by_its_key() {
        let dir = TempDir::new();
        dir.write_manifest(
            "[package]\nname = \"demo\"\n\n[dependencies]\ncapability_attr = { package = \"rusty-capability-attr\", version = \"0.1.3\" }\n",
        );
        assert_eq!(
            capability_attr_extern_name(&dir.file_path()),
            Some("capability_attr".to_string())
        );
    }

    #[test]
    fn returns_none_when_the_dependency_is_absent() {
        let dir = TempDir::new();
        dir.write_manifest("[package]\nname = \"demo\"\n\n[dependencies]\nsyn = \"2\"\n");
        assert_eq!(capability_attr_extern_name(&dir.file_path()), None);
    }

    #[test]
    fn returns_none_when_there_is_no_dependencies_table_at_all() {
        let dir = TempDir::new();
        dir.write_manifest("[package]\nname = \"demo\"\n");
        assert_eq!(capability_attr_extern_name(&dir.file_path()), None);
    }

    #[test]
    fn returns_none_when_no_manifest_is_found() {
        assert_eq!(
            capability_attr_extern_name(Path::new("/nonexistent/path/lib.rs")),
            None
        );
    }

    #[test]
    fn searches_ancestor_directories_not_just_the_immediate_parent() {
        let dir = TempDir::new();
        dir.write_manifest(
            "[package]\nname = \"demo\"\n\n[dependencies]\nrusty-capability-attr = \"0.1.3\"\n",
        );
        std::fs::create_dir_all(dir.0.join("src").join("nested")).unwrap();
        let nested_file = dir.0.join("src").join("nested").join("deep.rs");
        assert_eq!(
            capability_attr_extern_name(&nested_file),
            Some("rusty_capability_attr".to_string())
        );
    }
}
