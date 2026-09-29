//! Reading `[package.metadata.rusty.capabilities]`.
//!
//! RFC 0007's crate-level declared capability scope, in RFC 0008's
//! set-valued `io` shape (a plain `io = "network"` string, as RFC 0007's
//! own guide-level example first sketched, would inherit the same
//! "network implies filesystem" ordering quirk RFC 0008 exists to fix —
//! see `rfcs/0008-capability-mod-and-crate-level.md`).
//!
//! # Shape
//!
//! ```toml
//! [package.metadata.rusty.capabilities]
//! alloc = "heap"
//! io = { network = "yes", filesystem = "no" }
//! ptr = "none"
//! ```
//!
//! `alloc`/`ptr` are single strings (same vocabulary as
//! `#[capability(...)]`'s own function-level form); `io` is a table of
//! `category = "yes"/"no"`, same shape `capability-attr`'s mod-level
//! ceiling parses (`crates/capability-attr/src/parser.rs::parse_io_ceiling`) —
//! deliberately kept identical rather than inventing a second grammar for
//! the same concept. An omitted `io` category defaults to `"no"`; an
//! omitted `alloc`/`ptr` defaults to `none`, same as every other
//! declaration in this workspace. `draft = true` marks a declaration
//! nobody has reviewed yet (written by `--update` on a crate with no
//! prior declaration) — see [`crate::capability_check`].

use std::path::{Path, PathBuf};

use capability_core::{AllocLevel, CapabilityCeiling, IoCeiling, PtrBound, PtrLevel};

/// The parsed `[package.metadata.rusty.capabilities]` table.
#[derive(Debug)]
pub struct DeclaredCapabilities {
    /// The declared ceiling itself.
    pub ceiling: CapabilityCeiling,
    /// `true` if `draft = true` is present.
    pub draft: bool,
}

/// Read and parse `[package.metadata.rusty.capabilities]` from `cargo_toml`.
///
/// Returns `Ok(None)` if the file parses but has no such table at all (no
/// declaration exists yet) — distinct from a parse/shape error, which is
/// `Err`.
///
/// # Errors
///
/// Returns `Err` on a file-read failure, invalid TOML, or a value that
/// doesn't match the shape documented above (unknown level/category name,
/// wrong value type).
pub fn read_declared(cargo_toml: &Path) -> Result<Option<DeclaredCapabilities>, String> {
    let contents = std::fs::read_to_string(cargo_toml)
        .map_err(|e| format!("{}: could not read file: {e}", cargo_toml.display()))?;
    let table: toml::Table = contents
        .parse()
        .map_err(|e| format!("{}: not valid TOML: {e}", cargo_toml.display()))?;

    let Some(caps_table) = table
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("rusty"))
        .and_then(|r| r.get("capabilities"))
        .and_then(toml::Value::as_table)
    else {
        return Ok(None);
    };

    let alloc = parse_alloc(caps_table)?;
    let ptr = parse_ptr(caps_table)?;
    let io = parse_io_ceiling(caps_table)?;
    let draft = caps_table
        .get("draft")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);

    Ok(Some(DeclaredCapabilities {
        ceiling: CapabilityCeiling { alloc, io, ptr },
        draft,
    }))
}

/// Search `start`'s directory, then every ancestor, for a `Cargo.toml`.
///
/// A local copy of `taint-generate`'s own `manifest::find_manifest` —
/// duplicated deliberately rather than shared, since `taint-generate`
/// already depends on `taint-check`, and the reverse dependency would be
/// a real Cargo cycle. Small enough to not be worth a new shared crate.
#[must_use]
pub fn find_manifest(start: &Path) -> Option<PathBuf> {
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

fn parse_alloc(table: &toml::Table) -> Result<Option<AllocLevel>, String> {
    match table.get("alloc").and_then(toml::Value::as_str) {
        None => Ok(None),
        Some("none") => Ok(Some(AllocLevel::None)),
        Some("heap") => Ok(Some(AllocLevel::Heap)),
        Some("any") => Ok(Some(AllocLevel::Any)),
        Some(other) => Err(format!(
            "capabilities.alloc: unknown level `{other}` (expected `none`, `heap`, or `any`)"
        )),
    }
}

fn parse_ptr(table: &toml::Table) -> Result<Option<PtrLevel>, String> {
    match table.get("ptr").and_then(toml::Value::as_str) {
        None => Ok(None),
        Some("none") => Ok(Some(PtrLevel::None)),
        Some("read") => Ok(Some(PtrLevel::Read)),
        Some("any") => Ok(Some(PtrLevel::Any)),
        Some("write-bounded") => Ok(Some(PtrLevel::Write(PtrBound::Bounded))),
        Some("write-any") => Ok(Some(PtrLevel::Write(PtrBound::Any))),
        Some(other) => Err(format!(
            "capabilities.ptr: unknown level `{other}` (expected `none`, `read`, `any`, `write-bounded`, or `write-any`)"
        )),
    }
}

fn parse_io_ceiling(table: &toml::Table) -> Result<IoCeiling, String> {
    let Some(io_table) = table.get("io").and_then(toml::Value::as_table) else {
        return Ok(IoCeiling::default());
    };

    let mut ceiling = IoCeiling::default();
    for (key, value) in io_table {
        let permitted = match value.as_str() {
            Some("yes") => true,
            Some("no") => false,
            _ => return Err(format!("capabilities.io.{key}: expected \"yes\" or \"no\"")),
        };
        match key.as_str() {
            "display" => ceiling.display = permitted,
            "filesystem" => ceiling.filesystem = permitted,
            "registry" => ceiling.registry = permitted,
            "serial" => ceiling.serial = permitted,
            "usb" => ceiling.usb = permitted,
            "bluetooth" => ceiling.bluetooth = permitted,
            "network" => ceiling.network = permitted,
            "device" => ceiling.device = permitted,
            "process" => ceiling.process = permitted,
            "any" => ceiling.any = permitted,
            other => {
                return Err(format!(
                    "capabilities.io: unknown category `{other}` (expected `display`, `filesystem`, `registry`, `serial`, `usb`, `bluetooth`, `network`, `device`, `process`, or `any`)"
                ));
            }
        }
    }
    Ok(ceiling)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn write_manifest(contents: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusty-taint-check-manifest-test-{}-{}.toml",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn returns_none_when_no_capabilities_table_exists() {
        let path = write_manifest("[package]\nname = \"demo\"\n");
        assert!(read_declared(&path).unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parses_a_full_declaration() {
        let path = write_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"heap\"\nptr = \"none\"\n\n[package.metadata.rusty.capabilities.io]\nnetwork = \"yes\"\nfilesystem = \"no\"\n",
        );
        let declared = read_declared(&path).unwrap().unwrap();
        assert_eq!(declared.ceiling.alloc_or_none(), AllocLevel::Heap);
        assert_eq!(declared.ceiling.ptr_or_none(), PtrLevel::None);
        assert!(declared.ceiling.io.network);
        assert!(!declared.ceiling.io.filesystem);
        assert!(!declared.draft);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn omitted_categories_default_to_most_restrictive() {
        let path =
            write_manifest("[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\n");
        let declared = read_declared(&path).unwrap().unwrap();
        assert_eq!(declared.ceiling.alloc_or_none(), AllocLevel::None);
        assert_eq!(declared.ceiling.ptr_or_none(), PtrLevel::None);
        assert!(!declared.ceiling.io.network);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recognizes_the_draft_flag() {
        let path = write_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\ndraft = true\n",
        );
        let declared = read_declared(&path).unwrap().unwrap();
        assert!(declared.draft);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_alloc_level_is_an_error() {
        let path = write_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"bump\"\n",
        );
        assert!(read_declared(&path).unwrap_err().contains("alloc"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_io_category_is_an_error() {
        let path = write_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities.io]\nspi = \"yes\"\n",
        );
        assert!(read_declared(&path).unwrap_err().contains("spi"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(read_declared(Path::new("/nonexistent/Cargo.toml")).is_err());
    }

    #[test]
    fn find_manifest_locates_cargo_toml_in_an_ancestor_directory() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "rusty-taint-check-find-manifest-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        let nested = dir.join("src").join("lib.rs");
        std::fs::write(&nested, "").unwrap();

        assert_eq!(find_manifest(&nested), Some(dir.join("Cargo.toml")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_manifest_returns_none_when_nothing_is_found() {
        assert_eq!(find_manifest(Path::new("/nonexistent/deep/path")), None);
    }

    #[test]
    fn find_manifest_accepts_a_directory_path_directly() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "rusty-taint-check-find-manifest-dir-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();

        assert_eq!(find_manifest(&dir), Some(dir.join("Cargo.toml")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_every_ptr_level() {
        for (word, level) in [
            ("read", PtrLevel::Read),
            ("any", PtrLevel::Any),
            ("write-bounded", PtrLevel::Write(PtrBound::Bounded)),
            ("write-any", PtrLevel::Write(PtrBound::Any)),
        ] {
            let path = write_manifest(&format!(
                "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nptr = \"{word}\"\n"
            ));
            let declared = read_declared(&path).unwrap().unwrap();
            assert_eq!(declared.ceiling.ptr_or_none(), level, "ptr = \"{word}\"");
            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn unknown_ptr_level_is_an_error() {
        let path = write_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nptr = \"execute\"\n",
        );
        assert!(read_declared(&path).unwrap_err().contains("ptr"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn io_value_that_is_not_yes_or_no_is_an_error() {
        let path = write_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities.io]\nnetwork = \"maybe\"\n",
        );
        assert!(read_declared(&path)
            .unwrap_err()
            .contains("expected \"yes\" or \"no\""));
        let _ = std::fs::remove_file(&path);
    }
}
