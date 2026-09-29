//! Writing (updating) `[package.metadata.rusty.capabilities]` —
//! `--capabilities --update`'s format-preserving `Cargo.toml` rewrite.
//!
//! Narrowing (bringing the declaration down to match derived usage) is
//! always allowed; widening needs `--allow-widen`, and the caller is
//! expected to have shown the diff first — matching
//! `rfcs/0007-capability-manifest.md`'s friction rule. On a crate with no
//! declaration at all, [`apply_update`] writes a **draft** (`draft =
//! true`) instead of a reviewed declaration; `--capabilities` refuses to
//! pass against a draft until a human removes the flag (see
//! [`crate::capability_check::CapabilityReport::fails`]).

use std::path::Path;

use capability_core::{AllocLevel, CapabilityCeiling, IoCeiling, PtrLevel};
use toml_edit::{table, value, DocumentMut, Item, Table};

use crate::capability_derive::DerivedScope;
use crate::capability_manifest::DeclaredCapabilities;

/// One category's proposed change, for the diff `--update` should print
/// before writing.
#[derive(Debug)]
pub struct CategoryChange {
    /// The category name (`"alloc"`, `"io.network"`, `"ptr"`, ...).
    pub category: String,
    /// The previously declared value (or `"none"`/`"no"` if there was no
    /// prior declaration at all).
    pub from: String,
    /// The value `--update` would write.
    pub to: String,
    /// `true` if this change widens the declaration — needs
    /// `--allow-widen`.
    pub widens: bool,
}

/// A category's name and an accessor for its ceiling flag.
type IoCategoryName = (&'static str, fn(IoCeiling) -> bool);

const IO_CATEGORY_NAMES: &[IoCategoryName] = &[
    ("display", |c| c.display),
    ("filesystem", |c| c.filesystem),
    ("registry", |c| c.registry),
    ("serial", |c| c.serial),
    ("usb", |c| c.usb),
    ("bluetooth", |c| c.bluetooth),
    ("network", |c| c.network),
    ("device", |c| c.device),
    ("process", |c| c.process),
    ("any", |c| c.any),
];

/// The ceiling that exactly matches `derived` — the narrowest declaration
/// that covers everything actually found, never wider.
#[must_use]
fn ceiling_from_derived(derived: &DerivedScope) -> CapabilityCeiling {
    let used = derived.io_levels_used();
    let io = IoCeiling {
        display: used.contains(&capability_core::IoLevel::Display),
        filesystem: used.contains(&capability_core::IoLevel::Filesystem),
        registry: used.contains(&capability_core::IoLevel::Registry),
        serial: used.contains(&capability_core::IoLevel::Serial),
        usb: used.contains(&capability_core::IoLevel::Usb),
        bluetooth: used.contains(&capability_core::IoLevel::Bluetooth),
        network: used.contains(&capability_core::IoLevel::Network),
        device: used.contains(&capability_core::IoLevel::Device),
        process: used.contains(&capability_core::IoLevel::Process),
        any: false,
    };
    CapabilityCeiling {
        alloc: Some(derived.alloc),
        io,
        ptr: Some(derived.ptr),
    }
}

const fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Compute the ceiling `--update` would write, and the list of changes
/// versus `declared` (if any).
#[must_use]
pub fn compute_update(
    declared: Option<&DeclaredCapabilities>,
    derived: &DerivedScope,
) -> (CapabilityCeiling, Vec<CategoryChange>) {
    let new_ceiling = ceiling_from_derived(derived);
    let mut changes = Vec::new();

    let old_alloc = declared.map_or(AllocLevel::None, |d| d.ceiling.alloc_or_none());
    let new_alloc = new_ceiling.alloc_or_none();
    if old_alloc != new_alloc {
        changes.push(CategoryChange {
            category: "alloc".to_string(),
            from: format!("{old_alloc:?}"),
            to: format!("{new_alloc:?}"),
            widens: new_alloc.risk_level() > old_alloc.risk_level(),
        });
    }

    let old_ptr = declared.map_or(PtrLevel::None, |d| d.ceiling.ptr_or_none());
    let new_ptr = new_ceiling.ptr_or_none();
    if old_ptr != new_ptr {
        changes.push(CategoryChange {
            category: "ptr".to_string(),
            from: format!("{old_ptr:?}"),
            to: format!("{new_ptr:?}"),
            widens: new_ptr.risk_level() > old_ptr.risk_level(),
        });
    }

    let old_io = declared.map_or_else(IoCeiling::default, |d| d.ceiling.io);
    for (name, extract) in IO_CATEGORY_NAMES {
        let old_flag = extract(old_io);
        let new_flag = extract(new_ceiling.io);
        if old_flag != new_flag {
            changes.push(CategoryChange {
                category: format!("io.{name}"),
                from: yes_no(old_flag).to_string(),
                to: yes_no(new_flag).to_string(),
                widens: new_flag && !old_flag,
            });
        }
    }

    (new_ceiling, changes)
}

/// Compute and (unless it would widen without permission) write the
/// updated declaration to `cargo_toml`.
///
/// The `--allow-widen` friction only applies when narrowing/widening an
/// **existing** declaration — a crate with no declaration at all has
/// nothing reviewed to protect, and the draft this writes already forces
/// review before `--capabilities` can pass on it (see
/// [`crate::capability_check::CapabilityReport::fails`]), so an initial
/// draft-write is never refused for "widening from nothing".
///
/// # Errors
///
/// Returns `Err` if `declared` is `Some` (an existing declaration), any
/// change widens it, and `allow_widen` is `false` (nothing is written in
/// that case), or on a file-read/parse/write failure.
pub fn apply_update(
    cargo_toml: &Path,
    declared: Option<&DeclaredCapabilities>,
    derived: &DerivedScope,
    allow_widen: bool,
) -> Result<Vec<CategoryChange>, String> {
    let (new_ceiling, changes) = compute_update(declared, derived);

    if declared.is_some() && !allow_widen && changes.iter().any(|c| c.widens) {
        return Err("refusing to widen without --allow-widen".to_string());
    }

    let draft = declared.is_none();
    write_manifest(cargo_toml, &new_ceiling, draft)?;
    Ok(changes)
}

/// Format-preserving rewrite of `[package.metadata.rusty.capabilities]`
/// in `cargo_toml` — everything else in the file (comments, key order,
/// unrelated tables) is left byte-identical, the same principle
/// `rusty-source-edit` applies to Rust source.
fn write_manifest(
    cargo_toml: &Path,
    ceiling: &CapabilityCeiling,
    draft: bool,
) -> Result<(), String> {
    let contents = std::fs::read_to_string(cargo_toml)
        .map_err(|e| format!("{}: could not read file: {e}", cargo_toml.display()))?;
    let mut doc = contents
        .parse::<DocumentMut>()
        .map_err(|e| format!("{}: not valid TOML: {e}", cargo_toml.display()))?;

    let package = doc
        .entry("package")
        .or_insert_with(table)
        .as_table_mut()
        .ok_or_else(|| "package is not a table".to_string())?;
    let metadata = entry_table(package, "metadata");
    let rusty = entry_table(metadata, "rusty");
    let capabilities = entry_table(rusty, "capabilities");

    *capabilities = Table::new();
    capabilities.insert("alloc", value(render_alloc(ceiling.alloc_or_none())));
    capabilities.insert("ptr", value(render_ptr(ceiling.ptr_or_none())));
    if draft {
        capabilities.insert("draft", value(true));
    }

    let io_table = entry_table(capabilities, "io");
    *io_table = Table::new();
    for (name, extract) in IO_CATEGORY_NAMES {
        io_table.insert(name, value(yes_no(extract(ceiling.io))));
    }

    std::fs::write(cargo_toml, doc.to_string())
        .map_err(|e| format!("{}: could not write file: {e}", cargo_toml.display()))
}

/// Get-or-insert a nested table under `parent[key]`.
///
/// A table this call itself creates is marked implicit, so it doesn't
/// print its own empty `[a.b]` header line — only the deepest table that
/// actually ends up holding keys (`capabilities`, `capabilities.io`, both
/// explicitly reset to a plain, non-implicit `Table::new()` right after
/// this returns in [`write_manifest`]) gets a real header, matching how
/// Cargo.toml conventionally writes a deep `package.metadata.*` path as
/// one `[package.metadata.rusty.capabilities]` line rather than one empty
/// header per path segment. An *existing* table (the caller's own
/// `[package.metadata]`, say, with unrelated keys already in it) is left
/// exactly as already formatted.
fn entry_table<'a>(parent: &'a mut Table, key: &str) -> &'a mut Table {
    if !parent.contains_key(key) {
        let mut new_table = table().into_table().expect("table() is always a table");
        new_table.set_implicit(true);
        parent.insert(key, Item::Table(new_table));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .expect("just ensured present as a table")
}

const fn render_alloc(level: AllocLevel) -> &'static str {
    match level {
        AllocLevel::None => "none",
        AllocLevel::Heap => "heap",
        AllocLevel::Any => "any",
    }
}

const fn render_ptr(level: PtrLevel) -> &'static str {
    match level {
        PtrLevel::None => "none",
        PtrLevel::Read => "read",
        PtrLevel::Any => "any",
        PtrLevel::Write(capability_core::PtrBound::Bounded) => "write-bounded",
        PtrLevel::Write(capability_core::PtrBound::Any) => "write-any",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_derive::DerivedFn;
    use capability_core::IoLevel;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn write_temp_manifest(contents: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusty-taint-check-capability-update-test-{}-{}.toml",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn derived_with(alloc: AllocLevel, io: Option<IoLevel>) -> DerivedScope {
        DerivedScope {
            alloc,
            ptr: PtrLevel::None,
            functions: io
                .into_iter()
                .map(|level| DerivedFn {
                    path: PathBuf::from("src/lib.rs"),
                    fn_name: "f".to_string(),
                    line: 1,
                    detected: capability_core::CapabilitySet {
                        alloc: None,
                        io: Some(level),
                        ptr: None,
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn narrowing_is_allowed_without_allow_widen() {
        let path = write_temp_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"heap\"\nptr = \"none\"\n",
        );
        let declared = crate::capability_manifest::read_declared(&path).unwrap();
        let derived = derived_with(AllocLevel::None, None);
        let changes = apply_update(&path, declared.as_ref(), &derived, false).unwrap();
        assert!(changes.iter().any(|c| c.category == "alloc" && !c.widens));

        let reread = crate::capability_manifest::read_declared(&path)
            .unwrap()
            .unwrap();
        assert_eq!(reread.ceiling.alloc_or_none(), AllocLevel::None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detects_a_ptr_change() {
        let path = write_temp_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nptr = \"none\"\n",
        );
        let declared = crate::capability_manifest::read_declared(&path).unwrap();
        let mut derived = derived_with(AllocLevel::None, None);
        derived.ptr = PtrLevel::Read;
        let changes = apply_update(&path, declared.as_ref(), &derived, true).unwrap();
        let ptr_change = changes.iter().find(|c| c.category == "ptr").unwrap();
        assert_eq!(ptr_change.from, "None");
        assert_eq!(ptr_change.to, "Read");
        assert!(ptr_change.widens);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detects_an_io_category_change_in_both_directions() {
        let path = write_temp_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities.io]\nfilesystem = \"yes\"\n",
        );
        let declared = crate::capability_manifest::read_declared(&path).unwrap();
        let derived = derived_with(AllocLevel::None, Some(IoLevel::Network));
        let changes = apply_update(&path, declared.as_ref(), &derived, true).unwrap();

        let network_change = changes.iter().find(|c| c.category == "io.network").unwrap();
        assert_eq!(network_change.from, "no");
        assert_eq!(network_change.to, "yes");
        assert!(network_change.widens);

        let filesystem_change = changes
            .iter()
            .find(|c| c.category == "io.filesystem")
            .unwrap();
        assert_eq!(filesystem_change.from, "yes");
        assert_eq!(filesystem_change.to, "no");
        assert!(!filesystem_change.widens);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn widening_is_refused_without_allow_widen() {
        let path = write_temp_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"none\"\n",
        );
        let declared = crate::capability_manifest::read_declared(&path).unwrap();
        let derived = derived_with(AllocLevel::Heap, None);
        let err = apply_update(&path, declared.as_ref(), &derived, false).unwrap_err();
        assert!(err.contains("--allow-widen"));

        // Refused — file must be untouched.
        let reread = crate::capability_manifest::read_declared(&path)
            .unwrap()
            .unwrap();
        assert_eq!(reread.ceiling.alloc_or_none(), AllocLevel::None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn widening_succeeds_with_allow_widen() {
        let path = write_temp_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"none\"\n",
        );
        let declared = crate::capability_manifest::read_declared(&path).unwrap();
        let derived = derived_with(AllocLevel::Heap, None);
        let changes = apply_update(&path, declared.as_ref(), &derived, true).unwrap();
        assert!(changes.iter().any(|c| c.category == "alloc" && c.widens));

        let reread = crate::capability_manifest::read_declared(&path)
            .unwrap()
            .unwrap();
        assert_eq!(reread.ceiling.alloc_or_none(), AllocLevel::Heap);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writing_with_no_prior_declaration_marks_it_draft() {
        let path = write_temp_manifest("[package]\nname = \"demo\"\n");
        let derived = derived_with(AllocLevel::None, None);
        apply_update(&path, None, &derived, false).unwrap();

        let reread = crate::capability_manifest::read_declared(&path)
            .unwrap()
            .unwrap();
        assert!(reread.draft);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writing_into_a_fresh_manifest_does_not_print_empty_intermediate_headers() {
        // `package.metadata` and `package.metadata.rusty` have no keys of
        // their own here — only `package.metadata.rusty.capabilities`
        // does — so they must not get their own empty `[...]` header line.
        let path = write_temp_manifest("[package]\nname = \"demo\"\n");
        let derived = derived_with(AllocLevel::Heap, None);
        apply_update(&path, None, &derived, false).unwrap();

        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!rewritten.contains("[package.metadata]\n"));
        assert!(!rewritten.contains("[package.metadata.rusty]\n"));
        assert!(rewritten.contains("[package.metadata.rusty.capabilities]"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn updating_an_already_declared_draft_keeps_it_a_draft_until_removed() {
        // `apply_update` only ever writes `draft = true` when there was
        // no declaration at all beforehand — once a human has reviewed
        // and re-run `--update` on an *existing* (non-draft) declaration,
        // the flag must not reappear.
        let path = write_temp_manifest(
            "[package]\nname = \"demo\"\n\n[package.metadata.rusty.capabilities]\nalloc = \"none\"\n",
        );
        let declared = crate::capability_manifest::read_declared(&path).unwrap();
        let derived = derived_with(AllocLevel::None, None);
        apply_update(&path, declared.as_ref(), &derived, false).unwrap();

        let reread = crate::capability_manifest::read_declared(&path)
            .unwrap()
            .unwrap();
        assert!(!reread.draft);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn preserves_unrelated_manifest_content() {
        let path = write_temp_manifest(
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[dependencies]\nserde = \"1\"\n",
        );
        let derived = derived_with(AllocLevel::Heap, None);
        apply_update(&path, None, &derived, true).unwrap();

        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(rewritten.contains("version = \"1.0.0\""));
        assert!(rewritten.contains("[dependencies]"));
        assert!(rewritten.contains("serde"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_an_error() {
        let derived = derived_with(AllocLevel::None, None);
        assert!(apply_update(Path::new("/nonexistent/Cargo.toml"), None, &derived, false).is_err());
    }

    #[test]
    fn renders_every_alloc_and_ptr_level() {
        assert_eq!(render_alloc(AllocLevel::None), "none");
        assert_eq!(render_alloc(AllocLevel::Heap), "heap");
        assert_eq!(render_alloc(AllocLevel::Any), "any");
        assert_eq!(render_ptr(PtrLevel::None), "none");
        assert_eq!(render_ptr(PtrLevel::Read), "read");
        assert_eq!(render_ptr(PtrLevel::Any), "any");
        assert_eq!(
            render_ptr(PtrLevel::Write(capability_core::PtrBound::Bounded)),
            "write-bounded"
        );
        assert_eq!(
            render_ptr(PtrLevel::Write(capability_core::PtrBound::Any)),
            "write-any"
        );
    }

    #[test]
    fn updating_twice_reuses_the_existing_intermediate_tables() {
        // The second `apply_update` call hits `entry_table`'s
        // already-present branch for `metadata`/`rusty`/`capabilities`/
        // `io`, not just the freshly-created path the other tests cover.
        let path = write_temp_manifest("[package]\nname = \"demo\"\n");
        let first = derived_with(AllocLevel::None, None);
        apply_update(&path, None, &first, false).unwrap();

        let declared = crate::capability_manifest::read_declared(&path).unwrap();
        let second = derived_with(AllocLevel::Heap, Some(IoLevel::Network));
        apply_update(&path, declared.as_ref(), &second, true).unwrap();

        let reread = crate::capability_manifest::read_declared(&path)
            .unwrap()
            .unwrap();
        assert_eq!(reread.ceiling.alloc_or_none(), AllocLevel::Heap);
        assert!(reread.ceiling.io.network);
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            rewritten
                .matches("[package.metadata.rusty.capabilities]")
                .count(),
            1
        );
        let _ = std::fs::remove_file(&path);
    }
}
