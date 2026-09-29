//! Deriving a crate's *actual* capability scope — RFC 0007's other half of
//! the declared-vs-derived comparison.
//!
//! Runs the same `capability_core::inspector::inspect_body`
//! `capability-attr`'s own macro and `taint-generate` both use, over
//! every function [`crate::crate_scan::resolve_files`] finds anywhere in
//! the crate's `mod foo;` tree — attributed or not, unlike
//! `capability-attr`'s own per-function check, which only ever sees code
//! that already carries `#[capability(...)]`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use capability_core::{AllocLevel, CapabilitySet, IoLevel, PtrLevel};
use syn::Item;

use crate::crate_scan::resolve_files;

/// One function's own detected capability usage, with enough location
/// info to report a violation against (e.g. "in fn `push_state`,
/// src/sync.rs:41").
pub struct DerivedFn {
    /// The file this function is defined in.
    pub path: PathBuf,
    /// The function's name.
    pub fn_name: String,
    /// The function signature's 1-indexed source line.
    pub line: usize,
    /// This one function's own detected capability usage.
    pub detected: CapabilitySet,
}

/// The crate-wide derived scope.
///
/// The per-category maximum `alloc`/`ptr` across every function found,
/// plus every individual function's own contribution (needed both to
/// report which function is responsible for a violation, and to check
/// per-`io`-category headroom against a set-valued ceiling — a single
/// crate-wide maximum can't answer "was `filesystem` ever actually used",
/// only "what's the worst thing anyone did").
pub struct DerivedScope {
    /// The maximum [`AllocLevel`] detected across every function.
    pub alloc: AllocLevel,
    /// The maximum [`PtrLevel`] detected across every function.
    pub ptr: PtrLevel,
    /// Every function found, in file-then-declaration order.
    pub functions: Vec<DerivedFn>,
}

impl DerivedScope {
    /// The distinct [`IoLevel`]s actually reached by at least one
    /// function — a *set*, not a single crate-wide maximum, since a
    /// set-valued ceiling needs to know which categories were used, not
    /// just the worst one.
    ///
    /// Still lossy *within* one function: `inspect_body` tracks only one
    /// `io` value per function (that function's own worst operation), so
    /// a function doing both `filesystem` and `network` work contributes
    /// only `Network` here. This is the same limitation
    /// `capability-attr`'s own function-level check already has — this
    /// rollup doesn't introduce a new one, it just can't remove an
    /// existing one either.
    #[must_use]
    pub fn io_levels_used(&self) -> BTreeSet<IoLevel> {
        self.functions
            .iter()
            .map(|f| f.detected.io_or_none())
            .filter(|level| *level != IoLevel::None)
            .collect()
    }

    /// The first function whose own detected `io` matches `level` — used
    /// to name a culprit in a violation report.
    #[must_use]
    pub fn first_fn_with_io(&self, level: IoLevel) -> Option<&DerivedFn> {
        self.functions
            .iter()
            .find(|f| f.detected.io_or_none() == level)
    }

    /// The first function whose own detected `alloc` matches the crate's
    /// overall maximum — used to name a culprit for an `alloc` violation.
    #[must_use]
    pub fn first_fn_with_max_alloc(&self) -> Option<&DerivedFn> {
        self.functions
            .iter()
            .find(|f| f.detected.alloc_or_none() == self.alloc)
    }

    /// The first function whose own detected `ptr` matches the crate's
    /// overall maximum — used to name a culprit for a `ptr` violation.
    #[must_use]
    pub fn first_fn_with_max_ptr(&self) -> Option<&DerivedFn> {
        self.functions
            .iter()
            .find(|f| f.detected.ptr_or_none() == self.ptr)
    }
}

/// Derive `entry`'s crate-wide capability scope.
///
/// # Errors
///
/// Same as [`crate::crate_scan::scan_crate`] — a file-read or
/// Rust-syntax parse failure anywhere in the resolved `mod foo;` tree.
pub fn derive_crate_scope(entry: &Path) -> Result<DerivedScope, String> {
    let files = resolve_files(entry)?;
    let mut functions = Vec::new();
    for (path, file) in &files {
        collect_fns(&file.items, path, &mut functions);
    }

    let mut alloc = AllocLevel::None;
    let mut ptr = PtrLevel::None;
    for f in &functions {
        if f.detected.alloc_or_none().risk_level() > alloc.risk_level() {
            alloc = f.detected.alloc_or_none();
        }
        if f.detected.ptr_or_none().risk_level() > ptr.risk_level() {
            ptr = f.detected.ptr_or_none();
        }
    }

    Ok(DerivedScope {
        alloc,
        ptr,
        functions,
    })
}

/// Walk `items` (recursing into every `mod { ... }`, matching
/// `crate_scan`'s own "an inline mod's children are part of the same
/// crate" treatment) collecting every `fn`'s own detected usage.
fn collect_fns(items: &[Item], path: &Path, out: &mut Vec<DerivedFn>) {
    for item in items {
        match item {
            Item::Fn(f) => {
                let detected = capability_core::inspector::inspect_body(&f.block);
                let line = f.sig.ident.span().start().line;
                out.push(DerivedFn {
                    path: path.to_path_buf(),
                    fn_name: f.sig.ident.to_string(),
                    line,
                    detected,
                });
            }
            Item::Mod(m) => {
                if let Some((_, children)) = &m.content {
                    collect_fns(children, path, out);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn write_temp(contents: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusty-taint-check-capability-derive-test-{}-{}.rs",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn derives_the_max_alloc_and_ptr_across_functions() {
        let entry =
            write_temp("fn pure_fn() {}\nfn allocates() { let _v: Vec<u8> = Vec::new(); }\n");
        let scope = derive_crate_scope(&entry).unwrap();
        assert_eq!(scope.alloc, AllocLevel::Heap);
        assert_eq!(scope.ptr, PtrLevel::None);
        assert_eq!(scope.functions.len(), 2);
        let _ = std::fs::remove_file(&entry);
    }

    #[test]
    fn derives_the_max_ptr_and_names_its_culprit() {
        let entry =
            write_temp("fn pure_fn() {}\nfn reads_raw(p: *const u8) -> u8 { unsafe { *p } }\n");
        let scope = derive_crate_scope(&entry).unwrap();
        assert_eq!(scope.ptr, PtrLevel::Read);
        let culprit = scope.first_fn_with_max_ptr().unwrap();
        assert_eq!(culprit.fn_name, "reads_raw");
        let _ = std::fs::remove_file(&entry);
    }

    #[test]
    fn collect_fns_ignores_non_fn_non_mod_items() {
        let entry = write_temp("struct Unrelated;\nuse std::fmt;\nfn only_fn() {}\n");
        let scope = derive_crate_scope(&entry).unwrap();
        assert_eq!(scope.functions.len(), 1);
        assert_eq!(scope.functions[0].fn_name, "only_fn");
        let _ = std::fs::remove_file(&entry);
    }

    #[test]
    fn io_levels_used_is_a_set_not_a_single_maximum() {
        let entry = write_temp(
            "fn reads_file() { let _ = std::fs::read_to_string(\"x\"); }\nfn connects() { let _ = std::net::TcpStream::connect(\"x:1\"); }\n",
        );
        let scope = derive_crate_scope(&entry).unwrap();
        let used = scope.io_levels_used();
        assert!(used.contains(&IoLevel::Filesystem));
        assert!(used.contains(&IoLevel::Network));
        let _ = std::fs::remove_file(&entry);
    }

    #[test]
    fn finds_the_culprit_function_for_a_given_io_level() {
        let entry =
            write_temp("fn connects() { let _ = std::net::TcpStream::connect(\"x:1\"); }\n");
        let scope = derive_crate_scope(&entry).unwrap();
        let culprit = scope.first_fn_with_io(IoLevel::Network).unwrap();
        assert_eq!(culprit.fn_name, "connects");
        let _ = std::fs::remove_file(&entry);
    }

    #[test]
    fn recurses_into_inline_mods() {
        let entry = write_temp(
            "mod inner {\n    pub fn allocates() { let _v: Vec<u8> = Vec::new(); }\n}\n",
        );
        let scope = derive_crate_scope(&entry).unwrap();
        assert_eq!(scope.functions.len(), 1);
        assert_eq!(scope.functions[0].fn_name, "allocates");
        let _ = std::fs::remove_file(&entry);
    }

    #[test]
    fn empty_crate_derives_nothing() {
        let entry = write_temp("");
        let scope = derive_crate_scope(&entry).unwrap();
        assert_eq!(scope.alloc, AllocLevel::None);
        assert_eq!(scope.ptr, PtrLevel::None);
        assert!(scope.functions.is_empty());
        let _ = std::fs::remove_file(&entry);
    }

    #[test]
    fn missing_entry_file_is_an_error() {
        assert!(derive_crate_scope(Path::new("/nonexistent/lib.rs")).is_err());
    }
}
