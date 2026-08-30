//! `syn::Path` matching helpers shared by `capability-attr` (call-path
//! detection for its allocation/IO/raw-pointer vocabulary) and
//! `taint-check` (sink/sanitizer call-path detection).
//!
//! This crate is unpublished and has no design doc of its own: every
//! function here was a private, non-`pub` helper inside `capability-attr`'s
//! `inspector.rs` before this extraction, never reachable from outside
//! that crate — doubly so since a `proc-macro = true` crate can only
//! export its `#[proc_macro_attribute]` entry points to begin with. Moving
//! them here changes no public API of either dependent crate.

#![warn(missing_docs)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "workspace-wide dependency-graph check, not something a single-crate pass can fix or meaningfully scope"
)]

use syn::Path;

/// Join every segment of `path` with `::` (e.g. `std::fs::read_to_string`).
#[must_use]
pub fn path_to_string(path: &Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Join just the trailing one or two segments of `path` with `::`, so
/// `Vec::new()` and `std::vec::Vec::new()` both match the same
/// `"Vec::new"` check regardless of how fully-qualified the call is
/// written.
#[must_use]
pub fn path_last_two(path: &Path) -> String {
    let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    if segs.len() >= 2 {
        format!("{}::{}", segs[segs.len() - 2], segs[segs.len() - 1])
    } else {
        segs.last().cloned().unwrap_or_default()
    }
}

/// `true` if any segment of `path` is exactly `marker`.
///
/// Used to catch a module marker (`fs`, `net`, `Command`, ...) appearing
/// anywhere in a call path, regardless of how much of the path precedes or
/// follows it.
#[must_use]
pub fn path_has_segment(path: &Path, marker: &str) -> bool {
    path.segments.iter().any(|s| s.ident == marker)
}

/// The trailing segment's identifier, as a `String`.
///
/// `log_debug`, `self::log_debug`, `super::log_debug`, and
/// `crate::auth::log_debug` all yield `"log_debug"`. Unlike
/// [`syn::Path::get_ident`], this does not require the path be a single
/// bare segment.
#[must_use]
pub fn path_last_segment(path: &Path) -> Option<String> {
    path.segments.last().map(|s| s.ident.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn path_to_string_joins_every_segment() {
        let path: Path = parse_quote!(std::fs::read_to_string);
        assert_eq!(path_to_string(&path), "std::fs::read_to_string");
    }

    #[test]
    fn path_last_two_joins_trailing_two_segments() {
        let path: Path = parse_quote!(std::vec::Vec::new);
        assert_eq!(path_last_two(&path), "Vec::new");
    }

    #[test]
    fn path_last_two_handles_a_single_segment_path() {
        let path: Path = parse_quote!(new);
        assert_eq!(path_last_two(&path), "new");
    }

    #[test]
    fn path_has_segment_matches_anywhere_in_the_path() {
        let path: Path = parse_quote!(std::fs::read_to_string);
        assert!(path_has_segment(&path, "fs"));
        assert!(!path_has_segment(&path, "net"));
    }

    #[test]
    fn path_last_segment_ignores_qualification() {
        assert_eq!(
            path_last_segment(&parse_quote!(log_debug)),
            Some("log_debug".to_string())
        );
        assert_eq!(
            path_last_segment(&parse_quote!(self::log_debug)),
            Some("log_debug".to_string())
        );
        assert_eq!(
            path_last_segment(&parse_quote!(super::log_debug)),
            Some("log_debug".to_string())
        );
        assert_eq!(
            path_last_segment(&parse_quote!(crate::auth::log_debug)),
            Some("log_debug".to_string())
        );
    }
}
