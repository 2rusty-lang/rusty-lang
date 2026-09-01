//! Render a [`CapabilitySet`] back into `#[capability(...)]`'s surface
//! syntax.
//!
//! The exact inverse of `capability-attr`'s own attribute-argument parser.
//! Used by `taint-generate` to write a `#[capability(...)]` matching a
//! function's real, detected usage rather than guessing one.

use crate::vocabulary::{AllocLevel, CapabilitySet, IoLevel, PtrBound, PtrLevel};

const fn render_alloc(level: AllocLevel) -> &'static str {
    match level {
        AllocLevel::None => "none",
        AllocLevel::Heap => "heap",
        AllocLevel::Any => "any",
    }
}

const fn render_io(level: IoLevel) -> &'static str {
    match level {
        IoLevel::None => "none",
        IoLevel::Display => "display",
        IoLevel::Filesystem => "filesystem",
        IoLevel::Network => "network",
        IoLevel::Process => "process",
        IoLevel::Any => "any",
    }
}

const fn render_ptr(level: PtrLevel) -> &'static str {
    match level {
        PtrLevel::None => "none",
        PtrLevel::Read => "read",
        PtrLevel::Any => "any",
        PtrLevel::Write(PtrBound::Bounded) => "write, bounded",
        PtrLevel::Write(PtrBound::Any) => "write, any",
    }
}

/// Render `set` into `#[capability(...)]`'s argument surface syntax, e.g.
/// `alloc(heap), io(display), ptr(none)`.
///
/// Every category is always named explicitly (via each accessor's
/// `_or_none` default), so the output round-trips through
/// `capability-attr`'s own parser back to an equivalent [`CapabilitySet`]
/// regardless of which categories `set` actually had declared.
#[must_use]
pub fn render_capability_args(set: &CapabilitySet) -> String {
    format!(
        "alloc({}), io({}), ptr({})",
        render_alloc(set.alloc_or_none()),
        render_io(set.io_or_none()),
        render_ptr(set.ptr_or_none()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_category_explicitly() {
        let set = CapabilitySet::default();
        assert_eq!(
            render_capability_args(&set),
            "alloc(none), io(none), ptr(none)"
        );
    }

    #[test]
    fn renders_a_non_default_set() {
        let set = CapabilitySet {
            alloc: Some(AllocLevel::Heap),
            io: Some(IoLevel::Process),
            ptr: Some(PtrLevel::Write(PtrBound::Any)),
        };
        assert_eq!(
            render_capability_args(&set),
            "alloc(heap), io(process), ptr(write, any)"
        );
    }
}
