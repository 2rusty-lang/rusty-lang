//! Subset checking: does the detected [`CapabilitySet`] from a function body
//! exceed what was declared in `#[capability(...)]`?

use crate::vocabulary::CapabilitySet;

/// A single capability-category violation: the body used more than was
/// declared.
#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    /// Which category was violated (`"alloc"`, `"io"`, or `"ptr"`).
    pub category: &'static str,
    /// The declared level, rendered for the error message.
    pub declared: String,
    /// The detected (actually used) level, rendered for the error message.
    pub detected: String,
}

/// Compare `detected` against `declared`, category by category.
///
/// Returns the first violation found (categories are checked in a fixed
/// order: `alloc`, `io`, `ptr`), or `None` if every detected level is
/// within its declared bound.
///
/// Categories are checked independently — this deliberately does not
/// attempt to find *all* violations in one pass; the compile error for the
/// first one is enough to point the developer at the right line, and fixing
/// it and recompiling surfaces the next one if there is one. This mirrors
/// how `rustc` itself generally reports one class of error before
/// re-checking.
#[must_use]
pub fn check_subset(detected: &CapabilitySet, declared: &CapabilitySet) -> Option<Violation> {
    if detected.alloc_or_none().risk_level() > declared.alloc_or_none().risk_level() {
        return Some(Violation {
            category: "alloc",
            declared: format!("{:?}", declared.alloc_or_none()),
            detected: format!("{:?}", detected.alloc_or_none()),
        });
    }
    if detected.io_or_none().risk_level() > declared.io_or_none().risk_level() {
        return Some(Violation {
            category: "io",
            declared: format!("{:?}", declared.io_or_none()),
            detected: format!("{:?}", detected.io_or_none()),
        });
    }
    if detected.ptr_or_none().risk_level() > declared.ptr_or_none().risk_level() {
        return Some(Violation {
            category: "ptr",
            declared: format!("{:?}", declared.ptr_or_none()),
            detected: format!("{:?}", detected.ptr_or_none()),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vocabulary::{AllocLevel, IoLevel, PtrLevel};

    #[test]
    fn no_violation_when_detected_is_within_declared_bounds() {
        let declared = CapabilitySet {
            alloc: Some(AllocLevel::Heap),
            io: Some(IoLevel::Display),
            ptr: Some(PtrLevel::None),
        };
        let detected = CapabilitySet {
            alloc: Some(AllocLevel::Heap),
            io: Some(IoLevel::None),
            ptr: None,
        };
        assert!(check_subset(&detected, &declared).is_none());
    }

    #[test]
    fn violation_when_alloc_exceeds_declared() {
        let declared = CapabilitySet::default(); // alloc(none) implicitly
        let detected = CapabilitySet {
            alloc: Some(AllocLevel::Heap),
            io: None,
            ptr: None,
        };
        let violation = check_subset(&detected, &declared).unwrap();
        assert_eq!(violation.category, "alloc");
        assert_eq!(violation.declared, "None");
        assert_eq!(violation.detected, "Heap");
    }

    #[test]
    fn alloc_checked_before_io_and_ptr() {
        let declared = CapabilitySet::default();
        let detected = CapabilitySet {
            alloc: Some(AllocLevel::Heap),
            io: Some(IoLevel::Network),
            ptr: Some(PtrLevel::Any),
        };
        let violation = check_subset(&detected, &declared).unwrap();
        assert_eq!(violation.category, "alloc");
    }
}
