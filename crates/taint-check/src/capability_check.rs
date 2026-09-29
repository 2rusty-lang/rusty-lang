//! Comparing a crate's declared capability ceiling
//! ([`crate::capability_manifest`]) against its derived scope
//! ([`crate::capability_derive`]) — RFC 0007's three outcomes:
//!
//! | Derived vs declared | Meaning | Default result |
//! |---|---|---|
//! | derived ⊆ declared, equal | Aligned | pass |
//! | derived exceeds declared (**widened**) | Code does more than intended | **fail** |
//! | derived below declared (**headroom**) | Declaration is broader than needed | warning; **fail** under `--strict` |
//!
//! `alloc`/`ptr` are single-level comparisons (same "is detected within
//! the declared risk level" shape [`capability_core::lattice::check_subset`]
//! already uses); `io` is compared per category against the set-valued
//! ceiling ([RFC 0008](../../../rfcs/0008-capability-mod-and-crate-level.md)),
//! since a single crate-wide maximum can't say *which* permitted
//! categories were actually exercised.

use std::path::PathBuf;

use capability_core::{IoCeiling, IoLevel, PtrLevel};

use crate::capability_derive::DerivedScope;
use crate::capability_manifest::DeclaredCapabilities;

/// One category's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Derived is within (or equal to) what was declared.
    Aligned,
    /// Derived exceeds what was declared — code does more than intended.
    Widened,
    /// Declared permits more than derived ever uses.
    Headroom,
}

/// The culprit function responsible for a `Widened` outcome, if one could
/// be identified.
pub struct Culprit {
    /// The function's name.
    pub fn_name: String,
    /// The file it's defined in.
    pub path: PathBuf,
    /// Its 1-indexed source line.
    pub line: usize,
}

/// One category's comparison result.
pub struct CategoryResult {
    /// The category name (`"alloc"`, `"io.network"`, `"ptr"`, ...).
    pub category: String,
    /// The outcome.
    pub outcome: Outcome,
    /// The offending function, when [`Outcome::Widened`] and one could be
    /// identified.
    pub culprit: Option<Culprit>,
}

/// The full declared-vs-derived comparison, one [`CategoryResult`] per
/// category checked (`alloc`, `ptr`, and one per `io` sub-category).
pub struct CapabilityReport {
    /// Per-category results, in the order they were checked.
    pub results: Vec<CategoryResult>,
    /// `true` if the declaration itself is an unreviewed draft — see
    /// [`crate::capability_manifest::DeclaredCapabilities::draft`].
    pub draft: bool,
}

impl CapabilityReport {
    /// `true` if any category widened.
    #[must_use]
    pub fn has_widened(&self) -> bool {
        self.results.iter().any(|r| r.outcome == Outcome::Widened)
    }

    /// `true` if any category has headroom.
    #[must_use]
    pub fn has_headroom(&self) -> bool {
        self.results.iter().any(|r| r.outcome == Outcome::Headroom)
    }

    /// `true` if this report should fail a `--capabilities` run.
    ///
    /// A draft always fails (nobody has reviewed it yet — see
    /// `rfcs/0007-capability-manifest.md`'s draft-flag rule); a widened
    /// category always fails; a headroom-only report fails only under
    /// `--strict`.
    #[must_use]
    pub fn fails(&self, strict: bool) -> bool {
        self.draft || self.has_widened() || (strict && self.has_headroom())
    }
}

/// A category's name, the [`IoLevel`] it corresponds to, and an accessor
/// for its ceiling flag.
type IoCategory = (&'static str, IoLevel, fn(IoCeiling) -> bool);

/// The nine `io` categories [`capability_core::inspector`] can ever
/// detect (`any` is declare-only, like [`capability_core::PtrBound::Bounded`],
/// and excluded from per-category checking the same way — see
/// `capability_core::vocabulary`'s module docs).
const IO_CATEGORIES: &[IoCategory] = &[
    ("display", IoLevel::Display, |c| c.display),
    ("filesystem", IoLevel::Filesystem, |c| c.filesystem),
    ("registry", IoLevel::Registry, |c| c.registry),
    ("serial", IoLevel::Serial, |c| c.serial),
    ("usb", IoLevel::Usb, |c| c.usb),
    ("bluetooth", IoLevel::Bluetooth, |c| c.bluetooth),
    ("network", IoLevel::Network, |c| c.network),
    ("device", IoLevel::Device, |c| c.device),
    ("process", IoLevel::Process, |c| c.process),
];

/// Compare `declared` against `derived`, producing one [`CategoryResult`]
/// per category.
#[must_use]
pub fn check(declared: &DeclaredCapabilities, derived: &DerivedScope) -> CapabilityReport {
    let mut results = Vec::new();

    results.push(check_alloc(declared, derived));
    results.push(check_ptr(declared, derived));
    results.extend(check_io(declared, derived));

    CapabilityReport {
        results,
        draft: declared.draft,
    }
}

fn check_alloc(declared: &DeclaredCapabilities, derived: &DerivedScope) -> CategoryResult {
    let declared_level = declared.ceiling.alloc_or_none();
    let detected_level = derived.alloc;
    let outcome = compare_levels(detected_level.risk_level(), declared_level.risk_level());
    let culprit = (outcome == Outcome::Widened)
        .then(|| derived.first_fn_with_max_alloc())
        .flatten()
        .map(|f| Culprit {
            fn_name: f.fn_name.clone(),
            path: f.path.clone(),
            line: f.line,
        });
    CategoryResult {
        category: "alloc".to_string(),
        outcome,
        culprit,
    }
}

fn check_ptr(declared: &DeclaredCapabilities, derived: &DerivedScope) -> CategoryResult {
    let declared_level: PtrLevel = declared.ceiling.ptr_or_none();
    let detected_level = derived.ptr;
    let outcome = compare_levels(detected_level.risk_level(), declared_level.risk_level());
    let culprit = (outcome == Outcome::Widened)
        .then(|| derived.first_fn_with_max_ptr())
        .flatten()
        .map(|f| Culprit {
            fn_name: f.fn_name.clone(),
            path: f.path.clone(),
            line: f.line,
        });
    CategoryResult {
        category: "ptr".to_string(),
        outcome,
        culprit,
    }
}

fn check_io(declared: &DeclaredCapabilities, derived: &DerivedScope) -> Vec<CategoryResult> {
    let used = derived.io_levels_used();
    IO_CATEGORIES
        .iter()
        .map(|(name, level, permitted_fn)| {
            let permitted = permitted_fn(declared.ceiling.io) || declared.ceiling.io.any;
            let is_used = used.contains(level);
            let outcome = match (is_used, permitted) {
                (true, false) => Outcome::Widened,
                (false, true) => Outcome::Headroom,
                _ => Outcome::Aligned,
            };
            let culprit = (outcome == Outcome::Widened)
                .then(|| derived.first_fn_with_io(*level))
                .flatten()
                .map(|f| Culprit {
                    fn_name: f.fn_name.clone(),
                    path: f.path.clone(),
                    line: f.line,
                });
            CategoryResult {
                category: format!("io.{name}"),
                outcome,
                culprit,
            }
        })
        .collect()
}

fn compare_levels(detected: u8, declared: u8) -> Outcome {
    match detected.cmp(&declared) {
        std::cmp::Ordering::Greater => Outcome::Widened,
        std::cmp::Ordering::Less => Outcome::Headroom,
        std::cmp::Ordering::Equal => Outcome::Aligned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_derive::DerivedFn;
    use capability_core::{AllocLevel, CapabilityCeiling, CapabilitySet};
    use std::path::PathBuf;

    fn declared(ceiling: CapabilityCeiling, draft: bool) -> DeclaredCapabilities {
        DeclaredCapabilities { ceiling, draft }
    }

    fn derived_fn(name: &str, detected: CapabilitySet) -> DerivedFn {
        DerivedFn {
            path: PathBuf::from("src/lib.rs"),
            fn_name: name.to_string(),
            line: 1,
            detected,
        }
    }

    #[test]
    fn aligned_when_declared_matches_derived_exactly() {
        let d = declared(
            CapabilityCeiling {
                alloc: Some(AllocLevel::Heap),
                io: IoCeiling::default(),
                ptr: Some(PtrLevel::None),
            },
            false,
        );
        let derived = DerivedScope {
            alloc: AllocLevel::Heap,
            ptr: PtrLevel::None,
            functions: vec![],
        };
        let report = check(&d, &derived);
        assert!(!report.has_widened());
        assert!(!report.has_headroom());
        assert!(!report.fails(false));
        assert!(!report.fails(true));
    }

    #[test]
    fn widened_alloc_fails_even_without_strict() {
        let d = declared(CapabilityCeiling::default(), false);
        let derived = DerivedScope {
            alloc: AllocLevel::Heap,
            ptr: PtrLevel::None,
            functions: vec![derived_fn(
                "allocates",
                CapabilitySet {
                    alloc: Some(AllocLevel::Heap),
                    io: None,
                    ptr: None,
                },
            )],
        };
        let report = check(&d, &derived);
        assert!(report.has_widened());
        assert!(report.fails(false));
        let alloc_result = report
            .results
            .iter()
            .find(|r| r.category == "alloc")
            .unwrap();
        assert_eq!(alloc_result.outcome, Outcome::Widened);
        assert_eq!(alloc_result.culprit.as_ref().unwrap().fn_name, "allocates");
    }

    #[test]
    fn widened_ptr_names_its_culprit() {
        let d = declared(CapabilityCeiling::default(), false);
        let derived = DerivedScope {
            alloc: AllocLevel::None,
            ptr: PtrLevel::Read,
            functions: vec![derived_fn(
                "reads_raw_ptr",
                CapabilitySet {
                    alloc: None,
                    io: None,
                    ptr: Some(PtrLevel::Read),
                },
            )],
        };
        let report = check(&d, &derived);
        let ptr_result = report.results.iter().find(|r| r.category == "ptr").unwrap();
        assert_eq!(ptr_result.outcome, Outcome::Widened);
        assert_eq!(
            ptr_result.culprit.as_ref().unwrap().fn_name,
            "reads_raw_ptr"
        );
    }

    #[test]
    fn headroom_only_fails_under_strict() {
        let d = declared(
            CapabilityCeiling {
                alloc: Some(AllocLevel::Heap),
                io: IoCeiling::default(),
                ptr: None,
            },
            false,
        );
        let derived = DerivedScope {
            alloc: AllocLevel::None,
            ptr: PtrLevel::None,
            functions: vec![],
        };
        let report = check(&d, &derived);
        assert!(report.has_headroom());
        assert!(!report.has_widened());
        assert!(!report.fails(false));
        assert!(report.fails(true));
    }

    #[test]
    fn io_network_permitted_does_not_permit_filesystem() {
        let d = declared(
            CapabilityCeiling {
                alloc: None,
                io: IoCeiling {
                    network: true,
                    ..IoCeiling::default()
                },
                ptr: None,
            },
            false,
        );
        let derived = DerivedScope {
            alloc: AllocLevel::None,
            ptr: PtrLevel::None,
            functions: vec![derived_fn(
                "reads_file",
                CapabilitySet {
                    alloc: None,
                    io: Some(IoLevel::Filesystem),
                    ptr: None,
                },
            )],
        };
        let report = check(&d, &derived);
        let fs_result = report
            .results
            .iter()
            .find(|r| r.category == "io.filesystem")
            .unwrap();
        assert_eq!(fs_result.outcome, Outcome::Widened);
        assert_eq!(fs_result.culprit.as_ref().unwrap().fn_name, "reads_file");
        // network was declared but never used — separately reported as headroom.
        let net_result = report
            .results
            .iter()
            .find(|r| r.category == "io.network")
            .unwrap();
        assert_eq!(net_result.outcome, Outcome::Headroom);
    }

    #[test]
    fn any_io_ceiling_permits_every_category() {
        let d = declared(
            CapabilityCeiling {
                alloc: None,
                io: IoCeiling {
                    any: true,
                    ..IoCeiling::default()
                },
                ptr: None,
            },
            false,
        );
        let derived = DerivedScope {
            alloc: AllocLevel::None,
            ptr: PtrLevel::None,
            functions: vec![derived_fn(
                "connects",
                CapabilitySet {
                    alloc: None,
                    io: Some(IoLevel::Network),
                    ptr: None,
                },
            )],
        };
        let report = check(&d, &derived);
        assert!(!report.has_widened());
    }

    #[test]
    fn draft_always_fails_regardless_of_alignment() {
        let d = declared(CapabilityCeiling::default(), true);
        let derived = DerivedScope {
            alloc: AllocLevel::None,
            ptr: PtrLevel::None,
            functions: vec![],
        };
        let report = check(&d, &derived);
        assert!(!report.has_widened());
        assert!(!report.has_headroom());
        assert!(report.fails(false));
    }

    #[test]
    fn device_category_is_always_headroom_when_declared_since_it_is_undetectable() {
        // io(device) is declare-only (see capability_derive's module
        // docs) — a declared `device = "yes"` can never be matched by
        // real derived usage, so it always reports as headroom, never
        // aligned. This is expected, not a bug: it's a safety margin for
        // something the detector cannot itself verify.
        let d = declared(
            CapabilityCeiling {
                alloc: None,
                io: IoCeiling {
                    device: true,
                    ..IoCeiling::default()
                },
                ptr: None,
            },
            false,
        );
        let derived = DerivedScope {
            alloc: AllocLevel::None,
            ptr: PtrLevel::None,
            functions: vec![],
        };
        let report = check(&d, &derived);
        let device_result = report
            .results
            .iter()
            .find(|r| r.category == "io.device")
            .unwrap();
        assert_eq!(device_result.outcome, Outcome::Headroom);
    }
}
