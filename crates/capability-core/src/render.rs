//! Render a [`CapabilitySet`] back into `#[capability(...)]`'s surface
//! syntax.
//!
//! The exact inverse of `capability-attr`'s own attribute-argument parser.
//! Used by `taint-generate` to write a `#[capability(...)]` matching a
//! function's real, detected usage rather than guessing one.

use crate::vocabulary::{
    AllocLevel, CapabilityCeiling, CapabilitySet, IoCeiling, IoLevel, PtrBound, PtrLevel,
};

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
        IoLevel::Registry => "registry",
        IoLevel::Serial => "serial",
        IoLevel::Usb => "usb",
        IoLevel::Bluetooth => "bluetooth",
        IoLevel::Network => "network",
        IoLevel::Device => "device",
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

const fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Render `ceiling` into a mod-/crate-level `io(...)` ceiling's surface syntax.
///
/// E.g. `network: yes, filesystem: no, registry: no, serial: no, usb: no,
/// bluetooth: no, display: no, device: no, process: no, any: no` — see
/// `rfcs/0008-capability-mod-and-crate-level.md`. Every category is always
/// named explicitly, same round-trip reasoning as [`render_capability_args`].
#[must_use]
pub fn render_io_ceiling(ceiling: IoCeiling) -> String {
    format!(
        "network: {}, filesystem: {}, registry: {}, serial: {}, usb: {}, bluetooth: {}, display: {}, device: {}, process: {}, any: {}",
        yes_no(ceiling.network),
        yes_no(ceiling.filesystem),
        yes_no(ceiling.registry),
        yes_no(ceiling.serial),
        yes_no(ceiling.usb),
        yes_no(ceiling.bluetooth),
        yes_no(ceiling.display),
        yes_no(ceiling.device),
        yes_no(ceiling.process),
        yes_no(ceiling.any),
    )
}

/// Render `ceiling` into `#[capability(...)]`'s mod-/crate-level surface syntax.
///
/// E.g. `alloc(heap), io(network: yes, filesystem: no, ...), ptr(none)` —
/// see [`render_io_ceiling`] for the full `io(...)` shape.
#[must_use]
pub fn render_capability_ceiling(ceiling: &CapabilityCeiling) -> String {
    format!(
        "alloc({}), io({}), ptr({})",
        render_alloc(ceiling.alloc_or_none()),
        render_io_ceiling(ceiling.io),
        render_ptr(ceiling.ptr_or_none()),
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

    #[test]
    fn renders_every_alloc_level() {
        for (level, word) in [
            (AllocLevel::None, "none"),
            (AllocLevel::Heap, "heap"),
            (AllocLevel::Any, "any"),
        ] {
            let set = CapabilitySet {
                alloc: Some(level),
                io: None,
                ptr: None,
            };
            assert!(render_capability_args(&set).contains(&format!("alloc({word})")));
        }
    }

    #[test]
    fn renders_every_io_level() {
        for (level, word) in [
            (IoLevel::None, "none"),
            (IoLevel::Display, "display"),
            (IoLevel::Filesystem, "filesystem"),
            (IoLevel::Registry, "registry"),
            (IoLevel::Serial, "serial"),
            (IoLevel::Usb, "usb"),
            (IoLevel::Bluetooth, "bluetooth"),
            (IoLevel::Network, "network"),
            (IoLevel::Device, "device"),
            (IoLevel::Process, "process"),
            (IoLevel::Any, "any"),
        ] {
            let set = CapabilitySet {
                alloc: None,
                io: Some(level),
                ptr: None,
            };
            assert!(render_capability_args(&set).contains(&format!("io({word})")));
        }
    }

    #[test]
    fn renders_every_ptr_level() {
        for (level, word) in [
            (PtrLevel::None, "none"),
            (PtrLevel::Read, "read"),
            (PtrLevel::Any, "any"),
            (PtrLevel::Write(PtrBound::Bounded), "write, bounded"),
            (PtrLevel::Write(PtrBound::Any), "write, any"),
        ] {
            let set = CapabilitySet {
                alloc: None,
                io: None,
                ptr: Some(level),
            };
            assert!(render_capability_args(&set).contains(&format!("ptr({word})")));
        }
    }

    #[test]
    fn renders_default_io_ceiling_as_all_no() {
        assert_eq!(
            render_io_ceiling(IoCeiling::default()),
            "network: no, filesystem: no, registry: no, serial: no, usb: no, bluetooth: no, display: no, device: no, process: no, any: no"
        );
    }

    #[test]
    fn renders_a_non_default_io_ceiling() {
        let ceiling = IoCeiling {
            network: true,
            display: true,
            ..IoCeiling::default()
        };
        assert_eq!(
            render_io_ceiling(ceiling),
            "network: yes, filesystem: no, registry: no, serial: no, usb: no, bluetooth: no, display: yes, device: no, process: no, any: no"
        );
    }

    #[test]
    fn renders_a_full_capability_ceiling() {
        let ceiling = CapabilityCeiling {
            alloc: Some(AllocLevel::Heap),
            io: IoCeiling {
                network: true,
                ..IoCeiling::default()
            },
            ptr: Some(PtrLevel::None),
        };
        assert_eq!(
            render_capability_ceiling(&ceiling),
            "alloc(heap), io(network: yes, filesystem: no, registry: no, serial: no, usb: no, bluetooth: no, display: no, device: no, process: no, any: no), ptr(none)"
        );
    }
}
