//! Capability vocabulary types: `alloc`/`io`/`ptr` levels and the combined
//! [`CapabilitySet`].
//!
//! Extracted from `capability-attr`'s own `parser.rs` (see
//! `docs/adr/ADR-0005-generate-and-refactor.md` for why) — the parsing of
//! `#[capability(...)]`'s attribute-argument *syntax* into these types
//! stays in `capability-attr` itself (it's specific to that macro's surface
//! syntax); only the vocabulary and the risk-ordering it encodes lives
//! here, since `taint-generate` needs to construct a [`CapabilitySet`] from
//! real body-usage detection without going through any attribute-parsing
//! at all.
//!
//! # Vocabulary — reduced from the RFC, for general-purpose userspace use
//!
//! `docs/aisecurity/capability-rfc-updated.md` proposes five categories:
//! `alloc`, `io`, `register`, `ptr`, `interrupt`. This crate implements
//! three of them:
//!
//! - [`AllocLevel`] — kept, but collapsed from the RFC's six embedded-
//!   specific tiers (`none`/`static`/`bump`/`pool`/`global`/`any` — `bump`
//!   and `pool` describe allocator strategies with no equivalent in
//!   userspace Rust, which always uses the global allocator) down to three:
//!   [`AllocLevel::None`], [`AllocLevel::Heap`], [`AllocLevel::Any`].
//! - [`IoLevel`] — kept, but reshaped: the RFC's `spi`/`i2c`/`uart`/`dma`
//!   tiers describe embedded hardware buses a userspace tool never touches
//!   directly, so they were dropped from this vocabulary. In their place,
//!   [`IoLevel::Process`] is *added* — the RFC has no equivalent, but
//!   subprocess spawning (spawning a helper process, a pager, an external
//!   diff/merge tool, a hook script) is one of userspace software's
//!   largest and most security-relevant real capability dimensions (see
//!   the module doc's risk-ordering note below). Also widened beyond this
//!   crate's original, narrower scope: [`IoLevel::Registry`],
//!   [`IoLevel::Serial`], [`IoLevel::Usb`], [`IoLevel::Bluetooth`],
//!   [`IoLevel::Device`] — real peripheral/host-configuration categories a
//!   general-purpose userspace tool may need to declare, reinstated in a
//!   userspace-appropriate shape rather than the RFC's embedded-bus
//!   framing (no raw `spi`/`i2c` register-level access; these are the
//!   OS-mediated userspace equivalents — a serial *port*, a USB *device
//!   handle*, a Bluetooth *socket*, not a raw bus transaction).
//! - [`PtrLevel`] — kept close to the RFC's own `ptr(write, bounded)` /
//!   `ptr(write, any)` shape (same `#[capability(ptr(write, bounded))]`
//!   surface syntax), since raw-pointer capability is exactly what matters
//!   at an FFI boundary.
//! - `register(...)` and `interrupt(...)` — **dropped entirely**, not
//!   stubbed. Both describe raw hardware register/interrupt-controller
//!   access below the OS, which has no meaning in userspace at all (unlike
//!   `io(serial)`/`io(usb)`/`io(bluetooth)` above, which *are* real
//!   userspace-reachable capabilities, just previously out of this crate's
//!   narrower scope); a stub type with no real enforcement behind it would
//!   be worse than not shipping the category at all (dead API surface
//!   implying a guarantee this crate doesn't provide).
//!
//! # Risk ordering — `io(process)` ranked above `io(network)`
//!
//! The RFC orders IO risk as `display < uart < filesystem < network < dma`.
//! This crate's reordering (`none < display < filesystem < registry <
//! serial < usb < bluetooth < network < device < process < any`) is a
//! deliberate departure, not an oversight: arbitrary local subprocess
//! execution is effectively arbitrary code execution, and userspace
//! software that shells out to a helper process, plugin, or hook script
//! with attacker-influenced input is a well-known, real command-injection
//! class of bug. Ranking `process` above `network` reflects that a
//! compromised subprocess capability is a strictly larger blast radius
//! than an outbound network connection under that threat model — kept as
//! the default ordering for the general-purpose case too, since arbitrary
//! code execution remains the more severe outcome regardless of target.
//!
//! Placement of the widened categories, each a judgment call worth stating
//! rather than leaving implicit:
//!
//! - [`IoLevel::Registry`] — persistent, OS-wide configuration mutation.
//!   Ranked just above `filesystem`: same "persistent local state" risk
//!   class, but scoped to the whole host's configuration rather than the
//!   current user/repo's own files.
//! - [`IoLevel::Serial`] — direct, wired, point-to-point peripheral
//!   communication. Ranked above `registry`: it reaches an external
//!   device, not just local storage — but a wired connection bounds *who*
//!   can reach it to whoever already has physical access.
//! - [`IoLevel::Usb`] — a broader device class than `serial` (mass
//!   storage, HID, arbitrary vendor protocols), including removable
//!   storage — a vector for both device control and data
//!   exfiltration/injection via removable media. Ranked above `serial`.
//! - [`IoLevel::Bluetooth`] — wireless. Reachable without a cable or
//!   direct physical connection, closer to `network`'s "remote-ish actor"
//!   risk profile than the wired peripheral categories below it. Ranked
//!   just below `network`.
//! - [`IoLevel::Device`] — a generic, opaque "any other hardware device"
//!   catch-all. Ranked *above* `network`, deliberately conservative: its
//!   meaning is unbounded (a webcam, a smart-card reader, a firmware
//!   update channel), so an opaque catch-all defaults to at least as risky
//!   as the most specific hardware category it might stand in for, not
//!   less.

/// Allocation-capability tier, from least to most risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocLevel {
    /// No allocation of any kind — stack/static only.
    None,
    /// The global heap allocator (`Vec`, `Box`, `String`, `HashMap`, ...).
    Heap,
    /// Any allocation strategy, including custom allocators.
    Any,
}

impl AllocLevel {
    /// A total ordering over risk — higher means riskier / less restricted.
    #[must_use]
    pub const fn risk_level(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Heap => 1,
            Self::Any => 2,
        }
    }
}

/// I/O-capability tier, from least to most risk. See this module's doc
/// comment for why `Process` is ranked above `Network` in this crate.
///
/// `PartialOrd`/`Ord` are derived from variant declaration order, which
/// is deliberately kept identical to [`Self::risk_level`]'s own ordering
/// — needed so a `BTreeSet<IoLevel>` (used by
/// `taint-check::capability_derive` for RFC 0007's crate-wide `io`
/// tracking) sorts sensibly; nothing relies on the derived ordering for
/// the actual risk comparison itself, which always goes through
/// `risk_level()` explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IoLevel {
    /// Pure computation — no I/O of any kind.
    None,
    /// Write-only console/log output (`println!`, `eprintln!`, `write!`).
    Display,
    /// Filesystem read/write.
    Filesystem,
    /// Persistent, OS-wide configuration mutation (e.g. the Windows
    /// registry). See module doc for why this ranks above `Filesystem`.
    Registry,
    /// Direct, wired, point-to-point peripheral communication (a serial
    /// port). See module doc for its ranking.
    Serial,
    /// USB device access — mass storage, HID, or vendor-specific
    /// protocols, including removable media. See module doc for its
    /// ranking.
    Usb,
    /// Wireless peripheral communication (a Bluetooth socket). See module
    /// doc for its ranking, just below `Network`.
    Bluetooth,
    /// Outbound network I/O (fetch/push transports).
    Network,
    /// A generic, opaque hardware device not covered by a more specific
    /// category above. Deliberately conservative — see module doc.
    Device,
    /// Subprocess spawning (`std::process::Command`) — credential helpers,
    /// hooks, pagers, diff/merge tools. See module doc for why this ranks
    /// above `Network` in this crate's ordering.
    Process,
    /// Unrestricted I/O.
    Any,
}

impl IoLevel {
    /// A total ordering over risk — higher means riskier / less restricted.
    #[must_use]
    pub const fn risk_level(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Display => 1,
            Self::Filesystem => 2,
            Self::Registry => 3,
            Self::Serial => 4,
            Self::Usb => 5,
            Self::Bluetooth => 6,
            Self::Network => 7,
            Self::Device => 8,
            Self::Process => 9,
            Self::Any => 10,
        }
    }
}

/// Whether a detected/declared raw-pointer write is provably within a
/// statically declared bound.
///
/// Phase 1 (no PAC-style address verification) can never *prove* `Bounded`
/// from body inspection alone — any detected raw write is conservatively
/// classified `Any` (see [`crate::inspector`]). `Bounded` exists in the
/// vocabulary so a function can still *declare* it once a future phase can
/// verify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrBound {
    /// Write is within a statically declared/verified bound.
    Bounded,
    /// Write is unbounded/unverified.
    Any,
}

/// Raw-pointer-capability tier, from least to most risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtrLevel {
    /// No raw pointer operations.
    None,
    /// Raw pointer reads only.
    Read,
    /// Raw pointer writes, bounded or unbounded per [`PtrBound`].
    Write(PtrBound),
    /// All raw pointer operations.
    Any,
}

impl PtrLevel {
    /// A total ordering over risk — higher means riskier / less restricted.
    #[must_use]
    pub const fn risk_level(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Read => 1,
            Self::Write(PtrBound::Bounded) => 2,
            Self::Write(PtrBound::Any) => 3,
            Self::Any => 4,
        }
    }
}

/// The full set of capabilities a function/module may declare or exhibit.
///
/// A category left `None` means "not declared" —
/// [`CapabilitySet::alloc_or_none`] and friends treat an undeclared
/// category as the most restrictive level, matching the RFC's "undeclared
/// = not permitted" model.
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    /// Declared/detected allocation capability, if any.
    pub alloc: Option<AllocLevel>,
    /// Declared/detected I/O capability, if any.
    pub io: Option<IoLevel>,
    /// Declared/detected raw-pointer capability, if any.
    pub ptr: Option<PtrLevel>,
}

impl CapabilitySet {
    /// The declared/detected [`AllocLevel`], defaulting to [`AllocLevel::None`].
    #[must_use]
    pub fn alloc_or_none(&self) -> AllocLevel {
        self.alloc.unwrap_or(AllocLevel::None)
    }

    /// The declared/detected [`IoLevel`], defaulting to [`IoLevel::None`].
    #[must_use]
    pub fn io_or_none(&self) -> IoLevel {
        self.io.unwrap_or(IoLevel::None)
    }

    /// The declared/detected [`PtrLevel`], defaulting to [`PtrLevel::None`].
    #[must_use]
    pub fn ptr_or_none(&self) -> PtrLevel {
        self.ptr.unwrap_or(PtrLevel::None)
    }

    /// Merge `other` into `self`, keeping the higher-risk level per
    /// category. Used by the body inspector to accumulate the maximum
    /// capability observed across an entire function body.
    pub(crate) fn merge_max(&mut self, other: &Self) {
        if let Some(o) = other.alloc {
            if o.risk_level() > self.alloc_or_none().risk_level() {
                self.alloc = Some(o);
            }
        }
        if let Some(o) = other.io {
            if o.risk_level() > self.io_or_none().risk_level() {
                self.io = Some(o);
            }
        }
        if let Some(o) = other.ptr {
            if o.risk_level() > self.ptr_or_none().risk_level() {
                self.ptr = Some(o);
            }
        }
    }
}

/// A set-valued I/O ceiling for a mod- or crate-level declaration —
/// permits each I/O category independently, instead of `IoLevel`'s single
/// risk-ordered scale.
///
/// `IoLevel` works well at function granularity, where one function
/// typically has one coherent I/O purpose and "at most this much" is a
/// natural fit. A mod- or crate-level ceiling covers many functions with
/// genuinely different needs, where the same linear scale has a real cost:
/// declaring `network` permitted would silently also permit `filesystem`
/// and `display`, since both rank below `network` — a function that later,
/// silently, starts touching the filesystem would not be flagged, even
/// though nobody meant to permit that. See
/// `rfcs/0008-capability-mod-and-crate-level.md`.
///
/// A category left `false` means "not permitted" — the default (`derive`d)
/// ceiling permits nothing, matching `#[capability(...)]`'s existing
/// "omitted category defaults to its most restrictive level" convention at
/// the function level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one orthogonal, independently-settable permission flag per IoLevel category, not a state machine — collapsing them into enums would lose exactly the \"declare each category independently\" property this type exists for"
)]
pub struct IoCeiling {
    /// Write-only console/log output (`println!`, `eprintln!`, `write!`).
    pub display: bool,
    /// Filesystem read/write.
    pub filesystem: bool,
    /// Persistent, OS-wide configuration mutation.
    pub registry: bool,
    /// Direct, wired, point-to-point peripheral communication.
    pub serial: bool,
    /// USB device access, including removable media.
    pub usb: bool,
    /// Wireless peripheral communication.
    pub bluetooth: bool,
    /// Outbound network I/O.
    pub network: bool,
    /// A generic, opaque hardware device not covered by a more specific
    /// category.
    pub device: bool,
    /// Subprocess spawning.
    pub process: bool,
    /// Unrestricted I/O — permits every other category regardless of its
    /// own flag.
    pub any: bool,
}

impl IoCeiling {
    /// `true` if `level` is permitted under this ceiling.
    /// [`IoLevel::None`] is always permitted — there is nothing to check.
    #[must_use]
    pub const fn permits(self, level: IoLevel) -> bool {
        match level {
            IoLevel::None => true,
            IoLevel::Display => self.display || self.any,
            IoLevel::Filesystem => self.filesystem || self.any,
            IoLevel::Registry => self.registry || self.any,
            IoLevel::Serial => self.serial || self.any,
            IoLevel::Usb => self.usb || self.any,
            IoLevel::Bluetooth => self.bluetooth || self.any,
            IoLevel::Network => self.network || self.any,
            IoLevel::Device => self.device || self.any,
            IoLevel::Process => self.process || self.any,
            IoLevel::Any => self.any,
        }
    }
}

/// A mod- or crate-level capability ceiling.
///
/// `alloc`/`ptr` keep the existing single "at most this level" scale
/// ([`AllocLevel`]/[`PtrLevel`]) — neither has shown the same "broad but
/// not that broad" need `io` has in a network-heavy codebase, per
/// `rfcs/0008-capability-mod-and-crate-level.md`'s own scope decision.
/// `io` is set-valued (see [`IoCeiling`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct CapabilityCeiling {
    /// Declared allocation ceiling, if any.
    pub alloc: Option<AllocLevel>,
    /// Declared I/O ceiling — each category independently permitted.
    pub io: IoCeiling,
    /// Declared raw-pointer ceiling, if any.
    pub ptr: Option<PtrLevel>,
}

impl CapabilityCeiling {
    /// The declared [`AllocLevel`] ceiling, defaulting to [`AllocLevel::None`].
    #[must_use]
    pub fn alloc_or_none(&self) -> AllocLevel {
        self.alloc.unwrap_or(AllocLevel::None)
    }

    /// The declared [`PtrLevel`] ceiling, defaulting to [`PtrLevel::None`].
    #[must_use]
    pub fn ptr_or_none(&self) -> PtrLevel {
        self.ptr.unwrap_or(PtrLevel::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_levels_are_strictly_ordered() {
        assert!(AllocLevel::None.risk_level() < AllocLevel::Heap.risk_level());
        assert!(AllocLevel::Heap.risk_level() < AllocLevel::Any.risk_level());
        assert!(IoLevel::Display.risk_level() < IoLevel::Filesystem.risk_level());
        assert!(IoLevel::Filesystem.risk_level() < IoLevel::Registry.risk_level());
        assert!(IoLevel::Registry.risk_level() < IoLevel::Serial.risk_level());
        assert!(IoLevel::Serial.risk_level() < IoLevel::Usb.risk_level());
        assert!(IoLevel::Usb.risk_level() < IoLevel::Bluetooth.risk_level());
        assert!(IoLevel::Bluetooth.risk_level() < IoLevel::Network.risk_level());
        assert!(IoLevel::Network.risk_level() < IoLevel::Device.risk_level());
        assert!(IoLevel::Device.risk_level() < IoLevel::Process.risk_level());
        assert!(IoLevel::Process.risk_level() < IoLevel::Any.risk_level());
        assert!(PtrLevel::Read.risk_level() < PtrLevel::Write(PtrBound::Bounded).risk_level());
        assert!(
            PtrLevel::Write(PtrBound::Bounded).risk_level()
                < PtrLevel::Write(PtrBound::Any).risk_level()
        );
        assert!(PtrLevel::Write(PtrBound::Any).risk_level() < PtrLevel::Any.risk_level());
    }

    #[test]
    fn merge_max_keeps_the_higher_risk_level() {
        let mut set = CapabilitySet {
            alloc: Some(AllocLevel::None),
            io: Some(IoLevel::Display),
            ptr: None,
        };
        set.merge_max(&CapabilitySet {
            alloc: Some(AllocLevel::Heap),
            io: Some(IoLevel::None),
            ptr: Some(PtrLevel::Read),
        });
        assert_eq!(set.alloc_or_none(), AllocLevel::Heap);
        assert_eq!(set.io_or_none(), IoLevel::Display);
        assert_eq!(set.ptr_or_none(), PtrLevel::Read);
    }

    #[test]
    fn default_io_ceiling_permits_only_none() {
        let ceiling = IoCeiling::default();
        assert!(ceiling.permits(IoLevel::None));
        assert!(!ceiling.permits(IoLevel::Display));
        assert!(!ceiling.permits(IoLevel::Network));
    }

    #[test]
    fn io_ceiling_permits_network_without_implying_filesystem() {
        let ceiling = IoCeiling {
            network: true,
            ..IoCeiling::default()
        };
        assert!(ceiling.permits(IoLevel::Network));
        assert!(!ceiling.permits(IoLevel::Filesystem));
        assert!(!ceiling.permits(IoLevel::Display));
    }

    #[test]
    fn io_ceiling_any_permits_every_category() {
        let ceiling = IoCeiling {
            any: true,
            ..IoCeiling::default()
        };
        assert!(ceiling.permits(IoLevel::Display));
        assert!(ceiling.permits(IoLevel::Filesystem));
        assert!(ceiling.permits(IoLevel::Registry));
        assert!(ceiling.permits(IoLevel::Serial));
        assert!(ceiling.permits(IoLevel::Usb));
        assert!(ceiling.permits(IoLevel::Bluetooth));
        assert!(ceiling.permits(IoLevel::Network));
        assert!(ceiling.permits(IoLevel::Device));
        assert!(ceiling.permits(IoLevel::Process));
        assert!(ceiling.permits(IoLevel::Any));
    }

    #[test]
    fn io_ceiling_permits_each_widened_category_independently() {
        let ceiling = IoCeiling {
            usb: true,
            ..IoCeiling::default()
        };
        assert!(ceiling.permits(IoLevel::Usb));
        assert!(!ceiling.permits(IoLevel::Serial));
        assert!(!ceiling.permits(IoLevel::Bluetooth));
        assert!(!ceiling.permits(IoLevel::Registry));
        assert!(!ceiling.permits(IoLevel::Device));
    }

    #[test]
    fn capability_ceiling_defaults_are_most_restrictive() {
        let ceiling = CapabilityCeiling::default();
        assert_eq!(ceiling.alloc_or_none(), AllocLevel::None);
        assert_eq!(ceiling.ptr_or_none(), PtrLevel::None);
        assert!(!ceiling.io.permits(IoLevel::Display));
    }
}
