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
//! # Vocabulary — reduced from the RFC, grounded in `git.git`'s needs
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
//!   tiers describe hardware buses `git.git` never touches, so they're
//!   dropped. In their place, [`IoLevel::Process`] is *added* — the RFC has
//!   no equivalent, but subprocess spawning (credential helpers, pagers,
//!   diff/merge tools, hooks) is one of `git.git`'s largest and most
//!   security-relevant real capability dimensions (see the module doc's
//!   risk-ordering note below).
//! - [`PtrLevel`] — kept close to the RFC's own `ptr(write, bounded)` /
//!   `ptr(write, any)` shape (same `#[capability(ptr(write, bounded))]`
//!   surface syntax), since raw-pointer capability is exactly what matters
//!   at an FFI boundary.
//! - `register(...)` and `interrupt(...)` — **dropped entirely**, not
//!   stubbed. Both describe hardware register/interrupt-controller access
//!   that has no meaning for a userspace CLI tool; a stub type with no real
//!   enforcement behind it would be worse than not shipping the category at
//!   all (dead API surface implying a guarantee this crate doesn't provide).
//!
//! # Risk ordering — `io(process)` ranked above `io(network)`
//!
//! The RFC orders IO risk as `display < uart < filesystem < network < dma`.
//! This crate's reordering (`none < display < filesystem < network <
//! process < any`) is a deliberate departure, not an oversight: arbitrary
//! local subprocess execution is effectively arbitrary code execution, and
//! `git.git` has a real history of command-injection classes of bugs
//! reaching exactly this surface (credential-helper invocation, submodule
//! hook/URL handling). Ranking it above `network` reflects that a
//! compromised subprocess capability is a strictly larger blast radius than
//! an outbound network connection in this specific target's threat model.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoLevel {
    /// Pure computation — no I/O of any kind.
    None,
    /// Write-only console/log output (`println!`, `eprintln!`, `write!`).
    Display,
    /// Filesystem read/write (repo objects, refs, config, `.git/` files).
    Filesystem,
    /// Outbound network I/O (fetch/push transports).
    Network,
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
            Self::Network => 3,
            Self::Process => 4,
            Self::Any => 5,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_levels_are_strictly_ordered() {
        assert!(AllocLevel::None.risk_level() < AllocLevel::Heap.risk_level());
        assert!(AllocLevel::Heap.risk_level() < AllocLevel::Any.risk_level());
        assert!(IoLevel::Display.risk_level() < IoLevel::Filesystem.risk_level());
        assert!(IoLevel::Network.risk_level() < IoLevel::Process.risk_level());
        assert!(IoLevel::Process.risk_level() < IoLevel::Any.risk_level());
        assert!(PtrLevel::Read.risk_level() < PtrLevel::Write(PtrBound::Bounded).risk_level());
        assert!(
            PtrLevel::Write(PtrBound::Bounded).risk_level()
                < PtrLevel::Write(PtrBound::Any).risk_level()
        );
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
}
