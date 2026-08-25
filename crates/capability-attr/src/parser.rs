//! Capability vocabulary types, plus the `#[capability(...)]` attribute-args
//! parser.
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
//!   at an FFI boundary — the eventual integration point this crate is
//!   built toward (see this workspace's `spec/SPEC-00045-*.md` T3, design-
//!   only this pass).
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

use proc_macro2::TokenStream;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{Ident, Meta, Token};

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
/// statically declared bound. Phase 1 (this crate, no PAC-style address
/// verification) can never *prove* `Bounded` from body inspection alone —
/// any detected raw write is conservatively classified `Any` (see
/// `inspector.rs`). `Bounded` exists in the vocabulary so a function can
/// still *declare* it once a future phase can verify it.
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
/// A category left `None` means "not declared" — [`CapabilitySet::alloc_or_none`]
/// and friends treat an undeclared category as the most restrictive level,
/// matching the RFC's "undeclared = not permitted" model.
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
    pub fn alloc_or_none(&self) -> AllocLevel {
        self.alloc.unwrap_or(AllocLevel::None)
    }

    /// The declared/detected [`IoLevel`], defaulting to [`IoLevel::None`].
    pub fn io_or_none(&self) -> IoLevel {
        self.io.unwrap_or(IoLevel::None)
    }

    /// The declared/detected [`PtrLevel`], defaulting to [`PtrLevel::None`].
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

/// Parse the token stream inside `#[capability(...)]` into a [`CapabilitySet`].
///
/// Accepted surface syntax (a subset of the RFC's, per this module's own
/// vocabulary-reduction notes above):
///
/// ```text
/// #[capability(alloc(none), io(display), ptr(none))]
/// #[capability(alloc(heap), io(process), ptr(write, bounded))]
/// ```
pub fn parse_capability_args(args: TokenStream) -> syn::Result<CapabilitySet> {
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let metas = parser.parse2(args)?;

    let mut set = CapabilitySet::default();
    for meta in metas {
        let list = match &meta {
            Meta::List(list) => list,
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "expected `category(level)`, e.g. `alloc(none)`",
                ));
            }
        };
        let category = list
            .path
            .get_ident()
            .map(Ident::to_string)
            .unwrap_or_default();

        match category.as_str() {
            "alloc" => {
                ensure_not_duplicate(set.alloc.is_some(), &list.path, "alloc")?;
                set.alloc = Some(parse_alloc_level(list)?);
            }
            "io" => {
                ensure_not_duplicate(set.io.is_some(), &list.path, "io")?;
                set.io = Some(parse_io_level(list)?);
            }
            "ptr" => {
                ensure_not_duplicate(set.ptr.is_some(), &list.path, "ptr")?;
                set.ptr = Some(parse_ptr_level(list)?);
            }
            other => {
                return Err(syn::Error::new_spanned(
                    &list.path,
                    format!(
                        "unknown capability category `{other}` (expected `alloc`, `io`, or `ptr`)"
                    ),
                ));
            }
        }
    }

    Ok(set)
}

fn ensure_not_duplicate(already_set: bool, path: &syn::Path, category: &str) -> syn::Result<()> {
    if already_set {
        Err(syn::Error::new_spanned(
            path,
            format!("duplicate `{category}(...)` declaration"),
        ))
    } else {
        Ok(())
    }
}

fn single_ident(list: &syn::MetaList) -> syn::Result<Ident> {
    syn::parse2(list.tokens.clone())
}

fn parse_alloc_level(list: &syn::MetaList) -> syn::Result<AllocLevel> {
    let ident = single_ident(list)?;
    match ident.to_string().as_str() {
        "none" => Ok(AllocLevel::None),
        "heap" => Ok(AllocLevel::Heap),
        "any" => Ok(AllocLevel::Any),
        other => Err(syn::Error::new_spanned(
            ident,
            format!("unknown alloc level `{other}` (expected `none`, `heap`, or `any`)"),
        )),
    }
}

fn parse_io_level(list: &syn::MetaList) -> syn::Result<IoLevel> {
    let ident = single_ident(list)?;
    match ident.to_string().as_str() {
        "none" => Ok(IoLevel::None),
        "display" => Ok(IoLevel::Display),
        "filesystem" => Ok(IoLevel::Filesystem),
        "network" => Ok(IoLevel::Network),
        "process" => Ok(IoLevel::Process),
        "any" => Ok(IoLevel::Any),
        other => Err(syn::Error::new_spanned(
            ident,
            format!(
                "unknown io level `{other}` (expected `none`, `display`, `filesystem`, `network`, `process`, or `any`)"
            ),
        )),
    }
}

fn parse_ptr_level(list: &syn::MetaList) -> syn::Result<PtrLevel> {
    let idents = Punctuated::<Ident, Token![,]>::parse_terminated.parse2(list.tokens.clone())?;
    let words: Vec<String> = idents.iter().map(Ident::to_string).collect();

    match words.as_slice() {
        [w] if w == "none" => Ok(PtrLevel::None),
        [w] if w == "read" => Ok(PtrLevel::Read),
        [w] if w == "any" => Ok(PtrLevel::Any),
        [w, b] if w == "write" && b == "bounded" => Ok(PtrLevel::Write(PtrBound::Bounded)),
        [w, b] if w == "write" && b == "any" => Ok(PtrLevel::Write(PtrBound::Any)),
        _ => Err(syn::Error::new_spanned(
            &list.tokens,
            "unknown ptr level (expected `none`, `read`, `any`, `write, bounded`, or `write, any`)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn parses_all_three_categories() {
        let set = parse_capability_args(quote! { alloc(heap), io(display), ptr(none) }).unwrap();
        assert_eq!(set.alloc_or_none(), AllocLevel::Heap);
        assert_eq!(set.io_or_none(), IoLevel::Display);
        assert_eq!(set.ptr_or_none(), PtrLevel::None);
    }

    #[test]
    fn missing_category_defaults_to_none() {
        let set = parse_capability_args(quote! { alloc(any) }).unwrap();
        assert_eq!(set.alloc_or_none(), AllocLevel::Any);
        assert_eq!(set.io_or_none(), IoLevel::None);
        assert_eq!(set.ptr_or_none(), PtrLevel::None);
    }

    #[test]
    fn parses_ptr_write_bounded_and_any() {
        let bounded = parse_capability_args(quote! { ptr(write, bounded) }).unwrap();
        assert_eq!(bounded.ptr_or_none(), PtrLevel::Write(PtrBound::Bounded));

        let any = parse_capability_args(quote! { ptr(write, any) }).unwrap();
        assert_eq!(any.ptr_or_none(), PtrLevel::Write(PtrBound::Any));
    }

    #[test]
    fn unknown_category_is_a_parse_error() {
        let err = parse_capability_args(quote! { register(write, peripheral::GPIO) }).unwrap_err();
        assert!(err.to_string().contains("unknown capability category"));
    }

    #[test]
    fn unknown_alloc_level_is_a_parse_error() {
        let err = parse_capability_args(quote! { alloc(bump) }).unwrap_err();
        assert!(err.to_string().contains("unknown alloc level"));
    }

    #[test]
    fn duplicate_category_is_a_parse_error() {
        let err = parse_capability_args(quote! { alloc(none), alloc(heap) }).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

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
