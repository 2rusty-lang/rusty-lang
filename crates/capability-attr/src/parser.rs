//! The `#[capability(...)]` attribute-args parser: turns the tokens inside
//! the attribute's parens into a [`CapabilitySet`].
//!
//! The vocabulary types themselves ([`AllocLevel`], [`IoLevel`],
//! [`PtrLevel`]/[`PtrBound`], [`CapabilitySet`]) live in `capability-core`
//! now, shared with `taint-generate` — see that crate's `vocabulary`
//! module docs for the full reasoning behind the reduced/reshaped
//! vocabulary and its risk ordering. This module only owns parsing this
//! macro's specific surface syntax into those types.

use capability_core::{AllocLevel, CapabilitySet, IoLevel, PtrBound, PtrLevel};
use proc_macro2::TokenStream;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{Ident, Meta, Token};

/// Parse the token stream inside `#[capability(...)]` into a [`CapabilitySet`].
///
/// Accepted surface syntax (a subset of the RFC's, per `capability-core`'s
/// own vocabulary-reduction notes):
///
/// ```text
/// #[capability(alloc(none), io(display), ptr(none))]
/// #[capability(alloc(heap), io(process), ptr(write, bounded))]
/// ```
///
/// # Errors
///
/// Returns `Err` on an unknown category, an unknown level within a known
/// category, or a duplicate category declaration.
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
    fn round_trips_through_capability_core_render() {
        // `capability_core::render_capability_args` is the exact inverse
        // of this module's own parser — `taint-generate` relies on that
        // symmetry to write an attribute this crate will itself accept.
        let original = CapabilitySet {
            alloc: Some(AllocLevel::Heap),
            io: Some(IoLevel::Process),
            ptr: Some(PtrLevel::Write(PtrBound::Any)),
        };
        let rendered = capability_core::render_capability_args(&original);
        let tokens: proc_macro2::TokenStream = rendered.parse().unwrap();
        let reparsed = parse_capability_args(tokens).unwrap();
        assert_eq!(reparsed.alloc_or_none(), original.alloc_or_none());
        assert_eq!(reparsed.io_or_none(), original.io_or_none());
        assert_eq!(reparsed.ptr_or_none(), original.ptr_or_none());
    }
}
