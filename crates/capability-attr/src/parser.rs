//! The `#[capability(...)]` attribute-args parser: turns the tokens inside
//! the attribute's parens into a [`CapabilitySet`].
//!
//! The vocabulary types themselves ([`AllocLevel`], [`IoLevel`],
//! [`PtrLevel`]/[`PtrBound`], [`CapabilitySet`]) live in `capability-core`
//! now, shared with `taint-generate` — see that crate's `vocabulary`
//! module docs for the full reasoning behind the reduced/reshaped
//! vocabulary and its risk ordering. This module only owns parsing this
//! macro's specific surface syntax into those types.

use capability_core::{
    AllocLevel, CapabilityCeiling, CapabilitySet, IoCeiling, IoLevel, PtrBound, PtrLevel,
};
use proc_macro2::TokenStream;
use syn::parse::{ParseStream, Parser};
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
        "registry" => Ok(IoLevel::Registry),
        "serial" => Ok(IoLevel::Serial),
        "usb" => Ok(IoLevel::Usb),
        "bluetooth" => Ok(IoLevel::Bluetooth),
        "network" => Ok(IoLevel::Network),
        "device" => Ok(IoLevel::Device),
        "process" => Ok(IoLevel::Process),
        "any" => Ok(IoLevel::Any),
        other => Err(syn::Error::new_spanned(
            ident,
            format!(
                "unknown io level `{other}` (expected `none`, `display`, `filesystem`, `registry`, `serial`, `usb`, `bluetooth`, `network`, `device`, `process`, or `any`)"
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

/// Parse the token stream inside a mod-/crate-level `#[capability(...)]`
/// into a [`CapabilityCeiling`] — the RFC-0008 counterpart of
/// [`parse_capability_args`].
///
/// Accepted surface syntax:
///
/// ```text
/// #[capability(alloc(heap), io(network: yes, filesystem: no), ptr(none))]
/// ```
///
/// `alloc`/`ptr` share the exact grammar and parsers `parse_capability_args`
/// uses; only `io` differs, since a ceiling is set-valued (see
/// `capability_core::vocabulary::IoCeiling`'s docs and
/// `rfcs/0008-capability-mod-and-crate-level.md`).
///
/// # Errors
///
/// Same error shapes as [`parse_capability_args`], plus an unknown/
/// duplicate `io` sub-category or a non-`yes`/`no` value.
pub fn parse_capability_ceiling_args(args: TokenStream) -> syn::Result<CapabilityCeiling> {
    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let metas = parser.parse2(args)?;

    let mut ceiling = CapabilityCeiling::default();
    let mut alloc_seen = false;
    let mut io_seen = false;
    let mut ptr_seen = false;
    for meta in metas {
        let list = match &meta {
            Meta::List(list) => list,
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "expected `category(...)`, e.g. `alloc(none)` or `io(network: yes, ...)`",
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
                ensure_not_duplicate(alloc_seen, &list.path, "alloc")?;
                alloc_seen = true;
                ceiling.alloc = Some(parse_alloc_level(list)?);
            }
            "io" => {
                ensure_not_duplicate(io_seen, &list.path, "io")?;
                io_seen = true;
                ceiling.io = parse_io_ceiling(list)?;
            }
            "ptr" => {
                ensure_not_duplicate(ptr_seen, &list.path, "ptr")?;
                ptr_seen = true;
                ceiling.ptr = Some(parse_ptr_level(list)?);
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

    Ok(ceiling)
}

/// Parse `network: yes, filesystem: no, display: no, process: no, any: no`
/// (in any order, any subset — an omitted category defaults to `no`) into
/// an [`IoCeiling`].
fn parse_io_ceiling(list: &syn::MetaList) -> syn::Result<IoCeiling> {
    fn parse(input: ParseStream) -> syn::Result<IoCeiling> {
        let mut ceiling = IoCeiling::default();
        let mut seen: Vec<String> = Vec::new();
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![:]>()?;
            let value: Ident = input.parse()?;
            let permitted = match value.to_string().as_str() {
                "yes" => true,
                "no" => false,
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!("expected `yes` or `no`, found `{other}`"),
                    ));
                }
            };

            let key_str = key.to_string();
            if seen.contains(&key_str) {
                return Err(syn::Error::new_spanned(
                    &key,
                    format!("duplicate `{key_str}` in io ceiling"),
                ));
            }
            seen.push(key_str.clone());

            match key_str.as_str() {
                "display" => ceiling.display = permitted,
                "filesystem" => ceiling.filesystem = permitted,
                "registry" => ceiling.registry = permitted,
                "serial" => ceiling.serial = permitted,
                "usb" => ceiling.usb = permitted,
                "bluetooth" => ceiling.bluetooth = permitted,
                "network" => ceiling.network = permitted,
                "device" => ceiling.device = permitted,
                "process" => ceiling.process = permitted,
                "any" => ceiling.any = permitted,
                other => {
                    return Err(syn::Error::new_spanned(
                        &key,
                        format!(
                            "unknown io ceiling category `{other}` (expected `display`, `filesystem`, `registry`, `serial`, `usb`, `bluetooth`, `network`, `device`, `process`, or `any`)"
                        ),
                    ));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(ceiling)
    }

    parse.parse2(list.tokens.clone())
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

    #[test]
    fn parses_every_widened_io_level() {
        for (word, level) in [
            ("registry", IoLevel::Registry),
            ("serial", IoLevel::Serial),
            ("usb", IoLevel::Usb),
            ("bluetooth", IoLevel::Bluetooth),
            ("device", IoLevel::Device),
        ] {
            let ident = syn::Ident::new(word, proc_macro2::Span::call_site());
            let set = parse_capability_args(quote! { io(#ident) }).unwrap();
            assert_eq!(set.io_or_none(), level, "io({word})");
        }
    }

    #[test]
    fn unknown_io_level_is_a_parse_error() {
        let err = parse_capability_args(quote! { io(spi) }).unwrap_err();
        assert!(err.to_string().contains("unknown io level"));
    }

    #[test]
    fn unknown_ptr_level_is_a_parse_error() {
        let err = parse_capability_args(quote! { ptr(execute) }).unwrap_err();
        assert!(err.to_string().contains("unknown ptr level"));
    }

    #[test]
    fn duplicate_io_and_ptr_categories_are_parse_errors() {
        assert!(parse_capability_args(quote! { io(none), io(display) })
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
        assert!(parse_capability_args(quote! { ptr(none), ptr(read) })
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }

    #[test]
    fn non_list_meta_is_a_parse_error() {
        // `alloc` with no `(...)` at all — a bare path, not `category(level)`.
        let err = parse_capability_args(quote! { alloc }).unwrap_err();
        assert!(err.to_string().contains("expected `category(level)`"));
    }

    #[test]
    fn parses_every_ceiling_io_category() {
        let ceiling = parse_capability_ceiling_args(quote! {
            alloc(heap),
            io(display: yes, filesystem: no, registry: yes, serial: no, usb: yes, bluetooth: no, network: yes, device: no, any: no),
            ptr(read)
        })
        .unwrap();
        assert_eq!(ceiling.alloc_or_none(), AllocLevel::Heap);
        assert_eq!(ceiling.ptr_or_none(), PtrLevel::Read);
        assert!(ceiling.io.display);
        assert!(!ceiling.io.filesystem);
        assert!(ceiling.io.registry);
        assert!(!ceiling.io.serial);
        assert!(ceiling.io.usb);
        assert!(!ceiling.io.bluetooth);
        assert!(ceiling.io.network);
        assert!(!ceiling.io.device);
        assert!(!ceiling.io.any);
    }

    #[test]
    fn ceiling_omitted_categories_default_to_no_and_none() {
        let ceiling = parse_capability_ceiling_args(quote! {}).unwrap();
        assert_eq!(ceiling.alloc_or_none(), AllocLevel::None);
        assert_eq!(ceiling.ptr_or_none(), PtrLevel::None);
        assert!(!ceiling.io.network);
        assert!(!ceiling.io.any);
    }

    #[test]
    fn ceiling_unknown_top_level_category_is_a_parse_error() {
        let err = parse_capability_ceiling_args(quote! { register(write) }).unwrap_err();
        assert!(err.to_string().contains("unknown capability category"));
    }

    #[test]
    fn ceiling_duplicate_top_level_categories_are_parse_errors() {
        assert!(
            parse_capability_ceiling_args(quote! { alloc(none), alloc(heap) })
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(
            parse_capability_ceiling_args(quote! { io(network: yes), io(network: no) })
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(
            parse_capability_ceiling_args(quote! { ptr(none), ptr(read) })
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn ceiling_non_list_meta_is_a_parse_error() {
        let err = parse_capability_ceiling_args(quote! { alloc }).unwrap_err();
        assert!(err.to_string().contains("expected `category(...)`"));
    }

    #[test]
    fn ceiling_io_rejects_a_non_yes_no_value() {
        let err = parse_capability_ceiling_args(quote! { io(network: maybe) }).unwrap_err();
        assert!(err.to_string().contains("expected `yes` or `no`"));
    }

    #[test]
    fn ceiling_io_rejects_an_unknown_sub_category() {
        let err = parse_capability_ceiling_args(quote! { io(spi: yes) }).unwrap_err();
        assert!(err.to_string().contains("unknown io ceiling category"));
    }

    #[test]
    fn ceiling_io_rejects_a_duplicate_sub_category() {
        let err =
            parse_capability_ceiling_args(quote! { io(network: yes, network: no) }).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn ceiling_round_trips_through_capability_core_render() {
        let original = CapabilityCeiling {
            alloc: Some(AllocLevel::Heap),
            io: IoCeiling {
                network: true,
                usb: true,
                ..IoCeiling::default()
            },
            ptr: Some(PtrLevel::Read),
        };
        let rendered = capability_core::render_capability_ceiling(&original);
        let tokens: proc_macro2::TokenStream = rendered.parse().unwrap();
        let reparsed = parse_capability_ceiling_args(tokens).unwrap();
        assert_eq!(reparsed.alloc_or_none(), original.alloc_or_none());
        assert_eq!(reparsed.ptr_or_none(), original.ptr_or_none());
        assert_eq!(reparsed.io, original.io);
    }
}
