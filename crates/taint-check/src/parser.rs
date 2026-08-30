//! Attribute-argument parsing for the taint-check vocabulary:
//! `#[taint_check(labels = [...])]`, `#[sensitive(label)]`,
//! `#[taint_sink(label, policy = "...")]`, `#[taint_sanitizer]`.
//!
//! This module only parses attribute *arguments* into typed values — it
//! does not interpret what they mean for a given function body (that is
//! [`crate::inspector`]'s job) or decide whether an attribute should be
//! stripped before re-emission (that is [`crate::rewrite`]'s job). Kept
//! separate so the same parsing logic is shared verbatim between the
//! `#[proc_macro_attribute]` path (`taint-check-macros`) and the standalone
//! CLI path (`crate::cli`), which sees the exact same attribute tokens but
//! outside any macro-expansion context.

use proc_macro2::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Ident, LitStr, Token};

/// Parsed `labels = [...]` argument of `#[taint_check(labels = [...])]`.
pub struct TaintCheckArgs {
    /// The declared taint labels, in source order, as their `Ident` names.
    pub labels: Vec<String>,
}

impl Parse for TaintCheckArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let keyword: Ident = input.parse()?;
        if keyword != "labels" {
            return Err(syn::Error::new(
                keyword.span(),
                "expected `labels = [...]` — `#[taint_check]` currently only supports this one argument",
            ));
        }
        input.parse::<Token![=]>()?;
        let content;
        syn::bracketed!(content in input);
        let idents = Punctuated::<Ident, Token![,]>::parse_terminated(&content)?;
        Ok(Self {
            labels: idents.iter().map(ToString::to_string).collect(),
        })
    }
}

/// Parse `#[taint_check(labels = [...])]`'s argument tokens.
///
/// The tokens are the contents of the parens, same shape whether they
/// arrived via a real `#[proc_macro_attribute]` invocation or via
/// [`crate::cli`] reading them back out of a plain [`syn::Attribute`].
///
/// # Errors
///
/// Returns `Err` if the tokens aren't `labels = [ident, ident, ...]`.
pub fn parse_taint_check_args(args: TokenStream) -> syn::Result<TaintCheckArgs> {
    syn::parse2(args)
}

/// A parsed `#[taint_sink(label, policy = "...")]`.
#[derive(Debug)]
pub struct SinkPolicy {
    /// The label this function is a forbidden destination for.
    pub label: String,
    /// The free-form policy name to name in a violation message (e.g.
    /// `"no_sensitive"`). Not validated against a registry — see
    /// `rfcs/0003-taint-check.md`'s "Unresolved questions".
    pub policy: String,
}

impl Parse for SinkPolicy {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let label: Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        let keyword: Ident = input.parse()?;
        if keyword != "policy" {
            return Err(syn::Error::new(
                keyword.span(),
                "expected `policy = \"...\"` after the label",
            ));
        }
        input.parse::<Token![=]>()?;
        let policy: LitStr = input.parse()?;
        Ok(Self {
            label: label.to_string(),
            policy: policy.value(),
        })
    }
}

/// `true` if `attr` is `#[sensitive(...)]`.
#[must_use]
pub fn is_sensitive(attr: &Attribute) -> bool {
    attr.path().is_ident("sensitive")
}

/// `true` if `attr` is `#[taint_sink(...)]`.
#[must_use]
pub fn is_taint_sink(attr: &Attribute) -> bool {
    attr.path().is_ident("taint_sink")
}

/// `true` if `attr` is `#[taint_sanitizer]`.
#[must_use]
pub fn is_taint_sanitizer(attr: &Attribute) -> bool {
    attr.path().is_ident("taint_sanitizer")
}

/// Parse a `#[sensitive(label)]` attribute's single-ident argument.
///
/// # Errors
///
/// Returns `Err` if the attribute's argument isn't a single identifier.
pub fn parse_sensitive_attr(attr: &Attribute) -> syn::Result<String> {
    let ident: Ident = attr.parse_args()?;
    Ok(ident.to_string())
}

/// Parse a `#[taint_sink(label, policy = "...")]` attribute's arguments.
///
/// # Errors
///
/// Returns `Err` if the arguments aren't `label, policy = "..."`.
pub fn parse_taint_sink_attr(attr: &Attribute) -> syn::Result<SinkPolicy> {
    attr.parse_args()
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn parses_labels_list() {
        let tokens: TokenStream = quote::quote! { labels = [password, session_token] };
        let parsed = parse_taint_check_args(tokens).unwrap();
        assert_eq!(parsed.labels, vec!["password", "session_token"]);
    }

    #[test]
    fn rejects_unknown_keyword() {
        let tokens: TokenStream = quote::quote! { wrong = [a] };
        assert!(parse_taint_check_args(tokens).is_err());
    }

    #[test]
    fn recognizes_helper_attributes_by_name() {
        let sensitive: Attribute = parse_quote!(#[sensitive(password)]);
        let sink: Attribute = parse_quote!(#[taint_sink(password, policy = "no_sensitive")]);
        let sanitizer: Attribute = parse_quote!(#[taint_sanitizer]);
        assert!(is_sensitive(&sensitive));
        assert!(is_taint_sink(&sink));
        assert!(is_taint_sanitizer(&sanitizer));
        assert!(!is_sensitive(&sink));
        assert!(!is_taint_sink(&sanitizer));
    }

    #[test]
    fn parses_sensitive_label() {
        let attr: Attribute = parse_quote!(#[sensitive(password)]);
        assert_eq!(parse_sensitive_attr(&attr).unwrap(), "password");
    }

    #[test]
    fn parses_taint_sink_label_and_policy() {
        let attr: Attribute = parse_quote!(#[taint_sink(password, policy = "no_sensitive")]);
        let sink = parse_taint_sink_attr(&attr).unwrap();
        assert_eq!(sink.label, "password");
        assert_eq!(sink.policy, "no_sensitive");
    }

    #[test]
    fn taint_sink_requires_policy_keyword() {
        let attr: Attribute = parse_quote!(#[taint_sink(password, "no_sensitive")]);
        assert!(parse_taint_sink_attr(&attr).is_err());
    }

    #[test]
    fn taint_sink_rejects_a_misspelled_policy_keyword() {
        let attr: Attribute = parse_quote!(#[taint_sink(password, plicy = "no_sensitive")]);
        let err = parse_taint_sink_attr(&attr).unwrap_err();
        assert!(err.to_string().contains("policy"));
    }
}
