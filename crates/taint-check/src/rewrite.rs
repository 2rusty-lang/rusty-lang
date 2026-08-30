//! Strips the taint-check helper attributes (`#[sensitive(...)]`,
//! `#[taint_sink(...)]`, `#[taint_sanitizer]`) from a `mod` before
//! `taint-check-macros` re-emits it.
//!
//! None of these three are registered as real `#[proc_macro_attribute]`s —
//! only `#[taint_check]` itself is (see `taint-check-macros`' crate docs).
//! `#[taint_check]`'s expansion fully owns re-emitting the annotated `mod`,
//! so it must remove these helper attributes first; left in place, rustc
//! would fail to resolve them post-expansion (`cannot find attribute
//! ... in this scope`), and a `#[sensitive(...)]` on a function parameter
//! is not otherwise legal, stable-Rust syntax at all. This is the same
//! "consume custom syntax, re-emit plain Rust" move `#[async_trait]`-style
//! macros make for their own parameter/item annotations.

use syn::visit_mut::{self, VisitMut};
use syn::{FnArg, ItemFn, ItemMod};

use crate::parser;

struct AttrStripper;

impl VisitMut for AttrStripper {
    fn visit_item_fn_mut(&mut self, item_fn: &mut ItemFn) {
        item_fn
            .attrs
            .retain(|a| !(parser::is_taint_sink(a) || parser::is_taint_sanitizer(a)));
        for arg in &mut item_fn.sig.inputs {
            if let FnArg::Typed(pt) = arg {
                pt.attrs.retain(|a| !parser::is_sensitive(a));
            }
        }
        visit_mut::visit_item_fn_mut(self, item_fn);
    }
}

/// Remove every `#[sensitive(...)]` / `#[taint_sink(...)]` /
/// `#[taint_sanitizer]` attribute from `item_mod`, in place.
pub fn strip_helper_attrs(item_mod: &mut ItemMod) {
    AttrStripper.visit_item_mod_mut(item_mod);
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn strips_all_three_helper_attributes() {
        let mut module: ItemMod = syn::parse_quote! {
            mod scope {
                fn handle_login(#[sensitive(password)] password: &str) {
                    log_debug(password);
                }
                #[taint_sink(password, policy = "no_sensitive")]
                fn log_debug(msg: &str) {}
                #[taint_sanitizer]
                fn redact(s: &str) -> String { s.to_string() }
            }
        };
        strip_helper_attrs(&mut module);
        let rendered = quote! { #module }.to_string();
        assert!(!rendered.contains("sensitive"));
        assert!(!rendered.contains("taint_sink"));
        assert!(!rendered.contains("taint_sanitizer"));
    }
}
