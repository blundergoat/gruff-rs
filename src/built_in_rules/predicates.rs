//! Shared Rust predicates translate parsed syntax into facts used by built-in rules.
//! Function-block construction and rule dispatch call these helpers after parsing,
//! keeping visibility, attributes, and naming decisions consistent across findings.

use super::*;

pub(crate) fn is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

/// Strict counterpart to `is_public` - see `visibility_is_externally_public`.
pub(crate) fn is_externally_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

pub(crate) fn has_doc_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("doc"))
}

pub(crate) fn has_ignore_without_reason(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("ignore"))
        .any(|attr| match &attr.meta {
            syn::Meta::Path(_) => true,
            syn::Meta::List(list) => list.tokens.is_empty(),
            syn::Meta::NameValue(value) => match &value.value {
                syn::Expr::Lit(lit) => match &lit.lit {
                    syn::Lit::Str(reason) => reason.value().trim().is_empty(),
                    _ => true,
                },
                _ => true,
            },
        })
}

pub(crate) fn is_placeholder_identifier(name: &str) -> bool {
    matches!(name, "foo" | "bar" | "baz" | "qux")
}
