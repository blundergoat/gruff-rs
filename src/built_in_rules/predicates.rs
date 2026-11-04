//! Shared Rust predicates translate parsed syntax into facts used by built-in rules.
//! Function-block construction and rule dispatch call these helpers after parsing,
//! keeping visibility, attributes, and naming decisions consistent across findings.

use super::*;

/// Tells whether an item has any explicit visibility, treating restricted forms such as `pub(crate)` as public.
///
/// `visibility` is the item's parsed visibility qualifier.
/// Returns false only for inherited visibility, so `pub`, `pub(crate)`, `pub(super)` and `pub(in path)` all return true.
pub(crate) fn is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

/// Strict counterpart to `is_public` - see `visibility_is_externally_public`.
///
/// `visibility` is the item's parsed visibility qualifier.
/// Returns true only for a bare `pub`; restricted forms such as `pub(crate)` and inherited visibility return false.
pub(crate) fn is_externally_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

/// Tells whether an item carries any `doc` attribute, the form `///` comments take after parsing.
///
/// `attrs` is the item's attribute list.
/// Returns true for any `doc` attribute, including a `doc(hidden)` one that holds no text, and false when there is none.
pub(crate) fn has_doc_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("doc"))
}

/// Detects an `ignore` attribute that gives no reason for skipping a test.
///
/// `attrs` is the attribute list of the function being checked.
/// Returns true when any `ignore` is bare, has empty parentheses, or sets a value other than a string literal with non-blank text.
/// Parentheses holding any tokens count as a reason, and false is returned when no `ignore` attribute is present.
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

/// Tells whether an identifier is one of the stock placeholder names `foo`, `bar`, `baz` or `qux`.
///
/// `name` is the identifier to test, compared exactly and case-sensitively.
/// Returns true only for those four names; configured extra placeholders are not consulted here.
pub(crate) fn is_placeholder_identifier(name: &str) -> bool {
    matches!(name, "foo" | "bar" | "baz" | "qux")
}
