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

pub(crate) fn has_doc_comment_before(block: &str) -> bool {
    block
        .lines()
        .take_while(|line| !line.contains("fn "))
        .any(|line| line.trim_start().starts_with("///"))
}

pub(crate) fn is_generic_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "process" | "handle" | "do_it" | "run" | "execute" | "manage"
    )
}

pub(crate) fn is_boolean_predicate_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let words: Vec<&str> = lower.split('_').collect();
    // Passive-voice shape (`X_was_Y`, `X_by_Y`, `X_by`) is not a predicate.
    if words.last() == Some(&"by") {
        return false;
    }
    // Predicate verbs that read as a boolean test when used anywhere in
    // the name. Subject-predicate forms (`visibility_is_public`,
    // `line_in_ranges`, `path_matches`) ride on these.
    const PREDICATE_WORDS: &[&str] = &[
        "is",
        "has",
        "can",
        "should",
        "allows",
        "supports",
        "contains",
        "needs",
        "uses",
        "matches",
        "in",
        "intersects",
        "overlaps",
    ];
    if words.iter().any(|word| PREDICATE_WORDS.contains(word)) {
        return true;
    }
    // Compound predicates that combine two words (no separator on the
    // first half).
    lower.starts_with("starts_with") || lower.starts_with("ends_with")
}

pub(crate) fn is_placeholder_identifier(name: &str) -> bool {
    matches!(name, "foo" | "bar" | "baz" | "qux")
}
