use super::*;

mod items;
mod lockfile;
mod manifest;

pub(crate) use items::{
    collect_project_rust_index, inferred_file_module_path, ProjectIndexBuilders,
};
pub(crate) use lockfile::read_lockfile_summary;
pub(crate) use manifest::read_manifest_summary;

#[cfg(test)]
pub(crate) fn read_and_parse_sources(
    files: &[SourceFile],
) -> (Vec<ParsedSource>, Vec<RunDiagnostic>) {
    read_and_parse_sources_with_options(files, true)
}

pub(crate) fn read_and_parse_sources_with_options(
    files: &[SourceFile],
    parse_rust: bool,
) -> (Vec<ParsedSource>, Vec<RunDiagnostic>) {
    let mut parsed_sources = Vec::with_capacity(files.len());
    let mut diagnostics = Vec::new();

    for source_file in files {
        match fs::read_to_string(&source_file.absolute_path) {
            Ok(source) => parsed_sources.push(parse_source_file(source_file, source, parse_rust)),
            Err(error) => diagnostics.push(RunDiagnostic {
                diagnostic_type: "read-error".to_string(),
                message: format!("Unable to read file: {error}"),
                file_path: Some(source_file.display_path.clone()),
                line: Some(1),
            }),
        }
    }

    (parsed_sources, diagnostics)
}

pub(crate) fn parse_source_file(
    file: &SourceFile,
    source: String,
    parse_rust: bool,
) -> ParsedSource {
    let file_owned = file.clone();
    if !parse_rust || !file_owned.is_rust {
        return ParsedSource {
            file: file_owned,
            source,
            rust_ast: None,
            diagnostics: Vec::new(),
            line_starts: OnceLock::new(),
        };
    }

    match syn::parse_file(&source) {
        Ok(ast) => ParsedSource {
            file: file_owned,
            source,
            rust_ast: Some(ast),
            diagnostics: Vec::new(),
            line_starts: OnceLock::new(),
        },
        Err(error) => {
            let display_path = file_owned.display_path.clone();
            ParsedSource {
                file: file_owned,
                source,
                rust_ast: None,
                diagnostics: vec![RunDiagnostic {
                    diagnostic_type: "parse-error".to_string(),
                    message: format!("Rust parser error: {error}"),
                    file_path: Some(display_path),
                    line: Some(line_from_span(error.span().start())),
                }],
                line_starts: OnceLock::new(),
            }
        }
    }
}

pub(crate) fn line_from_span(position: LineColumn) -> usize {
    position.line.max(1)
}

pub(crate) fn build_project_context(
    project_root: &Path,
    sources: &[ParsedSource],
) -> ProjectContext {
    let mut diagnostics = Vec::new();
    let manifest = read_manifest_summary(project_root, &mut diagnostics);
    let lockfile = read_lockfile_summary(project_root, &mut diagnostics);
    let mut index = project_index(sources);
    sort_project_index(&mut index);

    ProjectContext {
        root_path: project_root.to_path_buf(),
        manifest,
        lockfile,
        rust_sources: index.rust_sources,
        identifier_counts: index.identifier_counts,
        modules: index.modules,
        items: index.items,
        call_names: index.call_names,
        diagnostics,
    }
}

pub(crate) struct ProjectIndex {
    rust_sources: Vec<RustSourceSummary>,
    identifier_counts: BTreeMap<String, usize>,
    modules: Vec<ModuleSummary>,
    items: Vec<ItemSummary>,
    call_names: Vec<CallNameSummary>,
}

pub(crate) fn project_index(sources: &[ParsedSource]) -> ProjectIndex {
    let mut rust_sources = Vec::with_capacity(sources.len());
    let mut identifier_counts = BTreeMap::new();
    let mut modules = Vec::with_capacity(sources.len());
    let mut items = Vec::with_capacity(sources.len().saturating_mul(4));
    let mut call_names = Vec::with_capacity(sources.len().saturating_mul(8));

    for source in sources {
        if let Some(ast) = &source.rust_ast {
            let reference_source = rust_code_reference_source(&source.source);
            count_rust_identifiers(&reference_source, &mut identifier_counts);
            rust_sources.push(RustSourceSummary {
                file_path: source.file.display_path.clone(),
                source: source.source.clone(),
            });
            let module_path = inferred_file_module_path(&source.file);
            collect_project_rust_index(
                &source.file,
                &source.source,
                ast,
                &module_path,
                ProjectIndexBuilders {
                    modules: &mut modules,
                    items: &mut items,
                    call_names: &mut call_names,
                },
            );
        }
    }
    ProjectIndex {
        rust_sources,
        identifier_counts,
        modules,
        items,
        call_names,
    }
}

pub(crate) fn sort_project_index(index: &mut ProjectIndex) {
    sort_project_modules(&mut index.modules);
    sort_project_items(&mut index.items);
    index.call_names.sort_by(|left, right| {
        (left.file_path.as_str(), left.name.as_str(), left.line).cmp(&(
            right.file_path.as_str(),
            right.name.as_str(),
            right.line,
        ))
    });
    index.call_names.dedup();
    index
        .rust_sources
        .sort_by(|left, right| left.file_path.cmp(&right.file_path));
}

pub(crate) fn count_rust_identifiers(source: &str, counts: &mut BTreeMap<String, usize>) {
    static IDENTIFIER_REGEX: OnceLock<Regex> = OnceLock::new();
    let identifier_regex = static_regex(&IDENTIFIER_REGEX, r"\b[A-Za-z_][A-Za-z0-9_]*\b");
    for found in identifier_regex.find_iter(source) {
        *counts.entry(found.as_str().to_string()).or_default() += 1;
    }
}

pub(crate) fn sort_project_modules(modules: &mut [ModuleSummary]) {
    modules.sort_by(|left, right| {
        (
            left.file_path.as_str(),
            left.module_path.as_str(),
            left.line,
            left.inline,
            left.cfg_gated,
        )
            .cmp(&(
                right.file_path.as_str(),
                right.module_path.as_str(),
                right.line,
                right.inline,
                right.cfg_gated,
            ))
    });
}

pub(crate) fn sort_project_items(items: &mut [ItemSummary]) {
    items.sort_by(|left, right| {
        (
            left.file_path.as_str(),
            left.module_path.as_str(),
            left.name.as_str(),
            left.kind.as_str(),
            left.line,
            left.cfg_gated,
            left.test_context,
        )
            .cmp(&(
                right.file_path.as_str(),
                right.module_path.as_str(),
                right.name.as_str(),
                right.kind.as_str(),
                right.line,
                right.cfg_gated,
                right.test_context,
            ))
    });
}

pub(crate) fn has_cfg_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("cfg"))
}

pub(crate) fn has_cfg_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }

        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        cfg_tokens_are_test_only(list.tokens.clone())
    })
}

pub(crate) fn cfg_tokens_are_test_only(tokens: proc_macro2::TokenStream) -> bool {
    syn::parse2::<syn::Meta>(tokens)
        .ok()
        .is_some_and(|meta| cfg_meta_is_test_only(&meta))
}

pub(crate) fn cfg_meta_is_test_only(meta: &syn::Meta) -> bool {
    if meta.path().is_ident("test") {
        return true;
    }
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    let Ok(nested) = syn::parse::Parser::parse2(parser, list.tokens.clone()) else {
        return false;
    };
    if list.path.is_ident("all") {
        return nested.iter().any(cfg_meta_is_test_only);
    }
    if list.path.is_ident("any") {
        return !nested.is_empty() && nested.iter().all(cfg_meta_is_test_only);
    }
    false
}

pub(crate) fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| last_segment_matches(attr, "test"))
}

pub(crate) fn last_segment_matches(attr: &syn::Attribute, name: &str) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == name)
}

pub(crate) fn is_test_module(item_mod: &syn::ItemMod) -> bool {
    item_mod.ident == "tests"
        || has_test_attr(&item_mod.attrs)
        || has_cfg_test_attr(&item_mod.attrs)
}

pub(crate) fn collect_call_names(
    file: &SourceFile,
    source: &str,
    call_names: &mut Vec<CallNameSummary>,
) {
    static CALL_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
    let call_name_regex = static_regex(&CALL_NAME_REGEX, r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(");
    let line_offsets = line_starts(source);
    for capture in call_name_regex.captures_iter(source) {
        let Some(name) = capture.get(1) else {
            continue;
        };
        if !is_call_name_candidate(name.as_str()) {
            continue;
        }
        push_call_name(file, source.len(), &line_offsets, name, call_names);
    }
}

pub(crate) fn is_call_name_candidate(name: &str) -> bool {
    !matches!(
        name,
        "fn" | "if" | "match" | "while" | "for" | "loop" | "return"
    )
}

pub(crate) fn push_call_name(
    file: &SourceFile,
    source_len: usize,
    line_starts: &[usize],
    name: regex::Match<'_>,
    call_names: &mut Vec<CallNameSummary>,
) {
    call_names.push(CallNameSummary {
        file_path: file.display_path.clone(),
        name: name.as_str().to_string(),
        line: byte_line_from_starts(line_starts, name.start().min(source_len)),
    });
}

pub(crate) fn visibility_is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

/// Returns true only for unrestricted `pub` items. `pub(crate)`, `pub(super)`,
/// and `pub(in path)` are reachable inside the crate but not part of the
/// external API surface, so the reportable public-API rules
/// (`modernisation.public-field`, `docs.missing-public-doc`,
/// `error-handling.public-unwrap`, `architecture.public-api-surface`) use this
/// stricter helper. Dead-code reachability and project-model indexing keep
/// using the lenient `visibility_is_public` above.
pub(crate) fn visibility_is_externally_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}
