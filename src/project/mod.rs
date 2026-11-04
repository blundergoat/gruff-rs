use super::*;

mod items;
mod lockfile;
mod manifest;

pub(crate) use items::{
    collect_project_rust_index, has_export_attr, inferred_file_module_path, ProjectIndexBuilders,
};
pub(crate) use lockfile::read_lockfile_summary;
pub(crate) use manifest::read_manifest_summary;

#[cfg(test)]
pub(crate) fn read_and_parse_sources(
    files: &[SourceFile],
) -> (Vec<ParsedSource>, Vec<RunDiagnostic>) {
    read_and_parse_sources_with_options(files, true, &DeepScanBudget::default())
}

/// Read and parse each selected source file, reporting files that cannot be read as run diagnostics instead of stopping the scan.
///
/// `files` lists the source files to read, and `parse_rust` set to false keeps Rust files as text without a syntax tree.
/// `deep_scan_budget` marks Rust files over its enabled line or byte limit as bounded deep scans instead of parsing them.
///
/// Returns the parsed sources in input order and the read diagnostics, including non-UTF-8 skips.
/// Rust parse errors and budget notes stay on each parsed source instead.
pub(crate) fn read_and_parse_sources_with_options(
    files: &[SourceFile],
    parse_rust: bool,
    deep_scan_budget: &DeepScanBudget,
) -> (Vec<ParsedSource>, Vec<RunDiagnostic>) {
    let mut parsed_sources = Vec::with_capacity(files.len());
    let mut diagnostics = Vec::new();

    for source_file in files {
        match read_source_text(source_file) {
            Ok(source) => parsed_sources.push(parse_source_file(
                source_file,
                source,
                parse_rust,
                deep_scan_budget,
            )),
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }

    (parsed_sources, diagnostics)
}

/// Read one source file and decode it as UTF-8 text.
///
/// `source_file` supplies the absolute path to read and the display path that diagnostics name.
/// Returns the file text, or Err with a `read-error` diagnostic when the file cannot be read or is not valid UTF-8.
/// A file that `invalid_utf8_can_be_skipped` accepts gets a `read-skip-non-utf8` diagnostic instead of the UTF-8 error.
fn read_source_text(source_file: &SourceFile) -> Result<String, RunDiagnostic> {
    let bytes = fs::read(&source_file.absolute_path).map_err(|error| {
        read_error_diagnostic(source_file, format!("Unable to read file: {error}"))
    })?;
    match String::from_utf8(bytes) {
        Ok(source) => Ok(source),
        Err(_) if invalid_utf8_can_be_skipped(source_file) => Err(RunDiagnostic {
            diagnostic_type: "read-skip-non-utf8".to_string(),
            message: "Skipped supported text file because it is not valid UTF-8.".to_string(),
            file_path: Some(source_file.display_path.clone()),
            line: Some(1),
            invalidates_run: None,
        }),
        Err(_) => Err(read_error_diagnostic(
            source_file,
            "Unable to read supported text as UTF-8; explicit inputs and security-relevant text must be valid UTF-8.".to_string(),
        )),
    }
}

/// Decide whether a file that is not valid UTF-8 is skipped with a `read-skip-non-utf8` diagnostic rather than reported as a read error.
///
/// `source_file` is the file whose bytes failed to decode.
/// Returns true only for a non-Rust file with `SourceOrigin::Directory` origin whose path is not security-relevant text.
fn invalid_utf8_can_be_skipped(source_file: &SourceFile) -> bool {
    source_file.origin == SourceOrigin::Directory
        && !source_file.is_rust
        && !crate::discovery::is_security_relevant_text_path(&source_file.absolute_path)
}

/// Build the `read-error` run diagnostic for a source file that could not be read or decoded.
///
/// `source_file` supplies the display path the diagnostic names, and `message` is the text shown for the failure.
/// Returns a diagnostic at line 1 that leaves `invalidates_run` unset.
fn read_error_diagnostic(source_file: &SourceFile, message: String) -> RunDiagnostic {
    RunDiagnostic {
        diagnostic_type: "read-error".to_string(),
        message,
        file_path: Some(source_file.display_path.clone()),
        line: Some(1),
        invalidates_run: None,
    }
}

/// Turn one file's text into a parsed source, building a Rust syntax tree only for a Rust file within budget while parsing is on.
///
/// `file` is the source file the text came from, `source` is its full text, and `parse_rust` set to false skips the syntax tree.
/// `deep_scan_budget`, when enabled, marks a Rust file over its line or byte limit as bounded and adds a `bounded-deep-scan` diagnostic.
///
/// Returns the parsed source; non-Rust, over-budget and unparsed files carry no syntax tree.
/// A Rust parse failure also leaves no tree and adds a `parse-error` diagnostic.
pub(crate) fn parse_source_file(
    file: &SourceFile,
    source: String,
    parse_rust: bool,
    deep_scan_budget: &DeepScanBudget,
) -> ParsedSource {
    let file_owned = file.clone();
    if !file_owned.is_rust {
        return parsed_source(file_owned, source, None, false, Vec::new());
    }

    let line_count = physical_line_count(&source);
    let byte_count = source.len();
    if deep_scan_budget.enabled
        && (line_count > deep_scan_budget.max_lines || byte_count > deep_scan_budget.max_bytes)
    {
        let display_path = file_owned.display_path.clone();
        return parsed_source(
            file_owned,
            source,
            None,
            true,
            vec![bounded_deep_scan_diagnostic(
                display_path,
                line_count,
                byte_count,
                deep_scan_budget,
            )],
        );
    }

    if !parse_rust {
        return parsed_source(file_owned, source, None, false, Vec::new());
    }

    parse_rust_source(file_owned, source)
}

/// Parse a Rust file's text with `syn`, keeping the text even when parsing fails.
///
/// `file` is the Rust source file, and `source` is its full text.
/// Returns the parsed source with its syntax tree, or with none and a `parse-error` diagnostic at the failing line when parsing fails.
fn parse_rust_source(file: SourceFile, source: String) -> ParsedSource {
    match syn::parse_file(&source) {
        Ok(ast) => parsed_source(file, source, Some(ast), false, Vec::new()),
        Err(error) => {
            let display_path = file.display_path.clone();
            parsed_source(
                file,
                source,
                None,
                false,
                vec![RunDiagnostic {
                    diagnostic_type: "parse-error".to_string(),
                    message: format!("Rust parser error: {error}"),
                    file_path: Some(display_path),
                    line: Some(line_from_span(error.span().start())),
                    invalidates_run: None,
                }],
            )
        }
    }
}

/// Assemble a parsed source from its file, text, optional syntax tree, budget flag and diagnostics.
///
/// `file` and `source` are the file and its text, and `rust_ast` is the syntax tree when one was parsed.
/// `bounded_deep_scan` marks a file the deep-scan budget skipped, and `diagnostics` holds this file's parse or budget diagnostics.
/// Returns the parsed source holding these values and an empty line-start cache.
fn parsed_source(
    file: SourceFile,
    source: String,
    rust_ast: Option<syn::File>,
    bounded_deep_scan: bool,
    diagnostics: Vec<RunDiagnostic>,
) -> ParsedSource {
    ParsedSource {
        file,
        source,
        rust_ast,
        bounded_deep_scan,
        diagnostics,
        line_starts: OnceLock::new(),
    }
}

/// Count the physical lines in a file's text for the deep-scan line budget.
///
/// `source` is the full file text.
/// Returns 0 for empty text, otherwise the number of newline bytes plus one, so a trailing newline counts as an extra line.
fn physical_line_count(source: &str) -> usize {
    if source.is_empty() {
        0
    } else {
        source.bytes().filter(|byte| *byte == b'\n').count() + 1
    }
}

/// Build the `bounded-deep-scan` diagnostic explaining that a large Rust file skipped deep analysis.
///
/// `display_path` names the file, `line_count` and `byte_count` are its size, and `budget` gives the limits and override state to quote.
/// Returns a line-1 diagnostic with `invalidates_run` set to false and a message saying text-level rules still ran.
fn bounded_deep_scan_diagnostic(
    display_path: String,
    line_count: usize,
    byte_count: usize,
    budget: &DeepScanBudget,
) -> RunDiagnostic {
    RunDiagnostic {
        diagnostic_type: "bounded-deep-scan".to_string(),
        message: format!(
            "path={display_path}; lines={line_count}; bytes={byte_count}; maxLines={}; maxBytes={}; override={}. Text-level rules (size, sensitive-data, config) still ran; masking, block parsing, AST walking, and other deep script analysis were skipped.",
            budget.max_lines, budget.max_bytes, budget.override_state
        ),
        file_path: Some(display_path),
        line: Some(1),
        invalidates_run: Some(false),
    }
}

/// Convert a parser span position into a report line number of at least 1.
///
/// `position` is the span start or end position reported by the parser.
/// Returns the position's line, raised to 1 when it is 0.
pub(crate) fn line_from_span(position: LineColumn) -> usize {
    position.line.max(1)
}

/// Build the project context: coverage, manifest, lockfile and a sorted index of the parsed Rust sources.
///
/// `project_root` is where `Cargo.toml` and the lockfile are read, and `sources` are the parsed files to index.
/// `coverage` arrives with the selected Rust files, which are replaced by those with a syntax tree; any left out sets `parse_incomplete`.
///
/// Returns the context, with the diagnostics from reading the manifest and lockfile in its `diagnostics`.
/// Its `manifest` is None when `Cargo.toml` is absent, unreadable or invalid TOML.
pub(crate) fn build_project_context(
    project_root: &Path,
    sources: &[ParsedSource],
    mut coverage: ProjectCoverage,
) -> ProjectContext {
    // A selected Rust file that failed to read or parse contributes no identifiers
    // to the index, so cross-file dead-code cannot be trusted. Base the authoritative
    // set on successfully parsed AST inputs rather than discovery alone: read-failed
    // files never enter `sources`, while parse-failed files have no AST.
    let selected_rust_files = std::mem::take(&mut coverage.analysed_rust_files);
    coverage.analysed_rust_files = sources
        .iter()
        .filter(|source| source.file.is_rust && source.rust_ast.is_some())
        .map(|source| source.file.display_path.clone())
        .collect();
    coverage.parse_incomplete |= !selected_rust_files.is_subset(&coverage.analysed_rust_files);
    let mut diagnostics = Vec::new();
    let manifest = read_manifest_summary(project_root, &mut diagnostics);
    let lockfile = read_lockfile_summary(project_root, &mut diagnostics);
    let mut index = project_index(sources);
    sort_project_index(&mut index);

    ProjectContext {
        root_path: project_root.to_path_buf(),
        coverage,
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

/// Index the parsed Rust sources into identifier counts, a file list, modules, items and call names.
///
/// `sources` are the parsed files; only those with a Rust syntax tree contribute.
///
/// Returns the index in input order, before `sort_project_index` sorts it.
/// Identifier counts come from each file's `rust_code_reference_source` text rather than its raw text.
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

/// Sort every list in the project index into a stable order, dropping repeated call names.
///
/// `index` is sorted in place: modules and items by their full summary keys, and Rust sources by file path.
/// Call names are sorted by file, name and line, then repeated entries are removed.
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

/// Add every identifier-shaped word in a text to a running count of occurrences.
///
/// `source` is the text to scan, and `counts` maps each word to its count and is increased in place.
/// Keywords count too, since any ASCII word starting with a letter or underscore matches.
pub(crate) fn count_rust_identifiers(source: &str, counts: &mut BTreeMap<String, usize>) {
    static IDENTIFIER_REGEX: OnceLock<Regex> = OnceLock::new();
    let identifier_regex = static_regex(&IDENTIFIER_REGEX, r"\b[A-Za-z_][A-Za-z0-9_]*\b");
    for found in identifier_regex.find_iter(source) {
        *counts.entry(found.as_str().to_string()).or_default() += 1;
    }
}

/// Sort module summaries into a stable order by file, module path, line, inline flag and cfg gate.
///
/// `modules` holds the module summaries and is sorted in place.
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

/// Sort item summaries into a stable order by file, module path, name, kind, container, line and their flag fields.
///
/// `items` holds the item summaries and is sorted in place; an item without a container sorts as an empty one.
pub(crate) fn sort_project_items(items: &mut [ItemSummary]) {
    items.sort_by(|left, right| {
        (
            left.file_path.as_str(),
            left.module_path.as_str(),
            left.name.as_str(),
            left.kind.as_str(),
            left.container.as_deref().unwrap_or(""),
            left.line,
            left.cfg_gated,
            left.test_context,
            left.trait_impl,
            left.exported_by_attr,
        )
            .cmp(&(
                right.file_path.as_str(),
                right.module_path.as_str(),
                right.name.as_str(),
                right.kind.as_str(),
                right.container.as_deref().unwrap_or(""),
                right.line,
                right.cfg_gated,
                right.test_context,
                right.trait_impl,
                right.exported_by_attr,
            ))
    });
}

/// Report whether an item carries any `cfg` attribute, whatever its condition.
///
/// `attrs` are the item's attributes.
/// Returns true when an attribute path is exactly `cfg`; `cfg_attr` does not count.
pub(crate) fn has_cfg_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("cfg"))
}

/// Report whether a `cfg` attribute limits an item to test builds.
///
/// `attrs` are the item's attributes.
/// Returns true when a `cfg` condition parses and `cfg_meta_is_test_only` accepts it; an unparseable condition counts as false.
pub(crate) fn has_cfg_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        let tokens = list.tokens.clone();
        syn::parse2::<syn::Meta>(tokens)
            .ok()
            .is_some_and(|meta| cfg_meta_is_test_only(&meta))
    })
}

/// Decide whether a `cfg` condition can hold only when compiling tests.
///
/// `meta` is the condition inside `cfg`, possibly an `all` or `any` that nests further conditions.
/// Returns true for `test`, for `all` with at least one test-only member, and for a non-empty `any` whose members are all test-only.
/// Any other condition, including `not`, returns false, as does a list whose members fail to parse.
pub(crate) fn cfg_meta_is_test_only(meta: &syn::Meta) -> bool {
    if meta.path().is_ident("test") {
        return true;
    }
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    let tokens = list.tokens.clone();
    let Ok(nested) = syn::parse::Parser::parse2(parser, tokens) else {
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

/// Report whether an item carries a test attribute such as `test` or `tokio::test`.
///
/// `attrs` are the item's attributes.
/// Returns true when any attribute path ends in a segment named exactly `test`.
pub(crate) fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| last_segment_matches(attr, "test"))
}

/// Report whether a fn is reached without a Rust reference the dead-code rules can count: a test or bench
/// entry point (`#[bench]`, `#[divan::bench]`, `#[maybe_tokio_test]`, or one applied through `cfg_attr`), or
/// an empty-body fn with no generics and no inputs whose `where` clause is a compile-time assertion over
/// concrete types, such as `fn assert_send() where Client: Send {}`. A foreign ABI alone reaches nothing;
/// `#[no_mangle]` and `#[export_name]` are read by `has_export_attr`.
/// Only the two dead-code rules read this; `has_test_attr` keeps its narrower meaning for its other consumers.
///
/// `attrs` are the fn's attributes, `sig` is its signature, checked for generics, inputs and `where` predicates, and `block` is its body.
/// Returns true for a harness entry attribute or an empty type-assertion fn, and false otherwise.
pub(crate) fn is_reached_without_rust_reference(
    attrs: &[syn::Attribute],
    sig: &syn::Signature,
    block: &syn::Block,
) -> bool {
    let is_type_assertion = block.stmts.is_empty()
        && sig.generics.params.is_empty()
        && sig.inputs.is_empty()
        && sig
            .generics
            .where_clause
            .as_ref()
            .is_some_and(|clause| !clause.predicates.is_empty());
    is_type_assertion || attrs.iter().any(is_harness_entry_attr)
}

/// Report whether an attribute marks a test or bench harness entry point. `cfg_attr` counts only through the
/// attributes it applies, never through its condition, so `#[cfg_attr(test, allow(dead_code))]` stays
/// production code.
///
/// `attr` is one attribute on the fn; for `cfg_attr`, every argument after the condition is checked with `path_is_harness_entry`.
/// Returns true when the attribute path, or a path `cfg_attr` applies, names a harness entry; an unparseable `cfg_attr` returns false.
fn is_harness_entry_attr(attr: &syn::Attribute) -> bool {
    if attr.path().is_ident("cfg_attr") {
        let Ok(arguments) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        ) else {
            return false;
        };
        return arguments
            .iter()
            .skip(1)
            .any(|applied| path_is_harness_entry(applied.path()));
    }
    path_is_harness_entry(attr.path())
}

/// Report whether an attribute path's last segment names a harness entry: `test`, `bench`, or a macro ending
/// in `_test` or `_bench`.
///
/// `path` is the attribute path, or a path applied through `cfg_attr`, whose last segment is checked.
/// Returns true for those names, and false for any other last segment or a path with no segments.
fn path_is_harness_entry(path: &syn::Path) -> bool {
    path.segments.last().is_some_and(|segment| {
        let name = segment.ident.to_string();
        name == "test" || name == "bench" || name.ends_with("_test") || name.ends_with("_bench")
    })
}

/// Check an attribute's last path segment against one name, so `test` matches both `test` and `tokio::test` attributes.
///
/// `attr` is the attribute to inspect, and `name` is the exact segment text to compare.
/// Returns true when the last segment equals `name`, and false otherwise or for a path with no segments.
pub(crate) fn last_segment_matches(attr: &syn::Attribute, name: &str) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == name)
}

/// Report whether a module declaration is test code by its name or attributes.
///
/// `item_mod` is the module declaration to inspect.
/// Returns true for a module named `tests`, one with a `test` attribute, or one gated by a test-only `cfg`.
pub(crate) fn is_test_module(item_mod: &syn::ItemMod) -> bool {
    item_mod.ident == "tests"
        || has_test_attr(&item_mod.attrs)
        || has_cfg_test_attr(&item_mod.attrs)
}

/// Record each word followed by an opening parenthesis as a possible call name, skipping control keywords and `fn`.
///
/// `file` supplies the display path recorded with each name, `source` is the text to scan, and `call_names` gets the matches appended.
/// Comments and strings are not excluded here; the regex runs over whatever text `source` holds.
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

/// Filter out keywords that the call-name regex would otherwise record as calls.
///
/// `name` is the word captured before an opening parenthesis.
/// Returns false for `fn`, `if`, `match`, `while`, `for`, `loop` and `return`, and true for every other word.
pub(crate) fn is_call_name_candidate(name: &str) -> bool {
    !matches!(
        name,
        "fn" | "if" | "match" | "while" | "for" | "loop" | "return"
    )
}

/// Append one call-name match with its file path and line to the collected call names.
///
/// `file` supplies the display path, and `source_len` caps the match's byte offset before the line lookup.
/// `line_starts` holds each line's starting byte offset, `name` is the regex match, and `call_names` receives the new entry.
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

/// Treat any written visibility, including `pub(crate)` and `pub(super)`, as public for dead-code reachability and project indexing.
///
/// `visibility` is the item's declared visibility.
/// Returns true for every `pub` form and false only when no visibility is written.
pub(crate) fn visibility_is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

/// Returns true only for unrestricted `pub` items. `pub(crate)`, `pub(super)`,
/// and `pub(in path)` are reachable inside the crate but not part of the
/// external API surface, so the reportable public-API rules
/// (`docs.missing-public-doc` and `architecture.public-api-surface`) use
/// this stricter helper. Dead-code reachability and project-model indexing
/// keep using the lenient `visibility_is_public` above.
///
/// `visibility` is the item's declared visibility, compared against the plain `pub` form.
pub(crate) fn visibility_is_externally_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}
