use super::*;

/// Runs the unused-private-function check over every top-level item of one parsed Rust file.
///
/// `file` supplies the display path for each finding, `ast` supplies the top-level items, and `findings` receives every new finding.
/// `source` is the file text; it passes through `rust_code_reference_source` before any same-file reference is counted.
/// Top-level items start outside test context.
pub(crate) fn analyse_dead_code(
    file: &SourceFile,
    ast: &syn::File,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let code_only_source = rust_code_reference_source(source);
    for item in &ast.items {
        analyse_dead_code_item(file, item, &code_only_source, false, findings);
    }
}

/// Routes one item to the dead-code check for functions, impl blocks or modules, and ignores every other item kind.
///
/// `file` supplies the display path for findings, `item` is the item to inspect, and `source` is the file's reference-counting text.
/// `test_context` is true inside a test-only module and suppresses findings there; new findings are appended to `findings`.
pub(crate) fn analyse_dead_code_item(
    file: &SourceFile,
    item: &Item,
    source: &str,
    test_context: bool,
    findings: &mut Vec<Finding>,
) {
    match item {
        Item::Fn(item_fn) => analyse_dead_item_fn(file, item_fn, source, test_context, findings),
        Item::Impl(item_impl) => analyse_dead_impl(file, item_impl, source, test_context, findings),
        Item::Mod(item_mod) => analyse_dead_mod(file, item_mod, source, test_context, findings),
        _ => {}
    }
}

/// Checks one free function for the unused-private-function finding by wrapping it in a `DeadFunctionCandidate`.
///
/// `file` supplies the display path, `item_fn` supplies the visibility, attributes, signature, body and name span to check.
/// `source` is the file's reference-counting text, `test_context` is true inside a test-only module, and `findings` receives any finding.
pub(crate) fn analyse_dead_item_fn(
    file: &SourceFile,
    item_fn: &syn::ItemFn,
    source: &str,
    test_context: bool,
    findings: &mut Vec<Finding>,
) {
    analyse_dead_function(
        file,
        source,
        DeadFunctionCandidate {
            visibility: &item_fn.vis,
            attrs: &item_fn.attrs,
            sig: &item_fn.sig,
            block: &item_fn.block,
            name: item_fn.sig.ident.to_string(),
            span: item_fn.sig.ident.span(),
            test_context,
        },
        findings,
    );
}

/// Checks every method of an inherent impl block for the unused-private-function finding and skips trait impls entirely.
///
/// `file` supplies the display path, `item_impl` is the impl block, and `source` is the file's reference-counting text.
/// `test_context` is true inside a test-only module; a test or `cfg(test)` attribute on the impl also makes its methods test code.
/// New findings are appended to `findings`.
pub(crate) fn analyse_dead_impl(
    file: &SourceFile,
    item_impl: &syn::ItemImpl,
    source: &str,
    test_context: bool,
    findings: &mut Vec<Finding>,
) {
    if item_impl.trait_.is_some() {
        return;
    }
    let impl_test_context =
        test_context || has_test_attr(&item_impl.attrs) || has_cfg_test_attr(&item_impl.attrs);
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            analyse_dead_impl_method(file, method, source, impl_test_context, findings);
        }
    }
}

/// Checks one inherent impl method for the unused-private-function finding by wrapping it in a `DeadFunctionCandidate`.
///
/// `file` supplies the display path, `method` supplies the visibility, attributes, signature, body and name span to check.
/// `source` is the file's reference-counting text, `test_context` is true for a test-only impl or module, and `findings` gets any finding.
pub(crate) fn analyse_dead_impl_method(
    file: &SourceFile,
    method: &syn::ImplItemFn,
    source: &str,
    test_context: bool,
    findings: &mut Vec<Finding>,
) {
    analyse_dead_function(
        file,
        source,
        DeadFunctionCandidate {
            visibility: &method.vis,
            attrs: &method.attrs,
            sig: &method.sig,
            block: &method.block,
            name: method.sig.ident.to_string(),
            span: method.sig.ident.span(),
            test_context,
        },
        findings,
    );
}

/// Checks every item inside an inline module body for unused private functions; a `mod name;` declaration without a body is skipped.
///
/// `file` supplies the display path, `item_mod` is the module, and `source` is the file's reference-counting text.
/// `test_context` is true inside a test-only module, and `is_test_module` can also mark this module test-only for everything nested in it.
/// New findings are appended to `findings`.
pub(crate) fn analyse_dead_mod(
    file: &SourceFile,
    item_mod: &syn::ItemMod,
    source: &str,
    test_context: bool,
    findings: &mut Vec<Finding>,
) {
    let Some((_, items)) = &item_mod.content else {
        return;
    };
    let nested_test_context = test_context || is_test_module(item_mod);
    for nested in items {
        analyse_dead_code_item(file, nested, source, nested_test_context, findings);
    }
}

pub(crate) struct DeadFunctionCandidate<'a> {
    visibility: &'a Visibility,
    attrs: &'a [syn::Attribute],
    sig: &'a syn::Signature,
    block: &'a syn::Block,
    name: String,
    span: proc_macro2::Span,
    test_context: bool,
}

/// Reports a private function as `dead-code.unused-private-function` when nothing in the file references its name besides its definition.
///
/// `candidate` carries the function's visibility, attributes, signature, body, name, name span and test context.
/// `file` gives the display path, `source` is the file's reference-counting text, and any advisory finding is appended to `findings`.
///
/// Functions `is_public` accepts, `main`, test-context functions and those `is_reached_outside_file_references` accepts are skipped.
/// Nothing is reported for a file that `is_parent_module_file` matches.
///
/// Panics when a checked name is long enough to push a generated regex past the regex crate's size limit, or the reference cache lock is poisoned.
pub(crate) fn analyse_dead_function(
    file: &SourceFile,
    source: &str,
    candidate: DeadFunctionCandidate<'_>,
    findings: &mut Vec<Finding>,
) {
    let DeadFunctionCandidate {
        visibility,
        attrs,
        sig,
        block,
        name,
        span,
        test_context,
    } = candidate;
    if is_public(visibility)
        || name == "main"
        || test_context
        || is_reached_outside_file_references(attrs, sig, block)
        || is_parent_module_file(source)
    {
        return;
    }
    if function_reference_count(source, &name) == 0 {
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "dead-code.unused-private-function".to_string(),
            message: format!("Private function `{name}` appears to be unused in this file."),
            file_path: file.display_path.clone(),
            line: Some(line_from_span(span.start())),
            severity: Severity::Advisory,
            pillar: Pillar::DeadCode,
            confidence: Confidence::Low,
            symbol: Some(name),
            remediation: Some(
                "Remove the function or add a real call site. If only macro-generated or build-script-generated code calls it, make that call visible in source or name the generated caller in the function's documentation."
                    .to_string(),
            ),
            metadata: json!({}),
        }));
    }
}

/// Report whether a private fn is reached by something a same-file reference count cannot see: a test
/// harness, an export attribute, or [`is_reached_without_rust_reference`].
///
/// `attrs` are the function's attributes, checked for test, `cfg(test)` and export markers.
/// `sig` and `block` are its signature and body, which `is_reached_without_rust_reference` reads together with `attrs`.
/// Returns true when any of those checks exempts the function from the same-file count, and false when none applies.
fn is_reached_outside_file_references(
    attrs: &[syn::Attribute],
    sig: &syn::Signature,
    block: &syn::Block,
) -> bool {
    has_test_attr(attrs)
        || has_cfg_test_attr(attrs)
        || has_export_attr(attrs)
        || is_reached_without_rust_reference(attrs, sig, block)
}

// Rust submodules can call private items in their parent module, so a
// file that declares `mod X;` is acting as a parent and its same-file
// dead-code detection misses descendant call sites. Skip dead-code on
// parents - the cost of a stale helper in a parent module is low,
// and the false-positive rate without this skip is high.
/// Detects a parent module file by a line-leading out-of-line `mod name;` declaration, so dead-code checks can skip it.
///
/// `source` is the file text to search for a line-leading `mod` declaration, optionally `pub` or `pub(...)`, ending in a semicolon.
/// The module name must be an ASCII identifier, so a declaration with a non-ASCII or raw `r#` name is not detected.
/// Returns true when a matching declaration is found, and false otherwise, as for a file with only inline modules or none.
fn is_parent_module_file(source: &str) -> bool {
    static SUBMODULE_DECL_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &SUBMODULE_DECL_REGEX,
        r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*;",
    )
    .is_match(source)
}

/// Counts how often `name` appears as a whole word in `source`, minus each `fn` definition of that name.
///
/// `source` is the text to search and `name` is the function name, escaped so it matches literally.
/// The two regexes for each `name` are compiled once and cached for the process.
/// This panics if the cache mutex is poisoned or a regex fails to compile, such as one for a `name` past the regex size limit.
///
/// Returns the count of whole-word matches of `name` minus its `fn` definitions, saturating at zero; zero means nothing else references it.
pub(crate) fn function_reference_count(source: &str, name: &str) -> usize {
    static CACHE: OnceLock<Mutex<HashMap<String, (Regex, Regex)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let (identifier_regex, definition_regex) = {
        let mut guard = cache.lock().expect("function reference regex cache");
        guard
            .entry(name.to_string())
            .or_insert_with(|| {
                let escaped = regex::escape(name);
                let identifier = Regex::new(&format!(r"\b{escaped}\b"))
                    .expect("generated function-reference regex compiles");
                // A definition is `fn <name>` followed by either its generic list or its
                // parameter list, and nothing else in Rust has that shape. Stopping at that
                // one delimiter keeps a bound containing parentheses, such as
                // `fn helper<F: Fn()>(..)`, subtractable: consuming the whole generic clause
                // would need balanced matching, and failing to match it makes the definition
                // count as one of its own references so the function reads as used forever.
                let definition = Regex::new(&format!(r"\bfn\s+{escaped}\s*[<(]"))
                    .expect("generated function-definition regex compiles");
                (identifier, definition)
            })
            .clone()
    };
    identifier_regex
        .find_iter(source)
        .count()
        .saturating_sub(definition_regex.find_iter(source).count())
}
