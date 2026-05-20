use super::*;

pub(crate) fn analyse_dead_code(
    file: &SourceFile,
    ast: &syn::File,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    for item in &ast.items {
        analyse_dead_code_item(file, item, source, false, findings);
    }
}

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
            name: item_fn.sig.ident.to_string(),
            span: item_fn.sig.ident.span(),
            test_context,
        },
        findings,
    );
}

pub(crate) fn analyse_dead_impl(
    file: &SourceFile,
    item_impl: &syn::ItemImpl,
    source: &str,
    test_context: bool,
    findings: &mut Vec<Finding>,
) {
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            analyse_dead_impl_method(file, method, source, test_context, findings);
        }
    }
}

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
            name: method.sig.ident.to_string(),
            span: method.sig.ident.span(),
            test_context,
        },
        findings,
    );
}

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
    name: String,
    span: proc_macro2::Span,
    test_context: bool,
}

pub(crate) fn analyse_dead_function(
    file: &SourceFile,
    source: &str,
    candidate: DeadFunctionCandidate<'_>,
    findings: &mut Vec<Finding>,
) {
    let DeadFunctionCandidate {
        visibility,
        attrs,
        name,
        span,
        test_context,
    } = candidate;
    if is_public(visibility) || name == "main" || has_test_attr(attrs) || test_context {
        return;
    }
    if function_call_count(source, &name) == 0 {
        findings.push(Finding::new(
            "dead-code.unused-private-function",
            format!("Private function `{name}` appears to be unused in this file."),
            file.display_path.clone(),
            Some(line_from_span(span.start())),
            Severity::Advisory,
            Pillar::DeadCode,
            Confidence::Low,
            Some(name),
            Some("Remove the function or add a real call site.".to_string()),
            json!({}),
        ));
    }
}

pub(crate) fn function_call_count(source: &str, name: &str) -> usize {
    static CACHE: OnceLock<Mutex<HashMap<String, (Regex, Regex)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let (call_regex, simple_definition_regex) = {
        let mut guard = cache.lock().expect("function call regex cache");
        guard
            .entry(name.to_string())
            .or_insert_with(|| {
                let escaped = regex::escape(name);
                let call = Regex::new(&format!(r"\b{escaped}\s*(?:::\s*<[^>]+>)?\s*\("))
                    .expect("generated function-call regex compiles");
                let definition = Regex::new(&format!(r"\bfn\s+{escaped}\s*\("))
                    .expect("generated function-definition regex compiles");
                (call, definition)
            })
            .clone()
    };
    let count = call_regex.find_iter(source).count();
    if simple_definition_regex.is_match(source) {
        count.saturating_sub(1)
    } else {
        count
    }
}

pub(crate) fn analyse_unreachable(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let terminator = static_regex(
        &UNREACHABLE_TERMINATOR_REGEX,
        r"\b(return|panic!|todo!|unimplemented!)",
    );
    let useful = static_regex(&NON_WHITESPACE_REGEX, r"\S");
    let mut previous_terminated = false;
    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if previous_terminated && useful.is_match(trimmed) && !trimmed.starts_with('}') {
            findings.push(finding(
                "waste.unreachable-code",
                "Statement appears after a terminating statement.",
                file,
                Some(line_index + 1),
                Severity::Warning,
                Pillar::Waste,
            ));
        }
        previous_terminated = terminator.is_match(trimmed) && trimmed.ends_with(';');
    }
}
