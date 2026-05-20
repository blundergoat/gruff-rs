use super::*;

pub(crate) fn analyse_comment_rules(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let masked = strip_rust_string_literals(source);
    let comments = extract_rust_comments(&masked);
    for comment in &comments {
        analyse_stale_todo_comment(file, comment, findings);
        analyse_commented_out_code_comment(file, comment, findings);
    }
}

pub(crate) fn analyse_stale_todo_comment(
    file: &SourceFile,
    comment: &RustComment,
    findings: &mut Vec<Finding>,
) {
    const MARKERS: &[&str] = &["TODO", "FIXME", "HACK", "XXX"];
    for marker in MARKERS {
        if let Some((after, found_marker)) = find_marker(&comment.text, marker) {
            if !has_durable_reference(after) {
                findings.push(Finding::new(
                    "docs.stale-todo",
                    format!("{found_marker} comment lacks an owner, issue reference, or reason."),
                    file.display_path.clone(),
                    Some(comment.line),
                    Severity::Advisory,
                    Pillar::Documentation,
                    Confidence::High,
                    None,
                    Some(
                        "Add an owner (@name), issue (#123 or URL), or a colon-prefixed reason."
                            .to_string(),
                    ),
                    json!({ "marker": found_marker, "missingReference": true }),
                ));
            }
            return;
        }
    }
}

pub(crate) fn find_marker<'a>(text: &'a str, marker: &str) -> Option<(&'a str, String)> {
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find(marker) {
        let pos = search_from + rel;
        let before_ok = pos == 0 || {
            let byte = text.as_bytes()[pos - 1];
            !byte.is_ascii_alphanumeric() && byte != b'_'
        };
        let after_pos = pos + marker.len();
        let after_ok = match text.as_bytes().get(after_pos) {
            None => true,
            Some(byte) => !byte.is_ascii_alphanumeric() && *byte != b'_',
        };
        if before_ok && after_ok {
            return Some((&text[after_pos..], marker.to_string()));
        }
        search_from = pos + marker.len();
    }
    None
}

pub(crate) fn has_durable_reference(after_marker: &str) -> bool {
    let trimmed = after_marker.trim_start();
    if let Some(rest) = trimmed.strip_prefix('(') {
        if let Some(end) = rest.find(')') {
            let inner = &rest[..end];
            return inner.contains('#')
                || inner.contains('@')
                || inner.starts_with("GH-")
                || inner.contains("://")
                || (inner.contains(':') && inner.trim().len() >= 3);
        }
        return false;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let inner = &rest[..end];
            return inner.contains('#')
                || inner.contains('@')
                || inner.starts_with("GH-")
                || inner.contains("://");
        }
        return false;
    }
    if let Some(rest) = trimmed.strip_prefix(':') {
        return rest.trim().len() >= 5;
    }
    false
}

pub(crate) fn analyse_commented_out_code_comment(
    file: &SourceFile,
    comment: &RustComment,
    findings: &mut Vec<Finding>,
) {
    if comment.is_doc {
        return;
    }
    if looks_like_disabled_rust_code(&comment.text) {
        findings.push(Finding::new(
                "docs.commented-out-code",
                "Comment payload looks like disabled Rust code; remove or document intent.",
                file.display_path.clone(),
                Some(comment.line),
                Severity::Advisory,
                Pillar::Documentation,
                Confidence::Medium,
                None,
                Some(
                    "Delete the commented-out code or convert it to a comment explaining why it is intentionally kept."
                        .to_string(),
                ),
                json!({}),
            ));
    }
}

pub(crate) fn looks_like_disabled_rust_code(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() < 5 {
        return false;
    }
    const STARTERS: &[&str] = &[
        "let ",
        "let mut ",
        "fn ",
        "pub fn ",
        "pub(",
        "use ",
        "if ",
        "match ",
        "for ",
        "while ",
        "loop {",
        "return ",
        "return;",
        "struct ",
        "enum ",
        "trait ",
        "impl ",
        "type ",
        "const ",
        "static ",
        "async fn ",
        "unsafe ",
        "mod ",
        "mut ",
        "self.",
    ];
    let starter_ok = STARTERS.iter().any(|prefix| trimmed.starts_with(prefix));
    if !starter_ok {
        return false;
    }
    let last = trimmed.as_bytes().last().copied().unwrap_or(0);
    matches!(last, b';' | b'}' | b'{')
}

pub(crate) fn analyse_item_rules(file: &SourceFile, ast: &syn::File, findings: &mut Vec<Finding>) {
    for item in &ast.items {
        analyse_public_item(file, item, findings);
    }
}

pub(crate) fn analyse_public_item(file: &SourceFile, item: &Item, findings: &mut Vec<Finding>) {
    match item {
        Item::Mod(item_mod) => analyse_public_module_item(file, item_mod, findings),
        Item::Struct(item_struct) => analyse_public_struct_item(file, item_struct, findings),
        Item::Enum(item_enum) => {
            analyse_public_named_item_doc(
                file,
                &item_enum.vis,
                &item_enum.attrs,
                item_enum.ident.to_string(),
                item_enum.ident.span(),
                findings,
            );
        }
        Item::Trait(item_trait) => {
            analyse_public_named_item_doc(
                file,
                &item_trait.vis,
                &item_trait.attrs,
                item_trait.ident.to_string(),
                item_trait.ident.span(),
                findings,
            );
        }
        _ => {}
    }
}

pub(crate) fn analyse_public_module_item(
    file: &SourceFile,
    item_mod: &syn::ItemMod,
    findings: &mut Vec<Finding>,
) {
    analyse_public_named_item_doc(
        file,
        &item_mod.vis,
        &item_mod.attrs,
        item_mod.ident.to_string(),
        item_mod.ident.span(),
        findings,
    );
    if let Some((_, items)) = &item_mod.content {
        for nested in items {
            analyse_public_item(file, nested, findings);
        }
    }
}

pub(crate) fn analyse_public_struct_item(
    file: &SourceFile,
    item_struct: &syn::ItemStruct,
    findings: &mut Vec<Finding>,
) {
    analyse_public_named_item_doc(
        file,
        &item_struct.vis,
        &item_struct.attrs,
        item_struct.ident.to_string(),
        item_struct.ident.span(),
        findings,
    );
    for field in &item_struct.fields {
        if is_externally_public(&field.vis) {
            push_public_field_finding(file, field.span(), findings);
        }
    }
}

pub(crate) fn analyse_public_named_item_doc(
    file: &SourceFile,
    visibility: &Visibility,
    attrs: &[syn::Attribute],
    name: String,
    span: proc_macro2::Span,
    findings: &mut Vec<Finding>,
) {
    if is_externally_public(visibility) && !has_doc_attr(attrs) {
        push_missing_public_item_doc(file, name, span, findings);
    }
}

pub(crate) fn push_public_field_finding(
    file: &SourceFile,
    span: proc_macro2::Span,
    findings: &mut Vec<Finding>,
) {
    findings.push(finding(
        "modernisation.public-field",
        "Public struct field exposes representation; prefer accessors when invariants matter.",
        file,
        Some(line_from_span(span.start())),
        Severity::Advisory,
        Pillar::Modernisation,
    ));
}

pub(crate) fn push_missing_public_item_doc(
    file: &SourceFile,
    name: String,
    span: proc_macro2::Span,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding::new(
        "docs.missing-public-doc",
        format!("Public item `{name}` is missing a Rust doc comment."),
        file.display_path.clone(),
        Some(line_from_span(span.start())),
        Severity::Advisory,
        Pillar::Documentation,
        Confidence::Medium,
        Some(name),
        Some("Add a /// doc comment explaining the public API contract.".to_string()),
        json!({}),
    ));
}

pub(crate) fn rust_function_blocks(ast: &syn::File, source: &str) -> Vec<FunctionBlock> {
    let lines: Vec<&str> = source.lines().collect();
    let mut blocks = Vec::new();

    for item in &ast.items {
        collect_function_blocks(item, &lines, false, &mut blocks);
    }

    blocks
}

pub(crate) fn collect_function_blocks(
    item: &Item,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    match item {
        Item::Fn(item_fn) => push_item_function_block(item_fn, lines, test_context, blocks),
        Item::Impl(item_impl) => push_impl_function_blocks(item_impl, lines, test_context, blocks),
        Item::Mod(item_mod) => {
            collect_module_function_blocks(item_mod, lines, test_context, blocks)
        }
        _ => {}
    }
}

pub(crate) fn push_item_function_block(
    item_fn: &syn::ItemFn,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    blocks.push(function_block_from_parts(FunctionBlockParts {
        lines,
        name: item_fn.sig.ident.to_string(),
        param_count: count_params(&item_fn.sig.inputs),
        visibility: &item_fn.vis,
        attrs: &item_fn.attrs,
        test_context,
        is_async: item_fn.sig.asyncness.is_some(),
        returns_bool: returns_bool(&item_fn.sig.output),
        returns_result: returns_result(&item_fn.sig.output),
        name_start: item_fn.sig.ident.span().start(),
        block_end: item_fn.block.span().end(),
        block: &item_fn.block,
    }));
}

pub(crate) fn push_impl_function_blocks(
    item_impl: &syn::ItemImpl,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            push_impl_method_function_block(method, lines, test_context, blocks);
        }
    }
}

pub(crate) fn push_impl_method_function_block(
    method: &syn::ImplItemFn,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    blocks.push(function_block_from_parts(FunctionBlockParts {
        lines,
        name: method.sig.ident.to_string(),
        param_count: count_params(&method.sig.inputs),
        visibility: &method.vis,
        attrs: &method.attrs,
        test_context,
        is_async: method.sig.asyncness.is_some(),
        returns_bool: returns_bool(&method.sig.output),
        returns_result: returns_result(&method.sig.output),
        name_start: method.sig.ident.span().start(),
        block_end: method.block.span().end(),
        block: &method.block,
    }));
}
