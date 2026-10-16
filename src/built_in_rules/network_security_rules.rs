//! Network security rules inspect executable Rust for exposed listeners, tainted requests, unsafe parsing, and raw HTML output.
//!
//! Operators reach these checks during project scans, including test and CI source.
//! Parsed source prevents a finite enum label from becoming an HTML warning.

use super::*;

pub(crate) static BIND_ALL_INTERFACES_REGEX: OnceLock<Regex> = OnceLock::new();

/// `security.hardcoded-bind-all-interfaces` — flags listener address
/// literals that bind to every network interface, optionally followed
/// by a port, in production and executable test source.
pub(crate) fn analyse_hardcoded_bind_all_interfaces(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    findings: &mut Vec<Finding>,
) {
    let lines: Vec<&str> = unit.source.lines().collect();
    let non_listeners = non_listener_literals::ranges(ast, unit.source);
    // Each all-interface literal becomes one reviewable exposure in the user's report.
    for capture in bind_all_interfaces_regex().captures_iter(unit.source) {
        record_bind_capture(unit, &capture, &lines, &non_listeners, findings);
    }
}

fn record_bind_capture(
    unit: &SourceUnit<'_>,
    capture: &regex::Captures<'_>,
    lines: &[&str],
    non_listeners: &[std::ops::Range<usize>],
    findings: &mut Vec<Finding>,
) {
    let Some(full) = capture.get(0) else {
        return;
    };
    let line = byte_line_from_starts(unit.line_starts(), full.start());
    if line_is_doc_or_comment(lines, line)
        || non_listeners
            .iter()
            .any(|range| range.start <= full.start() && full.end() <= range.end)
    {
        return;
    }
    let addr = capture.name("addr").map_or("", |matched| matched.as_str());
    if addr.is_empty() {
        return;
    }
    findings.push(bind_all_interfaces_finding(unit.file, line, addr));
}

fn bind_all_interfaces_regex() -> &'static Regex {
    static_regex(
        &BIND_ALL_INTERFACES_REGEX,
        r#""(?P<addr>0\.0\.0\.0|\[::\]|::0)(?::\d+)?""#,
    )
}

fn line_is_doc_or_comment(lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let Some(text) = lines.get(line - 1) else {
        return false;
    };
    let trimmed = text.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("/*")
}

fn bind_all_interfaces_finding(file: &SourceFile, line: usize, addr: &str) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.hardcoded-bind-all-interfaces".to_string(),
        message: format!(
            "Listener address `{addr}` binds to every network interface; review whether the bind should be restricted."
        ),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Bind to a loopback address for local-only servers, or gate the all-interfaces bind behind a deployment flag."
                .to_string(),
        ),
        metadata: json!({ "address": addr }),
    })
}

/// Syntax evidence that a matched literal is client data or a string comparison.
/// Unknown uses and opaque macro reads retain the listener warning.
mod non_listener_literals {
    use super::*;
    use syn::parse::Parser;
    use syn::visit::Visit;

    pub(super) fn ranges(ast: &syn::File, source: &str) -> Vec<std::ops::Range<usize>> {
        let mut collector = NonListenerLiterals {
            source,
            ranges: Vec::new(),
        };
        collector.visit_file(ast);
        collector.ranges
    }

    struct NonListenerLiterals<'a> {
        source: &'a str,
        ranges: Vec<std::ops::Range<usize>>,
    }

    impl<'ast> Visit<'ast> for NonListenerLiterals<'_> {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            for (index, statement) in block.stmts.iter().enumerate() {
                let syn::Stmt::Local(local) = statement else {
                    continue;
                };
                let (syn::Pat::Ident(binding), Some(init)) = (&local.pat, &local.init) else {
                    continue;
                };
                if binding.mutability.is_some()
                    || binding.by_ref.is_some()
                    || binding.subpat.is_some()
                {
                    continue;
                }
                let mut candidates = Vec::new();
                value_literals(&init.expr, self.source, &mut candidates);
                if candidates.is_empty() {
                    continue;
                }
                let mut uses = ClientAddressUses {
                    binding: &binding.ident,
                    total: 0,
                    client: 0,
                };
                for statement in &block.stmts[index + 1..] {
                    uses.visit_stmt(statement);
                }
                if uses.total == 1 && uses.client == 1 {
                    self.ranges.extend(candidates);
                }
            }
            syn::visit::visit_block(self, block);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "starts_with" {
                if let Some(syn::Expr::Lit(literal)) = call.args.first() {
                    if let syn::Lit::Str(value) = &literal.lit {
                        self.ranges.push(value.span().byte_range());
                    }
                }
            }
            if is_tls_client_connect(call) {
                if let Some(argument) = call.args.first() {
                    value_literals(argument, self.source, &mut self.ranges);
                }
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if is_endpoint_client(call) {
                if let Some(argument) = call.args.first() {
                    value_literals(argument, self.source, &mut self.ranges);
                }
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("assert") {
                let parser =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
                if let Ok(arguments) = parser.parse2(mac.tokens.clone()) {
                    if let Some(condition) = arguments.first() {
                        self.visit_expr(condition);
                    }
                }
            }
        }
    }

    /// Follow only value-preserving address conversions and match-arm values.
    fn value_literals(expr: &syn::Expr, source: &str, ranges: &mut Vec<std::ops::Range<usize>>) {
        match expr {
            syn::Expr::Lit(literal) => {
                if let syn::Lit::Str(value) = &literal.lit {
                    let range = value.span().byte_range();
                    if source
                        .get(range.clone())
                        .is_some_and(|text| bind_all_interfaces_regex().is_match(text))
                    {
                        ranges.push(range);
                    }
                }
            }
            syn::Expr::MethodCall(call)
                if matches!(
                    call.method.to_string().as_str(),
                    "parse" | "try_into" | "unwrap" | "expect"
                ) =>
            {
                value_literals(&call.receiver, source, ranges);
            }
            syn::Expr::Match(branch) => {
                for arm in &branch.arms {
                    value_literals(&arm.body, source, ranges);
                }
            }
            syn::Expr::Paren(group) => value_literals(&group.expr, source, ranges),
            syn::Expr::Group(group) => value_literals(&group.expr, source, ranges),
            syn::Expr::Try(attempt) => value_literals(&attempt.expr, source, ranges),
            _ => {}
        }
    }

    struct ClientAddressUses<'a> {
        binding: &'a syn::Ident,
        total: usize,
        client: usize,
    }

    impl<'ast> Visit<'ast> for ClientAddressUses<'_> {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if path.qself.is_none() && path.path.is_ident(self.binding) {
                self.total += 1;
            }
            syn::visit::visit_expr_path(self, path);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if is_endpoint_client(call) && argument_is_binding(call.args.first(), self.binding) {
                self.client += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if is_tls_client_connect(call) && argument_is_binding(call.args.first(), self.binding) {
                self.client += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if tokens_mention_binding(mac.tokens.clone(), self.binding) {
                self.total += 1;
            }
        }
    }

    fn argument_is_binding(argument: Option<&syn::Expr>, binding: &syn::Ident) -> bool {
        matches!(argument, Some(syn::Expr::Path(path)) if path.qself.is_none() && path.path.is_ident(binding))
    }

    fn is_endpoint_client(call: &syn::ExprCall) -> bool {
        matches!(call.func.as_ref(), syn::Expr::Path(path) if path_ends_with(&path.path, "Endpoint", "client"))
            && call.args.len() == 1
    }

    fn is_tls_client_connect(call: &syn::ExprMethodCall) -> bool {
        call.method == "connect"
            && call.args.len() == 1
            && matches!(call.receiver.as_ref(), syn::Expr::Call(receiver)
                if matches!(receiver.func.as_ref(), syn::Expr::Path(path)
                    if path_ends_with(&path.path, "Arc", "new")))
    }

    fn path_ends_with(path: &syn::Path, owner: &str, method: &str) -> bool {
        let mut segments = path.segments.iter().rev();
        segments
            .next()
            .is_some_and(|segment| segment.ident == method)
            && segments
                .next()
                .is_some_and(|segment| segment.ident == owner)
    }

    fn tokens_mention_binding(tokens: proc_macro2::TokenStream, binding: &syn::Ident) -> bool {
        tokens.into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(ident) => ident == *binding,
            proc_macro2::TokenTree::Group(group) => tokens_mention_binding(group.stream(), binding),
            _ => false,
        })
    }
}

/// Flag caller-derived request URLs even when the executable path belongs to a test or CI helper.
pub(crate) fn analyse_ssrf_candidate(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    // Each function keeps input evidence local so one helper cannot implicate another.
    for block in blocks {
        let mut taint = FunctionTaint::from_block(block);
        // Each source line can validate an input or carry it into a supported request sink.
        for (line_index, line) in block.body.lines().enumerate() {
            taint.observe_line(line);
            // A line without a tainted URL sink adds nothing to the user's security report.
            let Some(argument) = ssrf_sink_argument(line, &taint) else {
                continue;
            };
            findings.push(network_candidate_finding(
                file,
                "security.ssrf-candidate",
                "HTTP request URL is derived from local input; review host allow-listing.",
                block.start_line + line_index,
                &argument,
            ));
        }
    }
}

pub(crate) fn analyse_unsafe_deserialization(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
        let mut taint = FunctionTaint::from_block(block);
        for (line_index, line) in block.body.lines().enumerate() {
            taint.observe_line(line);
            if yaml_config_parse_is_intentional(block, line) {
                continue;
            }
            let Some(argument) = unsafe_deserialization_argument(line, &taint) else {
                continue;
            };
            findings.push(network_candidate_finding(
                file,
                "security.unsafe-deserialization",
                "Binary or YAML deserialization reads data derived from local input.",
                block.start_line + line_index,
                &argument,
            ));
        }
    }
}

pub(crate) fn analyse_xxe_candidate(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    for (line_index, line) in searchable.lines().enumerate() {
        if line.contains("ParserOption::NOENT")
            || line.contains("ParserOption::DTDLOAD")
            || line.contains(".resolve_entities(true)")
        {
            let mut result = network_candidate_finding(
                file,
                "security.xxe-candidate",
                "XML parser configuration enables external entity or DTD resolution.",
                line_index + 1,
                "xml-parser",
            );
            result.remediation = Some("Parse untrusted XML with DTD processing and external-entity resolution disabled, and validate the input at the boundary before it reaches the parser.".to_string());
            findings.push(result);
        }
    }
}

/// Flag request-derived HTML output unless parsed source proves the printed value is a finite enum label.
/// An operator scanning a handler still sees warnings for payloads and mixed dynamic output.
pub(crate) fn analyse_template_injection_xss(
    file: &SourceFile,
    ast: &syn::File,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    // Each function is checked separately so one safe handler cannot excuse another handler's output.
    for block in blocks {
        let mut taint = FunctionTaint::from_block(block);
        // Each source line can contain a reportable HTML sink even when an earlier line was safe.
        for (line_index, line) in block.body.lines().enumerate() {
            taint.observe_line(line);
            // Lines without a tainted template sink add no security finding for the user to review.
            let Some(argument) = template_sink_argument(line, &taint) else {
                continue;
            };
            // A single derived unit-enum label cannot carry request text into this exact HTML expression.
            if derived_unit_enum_html_argument(ast, block).as_deref() == Some(argument.as_str()) {
                continue;
            }
            findings.push(network_candidate_finding(
                file,
                "security.template-injection-xss",
                "HTML or template output includes request-derived data without local escaping evidence.",
                block.start_line + line_index,
                &argument,
            ));
        }
    }
}

/// Return the sole request parameter only when one Axum HTML expression prints its derived unit-enum label.
/// Any missing source fact leaves the user's security warning in place.
fn derived_unit_enum_html_argument(ast: &syn::File, block: &FunctionBlock) -> Option<String> {
    // A trusted wrapper and formatter must be visible before suppressing a security warning.
    if !uses_standard_axum_html_format(ast) {
        return None;
    }
    let function = top_level_handler_for_block(ast, block)?;
    let (parameter_name, enum_name) = sole_enum_parameter(function)?;
    // A payload or custom formatter can turn the displayed enum into request-derived text.
    if !has_derived_unit_enum_without_formatter(ast, enum_name) {
        return None;
    }
    let (format_literal, uses_explicit_argument) =
        single_html_format_literal(function, &parameter_name)?;
    let named_field = format!("{{{parameter_name}:?}}");
    // Captured and positional Debug fields are equivalent ways to print the same finite label.
    let allowed_fields = if uses_explicit_argument {
        vec!["{:?}", "{0:?}"]
    } else {
        vec![named_field.as_str()]
    };
    has_only_enum_debug_fields(&format_literal.value(), &allowed_fields).then_some(parameter_name)
}

/// Require Axum's HTML wrapper and reject source imports that can replace the expected formatter.
fn uses_standard_axum_html_format(ast: &syn::File) -> bool {
    let imports_html = ast.items.iter().any(
        |item| matches!(item, syn::Item::Use(import) if has_axum_html_import(&import.tree, "")),
    );
    // Without the observed Axum import, a local Html call has unknown behavior.
    if !imports_html {
        return false;
    }
    // An external module could supply a formatter that this single-file check cannot inspect.
    if ast
        .items
        .iter()
        .any(|item| matches!(item, syn::Item::Mod(module) if module.content.is_none()))
    {
        return false;
    }
    // An imported Debug derive or format macro could change what the handler prints.
    !ast.items.iter().any(|item| match item {
        syn::Item::Use(import) => {
            has_named_import(&import.tree, "Debug") || has_named_import(&import.tree, "format")
        }
        syn::Item::Macro(macro_item) => macro_item
            .ident
            .as_ref()
            .is_some_and(|name| name == "format"),
        _ => false,
    })
}

/// Locate only the top-level parsed handler that owns the user's reported source block.
fn top_level_handler_for_block<'a>(
    ast: &'a syn::File,
    block: &FunctionBlock,
) -> Option<&'a syn::ItemFn> {
    let mut matching_functions = ast.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function)
            if function.sig.ident == block.name
                && (block.start_line..block.start_line + block.line_count)
                    .contains(&function.sig.ident.span().start().line) =>
        {
            Some(function)
        }
        _ => None,
    });
    // Ambiguous top-level handlers or attributes may change what a user actually runs.
    let function = matching_functions.next()?;
    if matching_functions.next().is_some()
        || !function.attrs.is_empty()
        || !function.sig.generics.params.is_empty()
    {
        return None;
    }
    Some(function)
}

/// Return the handler's one plain enum parameter; unknown, generic and qualified types remain reportable.
fn sole_enum_parameter(function: &syn::ItemFn) -> Option<(String, &syn::Ident)> {
    // Multiple inputs could add unproved user text to the same HTML output.
    if function.sig.inputs.len() != 1 {
        return None;
    }
    let syn::FnArg::Typed(input) = function.sig.inputs.first()? else {
        return None;
    };
    let syn::Pat::Ident(parameter) = input.pat.as_ref() else {
        return None;
    };
    let syn::Type::Path(input_type) = input.ty.as_ref() else {
        return None;
    };
    // A qualified or generic type needs more provenance than this same-file exception can prove.
    if input_type.qself.is_some()
        || input_type.path.segments.len() != 1
        || !matches!(
            input_type.path.segments.first()?.arguments,
            syn::PathArguments::None
        )
    {
        return None;
    }
    Some((
        parameter.ident.to_string(),
        &input_type.path.segments.first()?.ident,
    ))
}

/// Confirm one same-file finite enum with derived Debug and no same-file custom formatter.
fn has_derived_unit_enum_without_formatter(ast: &syn::File, enum_name: &syn::Ident) -> bool {
    let mut matching_enums = ast.items.iter().filter_map(|item| match item {
        syn::Item::Enum(item_enum) if item_enum.ident == *enum_name => Some(item_enum),
        _ => None,
    });
    let Some(item_enum) = matching_enums.next() else {
        return false;
    };
    // A second declaration, payload variant, generic or extra derive leaves the output unproved.
    if matching_enums.next().is_some() || !enum_has_only_derived_debug_unit_variants(item_enum) {
        return false;
    }
    // A same-file formatter can print more than the enum's variant label.
    !has_same_file_enum_formatter(&ast.items, enum_name)
}

/// Read a direct `Html(format!(...))` expression with either captured or explicit enum Debug formatting.
fn single_html_format_literal(
    function: &syn::ItemFn,
    parameter_name: &str,
) -> Option<(syn::LitStr, bool)> {
    // Extra statements may add or transform user text before HTML is returned.
    if function.block.stmts.len() != 1 {
        return None;
    }
    let [syn::Stmt::Expr(syn::Expr::Call(html_call), None)] = function.block.stmts.as_slice()
    else {
        return None;
    };
    let syn::Expr::Path(html_wrapper) = html_call.func.as_ref() else {
        return None;
    };
    // A different wrapper or multiple arguments may mix request data into the rendered output.
    if !html_wrapper.path.is_ident("Html") || html_call.args.len() != 1 {
        return None;
    }
    let syn::Expr::Macro(format_expression) = html_call.args.first()? else {
        return None;
    };
    // Only a built-in-looking format call with a static literal is supported.
    if !format_expression.mac.path.is_ident("format") {
        return None;
    }
    read_enum_debug_format_arguments(&format_expression.mac, parameter_name)
}

/// Read a static format literal and at most one explicit argument naming the same enum parameter.
fn read_enum_debug_format_arguments(
    format_macro: &syn::Macro,
    parameter_name: &str,
) -> Option<(syn::LitStr, bool)> {
    let format_arguments = syn::parse::Parser::parse2(
        syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
        format_macro.tokens.clone(),
    )
    .ok()?;
    let syn::Expr::Lit(first_argument) = format_arguments.first()? else {
        return None;
    };
    let syn::Lit::Str(format_literal) = &first_argument.lit else {
        return None;
    };
    // An explicit argument must be exactly the same enum parameter, with no other dynamic input.
    let uses_explicit_argument = match format_arguments.len() {
        1 => false,
        2 => {
            let syn::Expr::Path(argument) = format_arguments.iter().nth(1)? else {
                return None;
            };
            if !argument.path.is_ident(parameter_name) {
                return None;
            }
            true
        }
        _ => return None,
    };
    Some((format_literal.clone(), uses_explicit_argument))
}

/// Recognize the exact Axum HTML import so an unrelated local wrapper cannot gain this exception.
fn has_axum_html_import(import: &syn::UseTree, prefix: &str) -> bool {
    match import {
        syn::UseTree::Path(path) => {
            has_axum_html_import(&path.tree, &format!("{prefix}{}::", path.ident))
        }
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| has_axum_html_import(item, prefix)),
        syn::UseTree::Name(name) => prefix == "axum::response::" && name.ident == "Html",
        _ => false,
    }
}

/// Catch explicit imports that could replace the standard Debug derive or format macro.
fn has_named_import(import: &syn::UseTree, symbol: &str) -> bool {
    match import {
        syn::UseTree::Path(path) => has_named_import(&path.tree, symbol),
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| has_named_import(item, symbol)),
        syn::UseTree::Name(name) => name.ident == symbol,
        syn::UseTree::Rename(rename) => rename.rename == symbol,
        syn::UseTree::Glob(_) => true,
    }
}

/// Confirm that Debug is derived for a finite enum whose variants have no request-carrying fields.
fn enum_has_only_derived_debug_unit_variants(item_enum: &syn::ItemEnum) -> bool {
    // Empty, generic or payload-bearing enums need a different proof of what Debug can print.
    if item_enum.variants.is_empty()
        || item_enum.variants.len() > 32
        || !item_enum.generics.params.is_empty()
        || !item_enum
            .variants
            .iter()
            .all(|variant| matches!(variant.fields, syn::Fields::Unit))
        || item_enum.attrs.len() != 1
    {
        return false;
    }
    let derive_attribute = &item_enum.attrs[0];
    // Additional derives or a different attribute may alter the source shape being trusted.
    if !derive_attribute.path().is_ident("derive") {
        return false;
    }
    let derived_traits = derive_attribute.parse_args_with(
        syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
    );
    matches!(derived_traits, Ok(traits) if traits.len() == 1 && traits[0].is_ident("Debug"))
}

/// Find a same-file Debug or Display implementation, including one inside an inline module.
fn has_same_file_enum_formatter(items: &[syn::Item], enum_name: &syn::Ident) -> bool {
    items.iter().any(|item| match item {
        syn::Item::Impl(item_impl) => has_enum_formatter_impl(item_impl, enum_name),
        syn::Item::Mod(module) => module
            .content
            .as_ref()
            .is_some_and(|(_, nested_items)| has_same_file_enum_formatter(nested_items, enum_name)),
        _ => false,
    })
}

/// Match only a formatter implemented for the enum whose HTML output is under review.
fn has_enum_formatter_impl(item_impl: &syn::ItemImpl, enum_name: &syn::Ident) -> bool {
    let Some((_, trait_path, _)) = &item_impl.trait_ else {
        return false;
    };
    // Only Debug and Display can change the output promised by this narrow formatter check.
    if !trait_path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Debug" || segment.ident == "Display")
    {
        return false;
    }
    let syn::Type::Path(implemented_type) = item_impl.self_ty.as_ref() else {
        return false;
    };
    implemented_type
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == *enum_name)
}

/// Accept literal text, escaped braces and enum Debug fields, with no other dynamic output.
fn has_only_enum_debug_fields(format_text: &str, allowed_fields: &[&str]) -> bool {
    let format_bytes = format_text.as_bytes();
    let mut index = 0;
    let mut saw_enum = false;
    // Every opening or closing brace must be either escaped text or this enum's Debug field.
    while index < format_bytes.len() {
        match format_bytes[index] {
            b'{' if format_bytes.get(index + 1) == Some(&b'{') => index += 2,
            b'{' => {
                // Any other field could carry request text into the returned HTML.
                let Some(debug_field) = allowed_fields
                    .iter()
                    .find(|field| format_bytes[index..].starts_with(field.as_bytes()))
                else {
                    return false;
                };
                saw_enum = true;
                index += debug_field.len();
            }
            b'}' if format_bytes.get(index + 1) == Some(&b'}') => index += 2,
            b'}' => return false,
            _ => index += 1,
        }
    }
    saw_enum
}

#[derive(Default)]
struct FunctionTaint {
    tainted: BTreeSet<String>,
    validated: BTreeSet<String>,
}

impl FunctionTaint {
    fn from_block(block: &FunctionBlock) -> Self {
        Self {
            tainted: function_param_names(&block.body)
                .into_iter()
                .filter(|name| !name_is_sanitized(name))
                .collect(),
            validated: BTreeSet::new(),
        }
    }

    fn observe_line(&mut self, line: &str) {
        for name in self.tainted.clone() {
            if line_has_validation_evidence(line, &name) || name_is_sanitized(&name) {
                self.validated.insert(name);
            }
        }
        if let Some((binding, rhs)) = let_binding(line) {
            if binding_name_is_predicate(&binding) {
                return;
            }
            self.observe_binding(binding, rhs);
        }
    }

    fn observe_binding(&mut self, binding: String, rhs: &str) {
        if rhs_is_input_source(rhs) || self.tainted.iter().any(|name| rhs_contains_name(rhs, name))
        {
            if name_is_sanitized(&binding) || line_has_validation_evidence(rhs, &binding) {
                self.validated.insert(binding.clone());
            }
            self.tainted.insert(binding);
        }
    }

    fn is_tainted(&self, name: &str) -> bool {
        self.tainted.contains(name) && !self.validated.contains(name) && !name_is_sanitized(name)
    }
}

fn function_param_names(body: &str) -> Vec<String> {
    static SIGNATURE_REGEX: OnceLock<Regex> = OnceLock::new();
    static PARAM_REGEX: OnceLock<Regex> = OnceLock::new();
    let signature = static_regex(
        &SIGNATURE_REGEX,
        r"fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\((?P<params>(?s:.*?))\)",
    );
    let param = static_regex(
        &PARAM_REGEX,
        r"(?:^|,)\s*(?:mut\s+)?(?P<name>[a-z_][a-z0-9_]*)\s*:",
    );
    let Some(params) = signature
        .captures(body)
        .and_then(|captures| captures.name("params"))
    else {
        return Vec::new();
    };
    param
        .captures_iter(params.as_str())
        .filter_map(|captures| captures.name("name").map(|name| name.as_str().to_string()))
        .collect()
}

/// Return a named local assignment that can carry input evidence to a later security sink.
fn let_binding(line: &str) -> Option<(String, &str)> {
    static LET_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &LET_BINDING_REGEX,
        r"\blet\s+(?:mut\s+)?(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*(?P<rhs>[^;]+)",
    );
    // Lines without a local assignment cannot carry input into a later sink.
    let captures = regex.captures(line)?;
    // A matched assignment must expose both sides before it can extend the input trail.
    let binding = captures.name("name")?.as_str();
    let right_hand_side = captures.name("rhs")?.as_str();
    // A discarded result cannot flow into a later sink, so it has no taint identity to retain.
    (binding != "_").then(|| (binding.to_string(), right_hand_side))
}

fn rhs_is_input_source(rhs: &str) -> bool {
    rhs.contains("std::env::var")
        || rhs.contains("env::var")
        || rhs.contains(".uri()")
        || rhs.contains(".query(")
        || rhs.contains(".headers(")
        || rhs.contains(".path(")
}

fn rhs_contains_name(rhs: &str, name: &str) -> bool {
    let pattern = format!(r"\b{}\b", regex::escape(name));
    Regex::new(&pattern)
        .map(|compiled| compiled.is_match(rhs))
        .unwrap_or(false)
}

fn line_has_validation_evidence(line: &str, name: &str) -> bool {
    line_uses_url_validation(line, name)
        || line_uses_allowlist(line, name)
        || line_uses_html_escape(line, name)
}

fn line_uses_url_validation(line: &str, name: &str) -> bool {
    (line.contains("Url::parse") || line.contains("validate_url")) && rhs_contains_name(line, name)
}

fn line_uses_allowlist(line: &str, name: &str) -> bool {
    (line.contains("allowed_host") || line.contains("allowlist")) && rhs_contains_name(line, name)
}

fn line_uses_html_escape(line: &str, name: &str) -> bool {
    (line.contains("html_escape") || line.contains("escape_html")) && rhs_contains_name(line, name)
}

fn binding_name_is_predicate(name: &str) -> bool {
    name.starts_with("has_")
        || name.starts_with("is_")
        || name.starts_with("does_")
        || name.starts_with("can_")
        || name.starts_with("should_")
        || name.starts_with("contains_")
        || name.starts_with("matches_")
}

fn name_is_sanitized(name: &str) -> bool {
    name.contains("safe")
        || name.contains("sanitized")
        || name.contains("validated")
        || name.contains("allowed")
        || name.contains("escaped")
}

fn ssrf_sink_argument(line: &str, taint: &FunctionTaint) -> Option<String> {
    static SSRF_SINK_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &SSRF_SINK_REGEX,
        r"(?:reqwest::get|(?:client|http_client)\.(?:get|post|put|delete)|\.uri|hyper::Uri::from_maybe_shared)\s*\(\s*&?(?P<arg>[a-z_][a-z0-9_]*)",
    );
    let argument = regex.captures(line)?.name("arg")?.as_str();
    taint.is_tainted(argument).then(|| argument.to_string())
}

fn unsafe_deserialization_argument(line: &str, taint: &FunctionTaint) -> Option<String> {
    static DESERIALIZATION_SINK_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &DESERIALIZATION_SINK_REGEX,
        // The optional turbofish keeps `serde_yaml::from_str::<Config>(body)` visible. These sinks
        // frequently cannot infer their type parameter, so the annotated spelling is the common one
        // and matching only the bare call left the dominant form of the pattern unreported. The
        // argument excludes parentheses rather than `>` so a nested generic such as
        // `::<Vec<String>>` is still consumed whole.
        r"(?:serde_yaml::from_(?:str|reader|slice)|bincode::(?:deserialize|deserialize_from)|rmp_serde::from_(?:slice|read)|serde_pickle::from_(?:slice|reader))(?:::<[^()]*>)?\s*\(\s*&?(?P<arg>[a-z_][a-z0-9_]*)",
    );
    let argument = regex.captures(line)?.name("arg")?.as_str();
    taint.is_tainted(argument).then(|| argument.to_string())
}

fn yaml_config_parse_is_intentional(block: &FunctionBlock, line: &str) -> bool {
    line.contains("serde_yaml::from_str")
        && (block.name.contains("config") || block.name.contains("yaml"))
}

fn template_sink_argument(line: &str, taint: &FunctionTaint) -> Option<String> {
    if line.contains("html_escape") || line.contains("escape_html") || line.contains("| escape") {
        return None;
    }
    let has_sink = line.contains("Html(format!")
        || line.contains(".body(format!")
        || line.contains("PreEscaped(format!")
        || line.contains("Markup::new(format!")
        || line.contains("render_str(");
    if !has_sink {
        return None;
    }
    taint
        .tainted
        .iter()
        .find(|name| taint.is_tainted(name) && rhs_contains_name(line, name))
        .cloned()
}

fn network_candidate_finding(
    file: &SourceFile,
    rule_id: &str,
    message: &str,
    line: usize,
    argument: &str,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::Medium,
        symbol: Some(argument.to_string()),
        remediation: Some(
            "Validate, constrain, or escape untrusted input at the boundary before passing it to the sink."
                .to_string(),
        ),
        metadata: json!({ "candidate": true, "argument": argument }),
    })
}
