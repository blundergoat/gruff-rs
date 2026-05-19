use super::*;

mod analyzers_a;
mod analyzers_b;
mod analyzers_c;
mod analyzers_d;
mod blocks;
mod helpers;

pub(crate) use analyzers_a::*;
pub(crate) use analyzers_b::*;
pub(crate) use analyzers_c::*;
pub(crate) use analyzers_d::*;
pub(crate) use blocks::*;
pub(crate) use helpers::*;

struct RegexRule {
    rule_id: &'static str,
    regex: &'static OnceLock<Regex>,
    pattern: &'static str,
    message: &'static str,
}

static AWS_ACCESS_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static PRIVATE_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static JWT_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
static DATABASE_URL_PASSWORD_REGEX: OnceLock<Regex> = OnceLock::new();
static API_KEY_PATTERN_REGEX: OnceLock<Regex> = OnceLock::new();

const SENSITIVE_PATTERNS: &[RegexRule] = &[
    RegexRule {
        rule_id: "sensitive-data.aws-access-key",
        regex: &AWS_ACCESS_KEY_REGEX,
        pattern: r"AKIA[0-9A-Z]{16}",
        message: "AWS access key pattern detected.",
    },
    RegexRule {
        rule_id: "sensitive-data.private-key",
        regex: &PRIVATE_KEY_REGEX,
        pattern: r"BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY",
        message: "Private key block detected.",
    },
    RegexRule {
        rule_id: "sensitive-data.jwt-token",
        regex: &JWT_TOKEN_REGEX,
        pattern: r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        message: "JWT-looking token detected.",
    },
    RegexRule {
        rule_id: "sensitive-data.database-url-password",
        regex: &DATABASE_URL_PASSWORD_REGEX,
        pattern: r"[a-z]+://[^:\s]+:[^@\s]+@",
        message: "Database URL appears to include a password.",
    },
    RegexRule {
        rule_id: "sensitive-data.api-key-pattern",
        regex: &API_KEY_PATTERN_REGEX,
        pattern: r"(sk_(?:live|test)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{32,}|Endpoint=sb://[^;\s]+;[^\s]*SharedAccessKey=[A-Za-z0-9+/=]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
        message: "API key pattern detected.",
    },
];

static TEST_ASSERTION_REGEX: OnceLock<Regex> = OnceLock::new();
static SLEEP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
static LOOP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
static CONDITIONAL_LOGIC_REGEX: OnceLock<Regex> = OnceLock::new();
static UNWRAP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
static PROCESS_COMMAND_REGEX: OnceLock<Regex> = OnceLock::new();
static PANIC_MACRO_REGEX: OnceLock<Regex> = OnceLock::new();
static PLACEHOLDER_MACRO_REGEX: OnceLock<Regex> = OnceLock::new();
static UNWRAP_EXPECT_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static UNSAFE_BLOCK_REGEX: OnceLock<Regex> = OnceLock::new();
static CLONE_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static ENV_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
static HIGH_ENTROPY_STRING_REGEX: OnceLock<Regex> = OnceLock::new();
static CYCLOMATIC_COMPLEXITY_REGEX: OnceLock<Regex> = OnceLock::new();
static NPATH_BRANCH_REGEX: OnceLock<Regex> = OnceLock::new();
static NPATH_BOOLEAN_REGEX: OnceLock<Regex> = OnceLock::new();
static METRIC_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
static LOOP_START_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_REGEX_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_FORMAT_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_CLONE_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
static UNBOUNDED_CHANNEL_REGEX: OnceLock<Regex> = OnceLock::new();
static LOCK_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
static UNREACHABLE_TERMINATOR_REGEX: OnceLock<Regex> = OnceLock::new();
static NON_WHITESPACE_REGEX: OnceLock<Regex> = OnceLock::new();
static TRIVIAL_ASSERT_REGEX: OnceLock<Regex> = OnceLock::new();
static SAME_LITERAL_ASSERT_REGEX: OnceLock<Regex> = OnceLock::new();

const TEST_CHECKS: &[RegexRule] = &[
    RegexRule {
        rule_id: "test-quality.sleep-in-test",
        regex: &SLEEP_IN_TEST_REGEX,
        pattern: r"(std::thread::sleep|tokio::time::sleep)",
        message: "Test sleeps instead of synchronising on behaviour.",
    },
    RegexRule {
        rule_id: "test-quality.loop-in-test",
        regex: &LOOP_IN_TEST_REGEX,
        pattern: r"\b(for|while|loop)\b",
        message: "Test contains loop logic.",
    },
    RegexRule {
        rule_id: "test-quality.conditional-logic",
        regex: &CONDITIONAL_LOGIC_REGEX,
        pattern: r"\b(if|match)\b",
        message: "Test contains conditional logic.",
    },
    RegexRule {
        rule_id: "test-quality.unwrap-in-test",
        regex: &UNWRAP_IN_TEST_REGEX,
        pattern: r"\.unwrap\(\)",
        message: "Test uses unwrap(), which can hide setup intent.",
    },
];

/// Run enabled text and Rust rules for one parsed source unit.
pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    analyse_text_rules(unit.file, unit.source, unit.rust_ast, config, &mut findings);
    if let Some(ast) = unit.rust_ast {
        analyse_rust_rules(unit.file, unit.source, ast, config, &mut findings);
    }
    findings
        .into_iter()
        .filter(|finding| config.rule_enabled(&finding.rule_id))
        .collect()
}

fn analyse_text_rules(
    file: &SourceFile,
    source: &str,
    rust_ast: Option<&syn::File>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let line_count = source.lines().count();
    let rule_id = "size.file-length";
    let threshold = config.threshold(rule_id, 600.0) as usize;
    if line_count > threshold {
        findings.push(finding(
            rule_id,
            format!("File has {line_count} lines, above the threshold of {threshold}."),
            file,
            Some(1),
            config.severity(rule_id, Severity::Warning),
            Pillar::Size,
        ));
    }

    let todo_count = source.matches("TODO").count() + source.matches("FIXME").count();
    let rule_id = "docs.todo-density";
    if todo_count >= config.threshold(rule_id, 4.0) as usize {
        findings.push(finding(
            rule_id,
            format!("File contains {todo_count} TODO/FIXME markers."),
            file,
            Some(first_matching_line(source, "TODO").unwrap_or(1)),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Documentation,
        ));
    }

    analyse_sensitive_data(file, source, rust_ast, config, findings);
}

fn analyse_sensitive_data(
    file: &SourceFile,
    source: &str,
    rust_ast: Option<&syn::File>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    for rule in SENSITIVE_PATTERNS {
        for capture in static_regex(rule.regex, rule.pattern).find_iter(source) {
            let preview = redact(capture.as_str());
            if config.secret_previews.contains(&preview) {
                continue;
            }
            findings.push(Finding::new(
                rule.rule_id,
                rule.message,
                file.display_path.clone(),
                Some(byte_line(source, capture.start())),
                Severity::Error,
                Pillar::SensitiveData,
                Confidence::High,
                None,
                Some("Remove the secret and load it from a secure runtime source.".to_string()),
                json!({ "preview": preview }),
            ));
        }
    }

    analyse_env_like_secrets(file, source, rust_ast, config, findings);
    analyse_high_entropy_strings(file, source, config, findings);
}

fn analyse_env_like_secrets(
    file: &SourceFile,
    source: &str,
    rust_ast: Option<&syn::File>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &ENV_LIKE_SECRET_REGEX,
        r#"\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|DATABASE_URL)[A-Z0-9_]*\s*=\s*["']?([^"'\s]+)"#,
    );
    let test_ranges = rust_ast.map(test_context_line_ranges).unwrap_or_default();

    for capture in regex.find_iter(source) {
        let line = byte_line(source, capture.start());
        if line_in_ranges(line, &test_ranges) {
            continue;
        }
        let preview = redact(capture.as_str());
        if config.secret_previews.contains(&preview) {
            continue;
        }
        findings.push(Finding::new(
            "sensitive-data.hardcoded-env-value",
            "Hardcoded environment-style secret assignment detected.",
            file.display_path.clone(),
            Some(line),
            Severity::Error,
            Pillar::SensitiveData,
            Confidence::High,
            None,
            Some("Load secret values from runtime configuration instead of source.".to_string()),
            json!({ "preview": preview }),
        ));
    }
}

fn test_context_line_ranges(ast: &syn::File) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for item in &ast.items {
        collect_test_context_line_ranges(item, false, &mut ranges);
    }
    ranges
}

fn collect_test_context_line_ranges(
    item: &Item,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    match item {
        Item::Fn(item_fn) => collect_function_test_range(item, item_fn, test_context, ranges),
        Item::Impl(item_impl) => collect_impl_test_ranges(item, item_impl, test_context, ranges),
        Item::Mod(item_mod) => collect_module_test_ranges(item, item_mod, test_context, ranges),
        _ => {
            if test_context {
                push_item_line_range(item, ranges);
            }
        }
    }
}

fn collect_function_test_range(
    item: &Item,
    item_fn: &syn::ItemFn,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    if test_context || has_test_attr(&item_fn.attrs) || has_cfg_test_attr(&item_fn.attrs) {
        push_item_line_range(item, ranges);
    }
}

fn collect_impl_test_ranges(
    item: &Item,
    item_impl: &syn::ItemImpl,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    let item_test_context =
        test_context || has_test_attr(&item_impl.attrs) || has_cfg_test_attr(&item_impl.attrs);
    if item_test_context {
        push_item_line_range(item, ranges);
    }
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            collect_impl_method_test_range(method, item_test_context, ranges);
        }
    }
}

fn collect_impl_method_test_range(
    method: &syn::ImplItemFn,
    item_test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    if item_test_context || has_test_attr(&method.attrs) || has_cfg_test_attr(&method.attrs) {
        push_span_line_range(method.span(), ranges);
    }
}

fn collect_module_test_ranges(
    item: &Item,
    item_mod: &syn::ItemMod,
    test_context: bool,
    ranges: &mut Vec<(usize, usize)>,
) {
    let item_test_context = test_context || is_test_module(item_mod);
    if item_test_context {
        push_item_line_range(item, ranges);
    }
    if let Some((_, items)) = &item_mod.content {
        for nested in items {
            collect_test_context_line_ranges(nested, item_test_context, ranges);
        }
    }
}

fn push_item_line_range(item: &Item, ranges: &mut Vec<(usize, usize)>) {
    push_span_line_range(item.span(), ranges);
}

fn push_span_line_range(span: proc_macro2::Span, ranges: &mut Vec<(usize, usize)>) {
    let start = line_from_span(span.start());
    let end = line_from_span(span.end()).max(start);
    ranges.push((start, end));
}

fn line_in_ranges(line: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&line))
}

fn analyse_high_entropy_strings(
    file: &SourceFile,
    source: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &HIGH_ENTROPY_STRING_REGEX,
        r#""([A-Za-z0-9+/=_-]{32,})"|'([A-Za-z0-9+/=_-]{32,})'"#,
    );

    for captures in regex.captures_iter(source) {
        let Some(secret) = captures.get(1).or_else(|| captures.get(2)) else {
            continue;
        };
        let value = secret.as_str();
        if !looks_high_entropy(value) {
            continue;
        }
        let preview = redact(value);
        if config.secret_previews.contains(&preview) {
            continue;
        }
        findings.push(Finding::new(
            "sensitive-data.high-entropy-string",
            "High-entropy string literal detected.",
            file.display_path.clone(),
            Some(byte_line(source, secret.start())),
            Severity::Error,
            Pillar::SensitiveData,
            Confidence::Medium,
            None,
            Some("Move generated secrets to a secure runtime secret source.".to_string()),
            json!({ "preview": preview, "entropy": shannon_entropy(value) }),
        ));
    }
}

fn analyse_rust_rules(
    file: &SourceFile,
    source: &str,
    ast: &syn::File,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let blocks = rust_function_blocks(ast, source);
    analyse_blocks(file, &blocks, config, findings);
    analyse_process_commands(file, source, findings);
    analyse_line_rules(file, source, &blocks, findings);
    analyse_item_rules(file, ast, findings);
    analyse_dead_code(file, ast, source, findings);
    analyse_comment_rules(file, source, findings);
    analyse_naming_patterns(file, ast, config, findings);
}

/// AST-aware migration of `naming.short-variable` and
/// `naming.placeholder-identifier`. Visits every binding `Pat::Ident` in
/// `let`/`for` patterns, function parameters, closure parameters, and
/// destructured patterns (tuple, tuple-struct, struct, slice). The
/// previous regex-based dispatch only saw `let`/`for` simple bindings.
/// Also emits `naming.identifier-shadow` when a same-file free function
/// `X` is shadowed by `let X = X(...)`.
fn analyse_naming_patterns(
    file: &SourceFile,
    ast: &syn::File,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let same_file_free_fns = collect_same_file_free_fns(ast);
    let mut visitor = NamingPatternVisitor {
        file,
        config,
        findings,
        same_file_free_fns: &same_file_free_fns,
    };
    visitor.visit_file(ast);
}

/// Returns the names of every `fn` declared as a free item in the file
/// (top-level functions and functions nested inside `mod` items). Methods
/// inside `impl` blocks and `use`-imported functions are intentionally
/// excluded so the v0.1 `naming.identifier-shadow` rule stays narrow.
fn collect_same_file_free_fns(ast: &syn::File) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_free_fns_in_items(&ast.items, &mut names);
    names
}

fn collect_free_fns_in_items(items: &[syn::Item], names: &mut BTreeSet<String>) {
    for item in items {
        match item {
            syn::Item::Fn(item_fn) => {
                names.insert(item_fn.sig.ident.to_string());
            }
            syn::Item::Mod(item_mod) => {
                if let Some((_, nested)) = &item_mod.content {
                    collect_free_fns_in_items(nested, names);
                }
            }
            _ => {}
        }
    }
}

struct NamingPatternVisitor<'a> {
    file: &'a SourceFile,
    config: &'a Config,
    findings: &'a mut Vec<Finding>,
    same_file_free_fns: &'a BTreeSet<String>,
}

impl NamingPatternVisitor<'_> {
    fn visit_pat_idents(&mut self, pat: &syn::Pat) {
        walk_pat_idents(pat, &mut |ident| {
            let name = ident.to_string();
            let line = line_from_span(ident.span().start());
            self.check_name(&name, line);
        });
    }

    fn check_identifier_shadow(&mut self, local: &syn::Local) {
        let syn::Pat::Ident(pat_ident) = &local.pat else {
            return;
        };
        let Some(init) = &local.init else {
            return;
        };
        let syn::Expr::Call(call) = init.expr.as_ref() else {
            return;
        };
        let syn::Expr::Path(path_expr) = call.func.as_ref() else {
            return;
        };
        let Some(last) = path_expr.path.segments.last() else {
            return;
        };
        let binding = pat_ident.ident.to_string();
        let callee = last.ident.to_string();
        if binding != callee {
            return;
        }
        if !self.same_file_free_fns.contains(&callee) {
            return;
        }
        let line = line_from_span(pat_ident.ident.span().start());
        self.findings.push(Finding::new(
            "naming.identifier-shadow",
            format!("Local binding `{binding}` shadows same-file function `{callee}`."),
            self.file.display_path.clone(),
            Some(line),
            Severity::Advisory,
            Pillar::Naming,
            Confidence::High,
            Some(binding.clone()),
            Some("Rename the local so it does not collide with the function it calls.".to_string()),
            json!({ "shadows": callee }),
        ));
    }

    fn check_name(&mut self, name: &str, line: usize) {
        let extra_placeholders = self
            .config
            .string_array_option("naming.placeholder-identifier", "extraPlaceholders");
        let extra_match = extra_placeholders.iter().any(|extra| extra == name);
        if is_placeholder_identifier(name) || extra_match {
            self.findings.push(Finding::new(
                "naming.placeholder-identifier",
                format!("Variable `{name}` uses a placeholder name instead of domain language."),
                self.file.display_path.clone(),
                Some(line),
                Severity::Advisory,
                Pillar::Naming,
                Confidence::Medium,
                Some(name.to_string()),
                Some("Use a name that describes the domain role.".to_string()),
                json!({}),
            ));
        }
        if name.len() <= 2
            && !matches!(name, "i" | "j" | "k")
            && !name.starts_with('_')
            && !self
                .config
                .accepted_abbreviations
                .contains(&name.to_ascii_lowercase())
        {
            self.findings.push(Finding::new(
                "naming.short-variable",
                format!("Variable `{name}` is too short to explain intent."),
                self.file.display_path.clone(),
                Some(line),
                Severity::Advisory,
                Pillar::Naming,
                Confidence::Medium,
                Some(name.to_string()),
                Some("Use a name that describes the domain role.".to_string()),
                json!({}),
            ));
        }
    }
}

impl<'ast> Visit<'ast> for NamingPatternVisitor<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        self.visit_pat_idents(&local.pat);
        self.check_identifier_shadow(local);
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_for_loop(&mut self, for_loop: &'ast syn::ExprForLoop) {
        self.visit_pat_idents(&for_loop.pat);
        syn::visit::visit_expr_for_loop(self, for_loop);
    }

    fn visit_fn_arg(&mut self, arg: &'ast syn::FnArg) {
        if let syn::FnArg::Typed(pat_type) = arg {
            self.visit_pat_idents(&pat_type.pat);
        }
        syn::visit::visit_fn_arg(self, arg);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        for input in &closure.inputs {
            self.visit_pat_idents(input);
        }
        syn::visit::visit_expr_closure(self, closure);
    }
}

/// Recursively walks a `syn::Pat`, invoking `callback` for every leaf
/// `Pat::Ident`. Handles tuples, tuple-structs, struct fields, slices,
/// references, or-patterns, and typed patterns. Unhandled variants
/// (`Pat::Lit`, `Pat::Wild`, etc.) carry no bindings to inspect.
fn walk_pat_idents<F: FnMut(&syn::Ident)>(pat: &syn::Pat, callback: &mut F) {
    match pat {
        syn::Pat::Ident(pat_ident) => callback(&pat_ident.ident),
        syn::Pat::Type(pat_type) => walk_pat_idents(&pat_type.pat, callback),
        syn::Pat::Tuple(pat_tuple) => {
            for elem in &pat_tuple.elems {
                walk_pat_idents(elem, callback);
            }
        }
        syn::Pat::TupleStruct(pat_ts) => {
            for elem in &pat_ts.elems {
                walk_pat_idents(elem, callback);
            }
        }
        syn::Pat::Struct(pat_struct) => {
            for field in &pat_struct.fields {
                walk_pat_idents(&field.pat, callback);
            }
        }
        syn::Pat::Slice(pat_slice) => {
            for elem in &pat_slice.elems {
                walk_pat_idents(elem, callback);
            }
        }
        syn::Pat::Reference(pat_ref) => walk_pat_idents(&pat_ref.pat, callback),
        syn::Pat::Or(pat_or) => {
            for case in &pat_or.cases {
                walk_pat_idents(case, callback);
            }
        }
        _ => {}
    }
}
