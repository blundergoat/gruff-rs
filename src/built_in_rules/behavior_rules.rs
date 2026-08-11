use super::*;

#[path = "safety_rationale.rs"]
mod safety_rationale;
#[path = "behavior_rules/tls_sql.rs"]
mod tls_sql;

pub(crate) use safety_rationale::{find_nearby_safety_rationale, is_weak_safety_rationale};
pub(crate) use tls_sql::{analyse_sql_dynamic_query, analyse_tls_verification_disabled};

static PROCESS_SHELL_INTERPRETER_REGEX: OnceLock<Regex> = OnceLock::new();
static PROCESS_SHELL_ARG_REGEX: OnceLock<Regex> = OnceLock::new();
static PROCESS_DYNAMIC_EXECUTABLE_REGEX: OnceLock<Regex> = OnceLock::new();
static PROCESS_DYNAMIC_ARGUMENT_REGEX: OnceLock<Regex> = OnceLock::new();
static INSECURE_RNG_FOR_SECRETS_REGEX: OnceLock<Regex> = OnceLock::new();
static WEAK_CRYPTO_IMPORT_REGEX: OnceLock<Regex> = OnceLock::new();
static WEAK_CRYPTO_CONSTRUCTOR_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_line_rules(
    file: &SourceFile,
    source: &str,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    let source_lines: Vec<&str> = source.lines().collect();
    let searchable_source = strip_rust_string_literals(source);
    let raw_lines: Vec<&str> = searchable_source.lines().collect();
    let code_only_source = strip_rust_comments_after_string_mask(&searchable_source);
    let code_only_lines: Vec<&str> = code_only_source.lines().collect();
    let test_context_ranges: Vec<(usize, usize)> = blocks
        .iter()
        .filter(|block| block.is_test_context())
        .map(|block| (block.start_line, block.start_line + block.line_count))
        .collect();
    let context = LineRuleContext {
        file,
        source_lines: &source_lines,
        raw_lines: &raw_lines,
        code_only_lines: &code_only_lines,
        test_context_ranges: &test_context_ranges,
    };

    for line_index in 0..raw_lines.len() {
        context.analyse_line(line_index, findings);
    }

    analyse_unreachable(file, &code_only_source, findings);
}

pub(crate) struct LineRuleContext<'a> {
    file: &'a SourceFile,
    source_lines: &'a [&'a str],
    raw_lines: &'a [&'a str],
    code_only_lines: &'a [&'a str],
    test_context_ranges: &'a [(usize, usize)],
}

impl LineRuleContext<'_> {
    fn analyse_line(&self, line_index: usize, findings: &mut Vec<Finding>) {
        let line_number = line_index + 1;
        let source_line = self.source_lines[line_index];
        let code_only_line = self.code_only_lines[line_index];
        self.analyse_safety_line(code_only_line, line_index, line_number, findings);
        self.analyse_waste_line(code_only_line, source_line, line_number, findings);
    }

    fn line_is_in_test_context(&self, line_number: usize) -> bool {
        if file_path_is_test_code(&self.file.display_path) {
            return true;
        }
        self.test_context_ranges
            .iter()
            .any(|(start, end)| line_number >= *start && line_number < *end)
    }
}

/// Returns true when `display_path` lives under a conventional test
/// directory (`tests/`, `src/tests/`) or ends in a `_test`/`_tests`
/// segment. Lets `waste.unwrap-expect` and
/// `waste.unnecessary-clone-candidate` stay silent inside test trees
/// even when individual functions are not marked `#[test]` (a common
/// shape for shared test fixture helpers).
fn file_path_is_test_code(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    if normalized.starts_with("tests/") || normalized.contains("/tests/") {
        return true;
    }
    let stem = std::path::Path::new(&normalized)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    stem.ends_with("_test") || stem.ends_with("_tests")
}

impl LineRuleContext<'_> {
    fn analyse_safety_line(
        &self,
        code_only_line: &str,
        line_index: usize,
        line_number: usize,
        findings: &mut Vec<Finding>,
    ) {
        let has_unsafe =
            static_regex(&UNSAFE_BLOCK_REGEX, r"\bunsafe\s*\{").is_match(code_only_line);
        if !has_unsafe {
            return;
        }
        match find_nearby_safety_rationale(self.raw_lines, line_index) {
            None => findings.push(finding(SimpleFindingDescriptor {
                rule_id: "security.unsafe-block",
                message: "Unsafe block lacks a nearby SAFETY rationale.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Warning,
                pillar: Pillar::Security,
            })),
            Some(rationale) if is_weak_safety_rationale(&rationale) => {
                findings.push(Finding::new(FindingDescriptor {
                        rule_id: "docs.weak-safety-rationale".to_string(),
                        message: format!(
                            "Unsafe block's SAFETY rationale is too short or vague: `{}`.",
                            rationale.trim()
                        ),
                        file_path: self.file.display_path.clone(),
                        line: Some(line_number),
                        severity: Severity::Advisory,
                        pillar: Pillar::Documentation,
                        confidence: Confidence::Medium,
                        symbol: None,
                        remediation: Some(
                            "Explain the invariants the caller must uphold or why the operation is sound."
                                .to_string(),
                        ),
                        metadata: json!({ "rationale": rationale.trim() }),
                    }));
            }
            Some(_) => {}
        }
    }

    fn analyse_waste_line(
        &self,
        line: &str,
        raw_line: &str,
        line_number: usize,
        findings: &mut Vec<Finding>,
    ) {
        if static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(").is_match(line)
            && !expect_has_substantive_rationale(raw_line)
            && !line.contains("#[test]")
            && !self.line_is_in_test_context(line_number)
        {
            findings.push(finding(SimpleFindingDescriptor {
                rule_id: "waste.unwrap-expect",
                message: "unwrap()/expect() can turn recoverable errors into panics.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Advisory,
                pillar: Pillar::Maintainability,
            }));
        }

        if static_regex(&CLONE_CALL_REGEX, r"\.clone\(\)").is_match(line)
            && !clone_is_consumed_or_owned(line)
            && !line.contains("#[test]")
            && !self.line_is_in_test_context(line_number)
        {
            findings.push(finding(SimpleFindingDescriptor {
                rule_id: "waste.unnecessary-clone-candidate",
                message: "clone() call may be avoidable; confirm ownership requires it.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Advisory,
                pillar: Pillar::Maintainability,
            }));
        }
    }
}

/// Report risky standard-library process builders after resolving their constructor imports.
pub(crate) fn analyse_process_commands(
    file: &SourceFile,
    source: &str,
    ast: &syn::File,
    findings: &mut Vec<Finding>,
) {
    let command_regex = static_regex(
        &PROCESS_COMMAND_REGEX,
        r"\b(?P<constructor>std::process::Command|process::Command|Command)::new\s*\(",
    );
    let import_scopes = ProcessCommandImportScopes::from_ast(ast);
    let source_views = ProcessCommandSourceViews::from_source(source);
    let literal_preserving_lines: Vec<&str> =
        source_views.literal_preserving_code.lines().collect();
    let code_only_lines: Vec<&str> = source_views.code_only.lines().collect();
    // Keep each finding anchored to the source line that constructs the process command.
    for (line_index, line) in code_only_lines.iter().enumerate() {
        let line_number = line_index + 1;
        let imports = import_scopes.imports_at_line(line_number);
        let constructs_std_process_command = command_regex.captures_iter(line).any(|captures| {
            captures.name("constructor").is_some_and(|constructor| {
                constructor_has_no_outer_path(line, constructor)
                    && imports.is_std_process_constructor(constructor.as_str())
            })
        });
        // A same-named builder is harmless unless its import proves this is the standard-library type.
        if !constructs_std_process_command {
            continue;
        }
        let window_end = process_command_window_end(&code_only_lines, line_index);
        let literal_preserving_window = literal_preserving_lines[line_index..window_end].join("\n");
        let code_only_window = code_only_lines[line_index..window_end].join("\n");
        // Builder factories and fixed test cleanup lack the execution risk this rule reports.
        if process_command_is_returned_builder(
            &literal_preserving_lines,
            line_index,
            &literal_preserving_window,
        ) || process_command_is_fixed_taskkill_cleanup(&literal_preserving_window)
        {
            continue;
        }
        let risk_signals =
            process_command_risk_signals(&literal_preserving_window, &code_only_window);
        // Fixed commands without a concrete risk shape do not warrant a security warning.
        if risk_signals.is_empty() {
            continue;
        }
        push_process_command_finding(file, line_number, risk_signals, findings);
    }
}

/// Reject a constructor match captured as the suffix of another qualified Rust path.
fn constructor_has_no_outer_path(line: &str, constructor: regex::Match<'_>) -> bool {
    !line[..constructor.start()].trim_end().ends_with("::")
}

/// Comment-safe source projections used by process constructor and risk matching.
struct ProcessCommandSourceViews {
    literal_preserving_code: String,
    code_only: String,
}

impl ProcessCommandSourceViews {
    /// Mask comments in both views while retaining string literals only for literal risk checks.
    fn from_source(source: &str) -> Self {
        let string_masked = strip_rust_string_literals(source);
        let code_only = strip_rust_comments_after_string_mask(&string_masked);
        debug_assert_eq!(source.len(), string_masked.len());
        debug_assert_eq!(source.len(), code_only.len());

        let mut literal_preserving_bytes = source.as_bytes().to_vec();
        // The two masks differ only at comment bytes, so applying that difference to the original
        // retains quoted executable names without letting comment examples become risk evidence.
        for (index, (string_masked_byte, code_only_byte)) in
            string_masked.bytes().zip(code_only.bytes()).enumerate()
        {
            if string_masked_byte != code_only_byte {
                literal_preserving_bytes[index] = b' ';
            }
        }
        let literal_preserving_code = String::from_utf8(literal_preserving_bytes)
            .expect("comment masking preserves valid UTF-8 source");
        Self {
            literal_preserving_code,
            code_only,
        }
    }
}

/// Provenance of one constructor name inside a lexical Rust scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ProcessImportProvenance {
    #[default]
    Unbound,
    StandardLibrary,
    Other,
    Conflicting,
}

impl ProcessImportProvenance {
    /// Add an explicit binding without guessing which conflicting import Rust resolves.
    fn record(&mut self, new_provenance: Self) {
        *self = match (*self, new_provenance) {
            (Self::Unbound, provenance) => provenance,
            (Self::StandardLibrary, Self::StandardLibrary) => Self::StandardLibrary,
            (Self::Other, Self::Other) => Self::Other,
            (existing, Self::Unbound) => existing,
            _ => Self::Conflicting,
        };
    }

    /// Let a local binding shadow its enclosing scope; absent names inherit normally.
    fn shadow(self, local: Self) -> Self {
        if local == Self::Unbound {
            self
        } else {
            local
        }
    }
}

/// Import bindings that can resolve `Command::new` or `process::Command::new`.
#[derive(Clone, Copy, Debug, Default)]
struct ProcessCommandImports {
    bare_command: ProcessImportProvenance,
    process_module: ProcessImportProvenance,
}

impl ProcessCommandImports {
    /// Return whether a matched constructor spelling resolves to `std::process::Command`.
    fn is_std_process_constructor(self, constructor: &str) -> bool {
        match constructor {
            "std::process::Command" => true,
            "Command" => self.bare_command == ProcessImportProvenance::StandardLibrary,
            "process::Command" => self.process_module == ProcessImportProvenance::StandardLibrary,
            _ => false,
        }
    }

    /// Apply bindings declared in a nested block while retaining unshadowed outer names.
    fn shadowed_by(self, local: Self) -> Self {
        Self {
            bare_command: self.bare_command.shadow(local.bare_command),
            process_module: self.process_module.shadow(local.process_module),
        }
    }

    /// Record only bindings that can affect the two constructor spellings this rule accepts.
    fn record_binding(&mut self, source_path: &[String], local_name: &str) {
        // Only a local `Command` binding can resolve the bare constructor spelling.
        if local_name == "Command"
            && source_path
                .last()
                .is_some_and(|segment| segment == "Command")
        {
            let provenance = if is_import_path(source_path, &["std", "process", "Command"]) {
                ProcessImportProvenance::StandardLibrary
            } else {
                ProcessImportProvenance::Other
            };
            self.bare_command.record(provenance);
        }
        // A local `process` module binding governs the `process::Command` spelling.
        if local_name == "process"
            && source_path
                .last()
                .is_some_and(|segment| segment == "process")
        {
            let provenance = if is_import_path(source_path, &["std", "process"]) {
                ProcessImportProvenance::StandardLibrary
            } else {
                ProcessImportProvenance::Other
            };
            self.process_module.record(provenance);
        }
    }
}

/// Effective imports for one nested source range.
#[derive(Clone, Copy, Debug)]
struct ScopedProcessCommandImports {
    start_line: usize,
    end_line: usize,
    depth: usize,
    imports: ProcessCommandImports,
}

/// Resolve process constructor names at the source line where they appear.
struct ProcessCommandImportScopes {
    file_imports: ProcessCommandImports,
    nested_scopes: Vec<ScopedProcessCommandImports>,
}

impl ProcessCommandImportScopes {
    /// Collect file, module, function, and nested-block imports from the parsed source.
    fn from_ast(ast: &syn::File) -> Self {
        let file_imports = process_command_imports_from_items(&ast.items);
        let mut collector = ProcessCommandScopeCollector {
            active_imports: file_imports,
            depth: 0,
            nested_scopes: Vec::new(),
        };
        // File-level imports are already recorded; visit every other item for nested scopes.
        for item in &ast.items {
            if !matches!(item, syn::Item::Use(_)) {
                collector.visit_item(item);
            }
        }
        Self {
            file_imports,
            nested_scopes: collector.nested_scopes,
        }
    }

    /// Return the innermost import scope containing a one-based source line.
    fn imports_at_line(&self, line_number: usize) -> ProcessCommandImports {
        self.nested_scopes
            .iter()
            .filter(|scope| line_number >= scope.start_line && line_number <= scope.end_line)
            .max_by_key(|scope| scope.depth)
            .map(|scope| scope.imports)
            .unwrap_or(self.file_imports)
    }
}

/// Walk nested Rust scopes while preserving the imports visible to each child block.
struct ProcessCommandScopeCollector {
    active_imports: ProcessCommandImports,
    depth: usize,
    nested_scopes: Vec<ScopedProcessCommandImports>,
}

impl ProcessCommandScopeCollector {
    /// Enter one source range with the imports that resolve names inside it.
    fn push_scope(&mut self, span: proc_macro2::Span, imports: ProcessCommandImports) {
        self.nested_scopes.push(ScopedProcessCommandImports {
            start_line: span.start().line,
            end_line: span.end().line,
            depth: self.depth,
            imports,
        });
    }
}

impl<'ast> Visit<'ast> for ProcessCommandScopeCollector {
    /// Apply block-local imports to functions, closures, and nested expression blocks.
    fn visit_block(&mut self, block: &'ast syn::Block) {
        let local_imports = process_command_imports_from_statements(&block.stmts);
        let enclosing_imports = self.active_imports;
        self.active_imports = enclosing_imports.shadowed_by(local_imports);
        self.depth += 1;
        self.push_scope(block.span(), self.active_imports);
        syn::visit::visit_block(self, block);
        self.depth -= 1;
        self.active_imports = enclosing_imports;
    }

    /// Start each inline module with its own imports; module children do not inherit `use` items.
    fn visit_item_mod(&mut self, item_mod: &'ast syn::ItemMod) {
        let Some((_, module_items)) = &item_mod.content else {
            return;
        };
        let enclosing_imports = self.active_imports;
        self.active_imports = process_command_imports_from_items(module_items);
        self.depth += 1;
        self.push_scope(item_mod.span(), self.active_imports);
        // Module imports already contribute to the scope, so only their sibling items need visits.
        for item in module_items {
            if !matches!(item, syn::Item::Use(_)) {
                self.visit_item(item);
            }
        }
        self.depth -= 1;
        self.active_imports = enclosing_imports;
    }
}

/// Collect relevant imports declared directly in one module or source file.
fn process_command_imports_from_items(items: &[syn::Item]) -> ProcessCommandImports {
    let use_trees = items.iter().filter_map(|item| match item {
        syn::Item::Use(item_use) => Some(&item_use.tree),
        _ => None,
    });
    process_command_imports_from_trees(use_trees)
}

/// Collect relevant imports declared directly in one executable block.
fn process_command_imports_from_statements(statements: &[syn::Stmt]) -> ProcessCommandImports {
    let use_trees = statements.iter().filter_map(|statement| match statement {
        syn::Stmt::Item(syn::Item::Use(item_use)) => Some(&item_use.tree),
        _ => None,
    });
    process_command_imports_from_trees(use_trees)
}

/// Merge relevant `use` trees that share one lexical namespace.
fn process_command_imports_from_trees<'a>(
    use_trees: impl Iterator<Item = &'a syn::UseTree>,
) -> ProcessCommandImports {
    let mut imports = ProcessCommandImports::default();
    for use_tree in use_trees {
        collect_process_command_bindings(use_tree, &mut Vec::new(), &mut imports);
    }
    imports
}

/// Walk one `use` tree and retain bindings relevant to process-command provenance.
fn collect_process_command_bindings(
    tree: &syn::UseTree,
    path_prefix: &mut Vec<String>,
    imports: &mut ProcessCommandImports,
) {
    match tree {
        syn::UseTree::Path(path) => {
            path_prefix.push(path.ident.to_string());
            collect_process_command_bindings(&path.tree, path_prefix, imports);
            path_prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "self" => {
            // `use path::{self}` binds the final path segment under its existing name.
            if let Some(local_name) = path_prefix.last() {
                imports.record_binding(path_prefix, local_name);
            }
        }
        syn::UseTree::Name(name) => {
            path_prefix.push(name.ident.to_string());
            imports.record_binding(path_prefix, &name.ident.to_string());
            path_prefix.pop();
        }
        syn::UseTree::Rename(rename) => {
            let source_name = rename.ident.to_string();
            let local_name = rename.rename.to_string();
            // A renamed `self` binds the accumulated path rather than another child segment.
            if source_name == "self" {
                imports.record_binding(path_prefix, &local_name);
            } else {
                path_prefix.push(source_name);
                imports.record_binding(path_prefix, &local_name);
                path_prefix.pop();
            }
        }
        syn::UseTree::Glob(_) => {
            // Only `std::process::*` proves that the glob exports the standard `Command` type.
            if is_import_path(path_prefix, &["std", "process"]) {
                imports
                    .bare_command
                    .record(ProcessImportProvenance::StandardLibrary);
            }
        }
        syn::UseTree::Group(group) => {
            // Every grouped child inherits the path accumulated before the braces.
            for item in &group.items {
                collect_process_command_bindings(item, path_prefix, imports);
            }
        }
    }
}

/// Compare a collected import path with the standard-library path required by the caller.
fn is_import_path(path: &[String], expected: &[&str]) -> bool {
    path.iter().map(String::as_str).eq(expected.iter().copied())
}

pub(crate) fn analyse_insecure_rng_for_secrets(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if !is_secret_like_rng_function_name(&block.name) {
        return;
    }

    let code_only = strip_rust_comments_after_string_mask(searchable_body);
    let regex = static_regex(
        &INSECURE_RNG_FOR_SECRETS_REGEX,
        r"\brand\s*::\s*(?P<call>thread_rng|random)\s*(?:::<[^>\n]+>)?\s*\(",
    );
    for (line_offset, line) in code_only.lines().enumerate() {
        let Some(call) = insecure_rng_call(line, regex) else {
            continue;
        };
        findings.push(insecure_rng_for_secrets_finding(
            file,
            block,
            line_offset,
            call,
        ));
        return;
    }
}

fn insecure_rng_call<'a>(line: &'a str, regex: &Regex) -> Option<&'a str> {
    regex.captures(line)?.name("call").map(|call| call.as_str())
}

fn insecure_rng_for_secrets_finding(
    file: &SourceFile,
    block: &FunctionBlock,
    line_offset: usize,
    call: &str,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.insecure-rng-for-secrets".to_string(),
        message: format!(
            "Function `{}` appears to generate secret material with non-cryptographic rand.",
            block.name
        ),
        file_path: file.display_path.clone(),
        line: Some(block.start_line + line_offset),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::Medium,
        symbol: Some(block.name.clone()),
        remediation: Some(
            "Use a cryptographically secure RNG such as rand::rngs::OsRng for tokens, keys, nonces, salts, and passwords. If the call is in a test fixture that intentionally uses a seeded RNG, add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                .to_string(),
        ),
        metadata: json!({ "function": block.name, "call": format!("rand::{call}") }),
    })
}

fn is_secret_like_rng_function_name(name: &str) -> bool {
    name.to_ascii_lowercase()
        .split(|character: char| character == '_' || !character.is_ascii_alphanumeric())
        .any(|segment| {
            matches!(
                segment,
                "token"
                    | "tokens"
                    | "secret"
                    | "secrets"
                    | "key"
                    | "keys"
                    | "password"
                    | "passwords"
                    | "nonce"
                    | "nonces"
                    | "salt"
                    | "salts"
            )
        })
}

pub(crate) fn analyse_weak_crypto(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let starts = line_starts(source);
    let mut reporter = WeakCryptoReporter {
        file,
        line_starts: &starts,
        findings,
        emitted: std::collections::BTreeSet::new(),
    };

    let import_regex = static_regex(
        &WEAK_CRYPTO_IMPORT_REGEX,
        r"(?m)^\s*use\s+(?P<primitive>md5|md_5|sha1|sha_1|rc4|des)(?:::|\s*;)",
    );
    for captures in import_regex.captures_iter(&searchable) {
        let Some(primitive) = captures.name("primitive") else {
            continue;
        };
        reporter.push(primitive.as_str(), primitive.start());
    }

    let constructor_regex = static_regex(
        &WEAK_CRYPTO_CONSTRUCTOR_REGEX,
        r"\b(?P<primitive>Md5|Sha1|Rc4|Des)::new\s*\(",
    );
    for captures in constructor_regex.captures_iter(&searchable) {
        let Some(primitive) = captures.name("primitive") else {
            continue;
        };
        reporter.push(primitive.as_str(), primitive.start());
    }
}

struct WeakCryptoReporter<'a, 'b> {
    file: &'a SourceFile,
    line_starts: &'a [usize],
    findings: &'b mut Vec<Finding>,
    emitted: std::collections::BTreeSet<String>,
}

impl WeakCryptoReporter<'_, '_> {
    fn push(&mut self, primitive: &str, byte_index: usize) {
        let normalized = normalize_weak_crypto_primitive(primitive);
        if !self.emitted.insert(normalized.to_string()) {
            return;
        }

        self.findings.push(Finding::new(FindingDescriptor {
            rule_id: "security.weak-crypto".to_string(),
            message: format!(
                "Weak cryptographic primitive `{primitive}` is referenced; review cryptographic use."
            ),
            file_path: self.file.display_path.clone(),
            line: Some(byte_line_from_starts(self.line_starts, byte_index)),
            severity: Severity::Warning,
            pillar: Pillar::Security,
            confidence: Confidence::Medium,
            symbol: Some(primitive.to_string()),
            remediation: Some(
                "Use modern primitives such as SHA-256/SHA-3 or audited password/key-derivation APIs for security-sensitive uses. If the legacy primitive is required for interoperability with an existing artefact, add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                    .to_string(),
            ),
            metadata: json!({ "primitive": primitive }),
        }));
    }
}

fn normalize_weak_crypto_primitive(primitive: &str) -> &'static str {
    match primitive {
        "md5" | "md_5" | "Md5" => "md5",
        "sha1" | "sha_1" | "Sha1" => "sha1",
        "rc4" | "Rc4" => "rc4",
        "des" | "Des" => "des",
        _ => "unknown",
    }
}

fn process_command_risk_signals(
    literal_preserving_window: &str,
    code_only_window: &str,
) -> Vec<&'static str> {
    let mut signals = Vec::new();

    if static_regex(
        &PROCESS_SHELL_INTERPRETER_REGEX,
        r#"(?i)\b(?:std::process::Command|process::Command|Command)::new\s*\(\s*"(?:sh|bash|dash|zsh|cmd|powershell|pwsh)"\s*\)"#,
    )
    .is_match(literal_preserving_window)
    {
        signals.push("shell-interpreter");
    }
    if static_regex(
        &PROCESS_SHELL_ARG_REGEX,
        r#"\.(?:arg|args)\s*\([^)]*"(?:-c|/C)""#,
    )
    .is_match(literal_preserving_window)
    {
        signals.push("shell-command-argument");
    }
    if static_regex(
        &PROCESS_DYNAMIC_EXECUTABLE_REGEX,
        r"\b(?:std::process::Command|process::Command|Command)::new\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_:]*::)",
    )
    .is_match(code_only_window)
    {
        signals.push("dynamic-executable");
    }
    if static_regex(
        &PROCESS_DYNAMIC_ARGUMENT_REGEX,
        r"\.(?:arg|args)\s*\(\s*(?:&?[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*(?:&?[A-Za-z_][A-Za-z0-9_]*|format!\s*\())",
    )
    .is_match(code_only_window)
    {
        signals.push("dynamic-arguments");
    }
    if code_only_window.contains(".env(") || code_only_window.contains(".envs(") {
        signals.push("custom-environment");
    }
    if code_only_window.contains(".current_dir(") {
        signals.push("custom-working-directory");
    }

    signals
}

/// End one bounded process-builder statement before risk evidence can leak from its neighbour.
fn process_command_window_end(code_only_lines: &[&str], line_index: usize) -> usize {
    let maximum_end = usize::min(line_index + 8, code_only_lines.len());
    let statement_end = code_only_lines[line_index..maximum_end]
        .iter()
        .position(|line| line.contains(';'))
        .map(|offset| line_index + offset + 1)
        .unwrap_or(maximum_end);
    let Some(binding_name) = process_command_binding_name(code_only_lines[line_index]) else {
        return statement_end;
    };

    let mut window_end = statement_end;
    // A named builder can be configured or executed by later statements; stop at the first
    // substantive line that no longer refers to that exact binding.
    for (offset, line) in code_only_lines[statement_end..maximum_end]
        .iter()
        .enumerate()
    {
        if line.trim().is_empty() {
            continue;
        }
        if !line_contains_identifier(line, binding_name) {
            break;
        }
        window_end = statement_end + offset + 1;
    }
    window_end
}

/// Return the local variable assigned from a process constructor on the same line.
fn process_command_binding_name(line: &str) -> Option<&str> {
    static PROCESS_COMMAND_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &PROCESS_COMMAND_BINDING_REGEX,
        r"\blet\s+(?:mut\s+)?(?P<binding>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(?:std::process::Command|process::Command|Command)::new\s*\(",
    )
    .captures(line)?
    .name("binding")
    .map(|binding| binding.as_str())
}

/// Match one Rust identifier without accepting it as a prefix or suffix of another name.
fn line_contains_identifier(line: &str, identifier: &str) -> bool {
    line.match_indices(identifier).any(|(start, _)| {
        let before_is_identifier = line[..start]
            .chars()
            .next_back()
            .is_some_and(|character| character == '_' || character.is_ascii_alphanumeric());
        let end = start + identifier.len();
        let after_is_identifier = line[end..]
            .chars()
            .next()
            .is_some_and(|character| character == '_' || character.is_ascii_alphanumeric());
        !before_is_identifier && !after_is_identifier
    })
}

fn process_command_is_returned_builder(
    source_lines: &[&str],
    line_index: usize,
    command_window: &str,
) -> bool {
    let Some(function_line_index) = (0..=line_index)
        .rev()
        .take(24)
        .find(|index| source_lines[*index].contains("fn "))
    else {
        return false;
    };
    let signature = source_lines[function_line_index..=line_index].join(" ");
    static COMMAND_RETURN_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &COMMAND_RETURN_REGEX,
        r"->\s*(?:(?:std::process::|process::)?Command)\b",
    )
    .is_match(&signature)
        && !process_command_has_execution_sink(command_window)
}

fn process_command_has_execution_sink(raw_window: &str) -> bool {
    static COMMAND_EXECUTION_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &COMMAND_EXECUTION_REGEX,
        r"\.(?:spawn|output|status|wait_with_output)\s*\(",
    )
    .is_match(raw_window)
}

fn push_process_command_finding(
    file: &SourceFile,
    line: usize,
    risk_signals: Vec<&'static str>,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding::new(FindingDescriptor {
        rule_id: "security.process-command".to_string(),
        message: "Process command execution is used; validate command arguments are not user-controlled."
            .to_string(),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Prefer direct executable arguments, avoid shell command strings, and validate any user-controlled inputs. If the command construction is in a test fixture or build script, add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                .to_string(),
        ),
        metadata: json!({ "riskSignals": risk_signals }),
    }));
}

fn process_command_is_fixed_taskkill_cleanup(raw_window: &str) -> bool {
    static TASKKILL_PID_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &TASKKILL_PID_REGEX,
        r#"(?:std::process::Command|process::Command|Command)::new\s*\(\s*"taskkill"\s*\)[\s\S]*\.args\s*\(\s*\[\s*"/PID"\s*,\s*&?[A-Za-z_][A-Za-z0-9_]*\.to_string\(\)\s*,\s*"/F"\s*,\s*"/T"\s*\]"#,
    )
    .is_match(raw_window)
}
