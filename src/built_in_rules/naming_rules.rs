use super::*;

/// Analyze durable local and parameter names for the built-in naming rules.
///
/// Every supported binding pattern is checked for placeholder names. Short-variable findings stay
/// limited to durable `let` bindings and function parameters because loop and closure context
/// usually supplies enough meaning. The same pass reports same-file function shadowing.
///
/// `file` supplies the display path each finding carries, and `ast` is the parsed file whose bindings are walked.
/// `config` supplies extra placeholder names and accepted abbreviations; every naming finding is appended to `findings`.
pub(crate) fn analyse_naming_patterns(
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
///
/// `ast` is the parsed file; only inline `mod` bodies are searched, so an out-of-line `mod name;` contributes no names.
fn collect_same_file_free_fns(ast: &syn::File) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_free_fns_in_items(&ast.items, &mut names);
    names
}

/// Insert the name of every free `fn` in `items` into `names`, recursing into inline `mod` bodies.
///
/// Other item kinds, including `impl` blocks and out-of-line `mod` declarations, add nothing to `names`.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingLifetime {
    Durable,
    ShortLived,
}

impl NamingPatternVisitor<'_> {
    /// Check the identifiers that `walk_pat_idents` reaches in `pat` against the placeholder and short-variable naming rules.
    ///
    /// `binding_lifetime` decides whether the short-variable rule applies; findings are pushed onto the visitor's list.
    fn visit_pat_idents(&mut self, pat: &syn::Pat, binding_lifetime: BindingLifetime) {
        walk_pat_idents(pat, &mut |ident| {
            let name = ident.to_string();
            let line = line_from_span(ident.span().start());
            self.check_name(&name, line, binding_lifetime);
        });
    }

    /// Report a `let` binding whose name matches its initialiser's last callee segment and a same-file free function name.
    ///
    /// `local` is the visited `let` statement; a match pushes one `naming.identifier-shadow` finding.
    fn check_identifier_shadow(&mut self, local: &syn::Local) {
        let Some(shadow) = shadow_candidate(local, self.same_file_free_fns) else {
            return;
        };
        self.findings
            .push(identifier_shadow_finding(&self.file.display_path, shadow));
    }

    /// Push the placeholder and short-variable findings that one bound identifier earns.
    ///
    /// `name` is the identifier text and `line` is the source line recorded on each finding.
    /// The short-variable check runs only when `binding_lifetime` is `BindingLifetime::Durable`.
    fn check_name(&mut self, name: &str, line: usize, binding_lifetime: BindingLifetime) {
        if self.name_is_placeholder(name) {
            self.findings.push(placeholder_identifier_finding(
                &self.file.display_path,
                name,
                line,
            ));
        }
        if binding_lifetime == BindingLifetime::Durable && self.name_is_too_short(name) {
            self.findings
                .push(short_variable_finding(&self.file.display_path, name, line));
        }
    }

    /// Decide whether `name` is a placeholder identifier, either built in or configured as an extra.
    ///
    /// Extra names come from the `extraPlaceholders` option of `naming.placeholder-identifier` and must match exactly.
    /// Returns true when `name` is a built-in or configured placeholder, and false otherwise.
    fn name_is_placeholder(&self, name: &str) -> bool {
        let extra_placeholders = self
            .config
            .string_array_option("naming.placeholder-identifier", "extraPlaceholders");
        is_placeholder_identifier(name) || extra_placeholders.iter().any(|extra| extra == name)
    }

    /// Decide whether `name` is a two-byte identifier that the short-variable rule should report.
    ///
    /// Only names exactly two bytes long count; a leading underscore, a plain two-letter English word (`at`, `by`, `on`, `to`, `up`), an accepted abbreviation, or an AWS-path abbreviation exempts one.
    /// Comparisons run against the lowercased `name`.
    /// Returns true when `name` should be reported as too short, and false otherwise.
    fn name_is_too_short(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        name.len() == 2
            && !name.starts_with('_')
            && !PLAIN_TWO_LETTER_WORDS.contains(&lower.as_str())
            && !self.config.accepted_abbreviations.contains(&lower)
            && !self.file_context_has_accepted_abbreviation(&lower)
    }

    /// Accept an AWS service abbreviation when the file's display path marks it as AWS code.
    ///
    /// The display path, with backslashes turned into slashes, must contain `/aws/` or end with `/aws.rs`.
    /// `name` must already be lowercase and is looked up in the fixed `AWS_CONTEXT_ABBREVIATIONS` list.
    /// Returns true only for a listed `name` in such a file, and false for any other name or path.
    fn file_context_has_accepted_abbreviation(&self, name: &str) -> bool {
        let normalized = self.file.display_path.replace('\\', "/");
        if normalized.contains("/aws/") || normalized.ends_with("/aws.rs") {
            return AWS_CONTEXT_ABBREVIATIONS.contains(&name);
        }
        false
    }
}

const PLAIN_TWO_LETTER_WORDS: &[&str] = &["at", "by", "on", "to", "up"];

const AWS_CONTEXT_ABBREVIATIONS: &[&str] = &[
    "ca", "ce", "cn", "cw", "dp", "dt", "gb", "gw", "lb", "pm", "py", "sa", "sg", "sn", "td", "tg",
    "tp", "ym",
];

struct IdentifierShadow {
    binding: String,
    callee: String,
    line: usize,
}

/// Find a `let` binding whose name equals its initialiser's last callee segment and a collected same-file free function name.
///
/// `local` is the visited `let` statement and `same_file_free_fns` holds the file's free function names.
/// The pattern must be an identifier pattern, even with `ref`, `mut` or `@`, and the initialiser a path call whose last segment equals it.
/// Returns the binding, callee and binding line on a match, or None when any condition or the same-file lookup fails.
fn shadow_candidate(
    local: &syn::Local,
    same_file_free_fns: &BTreeSet<String>,
) -> Option<IdentifierShadow> {
    let syn::Pat::Ident(pat_ident) = &local.pat else {
        return None;
    };
    let init = local.init.as_ref()?;
    let syn::Expr::Call(call) = init.expr.as_ref() else {
        return None;
    };
    let syn::Expr::Path(path_expr) = call.func.as_ref() else {
        return None;
    };
    let last = path_expr.path.segments.last()?;
    let binding = pat_ident.ident.to_string();
    let callee = last.ident.to_string();
    if binding != callee || !same_file_free_fns.contains(&callee) {
        return None;
    }
    Some(IdentifierShadow {
        binding,
        callee,
        line: line_from_span(pat_ident.ident.span().start()),
    })
}

/// Build the advisory `naming.identifier-shadow` finding for one local binding that shadows a same-file function.
///
/// `file_path` is the reported display path, and `shadow` supplies the binding name, the shadowed function and the line.
/// Returns a high-confidence finding whose symbol is the binding and whose metadata names the function under `shadows`.
fn identifier_shadow_finding(file_path: &str, shadow: IdentifierShadow) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "naming.identifier-shadow".to_string(),
        message: format!(
            "Local binding `{}` shadows same-file function `{}`.",
            shadow.binding, shadow.callee
        ),
        file_path: file_path.to_string(),
        line: Some(shadow.line),
        severity: Severity::Advisory,
        pillar: Pillar::Naming,
        confidence: Confidence::High,
        symbol: Some(shadow.binding),
        remediation: Some(
            "Rename the local so it does not collide with the function it calls.".to_string(),
        ),
        metadata: json!({ "shadows": shadow.callee }),
    })
}

/// Build the advisory `naming.placeholder-identifier` finding for one placeholder-named variable.
///
/// `file_path` is the reported display path, `name` the flagged identifier and `line` the source line it is bound on.
/// Returns a medium-confidence finding whose symbol is `name` and whose remediation asks for a domain name.
fn placeholder_identifier_finding(file_path: &str, name: &str, line: usize) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "naming.placeholder-identifier".to_string(),
        message: format!("Variable `{name}` uses a placeholder name instead of domain language."),
        file_path: file_path.to_string(),
        line: Some(line),
        severity: Severity::Advisory,
        pillar: Pillar::Naming,
        confidence: Confidence::Medium,
        symbol: Some(name.to_string()),
        remediation: Some("Use a name that describes the domain role.".to_string()),
        metadata: json!({}),
    })
}

/// Build the advisory `naming.short-variable` finding for one identifier judged too short.
///
/// `file_path` is the reported display path, `name` the flagged identifier and `line` the source line it is bound on.
/// Returns a medium-confidence finding whose remediation points to `allowlists.acceptedAbbreviations` in `.gruff-rs.yaml`.
fn short_variable_finding(file_path: &str, name: &str, line: usize) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "naming.short-variable".to_string(),
        message: format!("Variable `{name}` is too short to explain intent."),
        file_path: file_path.to_string(),
        line: Some(line),
        severity: Severity::Advisory,
        pillar: Pillar::Naming,
        confidence: Confidence::Medium,
        symbol: Some(name.to_string()),
        remediation: Some(
            "Use a name that describes the domain role. If this is a domain abbreviation (e.g. `aws`, `kms`), append it to `allowlists.acceptedAbbreviations` in `.gruff-rs.yaml`."
                .to_string(),
        ),
        metadata: json!({}),
    })
}

impl<'ast> Visit<'ast> for NamingPatternVisitor<'_> {
    /// Check the `let` bindings that `walk_pat_idents` reaches as durable, then test the statement for function shadowing.
    ///
    /// `local` is the visited statement; the walk then continues into its pattern and initialiser.
    fn visit_local(&mut self, local: &'ast syn::Local) {
        self.visit_pat_idents(&local.pat, BindingLifetime::Durable);
        self.check_identifier_shadow(local);
        syn::visit::visit_local(self, local);
    }

    /// Check the names `walk_pat_idents` reaches in a typed function parameter as durable, skipping a conventional `cx` context parameter.
    ///
    /// `arg` is the visited parameter; a `self` receiver is not checked, and the walk then continues into `arg`.
    fn visit_fn_arg(&mut self, arg: &'ast syn::FnArg) {
        // Rust poll and lint APIs conventionally pair `cx` with a typed context parameter.
        if let syn::FnArg::Typed(pat_type) = arg {
            if !is_conventional_context_parameter(pat_type) {
                self.visit_pat_idents(&pat_type.pat, BindingLifetime::Durable);
            }
        }
        syn::visit::visit_fn_arg(self, arg);
    }

    /// Check the names `walk_pat_idents` reaches in a `for` loop pattern as short-lived, so only the placeholder rule applies to them.
    ///
    /// `expression` is the visited loop; the walk then continues into its pattern, iterable and body.
    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.visit_pat_idents(&expression.pat, BindingLifetime::ShortLived);
        syn::visit::visit_expr_for_loop(self, expression);
    }

    /// Check the names `walk_pat_idents` reaches in each closure parameter as short-lived, so only the placeholder rule applies to them.
    ///
    /// `expression` is the visited closure; the walk then continues into its parameters and body.
    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        for input in &expression.inputs {
            self.visit_pat_idents(input, BindingLifetime::ShortLived);
        }
        syn::visit::visit_expr_closure(self, expression);
    }
}

/// Recognize the ecosystem-standard `cx` name only when its declared type is a context.
///
/// `parameter` must have the plain identifier `cx` as its pattern and a type that `is_context_type` accepts.
/// Returns true only for that pairing, so the caller skips the parameter's naming checks, and false for any other parameter.
fn is_conventional_context_parameter(parameter: &syn::PatType) -> bool {
    let syn::Pat::Ident(identifier) = parameter.pat.as_ref() else {
        return false;
    };
    identifier.ident == "cx" && is_context_type(&parameter.ty)
}

/// Return whether a parameter type ends in `Context`, including references and grouping.
///
/// `parameter_type` is unwrapped through references, macro groups and parentheses until a path type's last segment can be tested.
/// Returns true when that segment's name ends in `Context`, and false for every other type shape such as tuples or slices.
fn is_context_type(parameter_type: &syn::Type) -> bool {
    match parameter_type {
        syn::Type::Reference(reference) => is_context_type(&reference.elem),
        syn::Type::Group(group) => is_context_type(&group.elem),
        syn::Type::Paren(parenthesized) => is_context_type(&parenthesized.elem),
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.to_string().ends_with("Context")),
        _ => false,
    }
}

/// Recursively walks a `syn::Pat`, invoking `callback` for every leaf
/// `Pat::Ident`. Handles tuples, tuple-structs, struct fields, slices,
/// references, or-patterns, and typed patterns. Unhandled variants
/// (`Pat::Lit`, `Pat::Wild`, etc.) carry no bindings to inspect.
fn walk_pat_idents<F: FnMut(&syn::Ident)>(pat: &syn::Pat, callback: &mut F) {
    if should_recurse_walk_pat(pat, callback) {
        return;
    }
    walk_compound_pat(pat, callback);
}

/// Handle the identifier, typed and reference pattern shapes for `walk_pat_idents`, reporting whether `pat` was one of them.
///
/// An identifier is passed to `callback` as a `syn::Ident`; a typed or reference pattern has its inner pattern walked with the same `callback`.
/// Returns true when `pat` was handled here, so the caller skips the compound walk, and false for every other pattern shape.
fn should_recurse_walk_pat<F: FnMut(&syn::Ident)>(pat: &syn::Pat, callback: &mut F) -> bool {
    match pat {
        syn::Pat::Ident(pat_ident) => {
            callback(&pat_ident.ident);
            true
        }
        syn::Pat::Type(pat_type) => {
            walk_pat_idents(&pat_type.pat, callback);
            true
        }
        syn::Pat::Reference(pat_ref) => {
            walk_pat_idents(&pat_ref.pat, callback);
            true
        }
        _ => false,
    }
}

/// Walk the immediate sub-patterns of a supported compound `pat` through `walk_pat_idents`, passing each `syn::Ident` reached to `callback`.
///
/// Tuple, tuple-struct, slice, or-pattern and struct field patterns are handled; any other shape is ignored.
fn walk_compound_pat<F: FnMut(&syn::Ident)>(pat: &syn::Pat, callback: &mut F) {
    match pat {
        syn::Pat::Tuple(pat_tuple) => walk_each(pat_tuple.elems.iter(), callback),
        syn::Pat::TupleStruct(pat_ts) => walk_each(pat_ts.elems.iter(), callback),
        syn::Pat::Slice(pat_slice) => walk_each(pat_slice.elems.iter(), callback),
        syn::Pat::Or(pat_or) => walk_each(pat_or.cases.iter(), callback),
        syn::Pat::Struct(pat_struct) => walk_each(
            pat_struct.fields.iter().map(|field| field.pat.as_ref()),
            callback,
        ),
        _ => {}
    }
}

/// Run `walk_pat_idents` over each pattern in `pats`, sharing one `callback` that receives every `syn::Ident` the walker reaches.
fn walk_each<'a, I, F>(pats: I, callback: &mut F)
where
    I: IntoIterator<Item = &'a syn::Pat>,
    F: FnMut(&syn::Ident),
{
    for pat in pats {
        walk_pat_idents(pat, callback);
    }
}
