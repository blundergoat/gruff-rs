use super::*;

/// AST-aware migration of `naming.short-variable` and
/// `naming.placeholder-identifier`. Visits every binding `Pat::Ident` in
/// `let`/`for` patterns, function parameters, closure parameters, and
/// destructured patterns (tuple, tuple-struct, struct, slice). The
/// previous regex-based dispatch only saw `let`/`for` simple bindings.
/// Also emits `naming.identifier-shadow` when a same-file free function
/// `X` is shadowed by `let X = X(...)`.
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
        let Some(shadow) = shadow_candidate(local, self.same_file_free_fns) else {
            return;
        };
        self.findings
            .push(identifier_shadow_finding(&self.file.display_path, shadow));
    }

    fn check_name(&mut self, name: &str, line: usize) {
        if self.name_is_placeholder(name) {
            self.findings.push(placeholder_identifier_finding(
                &self.file.display_path,
                name,
                line,
            ));
        }
        if self.name_is_too_short(name) {
            self.findings
                .push(short_variable_finding(&self.file.display_path, name, line));
        }
    }

    fn name_is_placeholder(&self, name: &str) -> bool {
        let extra_placeholders = self
            .config
            .string_array_option("naming.placeholder-identifier", "extraPlaceholders");
        is_placeholder_identifier(name) || extra_placeholders.iter().any(|extra| extra == name)
    }

    fn name_is_too_short(&self, name: &str) -> bool {
        name.len() == 2
            && !name.starts_with('_')
            && !self
                .config
                .accepted_abbreviations
                .contains(&name.to_ascii_lowercase())
    }
}

struct IdentifierShadow {
    binding: String,
    callee: String,
    line: usize,
}

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
        remediation: Some("Use a name that describes the domain role.".to_string()),
        metadata: json!({}),
    })
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
    if should_recurse_walk_pat(pat, callback) {
        return;
    }
    walk_compound_pat(pat, callback);
}

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

fn walk_each<'a, I, F>(pats: I, callback: &mut F)
where
    I: IntoIterator<Item = &'a syn::Pat>,
    F: FnMut(&syn::Ident),
{
    for pat in pats {
        walk_pat_idents(pat, callback);
    }
}
