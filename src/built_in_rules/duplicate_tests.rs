//! Same-file test groups whose bodies differ only in literal values.
//! The default-off detector suggests a labelled table without claiming the cases have identical intent.

use super::*;
use proc_macro2::{TokenStream, TokenTree};
use syn::{spanned::Spanned, visit::Visit};

const RULE: &str = "test-quality.duplicate-test-body";

struct TestMember {
    name: String,
    qualified_name: String,
    line: usize,
    column: usize,
}

struct TestGroups<'a> {
    source: &'a str,
    modules: Vec<String>,
    groups: BTreeMap<Vec<String>, Vec<TestMember>>,
}

impl<'ast> Visit<'ast> for TestGroups<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        self.modules.push(module.ident.to_string());
        syn::visit::visit_item_mod(self, module);
        self.modules.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !has_test_attr(&item.attrs) || has_case_attribute(&item.attrs) {
            return;
        }
        let mut table = TableLoop::default();
        table.visit_block(&item.block);
        if table.0 {
            return;
        }
        let Some(body) = self.source.get(item.block.span().byte_range()) else {
            return;
        };
        let Ok(tokens) = body.parse::<TokenStream>() else {
            return;
        };
        let mut shape = Vec::new();
        normalize_tokens(tokens, &mut shape);
        let name = item.sig.ident.to_string();
        let mut qualified = self.modules.clone();
        qualified.push(name.clone());
        let start = item.sig.ident.span().start();
        self.groups.entry(shape).or_default().push(TestMember {
            name,
            qualified_name: qualified.join("::"),
            line: start.line,
            column: start.column + 1,
        });
    }
}

/// Known case attributes and explicit case loops already express repeated tests as a table.
fn has_case_attribute(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "case" | "test_case" | "test_matrix" | "rstest"
            )
        })
    })
}

#[derive(Default)]
struct TableLoop(bool);

impl<'ast> Visit<'ast> for TableLoop {
    fn visit_expr_for_loop(&mut self, _: &'ast syn::ExprForLoop) {
        self.0 = true;
    }
}

/// Keep lexical kinds and group delimiters so values cannot erase executable differences.
fn normalize_tokens(tokens: TokenStream, shape: &mut Vec<String>) {
    let tokens: Vec<_> = tokens.into_iter().collect();
    let mut index = 0;
    while index < tokens.len() {
        if let Some(end) = doc_attribute_end(&tokens, index) {
            index = end;
            continue;
        }
        match &tokens[index] {
            TokenTree::Group(group) => {
                shape.push(format!("open:{:?}", group.delimiter()));
                normalize_tokens(group.stream(), shape);
                shape.push(format!("close:{:?}", group.delimiter()));
            }
            TokenTree::Literal(literal) => shape.push(literal_kind(&literal.to_string())),
            TokenTree::Ident(ident) if ident == "true" || ident == "false" => {
                shape.push("literal:bool".to_string());
            }
            TokenTree::Ident(ident) => shape.push(format!("ident:{ident}")),
            TokenTree::Punct(punct) => {
                shape.push(format!("punct:{}:{:?}", punct.as_char(), punct.spacing()));
            }
        }
        index += 1;
    }
}

/// Token streams retain rustdoc as attributes; ordinary comments are already absent.
fn doc_attribute_end(tokens: &[TokenTree], start: usize) -> Option<usize> {
    if !matches!(&tokens[start], TokenTree::Punct(punct) if punct.as_char() == '#') {
        return None;
    }
    let mut next = start + 1;
    if matches!(tokens.get(next), Some(TokenTree::Punct(punct)) if punct.as_char() == '!') {
        next += 1;
    }
    match tokens.get(next) {
        Some(TokenTree::Group(group))
            if group.delimiter() == proc_macro2::Delimiter::Bracket
                && matches!(group.stream().into_iter().next(), Some(TokenTree::Ident(ident)) if ident == "doc") =>
        {
            Some(next + 1)
        }
        _ => None,
    }
}

/// Preserve numeric suffixes because typed literals can select different operations.
fn literal_kind(text: &str) -> String {
    match syn::parse_str::<syn::Lit>(text) {
        Ok(syn::Lit::Str(_)) => "literal:string".to_string(),
        Ok(syn::Lit::ByteStr(_)) => "literal:bytes".to_string(),
        Ok(syn::Lit::CStr(_)) => "literal:c-string".to_string(),
        Ok(syn::Lit::Char(_)) => "literal:char".to_string(),
        Ok(syn::Lit::Byte(_)) => "literal:byte".to_string(),
        Ok(syn::Lit::Int(value)) => format!("literal:int:{}", value.suffix()),
        Ok(syn::Lit::Float(value)) => format!("literal:float:{}", value.suffix()),
        // Unknown literal syntax retains its bytes instead of broadening a group.
        _ => format!("literal:verbatim:{text}"),
    }
}

/// Emit each group once at its first test, retaining the native unqualified symbol for identity.
pub(crate) fn analyse_duplicate_tests(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let mut collected = TestGroups {
        source: unit.source,
        modules: Vec::new(),
        groups: BTreeMap::new(),
    };
    collected.visit_file(ast);
    let minimum = if config.is_rule_option_enabled(RULE, "includePairs") {
        2
    } else {
        3
    };
    let mut groups: Vec<_> = collected
        .groups
        .into_values()
        .filter(|group| group.len() >= minimum)
        .collect();
    for group in &mut groups {
        group.sort_by_key(|member| (member.line, member.column));
    }
    groups.sort_by_key(|group| (group[0].line, group[0].column));
    for group in groups {
        let first = &group[0];
        let members: Vec<_> = group
            .iter()
            .map(|member| {
                json!({
                    "name": member.qualified_name, "file": unit.file.display_path,
                    "line": member.line, "column": member.column,
                })
            })
            .collect();
        let locations = group
            .iter()
            .map(|member| {
                format!(
                    "{} ({}:{})",
                    member.qualified_name, unit.file.display_path, member.line
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding::new(FindingDescriptor {
            rule_id: RULE.to_string(),
            message: format!("{} tests share a body shape: {locations}. Consider a table-driven case loop with a descriptive label per row.", group.len()),
            file_path: unit.file.display_path.clone(), line: Some(first.line),
            severity: Severity::Advisory, pillar: Pillar::TestQuality, confidence: Confidence::Medium,
            symbol: Some(first.name.clone()), remediation: None,
            metadata: json!({"members": members, "groupSize": group.len()}),
        }));
    }
}
