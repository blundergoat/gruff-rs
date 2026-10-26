//! Same-file test groups whose bodies differ only in eligible literal values (FAMILY-CONTRACT.md section 16).
//! The default-off detector suggests a labelled table without claiming the cases have identical intent.

use super::*;
use proc_macro2::{Delimiter, Spacing, Span, TokenStream, TokenTree};
use syn::{spanned::Spanned, visit::Visit};

const RULE: &str = "test-quality.duplicate-test-body";
/// Section 16 reports groups of three or more and has no pair option in 0.6.0.
const MIN_GROUP_SIZE: usize = 3;
/// Section 16's Rust member minimum: an assertion macro does a whole check in one statement, so a
/// shorter test is one named case whose table form reads no better.
const MIN_STATEMENTS: usize = 4;
/// Keywords that can sit directly before an array literal or slice pattern, so a following bracket is not an index.
const ARRAY_PREFIX_KEYWORDS: &[&str] = &[
    "as", "break", "else", "for", "if", "in", "let", "match", "move", "mut", "return", "while",
    "yield",
];

/// One qualifying test declaration and where a reviewer finds it.
struct TestMember {
    name: String,
    qualified_name: String,
    line: usize,
    column: usize,
}

/// Tests group only when every part matches: the same module declarations, the same ordered non-doc
/// attributes, the same signature apart from the name, and the same normalized body.
/// Enclosing module attributes are fixed by the module declarations, so comparing the test's own
/// attributes compares the whole attribute set section 16 names.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    containers: Vec<String>,
    attributes: Vec<String>,
    signature: String,
    shape: Vec<String>,
}

/// Collect qualifying tests per group key while walking one file's modules in source order.
struct TestGroups<'a> {
    source: &'a str,
    modules: Vec<String>,
    containers: Vec<String>,
    groups: BTreeMap<GroupKey, Vec<TestMember>>,
}

impl<'ast> Visit<'ast> for TestGroups<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        // A module is identified by its declaration, so two same-named modules never share a container.
        let start = module.ident.span().start();
        self.modules.push(module.ident.to_string());
        self.containers
            .push(format!("{}@{}:{}", module.ident, start.line, start.column));
        syn::visit::visit_item_mod(self, module);
        self.modules.pop();
        self.containers.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if let Some(key) = self.group_key(item) {
            let member = self.member(item);
            self.groups.entry(key).or_default().push(member);
        }
    }
}

impl TestGroups<'_> {
    /// Return the grouping key for a qualifying test, or `None` for a declaration section 16 leaves out:
    /// a non-test, a parameterized case, a table loop, or a body below the four-statement minimum.
    fn group_key(&self, item: &syn::ItemFn) -> Option<GroupKey> {
        if !has_test_attr(&item.attrs)
            || has_case_attribute(&item.attrs)
            || counted_statements(&item.block) < MIN_STATEMENTS
        {
            return None;
        }
        let mut table = TableLoop::default();
        table.visit_block(&item.block);
        if table.0 {
            return None;
        }
        let mut shape = Vec::new();
        for statement in &item.block.stmts {
            let tokens = self.tokens(statement.span())?;
            // A declared item is structure a case table cannot carry, so it compares exactly, documentation
            // included; a constant or static is a named value and normalizes like any other statement.
            if matches!(statement, syn::Stmt::Item(nested) if !matches!(nested, syn::Item::Const(_) | syn::Item::Static(_)))
            {
                shape.push(format!("item:{tokens}"));
                continue;
            }
            let tokens: Vec<_> = tokens.into_iter().collect();
            normalize_tokens(&tokens, LiteralContext::default(), &mut shape);
            // An item declared deeper, such as inside a block or closure, also compares exactly.
            let mut nested = NestedItems::default();
            nested.visit_stmt(statement);
            for span in nested.0 {
                shape.push(format!("item:{}", self.tokens(span)?));
            }
        }
        let attributes = item
            .attrs
            .iter()
            .filter(|attr| !attr.path().is_ident("doc"))
            .map(|attr| self.tokens(attr.span()).map(|tokens| tokens.to_string()))
            .collect::<Option<Vec<_>>>()?;
        Some(GroupKey {
            containers: self.containers.clone(),
            attributes,
            signature: self.signature(&item.sig)?,
            shape,
        })
    }

    /// Re-read declaration source as tokens so comments and formatting drop out.
    fn tokens(&self, span: Span) -> Option<TokenStream> {
        self.source.get(span.byte_range())?.parse().ok()
    }

    /// The signature without its name: asyncness, generics, inputs and return type decide how a body runs.
    fn signature(&self, signature: &syn::Signature) -> Option<String> {
        let mut after_fn = false;
        let kept: TokenStream = self
            .tokens(signature.span())?
            .into_iter()
            .filter(|token| {
                let is_name = after_fn;
                after_fn = matches!(token, TokenTree::Ident(ident) if ident == "fn");
                !is_name
            })
            .collect();
        Some(kept.to_string())
    }

    /// Record the native symbol, module-qualified name and declaration position of one member.
    fn member(&self, item: &syn::ItemFn) -> TestMember {
        let name = item.sig.ident.to_string();
        let mut qualified = self.modules.clone();
        qualified.push(name.clone());
        let start = item.sig.ident.span().start();
        TestMember {
            name,
            qualified_name: qualified.join("::"),
            line: start.line,
            column: start.column + 1,
        }
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

/// Any `for` loop anywhere in the body, including inside a closure, counts as a table loop,
/// so that test never joins a group.
#[derive(Default)]
struct TableLoop(bool);

impl<'ast> Visit<'ast> for TableLoop {
    fn visit_expr_for_loop(&mut self, _: &'ast syn::ExprForLoop) {
        self.0 = true;
    }
}

/// Top-level statements toward the member minimum; syn keeps a stray `;` as an empty statement, which does not count.
fn counted_statements(block: &syn::Block) -> usize {
    block
        .stmts
        .iter()
        .filter(|statement| {
            !matches!(statement, syn::Stmt::Expr(syn::Expr::Verbatim(tokens), Some(_)) if tokens.is_empty())
        })
        .count()
}

/// Spans of items declared below a statement's top level, constants and statics excepted.
#[derive(Default)]
struct NestedItems(Vec<Span>);

impl<'ast> Visit<'ast> for NestedItems {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if matches!(item, syn::Item::Const(_) | syn::Item::Static(_)) {
            syn::visit::visit_item(self, item);
        } else {
            // The item's exact tokens already cover anything declared inside it.
            self.0.push(item.span());
        }
    }
}

/// Where a token sits: inside an index, a slice or an attribute, every literal stays exact; inside a
/// macro body, a literal before `=>` is a map key.
#[derive(Clone, Copy, Default)]
struct LiteralContext {
    exact: bool,
    in_macro: bool,
}

/// Keep lexical kinds and group delimiters so values cannot erase executable differences.
fn normalize_tokens(tokens: &[TokenTree], context: LiteralContext, shape: &mut Vec<String>) {
    let mut index = 0;
    while index < tokens.len() {
        if let Some(end) = doc_attribute_end(tokens, index) {
            index = end;
            continue;
        }
        match &tokens[index] {
            TokenTree::Group(group) => {
                let nested = LiteralContext {
                    exact: context.exact
                        || is_index_group(group, tokens, index)
                        || is_attribute_group(group, tokens, index),
                    in_macro: context.in_macro || is_macro_body(tokens, index),
                };
                let inner: Vec<_> = group.stream().into_iter().collect();
                shape.push(format!("open:{:?}", group.delimiter()));
                normalize_tokens(&inner, nested, shape);
                shape.push(format!("close:{:?}", group.delimiter()));
            }
            TokenTree::Literal(literal) => {
                shape.push(literal_shape(literal, tokens, index, context))
            }
            TokenTree::Ident(ident) if !context.exact && (ident == "true" || ident == "false") => {
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

/// A bracket group after an expression is an index or slice, such as `values[0]`, `call()[1..]` or `x?[2]`.
/// After an operator, a delimiter or a keyword such as `in` it is an array literal or pattern instead.
fn is_index_group(group: &proc_macro2::Group, tokens: &[TokenTree], index: usize) -> bool {
    if group.delimiter() != Delimiter::Bracket {
        return false;
    }
    match index
        .checked_sub(1)
        .and_then(|previous| tokens.get(previous))
    {
        Some(TokenTree::Ident(ident)) => {
            !ARRAY_PREFIX_KEYWORDS.contains(&ident.to_string().as_str())
        }
        Some(TokenTree::Group(previous)) => {
            matches!(
                previous.delimiter(),
                Delimiter::Parenthesis | Delimiter::Bracket
            )
        }
        Some(TokenTree::Literal(_)) => true,
        Some(TokenTree::Punct(punct)) => punct.as_char() == '?',
        None => false,
    }
}

/// A bracket group after `#` or `#!` is an attribute, such as `#[cfg(feature = "x")]` on a statement; its
/// arguments select behaviour at compile time, so they are compared exactly. Documentation attributes never
/// reach here: `doc_attribute_end` skips them first.
fn is_attribute_group(group: &proc_macro2::Group, tokens: &[TokenTree], index: usize) -> bool {
    let hash_at = |position: usize| {
        index.checked_sub(position).is_some_and(
            |at| matches!(&tokens[at], TokenTree::Punct(punct) if punct.as_char() == '#'),
        )
    };
    let bang_before = index
        .checked_sub(1)
        .is_some_and(|at| matches!(&tokens[at], TokenTree::Punct(punct) if punct.as_char() == '!'));
    group.delimiter() == Delimiter::Bracket && (hash_at(1) || (bang_before && hash_at(2)))
}

/// A group after `name!` is a macro body, as in `json!({...})` or `hashmap! {...}`.
fn is_macro_body(tokens: &[TokenTree], index: usize) -> bool {
    index >= 2
        && matches!(&tokens[index - 1], TokenTree::Punct(punct) if punct.as_char() == '!')
        && matches!(&tokens[index - 2], TokenTree::Ident(_))
}

/// Normalize an eligible literal to its kind; keep it exact when section 16 retains it.
fn literal_shape(
    literal: &proc_macro2::Literal,
    tokens: &[TokenTree],
    index: usize,
    context: LiteralContext,
) -> String {
    let text = literal.to_string();
    let parsed = syn::parse_str::<syn::Lit>(&text);
    let retained = context.exact
        || is_key_literal(tokens, index, context)
        || follows_field_access(tokens, index)
        || matches!(&parsed, Ok(syn::Lit::Str(value)) if value.value().chars().any(is_contract_whitespace));
    match parsed {
        // Text compares after escapes are decoded, so `"a\tb"` and a raw string holding a tab are equal.
        Ok(syn::Lit::Str(value)) if retained => format!("text:{:?}", value.value()),
        _ if retained => format!("exact:{text}"),
        _ => literal_kind(&text),
    }
}

/// The ASCII whitespace that keeps decoded text exact: U+0009 to U+000D and U+0020.
fn is_contract_whitespace(character: char) -> bool {
    matches!(character, '\t'..='\r' | ' ')
}

/// A literal before a lone `:` is a record or object key (`Pair { 0: a }`, `json!({"id": 1})`);
/// inside a macro body, a literal before `=>` is a map key (`hashmap! {"id" => 1}`).
fn is_key_literal(tokens: &[TokenTree], index: usize, context: LiteralContext) -> bool {
    let next = tokens.get(index + 1);
    let colon = matches!(next, Some(TokenTree::Punct(punct)) if punct.as_char() == ':' && punct.spacing() == Spacing::Alone);
    let arrow = context.in_macro
        && matches!(next, Some(TokenTree::Punct(punct)) if punct.as_char() == '=' && punct.spacing() == Spacing::Joint)
        && matches!(tokens.get(index + 2), Some(TokenTree::Punct(punct)) if punct.as_char() == '>');
    colon || arrow
}

/// A literal after a single `.` is a tuple field name (`pair.0`), not a value; `..` ranges are not.
fn follows_field_access(tokens: &[TokenTree], index: usize) -> bool {
    let dot = |offset: usize| {
        index
            .checked_sub(offset)
            .is_some_and(|position| matches!(&tokens[position], TokenTree::Punct(punct) if punct.as_char() == '.'))
    };
    dot(1) && !dot(2)
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
            if group.delimiter() == Delimiter::Bracket
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

/// Emit each group of three or more once at its first test, retaining the native unqualified symbol for identity.
pub(crate) fn analyse_duplicate_tests(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    findings: &mut Vec<Finding>,
) {
    let mut collected = TestGroups {
        source: unit.source,
        modules: Vec::new(),
        containers: Vec::new(),
        groups: BTreeMap::new(),
    };
    collected.visit_file(ast);
    let mut groups: Vec<_> = collected
        .groups
        .into_values()
        .filter(|group| group.len() >= MIN_GROUP_SIZE)
        .collect();
    for group in &mut groups {
        group.sort_by_key(|member| (member.line, member.column));
    }
    groups.sort_by_key(|group| (group[0].line, group[0].column));
    for group in groups {
        findings.push(duplicate_group_finding(unit.file, &group));
    }
}

/// Build one finding with the complete group so every member is available to the reviewer.
fn duplicate_group_finding(file: &SourceFile, group: &[TestMember]) -> Finding {
    let first = &group[0];
    let members: Vec<_> = group
        .iter()
        .map(|member| {
            json!({
                "name": member.qualified_name, "file": file.display_path,
                "line": member.line, "column": member.column,
            })
        })
        .collect();
    let locations = group
        .iter()
        .map(|member| {
            format!(
                "{} ({}:{})",
                member.qualified_name, file.display_path, member.line
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    Finding::new(FindingDescriptor {
        rule_id: RULE.to_string(),
        message: format!("{} tests share a body shape: {locations}. Consider a table-driven case loop with a descriptive label per row.", group.len()),
        file_path: file.display_path.clone(), line: Some(first.line),
        severity: Severity::Advisory, pillar: Pillar::TestQuality, confidence: Confidence::Medium,
        symbol: Some(first.name.clone()), remediation: None,
        metadata: json!({"members": members, "groupSize": group.len()}),
    })
}
