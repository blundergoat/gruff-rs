//! Bounded source ownership and event proof for the existing workflow secret sink.
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// Supported block mapping keys; flow owners remain unsupported.
static ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?:([A-Za-z0-9_.-]+)|'([^']+)'|"([^"\\]+)"|(<<)):\s*(.*)$"#)
        .expect("constant guard entry regex")
});
/// Mapping sequence prefix establishes the property column.
static ITEM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^-(?: +|$)").expect("constant item regex"));
/// YAML aliases and anchors invalidate proof instead of being resolved.
static ALIAS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)[&*][A-Za-z0-9_-]+").expect("constant alias regex"));
/// Scalar headers mask shell text before mapping ownership is collected.
static SCALAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[|>](?:[+-]?\d*|\d*[+-]?)$").expect("constant scalar regex"));
/// Quoted spans preserve hashes inside YAML strings.
static QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(?:'(?:[^']|'')*'|"(?:[^"\\]|\\.)*")"#).expect("constant quote regex")
});
/// The bounded complete expression grammar rejects unsupported trailing tokens.
static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\s+|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*|==|!=|&&|\|\||[!()])").expect("constant token regex")
});
/// Context identifiers are valid unknown operands, never evidence of safety.
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
        .expect("constant identifier regex")
});

/// Mapping or sequence entry with inclusive source range and direct children.
#[derive(Default)]
struct GuardNode {
    key: String,
    content: String,
    indent: usize,
    start: usize,
    end: usize,
    is_item: bool,
    children: Vec<usize>,
}

/// Return only source lines inside an own guard false for the covered PR event.
/// Completing ownership first prevents late conditions and sibling scopes from being confused.
///
/// `source` is the whole workflow YAML text.
/// Returns the 1-based line numbers of every job or step whose own `if` is provably false for a `pull_request_target` event.
/// The set is empty when the file has no `jobs` mapping or uses a structure the ownership parser does not support.
pub(super) fn unreachable_secret_lines(source: &str) -> BTreeSet<usize> {
    let mut blocked = BTreeSet::new();
    let Some(nodes) = ownership(source) else {
        return blocked;
    };
    let Some(jobs) = child(&nodes, 0, "jobs") else {
        return blocked;
    };
    if !nodes[jobs].content.is_empty() {
        return blocked;
    }
    for &job in &nodes[jobs].children {
        if nodes[job].is_item || !nodes[job].content.is_empty() {
            continue;
        }
        mark_rejected(&nodes, job, &mut blocked);
        let Some(steps) = child(&nodes, job, "steps") else {
            continue;
        };
        if !nodes[steps].content.is_empty() {
            continue;
        }
        for &step in &nodes[steps].children {
            if nodes[step].is_item {
                mark_rejected(&nodes, step, &mut blocked);
            }
        }
    }
    blocked
}

/// Direct-child lookup cannot borrow an input named if from nested with/env mappings.
///
/// `nodes` is the ownership tree, `parent` the index of the entry to search and `key` the mapping key to match; an out-of-range `parent` panics.
/// Returns the index of the first direct mapping child whose key equals `key`, or `None` when there is none; sequence items never match.
fn child(nodes: &[GuardNode], parent: usize, key: &str) -> Option<usize> {
    nodes[parent]
        .children
        .iter()
        .copied()
        .find(|&index| !nodes[index].is_item && nodes[index].key == key)
}

/// Inclusive ranges include references before an own late condition.
///
/// `nodes` is the ownership tree and `index` is the job or step entry whose direct `if` child is evaluated; an out-of-range `index` panics.
/// When that guard is provably false for `pull_request_target`, every line in the entry's inclusive range is added to `blocked`.
fn mark_rejected(nodes: &[GuardNode], index: usize, blocked: &mut BTreeSet<usize>) {
    let Some(guard) = child(nodes, index, "if") else {
        return;
    };
    if event_truth(&nodes[guard].content, "pull_request_target") == Some(false) {
        blocked.extend(nodes[index].start..=nodes[index].end);
    }
}

/// Strip only unquoted YAML comments; unmatched quotes cannot establish ownership.
///
/// `raw` is one source line of the workflow file.
/// Returns the line trimmed and cut before a `#` that starts a comment, or `None` when a quote character opens no complete quoted span.
fn yaml_text(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            let quoted = QUOTE.find(&raw[index..])?;
            index += quoted.end();
            continue;
        }
        if bytes[index] == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace()) {
            return Some(raw[..index].trim());
        }
        index += 1;
    }
    Some(raw.trim())
}

/// Build complete block ownership; any unsupported structure disables guard proof.
///
/// `source` is the whole workflow YAML text.
/// Returns the entries in source order with the document root at index 0, or `None` when any line uses a structure the parser does not support.
fn ownership(source: &str) -> Option<Vec<GuardNode>> {
    let lines: Vec<_> = source.split('\n').collect();
    let mut nodes = vec![GuardNode {
        start: 1,
        end: lines.len(),
        ..GuardNode::default()
    }];
    let mut stack = vec![0usize];
    let mut scalar_indent = None;
    for (index, raw) in lines.iter().enumerate() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        if scalar_indent.is_some_and(|width| indent > width) {
            continue;
        }
        scalar_indent = None;
        if raw[indent..].starts_with('\t') {
            return None;
        }
        let text = yaml_text(raw)?;
        let prefix = ITEM.find(text).map_or("", |matched| matched.as_str());
        let parent = parent_node(&mut nodes, &mut stack, indent, index, prefix)?;
        let node = GuardNode {
            indent,
            start: index + 1,
            end: lines.len(),
            ..GuardNode::default()
        };
        let appended = append_entry(&mut nodes, parent, text, prefix, node)?;
        if appended != parent {
            stack.push(appended);
        }
        if SCALAR.is_match(&nodes[appended].content) {
            scalar_indent = Some(nodes[appended].indent);
        }
    }
    Some(nodes)
}

/// Close siblings before attaching the next mapping sequence item.
///
/// `nodes` is the tree and `stack` the path of open entries; entries indented at least `indent` spaces are popped and closed before this line.
/// `line_index` is the 0-based index of the current line, and a non-empty `prefix` pushes a new sequence item that owns the line.
/// Returns the owning entry's index, or `None` when the parent has scalar content or would mix mapping keys with sequence items.
fn parent_node(
    nodes: &mut Vec<GuardNode>,
    stack: &mut Vec<usize>,
    indent: usize,
    line_index: usize,
    prefix: &str,
) -> Option<usize> {
    while stack.len() > 1 && nodes[*stack.last()?].indent >= indent {
        nodes[stack.pop()?].end = line_index;
    }
    let parent = *stack.last()?;
    if !nodes[parent].content.is_empty() {
        return None;
    }
    if nodes[parent]
        .children
        .iter()
        .any(|&index| nodes[index].is_item == prefix.is_empty())
    {
        return None;
    }
    if prefix.is_empty() {
        return Some(parent);
    }
    let next = nodes.len();
    let end = nodes[0].end;
    nodes.push(GuardNode {
        indent,
        start: line_index + 1,
        end,
        is_item: true,
        ..GuardNode::default()
    });
    nodes[parent].children.push(next);
    stack.push(next);
    Some(next)
}

/// Duplicate keys, merges and aliases retain warnings rather than overwriting owners.
///
/// `nodes` is the tree, `parent` the owning entry, `text` the comment-free line, `prefix` its sequence-item prefix and `node` the entry to fill.
/// Returns the new entry's index, or `parent` after storing a keyless sequence item's text as its content.
/// `None` means an alias, anchor, merge key, duplicate key, or a line that is neither a key nor a sequence item.
fn append_entry(
    nodes: &mut Vec<GuardNode>,
    parent: usize,
    text: &str,
    prefix: &str,
    mut node: GuardNode,
) -> Option<usize> {
    if ALIAS.is_match(text) {
        return None;
    }
    let Some(entry) = ENTRY.captures(&text[prefix.len()..]) else {
        if prefix.is_empty() {
            return None;
        }
        nodes[parent].content = text[prefix.len()..].to_string();
        return Some(parent);
    };
    node.key = (1..=4)
        .find_map(|index| entry.get(index))?
        .as_str()
        .to_string();
    node.content = entry.get(5)?.as_str().to_string();
    if node.key == "<<" {
        return None;
    }
    if nodes[parent]
        .children
        .iter()
        .any(|&index| nodes[index].key == node.key)
    {
        return None;
    }
    node.indent += prefix.len();
    let next = nodes.len();
    nodes.push(node);
    nodes[parent].children.push(next);
    Some(next)
}

/// Decode only a whole YAML scalar/wrapper; errors fall back to unknown proof.
///
/// `content` is the raw value of an `if` key, plain or quoted, with or without its expression wrapper.
/// Returns the expression's non-whitespace tokens, which may be empty for an empty expression.
/// `None` means decoding failed, a quote or wrapper does not span the whole value, a token is unsupported, or there are more than 128 tokens.
fn guard_tokens(content: &str) -> Option<Vec<String>> {
    let mut expression = content.trim().to_string();
    if expression.starts_with('"') {
        expression = serde_json::from_str::<String>(&expression).ok()?;
    } else if expression.starts_with('\'') {
        let quote = QUOTE.find(&expression)?;
        if quote.end() != expression.len() {
            return None;
        }
        expression = expression[1..expression.len() - 1].replace("''", "'");
    }
    expression = expression.trim().to_string();
    if expression.starts_with(&("$".to_string() + "{{")) {
        if !expression.ends_with("}}") {
            return None;
        }
        expression = expression[3..expression.len() - 2].trim().to_string();
    }
    let mut tokens = Vec::new();
    let mut remaining = expression.as_str();
    while !remaining.is_empty() {
        let token = TOKEN.find(remaining)?.as_str();
        if !token.trim().is_empty() {
            tokens.push(token.to_string());
        }
        remaining = &remaining[token.len()..];
        // The budget bounds both recursive depth and parsing work on untrusted text.
        if tokens.len() > 128 {
            return None;
        }
    }
    Some(tokens)
}

/// An operand's runtime truthiness is unknown until the supported comparison proves it.
enum Operand {
    Event,
    Literal(String),
    Truth(Option<bool>),
}

impl Operand {
    /// Event/string values cannot be mistaken for boolean proof.
    ///
    /// Returns the boolean held by a `Truth` operand, which may itself be unknown, and `None` for an event name or string literal.
    fn truth(self) -> Option<bool> {
        match self {
            Self::Truth(result) => result,
            _ => None,
        }
    }
}

/// Parser cursor evaluates every token before any result is trusted.
struct GuardExpression {
    tokens: Vec<String>,
    position: usize,
    is_valid: bool,
    event: String,
}

impl GuardExpression {
    /// The empty sentinel bounds token reads without panicking on malformed input.
    ///
    /// Returns the token at the cursor without consuming it, or an empty string once every token has been read.
    fn peek(&self) -> &str {
        self.tokens.get(self.position).map_or("", String::as_str)
    }

    /// Negation binds before equality; parentheses carry their own boolean proof.
    ///
    /// Consumes the next operand, marking the expression invalid on a missing `)` or an unsupported token.
    /// Returns `Event` for `github.event_name` and `Literal` for a quoted string.
    /// Any other operand is `Truth`, holding a negation's or parenthesised group's value when proven and unknown for a bare identifier.
    fn unary(&mut self) -> Operand {
        let token = self.peek().to_string();
        self.position += 1;
        if token == "!" {
            return Operand::Truth(self.unary().truth().map(|result| !result));
        }
        if token == "(" {
            let result = self.disjunction();
            if self.peek() != ")" {
                self.is_valid = false;
            }
            self.position += 1;
            return Operand::Truth(result);
        }
        if token.starts_with('\'') {
            return Operand::Literal(token[1..token.len() - 1].replace("''", "'"));
        }
        if token == "github.event_name" {
            return Operand::Event;
        }
        if !IDENTIFIER.is_match(&token) {
            self.is_valid = false;
        }
        Operand::Truth(None)
    }

    /// Only an exact event/string comparison establishes reachability.
    ///
    /// Returns the result when `github.event_name` is compared with a string literal by `==` or `!=`, ignoring ASCII case.
    /// Any other comparison is `None`, and an operand with no operator after it returns that operand's own truth.
    fn comparison(&mut self) -> Option<bool> {
        let left = self.unary();
        let operator = self.peek().to_string();
        if operator != "==" && operator != "!=" {
            return left.truth();
        }
        self.position += 1;
        let right = self.unary();
        let literal = match (left, right) {
            (Operand::Event, Operand::Literal(text)) | (Operand::Literal(text), Operand::Event) => {
                text
            }
            _ => return None,
        };
        let equal = self.event.eq_ignore_ascii_case(&literal);
        Some(if operator == "==" { equal } else { !equal })
    }

    /// False AND unknown can prove unreachability; malformed branches still invalidate it.
    ///
    /// Returns `Some(false)` when any `&&` operand is false, `Some(true)` when all are true, and `None` otherwise.
    fn conjunction(&mut self) -> Option<bool> {
        let mut result = self.comparison();
        while self.peek() == "&&" {
            self.position += 1;
            let right = self.comparison();
            result = match (result, right) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            };
        }
        result
    }

    /// Unknown in an OR branch preserves a possibly reachable secret warning.
    ///
    /// Returns `Some(true)` when any `||` operand is true, `Some(false)` when all are false, and `None` otherwise.
    fn disjunction(&mut self) -> Option<bool> {
        let mut result = self.conjunction();
        while self.peek() == "||" {
            self.position += 1;
            let right = self.conjunction();
            result = match (result, right) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            };
        }
        result
    }
}

/// Complete syntax is required even when partial evaluation already appears false.
///
/// `content` is the raw `if` value and `event` is the event name that `github.event_name` is compared against.
/// Returns the guard's proven value for `event`, or `None` when it depends on unknown context or is empty, malformed or only partly consumed.
fn event_truth(content: &str, event: &str) -> Option<bool> {
    let tokens = guard_tokens(content)?;
    if tokens.is_empty() {
        return None;
    }
    let mut parser = GuardExpression {
        tokens,
        position: 0,
        is_valid: true,
        event: event.to_string(),
    };
    let result = parser.disjunction();
    if parser.is_valid && parser.position == parser.tokens.len() {
        result
    } else {
        None
    }
}
