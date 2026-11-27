//! Apply and audit the local suppressions recognized by `FAMILY-CONTRACT.md` section 13c.
//!
//! A Rust `allow` or `expect` attribute, or a matching zizmor comment, can suppress a finding without a duplicate Gruff setting.
//! Attributes apply to the item and enclosing scopes in the same file. Cross-file attributes leave the finding visible.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Item, Meta, Token};

use crate::analysis::apply_report_exclusions;
use crate::config::{Config, DeepScanBudget};
use crate::report::{Finding, SuppressedFinding, SuppressionSummary};

/// Reason on each inline audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c).
pub(crate) const INLINE_SUPPRESSION_REASON: &str =
    "Another tool's suppression comment names this check, so the finding is suppressed where it was written.";

/// Rules the rustc and clippy lints section 13c names make the same claim as, keyed by lint path.
const LINT_RULES: &[(&str, &[&str])] = &[
    ("clippy::too_many_lines", &["size.function-length"]),
    ("clippy::too_many_arguments", &["size.parameter-count"]),
    ("clippy::cognitive_complexity", &["complexity.cognitive"]),
    (
        "dead_code",
        &[
            "dead-code.unused-private-function",
            "dead-code.unused-private-item-candidate",
        ],
    ),
    (
        "unused",
        &[
            "dead-code.unused-private-function",
            "dead-code.unused-private-item-candidate",
        ],
    ),
    (
        "clippy::disallowed_names",
        &["naming.placeholder-identifier"],
    ),
];

/// The workflow rule each zizmor audit section 13c names makes the same claim as.
const ZIZMOR_AUDITS: &[(&str, &str)] = &[
    ("unpinned-uses", "security.github-actions-unpinned-action"),
    (
        "dangerous-triggers",
        "security.github-actions-pull-request-target",
    ),
];

/// Apply configured exclusions, built-in skips, and inline `allow`/`expect` or zizmor suppressions in audit order.
///
/// `findings` is consumed, `config` supplies exclusion lists and the deep-scan budget, and `project_root` locates files for inline checks.
/// Returns kept findings, suppression summaries with inline rows numbered after built-ins, and each suppressed finding paired with its summary.
pub(crate) fn apply_all_suppressions(
    findings: Vec<Finding>,
    config: &Config,
    project_root: &Path,
) -> (
    Vec<Finding>,
    Vec<SuppressionSummary>,
    Vec<SuppressedFinding>,
) {
    let (findings, mut summaries, mut suppressed) =
        apply_report_exclusions(findings, &config.exclusions, &config.sensitive_exclusions);
    let (kept, removed) =
        partition_inline_findings(findings, project_root, &config.deep_scan_budget);
    push_inline_rows(removed, &mut summaries, &mut suppressed);
    (kept, summaries, suppressed)
}

/// Findings an attribute or comment covers, grouped by file and rule; a BTreeMap orders them in UTF-8 byte order.
type InlineFindingsByFileAndRule = BTreeMap<(String, String), Vec<Finding>>;

/// Split findings into the ones the report keeps and the ones an attribute or comment covers.
///
/// `findings` is consumed, `project_root` locates each file holding a mapped finding (read only once),
/// and `deep_scan_budget` bounds which Rust files are parsed for attribute scopes.
/// Returns the kept findings in their original order and the covered ones grouped by file path and rule id.
fn partition_inline_findings(
    findings: Vec<Finding>,
    project_root: &Path,
    deep_scan_budget: &DeepScanBudget,
) -> (Vec<Finding>, InlineFindingsByFileAndRule) {
    let mut files: HashMap<String, FileSuppressions> = HashMap::new();
    let mut kept = Vec::new();
    let mut removed = InlineFindingsByFileAndRule::new();
    for finding in findings {
        // Only mapped rules can be covered, so a file holding no mapped finding is never read.
        if !is_mapped_rule(&finding.rule_id) {
            kept.push(finding);
            continue;
        }
        let file = files.entry(finding.file_path.clone()).or_insert_with(|| {
            FileSuppressions::read(project_root, &finding.file_path, deep_scan_budget)
        });
        if file.is_finding_suppressed(&finding) {
            removed
                .entry((finding.file_path.clone(), finding.rule_id.clone()))
                .or_default()
                .push(finding);
        } else {
            kept.push(finding);
        }
    }
    (kept, removed)
}

/// Append one inline row per file and rule, and keep each removed finding for SARIF.
///
/// `removed` holds the covered findings by file and rule; each row is appended to `summaries` and its findings to `suppressed`.
/// Row indexes start at the number of existing `summaries` whose source is set and rise in file-then-rule order.
fn push_inline_rows(
    removed: InlineFindingsByFileAndRule,
    summaries: &mut Vec<SuppressionSummary>,
    suppressed: &mut Vec<SuppressedFinding>,
) {
    // Configured rows keep their entry's index; inline rows continue the built-in sequence.
    let first_index = summaries
        .iter()
        .filter(|summary| summary.source.is_some())
        .count();
    for (offset, ((file_path, rule_id), findings)) in removed.into_iter().enumerate() {
        let summary = SuppressionSummary {
            index: first_index + offset,
            rule: rule_id,
            paths: vec![file_path],
            message_contains: None,
            symbol: None,
            reason: INLINE_SUPPRESSION_REASON.to_string(),
            suppressed: findings.len(),
            source: Some("inline"),
            config_key: "inline",
        };
        for finding in findings {
            suppressed.push(SuppressedFinding {
                finding,
                suppression: summary.clone(),
            });
        }
        summaries.push(summary);
    }
}

/// Report whether section 13c maps any lint or zizmor audit to the rule.
///
/// `rule_id` is the finding's rule, looked up in `LINT_RULES` and `ZIZMOR_AUDITS`.
/// Returns true when either table maps something to `rule_id`, otherwise false.
fn is_mapped_rule(rule_id: &str) -> bool {
    LINT_RULES.iter().any(|(_, rules)| rules.contains(&rule_id))
        || ZIZMOR_AUDITS.iter().any(|(_, rule)| *rule == rule_id)
}

/// Find local suppression evidence for findings in one file.
///
/// Text lines let the scan inspect a matching comment. Parsed Rust scopes show which lints an attribute covers.
/// If a scope cannot be read, its finding stays visible.
struct FileSuppressions {
    lines: Vec<String>,
    /// First and last line of each attributed item, inline module or the whole file, with the lints it allows.
    scopes: Vec<(usize, usize, Vec<String>)>,
}

impl FileSuppressions {
    /// Read and parse one file for local suppressions; unreadable, over-budget, or unparseable files cover nothing.
    ///
    /// `display_path` is joined onto `project_root`; only `.rs` files within `deep_scan_budget` are parsed for attribute scopes.
    /// Returns the file's text lines (empty when unreadable or skipped for an over-budget Rust file) and parsed attribute scopes.
    fn read(project_root: &Path, display_path: &str, deep_scan_budget: &DeepScanBudget) -> Self {
        let full_path = project_root.join(display_path);
        let is_rust = Path::new(display_path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));
        // Rust files only check parsed attribute scopes, so an over-budget `.rs` file skips reading its bytes into RAM.
        let max_bytes = u64::try_from(deep_scan_budget.max_bytes).unwrap_or(u64::MAX);
        if is_rust
            && deep_scan_budget.enabled
            && std::fs::metadata(&full_path).is_ok_and(|metadata| metadata.len() > max_bytes)
        {
            return Self {
                lines: Vec::new(),
                scopes: Vec::new(),
            };
        }
        let source = std::fs::read_to_string(&full_path).unwrap_or_default();
        let within_budget = !deep_scan_budget.enabled
            || (source.len() <= deep_scan_budget.max_bytes
                && source.lines().count() <= deep_scan_budget.max_lines);
        let scopes = if is_rust && within_budget {
            syn::parse_file(&source)
                .map(|file| file_scopes(&file))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Self {
            lines: source.lines().map(str::to_string).collect(),
            scopes,
        }
    }

    /// Report whether an attribute scope holding the finding's line, or a zizmor comment on that line or alone on
    /// the line above, names a check that makes the finding's claim.
    ///
    /// `finding` supplies the one-based line and rule id, and a finding with no line or line 0 is never suppressed.
    /// Returns true when an attribute scope, the same line or the comment line above covers `finding`, otherwise false.
    fn is_finding_suppressed(&self, finding: &Finding) -> bool {
        let Some(line) = finding.line.filter(|line| *line > 0) else {
            return false;
        };
        let is_in_allowed_scope = self.scopes.iter().any(|(first, last, lints)| {
            (*first..=*last).contains(&line)
                && lints
                    .iter()
                    .any(|lint| is_lint_for_rule(lint, &finding.rule_id))
        });
        let above = line
            .checked_sub(2)
            .and_then(|index| self.lines.get(index))
            .map(|text| text.trim());
        is_in_allowed_scope
            || self
                .lines
                .get(line - 1)
                .is_some_and(|text| has_zizmor_audit_for_rule(text, &finding.rule_id))
            || above.is_some_and(|text| {
                text.starts_with('#') && has_zizmor_audit_for_rule(text, &finding.rule_id)
            })
    }
}

/// Collect the file's own inner attributes as a whole-file scope, then every attributed item it holds.
///
/// `file` is the parsed source, and its inner `allow` or `expect` lints cover lines 1 through `usize::MAX`.
/// Returns the whole-file scope first when the file allows a lint, then the item scopes in traversal order; empty when nothing allows a lint.
fn file_scopes(file: &syn::File) -> Vec<(usize, usize, Vec<String>)> {
    let mut scopes = Vec::new();
    let file_lints = allowed_lints(&file.attrs);
    if !file_lints.is_empty() {
        scopes.push((1, usize::MAX, file_lints));
    }
    for item in &file.items {
        collect_item_scopes(item, &mut scopes);
    }
    scopes
}

/// Record one item's span when its attributes allow a lint, then descend into impls, traits and inline modules,
/// whose members carry attributes of their own.
///
/// `item` is the item to record, and `scopes` gains the line range of it and of each method or nested item whose attributes allow a lint.
/// Attributes are read on functions, impls, modules, traits, structs, enums, consts, statics and type aliases, and on impl or trait methods.
fn collect_item_scopes(item: &Item, scopes: &mut Vec<(usize, usize, Vec<String>)>) {
    let attrs: &[Attribute] = match item {
        Item::Fn(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::Const(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        _ => &[],
    };
    push_scope(item.span(), attrs, scopes);
    match item {
        Item::Fn(item_fn) => collect_block_item_scopes(&item_fn.block, scopes),
        Item::Impl(item_impl) => {
            for member in &item_impl.items {
                if let syn::ImplItem::Fn(method) = member {
                    push_scope(method.span(), &method.attrs, scopes);
                    collect_block_item_scopes(&method.block, scopes);
                }
            }
        }
        Item::Trait(item_trait) => {
            for member in &item_trait.items {
                if let syn::TraitItem::Fn(method) = member {
                    push_scope(method.span(), &method.attrs, scopes);
                    // A trait method with a default body can hold nested items whose own #[allow] attributes must be found too.
                    if let Some(default_body) = &method.default {
                        collect_block_item_scopes(default_body, scopes);
                    }
                }
            }
        }
        Item::Mod(item_mod) => {
            for nested in item_mod.content.iter().flat_map(|(_, items)| items) {
                collect_item_scopes(nested, scopes);
            }
        }
        _ => {}
    }
}

/// Record attribute scopes on items declared directly inside a function body block.
///
/// `block` is the function body whose statements are scanned for nested `syn::Stmt::Item` declarations.
/// `scopes` receives each attributed nested item's line range in traversal order.
fn collect_block_item_scopes(block: &syn::Block, scopes: &mut Vec<(usize, usize, Vec<String>)>) {
    for stmt in &block.stmts {
        // An item declared inside a function body, such as a nested fn, can carry its own suppression attribute.
        if let syn::Stmt::Item(nested) = stmt {
            collect_item_scopes(nested, scopes);
        }
    }
}

/// Push the span's lines as a scope when the attributes allow any lint.
///
/// `span` gives the first and last line, `attrs` are the item's attributes, and `scopes` gains the entry only when they allow a lint.
fn push_scope(
    span: proc_macro2::Span,
    attrs: &[Attribute],
    scopes: &mut Vec<(usize, usize, Vec<String>)>,
) {
    let lints = allowed_lints(attrs);
    if !lints.is_empty() {
        scopes.push((span.start().line, span.end().line, lints));
    }
}

/// List the lint paths an `allow` or `expect` attribute names, such as `clippy::too_many_lines`; a `reason = "..."`
/// argument is not a lint and is skipped.
///
/// `attrs` are scanned in order, and an `allow` or `expect` whose arguments fail to parse as a comma list contributes nothing.
/// Returns each lint path in attribute order with its segments joined by `::`, or an empty list when none is named.
fn allowed_lints(attrs: &[Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("allow") || attr.path().is_ident("expect"))
        .filter_map(|attr| {
            attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .ok()
        })
        .flatten()
        .filter_map(|meta| match meta {
            Meta::Path(path) => Some(
                path.segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            ),
            _ => None,
        })
        .collect()
}

/// Report whether one allowed lint makes the rule's claim.
///
/// `lint` is an allowed lint path such as `dead_code`, and `rule_id` is the finding's rule; both must match a `LINT_RULES` entry exactly.
/// Returns true when `LINT_RULES` maps `lint` to `rule_id`, otherwise false.
fn is_lint_for_rule(lint: &str, rule_id: &str) -> bool {
    LINT_RULES
        .iter()
        .any(|(name, rules)| *name == lint && rules.contains(&rule_id))
}

/// Report whether a YAML `# zizmor: ignore[...]` comment on the line names an audit that makes the rule's claim.
///
/// `line` is inspected only from its unquoted `#` comment onward, so a quoted value cannot fake a suppression.
/// Every `zizmor: ignore[...]` marker with a closing `]` is checked, so an earlier mention cannot hide a real one.
///
/// `rule_id` is the finding's rule.
/// Returns true when a comma-separated audit inside `ignore[...]` maps to `rule_id` in `ZIZMOR_AUDITS`, otherwise false.
fn has_zizmor_audit_for_rule(line: &str, rule_id: &str) -> bool {
    let Some(mut tail) = yaml_comment_tail(line) else {
        return false;
    };
    // Check every zizmor marker on the line, so an earlier mention in the comment cannot hide a real one.
    while let Some(start) = tail.find("zizmor:") {
        let rest = &tail[start + "zizmor:".len()..];
        let matched = rest
            .trim_start()
            .strip_prefix("ignore[")
            .and_then(|after| after.split_once(']'))
            .is_some_and(|(audits, _)| {
                audits.split(',').any(|audit| {
                    ZIZMOR_AUDITS
                        .iter()
                        .any(|(name, rule)| *name == audit.trim() && *rule == rule_id)
                })
            });
        if matched {
            return true;
        }
        tail = rest;
    }
    false
}

/// Extract the unquoted `# ...` YAML comment tail from one workflow line, or `None` when none starts.
///
/// `line` is scanned left to right while skipping single-quoted and double-quoted YAML spans started at a scalar boundary.
/// A `#` opens a comment only at byte 0 or after ASCII whitespace; returns the slice after `#`, or `None` otherwise.
fn yaml_comment_tail(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let at_boundary = index == 0
            || bytes[index - 1].is_ascii_whitespace()
            || matches!(bytes[index - 1], b':' | b'[' | b',' | b'{');
        // Skip a quoted YAML value whole, so a # inside it is not taken for the start of a comment.
        if at_boundary && matches!(bytes[index], b'\'' | b'"') {
            index = skip_yaml_quoted(bytes, index);
            continue;
        }
        if bytes[index] == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace()) {
            return Some(&line[index + 1..]);
        }
        index += 1;
    }
    None
}

/// Advance past one YAML single- or double-quoted span starting at `start`.
///
/// `bytes` holds the line's UTF-8 bytes and `start` points at the opening `'` or `"` byte.
/// Returns the byte offset immediately after the matching closing quote, or `bytes.len()` when unclosed.
fn skip_yaml_quoted(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        // Inside double quotes, a backslash escapes the next character.
        if quote == b'"' && bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == quote {
            // Inside single quotes, '' is an escaped quote, as in 'it''s'.
            if quote == b'\'' && bytes.get(index + 1) == Some(&b'\'') {
                index += 2;
                continue;
            }
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

#[cfg(test)]
mod line_tests {
    use super::FileSuppressions;
    use crate::report::{Confidence, Finding, FindingDescriptor, Pillar, Severity};

    /// A finding without a valid one-based line cannot be covered by a nearby comment.
    #[test]
    fn zero_line_is_not_suppressed() {
        let source = FileSuppressions {
            lines: vec!["# zizmor: ignore[unpinned-uses]".to_string()],
            scopes: Vec::new(),
        };
        let finding = Finding::new(FindingDescriptor {
            rule_id: "security.github-actions-unpinned-action".to_string(),
            message: "Unpinned action".to_string(),
            file_path: ".github/workflows/ci.yml".to_string(),
            line: Some(0),
            severity: Severity::Warning,
            pillar: Pillar::Security,
            confidence: Confidence::High,
            symbol: None,
            remediation: None,
            metadata: serde_json::Value::Null,
        });
        assert!(!source.is_finding_suppressed(&finding));
    }
}
