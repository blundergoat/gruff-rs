//! FAMILY-CONTRACT.md section 13c for gruff-rs: another tool's `allow` or `expect` attribute, or a zizmor comment,
//! suppresses the finding that makes the same claim where it was written, and every suppression is counted.
//!
//! An attribute counts on the reported item or on an item or inline module enclosing it in the same file, including
//! the file's own `#![allow(...)]`; an attribute inherited from another file, such as a crate root's `#![allow]`, is
//! not read yet, so those findings keep reporting.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Item, Meta, Token};

use crate::analysis::apply_report_exclusions;
use crate::config::Config;
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

/// Apply the configured exclusions and built-in skips, then remove each finding an `allow` or `expect` attribute or a
/// zizmor comment covers and count it in one inline audit row per file and rule, after the built-in rows and numbered
/// on from them.
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
    let (kept, removed) = partition_inline_findings(findings, project_root);
    push_inline_rows(removed, &mut summaries, &mut suppressed);
    (kept, summaries, suppressed)
}

/// Findings an attribute or comment covers, grouped by file and rule; a BTreeMap orders them in UTF-8 byte order.
type InlineFindingsByFileAndRule = BTreeMap<(String, String), Vec<Finding>>;

/// Split findings into the ones the report keeps and the ones an attribute or comment covers.
fn partition_inline_findings(
    findings: Vec<Finding>,
    project_root: &Path,
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
        let file = files
            .entry(finding.file_path.clone())
            .or_insert_with(|| FileSuppressions::read(project_root, &finding.file_path));
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
fn is_mapped_rule(rule_id: &str) -> bool {
    LINT_RULES.iter().any(|(_, rules)| rules.contains(&rule_id))
        || ZIZMOR_AUDITS.iter().any(|(_, rule)| *rule == rule_id)
}

/// One file's lines and the line ranges its `allow` and `expect` attributes cover.
struct FileSuppressions {
    lines: Vec<String>,
    /// First and last line of each attributed item, inline module or the whole file, with the lints it allows.
    scopes: Vec<(usize, usize, Vec<String>)>,
}

impl FileSuppressions {
    /// Read and parse one file; an unreadable file or one that does not parse covers nothing.
    fn read(project_root: &Path, display_path: &str) -> Self {
        let source = std::fs::read_to_string(project_root.join(display_path)).unwrap_or_default();
        let scopes = match display_path.ends_with(".rs") {
            true => syn::parse_file(&source)
                .map(|file| file_scopes(&file))
                .unwrap_or_default(),
            false => Vec::new(),
        };
        Self {
            lines: source.lines().map(str::to_string).collect(),
            scopes,
        }
    }

    /// Report whether an attribute scope holding the finding's line, or a zizmor comment on that line or alone on
    /// the line above, names a check that makes the finding's claim.
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
        Item::Impl(item_impl) => {
            for member in &item_impl.items {
                if let syn::ImplItem::Fn(method) = member {
                    push_scope(method.span(), &method.attrs, scopes);
                }
            }
        }
        Item::Trait(item_trait) => {
            for member in &item_trait.items {
                if let syn::TraitItem::Fn(method) = member {
                    push_scope(method.span(), &method.attrs, scopes);
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

/// Push the span's lines as a scope when the attributes allow any lint.
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
fn is_lint_for_rule(lint: &str, rule_id: &str) -> bool {
    LINT_RULES
        .iter()
        .any(|(name, rules)| *name == lint && rules.contains(&rule_id))
}

/// Report whether a `# zizmor: ignore[...]` on the line names an audit that makes the rule's claim.
fn has_zizmor_audit_for_rule(line: &str, rule_id: &str) -> bool {
    let Some(start) = line.find("zizmor:") else {
        return false;
    };
    let rest = &line[start + "zizmor:".len()..];
    let Some(audits) = rest
        .trim_start()
        .strip_prefix("ignore[")
        .and_then(|tail| tail.split(']').next())
    else {
        return false;
    };
    audits.split(',').any(|audit| {
        ZIZMOR_AUDITS
            .iter()
            .any(|(name, rule)| *name == audit.trim() && *rule == rule_id)
    })
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
