use super::*;
use crate::rules::{RuleDefinition, RuleRegistry};
use serde_json::json;
use std::fmt::Write as _;

const SUGGESTION_LIMIT: usize = 3;
const SUGGESTION_MAX_DISTANCE: usize = 3;

/// Render the deep-view card for a single rule, or surface a
/// suggestions-bearing error when the id does not match.
pub(crate) fn render_rule_detail(
    rule_id: &str,
    registry: &RuleRegistry,
    format: RuleListFormat,
) -> Result<String, String> {
    let Some(definition) = registry.get(rule_id) else {
        let suggestions = suggest_rule_ids(rule_id, registry);
        return Err(format_unknown_rule_error(rule_id, &suggestions));
    };
    Ok(match format {
        RuleListFormat::Json => render_detail_json(definition),
        RuleListFormat::Text => render_detail_text(definition),
    })
}

fn render_detail_text(definition: &RuleDefinition) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Rule: {}", definition.id);
    let _ = writeln!(out, "  Name:                {}", definition.name);
    let _ = writeln!(out, "  Pillar:              {:?}", definition.pillar);
    let _ = writeln!(out, "  Tier:                {}", definition.tier);
    let _ = writeln!(
        out,
        "  Kind:                {}",
        rule_kind_name(definition.kind)
    );
    let _ = writeln!(
        out,
        "  Default severity:    {}",
        severity_word(definition.default_severity)
    );
    let _ = writeln!(
        out,
        "  Confidence:          {}",
        confidence_word(definition.confidence)
    );
    let _ = writeln!(
        out,
        "  Enabled by default:  {}",
        if definition.default_enabled {
            "yes"
        } else {
            "no"
        }
    );
    out.push('\n');

    out.push_str("Description:\n");
    let _ = writeln!(out, "  {}", definition.description);
    out.push('\n');

    render_options_block(&mut out, definition);
    render_escape_hatches_block(&mut out, definition);
    render_false_positive_block(&mut out, definition);
    render_related_block(&mut out, definition);

    out.trim_end_matches('\n').to_string()
}

fn render_options_block(out: &mut String, definition: &RuleDefinition) {
    if definition.options.is_empty() {
        return;
    }
    out.push_str("Default options:\n");
    let name_width = definition
        .options
        .iter()
        .map(|opt| opt.name.len())
        .max()
        .unwrap_or(0);
    for option in definition.options {
        let _ = writeln!(
            out,
            "  {name:<name_width$}  list  {description}",
            name = option.name,
            name_width = name_width,
            description = option.description,
        );
    }
    out.push('\n');
}

fn render_escape_hatches_block(out: &mut String, definition: &RuleDefinition) {
    out.push_str("Escape hatches:\n");
    for option in definition.options {
        let _ = writeln!(out, "  rules.{}.options.{}", definition.id, option.name);
    }
    let _ = writeln!(out, "  rules.{}.enabled", definition.id);
    let _ = writeln!(out, "  paths.ignore");
    out.push('\n');
}

fn render_false_positive_block(out: &mut String, definition: &RuleDefinition) {
    if definition.false_positive_shapes.is_empty() {
        return;
    }
    out.push_str("Common false-positive shapes:\n");
    for shape in definition.false_positive_shapes {
        let _ = writeln!(out, "  - {}", shape.shape);
        let _ = writeln!(out, "    Mitigation: {}", shape.mitigation);
    }
    out.push('\n');
}

fn render_related_block(out: &mut String, definition: &RuleDefinition) {
    if definition.related_rules.is_empty() {
        return;
    }
    out.push_str("Related rules:\n");
    for related in definition.related_rules {
        let _ = writeln!(out, "  - {related}");
    }
    out.push('\n');
}

fn render_detail_json(definition: &RuleDefinition) -> String {
    let escape_hatches: Vec<String> = definition
        .options
        .iter()
        .map(|opt| format!("rules.{}.options.{}", definition.id, opt.name))
        .chain([
            format!("rules.{}.enabled", definition.id),
            "paths.ignore".to_string(),
        ])
        .collect();
    let payload = json!({
        "id": definition.id,
        "name": definition.name,
        "pillar": pillar_label(definition.pillar),
        "tier": definition.tier,
        "kind": rule_kind_name(definition.kind),
        "defaultSeverity": severity_word(definition.default_severity),
        "confidence": confidence_word(definition.confidence),
        "defaultEnabled": definition.default_enabled,
        "description": definition.description,
        "options": definition.options,
        "escapeHatches": escape_hatches,
        "falsePositiveShapes": definition.false_positive_shapes,
        "relatedRules": definition.related_rules,
    });
    serde_json::to_string_pretty(&payload).expect("rule detail serializes")
}

fn format_unknown_rule_error(rule_id: &str, suggestions: &[&'static str]) -> String {
    if suggestions.is_empty() {
        return format!("Unknown rule: {rule_id}.");
    }
    format!(
        "Unknown rule: {rule_id}. Did you mean: {}?",
        suggestions.join(", ")
    )
}

fn suggest_rule_ids(rule_id: &str, registry: &RuleRegistry) -> Vec<&'static str> {
    let mut scored: Vec<(usize, &'static str)> = registry
        .definitions()
        .iter()
        .map(|def| (levenshtein_distance(rule_id, def.id), def.id))
        .filter(|(distance, _)| *distance <= SUGGESTION_MAX_DISTANCE)
        .collect();
    scored.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    scored
        .into_iter()
        .take(SUGGESTION_LIMIT)
        .map(|(_, id)| id)
        .collect()
}

fn levenshtein_distance(left: &str, right: &str) -> usize {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let columns = right_bytes.len() + 1;
    let mut prev = (0..=right_bytes.len()).collect::<Vec<_>>();
    let mut curr = vec![0usize; columns];
    for (row, left_byte) in left_bytes.iter().enumerate() {
        curr[0] = row + 1;
        for (column, right_byte) in right_bytes.iter().enumerate() {
            let cost = if left_byte == right_byte { 0 } else { 1 };
            curr[column + 1] = (prev[column] + cost)
                .min(prev[column + 1] + 1)
                .min(curr[column] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[right_bytes.len()]
}

fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn confidence_word(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}
