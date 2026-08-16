//! Built-in rule metadata and the validated catalogue served to CLI users.
//! The registry keeps configuration, analysis, rule detail, and renderers on
//! one deterministic set of IDs whose public relationship links all resolve.

use crate::{Confidence, Pillar, Severity};
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
/// Broad execution context for a built-in rule.
pub(crate) enum RuleKind {
    Project,
    Text,
    Rust,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
/// Numeric threshold exposed by a configurable rule.
pub(crate) struct ThresholdDefinition {
    pub(crate) default: f64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
/// Value shape for a configurable rule option. Recorded so config parsing can
/// validate the JSON shape before the rule reads it. `boolean` is reserved for
/// future use; the current built-in surface only exposes `stringArray`.
#[allow(dead_code)]
pub(crate) enum OptionValueKind {
    Boolean,
    StringArray,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
/// Boolean or string option exposed by a configurable rule.
pub(crate) struct OptionDefinition {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) value_kind: OptionValueKind,
}

/// Documented false-positive pattern for a rule, surfaced by
/// `list-rules <id>` so consumers can recognise the shape before
/// reaching for a config override.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FalsePositiveShape {
    pub(crate) shape: &'static str,
    pub(crate) mitigation: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
/// Public metadata contract for a built-in analyzer rule.
pub(crate) struct RuleDefinition {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) pillar: Pillar,
    pub(crate) tier: &'static str,
    pub(crate) kind: RuleKind,
    pub(crate) default_severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) threshold: Option<ThresholdDefinition>,
    pub(crate) options: &'static [OptionDefinition],
    pub(crate) default_enabled: bool,
    pub(crate) description: &'static str,
    pub(crate) false_positive_shapes: &'static [FalsePositiveShape],
    pub(crate) related_rules: &'static [&'static str],
}

#[derive(Debug)]
/// Sorted registry for built-in rule metadata.
/// Config loading, analysis, and `list-rules` share this catalogue, so its IDs
/// must be unique and every relationship must resolve before a scan begins.
pub(crate) struct RuleRegistry {
    definitions: Vec<RuleDefinition>,
}

impl RuleRegistry {
    /// Build a sorted registry for scan and rule-detail consumers.
    /// Reject IDs or relationships that the resulting catalogue cannot serve.
    pub(crate) fn new(mut definitions: Vec<RuleDefinition>) -> Result<Self, String> {
        definitions.sort_by(|left, right| left.id.cmp(right.id));
        let mut seen = BTreeSet::new();

        // Every catalogue consumer needs stable, unique built-in IDs before lookup begins.
        for definition in &definitions {
            // Config-defined rules own `custom.*`, so a built-in entry there is ambiguous.
            if definition.id.starts_with("custom.") {
                return Err(format!(
                    "built-in rule id `{}` uses reserved custom namespace",
                    definition.id
                ));
            }

            // Duplicate IDs would make config and rule-detail lookup order-dependent.
            if !seen.insert(definition.id) {
                return Err(format!("duplicate rule id `{}`", definition.id));
            }
        }

        // Rule-detail links must resolve inside the complete catalogue shown to the user.
        for definition in &definitions {
            // Each declared relationship is validated independently for precise diagnostics.
            for &related_rule in definition.related_rules {
                // A missing target would send the user to a rule that the CLI cannot explain.
                if !seen.contains(related_rule) {
                    return Err(format!(
                        "rule `{}` references unknown related rule `{related_rule}`",
                        definition.id
                    ));
                }
            }
        }

        Ok(Self { definitions })
    }

    /// Return all rule definitions in deterministic rule-id order.
    pub(crate) fn definitions(&self) -> &[RuleDefinition] {
        &self.definitions
    }

    /// Look up a rule definition by stable rule id.
    pub(crate) fn get(&self, rule_id: &str) -> Option<&RuleDefinition> {
        self.definitions
            .binary_search_by(|definition| definition.id.cmp(rule_id))
            .ok()
            .map(|index| &self.definitions[index])
    }

    /// Return whether the registry contains a rule id.
    pub(crate) fn contains(&self, rule_id: &str) -> bool {
        self.get(rule_id).is_some()
    }

    /// Look up the declared value kind for a rule's option, if any.
    pub(crate) fn option_value_kind(&self, rule_id: &str, option: &str) -> Option<OptionValueKind> {
        self.get(rule_id).and_then(|definition| {
            definition
                .options
                .iter()
                .find(|item| item.name == option)
                .map(|item| item.value_kind)
        })
    }
}

/// Build the static registry of rules shipped with this binary.
pub(crate) fn builtin_registry() -> RuleRegistry {
    match RuleRegistry::new(builtin_definitions()) {
        Ok(registry) => registry,
        Err(error) => {
            // PANIC: catalogue defects are programmer errors, such as linking to a retired ID.
            panic!("invalid built-in rule definitions: {error}");
        }
    }
}

/// Process-lifetime cache of [`builtin_registry`] for hot-path lookups such as
/// `Config::is_rule_enabled`, which checks default enablement once per rule on
/// every `--no-config` scan. Building the registry sorts and validates every
/// definition, so rebuilding it per call is wasted work; callers that need an
/// owned registry keep using [`builtin_registry`].
pub(crate) fn builtin_registry_cached() -> &'static RuleRegistry {
    static REGISTRY: OnceLock<RuleRegistry> = OnceLock::new();
    REGISTRY.get_or_init(builtin_registry)
}

/// Catalogue default threshold for a configurable rule. Rule code reads this
/// instead of repeating the number, because `list-rules` and the config that
/// `init` generates render the catalogue: a second literal can disagree with the
/// shipped default and silently change what a scan reports.
pub(crate) fn builtin_threshold(rule_id: &str) -> f64 {
    match builtin_registry_cached()
        .get(rule_id)
        .and_then(|definition| definition.threshold)
    {
        Some(threshold) => threshold.default,
        // PANIC: a rule that reads a threshold but declares none is a catalogue
        // defect, the same programmer-error class as an unresolvable related ID.
        None => panic!("built-in rule `{rule_id}` reads a threshold it does not declare"),
    }
}

/// Catalogue default severity for a configurable rule, kept single-sourced for
/// the same reason as [`builtin_threshold`].
pub(crate) fn builtin_severity(rule_id: &str) -> Severity {
    match builtin_registry_cached().get(rule_id) {
        Some(definition) => definition.default_severity,
        // PANIC: rule code naming an ID the catalogue does not ship is a defect.
        None => panic!("built-in rule `{rule_id}` is missing from the catalogue"),
    }
}

const COMPLEXITY_COGNITIVE_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(15.0));
const COMPLEXITY_CYCLOMATIC_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(10.0));
const COMPLEXITY_NESTING_DEPTH_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(4.0));
const ARCHITECTURE_LARGE_MODULE_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(25.0));
const ARCHITECTURE_MODULE_FAN_OUT_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(8.0));
const ARCHITECTURE_PUBLIC_API_SURFACE_THRESHOLD: Option<ThresholdDefinition> =
    Some(threshold(12.0));
const DEPENDENCY_DUPLICATE_LOCKED_VERSION_THRESHOLD: Option<ThresholdDefinition> =
    Some(threshold(2.0));
const FILE_LENGTH_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(1000.0));
const FUNCTION_LENGTH_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(50.0));
const PARAMETER_COUNT_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(7.0));
const TEST_LONG_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(120.0));

macro_rules! rule_definition {
    (
        $id:literal,
        $name:literal,
        $pillar:expr,
        $kind:expr,
        $default_severity:expr,
        $confidence:expr,
        $threshold:expr,
        $description:literal $(,)?
    ) => {
        rule_definition!(
            $id,
            $name,
            $pillar,
            $kind,
            $default_severity,
            $confidence,
            $threshold,
            $description,
            false_positives: &[],
            related: &[]
        )
    };
    (
        $id:literal,
        $name:literal,
        $pillar:expr,
        $kind:expr,
        $default_severity:expr,
        $confidence:expr,
        $threshold:expr,
        $description:literal,
        false_positives: $false_positives:expr,
        related: $related:expr $(,)?
    ) => {
        RuleDefinition {
            id: $id,
            name: $name,
            pillar: $pillar,
            tier: "v0.1",
            kind: $kind,
            default_severity: $default_severity,
            confidence: $confidence,
            threshold: $threshold,
            options: &[],
            default_enabled: true,
            description: $description,
            false_positive_shapes: $false_positives,
            related_rules: $related,
        }
    };
}

mod idiom_security_size_test_definitions;
mod structure_docs_reliability_definitions;
mod waste_definitions;

use idiom_security_size_test_definitions::{
    METADATA_RULES, NAMING_RULES, PERFORMANCE_AND_SECURITY_RULES, SENSITIVE_DATA_RULES, SIZE_RULES,
    TEST_QUALITY_RULES,
};
use structure_docs_reliability_definitions::{
    ARCHITECTURE_RULES, COMPLEXITY_RULES, CONCURRENCY_RULES, DEAD_CODE_RULES, DEPENDENCY_RULES,
    DOCUMENTATION_AND_DESIGN_RULES, ERROR_HANDLING_RULES,
};
use waste_definitions::WASTE_RULES;

fn builtin_definitions() -> Vec<RuleDefinition> {
    [
        ARCHITECTURE_RULES,
        COMPLEXITY_RULES,
        DEAD_CODE_RULES,
        DEPENDENCY_RULES,
        DOCUMENTATION_AND_DESIGN_RULES,
        CONCURRENCY_RULES,
        ERROR_HANDLING_RULES,
        METADATA_RULES,
        NAMING_RULES,
        PERFORMANCE_AND_SECURITY_RULES,
        SENSITIVE_DATA_RULES,
        SIZE_RULES,
        TEST_QUALITY_RULES,
        WASTE_RULES,
    ]
    .into_iter()
    .flat_map(|definitions| definitions.iter().copied())
    .collect()
}

const fn threshold(default: f64) -> ThresholdDefinition {
    ThresholdDefinition { default }
}
