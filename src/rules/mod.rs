use crate::{Confidence, Pillar, Severity};
use serde::Serialize;
use std::collections::BTreeSet;

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
}

#[derive(Debug)]
/// Sorted registry for built-in rule metadata.
pub(crate) struct RuleRegistry {
    definitions: Vec<RuleDefinition>,
}

impl RuleRegistry {
    /// Build a sorted rule registry and reject duplicate rule ids.
    pub(crate) fn new(mut definitions: Vec<RuleDefinition>) -> Result<Self, String> {
        definitions.sort_by(|left, right| left.id.cmp(right.id));
        let mut seen = BTreeSet::new();
        for definition in &definitions {
            if definition.id.starts_with("custom.") {
                return Err(format!(
                    "built-in rule id `{}` uses reserved custom namespace",
                    definition.id
                ));
            }
            if !seen.insert(definition.id) {
                return Err(format!("duplicate rule id `{}`", definition.id));
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
            // PANIC: duplicate built-in rule ids are programmer errors caught by tests.
            panic!("invalid built-in rule definitions: {error}");
        }
    }
}

const COMPLEXITY_COGNITIVE_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(15.0));
const COMPLEXITY_CYCLOMATIC_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(10.0));
const COMPLEXITY_NESTING_DEPTH_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(4.0));
const COMPLEXITY_NPATH_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(100.0));
const ARCHITECTURE_LARGE_MODULE_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(25.0));
const ARCHITECTURE_MODULE_FAN_OUT_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(8.0));
const ARCHITECTURE_PUBLIC_API_SURFACE_THRESHOLD: Option<ThresholdDefinition> =
    Some(threshold(12.0));
const DEPENDENCY_DUPLICATE_LOCKED_VERSION_THRESHOLD: Option<ThresholdDefinition> =
    Some(threshold(1.0));
const METRICS_HALSTEAD_VOLUME_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(1500.0));
const METRICS_MAINTAINABILITY_PRESSURE_THRESHOLD: Option<ThresholdDefinition> =
    Some(threshold(45.0));
const FILE_LENGTH_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(600.0));
const FUNCTION_LENGTH_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(50.0));
const PARAMETER_COUNT_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(5.0));
const TEST_LONG_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(80.0));

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
        }
    };
}

mod definitions_a;
mod definitions_b;

use definitions_a::{
    ARCHITECTURE_RULES, COMPLEXITY_RULES, CONCURRENCY_RULES, DEAD_CODE_RULES, DEPENDENCY_RULES,
    DOCUMENTATION_AND_DESIGN_RULES, ERROR_HANDLING_RULES,
};
use definitions_b::{
    METADATA_RULES, NAMING_RULES, PERFORMANCE_AND_SECURITY_RULES, SENSITIVE_DATA_RULES, SIZE_RULES,
    TEST_QUALITY_RULES, WASTE_RULES,
};

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
