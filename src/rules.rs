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
const TODO_DENSITY_THRESHOLD: Option<ThresholdDefinition> = Some(threshold(4.0));
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

const ARCHITECTURE_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "architecture.large-module",
        "Large module",
        Pillar::Design,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::High,
        ARCHITECTURE_LARGE_MODULE_THRESHOLD,
        "Flags modules with more indexed items than the configured threshold.",
    ),
    rule_definition!(
        "architecture.module-fan-out",
        "Module fan-out",
        Pillar::Design,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::High,
        ARCHITECTURE_MODULE_FAN_OUT_THRESHOLD,
        "Flags files that declare many child modules.",
    ),
    rule_definition!(
        "architecture.public-api-surface",
        "Public API surface",
        Pillar::Design,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::High,
        ARCHITECTURE_PUBLIC_API_SURFACE_THRESHOLD,
        "Flags modules with many public exports.",
    ),
];

const COMPLEXITY_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "complexity.cognitive",
        "Cognitive complexity",
        Pillar::Complexity,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        COMPLEXITY_COGNITIVE_THRESHOLD,
        "Flags functions with high cognitive complexity.",
    ),
    rule_definition!(
        "complexity.cyclomatic",
        "Cyclomatic complexity",
        Pillar::Complexity,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        COMPLEXITY_CYCLOMATIC_THRESHOLD,
        "Flags functions with high branch and decision complexity.",
    ),
    rule_definition!(
        "complexity.nesting-depth",
        "Nesting depth",
        Pillar::Complexity,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        COMPLEXITY_NESTING_DEPTH_THRESHOLD,
        "Flags functions with deeply nested control flow.",
    ),
    rule_definition!(
        "complexity.npath",
        "NPath complexity",
        Pillar::Complexity,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::Medium,
        COMPLEXITY_NPATH_THRESHOLD,
        "Flags functions with many approximate execution paths.",
    ),
];

const DEAD_CODE_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "dead-code.unused-private-function",
        "Unused private function",
        Pillar::DeadCode,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Low,
        None,
        "Flags private functions with no same-file call sites.",
    ),
    rule_definition!(
        "dead-code.unused-private-item-candidate",
        "Unused private item candidate",
        Pillar::DeadCode,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags private items whose names are not referenced elsewhere in discovered Rust sources.",
    ),
];

const DEPENDENCY_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "dependency.duplicate-locked-version",
        "Duplicate locked dependency version",
        Pillar::Security,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::High,
        DEPENDENCY_DUPLICATE_LOCKED_VERSION_THRESHOLD,
        "Flags packages locked at more versions than the configured threshold.",
    ),
    rule_definition!(
        "dependency.git-source",
        "Git dependency source",
        Pillar::Security,
        RuleKind::Project,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags dependencies sourced directly from git repositories.",
    ),
    rule_definition!(
        "dependency.missing-package-metadata",
        "Missing package metadata",
        Pillar::Documentation,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags packages missing description or license metadata.",
    ),
    rule_definition!(
        "dependency.path-source",
        "Path dependency source",
        Pillar::Security,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags dependencies sourced from local filesystem paths.",
    ),
    rule_definition!(
        "dependency.wildcard-version",
        "Wildcard dependency version",
        Pillar::Security,
        RuleKind::Project,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags dependency requirements that use wildcard versions.",
    ),
];

const DOCUMENTATION_AND_DESIGN_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "design.god-function",
        "God function",
        Pillar::Design,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags functions that are both long and complex.",
    ),
    rule_definition!(
        "docs.missing-public-doc",
        "Missing public documentation",
        Pillar::Documentation,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags public Rust API items without doc comments.",
    ),
    rule_definition!(
        "docs.missing-readme",
        "Missing README",
        Pillar::Documentation,
        RuleKind::Project,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags projects without a root README file.",
    ),
    rule_definition!(
        "docs.todo-density",
        "TODO/FIXME density",
        Pillar::Documentation,
        RuleKind::Text,
        Severity::Advisory,
        Confidence::High,
        TODO_DENSITY_THRESHOLD,
        "Flags files with dense TODO or FIXME markers.",
    ),
    rule_definition!(
        "docs.stale-todo",
        "Stale TODO marker",
        Pillar::Documentation,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags TODO/FIXME/HACK/XXX comments without an owner, issue reference, or reason.",
    ),
    rule_definition!(
        "docs.commented-out-code",
        "Commented-out code",
        Pillar::Documentation,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags comments whose payload looks like a disabled Rust statement or item.",
    ),
    rule_definition!(
        "docs.weak-safety-rationale",
        "Weak SAFETY rationale",
        Pillar::Documentation,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags unsafe blocks whose nearby SAFETY: rationale is too short or vague.",
    ),
    rule_definition!(
        "docs.missing-errors-section",
        "Missing # Errors rustdoc section",
        Pillar::Documentation,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags externally public functions returning Result without a # Errors rustdoc section.",
    ),
];

const CONCURRENCY_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "concurrency.blocking-call-in-async",
        "Blocking call in async function",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::Medium,
        None,
        "Flags narrow blocking call patterns inside async functions.",
    ),
    rule_definition!(
        "concurrency.lock-across-await",
        "Lock guard across await",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::Medium,
        None,
        "Flags lock guard bindings that appear to live across an await point.",
    ),
    rule_definition!(
        "concurrency.unbounded-channel",
        "Unbounded channel",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags unbounded channel constructors in production code.",
    ),
];

const ERROR_HANDLING_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "error-handling.production-panic",
        "Production panic",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags panic! calls in non-test functions without a local invariant comment.",
    ),
    rule_definition!(
        "error-handling.public-unwrap",
        "Public API unwrap",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags unwrap or expect calls in public non-test functions.",
    ),
    rule_definition!(
        "error-handling.unimplemented-placeholder",
        "Unimplemented placeholder",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags todo! and unimplemented! placeholders in non-test functions.",
    ),
];

const METADATA_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "modernisation.public-field",
        "Public struct field",
        Pillar::Modernisation,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags public struct fields that expose representation.",
    ),
    rule_definition!(
        "metrics.halstead-volume",
        "Halstead-style volume",
        Pillar::Complexity,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        METRICS_HALSTEAD_VOLUME_THRESHOLD,
        "Flags functions whose deterministic token volume exceeds the configured threshold.",
    ),
    rule_definition!(
        "metrics.maintainability-pressure",
        "Maintainability pressure",
        Pillar::Complexity,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        METRICS_MAINTAINABILITY_PRESSURE_THRESHOLD,
        "Flags functions whose maintainability pressure score falls below the configured minimum.",
    ),
];

const NAMING_GENERIC_FUNCTION_OPTIONS: &[OptionDefinition] = &[OptionDefinition {
    name: "extraGenericNames",
    description: "Additional generic function names rejected by naming.generic-function.",
    value_kind: OptionValueKind::StringArray,
}];

const NAMING_BOOLEAN_PREFIX_OPTIONS: &[OptionDefinition] = &[OptionDefinition {
    name: "predicatePrefixes",
    description: "Additional predicate prefixes accepted by naming.boolean-prefix.",
    value_kind: OptionValueKind::StringArray,
}];

const NAMING_PLACEHOLDER_OPTIONS: &[OptionDefinition] = &[OptionDefinition {
    name: "extraPlaceholders",
    description: "Additional placeholder identifiers rejected by naming.placeholder-identifier.",
    value_kind: OptionValueKind::StringArray,
}];

const NAMING_RULES: &[RuleDefinition] = &[
    RuleDefinition {
        id: "naming.generic-function",
        name: "Generic function name",
        pillar: Pillar::Naming,
        tier: "v0.1",
        kind: RuleKind::Rust,
        default_severity: Severity::Advisory,
        confidence: Confidence::High,
        threshold: None,
        options: NAMING_GENERIC_FUNCTION_OPTIONS,
        default_enabled: true,
        description: "Flags function names that are too generic to explain intent.",
    },
    RuleDefinition {
        id: "naming.boolean-prefix",
        name: "Boolean predicate prefix",
        pillar: Pillar::Naming,
        tier: "v0.1",
        kind: RuleKind::Rust,
        default_severity: Severity::Advisory,
        confidence: Confidence::High,
        threshold: None,
        options: NAMING_BOOLEAN_PREFIX_OPTIONS,
        default_enabled: true,
        description: "Flags bool-returning functions whose names do not read like predicates.",
    },
    RuleDefinition {
        id: "naming.placeholder-identifier",
        name: "Placeholder identifier",
        pillar: Pillar::Naming,
        tier: "v0.1",
        kind: RuleKind::Rust,
        default_severity: Severity::Advisory,
        confidence: Confidence::Medium,
        threshold: None,
        options: NAMING_PLACEHOLDER_OPTIONS,
        default_enabled: true,
        description: "Flags placeholder identifiers such as foo, bar, baz, and qux.",
    },
    rule_definition!(
        "naming.short-variable",
        "Short variable name",
        Pillar::Naming,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags very short local variable names outside accepted abbreviations.",
    ),
    rule_definition!(
        "naming.identifier-shadow",
        "Identifier shadow",
        Pillar::Naming,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags `let X = X(...)` bindings that shadow a same-file free function.",
    ),
];

const PERFORMANCE_AND_SECURITY_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "performance.clone-in-loop",
        "Clone in loop",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags clone calls inside loop bodies as allocation hot spot candidates.",
    ),
    rule_definition!(
        "performance.format-in-loop",
        "Format in loop",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::Medium,
        None,
        "Flags format! calls inside loop bodies as allocation hot spot candidates.",
    ),
    rule_definition!(
        "performance.regex-in-loop",
        "Regex construction in loop",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags Regex::new calls inside loop bodies.",
    ),
    rule_definition!(
        "security.process-command",
        "Process command execution",
        Pillar::Security,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags process command construction for manual argument validation.",
    ),
    rule_definition!(
        "security.unsafe-block",
        "Unsafe block",
        Pillar::Security,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags unsafe blocks without a nearby SAFETY rationale.",
    ),
];

const SENSITIVE_DATA_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "sensitive-data.api-key-pattern",
        "API key pattern",
        Pillar::SensitiveData,
        RuleKind::Text,
        Severity::Error,
        Confidence::High,
        None,
        "Flags common API key patterns.",
    ),
    rule_definition!(
        "sensitive-data.aws-access-key",
        "AWS access key",
        Pillar::SensitiveData,
        RuleKind::Text,
        Severity::Error,
        Confidence::High,
        None,
        "Flags AWS access key patterns.",
    ),
    rule_definition!(
        "sensitive-data.database-url-password",
        "Database URL password",
        Pillar::SensitiveData,
        RuleKind::Text,
        Severity::Error,
        Confidence::High,
        None,
        "Flags database URLs that appear to include passwords.",
    ),
    rule_definition!(
        "sensitive-data.hardcoded-env-value",
        "Hardcoded environment-style secret",
        Pillar::SensitiveData,
        RuleKind::Text,
        Severity::Error,
        Confidence::High,
        None,
        "Flags secret-like KEY=value literals committed in source or config.",
    ),
    rule_definition!(
        "sensitive-data.high-entropy-string",
        "High entropy string",
        Pillar::SensitiveData,
        RuleKind::Text,
        Severity::Error,
        Confidence::Medium,
        None,
        "Flags long string literals that look like generated secrets.",
    ),
    rule_definition!(
        "sensitive-data.jwt-token",
        "JWT token",
        Pillar::SensitiveData,
        RuleKind::Text,
        Severity::Error,
        Confidence::High,
        None,
        "Flags JWT-looking token strings.",
    ),
    rule_definition!(
        "sensitive-data.private-key",
        "Private key block",
        Pillar::SensitiveData,
        RuleKind::Text,
        Severity::Error,
        Confidence::High,
        None,
        "Flags private key block markers.",
    ),
];

const SIZE_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "size.file-length",
        "File length",
        Pillar::Size,
        RuleKind::Text,
        Severity::Warning,
        Confidence::High,
        FILE_LENGTH_THRESHOLD,
        "Flags files over the configured line-count threshold.",
    ),
    rule_definition!(
        "size.function-length",
        "Function length",
        Pillar::Size,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        FUNCTION_LENGTH_THRESHOLD,
        "Flags functions over the configured line-count threshold.",
    ),
    rule_definition!(
        "size.parameter-count",
        "Parameter count",
        Pillar::Size,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        PARAMETER_COUNT_THRESHOLD,
        "Flags functions with too many parameters.",
    ),
];

const TEST_QUALITY_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "test-quality.conditional-logic",
        "Conditional logic in test",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags tests that contain conditional logic.",
    ),
    rule_definition!(
        "test-quality.ignored-without-reason",
        "Ignored test without reason",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags ignored tests that do not explain why they are skipped.",
    ),
    rule_definition!(
        "test-quality.long-test",
        "Long test",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        TEST_LONG_THRESHOLD,
        "Flags long test functions that are harder to scan and maintain.",
    ),
    rule_definition!(
        "test-quality.loop-in-test",
        "Loop in test",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags tests that contain loop logic.",
    ),
    rule_definition!(
        "test-quality.no-assertions",
        "No assertions in test",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags tests that do not appear to assert behavior.",
    ),
    rule_definition!(
        "test-quality.sleep-in-test",
        "Sleep in test",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags tests that sleep instead of synchronizing on behavior.",
    ),
    rule_definition!(
        "test-quality.trivial-assertion",
        "Trivial assertion",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags assertions that prove literals or constants instead of behavior.",
    ),
    rule_definition!(
        "test-quality.unwrap-in-test",
        "Unwrap in test",
        Pillar::TestQuality,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags unwrap calls in tests.",
    ),
];

const WASTE_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "waste.unnecessary-clone-candidate",
        "Unnecessary clone candidate",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags clone calls that may be avoidable.",
    ),
    rule_definition!(
        "waste.unreachable-code",
        "Unreachable code",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags statements after terminating statements.",
    ),
    rule_definition!(
        "waste.unwrap-expect",
        "Unwrap or expect",
        Pillar::Waste,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags unwrap and expect calls outside test attributes.",
    ),
];

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
