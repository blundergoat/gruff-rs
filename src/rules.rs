use crate::{Confidence, Pillar, Severity};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RuleKind {
    Project,
    Text,
    Rust,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ThresholdDefinition {
    pub(crate) name: &'static str,
    pub(crate) default: f64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OptionDefinition {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuleDefinition {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) pillar: Pillar,
    pub(crate) tier: &'static str,
    pub(crate) kind: RuleKind,
    pub(crate) default_severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) thresholds: &'static [ThresholdDefinition],
    pub(crate) options: &'static [OptionDefinition],
    pub(crate) default_enabled: bool,
    pub(crate) description: &'static str,
}

#[derive(Debug)]
pub(crate) struct RuleRegistry {
    definitions: Vec<RuleDefinition>,
}

impl RuleRegistry {
    pub(crate) fn new(mut definitions: Vec<RuleDefinition>) -> Result<Self, String> {
        definitions.sort_by(|left, right| left.id.cmp(right.id));
        let mut seen = BTreeSet::new();
        for definition in &definitions {
            if !seen.insert(definition.id) {
                return Err(format!("duplicate rule id `{}`", definition.id));
            }
        }
        Ok(Self { definitions })
    }

    pub(crate) fn definitions(&self) -> &[RuleDefinition] {
        &self.definitions
    }

    pub(crate) fn get(&self, rule_id: &str) -> Option<&RuleDefinition> {
        self.definitions
            .binary_search_by(|definition| definition.id.cmp(rule_id))
            .ok()
            .map(|index| &self.definitions[index])
    }

    pub(crate) fn contains(&self, rule_id: &str) -> bool {
        self.get(rule_id).is_some()
    }

    pub(crate) fn supports_threshold(&self, rule_id: &str, threshold: &str) -> bool {
        self.get(rule_id).is_some_and(|definition| {
            definition
                .thresholds
                .iter()
                .any(|item| item.name == threshold)
        })
    }

    pub(crate) fn supports_option(&self, rule_id: &str, option: &str) -> bool {
        self.get(rule_id)
            .is_some_and(|definition| definition.options.iter().any(|item| item.name == option))
    }
}

pub(crate) fn builtin_registry() -> RuleRegistry {
    RuleRegistry::new(builtin_definitions()).expect("built-in rule definitions are unique")
}

const COMPLEXITY_COGNITIVE_THRESHOLDS: &[ThresholdDefinition] = &[threshold("warn", 15.0)];
const COMPLEXITY_CYCLOMATIC_THRESHOLDS: &[ThresholdDefinition] =
    &[threshold("warn", 10.0), threshold("error", 20.0)];
const COMPLEXITY_NESTING_DEPTH_THRESHOLDS: &[ThresholdDefinition] =
    &[threshold("warn", 4.0), threshold("error", 6.0)];
const COMPLEXITY_NPATH_THRESHOLDS: &[ThresholdDefinition] =
    &[threshold("warn", 32.0), threshold("error", 128.0)];
const ARCHITECTURE_LARGE_MODULE_THRESHOLDS: &[ThresholdDefinition] = &[threshold("items", 25.0)];
const ARCHITECTURE_MODULE_FAN_OUT_THRESHOLDS: &[ThresholdDefinition] = &[threshold("modules", 8.0)];
const ARCHITECTURE_PUBLIC_API_SURFACE_THRESHOLDS: &[ThresholdDefinition] =
    &[threshold("items", 12.0)];
const DEPENDENCY_DUPLICATE_LOCKED_VERSION_THRESHOLDS: &[ThresholdDefinition] =
    &[threshold("versions", 2.0)];
const TODO_DENSITY_THRESHOLDS: &[ThresholdDefinition] = &[threshold("markers", 4.0)];
const FILE_LENGTH_THRESHOLDS: &[ThresholdDefinition] =
    &[threshold("warn", 400.0), threshold("error", 800.0)];
const FUNCTION_LENGTH_THRESHOLDS: &[ThresholdDefinition] =
    &[threshold("warn", 30.0), threshold("error", 60.0)];
const PARAMETER_COUNT_THRESHOLDS: &[ThresholdDefinition] = &[threshold("warn", 5.0)];
const TEST_LONG_THRESHOLDS: &[ThresholdDefinition] = &[threshold("warn", 30.0)];

fn builtin_definitions() -> Vec<RuleDefinition> {
    vec![
        rule(
            "architecture.large-module",
            "Large module",
            Pillar::Design,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::High,
            ARCHITECTURE_LARGE_MODULE_THRESHOLDS,
            "Flags modules with more indexed items than the configured threshold.",
        ),
        rule(
            "architecture.module-fan-out",
            "Module fan-out",
            Pillar::Design,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::High,
            ARCHITECTURE_MODULE_FAN_OUT_THRESHOLDS,
            "Flags files that declare many child modules.",
        ),
        rule(
            "architecture.public-api-surface",
            "Public API surface",
            Pillar::Design,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::High,
            ARCHITECTURE_PUBLIC_API_SURFACE_THRESHOLDS,
            "Flags modules with many public exports.",
        ),
        rule(
            "complexity.cognitive",
            "Cognitive complexity",
            Pillar::Complexity,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            COMPLEXITY_COGNITIVE_THRESHOLDS,
            "Flags functions with high cognitive complexity.",
        ),
        rule(
            "complexity.cyclomatic",
            "Cyclomatic complexity",
            Pillar::Complexity,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            COMPLEXITY_CYCLOMATIC_THRESHOLDS,
            "Flags functions with high branch and decision complexity.",
        ),
        rule(
            "complexity.nesting-depth",
            "Nesting depth",
            Pillar::Complexity,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            COMPLEXITY_NESTING_DEPTH_THRESHOLDS,
            "Flags functions with deeply nested control flow.",
        ),
        rule(
            "complexity.npath",
            "NPath complexity",
            Pillar::Complexity,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::Medium,
            COMPLEXITY_NPATH_THRESHOLDS,
            "Flags functions with many approximate execution paths.",
        ),
        rule(
            "dead-code.unused-private-function",
            "Unused private function",
            Pillar::DeadCode,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::Low,
            &[],
            "Flags private functions with no same-file call sites.",
        ),
        rule(
            "dead-code.unused-private-item-candidate",
            "Unused private item candidate",
            Pillar::DeadCode,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::Medium,
            &[],
            "Flags private items whose names are not referenced elsewhere in discovered Rust sources.",
        ),
        rule(
            "dependency.duplicate-locked-version",
            "Duplicate locked dependency version",
            Pillar::Security,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::High,
            DEPENDENCY_DUPLICATE_LOCKED_VERSION_THRESHOLDS,
            "Flags packages locked at more versions than the configured threshold.",
        ),
        rule(
            "dependency.git-source",
            "Git dependency source",
            Pillar::Security,
            RuleKind::Project,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags dependencies sourced directly from git repositories.",
        ),
        rule(
            "dependency.missing-package-metadata",
            "Missing package metadata",
            Pillar::Documentation,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags packages missing description or license metadata.",
        ),
        rule(
            "dependency.path-source",
            "Path dependency source",
            Pillar::Security,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags dependencies sourced from local filesystem paths.",
        ),
        rule(
            "dependency.wildcard-version",
            "Wildcard dependency version",
            Pillar::Security,
            RuleKind::Project,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags dependency requirements that use wildcard versions.",
        ),
        rule(
            "design.god-function",
            "God function",
            Pillar::Design,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags functions that are both long and complex.",
        ),
        rule(
            "docs.missing-public-doc",
            "Missing public documentation",
            Pillar::Documentation,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::Medium,
            &[],
            "Flags public Rust API items without doc comments.",
        ),
        rule(
            "docs.missing-readme",
            "Missing README",
            Pillar::Documentation,
            RuleKind::Project,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags projects without a root README file.",
        ),
        rule(
            "docs.todo-density",
            "TODO/FIXME density",
            Pillar::Documentation,
            RuleKind::Text,
            Severity::Advisory,
            Confidence::High,
            TODO_DENSITY_THRESHOLDS,
            "Flags files with dense TODO or FIXME markers.",
        ),
        rule(
            "concurrency.blocking-call-in-async",
            "Blocking call in async function",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::Medium,
            &[],
            "Flags narrow blocking call patterns inside async functions.",
        ),
        rule(
            "concurrency.lock-across-await",
            "Lock guard across await",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::Medium,
            &[],
            "Flags lock guard bindings that appear to live across an await point.",
        ),
        rule(
            "concurrency.unbounded-channel",
            "Unbounded channel",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::Medium,
            &[],
            "Flags unbounded channel constructors in production code.",
        ),
        rule(
            "error-handling.production-panic",
            "Production panic",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags panic! calls in non-test functions without a local invariant comment.",
        ),
        rule(
            "error-handling.public-unwrap",
            "Public API unwrap",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags unwrap or expect calls in public non-test functions.",
        ),
        rule(
            "error-handling.unimplemented-placeholder",
            "Unimplemented placeholder",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags todo! and unimplemented! placeholders in non-test functions.",
        ),
        rule(
            "modernisation.public-field",
            "Public struct field",
            Pillar::Modernisation,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags public struct fields that expose representation.",
        ),
        rule(
            "naming.generic-function",
            "Generic function name",
            Pillar::Naming,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags function names that are too generic to explain intent.",
        ),
        rule(
            "naming.boolean-prefix",
            "Boolean predicate prefix",
            Pillar::Naming,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags bool-returning functions whose names do not read like predicates.",
        ),
        rule(
            "naming.placeholder-identifier",
            "Placeholder identifier",
            Pillar::Naming,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::Medium,
            &[],
            "Flags placeholder identifiers such as foo, bar, baz, and qux.",
        ),
        rule(
            "naming.short-variable",
            "Short variable name",
            Pillar::Naming,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::Medium,
            &[],
            "Flags very short local variable names outside accepted abbreviations.",
        ),
        rule(
            "security.process-command",
            "Process command execution",
            Pillar::Security,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags process command construction for manual argument validation.",
        ),
        rule(
            "security.unsafe-block",
            "Unsafe block",
            Pillar::Security,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags unsafe blocks without a nearby SAFETY rationale.",
        ),
        rule(
            "sensitive-data.api-key-pattern",
            "API key pattern",
            Pillar::SensitiveData,
            RuleKind::Text,
            Severity::Error,
            Confidence::High,
            &[],
            "Flags common API key patterns.",
        ),
        rule(
            "sensitive-data.aws-access-key",
            "AWS access key",
            Pillar::SensitiveData,
            RuleKind::Text,
            Severity::Error,
            Confidence::High,
            &[],
            "Flags AWS access key patterns.",
        ),
        rule(
            "sensitive-data.database-url-password",
            "Database URL password",
            Pillar::SensitiveData,
            RuleKind::Text,
            Severity::Error,
            Confidence::High,
            &[],
            "Flags database URLs that appear to include passwords.",
        ),
        rule(
            "sensitive-data.hardcoded-env-value",
            "Hardcoded environment-style secret",
            Pillar::SensitiveData,
            RuleKind::Text,
            Severity::Error,
            Confidence::High,
            &[],
            "Flags secret-like KEY=value literals committed in source or config.",
        ),
        rule(
            "sensitive-data.high-entropy-string",
            "High entropy string",
            Pillar::SensitiveData,
            RuleKind::Text,
            Severity::Error,
            Confidence::Medium,
            &[],
            "Flags long string literals that look like generated secrets.",
        ),
        rule(
            "sensitive-data.jwt-token",
            "JWT token",
            Pillar::SensitiveData,
            RuleKind::Text,
            Severity::Error,
            Confidence::High,
            &[],
            "Flags JWT-looking token strings.",
        ),
        rule(
            "sensitive-data.private-key",
            "Private key block",
            Pillar::SensitiveData,
            RuleKind::Text,
            Severity::Error,
            Confidence::High,
            &[],
            "Flags private key block markers.",
        ),
        rule(
            "size.file-length",
            "File length",
            Pillar::Size,
            RuleKind::Text,
            Severity::Warning,
            Confidence::High,
            FILE_LENGTH_THRESHOLDS,
            "Flags files over configured line-count thresholds.",
        ),
        rule(
            "size.function-length",
            "Function length",
            Pillar::Size,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            FUNCTION_LENGTH_THRESHOLDS,
            "Flags functions over configured line-count thresholds.",
        ),
        rule(
            "size.parameter-count",
            "Parameter count",
            Pillar::Size,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            PARAMETER_COUNT_THRESHOLDS,
            "Flags functions with too many parameters.",
        ),
        rule(
            "test-quality.conditional-logic",
            "Conditional logic in test",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags tests that contain conditional logic.",
        ),
        rule(
            "test-quality.ignored-without-reason",
            "Ignored test without reason",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags ignored tests that do not explain why they are skipped.",
        ),
        rule(
            "test-quality.long-test",
            "Long test",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            TEST_LONG_THRESHOLDS,
            "Flags long test functions that are harder to scan and maintain.",
        ),
        rule(
            "test-quality.loop-in-test",
            "Loop in test",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags tests that contain loop logic.",
        ),
        rule(
            "test-quality.no-assertions",
            "No assertions in test",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags tests that do not appear to assert behavior.",
        ),
        rule(
            "test-quality.sleep-in-test",
            "Sleep in test",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags tests that sleep instead of synchronizing on behavior.",
        ),
        rule(
            "test-quality.trivial-assertion",
            "Trivial assertion",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags assertions that prove literals or constants instead of behavior.",
        ),
        rule(
            "test-quality.unwrap-in-test",
            "Unwrap in test",
            Pillar::TestQuality,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags unwrap calls in tests.",
        ),
        rule(
            "waste.unnecessary-clone-candidate",
            "Unnecessary clone candidate",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags clone calls that may be avoidable.",
        ),
        rule(
            "waste.unreachable-code",
            "Unreachable code",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Warning,
            Confidence::High,
            &[],
            "Flags statements after terminating statements.",
        ),
        rule(
            "waste.unwrap-expect",
            "Unwrap or expect",
            Pillar::Waste,
            RuleKind::Rust,
            Severity::Advisory,
            Confidence::High,
            &[],
            "Flags unwrap and expect calls outside test attributes.",
        ),
    ]
}

#[expect(
    clippy::too_many_arguments,
    reason = "central registry helper keeps static rule definitions compact"
)]
fn rule(
    id: &'static str,
    name: &'static str,
    pillar: Pillar,
    kind: RuleKind,
    default_severity: Severity,
    confidence: Confidence,
    thresholds: &'static [ThresholdDefinition],
    description: &'static str,
) -> RuleDefinition {
    RuleDefinition {
        id,
        name,
        pillar,
        tier: "v0.1",
        kind,
        default_severity,
        confidence,
        thresholds,
        options: &[],
        default_enabled: true,
        description,
    }
}

const fn threshold(name: &'static str, default: f64) -> ThresholdDefinition {
    ThresholdDefinition { name, default }
}
