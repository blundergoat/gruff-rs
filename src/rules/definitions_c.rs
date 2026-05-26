use super::*;

pub(crate) const WASTE_RULES: &[RuleDefinition] = &[
    rule_definition!(
        "waste.unnecessary-clone-candidate",
        "Unnecessary clone candidate",
        Pillar::Maintainability,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags clone calls that may be avoidable.",
    ),
    rule_definition!(
        "waste.unreachable-code",
        "Unreachable code",
        Pillar::DeadCode,
        RuleKind::Rust,
        Severity::Warning,
        Confidence::High,
        None,
        "Flags statements after terminating statements.",
    ),
    rule_definition!(
        "waste.unwrap-expect",
        "Unwrap or expect",
        Pillar::Maintainability,
        RuleKind::Rust,
        Severity::Advisory,
        Confidence::High,
        None,
        "Flags unwrap and expect calls outside test attributes.",
        false_positives: &[
            FalsePositiveShape {
                shape: "Owned values consumed via `.unwrap_or_default()` or other infallible variants the regex cannot distinguish from `.unwrap()`.",
                mitigation: "Rule already skips `unwrap_or`/`unwrap_or_default`/`unwrap_or_else`; if a real false positive lands, file with the call shape so the carve-out can be extended.",
            },
        ],
        related: &[
            "error-handling.public-unwrap",
            "test-quality.unwrap-in-test",
        ],
    ),
];
