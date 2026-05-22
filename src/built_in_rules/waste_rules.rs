use super::*;

/// Returns true when the line contains a `.clone()` whose result is
/// immediately consumed by an ownership-taking method (M33 exemptions:
/// `unwrap_or*`, `into*`, `collect*`, `?` propagation) or is being used
/// in a position where the surrounding code requires owned data (struct
/// field initialisation, `Some(_)` field wrap, `Entry::*` insertion,
/// tuple keys for entry/insert, `.map(...).collect()` chains). In those
/// cases the clone is not avoidable, so the candidate rule should stay
/// silent.
pub(crate) fn clone_is_consumed_or_owned(line: &str) -> bool {
    CLONE_OWNERSHIP_PATTERNS
        .iter()
        .any(|pattern| pattern.matches(line))
}

pub(crate) struct CloneOwnershipPattern {
    pub(crate) cell: &'static OnceLock<Regex>,
    pub(crate) pattern: &'static str,
}

impl CloneOwnershipPattern {
    pub(crate) fn matches(&self, line: &str) -> bool {
        static_regex(self.cell, self.pattern).is_match(line)
    }
}

static CONSUMER_REGEX: OnceLock<Regex> = OnceLock::new();
static STRUCT_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
static LOOKUP_REGEX: OnceLock<Regex> = OnceLock::new();
static SOME_WRAP_REGEX: OnceLock<Regex> = OnceLock::new();
static MAP_COLLECT_REGEX: OnceLock<Regex> = OnceLock::new();
static MAP_CLOSURE_LINE_REGEX: OnceLock<Regex> = OnceLock::new();
static LET_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
static MULTILINE_CHAIN_REGEX: OnceLock<Regex> = OnceLock::new();
static STANDALONE_ARGUMENT_REGEX: OnceLock<Regex> = OnceLock::new();

const CLONE_OWNERSHIP_PATTERNS: &[CloneOwnershipPattern] = &[
    CloneOwnershipPattern {
        cell: &CONSUMER_REGEX,
        pattern: r"\.clone\(\)\s*(?:\?|\.(?:unwrap_or_else|unwrap_or_default|unwrap_or|into_iter|into|collect)\b)",
    },
    CloneOwnershipPattern {
        cell: &STRUCT_FIELD_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*\.clone\(\)\s*\)*\s*,?\s*$",
    },
    CloneOwnershipPattern {
        cell: &LOOKUP_REGEX,
        pattern: r"\.(?:entry|insert|get|contains|contains_key|remove)\(\s*&?\s*\(?[^=;]*\.clone\(\)[^;]*\)",
    },
    CloneOwnershipPattern {
        cell: &SOME_WRAP_REGEX,
        pattern: r"\bSome\(\s*[^()]*\.clone\(\)\s*\)",
    },
    CloneOwnershipPattern {
        cell: &MAP_COLLECT_REGEX,
        pattern: r"\.map\([^)]*\.clone\(\)[^)]*\)\s*\.?\s*\)*\.?\s*(?:collect|\)\s*\.collect)\(\)",
    },
    CloneOwnershipPattern {
        cell: &MAP_CLOSURE_LINE_REGEX,
        pattern: r"^\s*\.map\(\|[^|]*\|\s*[^=;]+\.clone\(\)\s*\)\s*$",
    },
    CloneOwnershipPattern {
        cell: &LET_BINDING_REGEX,
        pattern: r"^\s*let\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[^=]+)?\s*=\s*[^=;]+\.clone\(\)\s*;\s*$",
    },
    CloneOwnershipPattern {
        cell: &STANDALONE_ARGUMENT_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.clone\(\)\s*,\s*$",
    },
    CloneOwnershipPattern {
        cell: &MULTILINE_CHAIN_REGEX,
        pattern: r"^\s*\.clone\(\)\s*$",
    },
];

/// Returns true when a `.expect("...")` call carries a substantive
/// rationale string (≥15 characters of non-whitespace content). The
/// waste rule accepts these because the author has already declared why
/// the unwrap is safe; trivial rationales like `.expect("ok")` still
/// fire.
pub(crate) fn expect_has_substantive_rationale(line: &str) -> bool {
    static EXPECT_RATIONALE_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(&EXPECT_RATIONALE_REGEX, r#"\.expect\(\s*"([^"]*)"\s*\)"#);
    regex.captures_iter(line).any(|captures| {
        captures
            .get(1)
            .map(|rationale| rationale.as_str().trim().len() >= 15)
            .unwrap_or(false)
    })
}
