use super::*;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FindingScope {
    Line,
    Symbol,
    File,
    Project,
}

impl FindingScope {
    /// Names this scope with the same lowercase word as its serde kebab-case spelling.
    ///
    /// Returns the static label `line`, `symbol`, `file` or `project`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::Symbol => "symbol",
            Self::File => "file",
            Self::Project => "project",
        }
    }
}

/// Classifies a finding as line, symbol, file or project scoped from its rule and the location it carries.
///
/// The rule identifier `rule_id` is matched first: `size.file-length` and `architecture.module-fan-out` are file scoped.
/// `docs.missing-readme`, `architecture.public-api-surface`, `architecture.large-module` and every `dependency.` rule are project scoped.
/// Any other rule is symbol scoped when the finding names a `symbol`, else line scoped when it has a `line`, else project scoped.
///
/// Returns the inferred scope, falling back to `FindingScope::Project` when the finding has neither a `symbol` nor a `line`.
pub(crate) fn infer_finding_scope(
    rule_id: &str,
    symbol: Option<&str>,
    line: Option<usize>,
) -> FindingScope {
    match rule_id {
        "size.file-length" | "architecture.module-fan-out" => FindingScope::File,
        "docs.missing-readme" | "architecture.public-api-surface" | "architecture.large-module" => {
            FindingScope::Project
        }
        id if id.starts_with("dependency.") => FindingScope::Project,
        _ if symbol.is_some() => FindingScope::Symbol,
        _ if line.is_some() => FindingScope::Line,
        _ => FindingScope::Project,
    }
}

/// Hashes a finding's rule, file and subject into a short identity that repeats whenever those three inputs repeat.
///
/// SHA-256 runs over the rule identifier `rule_id`, the finding's `file_path` and its subject, with a NUL byte between each part.
/// The subject is the finding's `symbol` when present; otherwise `scope` names a fixed word, except line scope, which uses `message`.
///
/// Returns the first 16 lowercase hex characters of the SHA-256 digest.
pub(crate) fn compute_stable_identity(
    rule_id: &str,
    file_path: &str,
    scope: FindingScope,
    symbol: Option<&str>,
    message: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(file_path.as_bytes());
    hasher.update(b"\0");
    hasher.update(stable_identity_subject(scope, symbol, message).as_bytes());
    lower_hex(&hasher.finalize())[..16].to_string()
}

/// Spell digest bytes as lowercase hex, two characters per byte, the form every published identity and digest uses.
///
/// `digest` is a hash output such as a SHA-256 digest.
/// Returns a string twice as long as `digest`, with no separators or prefix.
pub(crate) fn lower_hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Chooses the subject that `compute_stable_identity` hashes after a finding's rule and file.
///
/// A present `symbol` always wins; otherwise `scope` picks the fixed word `file`, `project` or `symbol`.
/// Line scope without a symbol uses the finding `message`, so that identity changes whenever the message text changes.
///
/// Returns the chosen subject, borrowed from `symbol` or `message`, or a static scope word.
fn stable_identity_subject<'a>(
    scope: FindingScope,
    symbol: Option<&'a str>,
    message: &'a str,
) -> &'a str {
    if let Some(symbol) = symbol {
        return symbol;
    }
    match scope {
        FindingScope::File => "file",
        FindingScope::Project => "project",
        FindingScope::Symbol => "symbol",
        FindingScope::Line => message,
    }
}
