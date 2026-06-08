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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::Symbol => "symbol",
            Self::File => "file",
            Self::Project => "project",
        }
    }
}

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
    format!("{:x}", hasher.finalize())[..16].to_string()
}

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
