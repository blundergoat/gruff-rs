//! Define the paired deep-scan budget and its command-line override.

use super::Config;

pub(crate) const DEEP_SCAN_DEFAULT_MAX_LINES: usize = 20_000;
pub(crate) const DEEP_SCAN_DEFAULT_MAX_BYTES: usize = 2_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Hold the effective paired limits for expensive Rust-source analysis.
///
/// Either limit is sufficient to degrade a Rust source file. The override label
/// is published in the non-fatal diagnostic so users can identify which layer
/// selected the effective values.
pub(crate) struct DeepScanBudget {
    pub(crate) enabled: bool,
    pub(crate) max_lines: usize,
    pub(crate) max_bytes: usize,
    pub(crate) override_state: &'static str,
}

impl Default for DeepScanBudget {
    fn default() -> Self {
        Self {
            enabled: true,
            max_lines: DEEP_SCAN_DEFAULT_MAX_LINES,
            max_bytes: DEEP_SCAN_DEFAULT_MAX_BYTES,
            override_state: "default",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Represent the atomic command-line override accepted by scan surfaces.
pub(crate) enum DeepScanBudgetOverride {
    Disabled,
    Limits { max_lines: usize, max_bytes: usize },
}

impl DeepScanBudgetOverride {
    pub(crate) fn as_cli_value(&self) -> String {
        match self {
            Self::Disabled => "off".to_string(),
            Self::Limits {
                max_lines,
                max_bytes,
            } => format!("{max_lines}:{max_bytes}"),
        }
    }
}

impl std::str::FromStr for DeepScanBudgetOverride {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        const ERROR: &str =
            "--deep-scan-budget must be two positive integers as LINES:BYTES, or off.";
        if value == "off" {
            return Ok(Self::Disabled);
        }
        let Some((lines, bytes)) = value.split_once(':') else {
            return Err(ERROR.to_string());
        };
        if bytes.contains(':') {
            return Err(ERROR.to_string());
        }
        let max_lines = lines.parse::<usize>().map_err(|_| ERROR.to_string())?;
        let max_bytes = bytes.parse::<usize>().map_err(|_| ERROR.to_string())?;
        if max_lines == 0 || max_bytes == 0 {
            return Err(ERROR.to_string());
        }
        Ok(Self::Limits {
            max_lines,
            max_bytes,
        })
    }
}

impl Config {
    /// Apply a command-line budget after config loading so CLI always wins.
    pub(crate) fn apply_deep_scan_budget_override(
        &mut self,
        override_value: Option<&DeepScanBudgetOverride>,
    ) {
        let Some(override_value) = override_value else {
            return;
        };
        match override_value {
            DeepScanBudgetOverride::Disabled => {
                self.deep_scan_budget.enabled = false;
                self.deep_scan_budget.override_state = "cli";
            }
            DeepScanBudgetOverride::Limits {
                max_lines,
                max_bytes,
            } => {
                self.deep_scan_budget = DeepScanBudget {
                    enabled: true,
                    max_lines: *max_lines,
                    max_bytes: *max_bytes,
                    override_state: "cli",
                };
            }
        }
    }
}
