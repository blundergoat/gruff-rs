//! Define CLI flags, output modes, and exit status for the commands in `gruff-rs --help`.
//!
//! Command handlers use these types to turn the caller's request into scan and display options.
//! Shell scripts and CI use the final exit status to tell a clean run, a failed gate, and an invalid scan apart.

use super::*;

mod args;

pub(crate) use args::{
    AnalyseArgs, CheckIgnoreArgs, CheckIgnoreFormat, CompletionArgs, DashboardArgs, HookArgs,
    InitArgs, ListRulesArgs, MigrateConfigArgs, ReportArgs, SummaryArgs,
};

/// Symfony-Console-style colours for help output: yellow section headers,
/// green flag/command literals, dimmed placeholders. Matches the gruff-php
/// help layout users may be coming from.
const HELP_STYLES: styling::Styles = styling::Styles::styled()
    .header(
        styling::Style::new()
            .fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Yellow)))
            .bold(),
    )
    .usage(
        styling::Style::new()
            .fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Yellow)))
            .bold(),
    )
    .literal(styling::Style::new().fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Green))))
    .placeholder(styling::Style::new().dimmed())
    .error(
        styling::Style::new()
            .fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Red)))
            .bold(),
    )
    .valid(styling::Style::new().fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Green))))
    .invalid(
        styling::Style::new().fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Yellow))),
    );

const HELP_TEMPLATE: &str = "\
{before-help}{name} {version}\n\n\
\x1b[1m\x1b[33mUsage:\x1b[0m\n  {usage}\n\n\
\x1b[1m\x1b[33mOptions:\x1b[0m\n{options}\n\n\
\x1b[1m\x1b[33mAvailable commands:\x1b[0m\n{subcommands}{after-help}";

// Start with one subcommand and the shared flags from the shell invocation.
//
// Help and argument validation are settled here before a command opens a project.
// The dispatcher gets one validated request with its matching command arguments.
#[derive(Parser)]
#[command(
    name = "gruff-rs",
    version = VERSION,
    about = "Rust project quality analysis.",
    styles = HELP_STYLES,
    help_template = HELP_TEMPLATE,
    subcommand_help_heading = "Available commands",
    subcommand_value_name = "command",
    arg_required_else_help = true,
)]
pub(crate) struct Cli {
    #[command(flatten)]
    pub(crate) global: GlobalOptions,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

// Shared flags that apply before or after the subcommand name.
//
// Use `--quiet` or `--silent` to control stdout, and `--no-interaction` when a script cannot answer prompts.
// The ANSI flags are accepted for compatibility. Command handlers can use the verbosity count for extra detail.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct GlobalOptions {
    /// Do not output any message.
    #[arg(long, global = true)]
    silent: bool,
    /// Only errors are displayed. All other output is suppressed.
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
    /// Force ANSI output.
    #[arg(long, global = true, conflicts_with = "no_ansi")]
    ansi: bool,
    /// Disable ANSI output.
    #[arg(long = "no-ansi", global = true)]
    no_ansi: bool,
    /// Increase the verbosity of stderr messages (-v, -vv, -vvv). `check-ignore`
    /// also reads this: any `-v` switches its text output to `<path>\t<source>:<pattern>`.
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    pub(crate) verbose: u8,
    /// Do not ask any interactive question (accepted for CLI parity; gruff-rs is non-interactive).
    #[arg(short = 'n', long, global = true)]
    no_interaction: bool,
}

impl GlobalOptions {
    /// Build the stdout writer that applies the `--silent` and `--quiet` flags to command output.
    ///
    /// Returns an `OutputWriter` that copies those two flags.
    pub(crate) fn writer(&self) -> OutputWriter {
        OutputWriter {
            silent: self.silent,
            quiet: self.quiet,
        }
    }

    /// Tell whether the run must not prompt, which `--no-interaction` or `--silent` requests.
    ///
    /// Returns true when either flag is set.
    pub(crate) fn is_non_interactive(&self) -> bool {
        self.no_interaction || self.silent
    }
}

/// Control what a command sends to stdout.
///
/// Quiet mode suppresses successful analysis output. Silent mode also suppresses listings and other ungated output.
/// A command can still print errors to stderr or write to an explicitly requested file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OutputWriter {
    silent: bool,
    quiet: bool,
}

impl OutputWriter {
    /// Print a command's primary output to stdout unless the silent or quiet flags suppress it.
    ///
    /// `body` is the text printed with a trailing newline, and `outcome` is the run's result: quiet mode prints `body` only for a failing outcome.
    /// Silent mode prints nothing whatever the outcome.
    /// Panics, as `println!` does, when writing to stdout fails.
    pub(crate) fn emit(self, outcome: RunOutcome, body: &str) {
        // Scripts requesting silence receive no standard output even when the scan reports a failure.
        if self.silent {
            return;
        }
        // Quiet mode keeps output that explains why a scan or configured gate failed.
        if self.quiet && !outcome.is_failure() {
            return;
        }
        println!("{body}");
    }

    /// Print output that has no analysis outcome, such as completion scripts or `list-rules`.
    ///
    /// An empty `body` prints a blank line. `--silent` suppresses even this output.
    pub(crate) fn emit_unconditional(self, body: &str) {
        // A caller can suppress rule listings even though the command has no finding gate.
        if self.silent {
            return;
        }
        println!("{body}");
    }

    /// Report whether the `--silent` flag suppresses all output from this writer.
    ///
    /// Returns true when `--silent` was set; `--quiet` alone gives false.
    pub(crate) fn is_silent(self) -> bool {
        self.silent
    }
}

/// The exit result a shell or CI runner sees from a scan.
///
/// A finding gate and an invalid scan use separate statuses.
/// Output writers use the result when deciding whether quiet mode still prints the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    Success,
    ThresholdHit,
    DiagnosticsFailed,
}

impl RunOutcome {
    /// Classify a run's exit outcome. A fatal diagnostic is exit 2; otherwise the
    /// `gate:` block evaluates first (a trip with `onMatch: fail` is exit 1), then
    /// the legacy `--fail-on` flag - the precedence documented in ADR-003.
    ///
    /// `report` supplies the diagnostics and findings, `fail_on` is the `--fail-on` threshold, and `gate` is the configured gate, if any.
    /// Returns `DiagnosticsFailed` for a failing diagnostic, then `ThresholdHit` when the gate fails or a finding meets `fail_on`, else `Success`.
    pub(crate) fn classify(
        report: &AnalysisReport,
        fail_on: FailThreshold,
        gate: Option<&Gate>,
    ) -> Self {
        Self::classify_with_confidence(report, fail_on, gate, Confidence::Low)
    }

    /// Apply the confidence floor to severity-based failure after checking diagnostics and count gates.
    /// Classify `report` using `gate` and the two limits `fail_on` and `min_confidence`.
    /// Returns the outcome to publish as the process exit status.
    pub(crate) fn classify_with_confidence(
        report: &AnalysisReport,
        fail_on: FailThreshold,
        gate: Option<&Gate>,
        min_confidence: Confidence,
    ) -> Self {
        if report.diagnostics.iter().any(RunDiagnostic::is_failure) {
            return Self::DiagnosticsFailed;
        }
        if gate.is_some_and(|gate| gate.evaluate_report(report).fails) {
            return Self::ThresholdHit;
        }
        // The severity gate honours the confidence floor the caller set for this scan.
        if report.findings.iter().any(|finding| {
            finding.confidence >= min_confidence
                && fail_on.is_triggered_by_severity(finding.severity)
        }) {
            return Self::ThresholdHit;
        }
        Self::Success
    }

    /// Map the run outcome to its numeric exit status.
    ///
    /// Returns 0 for `Success`, 1 for `ThresholdHit` and 2 for `DiagnosticsFailed`.
    pub(crate) fn numeric_code(self) -> usize {
        match self {
            Self::Success => 0,
            Self::ThresholdHit => 1,
            Self::DiagnosticsFailed => 2,
        }
    }

    /// Convert the run outcome into a process `ExitCode`.
    ///
    /// Returns an `ExitCode` built from `numeric_code`, so 0, 1 or 2.
    pub(crate) fn exit_code(self) -> ExitCode {
        ExitCode::from(self.numeric_code() as u8)
    }

    /// Tell whether the run did not succeed, which lets quiet mode still print a failing run's output.
    ///
    /// Returns true for `ThresholdHit` and `DiagnosticsFailed`, and false for `Success`.
    pub(crate) fn is_failure(self) -> bool {
        !matches!(self, Self::Success)
    }
}

// Map each supported command to its own set of arguments.
//
// A caller who wants only config or rule information can choose a command that does not scan files.
// The dispatcher routes each validated request to the matching handler.
#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Run gruff analysis.
    Analyse(Box<AnalyseArgs>),
    /// Emit gruff.hook.v2 JSON for coding-agent hooks.
    Hook(HookArgs),
    /// Render a gruff report to stdout or a file.
    Report(ReportArgs),
    /// List gruff rule metadata.
    #[command(alias = "rules")]
    ListRules(ListRulesArgs),
    /// Serve the local gruff dashboard.
    Dashboard(DashboardArgs),
    /// Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders.
    Summary(SummaryArgs),
    /// Report whether gruff would ignore each path and why, using the same config and ignore engine as `analyse`. Runs no analysis.
    CheckIgnore(CheckIgnoreArgs),
    /// Dump the shell completion script.
    Completion(CompletionArgs),
    /// Write a default `.gruff-rs.yaml` config derived from the built-in rule registry.
    Init(InitArgs),
    /// Rewrite a 0.5 config for the current schema, writing the result to a different file.
    MigrateConfig(MigrateConfigArgs),
}

// Formats accepted by the full analysis command.
//
// A caller selects a format for a terminal, browser, or automated consumer.
// The selected renderer uses the same underlying analysis result.
#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Text,
    Json,
    Sarif,
    Html,
    Markdown,
    Github,
    Hotspot,
}

impl OutputFormat {
    /// Give the lowercase name of the output format, such as `json` or `sarif`.
    ///
    /// Returns a static string holding the variant name in lowercase.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Html => "html",
            Self::Markdown => "markdown",
            Self::Github => "github",
            Self::Hotspot => "hotspot",
        }
    }
}

// Formats for a caller who asks for the scan digest.
//
// Text is the quick terminal view. JSON keeps the compact machine contract.
// Both omit the complete finding list.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum SummaryFormat {
    Text,
    Json,
}

// Formats `report` accepts for stdout or a requested file.
//
// Use HTML to review the full result in a browser.
// Use JSON when another program needs the same scan data.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ReportFormat {
    Html,
    Json,
}

// How `list-rules` presents rule metadata without running a scan.
//
// Text is suitable for reading rule names and options in a terminal.
// JSON lets tools query the same catalogue by rule ID.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum RuleListFormat {
    Text,
    Json,
}

// The finding severity at which a command returns exit 1.
//
// Callers can set it with `--fail-on` or a command's `failOn` config value.
// `None` disables the severity gate. Invalid scans can still exit with status 2.
#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq, Eq)]
pub(crate) enum FailThreshold {
    None,
    Advisory,
    Warning,
    Error,
}

impl FailThreshold {
    /// Give the canonical lowercase name of a fail-on threshold, the spelling `from_str` parses back to the same value.
    ///
    /// Returns one of none, advisory, warning or error.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Decide whether a finding of the given severity reaches this fail-on threshold.
    ///
    /// `severity` is the finding's severity; under `None` nothing triggers and under `Advisory` every severity does.
    /// Under `Warning` a warning or error triggers, and under `Error` only an error does.
    /// Returns true when `severity` meets this threshold.
    pub(crate) fn is_triggered_by_severity(self, severity: Severity) -> bool {
        match self {
            Self::None => false,
            Self::Advisory => true,
            Self::Warning => severity == Severity::Warning || severity == Severity::Error,
            Self::Error => severity == Severity::Error,
        }
    }
}

/// A threshold the CLI or config loader could not recognize.
///
/// The message names the supplied value and the accepted alternatives.
/// Callers can correct the flag or config before rerunning the command.
#[derive(Debug, Clone)]
pub(crate) struct FailThresholdParseError {
    pub(crate) value: String,
}

impl std::fmt::Display for FailThresholdParseError {
    /// Write the error message for a rejected fail-on value, listing the accepted values.
    ///
    /// `f` is the formatter the message goes to; the message quotes the rejected `value` and lists advisory, warning, error and none.
    /// Returns the formatter's result, an error only when writing to `f` fails.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid fail-on value \"{}\": expected one of advisory, warning, error, none",
            self.value
        )
    }
}

impl std::error::Error for FailThresholdParseError {}

impl std::str::FromStr for FailThreshold {
    type Err = FailThresholdParseError;

    /// Parse a fail-on threshold name, ignoring surrounding whitespace and letter case.
    ///
    /// `value` is the text to parse; only none, advisory, warning and error are accepted, so names such as never or medium are refused.
    /// Returns the matching threshold, or a `FailThresholdParseError` that keeps the original untrimmed `value` for its message.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "advisory" => Ok(Self::Advisory),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            _ => Err(FailThresholdParseError {
                value: value.to_string(),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for FailThreshold {
    /// Deserialize a fail-on threshold from a string with the same case and whitespace handling as `from_str`.
    ///
    /// `deserializer` is the serde source, asked for a string.
    /// Returns the parsed threshold, or a serde error when the source cannot supply a string or `from_str` rejects the name.
    /// A rejected name keeps the `from_str` message.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Read the threshold string supplied by a project's config.
        ///
        /// A valid value lets the command apply the requested exit policy.
        /// An invalid value becomes a config error before analysis begins.
        struct FailThresholdVisitor;

        impl serde::de::Visitor<'_> for FailThresholdVisitor {
            type Value = FailThreshold;

            /// Tell a caller which threshold strings a config value can use.
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a fail-on threshold (advisory, warning, error, or none)")
            }

            /// Accept a supported `value` or return the threshold error with the rejected text.
            fn visit_str<E>(self, value: &str) -> Result<FailThreshold, E>
            where
                E: serde::de::Error,
            {
                <FailThreshold as std::str::FromStr>::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(FailThresholdVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep the documented gate levels usable from a CLI flag.
    #[test]
    fn fail_threshold_from_str_accepts_canonical_values() {
        assert!(matches!(
            "none".parse::<FailThreshold>(),
            Ok(FailThreshold::None)
        ));
        assert!(matches!(
            "advisory".parse::<FailThreshold>(),
            Ok(FailThreshold::Advisory)
        ));
        assert!(matches!(
            "warning".parse::<FailThreshold>(),
            Ok(FailThreshold::Warning)
        ));
        assert!(matches!(
            "error".parse::<FailThreshold>(),
            Ok(FailThreshold::Error)
        ));
    }

    /// Ensure a stored threshold can be written back and parsed as the same policy.
    #[test]
    fn fail_threshold_round_trips_via_as_str() {
        for value in [
            FailThreshold::None,
            FailThreshold::Advisory,
            FailThreshold::Warning,
            FailThreshold::Error,
        ] {
            let parsed: FailThreshold = value.as_str().parse().expect("canonical value parses");
            assert_eq!(parsed.as_str(), value.as_str());
        }
    }

    /// Accept threshold text copied with different casing or surrounding whitespace.
    #[test]
    fn fail_threshold_from_str_is_case_insensitive_and_trims() {
        assert!(matches!(
            "None".parse::<FailThreshold>(),
            Ok(FailThreshold::None)
        ));
        assert!(matches!(
            "ADVISORY".parse::<FailThreshold>(),
            Ok(FailThreshold::Advisory)
        ));
        assert!(matches!(
            "  warning  ".parse::<FailThreshold>(),
            Ok(FailThreshold::Warning)
        ));
    }

    /// Show the supported way to disable severity gating when a caller supplies `never`.
    #[test]
    fn fail_threshold_from_str_rejects_never_with_documented_message() {
        let err = "never"
            .parse::<FailThreshold>()
            .expect_err("never must reject");
        assert_eq!(
            err.to_string(),
            "invalid fail-on value \"never\": expected one of advisory, warning, error, none"
        );
    }

    /// Reject unsupported threshold spellings rather than switching to a different exit policy.
    #[test]
    fn fail_threshold_from_str_rejects_legacy_and_typo_values() {
        for bogus in [
            "medium", "critical", "info", "warn", "low", "high", "notice", "",
        ] {
            let err = bogus
                .parse::<FailThreshold>()
                .expect_err(&format!("{bogus} must reject"));
            assert!(
                err.to_string().contains("advisory, warning, error, none"),
                "error for {bogus:?} missing valid-values list: {err}"
            );
        }
    }

    /// Keep the documented threshold strings usable in project config.
    #[test]
    fn fail_threshold_deserialize_accepts_canonical_lowercase() {
        let parsed: FailThreshold =
            serde_yaml::from_str("none").expect("lowercase none parses via serde");
        assert!(matches!(parsed, FailThreshold::None));
    }

    /// Let config users vary threshold casing without changing the chosen level.
    #[test]
    fn fail_threshold_deserialize_is_case_insensitive() {
        let parsed: FailThreshold =
            serde_yaml::from_str("Advisory").expect("capitalised value parses via serde");
        assert!(matches!(parsed, FailThreshold::Advisory));
    }

    /// Give a config user an actionable threshold error for the unsupported `never` value.
    #[test]
    fn fail_threshold_deserialize_yaml_rejects_never() {
        let err = serde_yaml::from_str::<FailThreshold>("never")
            .expect_err("never must reject via serde");
        assert!(
            err.to_string()
                .contains("expected one of advisory, warning, error, none"),
            "serde error missing valid-values list: {err}"
        );
    }

    /// Reject a misspelled config threshold before starting a scan.
    #[test]
    fn fail_threshold_deserialize_yaml_rejects_bogus() {
        let err = serde_yaml::from_str::<FailThreshold>("bogus")
            .expect_err("bogus must reject via serde");
        assert!(
            err.to_string().contains("advisory, warning, error, none"),
            "serde error missing valid-values list: {err}"
        );
    }
}
