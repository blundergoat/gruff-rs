use super::*;

mod args;

pub(crate) use args::{
    AnalyseArgs, CompletionArgs, DashboardArgs, ListRulesArgs, ReportArgs, SummaryArgs,
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

// Symfony-Console-style global flags shared by every subcommand.
// `--silent` and `-q/--quiet` gate the primary stdout writer. `--ansi`/`--no-ansi`
// is reserved for the text renderer's future colour mode; today the text renderer
// emits no ANSI, so these flags accept and store but otherwise do not change
// output. `-v/-vv/-vvv` is a count flag the analyzer can opt into for stderr
// debug traces. `-n/--no-interaction` is accepted for parity and ignored;
// gruff-rs is non-interactive.
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
    /// Increase the verbosity of stderr messages (-v, -vv, -vvv).
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Do not ask any interactive question (accepted for CLI parity; gruff-rs is non-interactive).
    #[arg(short = 'n', long, global = true)]
    no_interaction: bool,
}

impl GlobalOptions {
    pub(crate) fn writer(&self) -> OutputWriter {
        OutputWriter {
            silent: self.silent,
            quiet: self.quiet,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OutputWriter {
    silent: bool,
    quiet: bool,
}

impl OutputWriter {
    pub(crate) fn emit(self, outcome: RunOutcome, body: &str) {
        if self.silent {
            return;
        }
        if self.quiet && !outcome.is_failure() {
            return;
        }
        println!("{body}");
    }

    /// Emit a body that is not gated by the success/failure outcome of an
    /// analysis run (e.g. completion scripts, list-rules output).
    pub(crate) fn emit_unconditional(self, body: &str) {
        if self.silent {
            return;
        }
        println!("{body}");
    }

    pub(crate) fn is_silent(self) -> bool {
        self.silent
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    Success,
    ThresholdHit,
    DiagnosticsFailed,
}

impl RunOutcome {
    pub(crate) fn classify(report: &AnalysisReport, fail_on: FailThreshold) -> Self {
        if report.diagnostics.iter().any(RunDiagnostic::is_failure) {
            return Self::DiagnosticsFailed;
        }
        if report
            .findings
            .iter()
            .any(|finding| fail_on.triggered_by(finding.severity))
        {
            return Self::ThresholdHit;
        }
        Self::Success
    }

    pub(crate) fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::ThresholdHit => ExitCode::from(1),
            Self::DiagnosticsFailed => ExitCode::from(2),
        }
    }

    pub(crate) fn is_failure(self) -> bool {
        !matches!(self, Self::Success)
    }
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Run gruff analysis.
    Analyse(AnalyseArgs),
    /// Render a gruff report to stdout or a file.
    Report(ReportArgs),
    /// List gruff rule metadata.
    #[command(alias = "rules")]
    ListRules(ListRulesArgs),
    /// Serve the local gruff dashboard.
    Dashboard(DashboardArgs),
    /// Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders.
    Summary(SummaryArgs),
    /// Dump the shell completion script.
    Completion(CompletionArgs),
}

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

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum SummaryFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ReportFormat {
    Html,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum RuleListFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
pub(crate) enum FailThreshold {
    None,
    Advisory,
    Warning,
    Error,
}

impl FailThreshold {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    pub(crate) fn triggered_by(self, severity: Severity) -> bool {
        match self {
            Self::None => false,
            Self::Advisory => true,
            Self::Warning => severity == Severity::Warning || severity == Severity::Error,
            Self::Error => severity == Severity::Error,
        }
    }
}
