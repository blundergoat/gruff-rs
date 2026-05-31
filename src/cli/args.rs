use super::*;

const SUBCOMMAND_HELP_TEMPLATE: &str = "\
{before-help}\x1b[1m\x1b[33mDescription:\x1b[0m\n  {about}\n\n\
\x1b[1m\x1b[33mUsage:\x1b[0m\n  {usage}\n\n\
{all-args}{after-help}";

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct AnalyseArgs {
    /// Files or directories to scan. Defaults to the current directory.
    #[arg(value_name = "paths")]
    pub(crate) paths: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long)]
    pub(crate) no_config: bool,
    #[arg(long, default_value = "text")]
    pub(crate) format: OutputFormat,
    /// Severity gate. Defaults to `advisory`. Falls back to
    /// `minimumSeverity.analyse:` in `.gruff-rs.yaml` when omitted.
    #[arg(long)]
    pub(crate) fail_on: Option<FailThreshold>,
    /// Fail only on findings new since the baseline: alias for gate `scope: new`
    /// with a default `error: 0` cap. Requires a baseline (`--baseline` or a
    /// `gruff-baseline.json`); without one the run is a config error (exit 2).
    #[arg(long)]
    pub(crate) fail_on_new: bool,
    /// Include paths ignored by Git ignore files or built-in default dirs; config `paths.ignore` and VCS internals remain blocked.
    #[arg(long)]
    pub(crate) include_ignored: bool,
    #[arg(
        long,
        value_name = "MODE",
        num_args = 0..=1,
        default_missing_value = "working-tree",
        allow_hyphen_values = true,
        requires = "diff_git_unsafe"
    )]
    pub(crate) diff: Option<String>,
    /// Git base ref for changed-region filtering; executes Git, so it needs the unsafe-Git opt-in.
    #[arg(long, value_name = "REF", conflicts_with_all = ["diff", "diff_patch"], requires = "diff_git_unsafe")]
    pub(crate) since: Option<String>,
    /// Explicit changed line ranges such as 3-3,8-10.
    #[arg(long, value_name = "RANGES", conflicts_with_all = ["diff", "diff_patch", "since"])]
    pub(crate) changed_ranges: Option<String>,
    /// Changed-region scope: symbol or hunk.
    #[arg(long, default_value = "symbol")]
    pub(crate) changed_scope: ChangedScope,
    #[arg(long, value_name = "PATH", conflicts_with = "diff")]
    pub(crate) diff_patch: Option<PathBuf>,
    #[arg(long)]
    pub(crate) history_file: Option<PathBuf>,
    /// Apply a baseline file, defaulting to gruff-baseline.json when no path is provided.
    #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_BASELINE)]
    pub(crate) baseline: Option<PathBuf>,
    /// Write current findings to a baseline file, defaulting to gruff-baseline.json.
    #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_BASELINE)]
    pub(crate) generate_baseline: Option<PathBuf>,
    /// Do not apply the default gruff-baseline.json file even when it exists.
    #[arg(long)]
    pub(crate) no_baseline: bool,
    /// Opt in to the Git-executing diff modes (`--diff`, `--since`). Git-free
    /// modes (`--diff-patch`, `--changed-ranges`) never need it.
    #[arg(long, hide = true)]
    pub(crate) diff_git_unsafe: bool,
}

#[derive(Args)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct ReportArgs {
    /// Files or directories to scan. Defaults to the current directory.
    #[arg(value_name = "paths")]
    pub(crate) paths: Vec<PathBuf>,
    #[arg(long, default_value = "html")]
    pub(crate) format: ReportFormat,
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long)]
    pub(crate) no_config: bool,
    /// Severity gate. Defaults to `none` (M08a). Falls back to
    /// `minimumSeverity.report:` in `.gruff-rs.yaml` when omitted.
    #[arg(long)]
    pub(crate) fail_on: Option<FailThreshold>,
    /// Include paths ignored by Git ignore files or built-in default dirs; config `paths.ignore` and VCS internals remain blocked.
    #[arg(long)]
    pub(crate) include_ignored: bool,
    /// Do not apply the default gruff-baseline.json file even when it exists.
    #[arg(long)]
    pub(crate) no_baseline: bool,
}

#[derive(Args)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct DashboardArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) host: String,
    #[arg(long, default_value_t = 8766)]
    pub(crate) port: u16,
    #[arg(long, default_value = ".")]
    pub(crate) project_root: PathBuf,
}

#[derive(Args)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct ListRulesArgs {
    /// Render a single rule's detail card (description, options, escape
    /// hatches, false-positive shapes, related rules) instead of the
    /// flat catalogue.
    #[arg(value_name = "rule_id")]
    pub(crate) rule_id: Option<String>,
    #[arg(long, default_value = "text")]
    pub(crate) format: RuleListFormat,
    /// Preview the rules matched by one exact id, dotted prefix, or pillar selector.
    #[arg(long)]
    pub(crate) selector: Option<String>,
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long)]
    pub(crate) no_config: bool,
}

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct SummaryArgs {
    /// Files or directories to scan. Defaults to the current directory.
    #[arg(value_name = "paths")]
    pub(crate) paths: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long)]
    pub(crate) no_config: bool,
    #[arg(long, default_value = "text")]
    pub(crate) format: SummaryFormat,
    /// How many top rules and file offenders to list.
    #[arg(long, default_value_t = 10)]
    pub(crate) top: usize,
    /// Include paths ignored by Git ignore files or built-in default dirs; config `paths.ignore` and VCS internals remain blocked.
    #[arg(long)]
    pub(crate) include_ignored: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub(crate) enum CheckIgnoreFormat {
    Text,
    Json,
}

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct CheckIgnoreArgs {
    /// Paths to test against gruff's ignore policy. No analysis is run.
    #[arg(value_name = "paths", required = true)]
    pub(crate) paths: Vec<PathBuf>,
    #[arg(long, default_value = "text")]
    pub(crate) format: CheckIgnoreFormat,
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    #[arg(long, conflicts_with = "config")]
    pub(crate) no_config: bool,
}

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct CompletionArgs {
    /// Shell to emit completions for.
    #[arg(long, default_value = "bash")]
    pub(crate) shell: Shell,
}

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
pub(crate) struct InitArgs {
    /// Where to write the generated config. Defaults to .gruff-rs.yaml in the current directory.
    #[arg(long, default_value = ".gruff-rs.yaml")]
    pub(crate) output: PathBuf,
    /// Overwrite the output file if it already exists.
    #[arg(long)]
    pub(crate) force: bool,
    /// Print the generated config to stdout instead of writing to a file.
    #[arg(long, conflicts_with_all = ["output", "force"])]
    pub(crate) stdout: bool,
}
