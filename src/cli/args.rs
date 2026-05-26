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
    /// Severity gate. Defaults to `error` (M08a). Falls back to
    /// `minimumSeverity.analyse:` in `.gruff-rs.yaml` when omitted.
    #[arg(long)]
    pub(crate) fail_on: Option<FailThreshold>,
    /// Include paths ignored by Git ignore files or paths.ignore; VCS internals remain blocked.
    #[arg(long)]
    pub(crate) include_ignored: bool,
    #[arg(long, value_name = "MODE", requires = "diff_git_unsafe")]
    pub(crate) diff: Option<String>,
    #[arg(long, value_name = "PATH", conflicts_with = "diff")]
    pub(crate) diff_patch: Option<PathBuf>,
    #[arg(long, requires = "diff")]
    pub(crate) diff_git_unsafe: bool,
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
    /// Include paths ignored by Git ignore files or paths.ignore; VCS internals remain blocked.
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
    /// Include paths ignored by Git ignore files or paths.ignore; VCS internals remain blocked.
    #[arg(long)]
    pub(crate) include_ignored: bool,
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
