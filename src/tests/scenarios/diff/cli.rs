use super::*;

#[test]
pub(crate) fn diff_flags_accept_changed_region_forms() {
    // Git-executing modes require the --diff-git-unsafe opt-in (ADR-009 trust boundary).
    // The opt-in goes first: `--diff` allows hyphen values, so it would otherwise
    // swallow a trailing `--diff-git-unsafe` as its MODE.
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--diff-git-unsafe", "--diff"]).is_ok());
    assert!(
        Cli::try_parse_from(["gruff-rs", "analyse", "--diff-git-unsafe", "--diff", "-"]).is_ok()
    );
    assert!(Cli::try_parse_from([
        "gruff-rs",
        "analyse",
        "--diff-git-unsafe",
        "--since",
        "HEAD"
    ])
    .is_ok());
    // ...and are rejected without it.
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--diff"]).is_err());
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--since", "HEAD"]).is_err());
    // Git-free modes need no opt-in.
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--changed-ranges", "3-3,8-10"]).is_ok());
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--changed-scope", "hunk"]).is_ok());

    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("analyse")
        .expect("analyse subcommand exists")
        .render_long_help()
        .to_string();
    assert!(help.contains("--since"));
    assert!(help.contains("--changed-ranges"));
    assert!(help.contains("--changed-scope"));
    assert!(!help.contains("--diff-git-unsafe"));
}
