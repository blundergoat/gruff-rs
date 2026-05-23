use super::*;

#[test]
pub(crate) fn process_command_skips_builders_and_fixed_pid_cleanup() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use std::process::Command;

/// Build a configured command for callers to execute.
pub(crate) fn background_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Stop a known child process tree on Windows.
pub fn stop_child_process(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F", "/T"])
        .output();
}

/// Run a user-provided shell command.
pub fn run_shell(command: &str) {
    let _ = Command::new("bash")
        .args(["-c", command])
        .spawn();
}
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let process_commands: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();
    assert_eq!(
        process_commands.len(),
        1,
        "only the dynamic shell execution should report; findings={process_commands:?}"
    );
    assert_eq!(process_commands[0].line, Some(19));
}

#[test]
pub(crate) fn file_length_skips_markdown_and_agent_hooks_not_source() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    fs::create_dir_all(dir.path().join(".codex/hooks")).expect("hook dir");

    let mut markdown = String::from("# Review\n");
    let mut hook = String::from("#!/usr/bin/env bash\n");
    let mut source = String::from("/// Long source fixture.\npub fn long_source() {}\n");
    for index in 0..620 {
        markdown.push_str(&format!("review line {index}\n"));
        hook.push_str(&format!("# hook line {index}\n"));
        source.push_str(&format!("// source line {index}\n"));
    }
    fs::write(dir.path().join("REVIEW_improvements.md"), markdown).expect("review write");
    fs::write(dir.path().join(".codex/hooks/deny-dangerous.sh"), hook).expect("hook write");
    fs::write(dir.path().join("src/long_source.rs"), source).expect("source write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(
        !report.findings.iter().any(|finding| {
            finding.rule_id == "size.file-length"
                && matches!(
                    finding.file_path.as_str(),
                    "REVIEW_improvements.md" | ".codex/hooks/deny-dangerous.sh"
                )
        }),
        "markdown and agent hooks should not produce file-length findings; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.file_path.as_str(), finding.line))
            .collect::<Vec<_>>()
    );
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "size.file-length" && finding.file_path == "src/long_source.rs"
        }),
        "long source files must still produce file-length findings; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.file_path.as_str(), finding.line))
            .collect::<Vec<_>>()
    );
}

#[test]
pub(crate) fn short_variable_accepts_aws_context_abbreviations_only() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    fs::create_dir_all(dir.path().join("src/aws")).expect("aws dir");
    fs::write(
        dir.path().join("src/aws/commands.rs"),
        r#"/// Analyze AWS resources.
pub fn analyze_ecs(cluster_arns: &[String]) {
    for ca in cluster_arns {
        let cn = ca.as_str();
        let sg = cn.len();
        let td = sg + 1;
        let zz = td + 1;
        println!("{ca} {cn} {sg} {td} {zz}");
    }
}
"#,
    )
    .expect("aws source write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    for allowed in ["ca", "cn", "sg", "td"] {
        assert!(
            !report.findings.iter().any(|finding| {
                finding.rule_id == "naming.short-variable"
                    && finding.symbol.as_deref() == Some(allowed)
            }),
            "AWS-context abbreviation `{allowed}` should stay silent; findings={:?}",
            report
                .findings
                .iter()
                .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
                .collect::<Vec<_>>()
        );
    }
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "naming.short-variable" && finding.symbol.as_deref() == Some("zz")
        }),
        "unrecognised two-letter names should still report; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}
