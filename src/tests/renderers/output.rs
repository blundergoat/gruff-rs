//! Output renderer contracts for reports assembled directly or through analysis.
//! These tests let CLI users trust that each format preserves report data while
//! applying only the escaping required by its own output protocol.

use super::*;

const HOSTILE_RULE_ID: &str = "custom.`rule``|[id]\r\n# heading";
const HOSTILE_FILE_PATH: &str = "src/`path``|[name](target)<script>&\r\n- item.rs";
const HOSTILE_MESSAGE: &str =
    "message | `tick`` [link](target) <script>&\r\n- second\n# heading\n``` fence";

/// Build one finding and delta whose controlled fields exercise Markdown structure.
/// A CLI user reaches the same renderer after scanning an untrusted source tree.
fn hostile_renderer_report() -> AnalysisReport {
    let mut report = sample_report_with(
        vec![Finding::new(FindingDescriptor {
            rule_id: HOSTILE_RULE_ID.to_string(),
            message: HOSTILE_MESSAGE.to_string(),
            file_path: HOSTILE_FILE_PATH.to_string(),
            line: Some(9),
            severity: Severity::Warning,
            pillar: Pillar::Documentation,
            confidence: Confidence::High,
            symbol: None,
            remediation: None,
            metadata: json!({}),
        })],
        Vec::new(),
    );
    report.per_rule_deltas = Some(vec![RuleDelta {
        rule_id: HOSTILE_RULE_ID.to_string(),
        introduced: 1,
        removed: 0,
        net: 1,
    }]);
    report
}

/// Hostile finding fields stay inside one inert Markdown finding bullet.
#[test]
pub(crate) fn markdown_renderer_keeps_hostile_finding_fields_in_one_inert_bullet() {
    let report = hostile_renderer_report();
    let markdown = render_report(&report, OutputFormat::Markdown);
    let repeated_markdown = render_report(&report, OutputFormat::Markdown);
    let expected_finding = concat!(
        "\n- ``` custom.`rule``|[id]\\r\\n# heading ``` ",
        "``` src/`path``|[name](target)<script>&\\r\\n- item.rs ```:9 - ",
        "message \\| \\`tick\\`\\` \\[link\\]\\(target\\) &lt;script&gt;&amp;",
        "\\r\\n\\- second\\n\\# heading\\n\\`\\`\\` fence",
    );
    let expected_delta = "\nTop 5 regressed: +1 ``` custom.`rule``|[id]\\r\\n# heading ```\n";

    assert!(markdown.contains(expected_delta), "{markdown}");
    assert!(
        markdown.contains(expected_finding),
        "hostile fields must render as one escaped finding:\n{markdown}"
    );
    assert_eq!(markdown.matches("\n- ").count(), 1, "{markdown}");
    assert_eq!(markdown.matches("\n## ").count(), 1, "{markdown}");
    assert!(markdown.contains("| Pillar | Grade | Score | Findings | Advisory | Warning | Error |"));
    // Hostile pipes cannot add a row to the fixed header, separator, and eleven pillar rows.
    assert_eq!(
        markdown
            .lines()
            .filter(|line| line.starts_with("| "))
            .count(),
        13,
        "{markdown}"
    );
    // Hostile backticks remain inline code content and never open a fenced block.
    assert_eq!(
        markdown
            .lines()
            .filter(|line| line.starts_with("```"))
            .count(),
        0,
        "{markdown}"
    );
    // A missing separator means the fixed finding layout changed before plain-text review.
    let rendered_message = markdown
        .rsplit_once(" - ")
        .map(|(_, message)| message)
        .expect("finding message separator");
    assert!(!rendered_message.contains("<script>"), "{markdown}");
    assert!(!markdown.contains("\n# heading"), "{markdown}");
    assert!(!markdown.contains("[link](target)"), "{markdown}");
    assert!(!markdown.contains('\r'), "{markdown:?}");
    assert_eq!(markdown, repeated_markdown);
}

/// Markdown hardening leaves GitHub workflow-command bytes unchanged for the same report.
#[test]
pub(crate) fn github_renderer_is_unchanged_for_hostile_markdown_report() {
    let github = render_report(&hostile_renderer_report(), OutputFormat::Github);

    assert_eq!(
        github,
        concat!(
            "::warning file=src/`path``|[name](target)<script>&%0D%0A- item.rs,",
            "line=9,title=custom.`rule``|[id]%0D%0A# heading::",
            "message | `tick`` [link](target) <script>&%0D%0A- second",
            "%0A# heading%0A``` fence",
        )
    );
}

#[test]
pub(crate) fn report_renderers_escape_and_preserve_contracts() {
    let report = sample_report();

    let json_output = render_report(&report, OutputFormat::Json);
    let decoded: Value = serde_json::from_str(&json_output).expect("json report");
    assert_eq!(decoded["schemaVersion"], "gruff.analysis.v3");
    assert_eq!(decoded["findings"][0]["ruleId"], "security.process-command");
    assert_eq!(decoded["findings"][0]["file"], "src/lib.rs");
    assert!(decoded["findings"][0].get("filePath").is_none());
    assert!(decoded["findings"][0].get("column").is_none());
    assert!(decoded["findings"][0].get("endLine").is_none());
    assert_eq!(
        decoded["findings"][0]["metadata"]["locationPrecision"],
        "line-only"
    );
    assert_eq!(
        decoded["findings"][0]["extensions"]["rs"]["finding"]["scope"],
        "symbol"
    );
    assert_eq!(decoded["score"]["topOffenders"][0]["file"], "src/lib.rs");
    assert!(decoded["score"]["topOffenders"][0]
        .get("filePath")
        .is_none());

    let sarif: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Sarif)).expect("sarif report");
    assert_eq!(OutputFormat::Sarif.as_str(), "sarif");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "gruff-rs");
    assert_eq!(
        sarif["runs"][0]["properties"]["gruffSchemaVersion"],
        "gruff.analysis.v3"
    );
    let sarif_rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("sarif rules");
    let sarif_rule_ids: Vec<&str> = sarif_rules
        .iter()
        .map(|rule| rule["id"].as_str().expect("sarif rule id"))
        .collect();
    let mut sorted_rule_ids = sarif_rule_ids.clone();
    sorted_rule_ids.sort_unstable();
    assert_eq!(sarif_rule_ids, sorted_rule_ids);
    let rule_index = sarif_rule_ids
        .iter()
        .position(|rule_id| *rule_id == "security.process-command")
        .expect("security rule in sarif driver");
    let sarif_result = &sarif["runs"][0]["results"][0];
    assert_eq!(sarif_result["ruleId"], "security.process-command");
    assert_eq!(sarif_result["ruleIndex"].as_u64(), Some(rule_index as u64));
    assert_eq!(sarif_result["level"], "warning");
    assert_eq!(
        sarif_result["message"]["text"],
        "Use <escaped> command & args"
    );
    assert_eq!(
        sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/lib.rs"
    );
    assert_eq!(
        sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"],
        7
    );
    assert_eq!(
        sarif_result["partialFingerprints"]["gruffFingerprint"].as_str(),
        Some(report.findings[0].fingerprint.as_str())
    );

    let text = render_report(&report, OutputFormat::Text);
    assert!(text.contains("gruff-rs"));
    assert!(text.contains("security.process-command"));

    let markdown = render_report(&report, OutputFormat::Markdown);
    assert!(markdown.starts_with("# gruff-rs report"));
    assert!(markdown.contains("`security.process-command`"));

    let github = render_report(&report, OutputFormat::Github);
    assert!(github.starts_with("::warning file=src/lib.rs,line=7"));

    let html = render_report(&report, OutputFormat::Html);
    assert!(html.contains("Use &lt;escaped&gt; command &amp; args"));
    assert!(!html.contains("Use <escaped> command & args"));

    let hotspot: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Hotspot)).expect("hotspot json");
    assert_eq!(hotspot["schemaVersion"], "gruff.hotspot.v1");
    assert_eq!(hotspot["files"][0]["filePath"], "src/lib.rs");
}

#[test]
pub(crate) fn report_json_emits_optional_locations_only_when_present() {
    let mut finding = test_finding(
        "complexity.cyclomatic",
        "src/lib.rs",
        7,
        Severity::Warning,
        Pillar::Complexity,
    );
    finding.column = Some(4);
    finding.end_line = Some(9);
    finding.metadata = json!({"native": "preserved"});
    let report = sample_report_with(vec![finding], Vec::new());

    let decoded: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Json)).expect("json report");
    let emitted = &decoded["findings"][0];

    assert_eq!(emitted["column"], 4);
    assert_eq!(emitted["endLine"], 9);
    assert_eq!(emitted["metadata"]["native"], "preserved");
    assert_eq!(
        emitted["metadata"]["locationPrecision"],
        "scanner-pinpointed"
    );
}

#[test]
pub(crate) fn text_renderers_surface_ignored_paths_and_baseline_guidance() {
    let mut report = sample_report();
    report.paths.ignored_paths = vec!["target".to_string(), "node_modules".to_string()];

    let text = render_report(&report, OutputFormat::Text);
    assert!(text.contains("ignored: 2"));
    assert!(text.contains("pass --include-ignored"));

    let summary = crate::summary::render(&report, 10, SummaryFormat::Text, 1);
    assert!(summary.contains("ignored: 2"));
    assert!(summary.contains("pass --include-ignored"));
    assert!(summary.contains("gruff-rs analyse --generate-baseline"));

    report.baseline = Some(BaselineReport {
        path: "gruff-baseline.json".to_string(),
        source: "default".to_string(),
        suppressed: 1,
        new_count: 2,
        unchanged_count: 1,
        absent_count: 3,
        generated: false,
    });
    let baseline_summary = crate::summary::render(&report, 10, SummaryFormat::Text, 1);
    assert!(baseline_summary.contains("baseline: 2 new, 1 unchanged, 3 resolved"));
    assert!(baseline_summary.contains("gruff-rs analyse --no-baseline"));
    assert!(!baseline_summary.contains("gruff-rs analyse --generate-baseline"));
}

#[test]
pub(crate) fn github_renderer_escapes_annotation_properties() {
    let report = sample_report_with(
        vec![Finding::new(FindingDescriptor {
            rule_id: "custom.rule:id".to_string(),
            message: "Message with 100% and\nnewline".to_string(),
            file_path: "src/weird,path:100%.rs".to_string(),
            line: Some(3),
            severity: Severity::Warning,
            pillar: Pillar::Documentation,
            confidence: Confidence::High,
            symbol: None,
            remediation: None,
            metadata: json!({}),
        })],
        Vec::new(),
    );

    let github = render_report(&report, OutputFormat::Github);

    assert!(github.starts_with(
        "::warning file=src/weird%2Cpath%3A100%25.rs,line=3,title=custom.rule%3Aid::"
    ));
    assert!(github.ends_with("Message with 100%25 and%0Anewline"));
}

#[test]
pub(crate) fn report_json_keeps_deterministic_finding_order() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("b.rs"), "pub fn process() {}\n").expect("b write");
    fs::write(dir.path().join("a.rs"), "pub fn process() {}\n").expect("a write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("b.rs"), PathBuf::from("a.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    let ordered_paths: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.file_path.as_str())
        .collect();
    assert_eq!(ordered_paths, vec!["a.rs", "a.rs", "b.rs", "b.rs"]);
}

#[test]
pub(crate) fn summary_json_is_the_exact_findings_free_analysis_projection() {
    let findings: Vec<Finding> = (0..12)
        .map(|index| {
            test_finding(
                "docs.todo-density",
                &format!("src/file_{index}.rs"),
                1,
                Severity::Advisory,
                Pillar::Documentation,
            )
        })
        .collect();
    let report = sample_report_with(findings, Vec::new());

    let mut expected: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Json)).expect("analysis json");
    let expected_object = expected.as_object_mut().expect("analysis object");
    expected_object.insert(
        "schemaVersion".to_string(),
        Value::String("gruff.summary.v3".to_string()),
    );
    expected_object.remove("findings");

    let top_one: Value =
        serde_json::from_str(&crate::summary::render(&report, 1, SummaryFormat::Json, 1))
            .expect("summary json");
    let top_twelve: Value =
        serde_json::from_str(&crate::summary::render(&report, 12, SummaryFormat::Json, 1))
            .expect("summary json");

    assert_eq!(top_one, expected);
    assert_eq!(top_twelve, expected);
    assert!(top_one.get("findings").is_none());
}

#[test]
pub(crate) fn bounded_deep_scan_note_reaches_every_supported_output_surface() {
    let diagnostic = RunDiagnostic {
        diagnostic_type: "bounded-deep-scan".to_string(),
        message: "path=src/large.rs; lines=20001; bytes=2000001; maxLines=20000; maxBytes=2000000; override=cli. Text-level rules (size, sensitive-data, config) still ran; masking, block parsing, AST walking, and other deep script analysis were skipped.".to_string(),
        file_path: Some("src/large.rs".to_string()),
        line: Some(1),
        invalidates_run: Some(false),
    };

    for format in [
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::Sarif,
        OutputFormat::Html,
        OutputFormat::Markdown,
        OutputFormat::Github,
        OutputFormat::Hotspot,
    ] {
        let output = render_report(
            &sample_report_with(Vec::new(), vec![diagnostic.clone()]),
            format,
        );
        assert!(output.contains("bounded-deep-scan"), "{format:?}: {output}");
        assert!(
            output.replace('\\', "").contains("override=cli"),
            "{format:?}: {output}"
        );
    }

    for format in [SummaryFormat::Text, SummaryFormat::Json] {
        let output = crate::summary::render(
            &sample_report_with(Vec::new(), vec![diagnostic.clone()]),
            10,
            format,
            1,
        );
        assert!(output.contains("bounded-deep-scan"), "{format:?}: {output}");
        assert!(output.contains("override=cli"), "{format:?}: {output}");
    }

    let hook: Value = serde_json::from_str(&crate::hook::render_hook_report(
        sample_report_with(Vec::new(), vec![diagnostic]),
        false,
        false,
    ))
    .expect("hook report JSON");
    assert_eq!(hook["diagnostics"][0]["type"], "bounded-deep-scan");
    assert_eq!(hook["diagnostics"][0]["invalidatesRun"], false);
    assert!(hook["diagnostics"][0]["message"]
        .as_str()
        .is_some_and(|message| message.contains("override=cli")));
}
