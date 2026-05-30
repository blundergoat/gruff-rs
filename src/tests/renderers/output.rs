use super::*;

#[test]
pub(crate) fn report_renderers_escape_and_preserve_contracts() {
    let report = sample_report();

    let json_output = render_report(&report, OutputFormat::Json);
    let decoded: Value = serde_json::from_str(&json_output).expect("json report");
    assert_eq!(decoded["schemaVersion"], "gruff.analysis.v2");
    assert_eq!(decoded["findings"][0]["ruleId"], "security.process-command");

    let sarif: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Sarif)).expect("sarif report");
    assert_eq!(OutputFormat::Sarif.as_str(), "sarif");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "gruff-rs");
    assert_eq!(
        sarif["runs"][0]["properties"]["gruffSchemaVersion"],
        "gruff.analysis.v2"
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
pub(crate) fn summary_top_file_limit_is_not_capped_by_score_report() {
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

    let json_output = crate::summary::render(&report, 12, SummaryFormat::Json, 1);
    let decoded: Value = serde_json::from_str(&json_output).expect("summary json");

    assert_eq!(decoded["topFiles"].as_array().expect("top files").len(), 12);
}

#[test]
pub(crate) fn summary_json_pillar_shape_includes_canonical_fields_with_penalty() {
    // The canonical `gruff.summary.v2` pillar exposes 9 fields (cross-port contract).
    // `penalty` is the raw unclamped value subtracted from 100 before clamping, so a
    // saturated pillar still surfaces the underlying penalty for worst-pillar ranking.
    let mut findings: Vec<Finding> = (0..200)
        .map(|index| {
            test_finding(
                "docs.todo-density",
                &format!("src/many_{index}.rs"),
                1,
                Severity::Advisory,
                Pillar::Documentation,
            )
        })
        .collect();
    findings.push(test_finding(
        "complexity.cyclomatic",
        "src/complex.rs",
        1,
        Severity::Error,
        Pillar::Complexity,
    ));
    let report = sample_report_with(findings, Vec::new());
    let decoded: Value =
        serde_json::from_str(&crate::summary::render(&report, 5, SummaryFormat::Json, 1))
            .expect("summary json");
    assert_eq!(decoded["schemaVersion"], "gruff.summary.v2");
    let pillars = decoded["pillars"].as_array().expect("pillars array");
    let find_pillar = |slug: &'static str| {
        pillars
            .iter()
            .find(|pillar| pillar["pillar"] == slug)
            .unwrap_or_else(|| panic!("{slug} pillar present"))
    };

    let documentation = find_pillar("documentation");
    let fields: BTreeSet<&str> = documentation
        .as_object()
        .expect("pillar object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "advisory",
        "applicable",
        "error",
        "findings",
        "grade",
        "penalty",
        "pillar",
        "score",
        "warning",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        fields, expected,
        "JSON pillar must expose 9 canonical fields"
    );

    // Documentation: 200 advisory * (1.5 * 1.0) = 300.0 unclamped; score clamps to 0.
    assert_eq!(documentation["score"].as_f64(), Some(0.0));
    assert_eq!(documentation["penalty"].as_f64(), Some(300.0));
    assert_eq!(documentation["grade"], "F");
    assert!(documentation["applicable"].is_boolean());
    // Complexity: 1 error * (8.0 * 1.0) = 8.0; score 92.0.
    let complexity = find_pillar("complexity");
    assert_eq!(complexity["penalty"].as_f64(), Some(8.0));
    assert_eq!(complexity["score"].as_f64(), Some(92.0));
    assert!(complexity["applicable"].is_boolean());
    // Empty pillar still carries `penalty: 0.0` (no negative-zero leak).
    let security = find_pillar("security");
    assert_eq!(security["penalty"].as_f64(), Some(0.0));
    assert_eq!(security["score"].as_f64(), Some(100.0));
    assert!(security["applicable"].is_boolean());
}

#[test]
pub(crate) fn non_score_pillars_are_inapplicable_and_excluded_from_composite() {
    // A custom rule emitting `Pillar::Waste` (not in SCORE_PILLARS) must surface in the
    // pillar list with `applicable: false` AND must not drag down `composite`. Otherwise
    // downstream consumers that trust `applicable` recompute a different composite.
    let waste = test_finding(
        "custom.waste",
        "src/wasteful.rs",
        1,
        Severity::Error,
        Pillar::Waste,
    );
    let report = sample_report_with(vec![waste], Vec::new());

    // Composite must ignore Waste's 8.0 penalty: every SCORE_PILLARS pillar is 100.0,
    // and Waste is filtered out before averaging.
    assert_eq!(report.score.composite, 100.0);

    let decoded: Value =
        serde_json::from_str(&crate::summary::render(&report, 5, SummaryFormat::Json, 1))
            .expect("summary json");
    let waste_pillar = decoded["pillars"]
        .as_array()
        .expect("pillars array")
        .iter()
        .find(|pillar| pillar["pillar"] == "waste")
        .expect("waste pillar present");
    assert_eq!(waste_pillar["applicable"], false);
    assert_eq!(waste_pillar["penalty"].as_f64(), Some(8.0));
}

#[test]
pub(crate) fn pillar_ties_sort_by_canonical_label_not_enum_order() {
    // Tie-break contract is `pillar ASC by kebab-case label`, not enum declaration order.
    // Size (enum index 0) and Complexity (enum index 1) with equal finding counts would
    // sort as `size, complexity` under the derived `Ord`; the canonical contract is
    // `complexity, size`.
    let findings = vec![
        test_finding(
            "size.function-length",
            "src/big.rs",
            1,
            Severity::Warning,
            Pillar::Size,
        ),
        test_finding(
            "complexity.cyclomatic",
            "src/complex.rs",
            1,
            Severity::Warning,
            Pillar::Complexity,
        ),
    ];
    let report = sample_report_with(findings, Vec::new());
    let markdown = render_report(&report, OutputFormat::Markdown);

    let complexity_pos = markdown.find("| complexity |").expect("complexity row");
    let size_pos = markdown.find("| size |").expect("size row");
    assert!(
        complexity_pos < size_pos,
        "tied pillars must sort by kebab-case label (complexity < size):\n{markdown}"
    );
}

#[test]
pub(crate) fn html_pillars_section_matches_canonical_contract() {
    // Construct a report with multiple pillars at different finding counts so we can verify
    // (1) the seven canonical columns (pillar, grade, score, findings, advisory, warning, error)
    // and (2) the canonical sort order: findings DESC, then pillar ASC.
    let findings = vec![
        test_finding(
            "complexity.cyclomatic",
            "src/complex.rs",
            1,
            Severity::Warning,
            Pillar::Complexity,
        ),
        test_finding(
            "complexity.cyclomatic",
            "src/complex.rs",
            2,
            Severity::Advisory,
            Pillar::Complexity,
        ),
        test_finding(
            "complexity.cyclomatic",
            "src/complex.rs",
            3,
            Severity::Error,
            Pillar::Complexity,
        ),
        test_finding(
            "naming.snake_case",
            "src/named.rs",
            1,
            Severity::Advisory,
            Pillar::Naming,
        ),
        test_finding(
            "docs.missing",
            "src/docs.rs",
            1,
            Severity::Advisory,
            Pillar::Documentation,
        ),
        test_finding(
            "docs.missing",
            "src/docs.rs",
            2,
            Severity::Warning,
            Pillar::Documentation,
        ),
    ];
    let report = sample_report_with(findings, Vec::new());
    let html = render_report(&report, OutputFormat::Html);

    // Canonical table shell: `<table class="pillar-list">` with the seven canonical
    // headers in order. Matches gruff-go / gruff-ts / gruff-py / gruff-php.
    assert!(
        html.contains("<table class=\"pillar-list\">"),
        "missing canonical pillar-list table"
    );
    for header in [
        "<th scope=\"col\">pillar</th>",
        "<th scope=\"col\" class=\"num\">grade</th>",
        "<th scope=\"col\" class=\"num\">score</th>",
        "<th scope=\"col\" class=\"num\">findings</th>",
        "<th scope=\"col\" class=\"num\">advisory</th>",
        "<th scope=\"col\" class=\"num\">warning</th>",
        "<th scope=\"col\" class=\"num\">error</th>",
    ] {
        assert!(
            html.contains(header),
            "missing pillar table header {header:?}"
        );
    }

    // Pillar name cells use the canonical `<td class="pillar-name">` marker (lowercase
    // pillar slug). Cover all three pillars seeded by the fixture.
    for pillar in ["complexity", "documentation", "naming"] {
        let marker = format!("<td class=\"pillar-name\">{pillar}</td>");
        assert!(
            html.contains(&marker),
            "missing pillar-name cell for {pillar}"
        );
    }

    // Card-grid artefacts must not leak: no `<div class="pillar">` cards, no
    // `key`/`val`/`name`/`breakdown` plumbing, no plural severity labels.
    for stale in [
        "<div class=\"pillar\">",
        "class=\"pillar-grid\"",
        "<span class=\"key\">",
        "<div class=\"breakdown\">",
        ">advisories<",
        ">warnings<",
        ">errors<",
    ] {
        assert!(
            !html.contains(stale),
            "stale card-grid markup found: {stale}"
        );
    }

    // Grade is rendered inside a `<span class="grade-pill {letter}">` pill (canonical
    // shape). Spot-check the complexity row's grade-pill exists.
    assert!(
        html.contains("<span class=\"grade-pill "),
        "pillar table should render grades inside .grade-pill"
    );

    // Sort contract: findings DESC, then pillar ASC (matches `pillar_digests` in
    // summary.rs, which is the Phase 2 canonical contract). Complexity has 3 findings
    // (highest), Documentation has 2, Naming has 1.
    let complexity_pos = html
        .find("<td class=\"pillar-name\">complexity</td>")
        .expect("complexity row");
    let documentation_pos = html
        .find("<td class=\"pillar-name\">documentation</td>")
        .expect("documentation row");
    let naming_pos = html
        .find("<td class=\"pillar-name\">naming</td>")
        .expect("naming row");
    assert!(
        complexity_pos < documentation_pos,
        "complexity (3 findings) should come before documentation (2)"
    );
    assert!(
        documentation_pos < naming_pos,
        "documentation (2 findings) should come before naming (1)"
    );

    // Score must render with two decimal places (canonical contract). Spot-check that
    // the score cell carries a ".NN<" suffix for at least one pillar (complexity 86.50
    // when the fixture seeds three findings: 1 advisory, 1 warning, 1 error).
    assert!(
        html.contains(">86.50<"),
        "expected complexity score 86.50 in HTML, html = {html}"
    );

    // Per-severity cells use the tier class only when count > 0; zero stays neutral.
    // Complexity has advisory=1 (note), warning=1 (warn), error=1 (fail).
    assert!(
        html.contains("<td class=\"num note\">1</td>"),
        "expected non-zero advisory cell to carry .note tier class"
    );
    assert!(
        html.contains("<td class=\"num warn\">1</td>"),
        "expected non-zero warning cell to carry .warn tier class"
    );
    assert!(
        html.contains("<td class=\"num fail\">1</td>"),
        "expected non-zero error cell to carry .fail tier class"
    );
    // Naming has advisory=1, warning=0, error=0 — the zero cells must be neutral.
    assert!(
        html.contains("<td class=\"num\">0</td>"),
        "expected zero-count cells to stay neutral (no tier class)"
    );
}

#[test]
pub(crate) fn markdown_pillars_section_matches_canonical_contract() {
    // Construct a report with multiple pillars at different finding counts so we can verify
    // (1) the canonical `## Pillars` heading, (2) the seven canonical columns, and
    // (3) the canonical sort: findings DESC, then pillar ASC.
    let findings = vec![
        test_finding(
            "complexity.cyclomatic",
            "src/complex.rs",
            1,
            Severity::Warning,
            Pillar::Complexity,
        ),
        test_finding(
            "complexity.cyclomatic",
            "src/complex.rs",
            2,
            Severity::Advisory,
            Pillar::Complexity,
        ),
        test_finding(
            "complexity.cyclomatic",
            "src/complex.rs",
            3,
            Severity::Error,
            Pillar::Complexity,
        ),
        test_finding(
            "naming.snake_case",
            "src/named.rs",
            1,
            Severity::Advisory,
            Pillar::Naming,
        ),
        test_finding(
            "docs.missing",
            "src/docs.rs",
            1,
            Severity::Advisory,
            Pillar::Documentation,
        ),
        test_finding(
            "docs.missing",
            "src/docs.rs",
            2,
            Severity::Warning,
            Pillar::Documentation,
        ),
    ];
    let report = sample_report_with(findings, Vec::new());
    let markdown = render_report(&report, OutputFormat::Markdown);

    // Canonical heading.
    assert!(
        markdown.contains("\n## Pillars\n"),
        "missing canonical `## Pillars` heading"
    );

    // Canonical 7-column header + separator (cross-port harmonised contract).
    assert!(
        markdown.contains("| Pillar | Grade | Score | Findings | Advisory | Warning | Error |"),
        "missing canonical pillar table header in markdown:\n{markdown}"
    );
    assert!(
        markdown.contains("| --- | --- | ---: | ---: | ---: | ---: | ---: |"),
        "missing canonical pillar table separator in markdown:\n{markdown}"
    );

    // Score must render with two decimals. The complexity row composite from the fixture is
    // 86.50 (1 advisory + 1 warning + 1 error).
    assert!(
        markdown.contains(" 86.50 "),
        "expected complexity score 86.50 in markdown:\n{markdown}"
    );

    // Sort contract: findings DESC, then pillar ASC. Complexity (3 findings) before
    // Documentation (2) before Naming (1). Pillar names appear as the leading column cell
    // (` <name> | `).
    let complexity_pos = markdown
        .find("| complexity |")
        .expect("complexity row in markdown");
    let documentation_pos = markdown
        .find("| documentation |")
        .expect("documentation row in markdown");
    let naming_pos = markdown.find("| naming |").expect("naming row in markdown");
    assert!(
        complexity_pos < documentation_pos,
        "complexity (3 findings) must precede documentation (2)"
    );
    assert!(
        documentation_pos < naming_pos,
        "documentation (2 findings) must precede naming (1)"
    );

    // The Pillars block must appear AFTER the masthead score line and BEFORE the bulleted
    // findings list (consistent with the cross-port layout: header, pillars, findings).
    let score_pos = markdown.find("Score: **").expect("score header");
    let pillars_pos = markdown.find("## Pillars").expect("pillars heading");
    assert!(
        score_pos < pillars_pos,
        "Pillars section must follow the score header"
    );
    let first_finding_pos = markdown
        .find("\n- `")
        .expect("seeded fixture must produce a bulleted finding line");
    assert!(
        pillars_pos < first_finding_pos,
        "Pillars section must precede the findings list"
    );

    // Per-severity counts: complexity has advisory=1, warning=1, error=1.
    assert!(
        markdown.contains("| complexity | B | 86.50 | 3 | 1 | 1 | 1 |"),
        "complexity row should expose the 7 canonical cells exactly:\n{markdown}"
    );
    // Naming has advisory=1, warning=0, error=0 — zero cells must render literally as `0`.
    assert!(
        markdown.contains("| naming | A | 98.50 | 1 | 1 | 0 | 0 |"),
        "naming row should carry zero counts for warning and error:\n{markdown}"
    );
}
