use super::*;

fn summary(advisory: usize, warning: usize, error: usize) -> Summary {
    Summary {
        advisory,
        warning,
        error,
        total: advisory + warning + error,
    }
}

// M02 Mid-Implementation Proof: Gate::evaluate is a pure function over the report
// summary, classifying each configured shape deterministically.
#[test]
pub(crate) fn gate_evaluate_is_pure_over_severity_counts() {
    // An omitted cap is unlimited; an empty gate never fails.
    let empty = Gate::default();
    assert!(!empty.evaluate(&summary(50, 9, 0)).fails);

    // Per-severity cap: error over, others under -> fails, with an "(over)" marker.
    let error_gate = Gate {
        error: Some(0),
        warning: Some(10),
        advisory: Some(50),
        ..Gate::default()
    };
    let tripped = error_gate.evaluate(&summary(5, 3, 1));
    assert!(tripped.fails);
    assert!(tripped.message.contains("error 1/0 (over)"));
    assert!(tripped.message.contains("warning 3/10"));
    assert!(tripped.message.starts_with("Quality gate trip:"));

    // Within every cap -> pass.
    assert!(!error_gate.evaluate(&summary(50, 10, 0)).fails);

    // Total cap independent of per-severity caps.
    let total_gate = Gate {
        total: Some(2),
        ..Gate::default()
    };
    assert!(total_gate.evaluate(&summary(2, 1, 0)).fails);
    assert!(!total_gate.evaluate(&summary(1, 1, 0)).fails);

    // onMatch: warn breaches but does not fail; the decision reads "warn".
    let warn_gate = Gate {
        error: Some(0),
        on_match: GateOnMatch::Warn,
        ..Gate::default()
    };
    let warned = warn_gate.evaluate(&summary(0, 0, 1));
    assert!(!warned.fails);
    assert!(warned.message.starts_with("Quality gate warn:"));

    // A zero-finding scan with an advisory cap passes.
    assert!(!error_gate.evaluate(&summary(0, 0, 0)).fails);
}

// ADR-003 M02 addendum: the gate block evaluates before --fail-on; a trip with
// onMatch: fail is exit 1 (ThresholdHit), warn mode leaves the exit unchanged.
#[test]
pub(crate) fn gate_drives_classify_precedence_over_fail_on() {
    let report = sample_report_with(
        vec![test_finding(
            "sensitive-data.api-key-pattern",
            "src/lib.rs",
            1,
            Severity::Error,
            Pillar::SensitiveData,
        )],
        Vec::new(),
    );

    // Gate trips on the error even though --fail-on is none.
    let fail_gate = Gate {
        error: Some(0),
        ..Gate::default()
    };
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None, Some(&fail_gate)),
        RunOutcome::ThresholdHit,
    );

    // Warn mode records the diagnostic but does not change the exit.
    let warn_gate = Gate {
        error: Some(0),
        on_match: GateOnMatch::Warn,
        ..Gate::default()
    };
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None, Some(&warn_gate)),
        RunOutcome::Success,
    );

    // No gate: behaviour falls back to --fail-on alone (legacy unchanged).
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None, None),
        RunOutcome::Success,
    );
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::Error, None),
        RunOutcome::ThresholdHit,
    );
}

// ADR-003 strict validation: a valid gate parses; bad shapes are config errors.
#[test]
pub(crate) fn gate_block_parses_strictly() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme");
    fs::write(dir.path().join("sample.rs"), "pub fn ready() {}\n").expect("fixture");

    let analyse = |dir: &Path| {
        run_project_analysis(
            dir,
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
    };

    // Valid: nested severity caps, total, and onMatch parse into config.gate.
    write_config(
        dir.path(),
        "gate:\n  total: 200\n  severity:\n    error: 0\n    warning: 10\n  onMatch: warn\n",
    );
    assert!(analyse(dir.path()).is_ok());

    // Empty gate block is valid (gates nothing).
    write_config(dir.path(), "gate: {}\n");
    assert!(analyse(dir.path()).is_ok());

    // Unknown key under gate.severity is rejected, naming the offending path.
    write_config(dir.path(), "gate:\n  severity:\n    severtiy: 0\n");
    let err = analyse(dir.path()).expect_err("typo rejected");
    assert!(err.contains("severtiy"), "{err}");
    assert!(err.contains("gate.severity"), "{err}");

    // Negative / non-integer count is rejected.
    write_config(dir.path(), "gate:\n  severity:\n    error: -1\n");
    let err = analyse(dir.path()).expect_err("negative rejected");
    assert!(err.contains("gate.severity.error"), "{err}");

    // onMatch other than fail/warn is rejected.
    write_config(dir.path(), "gate:\n  onMatch: boom\n");
    let err = analyse(dir.path()).expect_err("bad onMatch rejected");
    assert!(err.contains("gate.onMatch"), "{err}");

    // A valid scope (`new`/`all`) parses. (`new`'s missing-baseline check is a
    // runtime diagnostic, not a parse error, so `all` is used here for a clean run.)
    write_config(dir.path(), "gate:\n  scope: all\n");
    assert!(analyse(dir.path()).is_ok());

    // An unknown scope value is rejected, naming the offending path.
    write_config(dir.path(), "gate:\n  scope: bogus\n");
    let err = analyse(dir.path()).expect_err("bad scope rejected");
    assert!(err.contains("gate.scope"), "{err}");
}

fn test_baseline_report(generated: bool) -> BaselineReport {
    BaselineReport {
        path: "gruff-baseline.json".to_string(),
        source: "explicit".to_string(),
        suppressed: 0,
        new_count: 0,
        unchanged_count: 0,
        absent_count: 0,
        generated,
    }
}

// ADR-003 baseline-aware gate-scope addendum: `scope: new` (and `--fail-on-new`)
// needs an *applied* baseline to define "new"; otherwise the run is a config error.
#[test]
pub(crate) fn gate_scope_new_requires_applied_baseline() {
    let new_gate = Gate {
        error: Some(0),
        scope: GateScope::New,
        ..Gate::default()
    };

    // No baseline -> precondition error naming the baseline requirement.
    let mut report = sample_report_with(Vec::new(), Vec::new());
    let error = new_gate
        .scope_precondition_error(&report)
        .expect("scope: new without a baseline is a config error");
    assert!(error.contains("baseline"), "{error}");

    // A *generated* baseline is not an applied comparison -> still an error.
    report.baseline = Some(test_baseline_report(true));
    assert!(new_gate.scope_precondition_error(&report).is_some());

    // An applied baseline satisfies the precondition.
    report.baseline = Some(test_baseline_report(false));
    assert!(new_gate.scope_precondition_error(&report).is_none());

    // `scope: all` and the default never require a baseline.
    let no_baseline = sample_report_with(Vec::new(), Vec::new());
    let all_gate = Gate {
        scope: GateScope::All,
        ..Gate::default()
    };
    assert!(all_gate.scope_precondition_error(&no_baseline).is_none());
    assert!(Gate::default()
        .scope_precondition_error(&no_baseline)
        .is_none());
}

// `scope: all` counts the pre-baseline finding set; the default and `new` count the
// post-baseline report summary (new-only when a baseline is applied).
#[test]
pub(crate) fn gate_scope_all_counts_pre_baseline_findings() {
    let mut report = sample_report_with(Vec::new(), Vec::new());
    // Post-baseline summary: zero new errors. Pre-baseline: one (baselined) error.
    report.summary = summary(0, 0, 0);
    report.all_findings_summary = Some(summary(0, 0, 1));

    let cap = |scope| Gate {
        error: Some(0),
        scope,
        ..Gate::default()
    };

    // Default/`new` gate the post-baseline summary -> within the cap -> pass.
    assert!(!cap(GateScope::Current).evaluate_report(&report).fails);
    assert!(!cap(GateScope::New).evaluate_report(&report).fails);
    // `all` gates the pre-baseline summary -> over the cap -> fails.
    assert!(cap(GateScope::All).evaluate_report(&report).fails);

    // With no captured pre-baseline summary, `all` falls back to the report summary.
    report.all_findings_summary = None;
    assert!(!cap(GateScope::All).evaluate_report(&report).fails);
}

// A gate-config-error diagnostic is fatal: exit 2 (DiagnosticsFailed), ahead of any
// gate or --fail-on evaluation.
#[test]
pub(crate) fn gate_config_error_diagnostic_is_exit_2() {
    let report = sample_report_with(
        Vec::new(),
        vec![RunDiagnostic {
            diagnostic_type: "gate-config-error".to_string(),
            message: "needs a baseline".to_string(),
            file_path: None,
            line: None,
        }],
    );
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None, Some(&Gate::default())),
        RunOutcome::DiagnosticsFailed,
    );
}
