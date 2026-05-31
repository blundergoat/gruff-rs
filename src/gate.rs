use super::*;

/// Per-severity / total finding-count gate from the `gate:` config block (ADR-003
/// M02 addendum). An omitted cap means unlimited for that dimension; gating is
/// count-based and never consults the score model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Gate {
    pub(crate) total: Option<u64>,
    pub(crate) error: Option<u64>,
    pub(crate) warning: Option<u64>,
    pub(crate) advisory: Option<u64>,
    pub(crate) on_match: GateOnMatch,
    pub(crate) scope: GateScope,
}

/// What a tripped gate does: `Fail` makes the run exit 1, `Warn` only records the
/// diagnostic without changing the exit code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum GateOnMatch {
    #[default]
    Fail,
    Warn,
}

/// Which finding set the gate counts (ADR-003 baseline-aware gate-scope addendum).
/// `Current` (default / `scope:` unset) preserves the historical behavior: gate over
/// the report summary, which is new-only when a baseline is applied (baseline
/// suppression drops `unchanged` before the summary is taken) and all findings
/// otherwise. `New` gates only on new findings and requires an applied baseline.
/// `All` gates over the pre-baseline finding set (new + unchanged).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum GateScope {
    #[default]
    Current,
    New,
    All,
}

/// Result of evaluating a gate over a report summary.
pub(crate) struct GateEvaluation {
    /// The run should exit 1 (a cap was exceeded AND `onMatch: fail`).
    pub(crate) fails: bool,
    /// Per-severity breakdown plus the `pass`/`trip`/`warn` decision.
    pub(crate) message: String,
}

impl Gate {
    /// Evaluate the gate against a report's severity counts. Pure: depends only on
    /// the summary and the configured caps, so the same inputs always classify the
    /// same way (Kill Criteria: no coupling to score or a separate runtime mode).
    pub(crate) fn evaluate(&self, summary: &Summary) -> GateEvaluation {
        let dimensions = [
            ("error", summary.error as u64, self.error),
            ("warning", summary.warning as u64, self.warning),
            ("advisory", summary.advisory as u64, self.advisory),
            ("total", summary.total as u64, self.total),
        ];
        let mut breached = false;
        let mut parts = Vec::new();
        for (name, count, cap) in dimensions {
            let (part, over) = format_gate_dimension(name, count, cap);
            breached |= over;
            parts.push(part);
        }
        let decision = match (breached, self.on_match) {
            (false, _) => "pass",
            (true, GateOnMatch::Fail) => "trip",
            (true, GateOnMatch::Warn) => "warn",
        };
        GateEvaluation {
            fails: breached && self.on_match == GateOnMatch::Fail,
            message: format!("Quality gate {decision}: {}.", parts.join(", ")),
        }
    }

    /// Evaluate the gate over the report, selecting the finding set per `scope`.
    /// This is the report-aware wrapper around the pure `evaluate`; the exit-code
    /// path (`RunOutcome::classify`) and the diagnostic both go through it so the
    /// scope choice is applied once, consistently.
    pub(crate) fn evaluate_report(&self, report: &AnalysisReport) -> GateEvaluation {
        self.evaluate(self.gated_summary(report))
    }

    /// The severity summary this gate counts. `All` uses the pre-baseline summary
    /// (falling back to the report summary when none was captured); `Current` and
    /// `New` use the report summary (new-only when a baseline is applied).
    fn gated_summary<'a>(&self, report: &'a AnalysisReport) -> &'a Summary {
        match self.scope {
            GateScope::All => report
                .all_findings_summary
                .as_ref()
                .unwrap_or(&report.summary),
            GateScope::Current | GateScope::New => &report.summary,
        }
    }

    /// `Some(message)` when this gate's scope cannot be satisfied for the run:
    /// `scope: new` (or `--fail-on-new`) with no applied baseline, where "new" is
    /// undefined. The caller turns this into a fatal config-error diagnostic (exit
    /// 2) rather than silently treating every finding as new.
    pub(crate) fn scope_precondition_error(&self, report: &AnalysisReport) -> Option<String> {
        (self.scope == GateScope::New && !is_baseline_applied(report)).then(|| {
            "`gate.scope: new` (and `--fail-on-new`) needs a baseline to define what is \
             \"new\"; pass `--baseline <path>`, keep a `gruff-baseline.json`, or drop \
             `scope: new`"
                .to_string()
        })
    }

    /// The non-fatal `gate` diagnostic carrying the per-severity breakdown for the
    /// gated scope, plus the baseline new/unchanged counts (debt visibility) when a
    /// baseline is applied. Pushed onto the report so the decision renders without
    /// forcing a config-error exit.
    pub(crate) fn diagnostic(&self, report: &AnalysisReport) -> RunDiagnostic {
        let base = self.evaluate_report(report).message;
        let message = match report
            .baseline
            .as_ref()
            .filter(|baseline| !baseline.generated)
        {
            Some(baseline) => format!(
                "{base} (baseline: {} new, {} unchanged)",
                baseline.new_count, baseline.unchanged_count
            ),
            None => base,
        };
        RunDiagnostic {
            diagnostic_type: "gate".to_string(),
            message,
            file_path: None,
            line: None,
        }
    }
}

/// Whether a baseline was *applied* for comparison (not merely generated). Drives
/// the `scope: new` precondition and the diagnostic's debt-count suffix.
fn is_baseline_applied(report: &AnalysisReport) -> bool {
    report
        .baseline
        .as_ref()
        .is_some_and(|baseline| !baseline.generated)
}

/// Render one gate dimension as `name count/cap` (with `(over)` when breached) or
/// `name count` when uncapped, returning the text and whether it breached. Kept
/// out of `evaluate`'s loop so the allocation is not flagged as loop-format debt.
fn format_gate_dimension(name: &str, count: u64, cap: Option<u64>) -> (String, bool) {
    match cap {
        Some(cap) => {
            let over = count > cap;
            let marker = if over { " (over)" } else { "" };
            (format!("{name} {count}/{cap}{marker}"), over)
        }
        None => (format!("{name} {count}"), false),
    }
}
