//! Apply the selectors a caller passes to choose what runs and what appears in the report.
//!
//! Use execution selectors to narrow findings, scores, and generated baselines to the requested rules.
//! Use display selectors to hide findings from a finished report while preserving the scan's counts and exit decision.

use super::*;

/// Choose which rules participate in the scan, score, and any generated baseline.
///
/// Empty lists keep the project selection a caller gets with bare `analyse`.
/// An explicit include supplies a new selection. An exclude still wins when both flags match.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExecutionSelectors {
    pub(crate) include_rules: Vec<String>,
    pub(crate) exclude_rules: Vec<String>,
    pub(crate) include_pillars: Vec<String>,
    pub(crate) exclude_pillars: Vec<String>,
}

impl ExecutionSelectors {
    /// Report whether the user narrowed execution at all.
    ///
    /// Returns `true` when any include or exclude list for rules or pillars holds an entry, and `false` when all four lists are empty.
    pub(crate) fn is_requested(&self) -> bool {
        !self.include_rules.is_empty()
            || !self.exclude_rules.is_empty()
            || !self.include_pillars.is_empty()
            || !self.exclude_pillars.is_empty()
    }
}

/// Choose which findings a caller sees in a finished report.
///
/// Use these selectors to focus a review on a severity, rule, or pillar.
/// Hidden findings still count toward the score and exit status.
#[derive(Clone, Debug, Default)]
pub(crate) struct DisplaySelectors {
    pub(crate) min_severity: Option<Severity>,
    pub(crate) show_rules: Vec<String>,
    pub(crate) hide_rules: Vec<String>,
    pub(crate) show_pillars: Vec<String>,
    pub(crate) hide_pillars: Vec<String>,
}

impl DisplaySelectors {
    /// Report whether the user narrowed the view at all.
    ///
    /// Returns `true` when a minimum severity is set or any show or hide list for rules or pillars holds an entry, and `false` otherwise.
    pub(crate) fn is_requested(&self) -> bool {
        self.min_severity.is_some()
            || !self.show_rules.is_empty()
            || !self.hide_rules.is_empty()
            || !self.show_pillars.is_empty()
            || !self.hide_pillars.is_empty()
    }

    /// Report whether one finding survives every active display selector.
    ///
    /// `finding` is hidden when its severity ranks below `min_severity`.
    /// It is also hidden when a non-empty `show_rules` lacks its rule ID or `hide_rules` contains it.
    /// The same show and hide test then runs on its pillar label with `show_pillars` and `hide_pillars`.
    ///
    /// Returns `true` when `finding` passes every check, and `false` as soon as one check hides it.
    pub(crate) fn allows(&self, finding: &Finding) -> bool {
        // A finding below the floor is muted before any rule or pillar check runs.
        if self
            .min_severity
            .is_some_and(|floor| finding.severity.rank() < floor.rank())
        {
            return false;
        }
        // An explicit rule shortlist hides all other rules from this view without changing the scan totals.
        if !self.show_rules.is_empty() && !self.show_rules.contains(&finding.rule_id) {
            return false;
        }
        // A rule the caller explicitly hides stays hidden even if another display flag would show it.
        if self.hide_rules.contains(&finding.rule_id) {
            return false;
        }
        let pillar = crate::report::pillar_label(finding.pillar).to_string();
        // A pillar shortlist works the same way, after checking the individual rule filters.
        if !self.show_pillars.is_empty() && !self.show_pillars.contains(&pillar) {
            return false;
        }
        !self.hide_pillars.contains(&pillar)
    }
}

impl Config {
    /// Use the caller's execution selectors before the scan calculates findings, grades, and baselines.
    ///
    /// `selectors` is empty when the caller wants the project selection. Returns the rule config or an error naming an invalid selector.
    pub(crate) fn with_execution_selectors(
        &self,
        selectors: &ExecutionSelectors,
    ) -> Result<Self, String> {
        // An unrestricted run keeps the configured selection rather than rebuilding an identical one.
        if !selectors.is_requested() {
            return Ok(self.clone());
        }

        let catalog = config_loader::rule_selector_catalog(
            rules::builtin_registry_cached(),
            &self.custom_rules,
        );
        let mut narrowed = self.clone();
        // For example, `--include-rule docs.missing-public-doc` limits the scan even when config normally selects more rules.
        if !selectors.include_rules.is_empty() || !selectors.include_pillars.is_empty() {
            narrowed.selectors.positive.clear();
            narrowed.selectors.has_positive = true;
        }

        // An exact include can deliberately enable a known rule that config otherwise leaves off.
        for rule_id in &selectors.include_rules {
            let ids = config_loader::exact_rule_selector(rule_id, &catalog)
                .ok_or_else(|| format!("unknown rule `{rule_id}` in --include-rule"))?;
            narrowed.selectors.positive.extend(ids);
            narrowed
                .rule_settings
                .entry(rule_id.clone())
                .or_default()
                .enabled = Some(true);
        }
        // Exclusions remove rules even when an included rule or pillar would have selected them.
        for rule_id in &selectors.exclude_rules {
            let ids = config_loader::exact_rule_selector(rule_id, &catalog)
                .ok_or_else(|| format!("unknown rule `{rule_id}` in --exclude-rule"))?;
            narrowed.selectors.negative.extend(ids);
        }
        // A pillar can select configured custom rules as well as built-ins in the same quality area.
        for pillar in &selectors.include_pillars {
            let ids = config_loader::pillar_rule_selector(pillar, &catalog)
                .ok_or_else(|| format!("unknown pillar `{pillar}` in --include-pillar"))?;
            narrowed.selectors.positive.extend(ids);
        }
        // A pillar exclusion removes the whole group before it can affect the score or gate.
        for pillar in &selectors.exclude_pillars {
            let ids = config_loader::pillar_rule_selector(pillar, &catalog)
                .ok_or_else(|| format!("unknown pillar `{pillar}` in --exclude-pillar"))?;
            narrowed.selectors.negative.extend(ids);
        }
        Ok(narrowed)
    }
}
