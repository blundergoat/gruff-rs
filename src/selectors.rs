//! The two selector families the family contract keeps apart.
//!
//! One decides which rules execute, so the score and any generated baseline move with it. The other decides what
//! a finished report shows, and a finding it hides still counted. Keeping them in one module says that they are
//! two answers to two different questions rather than one filter with two spellings.

use super::*;

/// The selectors that choose which rules execute.
///
/// Empty lists mean the configured selection stands, which is what a bare `analyse` runs.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExecutionSelectors {
    pub(crate) include_rules: Vec<String>,
    pub(crate) exclude_rules: Vec<String>,
    pub(crate) include_pillars: Vec<String>,
    pub(crate) exclude_pillars: Vec<String>,
}

impl ExecutionSelectors {
    /// Report whether the user narrowed execution at all.
    pub(crate) fn is_requested(&self) -> bool {
        !self.include_rules.is_empty()
            || !self.exclude_rules.is_empty()
            || !self.include_pillars.is_empty()
            || !self.exclude_pillars.is_empty()
    }
}

/// The selectors that choose what a finished report shows.
///
/// A finding hidden here still counted toward the score and the exit code, which is what separates these from the
/// execution selectors.
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
    pub(crate) fn is_requested(&self) -> bool {
        self.min_severity.is_some()
            || !self.show_rules.is_empty()
            || !self.hide_rules.is_empty()
            || !self.show_pillars.is_empty()
            || !self.hide_pillars.is_empty()
    }

    /// Report whether one finding survives every active display selector.
    pub(crate) fn allows(&self, finding: &Finding) -> bool {
        // A finding below the floor is muted before any rule or pillar check runs.
        if self
            .min_severity
            .is_some_and(|floor| finding.severity.rank() < floor.rank())
        {
            return false;
        }
        if !self.show_rules.is_empty() && !self.show_rules.contains(&finding.rule_id) {
            return false;
        }
        if self.hide_rules.contains(&finding.rule_id) {
            return false;
        }
        let pillar = crate::report::pillar_label(finding.pillar).to_string();
        if !self.show_pillars.is_empty() && !self.show_pillars.contains(&pillar) {
            return false;
        }
        !self.hide_pillars.contains(&pillar)
    }
}

impl Config {
    /// Return a copy narrowed to the rules and pillars the user asked to run.
    ///
    /// These selectors choose which rules execute, so the score and any generated baseline move with them. The
    /// presentation selectors never reach here, which is what keeps the two ideas apart.
    pub(crate) fn with_execution_selectors(&self, selectors: &ExecutionSelectors) -> Self {
        // An unrestricted run keeps the configured selection rather than rebuilding an identical one.
        if !selectors.is_requested() {
            return self.clone();
        }

        let registry = rules::builtin_registry_cached();
        let mut narrowed = self.clone();

        for rule_id in &selectors.include_rules {
            narrowed.selectors.positive.insert(rule_id.clone());
            narrowed.selectors.has_positive = true;
        }
        for rule_id in &selectors.exclude_rules {
            narrowed.selectors.negative.insert(rule_id.clone());
        }

        for definition in registry.definitions() {
            let pillar = crate::report::pillar_label(definition.pillar).to_string();
            // A pillar selector names a group of rules, so it is expanded into the rule selectors the run reads.
            if selectors.include_pillars.contains(&pillar) {
                narrowed
                    .selectors
                    .positive
                    .insert(definition.id.to_string());
                narrowed.selectors.has_positive = true;
            }
            if selectors.exclude_pillars.contains(&pillar) {
                narrowed
                    .selectors
                    .negative
                    .insert(definition.id.to_string());
            }
        }

        narrowed
    }
}
