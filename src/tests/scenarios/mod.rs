pub(crate) use super::*;

mod baseline;
mod calibration_extras;
mod diff;
mod discovery;
mod list_rules_detail;
mod smoke;
mod stable_identity;
mod summary_enrichment;

/// Builds a per-rule delta record for scenario tests, deriving its net change from the two counts.
///
/// `rule_id` names the rule the delta describes; `introduced` and `removed` are its counts of new and removed findings.
/// Returns a `RuleDelta` whose `net` is `introduced` minus `removed`, negative when more were removed than introduced.
pub(crate) fn rule_delta_fixture(rule_id: &str, introduced: usize, removed: usize) -> RuleDelta {
    RuleDelta {
        rule_id: rule_id.to_string(),
        introduced,
        removed,
        net: introduced as i64 - removed as i64,
    }
}
