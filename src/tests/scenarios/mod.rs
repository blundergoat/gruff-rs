pub(crate) use super::*;

mod baseline;
mod calibration_extras;
mod diff;
mod discovery;
mod list_rules_detail;
mod smoke;
mod stable_identity;
mod summary_enrichment;

pub(crate) fn rule_delta_fixture(rule_id: &str, introduced: usize, removed: usize) -> RuleDelta {
    RuleDelta {
        rule_id: rule_id.to_string(),
        introduced,
        removed,
        net: introduced as i64 - removed as i64,
    }
}
