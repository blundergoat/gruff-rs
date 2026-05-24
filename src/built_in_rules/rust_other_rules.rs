//! Wrapper module that groups the per-line and per-item Rust rule
//! submodules. Files continue to live alongside `mod.rs` and are pulled
//! in via `#[path]` so that the top-level `built_in_rules` keeps a low
//! module fan-out.
pub(crate) use super::*;

#[path = "behavior_rules.rs"]
mod behavior_rules;
#[path = "comment_item_and_blocks.rs"]
mod comment_item_and_blocks;
#[path = "concurrency_rules.rs"]
mod concurrency_rules;
#[path = "modernisation_rules.rs"]
mod modernisation_rules;
#[path = "network_security_rules.rs"]
mod network_security_rules;
#[path = "path_traversal_rules.rs"]
mod path_traversal_rules;
#[path = "perf_rules.rs"]
mod perf_rules;
#[path = "waste_rules.rs"]
mod waste_rules;

pub(crate) use behavior_rules::*;
pub(crate) use comment_item_and_blocks::*;
pub(crate) use concurrency_rules::*;
pub(crate) use modernisation_rules::*;
pub(crate) use network_security_rules::*;
pub(crate) use path_traversal_rules::*;
pub(crate) use perf_rules::*;
pub(crate) use waste_rules::*;
