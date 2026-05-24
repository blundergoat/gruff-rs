//! Wrapper module that groups the per-block Rust rule submodules. Files
//! continue to live alongside `mod.rs` and are pulled in via `#[path]`
//! so that the top-level `built_in_rules` keeps a low module fan-out.
pub(crate) use super::*;

#[path = "blocks.rs"]
mod blocks;
#[path = "dead_code.rs"]
mod dead_code;
#[path = "docs_rules.rs"]
mod docs_rules;
#[path = "function_block_metrics.rs"]
mod function_block_metrics;
#[path = "function_block_rules.rs"]
mod function_block_rules;
#[path = "rustdoc_parsing.rs"]
mod rustdoc_parsing;
#[path = "test_rules.rs"]
mod test_rules;

pub(crate) use blocks::*;
pub(crate) use dead_code::*;
pub(crate) use docs_rules::*;
pub(crate) use function_block_metrics::*;
pub(crate) use function_block_rules::*;
pub(crate) use rustdoc_parsing::*;
pub(crate) use test_rules::*;
