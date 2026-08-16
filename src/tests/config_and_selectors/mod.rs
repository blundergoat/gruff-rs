//! Configuration, selection, initialization, and registry contract tests.
//! These modules exercise the user-authored config path and the canonical rule
//! catalogue it validates before an analysis or rule-detail command runs.

pub(crate) use super::*;

mod config;
mod custom_rules;
mod exclusions;
mod gate;
mod init_command;
mod rule_registry;
mod secret_previews;
mod selectors;
