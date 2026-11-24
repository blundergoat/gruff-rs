//! Upgrade a 0.5 config into a new file before running gruff-rs 0.6 with it.
//! The per-command gate moves to `failOn`, empty `minimumSeverity:` placeholders and retired 0.5 rules are dropped,
//! and section 5 of `FAMILY-CONTRACT.md` makes category markers unconditional so `secretPreviews` is removed.
//!
//! Keep comments when the line edit produces the correct YAML. The caller always keeps the original config as a reference.

use std::fs;
use std::io::Write;
use std::process::ExitCode;

use serde_yaml::{Mapping, Value};

use crate::cli::{MigrateConfigArgs, OutputWriter};
use crate::config::SCHEMA_VERSION;

/// Built-in rule IDs retired between 0.5 and 0.6.0 (ADR-024).
pub(crate) const RETIRED_0_5_RULES: &[&str] = &[
    "concurrency.unbounded-channel",
    "dependency.path-source",
    "docs.stale-todo",
    "error-handling.public-unwrap",
    "modernisation.manual-is-empty",
    "naming.boolean-prefix",
    "naming.generic-function",
    "performance.clone-in-loop",
    "performance.format-in-loop",
    "security.path-traversal-candidate",
    "sensitive-data.database-url-password",
    "sensitive-data.hardcoded-env-value",
    "test-quality.conditional-logic",
    "test-quality.sleep-in-test",
    "waste.unreachable-code",
];

/// Guidance appended to config load errors caused by legacy 0.5 keys or retired rule IDs.
pub(crate) const MIGRATE_CONFIG_HINT: &str =
    "Run `gruff-rs migrate-config --config <old> --output <new>` to upgrade.";

/// Explain why the migrated config drops `allowlists.secretPreviews`.
const REMOVED_KEY_CHANGE: &str =
    "allowlists.secretPreviews removed; section 5 makes category markers unconditional";

/// Explain where to adjust the command's failure threshold after migration.
const RENAMED_GATE_CHANGE: &str =
    "minimumSeverity: renamed to failOn:, the key that gates the exit code in 0.6";

/// Tell whether `rule_id` is one of the fifteen built-in rules retired between 0.5 and 0.6.0.
///
/// `rule_id` is the exact rule identifier read from configuration.
/// Returns true when `rule_id` matches an entry in `RETIRED_0_5_RULES`, and false otherwise.
pub(crate) fn is_retired_0_5_rule(rule_id: &str) -> bool {
    RETIRED_0_5_RULES.contains(&rule_id)
}

/// Format a config load error for a retired 0.5 rule ID with the `migrate-config` upgrade hint.
///
/// `rule_id` is the retired identifier and `context` names the config key where it appeared.
/// Returns an error string naming the retired rule, its config location, and the upgrade command.
pub(crate) fn retired_rule_config_error(rule_id: &str, context: &str) -> String {
    format!(
        "unknown rule id `{rule_id}` in config key `{context}` (retired in 0.6.0). {MIGRATE_CONFIG_HINT}"
    )
}

/// Number one change against the line it happened on, so a user can read the summary beside their own file.
///
/// `index` is the zero-based index of the changed line in the original file and `description` says what changed.
/// Returns a summary line of the form `line N: description`, where N is `index` plus one.
fn change_line(index: usize, description: &str) -> String {
    format!("line {}: {description}", index + 1)
}

/// The upgraded config text and the reasons shown by `migrate-config`.
/// A caller can preview the same change list with `--dry-run` before choosing an output path.
///
/// An empty `changes` list means the input was already current and `text` is the input byte for byte.
#[derive(Debug)]
pub(crate) struct ConfigMigration {
    pub(crate) text: String,
    pub(crate) changes: Vec<String>,
}

/// Rewrite legacy keys in `original`, preserving formatting when the result parses as the intended mapping.
/// Returns migrated YAML and a change list, or an error if the input cannot be migrated unambiguously.
pub(crate) fn migrate_config_text(original: &str) -> Result<ConfigMigration, String> {
    // Show YAML syntax errors before opening a destination.
    let document: Value =
        serde_yaml::from_str(original).map_err(|error| format!("invalid YAML: {error}"))?;
    let mut mapping = match document {
        Value::Null => Mapping::new(),
        Value::Mapping(mapping) => mapping,
        _ => return Err("config must be a YAML mapping".to_string()),
    };
    let mut changes = Vec::new();
    rename_legacy_gate(&mut mapping, &mut changes)?;
    // Preserve all other allowlists and any unrelated occurrence of the same key name.
    if let Some(Value::Mapping(allowlists)) = mapping.get_mut("allowlists") {
        if allowlists.remove("secretPreviews").is_some() {
            changes.push(REMOVED_KEY_CHANGE.to_string());
            if allowlists.is_empty() {
                mapping.remove("allowlists");
            }
        }
    }
    drop_retired_entries(&mut mapping, &mut changes)?;
    // Older config files may have no schema version, which the new loader rejects.
    if mapping.get("schemaVersion").and_then(Value::as_str) != Some(SCHEMA_VERSION) {
        mapping.insert(Value::from("schemaVersion"), Value::from(SCHEMA_VERSION));
        changes.push(format!("schemaVersion set to {SCHEMA_VERSION}"));
    }
    if changes.is_empty() {
        return Ok(ConfigMigration {
            text: original.to_string(),
            changes,
        });
    }
    let intended = Value::Mapping(mapping);
    let comment_preserving_rewrite = migrate_config_lines(original);
    // Keep original formatting only when the line edit matches the parsed target mapping.
    if serde_yaml::from_str::<Value>(&comment_preserving_rewrite.text)
        .is_ok_and(|parsed| parsed == intended)
    {
        return Ok(comment_preserving_rewrite);
    }
    let text = serde_yaml::to_string(&intended)
        .map_err(|error| format!("unable to render migrated config: {error}"))?;
    changes
        .push("YAML formatting was regenerated. Comments remain in the original file.".to_string());
    Ok(ConfigMigration { text, changes })
}

/// Move a legacy gate map or drop an empty `minimumSeverity:` placeholder in `mapping`, recording each edit in `changes`.
/// Returns success when `minimumSeverity` is absent, scalar, removed as null, or renamed to `failOn` without conflict.
fn rename_legacy_gate(mapping: &mut Mapping, changes: &mut Vec<String>) -> Result<(), String> {
    // 0.5 `init` emitted a bare `minimumSeverity:` with only comments under it, which YAML reads as null.
    if mapping.get("minimumSeverity").is_some_and(Value::is_null) {
        mapping.remove("minimumSeverity");
        changes.push(
            "minimumSeverity: empty placeholder removed; use failOn: to gate exit codes or a scalar minimumSeverity: for display floor"
                .to_string(),
        );
        return Ok(());
    }
    // A scalar `minimumSeverity` controls display in 0.6, so only the old per-command map moves.
    if !mapping
        .get("minimumSeverity")
        .is_some_and(Value::is_mapping)
    {
        return Ok(());
    }
    // An upgrade may already contain `failOn`. Refuse two candidate gates rather than guessing which one the user meant.
    if mapping.contains_key("failOn") {
        return Err("config contains both a legacy minimumSeverity map and failOn".to_string());
    }
    if let Some(gate) = mapping.remove("minimumSeverity") {
        mapping.insert(Value::from("failOn"), gate);
        changes.push(RENAMED_GATE_CHANGE.to_string());
    }
    Ok(())
}

/// Drop retired 0.5 rule references from `rules`, `exclude`, and `sensitiveExclusions` in `mapping`.
///
/// Records every removed rule ID in `changes`, deletes sections that become empty, and leaves non-retired typos untouched for the loader.
/// Returns `Ok(())` when retired references drop safely, or `Err` if stripping `rules.select` would empty a previously non-empty selection.
fn drop_retired_entries(mapping: &mut Mapping, changes: &mut Vec<String>) -> Result<(), String> {
    let remove_rules = match mapping.get_mut("rules") {
        Some(Value::Mapping(rules)) => {
            let mut changed = drop_retired_map_entries(rules, "rules", changes);
            // A 0.5 config may also mention retired rule IDs inside `rules.custom`; drop the map only if removals empty it.
            let remove_custom = match rules.get_mut("custom") {
                Some(Value::Mapping(custom)) => {
                    let custom_changed = drop_retired_map_entries(custom, "rules.custom", changes);
                    changed |= custom_changed;
                    custom_changed && custom.is_empty()
                }
                _ => false,
            };
            // Drop `rules.custom` once removing retired entries leaves it empty so the output has no stale empty block.
            if remove_custom {
                rules.remove("custom");
            }
            changed |= drop_retired_selector_list(rules, "select", true, changes)?;
            changed |= drop_retired_selector_list(rules, "ignore", false, changes)?;
            changed && rules.is_empty()
        }
        _ => false,
    };
    // Drop `rules` itself if stripping retired keys left it empty; a pre-existing empty `rules: {}` stays untouched.
    if remove_rules {
        mapping.remove("rules");
    }
    drop_retired_exclusion_list(mapping, "exclude", true, changes);
    drop_retired_exclusion_list(mapping, "sensitiveExclusions", false, changes);
    Ok(())
}

/// Remove retired 0.5 rule keys from `entries` and record each removal under `prefix` in `changes`.
///
/// `entries` is a `rules` or `rules.custom` YAML mapping, `prefix` names its config path, and `changes` receives one entry per dropped rule.
/// Returns true when at least one retired key was removed from `entries`, and false when no retired rule was present.
fn drop_retired_map_entries(
    entries: &mut Mapping,
    prefix: &str,
    changes: &mut Vec<String>,
) -> bool {
    let retired_keys: Vec<String> = entries
        .keys()
        .filter_map(Value::as_str)
        .filter(|key| is_retired_0_5_rule(key))
        .map(str::to_string)
        .collect();
    // Delete every retired key found and log its exact config path so the user sees what `migrate-config` removed.
    for rule_id in &retired_keys {
        entries.remove(rule_id.as_str());
        changes.push(format!("{prefix}.{rule_id} removed; rule retired in 0.6.0"));
    }
    !retired_keys.is_empty()
}

/// Remove retired 0.5 rule IDs from `rules.select` or `rules.ignore`, recording every removal in `changes`.
///
/// When `refuse_empty` is true (for `rules.select`), emptying a non-empty list returns `Err` instead of silently widening the scan to all rules.
/// Otherwise (for `rules.ignore`), an emptied list is removed so no empty array stays behind.
///
/// `rules` is the `rules` YAML mapping, `key` is `"select"` or `"ignore"`, and `changes` collects user-visible summary notes.
/// Returns `Ok(true)` if any entry was removed, `Ok(false)` if none matched (or the key was absent), or `Err` if `refuse_empty` triggers.
fn drop_retired_selector_list(
    rules: &mut Mapping,
    key: &str,
    refuse_empty: bool,
    changes: &mut Vec<String>,
) -> Result<bool, String> {
    // Missing or non-sequence keys have no selector list to clean here; malformed shapes remain for the config loader to report.
    let Some(Value::Sequence(items)) = rules.get_mut(key) else {
        return Ok(false);
    };
    let was_non_empty = !items.is_empty();
    let mut removed = Vec::new();
    items.retain(|item| match item.as_str().map(str::trim) {
        Some(rule_id) if is_retired_0_5_rule(rule_id) => {
            removed.push(rule_id.to_string());
            false
        }
        _ => true,
    });
    // Leave the selector list unchanged when every configured entry is still active in 0.6.
    if removed.is_empty() {
        return Ok(false);
    }
    // Report each removed rule ID so the caller knows which 0.5 selectors no longer run.
    for rule_id in removed {
        changes.push(format!(
            "rules.{key} entry `{rule_id}` removed; rule retired in 0.6.0"
        ));
    }
    let became_empty = items.is_empty();
    // For example, a config with `rules.select: [docs.stale-todo]` would otherwise silently run every built-in rule after migration.
    if refuse_empty && was_non_empty && became_empty {
        return Err(
            "removing retired 0.5 rules would empty `rules.select`, widening analysis to all built-in rules; replace `rules.select` with active 0.6.0 rules before migrating"
                .to_string(),
        );
    }
    // Drop an emptied `rules.ignore` list because ignoring nothing is already the default.
    if !refuse_empty && became_empty {
        rules.remove(key);
    }
    Ok(true)
}

/// Remove exclusion entries in `mapping[section]` whose `rule` names a retired 0.5 rule, logging each removal in `changes`.
///
/// `section` is `"exclude"` or `"sensitiveExclusions"`; `trim_rule` trims selector whitespace (matching `exclude` loader semantics).
/// If dropping retired entries empties `section`, the now-empty section key is removed from `mapping`.
fn drop_retired_exclusion_list(
    mapping: &mut Mapping,
    section: &str,
    trim_rule: bool,
    changes: &mut Vec<String>,
) {
    // Absent or non-sequence sections have no exclusion rows to prune; invalid shapes stay for config loading.
    let Some(Value::Sequence(entries)) = mapping.get_mut(section) else {
        return;
    };
    let mut removed = Vec::new();
    entries.retain(|entry| {
        let rule_id = entry
            .as_mapping()
            .and_then(|map| map.get("rule"))
            .and_then(Value::as_str)
            .map(|rule| if trim_rule { rule.trim() } else { rule });
        match rule_id {
            Some(retired_id) if is_retired_0_5_rule(retired_id) => {
                removed.push(retired_id.to_string());
                false
            }
            _ => true,
        }
    });
    // Leave the section untouched when no exclusion references a retired 0.5 rule.
    if removed.is_empty() {
        return;
    }
    // List every dropped exclusion so the user can review which legacy suppressions were retired.
    for rule_id in removed {
        changes.push(format!(
            "{section} entry for `{rule_id}` removed; rule retired in 0.6.0"
        ));
    }
    // Drop the section key when every entry in it belonged to a retired rule.
    if entries.is_empty() {
        mapping.remove(section);
    }
}

/// Try a line rewrite of `original` that keeps whitespace and comments for conventional block mappings.
/// Returns the candidate YAML and the changes made by the line rewrite.
fn migrate_config_lines(original: &str) -> ConfigMigration {
    let lines: Vec<&str> = original.split('\n').collect();
    let mut migrated: Vec<String> = Vec::with_capacity(lines.len());
    let mut changes: Vec<String> = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let removed_line_count = legacy_preview_block_length(&lines, index);

        // The removed key takes its whole indented block with it, or an empty list stays behind meaning nothing.
        if removed_line_count > 0 {
            changes.push(change_line(index, REMOVED_KEY_CHANGE));
            index += removed_line_count;
            drop_emptied_parent(&mut migrated, &lines, index);
            continue;
        }

        // A per-command map under the old key is the exit gate, which now has its own name.
        if let Some(renamed) = renamed_gate_line(&lines, index) {
            changes.push(change_line(index, RENAMED_GATE_CHANGE));
            migrated.push(renamed);
            index += 1;
            continue;
        }

        migrated.push(lines[index].to_string());
        index += 1;
    }

    with_schema_version(migrated, changes, original)
}

/// Locate the obsolete preview setting in a block-style config so the rewrite can keep adjacent comments.
///
/// `lines` are the original file's lines and `index` is the line to test, which must be in range or the lookup panics.
/// Returns 0 unless the line is an indented `secretPreviews` key, otherwise 1 plus the run of deeper-indented lines after it.
fn legacy_preview_block_length(lines: &[&str], index: usize) -> usize {
    let line = lines[index];
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();

    // A top-level key belongs to the user's own config. The YAML check verifies the section before this line edit is accepted.
    if indent == 0 || !key_is(trimmed, "secretPreviews") {
        return 0;
    }

    let mut length = 1;
    // Old preview lists can span several lines. Remove their indented values with the key.
    while index + length < lines.len() && is_deeper_than(lines[index + length], indent) {
        length += 1;
    }

    length
}

/// Rewrite the old gate key when it introduces a per-command block, leaving the scalar display floor alone.
///
/// `lines` are the original file's lines and `index` is the line to test, which must be in range or the lookup panics.
/// Returns the line as `failOn:` at the same indent when it is a bare `minimumSeverity:` key followed by a deeper-indented line, otherwise None.
fn renamed_gate_line(lines: &[&str], index: usize) -> Option<String> {
    let line = lines[index];
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();

    // Unrelated keys keep their exact spelling in the migrated file.
    if !key_is(trimmed, "minimumSeverity") {
        return None;
    }

    // Leave inline values to the YAML rewrite. For example, `minimumSeverity: warning` is already a valid display floor.
    let tail = trimmed
        .split_once(':')
        .map(|(_, rest)| rest.trim())
        .unwrap_or_default();
    if !tail.is_empty() {
        return None;
    }

    // An empty or comment-only block is a placeholder, not a per-command gate map.
    let opens_block = block_has_active_child(lines, index, indent);
    opens_block.then(|| format!("{}failOn:", &line[..indent]))
}

/// Tell whether the YAML block opened at `index` with indentation `indent` contains at least one non-comment child line in `lines`.
///
/// Used by the comment-preserving line rewriter to distinguish a real `minimumSeverity:` gate map from a commented-out 0.5 placeholder.
/// Returns true when a deeper-indented non-comment line appears before the block ends, and false for empty or comment-only blocks.
fn block_has_active_child(lines: &[&str], index: usize, indent: usize) -> bool {
    let mut cursor = index + 1;
    // Scan deeper lines beneath the header until a blank line or dedent closes the block.
    while cursor < lines.len() {
        let line = lines[cursor];
        let trimmed = line.trim();
        // A blank line or dedent ends the candidate block before any real child entry was found.
        if trimmed.is_empty() || line.len() - line.trim_start().len() <= indent {
            return false;
        }
        // Any non-comment child line (for example `analyse: warning`) proves this block is a legacy gate map.
        if !trimmed.starts_with('#') {
            return true;
        }
        cursor += 1;
    }
    false
}

/// Remove the now-empty header from a block-style rewrite. The parsed mapping verifies that a blank line hid no later settings.
///
/// `migrated` is the output built so far, whose last line is the candidate header.
/// `lines` are the original file's lines and `index` is the first line after the removed block.
fn drop_emptied_parent(migrated: &mut Vec<String>, lines: &[&str], index: usize) {
    // If the removed setting came first, there is no preceding header to consider.
    let Some(header) = migrated.last() else {
        return;
    };

    let trimmed = header.trim();

    // A header is a bare `key:` with no value; a comment, a value, or an empty line is a line the user wants kept.
    if trimmed.starts_with('#') || !trimmed.ends_with(':') || trimmed.len() < 2 {
        return;
    }

    let header_indent = header.len() - header.trim_start().len();

    // A block that still has a child is not empty, so its header stays.
    if index < lines.len() && is_deeper_than(lines[index], header_indent) {
        return;
    }

    migrated.pop();
}

/// True when a trimmed line is exactly the named key followed by a colon, so a comment or a longer name is not it.
///
/// `trimmed` is the line to test, normally with its indentation removed, and `key` is the key name to match.
/// Returns true when `trimmed` starts with `key` and the next non-whitespace character is a colon, whatever value follows.
fn key_is(trimmed: &str, key: &str) -> bool {
    trimmed
        .strip_prefix(key)
        .is_some_and(|rest| rest.trim_start().starts_with(':'))
}

/// True when a line belongs to a block opened at the given indent; a blank line does not, so it ends the block.
///
/// `line` is the line to test and `indent` is the leading-whitespace width, in bytes, of the line that opened the block.
/// Returns true when `line` has non-blank text indented further than `indent`, and false otherwise.
fn is_deeper_than(line: &str, indent: usize) -> bool {
    !line.trim().is_empty() && line.len() - line.trim_start().len() > indent
}

/// Pin the schema version, inserting it at the top when the 0.5 file never named one.
///
/// A top-level `schemaVersion` line that differs from the pinned one is replaced, and each insertion or replacement is added to `changes`.
/// `lines` are the migrated lines and `original` is the input text, kept as the result when nothing changed.
///
/// Returns the migration result: `original` unchanged as `text` when `changes` stays empty, otherwise the joined `lines` with every change.
fn with_schema_version(
    mut lines: Vec<String>,
    mut changes: Vec<String>,
    original: &str,
) -> ConfigMigration {
    let pinned = format!("schemaVersion: \"{SCHEMA_VERSION}\"");
    let existing = lines
        .iter()
        .position(|line| key_is(line, "schemaVersion") && !line.starts_with(char::is_whitespace));

    match existing {
        None => {
            changes.push(format!(
                "line 1: schemaVersion added as {SCHEMA_VERSION}; every 0.6 loader requires it"
            ));
            lines.insert(0, pinned);
        }
        Some(position) if lines[position].trim() != pinned => {
            changes.push(format!(
                "line {}: schemaVersion pinned to {SCHEMA_VERSION}",
                position + 1
            ));
            lines[position] = pinned;
        }
        Some(_) => {}
    }

    // Keep the exact input if the user had already migrated it.
    if changes.is_empty() {
        return ConfigMigration {
            text: original.to_string(),
            changes,
        };
    }

    ConfigMigration {
        text: lines.join("\n"),
        changes,
    }
}

/// Read the named config, rewrite it, and put the result where the user asked.
///
/// The input is only read. The destination must be a new file so a migration cannot write through an alias.
///
/// `args` names the config to read, the optional `--output` destination and whether this is a dry run; `writer` prints the change summary.
///
/// Returns success after a dry run or a completed write, and exit code 2 for non-UTF-8 input, the cases above, or a failed write.
pub(crate) fn run_migrate_config(args: MigrateConfigArgs, writer: &OutputWriter) -> ExitCode {
    // A moved config or legacy non-UTF-8 file stops the command before it creates an output.
    let Ok(original) = fs::read_to_string(&args.config) else {
        eprintln!(
            "gruff-rs: config to migrate does not exist or could not be read: {}",
            args.config.display()
        );
        return ExitCode::from(2);
    };

    let migration = match migrate_config_text(&original) {
        Ok(migration) => migration,
        // For example, a config with both gate keys needs a user decision before it can be migrated.
        Err(error) => {
            eprintln!(
                "gruff-rs: unable to migrate {}: {error}",
                args.config.display()
            );
            return ExitCode::from(2);
        }
    };
    // An empty change list tells the caller they already use the current keys.
    let summary = if migration.changes.is_empty() {
        format!(
            "{} is already current; no changes.\n",
            args.config.display()
        )
    } else {
        let mut lines = vec!["Migration changes:".to_string()];
        lines.extend(
            migration
                .changes
                .iter()
                .map(|change| format!("  - {change}")),
        );
        format!("{}\n", lines.join("\n"))
    };
    writer.emit_unconditional(&summary);

    // `--dry-run` lets callers review the changes before they name a destination.
    if args.dry_run {
        writer.emit_unconditional("Dry run: nothing written.\n");
        return ExitCode::SUCCESS;
    }

    write_migrated(&args, &migration.text, writer)
}

/// Create the destination and write the migrated text, refusing any existing file, link or directory.
/// `args` supplies the input and output paths, and `writer` publishes where `migrated` was written.
/// Returns exit code 0 after a successful write or 2 if the destination is missing or cannot be written.
fn write_migrated(args: &MigrateConfigArgs, migrated: &str, writer: &OutputWriter) -> ExitCode {
    // With no destination, ask for `--output` and leave the original available for rollback.
    let Some(output) = args.output.as_ref() else {
        eprintln!(
            "gruff-rs: migrate-config needs --output <path>, or --dry-run to print the changes."
        );
        return ExitCode::from(2);
    };

    let result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .and_then(|mut file| file.write_all(migrated.as_bytes()));
    // A reused destination or a read-only parent directory leaves the original config available.
    if let Err(error) = result {
        eprintln!(
            "gruff-rs: unable to create migration output {}: {error}",
            output.display()
        );
        return ExitCode::from(2);
    }

    writer.emit_unconditional(&format!(
        "Wrote {}; {} is unchanged.\n",
        output.display(),
        args.config.display()
    ));
    ExitCode::SUCCESS
}
