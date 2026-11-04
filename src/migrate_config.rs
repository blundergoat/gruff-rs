//! Carries a 0.5 configuration forward to the 0.6 schema, out of place and line by line.
//!
//! Two keys moved in 0.6.0 and a user's committed file still spells them the old way: the per-command exit gate
//! left `minimumSeverity:` for `failOn:`, and `allowlists.secretPreviews` was removed outright because
//! FAMILY-CONTRACT.md section 5 makes category markers unconditional. A file carrying either is refused by the
//! loader, so a user upgrading needs a way across that does not mean re-typing their configuration.
//!
//! The rewrite is line-oriented rather than a parse-and-re-render, which keeps every comment, blank line and value
//! the user wrote exactly as written; anything the migration does not understand passes through untouched.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::{MigrateConfigArgs, OutputWriter};
use crate::config::SCHEMA_VERSION;

/// What the removal tells the user, written once because the loop only varies the line number.
const REMOVED_KEY_CHANGE: &str =
    "allowlists.secretPreviews removed; section 5 makes category markers unconditional";

/// What the rename tells the user, for the same reason.
const RENAMED_GATE_CHANGE: &str =
    "minimumSeverity: renamed to failOn:, the key that gates the exit code in 0.6";

/// Number one change against the line it happened on, so a user can read the summary beside their own file.
///
/// `index` is the zero-based index of the changed line in the original file and `description` says what changed.
/// Returns a summary line of the form `line N: description`, where N is `index` plus one.
fn change_line(index: usize, description: &str) -> String {
    format!("line {}: {description}", index + 1)
}

/// What one migration produced: the destination's text, and one readable line per rewrite.
///
/// An empty `changes` list means the input was already current and `text` is the input byte for byte.
pub(crate) struct ConfigMigration {
    pub(crate) text: String,
    pub(crate) changes: Vec<String>,
}

/// Rewrite one configuration's text for the current schema, leaving alone everything the migration does not know.
///
/// Stable contract: a line the migration does not rewrite is copied through unchanged, so a user's comments and
/// their own keys survive a migration intact.
///
/// It removes an indented `secretPreviews` block, renames a block-opening `minimumSeverity:` to `failOn:`, and pins `schemaVersion`.
/// `original` is the configuration file's text, split on newlines and rewritten one line at a time.
///
/// Returns the migrated text and one change line per rewrite; when nothing needed changing, `changes` is empty and `text` equals `original`.
pub(crate) fn migrate_config_text(original: &str) -> ConfigMigration {
    let lines: Vec<&str> = original.split('\n').collect();
    let mut migrated: Vec<String> = Vec::with_capacity(lines.len());
    let mut changes: Vec<String> = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let skipped = removed_key_block_length(&lines, index);

        // The removed key takes its whole indented block with it, or an empty list stays behind meaning nothing.
        if skipped > 0 {
            changes.push(change_line(index, REMOVED_KEY_CHANGE));
            index += skipped;
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

/// Report how many lines the removed redaction key occupies, counting the indented lines beneath it up to the first blank line.
///
/// `lines` are the original file's lines and `index` is the line to test, which must be in range or the lookup panics.
/// Returns 0 unless the line is an indented `secretPreviews` key, otherwise 1 plus the run of deeper-indented lines after it.
fn removed_key_block_length(lines: &[&str], index: usize) -> usize {
    let line = lines[index];
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();

    // Only the nested allowlists entry is removed, so a root key of that name is left for the loader to refuse.
    if indent == 0 || !key_is(trimmed, "secretPreviews") {
        return 0;
    }

    let mut length = 1;
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

    if !key_is(trimmed, "minimumSeverity") {
        return None;
    }

    // A key with a value on the same line is the 0.6 display floor and keeps its name.
    let tail = trimmed
        .split_once(':')
        .map(|(_, rest)| rest.trim())
        .unwrap_or_default();
    if !tail.is_empty() {
        return None;
    }

    // An empty block would be a key with nothing under it, which the loader reads as neither shape.
    let opens_block = index + 1 < lines.len() && is_deeper_than(lines[index + 1], indent);
    opens_block.then(|| format!("{}failOn:", &line[..indent]))
}

/// Drop a bare block header left directly above the removed block, because a key with nothing under it is not a valid mapping.
///
/// The header stays only when the next original line is non-blank and indented beneath it; a later child after a blank line does not count.
///
/// `migrated` is the output built so far, whose last line is the candidate header.
/// `lines` are the original file's lines and `index` is the first line after the removed block.
fn drop_emptied_parent(migrated: &mut Vec<String>, lines: &[&str], index: usize) {
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
/// The input is only ever read, barring a hard-link destination: a user who regrets the migration still has the configuration they started with,
/// which is what section 8's migration rule requires. Exits 2 when the input cannot be read and, outside a dry run, when no destination was
/// named or the destination resolves to the input's canonical path.
///
/// `args` names the config to read, the optional `--output` destination and whether this is a dry run; `writer` prints the change summary.
///
/// Returns success after a dry run or a completed write, and exit code 2 for non-UTF-8 input, the cases above, or a failed write.
pub(crate) fn run_migrate_config(args: MigrateConfigArgs, writer: &OutputWriter) -> ExitCode {
    let Ok(original) = fs::read_to_string(&args.config) else {
        eprintln!(
            "gruff-rs: config to migrate does not exist or could not be read: {}",
            args.config.display()
        );
        return ExitCode::from(2);
    };

    let migration = migrate_config_text(&original);
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

    if args.dry_run {
        writer.emit_unconditional("Dry run: nothing written.\n");
        return ExitCode::SUCCESS;
    }

    write_migrated(&args, &migration.text, writer)
}

/// Write the migrated text to the destination the user named, refusing a destination whose canonical path is the input's.
///
/// `args` supplies the `--output` destination and the input config path, and `migrated` is the text written.
/// `writer` prints the confirmation; an existing destination that passes that check is overwritten.
///
/// Returns success once written, or exit code 2 after an error on stderr when no destination was named, it is refused, or the write fails.
/// A hard link to the input has a different canonical path, so it is not refused and writing it overwrites the input.
fn write_migrated(args: &MigrateConfigArgs, migrated: &str, writer: &OutputWriter) -> ExitCode {
    // Without a destination there is nowhere to put the result, and writing over the input is the one thing
    // migration must never do; refusing is better than choosing a path the user did not name.
    let Some(output) = args.output.as_ref() else {
        eprintln!(
            "gruff-rs: migrate-config needs --output <path>, or --dry-run to print the changes."
        );
        return ExitCode::from(2);
    };

    if is_same_file(output, &args.config) {
        eprintln!(
            "gruff-rs: --output must name a different file from --config; {} is the copy you may want back.",
            args.config.display()
        );
        return ExitCode::from(2);
    }

    // A destination gruff cannot write is reported rather than swallowed, so the user does not believe it migrated.
    if let Err(error) = fs::write(output, migrated) {
        eprintln!("gruff-rs: unable to write {}: {error}", output.display());
        return ExitCode::from(2);
    }

    writer.emit_unconditional(&format!(
        "Wrote {}; {} is unchanged.\n",
        output.display(),
        args.config.display()
    ));
    ExitCode::SUCCESS
}

/// True when both paths exist and resolve to one canonical path, so a migration cannot be pointed back at its input by name or symlink.
///
/// `left` and `right` are the two paths, each canonicalized on disk before they are compared.
/// Returns true when both canonicalize to the same path, and false when they differ or either cannot be canonicalized, as for a new file.
/// Distinct hard links to one file canonicalize to different paths, so they compare false.
fn is_same_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(resolved_left), Ok(resolved_right)) => resolved_left == resolved_right,
        _ => false,
    }
}
