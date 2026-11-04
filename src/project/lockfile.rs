use super::*;

/// Read and parse the project's `Cargo.lock` into a summary of its locked packages.
///
/// `project_root` is the directory expected to hold `Cargo.lock`, and `diagnostics` receives a read or parse error diagnostic.
/// Returns the summary with packages sorted by name, version and source, or `None` when the file is absent, unreadable or not valid TOML.
pub(crate) fn read_lockfile_summary(
    project_root: &Path,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<LockfileSummary> {
    let raw = read_lockfile_raw(project_root, diagnostics)?;
    let value = parse_lockfile_value(&raw, diagnostics)?;
    Some(LockfileSummary {
        file_path: "Cargo.lock".to_string(),
        packages: locked_packages(&value, &raw),
    })
}

/// Load the raw text of `Cargo.lock` from the project root, recording a diagnostic only when `Path::exists` finds it but the read fails.
///
/// `project_root` is the directory joined with `Cargo.lock`, and `diagnostics` receives a `lockfile-read-error` entry on a read failure.
/// Returns the file contents, or `None` when `Path::exists` finds no file there, which includes an unreachable path, or the read fails.
pub(crate) fn read_lockfile_raw(
    project_root: &Path,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<String> {
    let path = project_root.join("Cargo.lock");
    if !path.exists() {
        return None;
    }
    Some(match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "lockfile-read-error".to_string(),
                message: format!("Unable to read Cargo.lock: {error}"),
                file_path: Some("Cargo.lock".to_string()),
                line: Some(1),
                invalidates_run: None,
            });
            return None;
        }
    })
}

/// Parse raw `Cargo.lock` text as TOML, recording a diagnostic when the syntax is invalid.
///
/// `raw` is the lockfile text, and `diagnostics` receives a `lockfile-parse-error` entry, without the parser's own message, on failure.
/// Returns the parsed TOML value, or `None` when `raw` is not valid TOML.
pub(crate) fn parse_lockfile_value(
    raw: &str,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<toml::Value> {
    Some(match raw.parse::<toml::Value>() {
        Ok(value) => value,
        Err(_) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "lockfile-parse-error".to_string(),
                message: "Invalid Cargo.lock; regenerate or fix TOML syntax before project rules use lockfile data."
                    .to_string(),
                file_path: Some("Cargo.lock".to_string()),
                line: Some(1),
                invalidates_run: None,
            });
            return None;
        }
    })
}

/// Build the sorted list of locked packages from a parsed lockfile, attaching a line found by package name and version.
///
/// `value` is the parsed lockfile whose `package` array is read, and `raw` is the same text, scanned for the `name` line of each pair.
/// Returns the packages with a string name and version, sorted by name, version and source, or an empty list without a `package` array.
/// A pair with no scanned line is placed on line 1, and a repeated pair shares the last such line.
pub(crate) fn locked_packages(value: &toml::Value, raw: &str) -> Vec<LockedPackageSummary> {
    let package_lines = lockfile_package_lines(raw);
    let mut packages = collect_locked_packages(value, &package_lines);
    sort_locked_packages(&mut packages);
    packages
}

/// Convert each entry of the lockfile's `package` array into a package summary, keeping array order.
///
/// `value` is the parsed lockfile, and `package_lines` maps each name and version pair to the line of its `name` key.
/// Returns one summary per table entry with a string name and version; a missing or non-array `package` key gives an empty list.
fn collect_locked_packages(
    value: &toml::Value,
    package_lines: &HashMap<(String, String), usize>,
) -> Vec<LockedPackageSummary> {
    value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| locked_package_from_value(package, package_lines))
        .collect()
}

/// Convert one `package` table from the lockfile into a summary of its name, version, optional source and line.
///
/// `package` is one entry of the `package` array, and `package_lines` supplies its line, which defaults to 1 when the pair is not listed.
/// Returns the summary, or `None` when `package` is not a table or lacks a string `name` or `version`.
/// A non-string `source` is recorded as no source.
fn locked_package_from_value(
    package: &toml::Value,
    package_lines: &HashMap<(String, String), usize>,
) -> Option<LockedPackageSummary> {
    let table = package.as_table()?;
    let name = table.get("name")?.as_str()?.to_string();
    let version = table.get("version")?.as_str()?.to_string();
    let source = table
        .get("source")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let line = package_lines
        .get(&(name.clone(), version.clone()))
        .copied()
        .unwrap_or(1);
    Some(LockedPackageSummary {
        name,
        version,
        line,
        source,
    })
}

/// Sort locked packages in place by name, then version string, then source, with a missing source ordered first.
///
/// `packages` is reordered in place by a stable sort, so entries with equal keys keep their relative order.
fn sort_locked_packages(packages: &mut [LockedPackageSummary]) {
    packages.sort_by(|left, right| {
        (
            left.name.as_str(),
            left.version.as_str(),
            left.source.as_deref(),
        )
            .cmp(&(
                right.name.as_str(),
                right.version.as_str(),
                right.source.as_deref(),
            ))
    });
}

/// Scan raw `Cargo.lock` text for the 1-based line of each package's `name` key, keyed by package name and version.
///
/// `raw` is the lockfile text, read line by line without a TOML parser.
/// A `version` line pairs with the latest `name` line since the last package header, even under another table such as metadata.
/// Returns a map from each name and version pair to its `name` line; a repeated pair keeps the last line seen.
pub(crate) fn lockfile_package_lines(raw: &str) -> HashMap<(String, String), usize> {
    let mut lines = HashMap::new();
    let mut current_name: Option<(String, usize)> = None;

    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            current_name = None;
            continue;
        }
        if let Some(name) = quoted_toml_value(trimmed, "name") {
            current_name = Some((name, index + 1));
            continue;
        }
        if let (Some((name, line)), Some(version)) =
            (&current_name, quoted_toml_value(trimmed, "version"))
        {
            lines.insert((name.clone(), version), *line);
        }
    }

    lines
}

/// Read the value of a simple `key = value` line without a TOML parser.
///
/// `line` is one lockfile line, and `key` is the name that must appear, trimmed, before its first `=`.
///
/// Returns the text after the first `=` with whitespace and surrounding double quotes trimmed, even when the value was not quoted.
/// Returns `None` when the line has no `=` or the text before it is not `key`.
pub(crate) fn quoted_toml_value(line: &str, key: &str) -> Option<String> {
    let (left, right) = line.split_once('=')?;
    if left.trim() != key {
        return None;
    }
    Some(right.trim().trim_matches('"').to_string())
}
