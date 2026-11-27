use super::*;

/// Summarise the project's `Cargo.toml` for project rules: package line, name, description, license and dependencies.
///
/// `project_root` is the directory whose `Cargo.toml` is read, and `diagnostics` receives any read or parse error for it.
/// Returns the summary, or None when `Cargo.toml` is absent, cannot be read or is not valid TOML.
pub(crate) fn read_manifest_summary(
    project_root: &Path,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<ManifestSummary> {
    let raw = read_manifest_raw(project_root, diagnostics)?;
    let value = parse_manifest_value(&raw, diagnostics)?;
    Some(ManifestSummary {
        file_path: "Cargo.toml".to_string(),
        package_line: manifest_package_line(&raw),
        package_name: manifest_package_field(&value, "name"),
        package_description: manifest_package_field(&value, "description"),
        package_license: manifest_package_field(&value, "license"),
        dependencies: manifest_dependencies(&value, &raw),
    })
}

/// Read the text of the project's `Cargo.toml`, reporting a failed read as a run diagnostic.
///
/// `project_root` is the directory to look in, and `diagnostics` gets a `manifest-read-error` entry when the file exists but cannot be read.
/// Returns the file text, or None when the file is absent or unreadable.
pub(crate) fn read_manifest_raw(
    project_root: &Path,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<String> {
    let path = project_root.join("Cargo.toml");
    if !path.exists() {
        return None;
    }
    Some(match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "manifest-read-error".to_string(),
                message: format!("Unable to read Cargo.toml: {error}"),
                file_path: Some("Cargo.toml".to_string()),
                line: Some(1),
                invalidates_run: None,
            });
            return None;
        }
    })
}

/// Parse manifest text as TOML, reporting invalid syntax as a run diagnostic.
///
/// `raw` is the `Cargo.toml` text, and `diagnostics` gets a `manifest-parse-error` entry at line 1 when parsing fails.
/// Returns the parsed TOML value, or None when the text is not valid TOML.
pub(crate) fn parse_manifest_value(
    raw: &str,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<toml::Value> {
    // A whole document deserialises through `from_str`; `str::parse` reads one bare TOML value and rejects every manifest.
    Some(match toml::from_str::<toml::Value>(raw) {
        Ok(value) => value,
        Err(_) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "manifest-parse-error".to_string(),
                message:
                    "Invalid Cargo.toml; fix TOML syntax before project rules use manifest data."
                        .to_string(),
                file_path: Some("Cargo.toml".to_string()),
                line: Some(1),
                invalidates_run: None,
            });
            return None;
        }
    })
}

/// Read one string field from the manifest's `package` table.
///
/// `value` is the parsed manifest, and `field` is the key to read, such as `name` or `license`.
/// Returns the field's text, or None when the `package` table or the field is missing or the field is not a string.
pub(crate) fn manifest_package_field(value: &toml::Value, field: &str) -> Option<String> {
    value
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get(field))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

/// Collect the dependencies listed in the top-level and target-specific dependency tables, with line 1 when no declaration line was found.
///
/// `value` is the parsed manifest, and `raw` is its text, scanned for the declaration lines.
/// Returns the dependencies sorted by section then name, or an empty list when none of those tables has entries.
pub(crate) fn manifest_dependencies(value: &toml::Value, raw: &str) -> Vec<DependencySummary> {
    let dependency_lines = manifest_dependency_lines(raw);
    let mut dependencies = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_manifest_dependencies(value, section, &dependency_lines, &mut dependencies);
    }
    collect_target_manifest_dependencies(value, &dependency_lines, &mut dependencies);
    dependencies.sort_by(|left, right| {
        (left.section.as_str(), left.name.as_str())
            .cmp(&(right.section.as_str(), right.name.as_str()))
    });
    dependencies
}

/// Collect the dependencies declared in each target-specific dependency table under the manifest's `target` table.
///
/// `value` is the parsed manifest, and `dependency_lines` maps a section and dependency name to its declaration line.
/// `dependencies` gets one entry per dependency, with a section name joining `target`, the target key and the table name with dots.
/// A missing or non-table `target`, or a non-table target entry, adds nothing.
pub(crate) fn collect_target_manifest_dependencies(
    value: &toml::Value,
    dependency_lines: &HashMap<(String, String), usize>,
    dependencies: &mut Vec<DependencySummary>,
) {
    let Some(targets) = value.get("target").and_then(toml::Value::as_table) else {
        return;
    };
    for (target, target_value) in targets {
        let Some(target_table) = target_value.as_table() else {
            continue;
        };
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let Some(table) = target_table.get(section).and_then(toml::Value::as_table) else {
                continue;
            };
            let section_name = format!("target.{target}.{section}");
            collect_manifest_dependency_table(table, &section_name, dependency_lines, dependencies);
        }
    }
}

/// Collect the dependencies from one top-level dependency table of the manifest.
///
/// `value` is the parsed manifest, `section` is the table name such as `dev-dependencies`, and `dependency_lines` gives declaration lines.
/// `dependencies` gets one entry per dependency in the table; a missing or non-table section adds nothing.
pub(crate) fn collect_manifest_dependencies(
    value: &toml::Value,
    section: &str,
    dependency_lines: &HashMap<(String, String), usize>,
    dependencies: &mut Vec<DependencySummary>,
) {
    let Some(table) = value.get(section).and_then(toml::Value::as_table) else {
        return;
    };
    collect_manifest_dependency_table(table, section, dependency_lines, dependencies);
}

/// Turn every entry of one dependency table into a dependency summary.
///
/// `table` is the dependency table, and `section` is the section name recorded on each entry and used to look up its line.
/// `dependency_lines` maps a section and name to a declaration line, and `dependencies` gets the new entries appended.
pub(crate) fn collect_manifest_dependency_table(
    table: &toml::value::Table,
    section: &str,
    dependency_lines: &HashMap<(String, String), usize>,
    dependencies: &mut Vec<DependencySummary>,
) {
    for (name, dependency) in table {
        dependencies.push(build_dependency_summary(
            name,
            section,
            dependency,
            dependency_lines,
        ));
    }
}

/// Build the summary for one manifest dependency with its version requirement, git source and declaration line.
///
/// `name` is the dependency key, `section` is its table name, `dependency` is its value, and `dependency_lines` gives its declaration line.
/// Returns the summary, with line 1 when no declaration line was recorded for that section and name.
fn build_dependency_summary(
    name: &str,
    section: &str,
    dependency: &toml::Value,
    dependency_lines: &HashMap<(String, String), usize>,
) -> DependencySummary {
    let (requirement, git, rev) = dependency_source_fields(dependency);
    DependencySummary {
        name: name.to_string(),
        section: section.to_string(),
        line: dependency_lines
            .get(&(section.to_string(), name.to_string()))
            .copied()
            .unwrap_or(1),
        requirement,
        git,
        rev,
    }
}

/// Pull the version requirement, git source and git revision out of one dependency value.
///
/// `dependency` is either a bare version string or a table with optional `version`, `git` and `rev` keys.
/// Returns the version, git and rev strings in that order, each None when its table key is missing or not a string.
/// A bare string fills only the version, and a value that is neither a string nor a table gives three Nones.
fn dependency_source_fields(
    dependency: &toml::Value,
) -> (Option<String>, Option<String>, Option<String>) {
    if let Some(requirement) = dependency.as_str() {
        return (Some(requirement.to_string()), None, None);
    }
    let Some(table) = dependency.as_table() else {
        return (None, None, None);
    };
    (
        table_str_field(table, "version"),
        table_str_field(table, "git"),
        table_str_field(table, "rev"),
    )
}

/// Read one string value from a TOML table by key.
///
/// `table` is the table to read, and `key` is the field name.
/// Returns the field's text, or None when the key is missing or its value is not a string.
fn table_str_field(table: &toml::value::Table, key: &str) -> Option<String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

/// Find the 1-based line of the `package` table header in manifest text.
///
/// `raw` is the `Cargo.toml` text.
/// Returns the first line whose trimmed text is exactly the bare `package` header, or 1 when there is none.
pub(crate) fn manifest_package_line(raw: &str) -> usize {
    raw.lines()
        .enumerate()
        .find_map(|(index, line)| (line.trim() == "[package]").then_some(index + 1))
        .unwrap_or(1)
}

/// Find the 1-based line of each simple dependency assignment under a recognised dependency section header, using a line scan.
///
/// `raw` is the `Cargo.toml` text; only lines with an equals sign under a dependency section header are recorded, by their key.
/// Returns a map from the quote-stripped section name and dependency name to its line; a repeated key keeps its last line.
pub(crate) fn manifest_dependency_lines(raw: &str) -> HashMap<(String, String), usize> {
    let mut lines = HashMap::new();
    let mut current_section: Option<String> = None;

    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = normalize_manifest_section(trimmed.trim_matches(&['[', ']'][..]));
            current_section = is_dependency_section(&section).then_some(section);
            continue;
        }

        let Some(section) = &current_section else {
            continue;
        };
        let Some((name, _)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_matches('"').trim_matches('\'');
        if !name.is_empty() && !name.starts_with('#') {
            lines.insert((section.clone(), name.to_string()), index + 1);
        }
    }

    lines
}

/// Remove every single and double quote from a manifest section name before it is used as a dependency-line lookup key.
///
/// `section` is the header text without its surrounding brackets.
/// Returns the section name with every single and double quote removed.
fn normalize_manifest_section(section: &str) -> String {
    section.replace(['"', '\''], "")
}

/// Decide whether a quote-stripped section name holds dependency declarations.
///
/// `section` is the normalized header name.
/// Returns true for `dependencies`, `dev-dependencies` and `build-dependencies`, and for any name ending in a dot and one of those three.
fn is_dependency_section(section: &str) -> bool {
    matches!(
        section,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    ) || section.ends_with(".dependencies")
        || section.ends_with(".dev-dependencies")
        || section.ends_with(".build-dependencies")
}
