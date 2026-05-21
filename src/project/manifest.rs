use super::*;

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
            });
            return None;
        }
    })
}

pub(crate) fn parse_manifest_value(
    raw: &str,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<toml::Value> {
    Some(match raw.parse::<toml::Value>() {
        Ok(value) => value,
        Err(_) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "manifest-parse-error".to_string(),
                message:
                    "Invalid Cargo.toml; fix TOML syntax before project rules use manifest data."
                        .to_string(),
                file_path: Some("Cargo.toml".to_string()),
                line: Some(1),
            });
            return None;
        }
    })
}

pub(crate) fn manifest_package_field(value: &toml::Value, field: &str) -> Option<String> {
    value
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get(field))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

pub(crate) fn manifest_dependencies(value: &toml::Value, raw: &str) -> Vec<DependencySummary> {
    let dependency_lines = manifest_dependency_lines(raw);
    let mut dependencies = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_manifest_dependencies(value, section, &dependency_lines, &mut dependencies);
    }
    dependencies.sort_by(|left, right| {
        (left.section.as_str(), left.name.as_str())
            .cmp(&(right.section.as_str(), right.name.as_str()))
    });
    dependencies
}

pub(crate) fn collect_manifest_dependencies(
    value: &toml::Value,
    section: &str,
    dependency_lines: &HashMap<(String, String), usize>,
    dependencies: &mut Vec<DependencySummary>,
) {
    let Some(table) = value.get(section).and_then(toml::Value::as_table) else {
        return;
    };

    for (name, dependency) in table {
        dependencies.push(build_dependency_summary(
            name,
            section,
            dependency,
            dependency_lines,
        ));
    }
}

fn build_dependency_summary(
    name: &str,
    section: &str,
    dependency: &toml::Value,
    dependency_lines: &HashMap<(String, String), usize>,
) -> DependencySummary {
    let (requirement, path, git) = dependency_source_fields(dependency);
    DependencySummary {
        name: name.to_string(),
        section: section.to_string(),
        line: dependency_lines
            .get(&(section.to_string(), name.to_string()))
            .copied()
            .unwrap_or(1),
        requirement,
        path,
        git,
    }
}

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
        table_str_field(table, "path"),
        table_str_field(table, "git"),
    )
}

fn table_str_field(table: &toml::value::Table, key: &str) -> Option<String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

pub(crate) fn manifest_package_line(raw: &str) -> usize {
    raw.lines()
        .enumerate()
        .find_map(|(index, line)| (line.trim() == "[package]").then_some(index + 1))
        .unwrap_or(1)
}

pub(crate) fn manifest_dependency_lines(raw: &str) -> HashMap<(String, String), usize> {
    let mut lines = HashMap::new();
    let mut current_section: Option<String> = None;

    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed.trim_matches(&['[', ']'][..]).to_string();
            current_section = matches!(
                section.as_str(),
                "dependencies" | "dev-dependencies" | "build-dependencies"
            )
            .then_some(section);
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
