use super::*;

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
            });
            return None;
        }
    })
}

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
            });
            return None;
        }
    })
}

pub(crate) fn locked_packages(value: &toml::Value, raw: &str) -> Vec<LockedPackageSummary> {
    let package_lines = lockfile_package_lines(raw);
    let mut packages = collect_locked_packages(value, &package_lines);
    sort_locked_packages(&mut packages);
    packages
}

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

pub(crate) fn quoted_toml_value(line: &str, key: &str) -> Option<String> {
    let (left, right) = line.split_once('=')?;
    if left.trim() != key {
        return None;
    }
    Some(right.trim().trim_matches('"').to_string())
}
