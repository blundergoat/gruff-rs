use super::*;

#[test]
pub(crate) fn error_handling_rules_flag_production_hazards_and_skip_tests() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "error-handling-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for error-handling rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"pub fn parse_public(input: &str) -> usize {
    input.parse::<usize>().unwrap()
}

pub fn production_panic(flag: bool) {
    if flag {
        panic!("broken invariant");
    }
}

fn unfinished() {
    todo!("finish this branch");
}

fn private_unwrap(input: &str) -> usize {
    input.parse::<usize>().unwrap()
}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("error-handling positive analysis succeeds");
    assert_has_rule(&positive, "error-handling.production-panic");
    assert_has_rule(&positive, "error-handling.unimplemented-placeholder");
    assert_has_rule(&positive, "error-handling.public-unwrap");
    assert_has_rule(&positive, "waste.unwrap-expect");

    let public_unwrap = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "error-handling.public-unwrap")
        .expect("public unwrap finding");
    assert_eq!(public_unwrap.symbol.as_deref(), Some("parse_public"));
    assert_eq!(public_unwrap.severity, Severity::Warning);
    assert!(matches!(public_unwrap.confidence, Confidence::High));
    assert!(public_unwrap
        .remediation
        .as_deref()
        .is_some_and(|message| message.contains("Result")));

    let panic = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "error-handling.production-panic")
        .expect("production panic finding");
    assert_eq!(panic.symbol.as_deref(), Some("production_panic"));
    assert!(panic.message.contains("panic!"));

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "error-handling-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for error-handling rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"pub fn parse_public(input: &str) -> Result<usize, std::num::ParseIntError> {
    input.parse::<usize>()
}

pub fn documented_invariant(flag: bool) {
    // PANIC: this branch represents an impossible state checked by the caller.
    if flag {
        panic!("documented invariant");
    }
}

#[test]
fn panic_in_test() {
    panic!("expected failure");
}

mod tests {
    pub fn helper_placeholder() {
        todo!("test helper");
    }
}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("error-handling negative analysis succeeds");
    assert_missing_rule(&negative, "error-handling.production-panic");
    assert_missing_rule(&negative, "error-handling.unimplemented-placeholder");
    assert_missing_rule(&negative, "error-handling.public-unwrap");
}

#[test]
pub(crate) fn concurrency_rules_flag_narrow_async_and_channel_patterns() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "concurrency-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for concurrency rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"pub async fn blocks_runtime() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}

pub async fn holds_lock(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    async_step().await;
    println!("{}", *guard);
}

pub fn creates_unbounded_channel() {
    let (_tx, _rx) = std::sync::mpsc::channel::<String>();
}

async fn async_step() {}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("concurrency positive analysis succeeds");
    assert_has_rule(&positive, "concurrency.blocking-call-in-async");
    assert_has_rule(&positive, "concurrency.lock-across-await");
    assert_has_rule(&positive, "concurrency.unbounded-channel");

    let blocking = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "concurrency.blocking-call-in-async")
        .expect("blocking async finding");
    assert_eq!(blocking.symbol.as_deref(), Some("blocks_runtime"));
    assert!(blocking.message.contains("std::thread::sleep"));
    assert!(matches!(blocking.confidence, Confidence::Medium));

    let lock = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "concurrency.lock-across-await")
        .expect("lock across await finding");
    assert_eq!(lock.symbol.as_deref(), Some("holds_lock"));
    assert_eq!(lock.metadata["guard"], json!("guard"));

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "concurrency-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for concurrency rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"pub async fn async_timer() {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
}

pub async fn drops_before_await(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    drop(guard);
    async_step().await;
}

pub async fn scoped_before_await(lock: &std::sync::RwLock<String>) {
    {
        let mut state = lock.write().unwrap();
        state.push_str("ready");
    }
    async_step().await;
}

pub fn bounded_channel() {
    let (_tx, _rx) = tokio::sync::mpsc::channel::<String>(16);
}

mod tests {
    pub async fn blocking_test_helper() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    pub fn test_channel_helper() {
        let (_tx, _rx) = std::sync::mpsc::channel::<String>();
    }
}

async fn async_step() {}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("concurrency negative analysis succeeds");
    assert_missing_rule(&negative, "concurrency.blocking-call-in-async");
    assert_missing_rule(&negative, "concurrency.lock-across-await");
    assert_missing_rule(&negative, "concurrency.unbounded-channel");
}

#[test]
pub(crate) fn performance_rules_flag_loop_scoped_hotspots() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "performance-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for performance rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"pub fn loop_hotspots(values: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let regex = Regex::new("ready").unwrap();
        if regex.is_match(value) {
            output.push(format!("{}", value.clone()));
        }
    }
    output
}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("performance positive analysis succeeds");
    assert_has_rule(&positive, "performance.regex-in-loop");
    assert_has_rule(&positive, "performance.format-in-loop");
    assert_has_rule(&positive, "performance.clone-in-loop");

    let regex = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "performance.regex-in-loop")
        .expect("regex-in-loop finding");
    assert_eq!(regex.symbol.as_deref(), Some("loop_hotspots"));
    assert_eq!(regex.metadata["pattern"], json!("Regex::new"));
    assert_eq!(regex.metadata["occurrences"], json!(1));
    assert!(regex.message.contains("Regex::new"));

    let waste = positive
        .score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Maintainability)
        .expect("waste score");
    assert!(
        waste.findings >= 3,
        "expected performance findings in waste: {waste:?}"
    );

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "performance-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for performance rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"pub fn setup_outside_loop(values: &[String]) -> Vec<String> {
    let regex = Regex::new("ready").unwrap();
    let label = format!("{}", values.len());
    let cloned = label.clone();
    let mut output = Vec::new();
    for value in values {
        if regex.is_match(value) {
            output.push(cloned.to_string());
        }
    }
    output
}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("performance negative analysis succeeds");
    assert_missing_rule(&negative, "performance.regex-in-loop");
    assert_missing_rule(&negative, "performance.format-in-loop");
    assert_missing_rule(&negative, "performance.clone-in-loop");
}

#[test]
pub(crate) fn rule_fixtures_prove_complexity_and_naming_rules() {
    let _guard = analysis_lock();
    let positive = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/complexity_naming_positive.rs",
    )]);
    let negative = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/complexity_naming_negative.rs",
    )]);

    assert_has_rule(&positive, "complexity.nesting-depth");
    assert_has_rule(&positive, "complexity.npath");
    assert_has_rule(&positive, "naming.boolean-prefix");
    assert_has_rule(&positive, "naming.placeholder-identifier");

    assert_missing_rule(&negative, "complexity.nesting-depth");
    assert_missing_rule(&negative, "complexity.npath");
    assert_missing_rule(&negative, "naming.boolean-prefix");
    assert_missing_rule(&negative, "naming.placeholder-identifier");
}

#[test]
pub(crate) fn rule_fixtures_prove_security_sensitive_and_test_quality_rules() {
    let _guard = analysis_lock();
    let security_positive = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/security_sensitive_positive.rs",
    )]);
    let security_negative = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/security_sensitive_negative.rs",
    )]);
    let test_positive = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/test_quality_positive.rs",
    )]);
    let test_negative = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/test_quality_negative.rs",
    )]);

    assert_has_rule(&security_positive, "security.unsafe-block");
    assert_has_rule(&security_positive, "sensitive-data.hardcoded-env-value");
    assert_has_rule(&security_positive, "sensitive-data.high-entropy-string");

    assert_missing_rule(&security_negative, "security.unsafe-block");
    assert_missing_rule(&security_negative, "sensitive-data.hardcoded-env-value");
    assert_missing_rule(&security_negative, "sensitive-data.high-entropy-string");

    assert_has_rule(&test_positive, "test-quality.ignored-without-reason");
    assert_has_rule(&test_positive, "test-quality.long-test");
    assert_has_rule(&test_positive, "test-quality.trivial-assertion");

    assert_missing_rule(&test_negative, "test-quality.ignored-without-reason");
    assert_missing_rule(&test_negative, "test-quality.long-test");
    assert_missing_rule(&test_negative, "test-quality.trivial-assertion");
    assert_missing_rule(&test_negative, "test-quality.sleep-in-test");
    assert_missing_rule(&test_negative, "test-quality.no-assertions");
}
