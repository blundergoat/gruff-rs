//! Rust rule behavior tests run the analyzer against complete temporary projects.
//! The cases keep production hazards, supported syntax shapes, and quiet examples
//! together so a rule cannot gain apparent precision by silently losing coverage.

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

/// Synthetic async functions covering every retained and rejected acquisition shape.
const LOCK_ACROSS_AWAIT_SOURCE: &str = r#"pub struct DomainReader;
impl DomainReader {
    pub fn read(&self) -> usize { 1 }
}
pub struct DomainWriter;
impl DomainWriter {
    pub fn write(&self) -> usize { 1 }
}
pub async fn mutex_unwrap(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    async_step().await;
    let _ = guard;
}
pub async fn mutex_expect(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().expect("state lock");
    async_step().await;
    let _ = guard;
}
pub async fn mutex_question(lock: &std::sync::Mutex<String>) -> Result<(), ()> {
    let guard = lock.lock()?;
    async_step().await;
    let _ = guard;
    Ok(())
}
pub async fn async_mutex_await(lock: &tokio::sync::Mutex<String>) {
    let guard = lock.lock().await;
    async_step().await;
    let _ = guard;
}
pub async fn parking_lot_lock(lock: &parking_lot::Mutex<String>) {
    let _guard = lock.lock();
    async_step().await;
}
pub async fn sync_read_unwrap(lock: &std::sync::RwLock<String>) {
    let guard = lock.read().unwrap();
    async_step().await;
    let _ = guard;
}
pub async fn sync_write_expect(lock: &std::sync::RwLock<String>) {
    let guard = lock.write().expect("state lock");
    async_step().await;
    let _ = guard;
}
pub async fn async_read_await(lock: &tokio::sync::RwLock<String>) {
    let guard = lock.read().await;
    async_step().await;
    let _ = guard;
}
pub async fn async_write_await(lock: &tokio::sync::RwLock<String>) {
    let guard = lock.write().await;
    async_step().await;
    let _ = guard;
}
pub async fn local_read_constructor() {
    let lock = std::sync::RwLock::new(String::new());
    let guard = lock.read().unwrap();
    async_step().await;
    let _ = guard;
}
pub async fn reads_bytes(reader: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<()> {
    let read = reader.read(buf)?;
    async_step().await;
    let _ = read;
    Ok(())
}
pub async fn writes_bytes(file: &mut std::fs::File, buf: &[u8]) -> std::io::Result<()> {
    let written = file.write(buf)?;
    async_step().await;
    let _ = written;
    Ok(())
}
pub async fn domain_read(reader: &DomainReader) {
    let value = reader.read();
    async_step().await;
    let _ = value;
}
pub async fn domain_write(writer: &DomainWriter) {
    let value = writer.write();
    async_step().await;
    let _ = value;
}
pub async fn take_value(lock: &tokio::sync::Mutex<Option<String>>) {
    let value = lock.lock().await.take();
    async_step().await;
    drop(value);
}
pub async fn drop_before_await(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    drop(guard);
    async_step().await;
}
pub async fn scoped_before_await(lock: &std::sync::RwLock<String>) {
    {
        let guard = lock.write().unwrap();
        let _ = guard;
    }
    async_step().await;
}
pub struct SharedRegistry {
    state: tokio::sync::RwLock<String>,
    reader: DomainReader,
}
impl SharedRegistry {
    pub async fn field_write_await(&self) {
        let guard = self.state.write().await;
        async_step().await;
        let _ = guard;
    }
    pub async fn field_domain_read(&self) {
        let value = self.reader.read();
        async_step().await;
        let _ = value;
    }
}
async fn async_step() {}
"#;

#[test]
/// Keeps supported guard acquisitions while rejecting I/O and domain methods.
pub(crate) fn lock_across_await_requires_guard_shaped_acquisitions() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), LOCK_ACROSS_AWAIT_SOURCE);
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    // Compare the full finding set so each retained and rejected syntax shape is contractual.
    let lock_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "concurrency.lock-across-await")
        .collect();
    let lock_symbols: BTreeSet<&str> = lock_findings
        .iter()
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();
    assert_eq!(
        lock_symbols,
        BTreeSet::from([
            "async_mutex_await",
            "async_read_await",
            "async_write_await",
            // A guard taken from a lock-typed struct field is the common async-service shape.
            "field_write_await",
            "local_read_constructor",
            "mutex_expect",
            "mutex_question",
            "mutex_unwrap",
            "parking_lot_lock",
            "sync_read_unwrap",
            "sync_write_expect",
        ]),
        "only receiver-evidenced lock guards should flag; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref()))
            .collect::<Vec<_>>()
    );
    assert!(lock_findings.iter().all(|finding| {
        matches!(finding.confidence, Confidence::Medium)
            && finding.message.contains("appears to hold lock guard")
    }));
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
    assert_has_rule(&positive, "naming.boolean-prefix");
    assert_has_rule(&positive, "naming.placeholder-identifier");

    assert_missing_rule(&negative, "complexity.nesting-depth");
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
    assert_missing_rule(&test_negative, "test-quality.conditional-logic");
    assert_missing_rule(&test_negative, "test-quality.unwrap-in-test");
}

#[test]
pub(crate) fn sensitive_data_rules_do_not_change_with_test_path() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let source = fs::read_to_string("tests/fixtures/rules/security_sensitive_positive.rs")
        .expect("sensitive fixture read");
    let relative_paths = [
        "src/sensitive.rs",
        "tests/sensitive.rs",
        "tests/calibration/sensitive.rs",
    ];

    for relative_path in relative_paths {
        let destination = dir.path().join(relative_path);
        fs::create_dir_all(destination.parent().expect("sensitive fixture parent"))
            .expect("sensitive fixture directory");
        fs::write(destination, &source).expect("sensitive fixture write");
    }

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: relative_paths.into_iter().map(PathBuf::from).collect(),
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("sensitive path analysis succeeds");
    let sensitive_rule_ids = |relative_path: &str| {
        report
            .findings
            .iter()
            .filter(|finding| {
                finding.file_path == relative_path && finding.rule_id.starts_with("sensitive-data.")
            })
            .map(|finding| finding.rule_id.clone())
            .collect::<BTreeSet<_>>()
    };
    let production_rule_ids = sensitive_rule_ids("src/sensitive.rs");

    assert!(production_rule_ids.contains("sensitive-data.hardcoded-env-value"));
    assert!(production_rule_ids.contains("sensitive-data.high-entropy-string"));
    assert_eq!(
        sensitive_rule_ids("tests/sensitive.rs"),
        production_rule_ids
    );
    assert_eq!(
        sensitive_rule_ids("tests/calibration/sensitive.rs"),
        production_rule_ids
    );
}
