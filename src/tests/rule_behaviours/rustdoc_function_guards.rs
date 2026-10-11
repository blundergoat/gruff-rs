//! Function-rustdoc behavior tests exercise complete temporary Rust projects.
//! They keep accepted outer comments, rejected lookalikes, documentation rules,
//! and function-length identity together so one fix cannot diverge another path.

use super::*;

/// Analyse one source file without project config so built-in rustdoc defaults remain visible.
fn analyse_rustdoc_source(source: &str) -> AnalysisReport {
    let directory = tempdir().expect("tempdir");
    baseline_with_lib(directory.path(), source);
    run_project_analysis(
        directory.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("rustdoc fixture analysis succeeds")
}

/// Accepts an attached block rustdoc comment as the public function's intent description.
#[test]
pub(crate) fn missing_public_doc_recognizes_block_rustdoc() {
    let _guard = analysis_lock();
    let report = analyse_rustdoc_source(
        r#"/**
Returns `value` unchanged for the caller.
*/
pub fn block_documented(value: usize) -> usize {
    value
}
"#,
    );

    // The missing-public scan must stay silent for the supported attached comment.
    assert!(
        !report.findings.iter().any(|finding| {
            finding.rule_id == "docs.missing-public-doc"
                && finding.symbol.as_deref() == Some("block_documented")
        }),
        "attached block rustdoc must satisfy the public-doc rule; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}

/// Feeds block rustdoc text into every function-level section and quality rule.
#[test]
pub(crate) fn function_docs_use_block_rustdoc_for_every_rule() {
    let _guard = analysis_lock();
    let report = analyse_rustdoc_source(
        r#"/**
Loads `input` for the caller.

# Errors
Returns an error when `input` is empty.
*/
pub fn load(input: &str) -> Result<usize, String> {
    Ok(input.len())
}

/**
Returns the validated `input`.

# Panics
Panics if `input` is zero.
*/
pub fn validated(input: usize) -> usize {
    if input == 0 {
        panic!("zero input");
    }
    input
}

/**
Reads `pointer` and returns its byte.

# Safety
The caller guarantees `pointer` is valid and aligned for `u8`.
*/
pub unsafe fn read_byte(pointer: *const u8) -> u8 {
    *pointer
}
"#,
    );

    // Every function-doc consumer must stay silent for its documented rule/symbol pair.
    for (rule_id, symbol) in [
        ("docs.missing-errors-section", "load"),
        ("docs.missing-panics-section", "validated"),
        ("docs.missing-safety-section", "read_byte"),
        ("docs.missing-param-doc", "load"),
        ("docs.missing-param-doc", "validated"),
        ("docs.missing-param-doc", "read_byte"),
        ("docs.missing-return-doc", "validated"),
        ("docs.missing-return-doc", "read_byte"),
    ] {
        // The collected finding details keep any unexpected rule result reviewable.
        assert!(
            !report.findings.iter().any(|finding| {
                finding.rule_id == rule_id && finding.symbol.as_deref() == Some(symbol)
            }),
            "{rule_id} must read block rustdoc for `{symbol}`; findings={:?}",
            report
                .findings
                .iter()
                .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
                .collect::<Vec<_>>()
        );
    }
}

/// Keeps outer block and line rustdoc distinct from inner, ordinary, detached, and explicit forms.
#[test]
pub(crate) fn function_docs_accept_only_supported_outer_rustdoc() {
    let _guard = analysis_lock();
    let report = analyse_rustdoc_source(
        r#"//! Crate documentation does not document the next function.
/*! Inner block documentation also belongs to the crate. */

pub fn inner_docs_are_not_function_docs() {}

// An ordinary line comment is not API documentation.
pub fn ordinary_line_comment() {}

/* An ordinary block comment is not API documentation. */
pub fn ordinary_block_comment() {}

/** Documentation attached to the structure. */
pub struct DocumentedItem;

pub fn docs_attached_to_another_item() {}

#[doc = "Explicit doc attributes remain outside this milestone."]
pub fn explicit_doc_attribute() {}

/// Existing line rustdoc remains accepted.
pub fn line_documented() {}

/**
 * Block rustdoc remains attached across blank lines and stacked attributes.
 * Nested slash-like text such as /* an inner block */ stays part of the comment.
 */

#[cfg_attr(any(), inline)]
#[allow(dead_code)]
pub fn block_documented_with_attributes() {}

/// Documents the nested module.
pub mod nested {
    /** Documents a nested public function. */
    pub fn block_documented_nested() {}
}
"#,
    );

    // Only missing-public results matter when comparing supported and rejected comments.
    let missing_symbols: BTreeSet<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "docs.missing-public-doc")
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();
    assert_eq!(
        missing_symbols,
        BTreeSet::from([
            "docs_attached_to_another_item",
            "explicit_doc_attribute",
            "inner_docs_are_not_function_docs",
            "ordinary_block_comment",
            "ordinary_line_comment",
        ]),
        "only unsupported or detached comments should leave functions undocumented"
    );
}

/// Counts declaration and body lines while preserving existing size-finding identities.
#[test]
pub(crate) fn function_length_excludes_rustdoc_and_attributes() {
    let _guard = analysis_lock();
    let directory = tempdir().expect("tempdir");
    baseline_with_lib(
        directory.path(),
        r#"/// Returns the measured value.
///
/// Keeps required API documentation outside the executable size count.
#[inline]
#[cold]
pub fn measured() -> usize {
    let first = 1;
    first + 1
}
"#,
    );
    write_config(
        directory.path(),
        "rules:\n  size.function-length:\n    threshold: 3\n    severity: warning\n",
    );
    let report = run_project_analysis(
        directory.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("function-length fixture analysis succeeds");
    // The controlled size finding exposes its line, identities, and measured metadata.
    let finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "size.function-length"
                && finding.symbol.as_deref() == Some("measured")
        })
        .expect("measured function remains above the controlled threshold");

    assert_eq!(
        finding.line,
        Some(1),
        "the existing finding anchor must stay fixed"
    );
    assert_eq!(finding.fingerprint, "44b204f4b4481dd7");
    assert_eq!(finding.stable_identity, "30ce12daa68ddd0f");
    assert_eq!(
        finding.metadata["measured"],
        json!(4),
        "rustdoc and attributes must not count; finding={finding:?}"
    );
    assert!(finding.message.contains("has 4 lines"));
}

/// Build one function with `statements` statements between its signature and its tail: `statements + 3` code lines.
/// Padding puts a blank, comment, doc-comment or attribute line, and once a multi-line attribute, between statements.
fn chained_function(statements: usize, padded: bool) -> String {
    let mut source =
        String::from("/// Sums a chain of values.\npub fn chained(seed: i32) -> i32 {\n");
    for index in 0..statements {
        if padded {
            source.push_str(match index % 4 {
                0 => "\n",
                1 => "    // The next step adds its index.\n",
                2 => "    /// Step of the chain.\n",
                _ => "    #[allow(unused_variables)]\n",
            });
            if index == 10 {
                source.push_str(
                    "    #[allow(\n        unused_variables,\n        unused_mut,\n    )]\n",
                );
            }
        }
        source.push_str(&format!("    let value_{index} = seed + {index};\n"));
    }
    source.push_str("    seed\n}\n");
    source
}

/// Function length counts code lines only (FAMILY-CONTRACT section 12, search `Code lines in every line count`): the
/// blank, comment, doc-comment and attribute lines inside a body are free, and a function long in code lines reports.
#[test]
pub(crate) fn function_length_counts_code_lines_only() {
    let _guard = analysis_lock();
    let measured = |report: &AnalysisReport| {
        report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "size.function-length")
            .map(|finding| finding.metadata["measured"].clone())
    };

    let at_limit = analyse_rustdoc_source(&chained_function(47, true));
    assert_eq!(
        measured(&at_limit),
        None,
        "fifty code lines with padding between them stay at the limit"
    );

    let over_limit = analyse_rustdoc_source(&chained_function(48, true));
    assert_eq!(
        measured(&over_limit),
        Some(json!(51)),
        "fifty-one code lines report whatever padding sits between them"
    );
}

/// Keep constructor, value-stem, and shared-receiver getter descriptions quiet for API readers.
///
/// Incomplete or action prose still warns; bool results must say what true means. The fixture also checks
/// nested functions, receiver ownership, wrapped summaries, and attributes.
#[test]
pub(crate) fn missing_return_doc_reads_constructor_stem_and_getter_summaries() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"//! Probe crate.

/// Command-line options.
pub struct Cli {
    level: u8,
}

impl Cli {
    /// Parse CLI config overrides.
    pub fn from_options(level: u8) -> Self {
        Self { level }
    }

    /// Logging filter level.
    pub fn log_level(&self) -> u8 {
        self.level
    }

    /// Return the FIPS status.
    pub fn fips(&self) -> bool {
        self.level > 0
    }

    /// Lock the level.
    pub fn lock(&self) -> u8 {
        self.level
    }

    /// Saves the level.
    pub fn save(&self, path: &str) -> bool {
        path.is_empty()
    }

    /// Create a command-line option set.
    pub fn create_level(level: u8) -> Cli {
        Cli { level }
    }

    /// Return early when the level is zero.
    pub fn warm(&self) -> bool {
        self.level == 0
    }

    /// Get ready to flush the level.
    pub fn flush_pending(&self) -> usize {
        usize::from(self.level)
    }

    /// Create the output directory if it is missing.
    pub fn ensure_dir(&self) -> bool {
        self.level > 1
    }

    /// Increment the counter and log the event.
    pub fn count(&self) -> u32 {
        u32::from(self.level)
    }

    /// Try to lock the mutex, blocking the current thread.
    pub fn try_lock(&self) -> u8 {
        self.level
    }

    /// Panics if the name table is poisoned.
    pub fn name(&self) -> u8 {
        self.level
    }

    /// Removes the front element.
    pub fn pop_front(&self) -> Option<u8> {
        Some(self.level)
    }

    /// Resets the counter to zero.
    pub fn reset_counter(&self) -> u64 {
        u64::from(self.level)
    }

    /// Return a value to the pool.
    pub fn release(&self, value: u8) -> bool {
        value == self.level
    }

    /// Gets the response status code.
    pub fn status(&self) -> u8 {
        self.level
    }

    /// Validate the input.
    pub fn validate_input(&self) -> bool {
        self.level > 0
    }

    /// Truncate the log.
    pub fn log(&self) -> usize {
        usize::from(self.level)
    }

    /// Create the index.
    pub fn create_index(&self) -> bool {
        self.level > 0
    }

    /// Split the buffer at the given index.
    pub fn split_off(&mut self, at: u8) -> Self {
        Self { level: at }
    }

    /// Return the connection checked out by the handler
    /// back to the shared pool.
    pub fn give_back(&self, connection: u8) -> bool {
        connection == self.level
    }

    /// Create the directory.
    pub fn create_dir(&self, path: &str) -> Option<bool> {
        Some(path.is_empty())
    }

    /// Checks the header.
    pub fn check_header(&self) -> bool {
        self.level > 0
    }

    /// Wake all waiters.
    pub fn notify_all(&self) -> usize {
        usize::from(self.level)
    }

    /// Checks whether the level is valid.
    pub fn is_valid(&self) -> bool {
        self.level > 0
    }

    /// This socket's local port.
    pub fn local_port(&self) -> u16 {
        u16::from(self.level)
    }

    /// Status code of the response.
    pub fn status_code(&self) -> u16 {
        u16::from(self.level)
    }

    /// Purge expired entries from the cache.
    pub fn purge_expired(&self) -> usize {
        usize::from(self.level)
    }

    /// Apply the pending changes.
    pub fn apply_pending(&self) -> usize {
        usize::from(self.level)
    }

    /// Signal parked waiters if any are sleeping.
    pub fn signal_waiters(&self) -> bool {
        self.level > 0
    }

    /// Split the part off.
    pub fn part(self: &mut Self) -> Self {
        Self { level: self.level }
    }

    /// Enable verbose output.
    pub fn verbose(mut self) -> Self {
        self.level += 1;
        self
    }

    /// Builds the options from parts.
    #[must_use = "the {options} are inert"]
    pub fn from_parts(level: u8) -> Self {
        Self { level }
    }
}

/// Create a marker file at the path.
pub fn create_marker<P: AsRef<str>>(path: P) -> bool
where
    P: Copy,
{
    path.as_ref().is_empty()
}

/// Compute the checksum of the items.
pub fn checksum(items: &[u8]) -> u32 {
    struct Inner;
    impl Inner {
        fn make() -> Self {
            Inner
        }
    }
    let _inner = Inner::make();
    items.len() as u32
}

/// Sum the total of the items.
pub fn total(items: &[u32]) -> u32 {
    struct Acc;
    impl Acc {
        fn value(&self) -> u32 {
            0
        }
    }
    Acc.value() + items.iter().sum::<u32>()
}
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("missing-return-doc analysis succeeds");
    let mut flagged: Vec<String> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "docs.missing-return-doc")
        .filter_map(|finding| finding.symbol.clone())
        .map(|symbol| symbol.rsplit("::").next().unwrap_or(&symbol).to_string())
        .collect();
    flagged.sort();
    assert_eq!(
        flagged,
        vec![
            "apply_pending",
            "check_header",
            "checksum",
            "count",
            "create_dir",
            "create_index",
            "create_marker",
            "ensure_dir",
            "flush_pending",
            "give_back",
            "lock",
            "log",
            "name",
            "notify_all",
            "part",
            "pop_front",
            "purge_expired",
            "release",
            "reset_counter",
            "save",
            "signal_waiters",
            "split_off",
            "total",
            "try_lock",
            "validate_input",
            "warm",
        ]
    );
}

/// Keeps observed getter and conversion descriptions quiet while nearby incomplete descriptions still warn.
/// The source forms mirror pinned alacritty and serde_json methods; each control changes the meaning users would read.
#[test]
pub(crate) fn missing_return_doc_reads_value_nouns_and_conversion_destinations() {
    let _guard = analysis_lock();
    let report = analyse_rustdoc_source(
        r#"//! Return-description cases.

pub struct Direction;
pub struct SearchState;

impl SearchState {
    /// Direction of the search from its origin.
    pub fn direction(&self) -> Direction { Direction }

    /// Direction to take next.
    pub fn ambiguous_direction(&self) -> Direction { Direction }

    /// Direction of the search from its origin.
    pub fn status(&self) -> Direction { Direction }

    /// Lock the mutex.
    pub fn lock(&self) -> Direction { Direction }
}

pub struct Number;

impl Number {
    /// Converts an i128 to a Number. Values outside the supported range return None.
    pub fn from_i128(_value: i128) -> Option<Number> { Some(Number) }

    /// Converts an i128 to a String.
    pub fn wrong_target(_value: i128) -> Option<Number> { Some(Number) }

    /// Converts an i128.
    pub fn missing_destination(_value: i128) -> Option<Number> { Some(Number) }

    /// Converts an i128 to a Number.
    pub fn returns_bool(_value: i128) -> bool { true }
}
"#,
    );
    let mut warned_methods: Vec<String> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "docs.missing-return-doc")
        .filter_map(|finding| finding.symbol.clone())
        .map(|symbol| symbol.rsplit("::").next().unwrap_or(&symbol).to_string())
        .collect();
    warned_methods.sort();
    assert_eq!(
        warned_methods,
        [
            "ambiguous_direction",
            "lock",
            "missing_destination",
            "returns_bool",
            "status",
            "wrong_target"
        ]
    );
}

/// Project config that turns `everyCallable` on for the three scope-widened documentation rules.
const EVERY_CALLABLE_ON: &str = "rules:
  docs.missing-public-doc:
    options:
      everyCallable: true
  docs.missing-param-doc:
    options:
      everyCallable: true
  docs.missing-return-doc:
    options:
      everyCallable: true
";

/// Analyse one undocumented and one under-documented function at each visibility under `config`, and list
/// the missing-public, missing-param and missing-return findings as sorted (rule id, symbol, severity,
/// message) rows. `Combines both inputs.` names neither parameter nor the return value, so the param and
/// return rules fire wherever they are in scope.
fn every_callable_rows(config: &str) -> Vec<(String, String, String, String)> {
    documentation_rule_rows(
        r#"//! Visibility cases for the everyCallable switch.

fn private_undocumented(left: u32) -> u32 {
    left
}

pub(crate) fn crate_undocumented(left: u32) -> u32 {
    left
}

pub fn public_undocumented(left: u32) -> u32 {
    left
}

/// Combines both inputs.
fn private_add(left: u32, right: u32) -> u32 {
    left + right
}

/// Combines both inputs.
pub(crate) fn crate_add(left: u32, right: u32) -> u32 {
    left + right
}

/// Combines both inputs.
pub fn public_add(left: u32, right: u32) -> u32 {
    left + right
}
"#,
        config,
    )
}

/// Analyse `source` as the library file of a temporary project under `config`, and list the missing-public,
/// missing-param and missing-return findings as sorted (rule id, symbol, severity, message) rows.
fn documentation_rule_rows(source: &str, config: &str) -> Vec<(String, String, String, String)> {
    let directory = tempdir().expect("tempdir");
    baseline_with_lib(directory.path(), source);
    write_config(directory.path(), config);
    let report = run_project_analysis(
        directory.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("everyCallable fixture analysis succeeds");
    let scoped_rules = [
        "docs.missing-param-doc",
        "docs.missing-public-doc",
        "docs.missing-return-doc",
    ];
    let mut rows: Vec<(String, String, String, String)> = report
        .findings
        .iter()
        .filter(|finding| scoped_rules.iter().any(|rule| finding.rule_id == *rule))
        .map(|finding| {
            (
                finding.rule_id.to_string(),
                finding.symbol.clone().unwrap_or_default(),
                format!("{:?}", finding.severity),
                finding.message.clone(),
            )
        })
        .collect();
    rows.sort();
    rows
}

/// Control: with `everyCallable` unset, the documentation rules still see only public functions and still
/// call them public.
#[test]
pub(crate) fn every_callable_off_keeps_documentation_rules_public_only() {
    let _guard = analysis_lock();
    let rows = every_callable_rows("");
    let scoped: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.0.as_str(), row.1.as_str()))
        .collect();

    assert_eq!(
        scoped,
        [
            ("docs.missing-param-doc", "public_add"),
            ("docs.missing-public-doc", "public_undocumented"),
            ("docs.missing-return-doc", "public_add"),
        ],
        "rows={rows:?}"
    );
    assert!(
        rows.iter()
            .all(|row| row.3.starts_with(&format!("Public function `{}` ", row.1))),
        "rows={rows:?}"
    );
}

/// With `everyCallable` on, private and crate-visible functions join the public ones in all three
/// documentation rules, at the severity each rule gives its public finding.
#[test]
pub(crate) fn every_callable_brings_private_and_crate_functions_in_at_public_severity() {
    let _guard = analysis_lock();
    let rows = every_callable_rows(EVERY_CALLABLE_ON);
    let scoped: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.0.as_str(), row.1.as_str()))
        .collect();

    assert_eq!(
        scoped,
        [
            ("docs.missing-param-doc", "crate_add"),
            ("docs.missing-param-doc", "private_add"),
            ("docs.missing-param-doc", "public_add"),
            ("docs.missing-public-doc", "crate_undocumented"),
            ("docs.missing-public-doc", "private_undocumented"),
            ("docs.missing-public-doc", "public_undocumented"),
            ("docs.missing-return-doc", "crate_add"),
            ("docs.missing-return-doc", "private_add"),
            ("docs.missing-return-doc", "public_add"),
        ],
        "rows={rows:?}"
    );
    for row in &rows {
        let public = rows
            .iter()
            .find(|other| other.0 == row.0 && other.1.starts_with("public_"))
            .expect("each rule keeps its public control finding");
        assert_eq!(row.2, public.2, "{row:?} must keep the public severity");
    }
}

/// With `everyCallable` on, no message calls a private or crate-visible function public, while the public
/// control keeps its `Public function` wording.
#[test]
pub(crate) fn every_callable_messages_do_not_call_private_functions_public() {
    let _guard = analysis_lock();
    let rows = every_callable_rows(EVERY_CALLABLE_ON);

    assert!(
        rows.iter().any(|row| !row.1.starts_with("public_")),
        "the switch must bring non-public functions in; rows={rows:?}"
    );
    for (rule_id, symbol, _, message) in &rows {
        if symbol.starts_with("public_") {
            assert!(
                message.starts_with(&format!("Public function `{symbol}` ")),
                "{rule_id}: {message}"
            );
        } else {
            assert!(
                message.starts_with(&format!("Function `{symbol}` ")),
                "{rule_id}: {message}"
            );
            assert!(
                !message.to_lowercase().contains("public"),
                "{rule_id}: {message}"
            );
        }
    }
}

/// Analyse a public and a private `#[tauri::command]`, a `#[wasm_bindgen]` export and a plain public control
/// under `config`, and list their documentation rule rows. Each rustdoc names neither parameter nor the return
/// value, so the parameter and return rules fire on every function they check.
fn bridge_rows(config: &str) -> Vec<(String, String, String, String)> {
    documentation_rule_rows(
        r#"//! Bridge cases for the everyCallable switch.

/// Combines both inputs.
#[tauri::command]
pub fn public_command(left: u32, right: u32) -> u32 {
    left + right
}

/// Combines both inputs.
#[tauri::command]
fn private_command(left: u32, right: u32) -> u32 {
    left + right
}

/// Combines both inputs.
#[wasm_bindgen]
pub fn wasm_export(left: u32, right: u32) -> u32 {
    left + right
}

/// Combines both inputs.
pub fn public_add(left: u32, right: u32) -> u32 {
    left + right
}
"#,
        config,
    )
}

/// Control: with `everyCallable` unset, the parameter and return rules still skip bridge functions, while
/// the plain public function keeps both findings.
#[test]
pub(crate) fn every_callable_off_keeps_skipping_bridge_functions() {
    let _guard = analysis_lock();
    let rows = bridge_rows("");
    let scoped: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.0.as_str(), row.1.as_str()))
        .collect();

    assert_eq!(
        scoped,
        [
            ("docs.missing-param-doc", "public_add"),
            ("docs.missing-return-doc", "public_add"),
        ],
        "rows={rows:?}"
    );
}

/// With `everyCallable` on, bridge functions join the parameter and return rules at the severity those
/// rules give the plain public function.
#[test]
pub(crate) fn every_callable_brings_bridge_functions_in_at_public_severity() {
    let _guard = analysis_lock();
    let rows = bridge_rows(EVERY_CALLABLE_ON);
    let scoped: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.0.as_str(), row.1.as_str()))
        .collect();

    assert_eq!(
        scoped,
        [
            ("docs.missing-param-doc", "private_command"),
            ("docs.missing-param-doc", "public_add"),
            ("docs.missing-param-doc", "public_command"),
            ("docs.missing-param-doc", "wasm_export"),
            ("docs.missing-return-doc", "private_command"),
            ("docs.missing-return-doc", "public_add"),
            ("docs.missing-return-doc", "public_command"),
            ("docs.missing-return-doc", "wasm_export"),
        ],
        "rows={rows:?}"
    );
    for row in &rows {
        let control = rows
            .iter()
            .find(|other| other.0 == row.0 && other.1 == "public_add")
            .expect("each rule keeps its plain public control finding");
        assert_eq!(row.2, control.2, "{row:?} must keep the public severity");
    }
}

/// Analyse public functions returning a count, unit, never, a `Result` with a success value and a unit
/// `Result` under `config`, each documented without describing a return value, and list the missing-return
/// messages.
fn messages_for_return_shapes(config: &str) -> Vec<String> {
    documentation_rule_rows(
        r#"//! Return shapes for the missing-return rule.

/// Counts `items`.
pub fn count_items(items: &[u32]) -> usize {
    items.len()
}

/// Runs the job `count` times.
pub fn unit_return(count: u32) -> () {
    let _ = count;
}

/// Stops the process with exit `code`.
pub fn never_return(code: i32) -> ! {
    std::process::exit(code)
}

/// Loads the file at `path`.
///
/// # Errors
///
/// Fails when the file cannot be read.
pub fn load_text(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}

/// Saves `text` to the output file.
///
/// # Errors
///
/// Fails when the file cannot be written.
pub fn save_text(text: &str) -> Result<(), std::io::Error> {
    std::fs::write("out.txt", text)
}
"#,
        config,
    )
    .into_iter()
    .filter(|(rule, ..)| rule == "docs.missing-return-doc")
    .map(|(.., message)| message)
    .collect()
}

const COUNT_ITEMS_RETURN: &str =
    "Public function `count_items` returns a value; its rustdoc does not describe what the return value represents.";

/// On by default: a fn declared `-> ()` or `-> !` hands back nothing, so the return rule leaves it alone.
#[test]
pub(crate) fn unit_and_never_returns_need_no_return_doc() {
    let _guard = analysis_lock();
    let messages = messages_for_return_shapes("");
    assert!(
        messages.iter().any(|message| message == COUNT_ITEMS_RETURN),
        "{messages:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("`unit_return`") || message.contains("`never_return`")),
        "{messages:?}"
    );
}

/// Control: with `everyCallable` unset, a function returning `Result` is still outside the return rule.
#[test]
pub(crate) fn every_callable_off_still_skips_result_returns() {
    let _guard = analysis_lock();
    assert_eq!(
        messages_for_return_shapes(""),
        vec![COUNT_ITEMS_RETURN.to_string()]
    );
}

/// With `everyCallable` on, a `Result` with a non-unit success type is asked for its success value, and a
/// `Result<(), E>` still returns nothing to describe.
#[test]
pub(crate) fn every_callable_asks_for_result_success_value() {
    let _guard = analysis_lock();
    assert_eq!(
        messages_for_return_shapes(EVERY_CALLABLE_ON),
        vec![
            COUNT_ITEMS_RETURN.to_string(),
            "Public function `load_text` returns a value; its rustdoc does not describe what the success value represents."
                .to_string(),
        ]
    );
}

/// Analyse two one-parameter public functions whose rustdoc uses a contract keyword ("path", "name") without
/// naming the parameter, plus a keyword-free control, under `config`, and list their (rule id, symbol,
/// severity) rows. None returns a value, so only the parameter rule can fire.
fn keyword_escape_rows(config: &str) -> Vec<(String, String, String)> {
    documentation_rule_rows(
        r#"//! Single-parameter keyword cases for the everyCallable switch.

/// Opens the file at the given path.
pub fn open_keyword(file_name: &str) {
    let _ = file_name;
}

/// Takes the name.
pub fn name_keyword(label_text: &str) {
    let _ = label_text;
}

/// Opens the file.
pub fn open_control(file_name: &str) {
    let _ = file_name;
}
"#,
        config,
    )
    .into_iter()
    .map(|row| (row.0, row.1, row.2))
    .collect()
}

/// Control: with `everyCallable` unset, a contract keyword still excuses a lone parameter the rustdoc never
/// names, so only the keyword-free control is reported.
#[test]
pub(crate) fn every_callable_off_keeps_single_parameter_keyword_escape() {
    let _guard = analysis_lock();
    let rows = keyword_escape_rows("");
    let symbols: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.0.as_str(), row.1.as_str()))
        .collect();
    assert_eq!(
        symbols,
        [("docs.missing-param-doc", "open_control")],
        "rows={rows:?}"
    );
}

/// With `everyCallable` on, a contract keyword no longer excuses a lone parameter: every function whose
/// rustdoc does not name its parameter is reported, at the control's severity.
#[test]
pub(crate) fn every_callable_removes_single_parameter_keyword_escape() {
    let _guard = analysis_lock();
    let rows = keyword_escape_rows(EVERY_CALLABLE_ON);
    let advisory = format!("{:?}", Severity::Advisory);
    let expected: Vec<(String, String, String)> = ["name_keyword", "open_control", "open_keyword"]
        .iter()
        .map(|symbol| {
            (
                "docs.missing-param-doc".to_string(),
                (*symbol).to_string(),
                advisory.clone(),
            )
        })
        .collect();
    assert_eq!(rows, expected);
}

/// Names every parameter the rustdoc leaves out at default settings, in signature order, and keeps the singular
/// wording when only one is missing.
#[test]
pub(crate) fn missing_param_doc_message_names_every_missing_parameter() {
    let _guard = analysis_lock();
    let report = analyse_rustdoc_source(
        r#"/// Combines the inputs; `scale` multiplies the sum.
pub fn combine(left: usize, right: usize, scale: usize, offset: usize) -> usize {
    (left + right) * scale + offset
}

/// Moves the cursor forward.
pub fn advance(step: usize) {
    let _ = step;
}
"#,
    );

    let mut messages: Vec<(String, String)> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "docs.missing-param-doc")
        .map(|finding| {
            (
                finding.symbol.clone().unwrap_or_default(),
                finding.message.clone(),
            )
        })
        .collect();
    messages.sort();
    assert_eq!(
        messages,
        vec![
            (
                "advance".to_string(),
                "Public function `advance` rustdoc does not mention parameter `step` by name.".to_string()
            ),
            (
                "combine".to_string(),
                "Public function `combine` rustdoc does not mention parameters `left`, `right` and `offset` by name."
                    .to_string()
            ),
        ]
    );
}

/// Rows for closures assigned to private `const` and `static` items, an undocumented private and public closure,
/// and a public fn control whose parameter rustdoc is reported at default settings.
fn closure_item_rows(config: &str) -> Vec<(String, String, String, String)> {
    documentation_rule_rows(
        r#"//! Closure items for the everyCallable switch.

/// Applies the factor.
const DOUBLE: fn(u32) -> u32 = |count| count * 2;

/// Writes it out.
static LOG: &(dyn Fn(&str) + Sync) = &|line| {
    let _ = line;
};

const UNDOCUMENTED: fn() = || {};

pub const PUBLIC_HOOK: fn() = || {};

/// Opens the file.
pub fn open_control(file_name: &str) {
    let _ = file_name;
}
"#,
        config,
    )
}

/// Project closure-item rows to their rule and symbol.
fn rule_symbol_pairs(rows: &[(String, String, String, String)]) -> Vec<(&str, &str)> {
    rows.iter()
        .map(|row| (row.0.as_str(), row.1.as_str()))
        .collect()
}

#[test]
pub(crate) fn every_callable_off_leaves_closure_items_unchecked() {
    let _guard = analysis_lock();
    let rows = closure_item_rows("");
    assert_eq!(
        rule_symbol_pairs(&rows),
        [("docs.missing-param-doc", "open_control")],
        "rows={rows:?}"
    );
}

#[test]
pub(crate) fn every_callable_checks_closures_assigned_to_const_and_static_items() {
    let _guard = analysis_lock();
    let rows = closure_item_rows(EVERY_CALLABLE_ON);
    assert_eq!(
        rule_symbol_pairs(&rows),
        [
            ("docs.missing-param-doc", "DOUBLE"),
            ("docs.missing-param-doc", "LOG"),
            ("docs.missing-param-doc", "open_control"),
            ("docs.missing-public-doc", "PUBLIC_HOOK"),
            ("docs.missing-public-doc", "UNDOCUMENTED"),
            ("docs.missing-return-doc", "DOUBLE"),
        ],
        "rows={rows:?}"
    );
    let advisory = format!("{:?}", Severity::Advisory);
    assert!(rows.iter().all(|row| row.2 == advisory), "rows={rows:?}");
    let closure_messages: Vec<&str> = rows
        .iter()
        .filter(|row| ["DOUBLE", "LOG", "UNDOCUMENTED"].contains(&row.1.as_str()))
        .map(|row| row.3.as_str())
        .collect();
    assert!(
        closure_messages
            .iter()
            .all(|message| message.starts_with("Function `")),
        "messages={closure_messages:?}"
    );
    assert!(closure_messages.contains(
        &"Function `DOUBLE` returns a value; its rustdoc does not describe what the return value represents."
    ));
    assert!(closure_messages
        .contains(&"Function `LOG` rustdoc does not mention parameter `line` by name."));
}

/// The missing-doc message asks only for what each fn has: its parameters by name, what it returns when it
/// returns something other than `()`, and when it fails when it returns a `Result` (operator decision D3).
#[test]
fn missing_doc_message_asks_only_for_what_the_signature_has() {
    let rows = documentation_rule_rows(
        r#"//! Signature shapes for the missing-doc message.

pub fn reset() {}

pub fn scale(width: u32, _unused: u32) -> u32 {
    width * 2
}

pub fn load_text(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}
"#,
        "",
    );
    let messages: Vec<(&str, &str)> = rows
        .iter()
        .filter(|row| row.0 == "docs.missing-public-doc")
        .map(|row| (row.1.as_str(), row.3.as_str()))
        .collect();
    let base = "needs a brief intent description above its signature (one plain-English line, not a restatement of the type signature).";
    assert_eq!(
        messages,
        vec![
            ("load_text", format!("Public function `load_text` {base} Also say what `path` is for, what it returns and when it returns an error.").as_str()),
            ("reset", format!("Public function `reset` {base}").as_str()),
            ("scale", format!("Public function `scale` {base} Also say what `width` is for and what it returns.").as_str()),
        ]
    );
}
