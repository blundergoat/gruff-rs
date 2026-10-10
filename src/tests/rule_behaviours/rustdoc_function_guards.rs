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
