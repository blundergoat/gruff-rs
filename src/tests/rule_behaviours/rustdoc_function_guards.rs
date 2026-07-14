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
