//! Exercises parser masks that keep findings aligned with the original Rust source.
//!
//! Contributors run these invariants after literal or comment handling changes so
//! CLI line numbers and code visibility remain stable across supported source shapes.

use crate::{
    byte_line_from_starts, extract_rust_comments, line_starts, rust_code_reference_source,
    strip_rust_comments_after_string_mask, strip_rust_string_literals,
};

// A token that is not a Rust keyword, operator, or comment marker. Its presence
// in masked output proves a span passed through unchanged; its absence proves
// the span was replaced.
const SENTINEL: &str = "ZZMARKERZZ";

// Single- and multi-byte characters whose adjacencies stress every masker
// branch: quote and comment openers, escape and raw-string markers, braces for
// unicode escapes, and multi-byte UTF-8 to confirm masking stays byte-aligned.
const FUZZ_ALPHABET: &[char] = &[
    ' ', '\n', '\t', '"', '\'', '\\', '/', '*', 'r', '#', '{', '}', 'x', 'u', 'a', 'b', ';', 'é',
    '🚀',
];

// Hand-picked Rust fragments covering plain code, every string and char literal
// form (including the quote-holding char-literal footgun), lifetimes, raw
// strings with varied hash counts, doc and nested block comments, unterminated
// forms, and multi-byte text.
fn corpus() -> Vec<&'static str> {
    vec![
        "let x = 5;\n",
        "fn helper() {}\n",
        "a + b - c\n",
        "\"plain\"",
        r#""esc \" quote""#,
        r#""// not a comment""#,
        r#""/* not a block */""#,
        "\"\"",
        "\"unterminated",
        "'a'",
        r"'\''",
        "'\"'",
        r"'\n'",
        r"'\x41'",
        r"'\u{1F600}'",
        "'static ",
        "&'a T",
        r#"r"raw""#,
        r##"r#"q "quote" q"#"##,
        r###"r##"has "# inside"##"###,
        r#"r"unterminated raw"#,
        "// line \" quote\n",
        "/// doc\n",
        "//! inner\n",
        "/* block */",
        "/** docblock */",
        "/* o /* n */ o */",
        "/* unterminated",
        "café\n",
        "🚀 x\n",
        "\t\n",
        "\n\n",
    ]
}

// Every ordered pair of corpus fragments, so construct-against-construct
// adjacencies (a raw string butted against a comment, etc.) are exercised.
fn concat_pairs(parts: &[&str]) -> Vec<String> {
    let mut combos = Vec::new();
    for left in parts {
        for right in parts {
            combos.push([*left, *right].concat());
        }
    }
    combos
}

// Every string of length one to three over the stress alphabet. Exhaustive
// trigrams catch local masker bugs with no randomness, keeping the suite
// deterministic.
fn fuzzed_inputs() -> Vec<String> {
    let mut inputs = Vec::new();
    for first in FUZZ_ALPHABET {
        inputs.push(first.to_string());
        for second in FUZZ_ALPHABET {
            let mut pair = String::new();
            pair.push(*first);
            pair.push(*second);
            for third in FUZZ_ALPHABET {
                let mut triple = pair.clone();
                triple.push(*third);
                inputs.push(triple);
            }
            inputs.push(pair);
        }
    }
    inputs
}

// The full input set every structural invariant runs over.
fn all_inputs() -> Vec<String> {
    let base = corpus();
    let mut inputs = base
        .iter()
        .map(|fragment| (*fragment).to_string())
        .collect::<Vec<_>>();
    inputs.extend(concat_pairs(&base));
    inputs.extend(fuzzed_inputs());
    inputs
}

// The maskers replace spans in place: identical byte length and identical
// newline offsets, so finding line and column numbers stay aligned with the
// original source.
fn assert_byte_aligned(label: &str, input: &str, output: &str) {
    assert_eq!(
        input.len(),
        output.len(),
        "{label} must preserve byte length; input={input:?} output={output:?}"
    );
    assert_eq!(
        line_starts(input),
        line_starts(output),
        "{label} must preserve newline offsets; input={input:?} output={output:?}"
    );
}

#[test]
pub(crate) fn maskers_preserve_byte_length_and_newline_offsets() {
    for input in all_inputs() {
        let stripped = strip_rust_string_literals(&input);
        assert_byte_aligned("strip_rust_string_literals", &input, &stripped);

        let decommented = strip_rust_comments_after_string_mask(&input);
        assert_byte_aligned(
            "strip_rust_comments_after_string_mask",
            &input,
            &decommented,
        );

        let composed = strip_rust_comments_after_string_mask(&stripped);
        assert_byte_aligned("string-then-comment mask", &input, &composed);
    }
}

/// Keeps finding lines stable when non-ASCII source and nested comments pass
/// through the combined string and comment masks.
#[test]
pub(crate) fn rust_masking_preserves_non_ascii_byte_offsets_and_nested_comments() {
    let source = "éé\nlet sql = format!(\"SELECT {}\", name);\n/* outer /* inner */ still outer */\nlet done = true;\n";
    let masked_strings = strip_rust_string_literals(source);
    assert_eq!(masked_strings.len(), source.len());
    let masked_comments = strip_rust_comments_after_string_mask(&masked_strings);
    assert_eq!(masked_comments.len(), source.len());
    assert!(!masked_comments.contains("still outer"));
    let format_offset = masked_comments.find("format!").expect("format offset");
    assert_eq!(
        byte_line_from_starts(&line_starts(source), format_offset),
        2
    );
}

#[test]
pub(crate) fn masking_is_idempotent() {
    for input in all_inputs() {
        let once = strip_rust_string_literals(&input);
        let twice = strip_rust_string_literals(&once);
        assert_eq!(
            once, twice,
            "string masking must be idempotent; input={input:?}"
        );

        let masked = strip_rust_comments_after_string_mask(&once);
        let remasked = strip_rust_comments_after_string_mask(&strip_rust_string_literals(&masked));
        assert_eq!(
            masked, remasked,
            "full masking must be idempotent; input={input:?}"
        );
    }
}

#[test]
pub(crate) fn extracted_comment_lines_stay_in_bounds() {
    for input in all_inputs() {
        let masked = strip_rust_string_literals(&input);
        let line_count = line_starts(&masked).len();
        for comment in extract_rust_comments(&masked) {
            assert!(
                (1..=line_count).contains(&comment.line),
                "comment line {} out of bounds 1..={line_count} for input={input:?}",
                comment.line
            );
        }
    }
}

#[test]
pub(crate) fn string_literal_contents_are_masked() {
    let cases = [
        format!("\"{SENTINEL}\""),
        format!("\"prefix {SENTINEL} suffix\""),
        format!("r\"{SENTINEL}\""),
        format!("r#\"{SENTINEL}\"#"),
        format!("r##\"{SENTINEL}\"##"),
        format!("let a = 1;\n\"{SENTINEL}\"\nlet b = 2;\n"),
    ];
    for case in &cases {
        let stripped = strip_rust_string_literals(case);
        assert!(
            !stripped.contains(SENTINEL),
            "string content must be masked; case={case:?} stripped={stripped:?}"
        );
    }
}

#[test]
pub(crate) fn char_literal_holding_a_quote_does_not_swallow_following_code() {
    let source = format!("let q = '\"';\nlet real = \"{SENTINEL}\";\n");
    let stripped = strip_rust_string_literals(&source);
    assert!(
        !stripped.contains(SENTINEL),
        "the string after a quote-holding char literal must still be masked; stripped={stripped:?}"
    );
    assert!(
        stripped.contains("let real ="),
        "code after a quote-holding char literal must survive; stripped={stripped:?}"
    );
}

#[test]
pub(crate) fn lifetimes_are_not_masked_as_char_literals() {
    let source = "fn longest<'a>(x: &'a str) -> &'a str { x }\nstatic S: &'static str = \"x\";\n";
    let stripped = strip_rust_string_literals(source);
    assert!(
        stripped.contains("'a"),
        "lifetime 'a must survive masking; stripped={stripped:?}"
    );
    assert!(
        stripped.contains("'static"),
        "lifetime 'static must survive masking; stripped={stripped:?}"
    );
}

#[test]
pub(crate) fn doc_comment_quote_does_not_open_a_string() {
    let source = format!("/// docs mention a \" quote\nlet secret = \"{SENTINEL}\";\n");
    let stripped = strip_rust_string_literals(&source);
    assert!(
        !stripped.contains(SENTINEL),
        "a quote inside a doc comment must not pull following code into a string; stripped={stripped:?}"
    );
    assert!(
        stripped.contains("let secret ="),
        "code after a doc comment must survive; stripped={stripped:?}"
    );
}

#[test]
pub(crate) fn comments_pass_the_string_mask_then_fall_to_the_comment_mask() {
    let source = format!("let a = 1; // {SENTINEL}\n/* {SENTINEL} */ let b = 2;\n");

    let after_strings = strip_rust_string_literals(&source);
    assert!(
        after_strings.contains(SENTINEL),
        "comment text must survive the string mask; after_strings={after_strings:?}"
    );

    let after_comments = strip_rust_comments_after_string_mask(&after_strings);
    assert!(
        !after_comments.contains(SENTINEL),
        "comment text must be removed by the comment mask; after_comments={after_comments:?}"
    );
    assert_byte_aligned("string-then-comment mask", &source, &after_comments);
}

#[test]
pub(crate) fn extract_rust_comments_reports_lines_and_doc_flags() {
    let source = "/// doc line\nlet x = 1;\n// plain line\n/* block */\n";
    let comments = extract_rust_comments(&strip_rust_string_literals(source));

    assert_eq!(
        comments.len(),
        3,
        "expected three comments; got {comments:?}"
    );

    assert_eq!(comments[0].line, 1);
    assert!(comments[0].is_doc, "/// must be flagged as a doc comment");
    assert_eq!(comments[0].text, "doc line");

    assert_eq!(comments[1].line, 3);
    assert!(
        !comments[1].is_doc,
        "// must not be flagged as a doc comment"
    );
    assert_eq!(comments[1].text, "plain line");

    assert_eq!(comments[2].line, 4);
    assert_eq!(comments[2].text, "block");
}

#[test]
pub(crate) fn serde_default_reference_survives_as_a_call_site() {
    let with_serde = "#[serde(default = \"make_default\")]\nstruct Config;\n";
    let reference = rust_code_reference_source(with_serde);
    assert!(
        reference.contains("make_default"),
        "serde default function reference must survive masking; reference={reference:?}"
    );

    let plain_string = "let label = \"make_default\";\n";
    let plain_reference = rust_code_reference_source(plain_string);
    assert!(
        !plain_reference.contains("make_default"),
        "a non-serde string must be masked, not kept as a reference; reference={plain_reference:?}"
    );
}
