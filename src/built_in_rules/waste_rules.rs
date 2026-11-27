//! Filter low-signal unwrap and clone patterns so waste rules report avoidable boilerplate instead of idiomatic Rust.
//!
//! Used by per-file analysis when deciding whether a `.clone()`, `.unwrap()`, or `.expect()` call deserves a finding.
//! Recognises ownership-consuming clones, substantive `.expect(...)` rationales, Cargo build-script variables, and literal constructors.

use super::*;

/// Report whether a `.clone()` on `line` is immediately consumed or required for owned data, keeping the clone rule silent.
///
/// Matches idiomatic ownership positions where cloning is usually intentional rather than avoidable waste:
/// - Ownership-taking consumers such as `unwrap_or*`, `into*`, `collect*`, and `?` propagation.
/// - Owned positions such as struct fields, `Some(...)` wraps, map entry/insert keys, and `.map(...).collect()` chains.
///
/// Returns true when any ownership pattern matches `line`, and false when the clone looks avoidable.
pub(crate) fn clone_is_consumed_or_owned(line: &str) -> bool {
    CLONE_OWNERSHIP_PATTERNS
        .iter()
        .any(|pattern| pattern.matches(line))
}

pub(crate) struct CloneOwnershipPattern {
    pub(crate) cell: &'static OnceLock<Regex>,
    pub(crate) pattern: &'static str,
}

impl CloneOwnershipPattern {
    /// Tests one source line against this ownership pattern's regex, which `static_regex` builds from `pattern` and caches in `cell`.
    ///
    /// `line` is one line of source text checked for an owned or consumed `.clone()`.
    /// If `cell` is still empty and `pattern` is not a valid regex, building it panics.
    /// Returns true when the regex matches `line`; the anchored patterns must match the whole line.
    pub(crate) fn matches(&self, line: &str) -> bool {
        static_regex(self.cell, self.pattern).is_match(line)
    }
}

static CONSUMER_REGEX: OnceLock<Regex> = OnceLock::new();
static STRUCT_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
static LOOKUP_REGEX: OnceLock<Regex> = OnceLock::new();
static SOME_WRAP_REGEX: OnceLock<Regex> = OnceLock::new();
static MAP_COLLECT_REGEX: OnceLock<Regex> = OnceLock::new();
static MAP_CLOSURE_LINE_REGEX: OnceLock<Regex> = OnceLock::new();
static LET_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
static MULTILINE_CHAIN_REGEX: OnceLock<Regex> = OnceLock::new();
static STANDALONE_ARGUMENT_REGEX: OnceLock<Regex> = OnceLock::new();

const CLONE_OWNERSHIP_PATTERNS: &[CloneOwnershipPattern] = &[
    CloneOwnershipPattern {
        cell: &CONSUMER_REGEX,
        pattern: r"\.clone\(\)\s*(?:\?|\.(?:unwrap_or_else|unwrap_or_default|unwrap_or|into_iter|into|collect)\b)",
    },
    CloneOwnershipPattern {
        cell: &STRUCT_FIELD_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*\.clone\(\)\s*\)*\s*,?\s*$",
    },
    CloneOwnershipPattern {
        cell: &LOOKUP_REGEX,
        pattern: r"\.(?:entry|insert|get|contains|contains_key|remove)\(\s*&?\s*\(?[^=;]*\.clone\(\)[^;]*\)",
    },
    CloneOwnershipPattern {
        cell: &SOME_WRAP_REGEX,
        pattern: r"\bSome\(\s*[^()]*\.clone\(\)\s*\)",
    },
    CloneOwnershipPattern {
        cell: &MAP_COLLECT_REGEX,
        pattern: r"\.map\([^)]*\.clone\(\)[^)]*\)\s*\.?\s*\)*\.?\s*(?:collect|\)\s*\.collect)\(\)",
    },
    CloneOwnershipPattern {
        cell: &MAP_CLOSURE_LINE_REGEX,
        pattern: r"^\s*\.map\(\|[^|]*\|\s*[^=;]+\.clone\(\)\s*\)\s*$",
    },
    CloneOwnershipPattern {
        cell: &LET_BINDING_REGEX,
        pattern: r"^\s*let\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[^=]+)?\s*=\s*[^=;]+\.clone\(\)\s*;\s*$",
    },
    CloneOwnershipPattern {
        cell: &STANDALONE_ARGUMENT_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.clone\(\)\s*,\s*$",
    },
    CloneOwnershipPattern {
        cell: &MULTILINE_CHAIN_REGEX,
        pattern: r"^\s*\.clone\(\)\s*$",
    },
];

/// Returns true when a `.expect("...")` call carries a substantive rationale string (at least 15 bytes after trimming surrounding whitespace).
/// The waste rule accepts these because the author has already declared why the unwrap is safe; a trivial `.expect("ok")` gets no exemption here.
///
/// `line` is one source line whose comments are stripped first before searching for textual `.expect("...")` matches.
/// Any one match with such a rationale passes.
pub(crate) fn expect_has_substantive_rationale(line: &str) -> bool {
    static EXPECT_RATIONALE_REGEX: OnceLock<Regex> = OnceLock::new();
    let code = crate::parser::source_without_comments(line);
    let regex = static_regex(&EXPECT_RATIONALE_REGEX, r#"\.expect\(\s*"([^"]*)"\s*\)"#);
    regex.captures_iter(&code).any(|captures| {
        captures
            .get(1)
            .map(|rationale| rationale.as_str().trim().len() >= 15)
            .unwrap_or(false)
    })
}

/// Returns true when the line's unwraps are accepted: an `expect` with a substantive rationale, or only calls that
/// have an outcome fixed by the source.
///
/// `raw_line` is one source line with its string literals intact, because both checks read the literal arguments.
/// `display_path` is the file's display path, which decides whether Cargo build-script variables count as fixed.
pub(crate) fn is_accepted_unwrap_line(raw_line: &str, display_path: &str) -> bool {
    expect_has_substantive_rationale(raw_line)
        || has_only_fixed_outcome_unwraps(raw_line, display_path)
}

/// Variables Cargo sets for every build script, so reading one in `build.rs` cannot fail.
const CARGO_BUILD_SCRIPT_VARIABLES: &[&str] = &[
    "OUT_DIR",
    "TARGET",
    "HOST",
    "NUM_JOBS",
    "OPT_LEVEL",
    "DEBUG",
    "PROFILE",
    "RUSTC",
    "RUSTDOC",
    "CARGO",
    "CARGO_MANIFEST_DIR",
    "CARGO_PKG_NAME",
    "CARGO_PKG_VERSION",
    "CARGO_CFG_TARGET_ARCH",
    "CARGO_CFG_TARGET_OS",
    "CARGO_CFG_TARGET_ENDIAN",
    "CARGO_CFG_TARGET_POINTER_WIDTH",
    "CARGO_CFG_TARGET_ENV",
    "CARGO_CFG_TARGET_VENDOR",
];

/// Report whether every `unwrap()` or `expect()` on `raw_line` follows a call whose outcome is fixed by the source.
///
/// Exempts deterministic calls so `waste.unwrap-expect` avoids noisy findings when any non-exempt unwrap keeps reporting:
/// - Cargo-set build variables in `CARGO_BUILD_SCRIPT_VARIABLES` when `display_path` is `build.rs` or ends in `/build.rs`.
/// - `CString::new`, `Regex::new`, `Url::parse`, and IP/socket `from_str` with a string literal (excluding NUL in `CString::new`).
///
/// `raw_line` keeps string literals intact after stripping comments; returns false when the line has no `unwrap` or `expect` call.
fn has_only_fixed_outcome_unwraps(raw_line: &str, display_path: &str) -> bool {
    static UNWRAP_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
    static BUILD_VARIABLE_REGEX: OnceLock<Regex> = OnceLock::new();
    static LITERAL_CONSTRUCTOR_REGEX: OnceLock<Regex> = OnceLock::new();
    static STRING_ESCAPE_REGEX: OnceLock<Regex> = OnceLock::new();
    let code = crate::parser::source_without_comments(raw_line);
    let calls = static_regex(&UNWRAP_CALL_REGEX, r"\.(?:unwrap|expect)\s*\(")
        .find_iter(&code)
        .count();
    let is_build_script = display_path == "build.rs" || display_path.ends_with("/build.rs");
    let build_variables = static_regex(
        &BUILD_VARIABLE_REGEX,
        r#"\benv::var(?:_os)?\(\s*"([A-Z_]+)"\s*\)\s*\.(?:unwrap|expect)\s*\("#,
    )
    .captures_iter(&code)
    .filter(|captures| is_build_script && CARGO_BUILD_SCRIPT_VARIABLES.contains(&&captures[1]))
    .count();
    // CString rejects NUL bytes and escapes. Consume other escapes too, so an escaped backslash before `0` is not a NUL.
    let literal_constructors = static_regex(
        &LITERAL_CONSTRUCTOR_REGEX,
        r####"\b(CString::new|Regex::new|Url::parse|(?:IpAddr|Ipv4Addr|Ipv6Addr|SocketAddr)::from_str)\(\s*(?:"((?:[^"\\]|\\.)*)"|r(?:"([^"]*)"|#"((?:[^"]|"[^#])*)"#|##"((?:[^"]|"[^#]|"#[^#])*)"##))\s*\)\s*\.(?:unwrap|expect)\s*\("####,
    )
    .captures_iter(&code)
    .filter(|captures| {
        // Only CString::new can panic on its literal, so every other constructor stays a fixed outcome.
        if &captures[1] != "CString::new" {
            return true;
        }
        // A normal string literal can spell NUL as an escape, so both a raw NUL byte and the escapes are checked.
        if let Some(regular) = captures.get(2) {
            return !regular.as_str().contains('\0')
                && !static_regex(&STRING_ESCAPE_REGEX, r"\\(?:(0|x00|u\{0[0_]*\})|.)")
                    .captures_iter(regular.as_str())
                    .any(|escape| escape.get(1).is_some());
        }
        let raw = captures
            .get(3)
            .or_else(|| captures.get(4))
            .or_else(|| captures.get(5))
            .map_or("", |matched| matched.as_str());
        !raw.contains('\0')
    })
    .count();
    calls > 0 && build_variables + literal_constructors == calls
}

#[cfg(test)]
mod fixed_outcome_tests {
    use super::is_accepted_unwrap_line;

    /// NUL escapes keep CString unwraps visible, escaped backslashes and other constructors retain fixed outcomes,
    /// and a target-dependent Cargo variable is not assumed present in every build script.
    #[test]
    fn fixed_outcome_unwraps_keep_nul_and_target_controls() {
        for (line, accepted) in [
            (r#"CString::new("\0").unwrap()"#, false),
            (r#"CString::new("\x00").unwrap()"#, false),
            (r#"CString::new("\u{0}").unwrap()"#, false),
            (r#"CString::new("\u{0000}").unwrap()"#, false),
            (r#"CString::new("\\0").unwrap()"#, true),
            (r#"Regex::new("\0").unwrap()"#, true),
            (
                r#"std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap()"#,
                false,
            ),
            (r#"std::env::var("OUT_DIR").unwrap()"#, true),
        ] {
            assert_eq!(
                is_accepted_unwrap_line(line, "build.rs"),
                accepted,
                "{line}"
            );
        }
    }
}
