//! Function rustdoc parsing supplies one attached-comment contract to block rules.
//! It uses the parser's function attributes to distinguish the user's outer
//! `///` and `/** */` comments from inner, ordinary, detached, or explicit forms.

use super::*;

/// Attached outer rustdoc normalized for every function-level documentation rule.
/// The source line records where the user's `///` or `/** */` comment begins,
/// while the text supplies one shared section and prose contract to the scan.
#[derive(Clone)]
pub(crate) struct FunctionRustdoc {
    pub(crate) text: String,
    pub(crate) start_line: usize,
}

/// Source facts discovered once before a function enters block-level analysis.
/// The block start preserves existing finding locations, while rustdoc carries
/// normalized text and its real source line to every documentation rule.
pub(crate) struct FunctionSourceContext {
    pub(crate) block_start_index: usize,
    pub(crate) rustdoc: Option<FunctionRustdoc>,
}

/// Discover the existing block anchor and any supported rustdoc attached to this function.
pub(crate) fn function_source_context(
    lines: &[&str],
    attributes: &[syn::Attribute],
    function_index: usize,
) -> FunctionSourceContext {
    FunctionSourceContext {
        block_start_index: function_block_start_index(lines, function_index),
        rustdoc: extract_attached_outer_rustdoc(lines, attributes),
    }
}

/// Preserve the report anchor while walking attached line docs, attributes, and spacing once.
fn function_block_start_index(lines: &[&str], function_index: usize) -> usize {
    let mut start = function_index;

    // Attached prefix lines remain part of the block so existing finding identities stay stable.
    while start > 0 {
        let previous = lines[start - 1].trim();

        // A different item or ordinary comment ends the function's attached source prefix.
        if !(previous.starts_with("#[") || previous.starts_with("///") || previous.is_empty()) {
            break;
        }
        start -= 1;
    }
    start
}

/// Extract normalized text and the first source line from supported attached rustdoc attributes.
fn extract_attached_outer_rustdoc(
    lines: &[&str],
    attributes: &[syn::Attribute],
) -> Option<FunctionRustdoc> {
    let mut text_parts = Vec::new();
    let mut start_line = None;

    // Parser attachment decides ownership, so docs belonging to another item never cross over.
    for attribute in attributes {
        let Some((attribute_line, text)) = supported_outer_rustdoc_attribute(lines, attribute)
        else {
            continue;
        };
        start_line =
            Some(start_line.map_or(attribute_line, |line: usize| line.min(attribute_line)));
        text_parts.push(text);
    }

    // No supported source comment means the function remains undocumented for this milestone.
    let start_line = start_line?;
    Some(FunctionRustdoc {
        text: text_parts.join("\n"),
        start_line,
    })
}

/// Accept one parser-owned `///` or `/** */` attribute and reject deferred explicit doc attributes.
fn supported_outer_rustdoc_attribute(
    lines: &[&str],
    attribute: &syn::Attribute,
) -> Option<(usize, String)> {
    let attribute_line = line_from_span(attribute.span().start());

    // Missing source text can occur only for a synthetic span, which users cannot document here.
    let source_line = lines.get(attribute_line.saturating_sub(1))?.trim_start();

    // Only source-visible outer comments are in scope; inner and `#[doc = ...]` forms stay deferred.
    if !(source_line.starts_with("///") || source_line.starts_with("/**"))
        || source_line.starts_with("//!")
        || source_line.starts_with("/*!")
    {
        return None;
    }

    // Syn represents supported doc comments as a string-valued `doc` attribute.
    let syn::Meta::NameValue(name_value) = &attribute.meta else {
        return None;
    };

    // A non-string attribute cannot carry the prose shown to a documentation-rule user.
    let syn::Expr::Lit(expression) = &name_value.value else {
        return None;
    };

    // Empty string content is still present rustdoc, matching Rust's own attachment semantics.
    let syn::Lit::Str(text) = &expression.lit else {
        return None;
    };
    Some((attribute_line, normalize_outer_rustdoc_text(&text.value())))
}

/// Normalize line and block rustdoc into the same plain text used by section and prose checks.
fn normalize_outer_rustdoc_text(text: &str) -> String {
    // One decorative leading star is removed from conventional block-rustdoc lines.
    text.lines()
        .map(|line| {
            let trimmed = line.trim();
            trimmed.strip_prefix('*').unwrap_or(trimmed).trim_start()
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

/// True iff the function signature in `body` includes a `-> <type>` clause
/// (other than implicit unit). Strips rustdoc/comment lines first so doc
/// examples containing `fn foo() -> T {}` cannot trigger a false positive
/// on a fn whose real signature is `fn bar()`.
pub(crate) fn signature_has_return_type(body: &str) -> bool {
    static SIG_RETURN_REGEX: OnceLock<Regex> = OnceLock::new();
    let code = body_without_doc_comments(body);
    static_regex(
        &SIG_RETURN_REGEX,
        r"fn\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*->\s*[^{;]+\{",
    )
    .is_match(&code)
}

/// Returns `body` with `///`, `//!`, and `//` lines removed. Used by
/// signature-region regexes that would otherwise match patterns inside
/// rustdoc examples (e.g. `/// fn example(arg: i32) -> Result<()>`).
/// Preserves line count so any caller relying on line offsets stays
/// aligned.
pub(crate) fn body_without_doc_comments(body: &str) -> String {
    body.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("///") || trimmed.starts_with("//!") || trimmed.starts_with("//")
            {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// True iff `body` carries a macro attribute that marks the function as a
/// frontend bridge: `#[tauri::command]`, `#[command]`, `#[wasm_bindgen]`,
/// or `#[pyfunction]`. Bridge functions follow user-facing-summary rustdoc
/// convention rather than the Rust API contract style.
pub(crate) fn has_frontend_bridge_attr(body: &str) -> bool {
    static BRIDGE_ATTR_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &BRIDGE_ATTR_REGEX,
        r"#\s*\[\s*(?:tauri\s*::\s*command|command|wasm_bindgen|pyfunction|pyo3\s*::\s*pyfunction)\b",
    )
    .is_match(body)
}

/// Best-effort parameter-name extraction from the signature line of a
/// function block. Source-only: parses the first `fn name(` ... `)` token
/// stream, splits on top-level commas, and pulls the leftmost identifier
/// before `:` in each chunk. Skips `self` receivers and bare `_`. Strips
/// rustdoc/comment lines first so `/// fn example(unrelated: i32)` in
/// docs cannot be picked up as the real signature.
pub(crate) fn extract_param_names(body: &str) -> Vec<String> {
    let code = body_without_doc_comments(body);
    let Some(inside) = function_signature_params(&code) else {
        return Vec::new();
    };
    split_top_level_commas(inside)
        .into_iter()
        .filter_map(parameter_name)
        .collect()
}

fn function_signature_params(body: &str) -> Option<&str> {
    let fn_index = body.find("fn ")?;
    let after_fn = &body[fn_index..];
    let open_paren = after_fn.find('(')?;
    let close = matching_close_paren_offset(after_fn, open_paren)?;
    Some(&after_fn[open_paren + 1..close])
}

fn matching_close_paren_offset(after_fn: &str, open_paren: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (offset, byte) in after_fn.as_bytes().iter().enumerate().skip(open_paren) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(inside: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for character in inside.chars() {
        match character {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                current.push(character);
            }
            '>' | ')' | ']' | '}' => {
                if depth > 0 {
                    depth -= 1;
                }
                current.push(character);
            }
            ',' if depth == 0 => {
                chunks.push(std::mem::take(&mut current));
            }
            _ => current.push(character),
        }
    }
    chunks.push(current);
    chunks
}

fn parameter_name(chunk: String) -> Option<String> {
    let trimmed = chunk.trim();
    if trimmed.is_empty() || parameter_is_self(trimmed) || trimmed == "_" {
        return None;
    }
    let until_colon = trimmed
        .split(':')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .trim_start_matches("mut ")
        .trim_start_matches('&')
        .trim();
    let identifier: String = until_colon
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect();
    if identifier.is_empty() || identifier == "self" {
        None
    } else {
        Some(identifier)
    }
}

fn parameter_is_self(trimmed: &str) -> bool {
    let candidate = trimmed
        .trim_start_matches('&')
        .trim_start()
        .trim_start_matches("mut ")
        .trim_start();
    let rest = match candidate.strip_prefix("self") {
        Some(rest) => rest,
        None => return false,
    };
    match rest.chars().next() {
        Some(next) => !(next.is_ascii_alphanumeric() || next == '_'),
        None => true,
    }
}
