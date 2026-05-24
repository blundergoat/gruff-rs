use super::*;

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
                depth -= 1;
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
    trimmed.starts_with("self") || trimmed.starts_with("&self") || trimmed.starts_with("&mut self")
}
