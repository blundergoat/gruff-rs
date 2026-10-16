//! Function documentation rules share one parser-attached outer-rustdoc source.
//! Public API scans use the same normalized `///` or `/** */` text for presence,
//! required sections, parameter descriptions, and return-value descriptions.

use super::*;

pub(crate) static UNSAFE_FN_SIGNATURE_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_public_function_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let docs = function_doc_text(block);
    let every_callable = is_every_callable(config, "docs.missing-public-doc");

    // Public functions without supported attached rustdoc need an intent description; with
    // `everyCallable` on, so does every other function outside test code.
    let in_scope = block.is_externally_public || is_documentable_block(block, every_callable);
    if in_scope && !docs.is_present() {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "docs.missing-public-doc",
                message: format!(
                    "{} `{}` needs a brief intent description above its signature (one plain-English line, not a restatement of the type signature).{}",
                    callable_label(block),
                    block.name,
                    missing_doc_contract_request(block)
                ),
                file,
                block,
                severity: Severity::Advisory,
                pillar: Pillar::Documentation,
            },
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: Some(
                    "Add concise outer rustdoc above the function (`/// Description.` or `/** Description. */`). This rule wants content, not boilerplate - if your project policy is 'no comments', that policy is about avoiding comments that restate code, not about removing documentation. The description should answer 'what is this for, what does it return at the edge values, what must the caller satisfy'."
                        .to_string(),
                ),
                metadata: json!({}),
            },
        ));
    }
}

/// Externally-public functions returning syntactic `Result<...>` should
/// document the error contract. The rule fires when the preceding rustdoc
/// (if any) does not contain `# Errors` or `## Errors`. Type-alias `Result`
/// shapes are intentionally not detected - see `fn returns_result`.
pub(crate) fn analyse_missing_errors_section(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public || !block.returns_result {
        return;
    }
    let docs = function_doc_text(block);
    if docs.contains_section("Errors") || docs.has_error_contract_prose() {
        return;
    }
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-errors-section",
            message: format!(
                "Public function `{}` returns Result; its rustdoc needs a `# Errors` section describing when each Err variant fires.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add a `# Errors` section explaining the conditions that produce each Err (input validation, IO failure, resource exhaustion, etc.). The rule wants content, not boilerplate - each entry should answer 'what triggers this error and what should the caller do about it'."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    ));
}

/// Public functions that can panic should declare `# Panics` in rustdoc.
/// "Can panic" is approximated by `panic!`, `unwrap`, or `expect` in the
/// body. Fires only on `pub` items so private helpers and test scaffolding
/// are not noisy.
pub(crate) fn analyse_missing_panics_section(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public || block.is_test || block.test_context {
        return;
    }
    if path_is_test_infrastructure(&file.display_path) {
        return;
    }
    if !block_body_can_panic(&block.body) {
        return;
    }
    let docs = function_doc_text(block);
    if docs.is_empty() || docs.contains_section("Panics") || docs.has_panic_contract_prose() {
        return;
    }
    findings.push(missing_panics_section_finding(file, block));
}

fn block_body_can_panic(body: &str) -> bool {
    let stripped = strip_rust_string_literals(body);
    let code_only = strip_rust_comments_after_string_mask(&stripped);
    static_regex(&PANIC_MACRO_REGEX, r"\bpanic!\s*\(").is_match(&code_only)
        || static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(").is_match(&code_only)
}

fn missing_panics_section_finding(file: &SourceFile, block: &FunctionBlock) -> Finding {
    block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-panics-section",
            message: format!(
                "Public function `{}` contains code that can panic (`panic!`, `unwrap`, or `expect`); its rustdoc needs a `# Panics` section.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add a `# Panics` section describing the inputs or runtime states that cause the panic so callers can avoid them or wrap the call defensively. The rule wants content, not boilerplate - each entry should answer 'which input or state triggers the panic'."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    )
}

/// Public `unsafe fn` requires a `# Safety` rustdoc section explaining the
/// caller invariants. The unsafe-ness is detected from the signature line
/// in `block.body` (which includes the `fn` line and preceding attrs).
pub(crate) fn analyse_missing_safety_section(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public {
        return;
    }
    let code = body_without_doc_comments(&block.body);
    let is_unsafe_fn =
        static_regex(&UNSAFE_FN_SIGNATURE_REGEX, r"\bunsafe\s+fn\s+").is_match(&code);
    if !is_unsafe_fn {
        return;
    }
    let docs = function_doc_text(block);
    if docs.contains_section("Safety") {
        return;
    }
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-safety-section",
            message: format!(
                "Public `unsafe fn` `{}` needs a `# Safety` rustdoc section listing the invariants the caller must uphold.",
                block.name
            ),
            file,
            block,
            severity: Severity::Warning,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add a `# Safety` section listing every invariant the caller must guarantee before calling this function (pointer validity, type provenance, thread state, lifetime of borrowed data, etc.). This is the API contract for unsafe code, not boilerplate - missing invariants here become real soundness bugs."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    ));
}

/// Public functions whose rustdoc does not mention each parameter by name
/// produce a finding; with `everyCallable` on, so does every other function
/// outside test code, bridge-macro fns included. Skips empty rustdoc,
/// underscore-prefixed parameters, and, with the switch off, bridge-macro fns
/// and a lone parameter whose rustdoc uses a contract keyword such as "path".
pub(crate) fn analyse_missing_param_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let every_callable = is_every_callable(config, "docs.missing-param-doc");
    if !is_documentable_block(block, every_callable) || is_skipped_bridge(block, every_callable) {
        return;
    }
    if block.param_count == 0 {
        return;
    }
    let docs = function_doc_text(block);
    if docs.is_empty() {
        return;
    }
    let undocumented = collect_undocumented_params(&block.body, &docs, every_callable);
    if undocumented.is_empty() {
        return;
    }
    findings.push(missing_param_doc_finding(file, block, undocumented));
}

/// List the non-underscore parameters the rustdoc never names. While the rule's `everyCallable` switch,
/// carried by `every_callable`, is off, a lone parameter counts as documented when the rustdoc uses a
/// contract keyword (`has_single_parameter_contract_prose`).
fn collect_undocumented_params(
    body: &str,
    docs: &DocCommentText,
    every_callable: bool,
) -> Vec<String> {
    let params: Vec<String> = extract_param_names(body)
        .into_iter()
        .filter(|name| !name.starts_with('_'))
        .collect();
    if !every_callable && params.len() == 1 && docs.has_single_parameter_contract_prose() {
        return Vec::new();
    }
    params
        .into_iter()
        .filter(|name| !docs.has_identifier_mention(name))
        .collect()
}

fn missing_param_doc_finding(
    file: &SourceFile,
    block: &FunctionBlock,
    undocumented: Vec<String>,
) -> Finding {
    let noun = if undocumented.len() == 1 {
        "parameter"
    } else {
        "parameters"
    };
    block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-param-doc",
            message: format!(
                "{} `{}` rustdoc does not mention {} {} by name.",
                callable_label(block),
                block.name,
                noun,
                backticked_name_list(&undocumented)
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::Medium,
            remediation: Some(
                "Mention each parameter by name in the rustdoc - either in prose or in an `# Arguments` section. The mention should answer 'what does this value represent and what range/shape is the function expecting', not restate the type signature."
                    .to_string(),
            ),
            metadata: json!({ "undocumented": undocumented }),
        },
    )
}

/// The second sentence of the missing-doc message: what else the rustdoc should say, asked only for what the
/// fn has. It names each non-underscore parameter, asks what it returns only when it returns something other
/// than `()` or `!` (for a `Result`, only when its written success type is neither), and asks when it fails
/// only when it returns a `Result`. Empty when there is nothing more.
fn missing_doc_contract_request(block: &FunctionBlock) -> String {
    let params: Vec<String> = extract_param_names(&block.body)
        .into_iter()
        .filter(|name| !name.starts_with('_'))
        .collect();
    let signature = own_signature(&block.body);
    let output = signature
        .as_ref()
        .and_then(|signature| match &signature.output {
            syn::ReturnType::Type(_, output) => Some(output.as_ref().clone()),
            syn::ReturnType::Default => None,
        });
    let gives_value = match &output {
        Some(output) if block.returns_result => {
            result_success_type(output).is_some_and(|success| !is_empty_type(success))
        }
        Some(output) => !is_empty_type(output),
        None => false,
    };
    let mut wanted = Vec::new();
    if !params.is_empty() {
        let verb = if params.len() == 1 { "is" } else { "are" };
        wanted.push(format!("what {} {verb} for", backticked_name_list(&params)));
    }
    if gives_value {
        wanted.push("what it returns".to_string());
    }
    if block.returns_result {
        wanted.push("when it returns an error".to_string());
    }
    match wanted.split_last() {
        None => String::new(),
        Some((last, [])) => format!(" Also say {last}."),
        Some((last, rest)) => format!(" Also say {} and {last}.", rest.join(", ")),
    }
}

/// Join `names` as code spans in an English list, such as "`a`, `b` and `c`".
fn backticked_name_list(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|name| format!("`{name}`")).collect();
    match quoted.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => quoted.concat(),
    }
}

/// Public functions whose rustdoc does not describe their return value
/// produce a finding; with `everyCallable` on, so does every other function
/// outside test code, bridge-macro fns included. Skips `-> ()` and `-> !`
/// fns, empty rustdocs and, with the switch off, Result-returning and
/// bridge-macro fns; with it on, a Result is checked for its success value.
pub(crate) fn analyse_missing_return_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let every_callable = is_every_callable(config, "docs.missing-return-doc");
    if !is_documentable_block(block, every_callable) || is_skipped_bridge(block, every_callable) {
        return;
    }
    if !signature_has_return_type(&block.body) {
        return;
    }
    let docs = function_doc_text(block);
    if docs.is_empty() || docs.has_returns_section() {
        return;
    }
    let signature = own_signature(&block.body);
    if is_skipped_return(block, signature.as_ref(), every_callable) {
        return;
    }
    // A constructor or builder returns the type its summary already describes.
    if signature.as_ref().is_some_and(is_constructor_or_builder) {
        return;
    }
    let summary = docs.summary();
    if has_described_return_value(block, signature.as_ref(), &summary) {
        return;
    }
    findings.push(missing_return_doc_finding(file, block));
}

/// Accept the bounded summary forms that tell API readers what a function returns.
/// Other prose leaves the missing-description warning in place.
fn has_described_return_value(
    block: &FunctionBlock,
    signature: Option<&syn::Signature>,
    summary: &str,
) -> bool {
    summary_has_return_stem(summary, signature)
        || is_getter_summary_naming_value(block, signature, summary)
        || is_conversion_summary_naming_return_value(summary, signature)
}

/// The fn's own signature, parsed from its item text, so a nested fn, a `where` clause or an attribute's text
/// is never read as this fn's shape. `None` when the text does not parse as one fn, which leaves every
/// signature-based exemption unapplied.
fn own_signature(body: &str) -> Option<syn::Signature> {
    let code = body_without_doc_comments(body);
    syn::parse_str::<syn::ImplItemFn>(&code)
        .map(|item| item.sig)
        .or_else(|_| syn::parse_str::<syn::TraitItemFn>(&code).map(|item| item.sig))
        .ok()
}

/// Report whether the return rule skips a declared return that hands the caller nothing to describe:
/// `-> ()` and `-> !` always, and a `Result` unless `every_callable` carries the rule's `everyCallable`
/// switch and the Result's written success type is neither. The `# Errors` rule covers a Result's failures;
/// a Result without a written success type (`fmt::Result`) or with an unparsed signature stays skipped.
fn is_skipped_return(
    block: &FunctionBlock,
    signature: Option<&syn::Signature>,
    every_callable: bool,
) -> bool {
    let returned = signature.and_then(|signature| match &signature.output {
        syn::ReturnType::Type(_, returned) => Some(returned.as_ref()),
        syn::ReturnType::Default => None,
    });
    if block.returns_result {
        return !every_callable
            || returned
                .and_then(result_success_type)
                .is_none_or(is_empty_type);
    }
    returned.is_some_and(is_empty_type)
}

/// The written success type of a `Result<T, ...>` return, such as `String` in `io::Result<String>`.
fn result_success_type(returned: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(path) = returned else {
        return None;
    };
    let segment = path
        .path
        .segments
        .last()
        .filter(|segment| segment.ident == "Result")?;
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.first()? {
        syn::GenericArgument::Type(success) => Some(success),
        _ => None,
    }
}

/// Report whether a type gives the caller nothing: unit `()` or never `!`.
fn is_empty_type(returned: &syn::Type) -> bool {
    match returned {
        syn::Type::Never(_) => true,
        syn::Type::Tuple(tuple) => tuple.elems.is_empty(),
        _ => false,
    }
}

/// Report whether a signature returns exactly the named type, such as `Self`; `&Self` is another type.
fn is_returned_type(signature: &syn::Signature, name: &str) -> bool {
    let syn::ReturnType::Type(_, returned) = &signature.output else {
        return false;
    };
    matches!(returned.as_ref(), syn::Type::Path(path) if path.qself.is_none() && path.path.is_ident(name))
}

/// Report whether a fn is a constructor or a builder step: it returns exactly `Self` and takes no receiver,
/// `self` by value or `&self`. A `&mut self` (or `self: &mut Self`) method returning `Self` (`split_off`,
/// `take`) hands back a part,
/// which its summary still has to name.
fn is_constructor_or_builder(signature: &syn::Signature) -> bool {
    is_returned_type(signature, "Self")
        && signature.receiver().is_none_or(|receiver| {
            !matches!(receiver.ty.as_ref(), syn::Type::Reference(reference) if reference.mutability.is_some())
        })
}

/// Report whether a signature returns `bool` or `Option<bool>`, whose meaning a summary has to state.
fn has_bool_result(signature: &syn::Signature) -> bool {
    if is_returned_type(signature, "bool") {
        return true;
    }
    let syn::ReturnType::Type(_, returned) = &signature.output else {
        return false;
    };
    let syn::Type::Path(path) = returned.as_ref() else {
        return false;
    };
    path.path.segments.last().is_some_and(|last| {
        last.ident == "Option"
            && matches!(&last.arguments, syn::PathArguments::AngleBracketed(arguments)
                if matches!(arguments.args.first(), Some(syn::GenericArgument::Type(syn::Type::Path(inner))) if inner.path.is_ident("bool")))
    })
}

/// Report whether the summary opens with an imperative stem naming what comes back, as in
/// `/// Return the FIPS status.` or `/// Get the parsed overrides.`. The word after the stem must name a
/// value, so `Return early` and `Get ready` do not count. `Create` counts only when the fn does not return
/// `bool` or `Option<bool>`, whose meaning a creation summary leaves unsaid, and neither does `Return` on
/// such a fn when the summary gives something back (`to the pool`, `into`, `back`). With no parsed
/// signature nothing counts.
fn summary_has_return_stem(summary: &str, signature: Option<&syn::Signature>) -> bool {
    const VALUE_OPENERS: &str =
        "the a an this its their whether true false all every each one some none new";
    let words = lowercase_words(summary);
    let [stem, object, ..] = words.as_slice() else {
        return false;
    };
    let Some(signature) = signature.filter(|_| is_listed(VALUE_OPENERS, object)) else {
        return false;
    };
    let is_bool_result = has_bool_result(signature);
    let gives_back = words.iter().any(|word| is_listed("into back", word))
        || words
            .windows(2)
            .any(|pair| pair[0] == "to" && is_listed("the its their a an", &pair[1]));
    match stem.as_str() {
        "get" => true,
        "return" => !(is_bool_result && gives_back),
        "create" => !is_bool_result,
        _ => false,
    }
}

/// Report whether a signature takes `&self` and nothing else.
fn has_only_shared_self_input(signature: &syn::Signature) -> bool {
    signature.inputs.len() == 1
        && matches!(
            signature.inputs.first(),
            Some(syn::FnArg::Receiver(receiver))
                if matches!(receiver.ty.as_ref(), syn::Type::Reference(reference) if reference.mutability.is_none())
        )
}

/// Verbs that read a value rather than change state, in imperative and third-person form.
const QUERY_VERBS: &str = "get gets retrieve retrieves return returns report reports check checks does indicates tells determines exposes provides access accesses yields obtain obtains iterate iterates convert converts compute computes calculate calculates find finds look looks peek peeks borrow borrows view derive derives generate generates resolve resolves build builds make makes treat treats accessor is has";

/// Report whether a summary's first word makes it an action rather than a description of a value: a
/// `Panics`, `Errors` or `Safety` heading, an imperative mutator such as `Remove` or `Clear`, or a
/// third-person verb such as `Removes` or `Resets` that is not a query verb (`Gets`, `Reports`, `Checks`);
/// `Status` and `Previous` end in `-us` and are not verbs.
fn is_action_opener(first: &str) -> bool {
    const HEADINGS: &str = "panics errors safety";
    const MUTATORS: &str = "remove reset clear set pop push insert add delete update write flush close open start stop attempt try acquire release take drain append apply supply register send increment decrement lock unlock spawn run consume mark enable disable toggle swap replace cancel purge evict commit refresh reload save store emit notify wake truncate execute kill advance handle";
    if is_listed(HEADINGS, first) || is_listed(MUTATORS, first) {
        return true;
    }
    let is_third_person_verb =
        first.len() > 3 && first.ends_with('s') && !first.ends_with("ss") && !first.ends_with("us");
    is_third_person_verb && !is_listed(QUERY_VERBS, first)
}

/// Report whether a word is one of a space-separated word list.
fn is_listed(list: &str, word: &str) -> bool {
    list.split_whitespace().any(|listed| listed == word)
}

/// Split prose into lowercase ASCII words, dropping punctuation and Markdown ticks.
fn lowercase_words(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// A getter documented by a description names what it returns, as `/// Logging filter level.` does on
/// `fn log_level(&self) -> LevelFilter`. It counts only when the fn takes `&self` and nothing else and the
/// summary names the value word ([`getter_value_word`]) or its plural. A noun opening such as
/// `Direction of the search` also counts; an action such as `Lock the mutex` still needs return prose.
fn is_getter_summary_naming_value(
    block: &FunctionBlock,
    signature: Option<&syn::Signature>,
    summary: &str,
) -> bool {
    let Some(signature) = signature.filter(|signature| has_only_shared_self_input(signature))
    else {
        return false;
    };
    let Some(value_word) = getter_value_word(block) else {
        return false;
    };
    let names_value = |word: &str| {
        word == value_word
            || word.strip_suffix('s') == Some(value_word.as_str())
            || value_word.strip_suffix('s') == Some(word)
    };
    let words = lowercase_words(described_clause(summary));
    // A getter's value noun can open a description of what the caller receives, as in `Direction of the search`.
    if words.first() == Some(&value_word) {
        return !has_bool_result(signature)
            && words.get(1).is_some_and(|word| word == "of")
            && words.len() >= 3;
    }
    let named_at = words
        .iter()
        .skip(1)
        .position(|word| names_value(word))
        .map(|index| index + 1);
    named_at.is_some_and(|named_at| {
        !names_value(&words[0])
            && words[named_at - 1] != "to"
            && is_descriptive_summary(&words, named_at, has_bool_result(signature))
    })
}

/// Accept `Converts an i128 to a Number` only when `Number` is the parsed direct or optional return value.
/// A different destination or an unknown return shape still asks the caller for return documentation.
fn is_conversion_summary_naming_return_value(
    summary: &str,
    signature: Option<&syn::Signature>,
) -> bool {
    // Without a parsed non-boolean return type, prose alone cannot establish the conversion's result.
    let Some(signature) = signature.filter(|signature| !has_bool_result(signature)) else {
        return false;
    };
    // An unknown or complex return shape needs a fuller description for API readers.
    let Some(returned_name) = returned_value_type_name(signature) else {
        return false;
    };
    let words = lowercase_words(summary);
    // A summary with no input words cannot tell callers what is converted.
    let [verb, source, ..] = words.as_slice() else {
        return false;
    };
    // A summary must name the input before it can describe a conversion into the return value.
    if !is_listed("convert converts", verb) || !is_listed("a an the", source) {
        return false;
    }
    // Missing destination words leave callers unsure what the conversion produces.
    let Some(destination_start) = words.len().checked_sub(3) else {
        return false;
    };
    destination_start >= 3
        && words[destination_start] == "to"
        && is_listed("a an the", &words[destination_start + 1])
        && words[destination_start + 2] == returned_name.to_ascii_lowercase()
}

/// Read a simple `T` or `Option<T>` result so conversion prose can name exactly what callers receive.
/// Complex or qualified types stay outside this wording exception.
fn returned_value_type_name(signature: &syn::Signature) -> Option<String> {
    // A function without an explicit return type has no destination to compare with its docs.
    let syn::ReturnType::Type(_, returned) = &signature.output else {
        return None;
    };
    // Non-path types cannot be named by this narrow summary form.
    let syn::Type::Path(path) = returned.as_ref() else {
        return None;
    };
    // A qualified or multi-segment type leaves the short destination name ambiguous.
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    let segment = &path.path.segments[0];
    // A direct return type may be named as written when it has no generic arguments.
    if segment.ident != "Option" {
        return matches!(segment.arguments, syn::PathArguments::None)
            .then(|| segment.ident.to_string());
    }
    // Only a single optional value is simple enough for this wording exception.
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    // Multiple generic arguments do not identify one value for the caller.
    if arguments.args.len() != 1 {
        return None;
    }
    // The optional inner type must itself be a plain named value.
    let syn::GenericArgument::Type(syn::Type::Path(inner)) = &arguments.args[0] else {
        return None;
    };
    inner
        .qself
        .is_none()
        .then(|| inner.path.get_ident().map(ToString::to_string))
        .flatten()
}

/// Report whether a `bool` summary says what `true` means: `whether`, `true` or `false`, a `Does`, `Is`, `Has` or
/// `Can` question, or `if` after a query verb (`Checks if`). An `if` after an action states a precondition, as in
/// `Signal parked waiters if any are sleeping.`
fn has_bool_meaning(words: &[String], opener: &str) -> bool {
    words
        .iter()
        .any(|word| is_listed("whether true false", word))
        || is_listed("does is has can", opener)
        || (is_listed(QUERY_VERBS, opener) && words.iter().any(|word| word == "if"))
}

/// The clause of a summary that describes the value: after a conditional lead-in such as `If this error is with
/// a table,` it is the rest (`the name of the table.`), which says what comes back when the condition holds.
fn described_clause(summary: &str) -> &str {
    match summary.split_once(',') {
        Some((condition, rest))
            if lowercase_words(condition)
                .first()
                .is_some_and(|word| is_listed("if when", word)) =>
        {
            rest
        }
        _ => summary,
    }
}

/// The value a getter's name promises: its final `_` segment, unless that is a quantifier such as `all` or
/// `once`, which names no value (`notify_all`, `poll_once`).
fn getter_value_word(block: &FunctionBlock) -> Option<String> {
    let fn_name = block.name.rsplit("::").next().unwrap_or(&block.name);
    fn_name
        .rsplit('_')
        .next()
        .map(str::to_ascii_lowercase)
        .filter(|word| {
            word.len() >= 2 && !is_listed("all once now mut ref async blocking unchecked", word)
        })
}

/// Report whether a summary whose word at `named_at` names the value reads as a description of it. An action
/// opener ([`is_action_opener`]) or `Create` never counts, read past a leading adverb (`Cheaply convert`), unless
/// an article opens the summary (`This socket's local port.`). A `bool` result counts once the summary says what
/// `true` means (`whether`, `true`, `false`, `if` after a query verb as in `Checks if`, or a `Does` or `Is`
/// question). Any other result counts when
/// the summary opens with an article or a query verb (`Gets`, `Iterate`, `Convert`), or has no article before
/// the named word, as a bare noun phrase does, so `Truncate the log.` on `fn log` is an action.
fn is_descriptive_summary(words: &[String], named_at: usize, is_bool_result: bool) -> bool {
    const ARTICLES: &str = "the a an this that its their";
    let opener = words
        .iter()
        .take(named_at)
        .find(|word| !(word.len() > 5 && word.ends_with("ly") && !is_action_opener(word)))
        .map_or(words[0].as_str(), String::as_str);
    let opens_with_article = is_listed(ARTICLES, opener);
    if !opens_with_article && (is_action_opener(opener) || opener == "create") {
        return false;
    }
    if is_bool_result {
        return has_bool_meaning(words, opener);
    }
    opens_with_article
        || is_listed(QUERY_VERBS, opener)
        || !words[..named_at]
            .iter()
            .any(|word| is_listed(ARTICLES, word))
}

fn missing_return_doc_finding(file: &SourceFile, block: &FunctionBlock) -> Finding {
    // A Result reaches this rule only for its success value; the `# Errors` rule asks about its failures.
    let described = if block.returns_result {
        "the success value"
    } else {
        "the return value"
    };
    block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-return-doc",
            message: format!(
                "{} `{}` returns a value; its rustdoc does not describe what {} represents.",
                callable_label(block),
                block.name,
                described
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::Medium,
            remediation: Some(
                "Describe the return value in the rustdoc - either in prose (e.g. `Returns the count of ...`) or in a `# Returns` section. The description should answer 'what does this represent at the edge values, when might it be empty/None/zero' rather than restating the return type."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    )
}

/// Check closures assigned to `const` and `static` items as callables, for each documentation rule whose
/// `everyCallable` switch is on; with every switch off no closure is checked.
pub(crate) fn analyse_closure_item_docs(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
        if is_every_callable(config, "docs.missing-public-doc") {
            analyse_public_function_doc(file, block, config, findings);
        }
        if is_every_callable(config, "docs.missing-param-doc") {
            analyse_missing_param_doc(file, block, config, findings);
        }
        if is_every_callable(config, "docs.missing-return-doc") {
            analyse_missing_return_doc(file, block, config, findings);
        }
    }
}

/// Read `rules.<rule_id>.options.everyCallable`, the switch that widens a documentation rule past
/// public functions; an unset switch reads as false.
fn is_every_callable(config: &Config, rule_id: &str) -> bool {
    config.is_rule_option_enabled(rule_id, "everyCallable")
}

/// Report whether a documentation rule checks this function: a public function outside test code, or any
/// function outside test code when `every_callable` carries the rule's `everyCallable` switch.
fn is_documentable_block(block: &FunctionBlock, every_callable: bool) -> bool {
    (block.is_externally_public || every_callable) && !block.is_test && !block.test_context
}

/// Report whether the parameter and return rules skip this function as a frontend bridge
/// (`#[tauri::command]`, `#[wasm_bindgen]` and the others [`has_frontend_bridge_attr`] matches). A bridge is
/// skipped only while the rule's `everyCallable` switch, carried by `every_callable`, is off.
fn is_skipped_bridge(block: &FunctionBlock, every_callable: bool) -> bool {
    !every_callable && has_frontend_bridge_attr(&block.body)
}

/// Name a function in a documentation message. Only an externally public function is called public, so a
/// private or crate-visible function that `everyCallable` brings into scope reads as a plain function.
fn callable_label(block: &FunctionBlock) -> &'static str {
    if block.is_externally_public {
        "Public function"
    } else {
        "Function"
    }
}

/// Return the parser-attached function rustdoc used by every documentation rule.
pub(crate) fn function_doc_text(block: &FunctionBlock) -> DocCommentText {
    // Absence means the user supplied no supported outer comment for this function.
    match &block.rustdoc {
        // Attached rustdoc gives every function-doc rule the same normalized source text.
        Some(rustdoc) => DocCommentText {
            text: rustdoc.text.clone(),
            source_line: Some(rustdoc.start_line),
        },
        // No supported comment keeps absence distinct from an intentionally empty doc comment.
        None => DocCommentText {
            text: String::new(),
            source_line: None,
        },
    }
}

/// Normalized function rustdoc plus the source-presence fact used by rule consumers.
/// Empty text means the user attached an empty doc comment; no source line means
/// there was no supported outer comment and the missing-public-doc rule may fire.
pub(crate) struct DocCommentText {
    text: String,
    source_line: Option<usize>,
}

impl DocCommentText {
    /// Report whether the user attached a supported outer comment to the function.
    pub(crate) fn is_present(&self) -> bool {
        self.source_line.is_some()
    }

    /// Find a Markdown rustdoc heading required by an API-contract rule.
    pub(crate) fn contains_section(&self, heading: &str) -> bool {
        self.text.lines().any(|line| {
            let trimmed = line.trim();
            let with_one = format!("# {heading}");
            let with_two = format!("## {heading}");
            let with_three = format!("### {heading}");
            trimmed.starts_with(&with_one)
                || trimmed.starts_with(&with_two)
                || trimmed.starts_with(&with_three)
        })
    }

    /// Return the first sentence of the first paragraph, joined into one line, where a rustdoc summary names
    /// what the item is or does; a summary sentence may wrap onto the next line.
    pub(crate) fn summary(&self) -> String {
        let paragraph: Vec<&str> = self
            .text
            .lines()
            .map(str::trim)
            .skip_while(|line| line.is_empty())
            .take_while(|line| !line.is_empty())
            .collect();
        let paragraph = paragraph.join(" ");
        paragraph.split(". ").next().unwrap_or_default().to_string()
    }

    /// Report whether attached rustdoc contains no usable prose.
    pub(crate) fn is_empty(&self) -> bool {
        self.text.trim().is_empty()
    }

    /// Find a parameter name as a complete rustdoc word rather than a substring.
    pub(crate) fn has_identifier_mention(&self, name: &str) -> bool {
        let lower = self.text.to_ascii_lowercase();
        let needle = name.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let pattern_len = needle.len();
        let mut index = 0usize;
        // Each matching word is checked until the user's prose contains the full identifier.
        while let Some(found) = lower[index..].find(needle.as_str()) {
            let absolute = index + found;

            // A complete identifier mention satisfies the parameter contract for the user.
            if is_word_boundary_match(bytes, absolute, pattern_len) {
                return true;
            }
            index = absolute + pattern_len;
        }
        false
    }

    /// Accept an explicit Returns heading or concise equivalent contract prose.
    pub(crate) fn has_returns_section(&self) -> bool {
        // An explicit heading is the clearest return-value contract for the user.
        if self.contains_section("Returns") {
            return true;
        }
        let lower = self.text.to_ascii_lowercase();
        lower.contains("returns ")
            || lower.contains("returning ")
            || lower.contains("yields ")
            || lower.contains("produces ")
            || lower.contains("provides ")
    }

    /// Accept concise prose that explains when a Result-returning function fails.
    fn has_error_contract_prose(&self) -> bool {
        let normalized = normalized_contract_text(&self.text);
        contains_any_phrase(
            &normalized,
            &[
                "returns err",
                "returns an error",
                "return error",
                "fails when",
                "fails if",
                "fail when",
                "fail if",
                "errors when",
                "errors if",
                "error when",
                "error if",
            ],
        )
    }

    /// Accept concise prose that identifies a panic trigger and reject denial-only text.
    fn has_panic_contract_prose(&self) -> bool {
        let normalized = normalized_contract_text(&self.text);

        // A no-panic statement does not document the real panic path found in the function.
        if contains_any_phrase(
            &normalized,
            &[
                "never panic",
                "never panics",
                "does not panic",
                "doesnt panic",
            ],
        ) {
            return false;
        }
        contains_any_phrase(
            &normalized,
            &[
                "panics when",
                "panics if",
                "panic when",
                "panic if",
                "will panic when",
                "will panic if",
            ],
        )
    }

    /// Accept concise single-parameter prose that still explains the caller's input contract. The parameter
    /// rule consults this only while its `everyCallable` switch is off.
    fn has_single_parameter_contract_prose(&self) -> bool {
        let normalized = normalized_contract_text(&self.text);
        contains_any_phrase(
            &normalized,
            &[
                "input",
                "argument",
                "parameter",
                "payload",
                "request",
                "source",
                "target",
                "path",
                "name",
                "identifier",
                "buffer",
                "bytes",
                "text",
                "slice",
            ],
        )
    }
}

fn normalized_contract_text(input: &str) -> String {
    let raw: String = input
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect();
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_any_phrase(haystack: &str, phrases: &[&str]) -> bool {
    let padded = format!(" {haystack} ");
    phrases
        .iter()
        .any(|phrase| padded.contains(&format!(" {phrase} ")))
}

fn is_word_boundary_match(bytes: &[u8], absolute: usize, pattern_len: usize) -> bool {
    let before_ok = absolute == 0 || !is_word_char(bytes[absolute - 1]);
    let after_pos = absolute + pattern_len;
    let after_ok = match bytes.get(after_pos) {
        None => true,
        Some(byte) => !is_word_char(*byte),
    };
    before_ok && after_ok
}

fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
