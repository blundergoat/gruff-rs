use super::*;

pub(crate) fn cases() -> Vec<CalibrationCase> {
    vec![
        // ----- modernisation: M01/M07 batch -----
        case(
            "modernisation.manual-is-empty",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn check(values: &Vec<i32>) -> bool { values.len() == 0 }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn check(values: &Vec<i32>) -> bool { values.is_empty() }\n",
                )
            }),
        ),
        case(
            "modernisation.manual-contains",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn has_value(items: &[i32], target: i32) -> bool {\n    items.iter().any(|item| *item == target)\n}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn has_value(items: &[i32], target: i32) -> bool {\n    items.contains(&target)\n}\n",
                )
            }),
        ),
        case(
            "modernisation.manual-strip-prefix",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn strip<'a>(input: &'a str, prefix: &str) -> &'a str {\n    if input.starts_with(prefix) { &input[prefix.len()..] } else { input }\n}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn strip<'a>(input: &'a str, prefix: &str) -> &'a str {\n    input.strip_prefix(prefix).unwrap_or(input)\n}\n",
                )
            }),
        ),
        case(
            "modernisation.manual-unwrap-or-default",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn value(opt: Option<i32>) -> i32 {\n    match opt { Some(inner) => inner, None => Default::default() }\n}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn value(opt: Option<i32>) -> i32 {\n    opt.unwrap_or_default()\n}\n",
                )
            }),
        ),
        // ----- docs: M02/M07 batch -----
        case(
            "docs.missing-panics-section",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Loads the value.\npub fn load(payload: i32) -> i32 {\n    if payload < 0 { panic!(\"negative payload\"); }\n    payload\n}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Loads the value.\n///\n/// # Panics\n///\n/// Panics when `payload` is negative.\npub fn load(payload: i32) -> i32 {\n    if payload < 0 { panic!(\"negative payload\"); }\n    payload\n}\n",
                )
            }),
        ),
        case(
            "docs.missing-safety-section",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Reads the byte.\npub unsafe fn touch(pointer: *const u8) -> u8 { *pointer }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Reads the byte.\n///\n/// # Safety\n///\n/// Caller guarantees `pointer` is non-null and aligned for `u8`.\npub unsafe fn touch(pointer: *const u8) -> u8 { *pointer }\n",
                )
            }),
        ),
        case(
            "docs.missing-param-doc",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Processes input.\npub fn process(payload: &str) -> usize { payload.len() }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Processes the `payload` string.\n///\n/// Returns the byte length.\npub fn process(payload: &str) -> usize { payload.len() }\n",
                )
            }),
        ),
        case(
            "docs.missing-return-doc",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Computes a thing for `seed`.\npub fn compute(seed: i32) -> i32 { seed + 1 }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Computes a thing for `seed`.\n///\n/// Returns the incremented seed.\npub fn compute(seed: i32) -> i32 { seed + 1 }\n",
                )
            }),
        ),
        // ----- security: M03 batch -----
        case(
            "security.path-traversal-candidate",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn open(input: &str) {\n    let _ = std::path::Path::new(input);\n}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn open() {\n    let _ = std::path::Path::new(\"/etc/static-fixture\");\n}\n",
                )
            }),
        ),
        // ----- test-quality: M04/M07 batch -----
        case(
            "test-quality.should-panic-without-expected",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[should_panic]\n    fn panics() { panic!(\"boom\"); }\n}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[should_panic(expected = \"boom\")]\n    fn panics() { panic!(\"boom\"); }\n}\n",
                )
            }),
        ),
    ]
}
