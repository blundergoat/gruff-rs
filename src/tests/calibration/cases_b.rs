use super::*;

pub(crate) fn cases() -> Vec<CalibrationCase> {
    vec![
        // ----- docs -----
        case(
            "docs.missing-public-doc",
            Box::new(|root| baseline_with_lib(root, "pub fn undocumented_entry() {}\n")),
            Box::new(|root| baseline_with_lib(root, "/// Documented entry.\npub fn entry() {}\n")),
        ),
        case(
            "docs.missing-readme",
            Box::new(|root| {
                fs::create_dir_all(root.join("src")).expect("src dir");
                fs::write(root.join("Cargo.toml"), CALIBRATION_BASELINE_MANIFEST)
                    .expect("manifest");
                fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
                    .expect("lockfile");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "docs.stale-todo",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\n// TODO fix this later\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\n// TODO(#123): remove after parser migration\npub fn entry() {}\n",
                )
            }),
        ),
        case(
            "docs.commented-out-code",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\n// let value = compute();\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\n// reminder: the next refactor should remove the cache\npub fn entry() {}\n",
                    )
            }),
        ),
        case(
            "docs.weak-safety-rationale",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {\n    // SAFETY: safe\n    unsafe { std::ptr::null::<i32>(); }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {\n    // SAFETY: caller guarantees pointer is non-null and aligned for u8.\n    unsafe { std::ptr::null::<i32>(); }\n}\n",
                    )
            }),
        ),
        case(
            "docs.missing-errors-section",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Loads the value.\npub fn load() -> Result<i32, String> { Ok(0) }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Loads the value.\n///\n/// # Errors\n///\n/// Returns Err when input is missing.\npub fn load() -> Result<i32, String> { Ok(0) }\n",
                    )
            }),
        ),
        // ----- error handling -----
        case(
            "error-handling.production-panic",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn always_panics() { panic!(\"boom\"); }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn returns_value() -> i32 { 1 }\n")
            }),
        ),
        case(
            "error-handling.public-unwrap",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let value: Option<i32> = Some(1); value.unwrap(); }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> Option<i32> { Some(1) }\n",
                )
            }),
        ),
        case(
            "error-handling.unimplemented-placeholder",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> i32 { todo!(\"unfinished\") }\n",
                )
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() -> i32 { 0 }\n")),
        ),
        // ----- metrics -----
        case(
            "metrics.halstead-volume",
            Box::new(|root| {
                let mut body = String::from(
                        "/// Probe.\npub fn dense(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {\n    let mut acc = 0;\n",
                    );
                for index in 0..60 {
                    body.push_str(&format!(
                            "    acc = acc + (a * {index}) - (b ^ {index}) | (c & {index}) + (d % ({index} + 1)) * (e + {index});\n"
                        ));
                }
                body.push_str("    acc\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
            }),
        ),
        case(
            "metrics.maintainability-pressure",
            Box::new(|root| {
                let mut body = String::from(
                        "/// Probe.\npub fn dense(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {\n    let mut acc = 0;\n",
                    );
                for index in 0..60 {
                    body.push_str(&format!(
                            "    if a == {index} {{ acc += b * {index} - c + d / ({index} + 1) - e; }}\n"
                        ));
                }
                body.push_str("    acc\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
            }),
        ),
        // ----- modernisation -----
        case(
            "modernisation.public-field",
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub struct Wide { pub value: i32 }\n")
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub struct Narrow { value: i32 }\nimpl Narrow { /// Read.\npub fn value(&self) -> i32 { self.value } }\n",
                    )
            }),
        ),
        // ----- naming -----
        case(
            "naming.boolean-prefix",
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn ready() -> bool { true }\n")
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn is_ready() -> bool { true }\n")
            }),
        ),
        case(
            "naming.generic-function",
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn process() {}\n")),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn ingest_payload() {}\n")),
        ),
        case(
            "naming.placeholder-identifier",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let foo = 1; let _ = foo; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let count = 1; let _ = count; }\n",
                )
            }),
        ),
        case(
            "naming.short-variable",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> i32 { let xy = 1; xy + 1 }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> i32 { let count = 1; count + 1 }\n",
                )
            }),
        ),
        case(
            "naming.identifier-shadow",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\nfn payload(input: &str) -> String { input.to_string() }\n/// Probe.\npub fn entry(input: &str) -> String { let payload = payload(input); payload }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\nfn payload(input: &str) -> String { input.to_string() }\n/// Probe.\npub fn entry(input: &str) -> String { let body = payload(input); body }\n",
                    )
            }),
        ),
        // ----- performance -----
        case(
            "performance.clone-in-loop",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn entry(values: Vec<String>) {
    for value in values {
        let _owned = value.clone();
    }
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(value: &String) { let _owned = value.clone(); }\n",
                )
            }),
        ),
        case(
            "performance.format-in-loop",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn entry(values: Vec<i32>) {
    for value in values {
        let _formatted = format!("{value}");
    }
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(value: i32) { let _formatted = format!(\"{value}\"); }\n",
                    )
            }),
        ),
        case(
            "performance.regex-in-loop",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn entry(values: Vec<i32>) {
    for value in values {
        let _compiled = regex::Regex::new("^a$");
        let _consume = value;
    }
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _compiled = regex::Regex::new(\"^a$\"); }\n",
                )
            }),
        ),
    ]
}
