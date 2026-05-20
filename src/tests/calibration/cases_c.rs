use super::*;

pub(crate) fn cases() -> Vec<CalibrationCase> {
    vec![
        // ----- security -----
        case(
            "security.process-command",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = std::process::Command::new(\"ls\"); }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> &'static str { \"ls\" }\n",
                )
            }),
        ),
        case(
            "security.unsafe-block",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(p: *const u8) -> u8 { unsafe { *p } }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(p: *const u8) -> u8 {\n    // SAFETY: caller validated pointer.\n    unsafe { *p }\n}\n",
                    )
            }),
        ),
        // ----- sensitive data -----
        case(
            "sensitive-data.api-key-pattern",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"ghp_aaaaaaaaaaaaaaaaaaaaaa\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"safe-string\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.aws-access-key",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"AKIAABCDEFGHIJKLMNOP\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"safe-string\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.database-url-password",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"postgres://user:secret@db/app\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"postgres://db/app\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.hardcoded-env-value",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"DATABASE_PASSWORD=correct-horse-battery-123\"; }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"DATABASE_PASSWORD\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.high-entropy-string",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"Q7m2P9x8R4s6T1v3W5y7Z0a2B4c6D8e0\"; }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"hello world\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.jwt-token",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"; }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"plain-string\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.private-key",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"-----BEGIN RSA PRIVATE KEY-----\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"plain-string\"; }\n",
                )
            }),
        ),
        // ----- size -----
        case(
            "size.file-length",
            Box::new(|root| {
                let mut body = String::from("/// Probe.\npub fn entry() {}\n");
                for index in 0..620 {
                    body.push_str(&format!("// filler line {index}\n"));
                }
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "size.function-length",
            Box::new(|root| {
                let mut body = String::from("/// Probe.\npub fn long_entry() {\n");
                for index in 0..60 {
                    body.push_str(&format!("    let _ = {index};\n"));
                }
                body.push_str("}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "size.parameter-count",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 { a + b + c + d + e + f }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn entry(a: i32) -> i32 { a }\n")
            }),
        ),
        // ----- test quality -----
        case(
            "test-quality.conditional-logic",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let value = 1;\n        if value > 0 { assert_eq!(value, 1); } else { assert_eq!(value, 0); }\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(2 + 2, 4); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.ignored-without-reason",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[ignore]\n    fn skipped() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[ignore = \"flaky on CI\"]\n    fn skipped() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.long-test",
            Box::new(|root| {
                let mut body = String::from(
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn long() {\n        let value = 0;\n",
                    );
                for index in 0..90 {
                    body.push_str(&format!("        let value = value + {index};\n"));
                }
                body.push_str("        assert_eq!(value, 4005);\n    }\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn quick() { assert_eq!(2 + 2, 4); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.loop-in-test",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let mut sum = 0;\n        for index in 0..3 { sum += index; }\n        assert_eq!(sum, 3);\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1 + 2, 3); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.no-assertions",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { let _ = 1; }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.sleep-in-test",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        std::thread::sleep(std::time::Duration::from_millis(1));\n        assert_eq!(1, 1);\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(2, 2); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.trivial-assertion",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert!(true); }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { let actual = 2 + 2; assert_eq!(actual, 4); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.unwrap-in-test",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let value: Option<i32> = Some(1);\n        let v = value.unwrap();\n        assert_eq!(v, 1);\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
        ),
        // ----- waste -----
        case(
            "waste.unnecessary-clone-candidate",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(value: &String) -> String { value.clone() }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(value: String) -> String { value }\n",
                )
            }),
        ),
        case(
            "waste.unreachable-code",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> i32 {\n    return 1;\n    let _ignored = 2;\n    3\n}\n",
                    )
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() -> i32 { 1 }\n")),
        ),
        case(
            "waste.unwrap-expect",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\nfn entry() { let value: Option<i32> = Some(1); value.unwrap(); }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn entry(value: Option<i32>) -> Option<i32> { value }\n",
                )
            }),
        ),
    ]
}
