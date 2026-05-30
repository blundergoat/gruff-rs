use super::*;

pub(crate) fn cases() -> Vec<CalibrationCase> {
    vec![
        // ----- security -----
        case(
            "security.process-command",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(argument: &str) { let _ = std::process::Command::new(\"sh\").args([\"-c\", argument]).spawn(); }\n",
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
            "security.insecure-rng-for-secrets",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn generate_token() {
    let _ = rand::thread_rng();
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn choose_backoff() {
    let _ = rand::thread_rng();
}
"#,
                )
            }),
        ),
        case(
            "security.sql-dynamic-query",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn load(tenant: &str) {
    let _ = sqlx::query(format!("select * from users_{tenant}"));
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn load() {
    let _ = sqlx::query("select * from users");
}
"#,
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
        case(
            "security.weak-crypto",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"use md5::Md5;

/// Probe.
pub fn digest() {
    let _ = Md5::new();
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"use sha2::Sha256;

/// Probe.
pub fn digest() {
    let _ = Sha256::new();
}
"#,
                )
            }),
        ),
        case(
            "security.tls-verification-disabled",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn client() {
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_certs(true);
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn client() {
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_certs(false);
}
"#,
                )
            }),
        ),
        case(
            "dependency.git-unpinned-revision",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "Calibration baseline."
license = "MIT"

[dependencies]
gitdep = { git = "https://example.invalid/repo.git" }
"#,
                )
                .expect("calibration manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "Calibration baseline."
license = "MIT"

[dependencies]
gitdep = { git = "https://example.invalid/repo.git", rev = "1111111111111111111111111111111111111111" }
"#,
                )
                .expect("calibration manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
        ),
        case(
            "ci.github-event-shell-interpolation",
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n");
                fs::create_dir_all(root.join(".github/workflows")).expect("workflow dir");
                fs::write(
                    root.join(".github/workflows/ci.yml"),
                    "name: ci\njobs:\n  test:\n    steps:\n      - run: echo '${{ github.event.pull_request.title }}'\n",
                )
                .expect("workflow write");
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n");
                fs::create_dir_all(root.join(".github/workflows")).expect("workflow dir");
                fs::write(
                    root.join(".github/workflows/ci.yml"),
                    "name: ci\njobs:\n  test:\n    steps:\n      - run: echo '${{ github.ref }}'\n",
                )
                .expect("workflow write");
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
            "sensitive-data.url-embedded-credentials",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"https://user:secret@example.invalid/path\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"https://example.invalid/path\"; }\n",
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
                    concat!(
                        "/// Probe.\n",
                        "pub fn entry() {\n",
                        "    let _ = \"-----BEGIN RSA ",
                        "PRIVATE KEY-----\n",
                        "MIIEowIBAAKCAQEAwvR2b2d1c2ZpeHR1cmV2YWx1ZQ==\n",
                        "-----END RSA ",
                        "PRIVATE KEY-----\";\n",
                        "}\n",
                    ),
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
                        "/// Probe.\npub fn entry(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32) -> i32 { a + b + c + d + e + f + g + h }\n",
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
                body.push_str("        assert_eq!(value, 0);\n");
                for index in 0..130 {
                    body.push_str(&format!("        let value = value + {index};\n"));
                }
                body.push_str("        assert_eq!(value, 8385);\n    }\n}\n");
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
