use super::*;

#[test]
pub(crate) fn project_ignore_globs_match_external_hidden_directories() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    for path in [
        ".claude/hooks",
        ".codex/hooks",
        ".agents/skills",
        ".goat-flow/tasks",
        ".github/workflows",
        "src",
    ] {
        fs::create_dir_all(dir.path().join(path)).expect("fixture dir");
    }
    for (path, body) in [
        (".claude/hooks/a.sh", "#!/usr/bin/env bash\n"),
        (".codex/hooks/a.sh", "#!/usr/bin/env bash\n"),
        (".agents/skills/a.md", "# Skill\n"),
        (".goat-flow/tasks/a.md", "# Task\n"),
        (".github/workflows/ci.yml", "name: ci\n"),
        ("src/lib.rs", "pub fn ready() {}\n"),
    ] {
        fs::write(dir.path().join(path), body).expect("fixture file");
    }

    let ignored_paths = [
        "**/.claude/**",
        "**/.codex/**",
        "**/.agents/**",
        "**/.goat-flow/**",
        "**/.github/**",
    ]
    .map(str::to_string)
    .to_vec();
    let config = Config {
        ignored_path_matchers: compile_path_matchers(&ignored_paths),
        ignored_paths,
        ..Config::default()
    };
    let discovery = discover_sources(
        Path::new("."),
        &AnalysisOptions {
            paths: vec![dir.path().to_path_buf()],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
        &config,
    );
    let discovered_paths: Vec<&str> = discovery
        .files
        .iter()
        .map(|file| file.display_path.as_str())
        .collect();

    assert_eq!(discovered_paths.len(), 1, "{discovered_paths:?}");
    assert!(discovered_paths[0].ends_with("/src/lib.rs"));
    for ignored_dir in [".claude", ".codex", ".agents", ".goat-flow", ".github"] {
        assert!(
            discovery
                .ignored_paths
                .iter()
                .any(|path| path.ends_with(&format!("/{ignored_dir}"))),
            "missing ignored dir `{ignored_dir}` in {:?}",
            discovery.ignored_paths
        );
    }
}

#[test]
pub(crate) fn discovery_includes_security_relevant_text_names_and_extensions() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let private_key_marker = concat!("-----BEGIN ", "PRIVATE KEY-----\n");
    for path in [".cargo", "infra", "certs"] {
        fs::create_dir_all(dir.path().join(path)).expect("fixture dir");
    }
    for (path, body) in [
        ("Dockerfile", "FROM scratch\n"),
        ("Makefile", "test:\n\tcargo test\n"),
        ("justfile", "test:\n    cargo test\n"),
        (".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"),
        (".pypirc", "[pypi]\nusername = __token__\n"),
        ("Cargo.lock", "[[package]]\nname = \"demo\"\n"),
        ("infra/main.tf", "resource \"x\" \"y\" {}\n"),
        ("infra/secrets.tfvars", "database_password = \"secret\"\n"),
        ("certs/private.pem", private_key_marker),
        ("certs/tls.key", private_key_marker),
        (".cargo/config", "[net]\ngit-fetch-with-cli = true\n"),
    ] {
        fs::write(dir.path().join(path), body).expect("fixture file");
    }

    let discovery = discover_sources(
        dir.path(),
        &AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
        &Config::default(),
    );
    let discovered_paths: BTreeSet<&str> = discovery
        .files
        .iter()
        .map(|file| file.display_path.as_str())
        .collect();

    for expected in [
        ".cargo/config",
        ".npmrc",
        ".pypirc",
        "Cargo.lock",
        "Dockerfile",
        "Makefile",
        "certs/private.pem",
        "certs/tls.key",
        "infra/main.tf",
        "infra/secrets.tfvars",
        "justfile",
    ] {
        assert!(
            discovered_paths.contains(expected),
            "missing `{expected}` from discovered paths: {discovered_paths:?}"
        );
    }
}

const RISKY_RS: &str =
    "pub fn risky() -> i32 {\n    let value: Option<i32> = None;\n    value.unwrap()\n}\n";

fn vendor_ignore_config() -> Config {
    let patterns = vec!["vendor/**".to_string(), "src/generated.rs".to_string()];
    Config {
        ignored_path_matchers: compile_path_matchers(&patterns),
        ignored_paths: patterns,
        ..Config::default()
    }
}

// ADR-018 req 5(a): an explicit file arg matching `paths.ignore` produces no
// findings and is reported in `ignoredPathDetails` with its source and pattern.
#[test]
pub(crate) fn config_ignore_is_authoritative_for_explicit_file_args() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("vendor")).expect("vendor dir");
    fs::write(dir.path().join("vendor/lib.rs"), RISKY_RS).expect("ignored file");
    write_config(dir.path(), r#"{ "paths": { "ignore": ["vendor/**"] } }"#);

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("vendor/lib.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.file_path != "vendor/lib.rs"),
        "explicit config-ignored file must produce no findings: {:?}",
        report
            .findings
            .iter()
            .map(|finding| &finding.file_path)
            .collect::<Vec<_>>()
    );
    let detail = report
        .paths
        .ignored_path_details
        .iter()
        .find(|entry| entry.path == "vendor/lib.rs")
        .expect("explicit ignored file reported in ignoredPathDetails");
    assert_eq!(detail.source, IgnoreSource::Config);
    assert_eq!(detail.pattern.as_deref(), Some("vendor/**"));
}

// ADR-018 req 5(b): a diff that touches a config-ignored file does not flag it,
// while a tracked changed file in the same diff is still analysed.
#[test]
pub(crate) fn config_ignore_is_authoritative_in_diff_patch_mode() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("vendor")).expect("vendor dir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("vendor/lib.rs"), RISKY_RS).expect("ignored file");
    fs::write(dir.path().join("src/app.rs"), RISKY_RS).expect("tracked file");
    write_config(dir.path(), r#"{ "paths": { "ignore": ["vendor/**"] } }"#);

    let patch = concat!(
        "diff --git a/vendor/lib.rs b/vendor/lib.rs\n",
        "--- a/vendor/lib.rs\n+++ b/vendor/lib.rs\n@@ -0,0 +1,4 @@\n",
        "+pub fn risky() -> i32 {\n+    let value: Option<i32> = None;\n+    value.unwrap()\n+}\n",
        "diff --git a/src/app.rs b/src/app.rs\n",
        "--- a/src/app.rs\n+++ b/src/app.rs\n@@ -0,0 +1,4 @@\n",
        "+pub fn risky() -> i32 {\n+    let value: Option<i32> = None;\n+    value.unwrap()\n+}\n",
    );
    let patch_path = dir.path().join("change.patch");
    fs::write(&patch_path, patch).expect("patch write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            diff: Some(DiffSelection::Patch {
                path: patch_path,
                scope: ChangedScope::Symbol,
            }),
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.file_path != "vendor/lib.rs"),
        "config-ignored file must not be flagged even when the diff touches it"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.file_path == "src/app.rs"),
        "tracked changed file should still be analysed in diff mode"
    );
    assert!(
        report
            .paths
            .ignored_path_details
            .iter()
            .any(|entry| entry.path == "vendor" && entry.source == IgnoreSource::Config),
        "ignored vendor tree reported with config source: {:?}",
        report.paths.ignored_path_details
    );
}

// ADR-018 req 5(c): `check-ignore`'s engine (`classify_ignored_path`) returns the
// correct verdict and pattern, and is the SAME engine discovery records with.
#[test]
pub(crate) fn check_ignore_engine_matches_discovery() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let config = vendor_ignore_config();

    let ignored = classify_ignored_path(
        dir.path(),
        &dir.path().join("vendor/lib.rs"),
        &config,
        false,
    )
    .expect("config-ignored path classified");
    assert_eq!(ignored.path, "vendor/lib.rs");
    assert_eq!(ignored.source, IgnoreSource::Config);
    assert_eq!(ignored.pattern.as_deref(), Some("vendor/**"));

    let exact = classify_ignored_path(
        dir.path(),
        &dir.path().join("src/generated.rs"),
        &config,
        false,
    )
    .expect("exact config-ignored path classified");
    assert_eq!(exact.pattern.as_deref(), Some("src/generated.rs"));

    assert!(
        classify_ignored_path(dir.path(), &dir.path().join("src/app.rs"), &config, false).is_none(),
        "non-ignored path must classify as not ignored"
    );

    // Same engine: an explicit-arg discovery scan records the identical entry.
    fs::create_dir_all(dir.path().join("vendor")).expect("vendor dir");
    fs::write(dir.path().join("vendor/lib.rs"), "pub fn f() {}\n").expect("file");
    let discovery = discover_sources(
        dir.path(),
        &AnalysisOptions {
            paths: vec![dir.path().join("vendor/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
        &config,
    );
    assert_eq!(discovery.ignored_path_details, vec![ignored]);
}

// ADR-018 req 5(d): `--include-ignored` opts into git/default ignores only and
// must never reveal config-ignored paths.
#[test]
pub(crate) fn include_ignored_still_honours_config_ignore() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("vendor")).expect("vendor dir");
    fs::write(dir.path().join("vendor/lib.rs"), "pub fn f() {}\n").expect("file");
    fs::write(dir.path().join("keep.rs"), "pub fn g() {}\n").expect("file");
    let config = vendor_ignore_config();

    let discovery = discover_sources(
        dir.path(),
        &AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            include_ignored: true,
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
        &config,
    );
    let discovered: Vec<&str> = discovery
        .files
        .iter()
        .map(|file| file.display_path.as_str())
        .collect();
    assert!(
        discovered.iter().any(|path| path.ends_with("keep.rs")),
        "non-ignored file should be discovered: {discovered:?}"
    );
    assert!(
        !discovered.iter().any(|path| path.contains("vendor/")),
        "--include-ignored must not reveal config-ignored vendor: {discovered:?}"
    );

    let ignored =
        classify_ignored_path(dir.path(), &dir.path().join("vendor/lib.rs"), &config, true)
            .expect("config ignore authoritative even under include_ignored");
    assert_eq!(ignored.source, IgnoreSource::Config);
}
