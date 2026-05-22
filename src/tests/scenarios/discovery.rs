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
