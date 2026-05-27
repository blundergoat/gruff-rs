use super::*;

#[test]
pub(crate) fn dashboard_scan_preserves_cwd_and_report_paths() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("sample write");
    let cwd_before = std::env::current_dir().expect("cwd");
    let query = format!(
        "projectRoot={}&path=sample.rs",
        dir.path().to_string_lossy()
    );

    let response = dashboard_response("/scan", &query, dir.path());

    assert_eq!(response.status, "200 OK");
    assert_eq!(std::env::current_dir().expect("cwd"), cwd_before);
    assert!(response.body.contains("Dashboard scan"));
    assert!(response.body.contains("sample.rs"));
    assert!(!response
        .body
        .contains(&dir.path().join("sample.rs").display().to_string()));
}

#[test]
pub(crate) fn dashboard_scan_rejects_absolute_or_escaping_paths() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("sample write");

    // Use a canonicalized tempdir outside the dashboard root rather than a
    // hardcoded `/`, so the test exercises the same boundary on every OS
    // (Rust's Path::is_absolute() and PathBuf canonicalization both behave
    // platform-specifically when given Unix-style literals).
    let outside = tempdir().expect("outside tempdir");
    fs::write(outside.path().join("README.md"), "# Outside\n").expect("outside readme write");
    let outside_root_canon = outside.path().canonicalize().expect("outside canonical");
    let outside_query = format!(
        "projectRoot={}&path=.",
        outside_root_canon.to_string_lossy()
    );
    let outside_root = dashboard_response("/scan", &outside_query, dir.path());
    assert_eq!(outside_root.status, "400 Bad Request");
    assert!(outside_root.body.contains("projectRoot must stay inside"));

    let sample_absolute = dir
        .path()
        .join("sample.rs")
        .canonicalize()
        .expect("sample canonical")
        .to_string_lossy()
        .into_owned();
    let absolute_query = format!("path={sample_absolute}");
    let absolute_path = dashboard_response("/scan", &absolute_query, dir.path());
    assert_eq!(absolute_path.status, "400 Bad Request");
    assert!(absolute_path.body.contains("path must be relative"));

    let parent_escape = dashboard_response("/scan", "path=../", dir.path());
    assert_eq!(parent_escape.status, "400 Bad Request");
    assert!(parent_escape.body.contains("'..'"));

    let nested_parent_escape =
        dashboard_response("/scan", "path=subdir/../../README.md", dir.path());
    assert_eq!(nested_parent_escape.status, "400 Bad Request");
    assert!(nested_parent_escape.body.contains("'..'"));

    let missing_path = dashboard_response("/scan", "path=does-not-exist", dir.path());
    assert_eq!(missing_path.status, "400 Bad Request");
    assert!(missing_path.body.contains("does not exist"));

    let malformed_percent = dashboard_response("/scan", "path=%E2%82%AC&bad=%€", dir.path());
    assert_eq!(malformed_percent.status, "400 Bad Request");
}

#[cfg(unix)]
#[test]
pub(crate) fn dashboard_scan_rejects_symlink_pointing_outside_root() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().expect("tempdir");
    let outside = tempdir().expect("outside tempdir");
    fs::write(outside.path().join("secret.rs"), "// outside\n").expect("outside write");
    symlink(outside.path(), dir.path().join("escape")).expect("symlink");

    let response = dashboard_response("/scan", "path=escape", dir.path());

    assert_eq!(response.status, "400 Bad Request");
    assert!(response.body.contains("path must stay inside"));
}
