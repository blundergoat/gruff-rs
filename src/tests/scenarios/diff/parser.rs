use super::*;

#[test]
pub(crate) fn diff_patch_parser_maps_new_side_lines_for_renames_crlf_and_deletions() {
    let patch = concat!(
        "diff --git a/src/old.rs b/src/new.rs\r\n",
        "similarity index 80%\r\n",
        "rename from src/old.rs\r\n",
        "rename to src/new.rs\r\n",
        "--- a/src/old.rs\r\n",
        "+++ b/src/new.rs\r\n",
        "@@ -1,3 +10,4 @@\r\n",
        " context\r\n",
        "-old\r\n",
        "+new\r\n",
        " keep\r\n",
        "+added\r\n",
        "diff --git a/src/delete.rs b/src/delete.rs\r\n",
        "--- a/src/delete.rs\r\n",
        "+++ b/src/delete.rs\r\n",
        "@@ -4,2 +4,0 @@\r\n",
        "-old\r\n",
        "-old\r\n",
        "diff --git a/bin.dat b/bin.dat\r\n",
        "Binary files a/bin.dat and b/bin.dat differ\r\n",
    );

    let parsed = parse_unified_diff(patch);

    assert_eq!(
        parsed.lines_by_file.get("src/new.rs"),
        Some(&BTreeSet::from([11, 13]))
    );
    assert!(parsed.saw_hunk);
    assert_eq!(
        parsed.lines_by_file.get("src/delete.rs"),
        Some(&BTreeSet::new())
    );
    assert!(!parsed.lines_by_file.contains_key("bin.dat"));
    assert!(parse_unified_diff("").lines_by_file.is_empty());
    assert!(!parse_unified_diff("").saw_hunk);
}

#[test]
pub(crate) fn diff_patch_parser_handles_quoted_paths_and_plus_content_lines() {
    let patch = concat!(
        "diff --git \"a/src/\\303\\251.rs\" \"b/src/\\303\\251.rs\"\n",
        "--- \"a/src/\\303\\251.rs\"\n",
        "+++ \"b/src/\\303\\251.rs\"\n",
        "@@ -1,2 +1,3 @@\n",
        " context\n",
        "+++ not a file header\n",
        "+added\n",
    );

    let parsed = parse_unified_diff(patch);

    assert_eq!(
        parsed.lines_by_file.get("src/é.rs"),
        Some(&BTreeSet::from([2, 3]))
    );
}
