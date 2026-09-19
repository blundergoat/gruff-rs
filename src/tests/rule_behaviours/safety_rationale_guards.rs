//! Weak `SAFETY:` rationale tests exercise the detector's punctuation contract.
//! The table keeps accepted and rejected comment text together so CLI users do
//! not receive contradictory guidance when a rationale contains separators.

/// Locks documented examples to the helper contract before an unsafe-block
/// scan turns weak text into a `docs.weak-safety-rationale` finding.
#[test]
pub(crate) fn safety_rationale_examples_match_documented_contract() {
    let cases = [
        ("same-thread access", false),
        ("caller-validated pointer", false),
        ("pointer is non-null.", false),
        ("caller guarantees pointer alignment", false),
        ("", true),
        ("   ", true),
        ("safe", true),
        ("safe.", true),
        ("obvious!", true),
        ("pointer valid", true),
        ("this is safe", true),
        ("safe because safe", true),
    ];

    for (rationale, expected_weak) in cases {
        assert_eq!(
            crate::built_in_rules::is_weak_safety_rationale(rationale),
            expected_weak,
            "unexpected weak-rationale classification for {rationale:?}"
        );
    }
}

#[test]
/// Mixed-case markers and their continuation lines form one rationale.
pub(crate) fn nearby_safety_rationale_accepts_case_and_multiline_comments() {
    let lines = [
        "    // Safety:",
        "    // the pointer remains valid for the operation,",
        "    // and the caller retains exclusive access.",
        "    #[allow(unused_unsafe)]",
        "    unsafe { read_pointer() }",
    ];

    let rationale = crate::built_in_rules::find_nearby_safety_rationale(&lines, 4)
        .expect("mixed-case multiline rationale");
    assert_eq!(
        rationale,
        "the pointer remains valid for the operation, and the caller retains exclusive access."
    );

    for marker in ["SAFETY", "Safety", "safety"] {
        let marker_line = format!("// {marker}: caller validated pointer alignment");
        let case_lines = [marker_line.as_str(), "unsafe { read_pointer() }"];
        assert!(
            crate::built_in_rules::find_nearby_safety_rationale(&case_lines, 1).is_some(),
            "marker case should be accepted: {marker}"
        );
    }
}

#[test]
/// Same-line rationale text counts only when Rust parses it as a comment.
pub(crate) fn same_line_safety_rationale_ignores_string_literals() {
    let literal_lines = [r#"unsafe { inspect("SAFETY: pointer remains valid") }"#];
    assert!(
        crate::built_in_rules::find_nearby_safety_rationale(&literal_lines, 0).is_none(),
        "a string literal must not document an unsafe block"
    );

    let comment_lines =
        ["unsafe { inspect_pointer() } // Safety: caller retains exclusive pointer access"];
    assert_eq!(
        crate::built_in_rules::find_nearby_safety_rationale(&comment_lines, 0).as_deref(),
        Some("caller retains exclusive pointer access")
    );
}

#[test]
/// Rationale lookup is bounded and cannot cross an intervening statement.
pub(crate) fn nearby_safety_rationale_stops_at_code_and_sixteen_lines() {
    let separated_lines = [
        "// SAFETY: caller validated pointer alignment",
        "let unrelated = prepare();",
        "unsafe { read_pointer() }",
    ];
    assert!(
        crate::built_in_rules::find_nearby_safety_rationale(&separated_lines, 2).is_none(),
        "an intervening statement must end the rationale prelude"
    );

    let mut within_bound = vec!["// SAFETY: caller validated pointer alignment"];
    within_bound.extend(std::iter::repeat_n("// continued invariant", 15));
    within_bound.push("unsafe { read_pointer() }");
    assert!(
        crate::built_in_rules::find_nearby_safety_rationale(&within_bound, 16).is_some(),
        "a marker sixteen lines before the block should be accepted"
    );

    let mut beyond_bound = vec!["// SAFETY: caller validated pointer alignment"];
    beyond_bound.extend(std::iter::repeat_n("// continued invariant", 16));
    beyond_bound.push("unsafe { read_pointer() }");
    assert!(
        crate::built_in_rules::find_nearby_safety_rationale(&beyond_bound, 17).is_none(),
        "a marker beyond the bounded prelude must stay unresolved"
    );
}

#[test]
/// Plain block-comment lines count as rationale text, but dereferences remain executable code.
pub(crate) fn nearby_safety_rationale_follows_block_comment_boundaries() {
    let block_comment_lines = [
        "    /* SAFETY: caller validated pointer alignment and",
        "       the allocation remains live for this read.",
        "    */",
        "    unsafe { read_pointer() }",
    ];
    assert_eq!(
        crate::built_in_rules::find_nearby_safety_rationale(&block_comment_lines, 3).as_deref(),
        Some("caller validated pointer alignment and the allocation remains live for this read.")
    );

    let marker_inside_block = [
        "    /*",
        "       SAFETY: caller validated pointer alignment and",
        "       the allocation remains live for this read.",
        "    */",
        "    unsafe { read_pointer() }",
    ];
    assert_eq!(
        crate::built_in_rules::find_nearby_safety_rationale(&marker_inside_block, 4).as_deref(),
        Some("caller validated pointer alignment and the allocation remains live for this read.")
    );

    let dereference_lines = [
        "    // SAFETY: caller validated pointer alignment",
        "    *destination = value;",
        "    unsafe { read_pointer() }",
    ];
    assert!(
        crate::built_in_rules::find_nearby_safety_rationale(&dereference_lines, 2).is_none(),
        "an executable dereference must end the rationale prelude"
    );

    let inline_block_comment = [
        "    // SAFETY: old rationale must not cross executable code",
        "    prepare_pointer(); /* unrelated note */",
        "    unsafe { read_pointer() }",
    ];
    assert!(
        crate::built_in_rules::find_nearby_safety_rationale(&inline_block_comment, 2).is_none(),
        "a trailing block comment must not disguise executable code as rationale text"
    );
}

#[test]
/// A rationale still explains a block when a statement leading into it or a control-flow header sits between
/// them, under a bare `SAFETY` line or a `# Safety` heading, and as the
/// first comment inside the block. Prose that merely mentions safety explains nothing, and a blank line ends
/// the prelude.
pub(crate) fn nearby_safety_rationale_reads_continuations_headings_and_the_block_body() {
    let find = crate::built_in_rules::find_nearby_safety_rationale;
    let continuation = [
        "// SAFETY: the slice is non-empty",
        "let value =",
        "    unsafe { read_pointer() };",
    ];
    assert_eq!(
        find(&continuation, 2).as_deref(),
        Some("the slice is non-empty")
    );
    let header = [
        "// SAFETY: the tag was checked above",
        "match tag {",
        "    Tag::Raw => unsafe { read_pointer() },",
    ];
    assert_eq!(
        find(&header, 2).as_deref(),
        Some("the tag was checked above")
    );
    let blank = [
        "// SAFETY: aligned by construction",
        "",
        "unsafe { read_pointer() }",
    ];
    assert!(find(&blank, 2).is_none(), "a blank line ends the prelude");
    let bare = [
        "// SAFETY",
        "// The buffer outlives the call.",
        "unsafe { read_pointer() }",
    ];
    assert_eq!(
        find(&bare, 2).as_deref(),
        Some("The buffer outlives the call.")
    );
    let heading = [
        "// # Safety",
        "// The caller guarantees exclusive access.",
        "unsafe { read_pointer() }",
    ];
    assert_eq!(
        find(&heading, 2).as_deref(),
        Some("The caller guarantees exclusive access.")
    );
    let inside = [
        "unsafe {",
        "    // SAFETY: the glyph table is static",
        "    read_pointer()",
        "}",
    ];
    assert_eq!(
        find(&inside, 0).as_deref(),
        Some("the glyph table is static")
    );
    let inside_below_marker = [
        "unsafe {",
        "    // SAFETY:",
        "    // We have a unique not null pointer here",
        "    read_pointer()",
        "}",
    ];
    assert_eq!(
        find(&inside_below_marker, 0).as_deref(),
        Some("We have a unique not null pointer here")
    );
    let inside_empty = ["unsafe {", "    // SAFETY:", "    read_pointer()", "}"];
    assert_eq!(find(&inside_empty, 0).as_deref(), Some(""));
    for decoy in [
        [
            "// thread safety is handled by the lock",
            "unsafe { read_pointer() }",
        ],
        ["// TODO: safety review", "unsafe { read_pointer() }"],
        [
            "// SAFETYNET is a separate type",
            "unsafe { read_pointer() }",
        ],
    ] {
        assert!(find(&decoy, 1).is_none(), "{decoy:?}");
    }
    let completed = [
        "// SAFETY: caller validated pointer alignment",
        "let unrelated = prepare();",
        "",
        "unsafe { read_pointer() }",
    ];
    assert!(
        find(&completed, 3).is_none(),
        "a completed statement still ends the prelude after a blank line"
    );
    let weak = crate::built_in_rules::is_weak_safety_rationale;
    for placeholder in [
        "TODO: document the invariant here",
        "FIXME this is unsound, see issue 123",
    ] {
        assert!(
            weak(placeholder),
            "a placeholder gives no rationale: {placeholder}"
        );
    }
    assert!(!weak("the pointer comes from a live Box and is aligned"));
    for (lines, block_line) in [
        (
            vec![
                "match k {",
                "    // SAFETY: k == 0 guarantees p is valid for reads.",
                "    0 => unsafe { *p },",
                "    _ => unsafe { *q },",
            ],
            3,
        ),
        (
            vec![
                "add(",
                "    // SAFETY: p is valid for reads for the whole call.",
                "    unsafe { *p },",
                "    unsafe { *q },",
            ],
            3,
        ),
        (
            vec![
                "Pair {",
                "    // SAFETY: p is valid for reads for the whole call.",
                "    first: unsafe { *p },",
                "    second: unsafe { *q },",
            ],
            3,
        ),
        (
            vec![
                "while unsafe { next(it) } != 0 {",
                "    // SAFETY: it stays valid until next returns 0.",
                "    let _value = unsafe { get(it) };",
            ],
            0,
        ),
        (
            vec!["// SAFETY HAZARD: p may be dangling here", "unsafe { *p }"],
            1,
        ),
        (
            vec![
                "// SAFETY is not guaranteed here, the pointer may dangle after free",
                "unsafe { *p }",
            ],
            1,
        ),
        (
            vec![
                "// SAFETY HAZARD - this pointer may dangle after the owner frees it",
                "unsafe { *p }",
            ],
            1,
        ),
        (
            vec!["// SAFETY Note: the pointer may dangle", "unsafe { *p }"],
            1,
        ),
        (
            vec![
                "// SAFETY Cannot be guaranteed when the buffer is shared with another thread.",
                "unsafe { *p }",
            ],
            1,
        ),
        (
            vec![
                "// SAFETY This is safe because the buffer outlives the call",
                "unsafe { *p }",
            ],
            1,
        ),
        (
            vec![
                "// SAFETY: `p` is non-null and valid for reads for the whole call.",
                "let a = checked_read(p); // slow path :(",
                "let b = unsafe { *q };",
            ],
            2,
        ),
        (
            vec![
                "if borrowed {",
                "    // SAFETY: the borrowed buffer is released by its owner, never here.",
                "} else {",
                "    unsafe { *p = 0 };",
            ],
            3,
        ),
    ] {
        assert!(
            find(&lines, block_line).is_none(),
            "a sibling's, another branch's, a loop body's or a hazard's comment explains nothing: {lines:?}"
        );
    }
}
