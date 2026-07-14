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
