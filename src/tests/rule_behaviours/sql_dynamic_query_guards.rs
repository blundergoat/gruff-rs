use super::*;

#[test]
pub(crate) fn sql_dynamic_query_keeps_attack_shapes() {
    let _guard = analysis_lock();
    let body = r#"/// Probe.
pub fn attack_shapes(user_id: i64, key: &str, prefix: &str, id: i64, v: i64) {
    let _raw_value = db.query(&format!("SELECT * FROM users WHERE id = {user_id}"));
    let _quoted_value = conn.execute(&format!("DELETE FROM t WHERE k = '{key}'"));
    let _prefix_and_value = db.prepare(&format!("SELECT * FROM {prefix}users WHERE name = '{key}'"));
    let q = format!("UPDATE t SET v = {v}");
    let _binding_flow = db.execute(&q);
    let _no_bind_marker = db.prepare(&format!("SELECT * FROM {prefix}users WHERE id = {id}"));
    let _lowercase = db.query(&format!("select * from t where id = {id}"));
}
"#;

    let report = analyse_sql_fixture(body);
    let lines = sql_dynamic_lines(&report);
    assert_eq!(
        lines,
        vec![3, 4, 5, 7, 8, 9],
        "attack-shaped dynamic SQL must keep flagging; findings={:?}",
        sql_dynamic_findings(&report)
    );
}

#[test]
pub(crate) fn sql_dynamic_query_handles_fixed_placeholder_arity() {
    let _guard = analysis_lock();
    let safe = r#"/// Probe.
pub fn fixed_placeholder_arity(ids: Vec<i64>) {
    let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT id FROM t WHERE id IN ({placeholders})");
    let mut stmt = conn.prepare(&sql)?;
    let params = rusqlite::params_from_iter(ids);
    stmt.query(params)?;
}
"#;
    assert_missing_rule(&analyse_sql_fixture(safe), "security.sql-dynamic-query");

    let direct_safe = r#"/// Probe.
pub fn direct_fixed_placeholder_arity(ids: Vec<i64>) {
    let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let mut stmt = conn.prepare(&format!("SELECT id FROM t WHERE id IN ({placeholders})"))?;
    let params = rusqlite::params_from_iter(ids);
    stmt.query(params)?;
}
"#;
    assert_missing_rule(
        &analyse_sql_fixture(direct_safe),
        "security.sql-dynamic-query",
    );

    let unsafe_join = r#"/// Probe.
pub fn raw_placeholder_join(ids: Vec<String>) {
    let placeholders = ids.join(",");
    let sql = format!("SELECT id FROM t WHERE id IN ({placeholders})");
    conn.prepare(&sql)?;
}
"#;
    assert_has_rule(
        &analyse_sql_fixture(unsafe_join),
        "security.sql-dynamic-query",
    );

    let mixed_identifier = r#"/// Probe.
pub fn mixed_identifier_and_placeholders(table: &str, ids: Vec<i64>) {
    let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT * FROM {table} WHERE id IN ({placeholders})");
    conn.prepare(&sql)?;
    let params = rusqlite::params_from_iter(ids);
}
"#;
    assert_has_rule(
        &analyse_sql_fixture(mixed_identifier),
        "security.sql-dynamic-query",
    );
}

#[test]
pub(crate) fn sql_dynamic_query_skips_non_sql_format_calls() {
    let _guard = analysis_lock();
    let body = r#"/// Probe.
pub fn non_sql(idx: usize, n: usize) {
    let _xpath = xp.query(&format!("//item[{idx}]"));
    let _command = cmd.execute(&format!("--limit={n}"));
}
"#;

    assert_missing_rule(&analyse_sql_fixture(body), "security.sql-dynamic-query");
}

#[test]
pub(crate) fn sql_dynamic_query_keeps_unbounded_identifier_interpolation() {
    let _guard = analysis_lock();
    let body = r#"/// Probe.
pub fn identifier_interpolation(prefix: &str, schema: &str, table: &str) {
    let _prefix = db.prepare(&format!("SELECT * FROM {prefix}users WHERE id = ?"));
    let _schema_table = db.query(&format!("SELECT * FROM {schema}.{table} WHERE id = $1"));
}
"#;

    let report = analyse_sql_fixture(body);
    assert_eq!(
        sql_dynamic_lines(&report),
        vec![3, 4],
        "unbounded identifier interpolation should stay visible; findings={:?}",
        sql_dynamic_findings(&report)
    );
}

fn analyse_sql_fixture(body: &str) -> AnalysisReport {
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), body);
    run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds")
}

fn sql_dynamic_findings(report: &AnalysisReport) -> Vec<&Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.sql-dynamic-query")
        .collect()
}

fn sql_dynamic_lines(report: &AnalysisReport) -> Vec<usize> {
    sql_dynamic_findings(report)
        .into_iter()
        .filter_map(|finding| finding.line)
        .collect()
}
