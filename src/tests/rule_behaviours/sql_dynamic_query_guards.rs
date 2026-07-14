//! SQL dynamic-query behaviour tests keep the security signal tied to SQL-shaped text.
//! They model direct and one-hop `format!` values at supported database sink names so
//! maintainers can tighten prose noise without dropping injection-relevant statements.

use super::*;

/// Keeps direct and one-hop SQL injection shapes visible across every supported sink name.
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
    let query_text = format!("SELECT id FROM users WHERE id = {id}");
    let _bound_query = db.query(&query_text);
    let prepare_text = format!("DELETE FROM users WHERE id = {id}");
    let _bound_prepare = db.prepare(&prepare_text);
    let _no_bind_marker = db.prepare(&format!("SELECT * FROM {prefix}users WHERE id = {id}"));
    let _lowercase = db.query(&format!("select * from t where id = {id}"));
}
"#;

    let report = analyse_sql_fixture(body);
    let lines = sql_dynamic_lines(&report);
    assert_eq!(
        lines,
        vec![3, 4, 5, 7, 9, 11, 12, 13],
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
pub(crate) fn sql_dynamic_query_rejects_value_interpolation_beside_placeholder_list() {
    let _guard = analysis_lock();
    // A proven `?` list (`placeholders`) plus a nearby `params_from_iter` must not
    // exempt a template that ALSO interpolates a value through a positional `{}`:
    // that value is formatted straight into the SQL text and is a real injection
    // sink. The fixed-arity exemption may only fire when every placeholder is a
    // proven `?` list.
    let positional_value = r#"/// Probe.
pub fn positional_value(status: &str, ids: Vec<i64>) {
    let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT * FROM t WHERE status = {} AND id IN ({placeholders})", status);
    conn.prepare(&sql)?;
    let params = rusqlite::params_from_iter(ids);
}
"#;
    assert_has_rule(
        &analyse_sql_fixture(positional_value),
        "security.sql-dynamic-query",
    );

    // An indexed `{0}` is likewise an unproven value interpolation, not a `?` list.
    let indexed_value = r#"/// Probe.
pub fn indexed_value(status: &str, ids: Vec<i64>) {
    let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT * FROM t WHERE status = {0} AND id IN ({placeholders})", status);
    conn.prepare(&sql)?;
    let params = rusqlite::params_from_iter(ids);
}
"#;
    assert_has_rule(
        &analyse_sql_fixture(indexed_value),
        "security.sql-dynamic-query",
    );
}

#[test]
pub(crate) fn sql_dynamic_query_proof_is_scoped_to_current_function_and_exact_name() {
    let _guard = analysis_lock();
    // A helper's fixed-`?` list must not vouch for an untrusted `placeholders`
    // parameter in a LATER public function: the proof window stays inside one fn.
    let cross_function = r#"/// Probe.
pub fn build_list(ids: &[i64]) -> String {
    std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",")
}

/// Probe.
pub fn run_attack(placeholders: &str, ids: Vec<i64>) {
    let sql = format!("SELECT * FROM t WHERE name IN ({placeholders})");
    conn.prepare(&sql)?;
    let params = rusqlite::params_from_iter(ids);
}
"#;
    assert_has_rule(
        &analyse_sql_fixture(cross_function),
        "security.sql-dynamic-query",
    );

    // A prefix-named binding (`placeholders_safe`) must not prove `{placeholders}`.
    let prefix_name = r#"/// Probe.
pub fn run_prefix(placeholders: &str, ids: Vec<i64>) {
    let placeholders_safe = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT * FROM t WHERE name IN ({placeholders})");
    conn.prepare(&sql)?;
    let params = rusqlite::params_from_iter(ids);
}
"#;
    assert_has_rule(
        &analyse_sql_fixture(prefix_name),
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

/// Keeps formatted prose quiet across every direct and one-hop sink shape the rule inspects.
#[test]
pub(crate) fn sql_dynamic_query_requires_sql_shapes_across_supported_sinks() {
    let _guard = analysis_lock();
    let body = r#"/// Probe.
pub fn formatted_prose(source: &str, topic: &str) {
    let _direct_query = backend.query(&format!("Show the report from {source}"));
    let _direct_execute = backend.execute(&format!("Update where the export came from: {source}"));
    let _direct_prepare = backend.prepare(&format!("Create a summary for {topic}"));
    let query_text = format!("From the archive, select the note about {topic}");
    let _bound_query = backend.query(&query_text);
    let execute_text = format!("Delete the draft from the list for {topic}");
    let _bound_execute = backend.execute(&execute_text);
    let prepare_text = format!("Grant the reviewer access to {topic}");
    let _bound_prepare = backend.prepare(&prepare_text);
}
"#;

    let report = analyse_sql_fixture(body);
    assert_eq!(
        sql_dynamic_lines(&report),
        Vec::<usize>::new(),
        "plain-English format values must stay quiet; findings={:?}",
        sql_dynamic_findings(&report)
    );
}

/// Pins every SQL statement family retained by the bounded structural matcher.
#[test]
pub(crate) fn sql_dynamic_query_keeps_supported_statement_families() {
    let _guard = analysis_lock();
    let body = r#"/// Probe.
pub fn supported_sql(table: &str, value: &str, user: &str) {
    let _select = db.query(&format!("SELECT id FROM {table} WHERE name = '{value}'"));
    let _insert = db.execute(&format!("INSERT INTO {table} (name) VALUES ('{value}')"));
    let _update = db.execute(&format!("UPDATE {table} SET name = '{value}'"));
    let _delete = db.execute(&format!("DELETE FROM {table} WHERE name = '{value}'"));
    let _cte = db.query(&format!("/* active rows */ WITH active AS (SELECT id FROM {table}) SELECT id FROM active WHERE name = '{value}'"));
    let _alter = db.execute(&format!("ALTER TABLE {table} ADD COLUMN note TEXT DEFAULT '{value}'"));
    let _drop = db.execute(&format!("DROP TABLE {table}"));
    let _create = db.execute(&format!("CREATE TABLE {table} (name TEXT DEFAULT '{value}')"));
    let _show = db.query(&format!("SHOW TABLES LIKE '{value}'"));
    let _truncate = db.execute(&format!("TRUNCATE TABLE {table}"));
    let _merge = db.execute(&format!("MERGE INTO {table} USING staged ON staged.id = {table}.id"));
    let _grant = db.execute(&format!("GRANT SELECT ON {table} TO {user}"));
    let _revoke = db.execute(&format!("REVOKE SELECT ON {table} FROM {user}"));
    let _replace = db.execute(&format!("REPLACE INTO {table} (name) VALUES ('{value}')"));
    let _upsert = db.execute(&format!("UPSERT INTO {table} (name) VALUES ('{value}')"));
    let _vacuum = db.execute(&format!("VACUUM {table}"));
}
"#;

    let report = analyse_sql_fixture(body);
    assert_eq!(
        sql_dynamic_lines(&report),
        (3..=18).collect::<Vec<_>>(),
        "every supported dynamic-SQL family must remain visible; findings={:?}",
        sql_dynamic_findings(&report)
    );
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

/// Analyses one synthetic Rust source as a config-free project from a CLI user's perspective.
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

/// Returns only SQL dynamic-query findings so exact rule contracts remain easy to review.
fn sql_dynamic_findings(report: &AnalysisReport) -> Vec<&Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.sql-dynamic-query")
        .collect()
}

/// Returns SQL finding lines in report order; an empty list means every sample stayed quiet.
fn sql_dynamic_lines(report: &AnalysisReport) -> Vec<usize> {
    sql_dynamic_findings(report)
        .into_iter()
        .filter_map(|finding| finding.line)
        .collect()
}
