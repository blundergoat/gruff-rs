use crate::{
    grade, html_escape, AnalysisReport, FileScore, Finding, Pillar, PillarScore, RequestedScope,
    RunDiagnostic, Severity,
};
use std::fmt::Write as _;

const SCHEMA_VERSION: &str = "gruff.analysis.v1";
const DISTRIBUTION_BUCKETS: [DistributionBucket; 5] = [
    DistributionBucket::new("1-5", ""),
    DistributionBucket::new("6-10", ""),
    DistributionBucket::new("11-15", "warn"),
    DistributionBucket::new("16-20", "fail"),
    DistributionBucket::new("21+", "fail"),
];

/// Render the full HTML inspection report for the given analysis result.
pub(crate) fn render(report: &AnalysisReport, scope: &RequestedScope) -> String {
    let view = ReportView::build(report, scope);
    document(&view)
}

struct ReportView<'a> {
    report: &'a AnalysisReport,
    scope: &'a RequestedScope,
    grade_letter: String,
    grade_class: char,
    composite_text: String,
    verdict_summary: String,
    pillar_rows: Vec<PillarRow>,
    offender_rows: Vec<OffenderRow<'a>>,
    distribution: Vec<DistributionBar>,
    distribution_summary: String,
    findings_total: usize,
    pillar_for_mutation_missing: bool,
}

struct PillarRow {
    pillar: Pillar,
    score: f64,
    grade_letter: String,
    grade_class: char,
    findings: usize,
    advisories: usize,
    warnings: usize,
    errors: usize,
}

struct OffenderRow<'a> {
    file: &'a FileScore,
    grade_letter: String,
    grade_class: char,
}

struct DistributionBar {
    label: &'static str,
    count: usize,
    class: &'static str,
}

struct DistributionBucket {
    label: &'static str,
    class: &'static str,
}

impl DistributionBucket {
    const fn new(label: &'static str, class: &'static str) -> Self {
        Self { label, class }
    }
}

impl<'a> ReportView<'a> {
    fn build(report: &'a AnalysisReport, scope: &'a RequestedScope) -> Self {
        let composite = report.score.composite;
        let grade_letter = grade(composite);
        let grade_class = grade_class_letter(&grade_letter);
        let composite_text = format!("{:.2} / 100", composite);
        let summary_line = verdict_summary(&report.findings, &report.summary);

        let pillar_rows = build_pillar_rows(&report.score.pillars, &report.findings);
        let offender_rows = build_offender_rows(&report.score.top_offenders);
        let (distribution, distribution_summary) = build_distribution(&report.findings);

        ReportView {
            report,
            scope,
            grade_letter,
            grade_class,
            composite_text,
            verdict_summary: summary_line,
            pillar_rows,
            offender_rows,
            distribution,
            distribution_summary,
            findings_total: report.findings.len(),
            pillar_for_mutation_missing: true,
        }
    }
}

fn document(view: &ReportView<'_>) -> String {
    let mut out = String::with_capacity(16 * 1024);
    out.push_str("<!DOCTYPE html>\n");
    out.push_str("<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"UTF-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    out.push_str(&format!(
        "<title>gruff-rs inspection report - {}</title>\n",
        html_escape(&view.grade_letter)
    ));
    out.push_str("<style>");
    out.push_str(&css(!view.report.diagnostics.is_empty()));
    out.push_str("</style>\n</head>\n<body>\n");
    out.push_str("<main class=\"paper\">");
    out.push_str("<span class=\"corner-tr\"></span><span class=\"corner-bl\"></span>");
    out.push_str(&masthead(view));
    out.push_str(&diagnostics_section(&view.report.diagnostics));
    out.push_str(&verdict_section(view));
    out.push_str(&pillars_section(view));
    out.push_str(&offenders_section(view));
    out.push_str(&distribution_section(view));
    out.push_str(&findings_section(
        &view.report.findings,
        view.findings_total,
    ));
    out.push_str(&footer_section(view));
    out.push_str("</main>\n</body>\n</html>\n");
    out
}

fn masthead(view: &ReportView<'_>) -> String {
    let paths_label = if view.scope.paths.is_empty() {
        ".".to_string()
    } else {
        view.scope.paths.join(", ")
    };
    let scope_label = view.scope.diff_label.as_deref().unwrap_or("full project");
    let tool_version = format!("gruff {}", view.report.tool.version);

    format!(
        concat!(
            "<header class=\"masthead\">",
            "<div class=\"brand\">",
            "<div class=\"wordmark\">gruff</div>",
            "<div class=\"tagline\">rust code quality · inspection report</div>",
            "</div>",
            "<div class=\"meta\">",
            "{paths_row}{scope_row}{format_row}{fail_row}",
            "<div class=\"inspection-id\">{tool_version}</div>",
            "</div></header>"
        ),
        paths_row = meta_row("paths", &paths_label),
        scope_row = meta_row("scope", scope_label),
        format_row = meta_row("format", &view.report.run.format),
        fail_row = meta_row("fail", &view.report.run.fail_on),
        tool_version = html_escape(&tool_version),
    )
}

fn meta_row(label: &str, value: &str) -> String {
    format!(
        "<div><span class=\"label\">{}</span><span class=\"val\">{}</span></div>",
        html_escape(label),
        html_escape(value)
    )
}

fn diagnostics_section(diagnostics: &[RunDiagnostic]) -> String {
    if diagnostics.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("<section class=\"diagnostics\">");
    out.push_str(
        "<h2 class=\"section-head\">diagnostics <span class=\"aside\">run messages</span></h2>",
    );
    out.push_str("<div class=\"diagnostic-list\">");
    for diagnostic in diagnostics {
        out.push_str(&diagnostic_row(diagnostic));
    }
    out.push_str("</div></section>");
    out
}

fn diagnostic_row(diagnostic: &RunDiagnostic) -> String {
    let location = match (diagnostic.file_path.as_deref(), diagnostic.line) {
        (Some(file), Some(line)) => Some(format!("{file}:{line}")),
        (Some(file), None) => Some(file.to_string()),
        (None, _) => None,
    };
    let location_html = match location {
        Some(value) => format!(
            "<span class=\"diagnostic-location\">{}</span>",
            html_escape(&value)
        ),
        None => String::new(),
    };
    format!(
        concat!(
            "<div class=\"diagnostic\">",
            "<span class=\"diagnostic-type\">{}</span>",
            "<span class=\"diagnostic-message\">{}</span>",
            "{}",
            "</div>"
        ),
        html_escape(&diagnostic.diagnostic_type),
        html_escape(&diagnostic.message),
        location_html
    )
}

fn verdict_section(view: &ReportView<'_>) -> String {
    let summary = &view.report.summary;
    format!(
        concat!(
            "<section class=\"verdict\">",
            "<div class=\"grade-stamp grade-{class}\">",
            "<div class=\"grade-letter\">{letter}</div>",
            "<div class=\"grade-score\">{score}</div>",
            "</div>",
            "<div class=\"verdict-body\">",
            "<div class=\"verdict-headline\">Inspection complete.<br><em>{summary}</em></div>",
            "<div class=\"verdict-stats\">",
            "{total_stat}{error_stat}{warning_stat}{advisory_stat}",
            "</div></div></section>"
        ),
        class = view.grade_class,
        letter = html_escape(&view.grade_letter),
        score = html_escape(&view.composite_text),
        summary = html_escape(&view.verdict_summary),
        total_stat = stat_block(&summary.total.to_string(), "findings", ""),
        error_stat = stat_block(&summary.error.to_string(), "errors", "fail"),
        warning_stat = stat_block(&summary.warning.to_string(), "warnings", "warn"),
        advisory_stat = stat_block(&summary.advisory.to_string(), "advisories", "note"),
    )
}

fn stat_block(value: &str, label: &str, class: &str) -> String {
    format!(
        "<div class=\"stat\"><div class=\"num {class}\">{value}</div><div class=\"lbl\">{label}</div></div>",
        class = html_escape(class),
        value = html_escape(value),
        label = html_escape(label),
    )
}

fn pillars_section(view: &ReportView<'_>) -> String {
    let mut out = String::new();
    out.push_str("<section class=\"pillars\">");
    out.push_str("<h2 class=\"section-head\">pillar grades <span class=\"aside\">weighted composite</span></h2>");
    out.push_str("<div class=\"pillar-grid\">");
    for row in &view.pillar_rows {
        out.push_str(&pillar_card(row));
    }
    if view.pillar_for_mutation_missing {
        out.push_str(&mutation_placeholder());
    }
    out.push_str("</div></section>");
    out
}

fn pillar_card(row: &PillarRow) -> String {
    format!(
        concat!(
            "<div class=\"pillar\">",
            "<div class=\"name\">{name}</div>",
            "<div class=\"grade grade-{class}\">{letter}</div>",
            "<div class=\"breakdown\">",
            "<div class=\"row\"><span class=\"key\">score</span><span class=\"val\">{score:.2}</span></div>",
            "<div class=\"row\"><span class=\"key\">findings</span><span class=\"val\">{findings}</span></div>",
            "<div class=\"row\"><span class=\"key\">advisories</span><span class=\"val\">{advisories}</span></div>",
            "<div class=\"row\"><span class=\"key\">warnings</span><span class=\"val\">{warnings}</span></div>",
            "<div class=\"row\"><span class=\"key\">errors</span><span class=\"val\">{errors}</span></div>",
            "</div></div>"
        ),
        name = html_escape(pillar_label(row.pillar)),
        class = row.grade_class,
        letter = html_escape(&row.grade_letter),
        score = row.score,
        findings = row.findings,
        advisories = row.advisories,
        warnings = row.warnings,
        errors = row.errors,
    )
}

fn mutation_placeholder() -> String {
    concat!(
        "<div class=\"pillar pillar-empty\">",
        "<div class=\"name\">mutation</div>",
        "<div class=\"grade grade-n\">n/a</div>",
        "<div class=\"breakdown\">",
        "<div class=\"row\"><span class=\"key\">score</span><span class=\"val\">not scored</span></div>",
        "<div class=\"row empty-note\">Mutation data unavailable. Wire <code>cargo-mutants</code> ingest to score this pillar.</div>",
        "</div></div>",
    )
    .to_string()
}

fn offenders_section(view: &ReportView<'_>) -> String {
    let mut out = String::new();
    out.push_str("<section class=\"offenders\">");
    out.push_str("<h2 class=\"section-head\">top offenders <span class=\"aside\">sorted by score</span></h2>");
    out.push_str(concat!(
        "<table class=\"offender-list\"><thead><tr>",
        "<th scope=\"col\">file</th>",
        "<th scope=\"col\" class=\"num\">cyclo</th>",
        "<th scope=\"col\" class=\"num\">cognit.</th>",
        "<th scope=\"col\" class=\"num\">LOC</th>",
        "<th scope=\"col\" class=\"num\">findings</th>",
        "<th scope=\"col\" class=\"num\">grade</th>",
        "</tr></thead><tbody>"
    ));
    if view.offender_rows.is_empty() {
        out.push_str("<tr><td colspan=\"6\">No offenders found.</td></tr>");
    } else {
        for row in &view.offender_rows {
            out.push_str(&offender_row(row));
        }
    }
    out.push_str("</tbody></table></section>");
    out
}

fn offender_row(row: &OffenderRow<'_>) -> String {
    format!(
        concat!(
            "<tr>",
            "<td class=\"file-path\">{file}</td>",
            "<td class=\"num\">n/a</td>",
            "<td class=\"num\">n/a</td>",
            "<td class=\"num\">n/a</td>",
            "<td class=\"num\">{findings}</td>",
            "<td class=\"num\"><span class=\"grade-pill grade-{class}\">{letter}</span></td>",
            "</tr>"
        ),
        file = html_escape(&row.file.file_path),
        findings = row.file.findings,
        class = row.grade_class,
        letter = html_escape(&row.grade_letter),
    )
}

fn distribution_section(view: &ReportView<'_>) -> String {
    let max = distribution_max(&view.distribution);
    let mut bars = String::new();
    let mut axis = String::new();
    for bucket_bar in &view.distribution {
        push_distribution_bar(&mut bars, &mut axis, bucket_bar, max);
    }

    format!(
        concat!(
            "<section class=\"chart-section\">",
            "<h2 class=\"section-head\">distribution <span class=\"aside\">cyclomatic complexity</span></h2>",
            "<p class=\"chart-summary\">{summary}</p>",
            "<div class=\"chart-card\"><div class=\"title\">cyclomatic complexity · flagged methods</div>",
            "<div class=\"histogram\">{bars}</div>",
            "<div class=\"histogram-axis\">{axis}</div>",
            "</div></section>"
        ),
        summary = html_escape(&view.distribution_summary),
        bars = bars,
        axis = axis,
    )
}

fn distribution_max(distribution: &[DistributionBar]) -> usize {
    distribution
        .iter()
        .map(|bucket_bar| bucket_bar.count)
        .max()
        .unwrap_or(0)
        .max(1)
}

fn push_distribution_bar(
    bars: &mut String,
    axis: &mut String,
    bucket_bar: &DistributionBar,
    max: usize,
) {
    let height = distribution_bar_height(bucket_bar.count, max);
    let _ = write!(
        bars,
        "<div class=\"bar {}\" style=\"height:{}%;\"><span class=\"count\">{}</span></div>",
        html_escape(bucket_bar.class),
        height,
        bucket_bar.count
    );
    let _ = write!(axis, "<span>{}</span>", html_escape(bucket_bar.label));
}

fn distribution_bar_height(count: usize, max: usize) -> i64 {
    if count == 0 {
        4
    } else {
        ((count as f64 / max as f64) * 100.0).round() as i64
    }
    .max(4)
}

fn findings_section(findings: &[Finding], total: usize) -> String {
    let mut out = String::new();
    out.push_str("<section class=\"findings\">");
    out.push_str(&format!(
        "<h2 class=\"section-head\">flagged findings <span class=\"aside\">{} shown</span></h2>",
        total
    ));
    out.push_str("<div class=\"findings-list\">");
    if findings.is_empty() {
        out.push_str("<div class=\"empty\">No findings.</div>");
    } else {
        for finding in findings {
            out.push_str(&finding_row(finding));
        }
    }
    out.push_str("</div></section>");
    out
}

fn finding_row(finding: &Finding) -> String {
    let severity_class = match finding.severity {
        Severity::Error => "fail",
        Severity::Warning => "warn",
        Severity::Advisory => "note",
    };
    let escaped_path = html_escape(&finding.file_path);
    let location = match finding.line {
        Some(line) => format!("{escaped_path}:{line}"),
        None => escaped_path,
    };

    format!(
        concat!(
            "<div class=\"finding\">",
            "<div class=\"severity {sev_class}\">{sev_label}</div>",
            "<div class=\"finding-body\">",
            "<h3 class=\"rule\">{rule}</h3>",
            "<div class=\"msg\">{msg}</div>",
            "<div class=\"loc\"><code>{loc}</code></div>",
            "</div>",
            "<div class=\"points\"><b>{pillar}</b></div>",
            "</div>"
        ),
        sev_class = html_escape(severity_class),
        sev_label = html_escape(severity_text(finding.severity)),
        rule = html_escape(&finding.rule_id),
        msg = html_escape(&finding.message),
        loc = location,
        pillar = html_escape(pillar_label(finding.pillar)),
    )
}

fn footer_section(view: &ReportView<'_>) -> String {
    format!(
        concat!(
            "<footer class=\"footer\">",
            "<div class=\"left\">gruff-rs · v{version}</div>",
            "<div class=\"center\">strong opinions, opinionated defaults</div>",
            "<div class=\"right\">schema · {schema}</div>",
            "</footer>"
        ),
        version = html_escape(&view.report.tool.version),
        schema = html_escape(SCHEMA_VERSION),
    )
}

fn build_pillar_rows(pillars: &[PillarScore], findings: &[Finding]) -> Vec<PillarRow> {
    pillars
        .iter()
        .map(|pillar| {
            let mut advisories = 0usize;
            let mut warnings = 0usize;
            let mut errors = 0usize;
            for finding in findings.iter().filter(|f| f.pillar == pillar.pillar) {
                match finding.severity {
                    Severity::Advisory => advisories += 1,
                    Severity::Warning => warnings += 1,
                    Severity::Error => errors += 1,
                }
            }
            let letter = grade(pillar.score);
            let class = grade_class_letter(&letter);
            PillarRow {
                pillar: pillar.pillar,
                score: pillar.score,
                grade_letter: letter,
                grade_class: class,
                findings: pillar.findings,
                advisories,
                warnings,
                errors,
            }
        })
        .collect()
}

fn build_offender_rows(offenders: &[FileScore]) -> Vec<OffenderRow<'_>> {
    offenders
        .iter()
        .map(|file| {
            let letter = grade(file.score);
            let class = grade_class_letter(&letter);
            OffenderRow {
                file,
                grade_letter: letter,
                grade_class: class,
            }
        })
        .collect()
}

fn build_distribution(findings: &[Finding]) -> (Vec<DistributionBar>, String) {
    let counts = cyclomatic_distribution_counts(findings);
    let bars = DISTRIBUTION_BUCKETS
        .iter()
        .zip(counts.iter())
        .map(|(bucket, count)| DistributionBar {
            label: bucket.label,
            count: *count,
            class: bucket.class,
        })
        .collect();

    (bars, distribution_summary(&counts))
}

fn cyclomatic_distribution_counts(findings: &[Finding]) -> [usize; 5] {
    let mut counts = [0usize; 5];
    for finding in findings {
        let Some(value) = cyclomatic_value(finding) else {
            continue;
        };
        counts[cyclomatic_bucket_index(value)] += 1;
    }
    counts
}

fn cyclomatic_value(finding: &Finding) -> Option<u64> {
    (finding.rule_id == "complexity.cyclomatic")
        .then(|| {
            finding
                .metadata
                .get("complexity")
                .and_then(|value| value.as_u64())
        })
        .flatten()
}

fn cyclomatic_bucket_index(value: u64) -> usize {
    match value {
        0..=5 => 0,
        6..=10 => 1,
        11..=15 => 2,
        16..=20 => 3,
        _ => 4,
    }
}

fn distribution_summary(counts: &[usize; 5]) -> String {
    let moderate = counts[2];
    let high = counts[3];
    let severe = counts[4];
    let exceeds = moderate + high + severe;
    if exceeds == 0 {
        "No methods exceed cyclomatic complexity 10 in this scan.".to_string()
    } else {
        format!(
            "{exceeds} {noun} {verb} cyclomatic complexity 10 ({moderate} in 11-15, {high} in 16-20, {severe} at 21+).",
            noun = if exceeds == 1 { "method" } else { "methods" },
            verb = if exceeds == 1 { "exceeds" } else { "exceed" },
        )
    }
}

fn verdict_summary(findings: &[Finding], summary: &crate::Summary) -> String {
    let threshold = summary.warning + summary.error;
    if threshold == 0 {
        return "No warning or error findings flagged.".to_string();
    }
    let mut pillars: std::collections::BTreeSet<Pillar> = std::collections::BTreeSet::new();
    for finding in findings {
        if matches!(finding.severity, Severity::Warning | Severity::Error) {
            pillars.insert(finding.pillar);
        }
    }
    format!(
        "{threshold} {finding_noun} at warning or error severity across {count} {pillar_noun}.",
        threshold = threshold,
        finding_noun = if threshold == 1 {
            "finding"
        } else {
            "findings"
        },
        count = pillars.len(),
        pillar_noun = if pillars.len() == 1 {
            "pillar"
        } else {
            "pillars"
        },
    )
}

fn severity_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn pillar_label(pillar: Pillar) -> &'static str {
    match pillar {
        Pillar::Size => "size",
        Pillar::Complexity => "complexity",
        Pillar::DeadCode => "dead-code",
        Pillar::Waste => "waste",
        Pillar::Naming => "naming",
        Pillar::Documentation => "documentation",
        Pillar::Modernisation => "modernisation",
        Pillar::Security => "security",
        Pillar::SensitiveData => "sensitive-data",
        Pillar::TestQuality => "test-quality",
        Pillar::Design => "design",
    }
}

fn grade_class_letter(grade_letter: &str) -> char {
    grade_letter
        .chars()
        .next()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| matches!(c, 'a' | 'b' | 'c' | 'd' | 'f'))
        .unwrap_or('n')
}

fn css(include_diagnostics: bool) -> String {
    let mut out = String::with_capacity(CSS_BASE.len() + 256);
    out.push_str(CSS_BASE);
    if include_diagnostics {
        out.push_str(CSS_DIAGNOSTICS);
    }
    out
}

const CSS_BASE: &str = r#":root{color-scheme:dark;--ink:#0d0c0a;--ink-2:#161412;--ink-3:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--grade-a:#7fa15a;--grade-b:#b8b450;--grade-c:#d08c36;--grade-d:#c2552b;--grade-f:#8b2828;--advisory:#b5ab94;--serif:Georgia,'Iowan Old Style',serif;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}*{box-sizing:border-box;margin:0;padding:0}html{background:var(--ink);scrollbar-gutter:stable}body{font-family:var(--mono);color:var(--paper);background:var(--ink);min-height:100vh;line-height:1.5;font-size:14px;padding:48px 32px}.paper{display:block;max-width:1180px;margin:0 auto 24px;background:var(--ink-2);border:1px solid var(--rule);position:relative;padding:56px 64px 48px;scrollbar-gutter:stable}.corner-tr,.corner-bl,.paper:before,.paper:after{content:'';position:absolute;width:22px;height:22px;border:1px solid var(--forge)}.paper:before{top:12px;left:12px;border-right:0;border-bottom:0}.paper:after{bottom:12px;right:12px;border-left:0;border-top:0}.corner-tr{top:12px;right:12px;border-left:0;border-bottom:0}.corner-bl{bottom:12px;left:12px;border-right:0;border-top:0}.dashboard-banner{font:11px var(--mono);letter-spacing:.12em;color:var(--paper-mute);background:var(--ink-3);border-bottom:1px solid var(--rule);padding:12px 32px;text-transform:uppercase}.dashboard-banner code{font:inherit;color:var(--paper);background:none;padding:0;border:0}.dashboard-banner a{color:var(--forge);text-decoration:none;border-bottom:1px solid var(--rule);padding-bottom:1px}.masthead{display:grid;grid-template-columns:1fr auto;gap:32px;padding-bottom:28px;border-bottom:1px solid var(--rule);align-items:end}.wordmark{font-family:var(--serif);font-weight:900;font-size:96px;line-height:.85;color:var(--paper);font-style:italic}.wordmark:after{content:'\B7rs';color:var(--forge);font-style:normal;font-size:.45em;margin-left:.15em;vertical-align:super}.tagline{margin-top:12px;font-size:11px;letter-spacing:.24em;color:var(--paper-mute);text-transform:uppercase}.meta{text-align:right;font-size:11px;color:var(--paper-dim);line-height:1.9}.label{color:var(--paper-mute);text-transform:uppercase;letter-spacing:.16em;margin-right:8px}.val{color:var(--paper)}.inspection-id{margin-top:10px;color:var(--forge);font-weight:700;font-size:12px;letter-spacing:.1em}.section-head{font-size:11px;letter-spacing:.32em;color:var(--paper-mute);text-transform:uppercase;padding-bottom:16px;margin-bottom:20px;border-bottom:1px solid var(--rule);display:flex;justify-content:space-between;align-items:baseline;font-family:var(--mono);font-weight:500;line-height:1.5}.section-head:before{content:'\A7';margin-right:10px;color:var(--forge);font-family:var(--serif);font-size:14px;font-style:italic}.aside{color:var(--paper-mute);font-size:10px;letter-spacing:.24em}.verdict{display:grid;grid-template-columns:auto 1fr;gap:56px;padding:48px 0;border-bottom:1px solid var(--rule);align-items:center}.grade-stamp{width:220px;height:220px;border:3px solid var(--grade-b);color:var(--grade-b);display:flex;flex-direction:column;align-items:center;justify-content:center;transform:rotate(-4deg)}.grade-stamp.grade-a{border-color:var(--grade-a);color:var(--grade-a)}.grade-stamp.grade-b{border-color:var(--grade-b);color:var(--grade-b)}.grade-stamp.grade-c{border-color:var(--grade-c);color:var(--grade-c)}.grade-stamp.grade-d{border-color:var(--grade-d);color:var(--grade-d)}.grade-stamp.grade-f{border-color:var(--grade-f);color:var(--grade-f)}.grade-stamp.grade-n{border-color:var(--paper-mute);color:var(--paper-mute)}.grade-letter{font-family:var(--serif);font-style:italic;font-weight:900;font-size:112px;line-height:1}.grade-score{font-size:13px;letter-spacing:.1em}.verdict-body{display:flex;flex-direction:column;gap:18px}.verdict-headline{font-family:var(--serif);font-style:italic;font-weight:600;font-size:38px;line-height:1.15}.verdict-headline em{color:var(--forge)}.verdict-stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--rule);padding-top:20px}.stat{border-right:1px solid var(--rule);padding:0 18px}.stat:first-child{padding-left:0}.stat:last-child{border-right:0}.verdict-stats .num{font-family:var(--serif);font-weight:800;font-size:32px;line-height:1;color:var(--paper)}.verdict-stats .num.warn{color:var(--grade-c)}.verdict-stats .num.fail{color:var(--grade-f)}.verdict-stats .num.note{color:var(--advisory)}.lbl{font-size:10px;text-transform:uppercase;letter-spacing:.2em;color:var(--paper-mute);margin-top:8px}.pillars,.offenders,.chart-section{padding:48px 0;border-bottom:1px solid var(--rule)}.pillar-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--rule);border:1px solid var(--rule)}.pillar{background:var(--ink-2);padding:24px 20px;display:flex;flex-direction:column;gap:14px}.pillar .name{font-size:10px;text-transform:uppercase;letter-spacing:.24em;color:var(--paper-mute)}.pillar .grade{font-family:var(--serif);font-weight:800;font-style:italic;font-size:52px;line-height:.9}.grade.grade-a,.grade-pill.grade-a{color:var(--grade-a)}.grade.grade-b,.grade-pill.grade-b{color:var(--grade-b)}.grade.grade-c,.grade-pill.grade-c{color:var(--grade-c)}.grade.grade-d,.grade-pill.grade-d{color:var(--grade-d)}.grade.grade-f,.grade-pill.grade-f{color:var(--grade-f)}.grade.grade-n,.grade-pill.grade-n{color:var(--paper-mute)}.pillar.pillar-empty .grade{font-size:36px}.pillar.pillar-empty .breakdown .empty-note{display:block;color:var(--paper-mute);font-size:11px;line-height:1.5;margin-top:6px}.pillar.pillar-empty code{color:var(--forge);background:var(--ink-3);padding:1px 6px;border:1px solid var(--rule)}.breakdown{font-size:11px;color:var(--paper-dim);line-height:1.7}.row{display:flex;justify-content:space-between;gap:8px}.row.empty-note{display:block}.key{color:var(--paper-mute)}table{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto;font-family:var(--mono)}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--paper-mute);font-weight:500;padding:12px 14px 12px 0;border-bottom:1px solid var(--rule)}th:last-child,td:last-child{padding-right:0}th.num,td.num{text-align:right;padding-left:18px}td{padding:14px 14px 14px 0;border-bottom:1px solid var(--ink-3);color:var(--paper-dim);font-size:13px;font-family:var(--mono);font-weight:500;line-height:1.4}td.num{color:var(--paper);font-variant-numeric:tabular-nums}.file-path{color:var(--paper);font-weight:500}.grade-pill{display:inline-block;font-family:var(--serif);font-style:italic;font-weight:800;font-size:18px;line-height:1;padding:4px 10px;border:1.5px solid currentColor;min-width:36px;text-align:center}.chart-summary{color:var(--paper-dim);font-size:12px;margin:-6px 0 18px}.chart-card{border:1px solid var(--rule);padding:24px;background:var(--ink-3)}.title{font-size:10px;text-transform:uppercase;letter-spacing:.2em;color:var(--paper-mute);margin-bottom:24px}.histogram{display:flex;align-items:flex-end;gap:6px;height:180px;padding-bottom:20px;border-bottom:1px solid var(--rule)}.bar{flex:1;background:var(--forge);position:relative;min-height:4px}.bar.warn{background:var(--grade-c)}.bar.fail{background:var(--grade-f)}.bar .count{position:absolute;top:-22px;left:50%;transform:translateX(-50%);font-size:11px;color:var(--paper-dim)}.histogram-axis{display:flex;gap:6px;margin-top:8px;font-size:10px;color:var(--paper-mute)}.histogram-axis span{flex:1;text-align:center}.findings{padding:48px 0}.findings-list{display:flex;flex-direction:column}.finding{display:grid;grid-template-columns:auto 1fr auto;gap:24px;padding:18px 0;border-bottom:1px solid var(--ink-3);align-items:start}.severity{font-size:9px;text-transform:uppercase;letter-spacing:.24em;padding:4px 10px;border:1px solid currentColor;margin-top:2px;min-width:76px;text-align:center}.severity.fail{color:var(--grade-f)}.severity.warn{color:var(--grade-c)}.severity.note{color:var(--paper-mute)}.rule{font-size:10px;color:var(--forge);text-transform:uppercase;letter-spacing:.16em;margin-bottom:6px;font-family:var(--mono);font-weight:700;line-height:1.5}.msg{font-family:var(--serif);font-weight:500;font-size:17px;color:var(--paper);line-height:1.4}.loc{font-size:11px;color:var(--paper-mute);margin-top:8px}.loc code{color:var(--paper-dim);background:var(--ink-3);padding:1px 6px;border:1px solid var(--rule)}.points{font-size:10px;color:var(--paper-mute);text-align:right;letter-spacing:.1em;min-width:96px;padding-left:12px}.empty{color:var(--paper-dim);font-size:12px}.footer{margin-top:48px;padding-top:24px;border-top:1px solid var(--rule);display:grid;grid-template-columns:1fr auto 1fr;gap:24px;align-items:center;font-size:10px;color:var(--paper-mute);letter-spacing:.12em;text-transform:uppercase}.center{font-family:var(--serif);font-style:italic;font-size:13px;color:var(--paper-dim);text-transform:none;letter-spacing:0}.right{text-align:right}@media(max-width:900px){body{padding:16px}.paper{padding:28px 20px}.wordmark{font-size:64px}.masthead,.verdict{grid-template-columns:1fr}.meta{text-align:left}.grade-stamp{margin:0 auto}.pillar-grid{grid-template-columns:repeat(2,1fr)}.verdict-stats{grid-template-columns:repeat(2,1fr);gap:16px}.stat{border-right:0;padding:0}.verdict-headline{font-size:28px}}@media(max-width:560px){.finding{grid-template-columns:1fr}.points{text-align:left;padding-left:0}}"#;

const CSS_DIAGNOSTICS: &str = ".diagnostics{padding:28px 0 0}.diagnostic-list{display:grid;gap:10px}.diagnostic{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px;color:var(--paper-dim);font-size:12px}.diagnostic-type{text-transform:uppercase;letter-spacing:.14em;color:var(--forge);font-size:10px}.diagnostic-location{grid-column:2;color:var(--paper-mute);font-size:11px}";
