//! Render each HTML section of the standalone report shown by `report --format html` and the local browser dashboard.
//!
//! Formats the masthead, diagnostics, suppression audit, verdict, pillar table, top offenders, complexity chart, and findings list.
//! Every finding field and path is HTML-escaped so untrusted repository content cannot inject markup into the viewer's browser.

use super::styles::css;
use super::{severity_text, DistributionBar, OffenderRow, PillarRow, ReportView, SCHEMA_VERSION};
use crate::{
    html_escape, pillar_label, scoring::score_text, Finding, RunDiagnostic, Severity,
    SuppressionSummary,
};
use std::fmt::Write as _;

/// Render the complete standalone HTML inspection report page.
///
/// `view` supplies the grade for the title, whether there are diagnostics for the stylesheet, and the data for every section.
/// Returns the page with inline CSS and, in order, the masthead, diagnostics, verdict, pillars, offenders, distribution, findings and footer.
pub(crate) fn document(view: &ReportView<'_>) -> String {
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
    out.push_str(&css(
        !view.report.diagnostics.is_empty() || !view.report.suppressions.is_empty()
    ));
    out.push_str("</style>\n</head>\n<body>\n");
    out.push_str("<main class=\"paper\">");
    out.push_str("<span class=\"corner-tr\"></span><span class=\"corner-bl\"></span>");
    out.push_str(&masthead(view));
    out.push_str(&diagnostics_section(&view.report.diagnostics));
    out.push_str(&suppressions_section(&view.report.suppressions));
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

/// Render the report header with the gruff wordmark and the run's metadata.
///
/// `view` supplies the scanned paths, shown as `.` when none were given, and the diff label, shown as `full project` when absent.
/// It also supplies the output format, the `fail_on` setting and the tool version.
///
/// Returns the escaped `header` element.
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

/// Render one label and value pair of the masthead metadata.
///
/// `label` and `value` are HTML-escaped into the label and value spans.
/// Returns the row as a `div` element.
fn meta_row(label: &str, value: &str) -> String {
    format!(
        "<div><span class=\"label\">{}</span><span class=\"val\">{}</span></div>",
        html_escape(label),
        html_escape(value)
    )
}

/// Render the run diagnostics section of the report.
///
/// `diagnostics` are the run messages to list, one row each.
/// Returns an empty string when there are no diagnostics, so the section is left out of the page.
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

/// Render the suppression audit section of the report so HTML never filters findings in silence (`FAMILY-CONTRACT.md` section 13a).
///
/// `suppressions` are the suppression summary rows from configured, built-in, and inline channels.
/// Returns an empty string when there are no suppressions, leaving the page unchanged on clean scans.
fn suppressions_section(suppressions: &[SuppressionSummary]) -> String {
    // A clean scan with no suppressions keeps the page unchanged.
    if suppressions.is_empty() {
        return String::new();
    }
    let total: usize = suppressions.iter().map(|row| row.suppressed).sum();
    let mut out = String::new();
    out.push_str("<section class=\"diagnostics\">");
    let _ = write!(
        out,
        "<h2 class=\"section-head\">suppressions <span class=\"aside\">{total} suppressed across {} {}</span></h2>",
        suppressions.len(),
        if suppressions.len() == 1 { "entry" } else { "entries" }
    );
    out.push_str("<div class=\"diagnostic-list\">");
    // One row per suppression entry, with its reason, so a reviewer can check each one.
    for row in suppressions {
        let scope = if row.paths.is_empty() {
            row.rule.clone()
        } else {
            format!("{} ({})", row.rule, row.paths.join(", "))
        };
        let _ = write!(
            out,
            "<div class=\"diagnostic\"><span class=\"diagnostic-type\">{}</span><span class=\"diagnostic-message\">{} suppressed: {}</span><span class=\"diagnostic-location\">{}</span></div>",
            html_escape(row.config_key),
            row.suppressed,
            html_escape(&row.reason),
            html_escape(&scope)
        );
    }
    out.push_str("</div></section>");
    out
}

/// Render one run diagnostic as a row of type, message and optional location.
///
/// `diagnostic` supplies the type and message, and a location of `file:line`, or the file alone when it has no line.
/// Returns the escaped `div` element; the location span is omitted when the diagnostic has no file path.
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

/// Render the verdict section with the grade stamp, composite score, summary sentence and severity counts.
///
/// `view` supplies the grade class and letter, the composite score text, the verdict summary and the finding totals by severity.
/// Returns the section HTML with one stat block each for total, error, warning and advisory findings.
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
        error_stat = stat_block(&summary.error.to_string(), "error", "fail"),
        warning_stat = stat_block(&summary.warning.to_string(), "warning", "warn"),
        advisory_stat = stat_block(&summary.advisory.to_string(), "advisory", "note"),
    )
}

/// Render one verdict statistic as a number above a caption.
///
/// `value` is the number shown, `label` its caption and `class` the extra CSS class on the number, empty for none; all three are HTML-escaped.
/// Returns the stat `div` element.
fn stat_block(value: &str, label: &str, class: &str) -> String {
    format!(
        "<div class=\"stat\"><div class=\"num {class}\">{value}</div><div class=\"lbl\">{label}</div></div>",
        class = html_escape(class),
        value = html_escape(value),
        label = html_escape(label),
    )
}

/// Render the pillars table with each pillar's grade, score and finding counts by severity.
///
/// `view` supplies the pillar rows.
/// Returns the section HTML; the table holds a single `No pillars.` row when there are no pillar rows.
fn pillars_section(view: &ReportView<'_>) -> String {
    let mut out = String::new();
    out.push_str("<section class=\"pillars\">");
    out.push_str(
        "<h2 class=\"section-head\">pillars <span class=\"aside\">weighted composite</span></h2>",
    );
    out.push_str(concat!(
        "<table class=\"pillar-list\"><thead><tr>",
        "<th scope=\"col\">pillar</th>",
        "<th scope=\"col\" class=\"num\">grade</th>",
        "<th scope=\"col\" class=\"num\">score</th>",
        "<th scope=\"col\" class=\"num\">findings</th>",
        "<th scope=\"col\" class=\"num\">advisory</th>",
        "<th scope=\"col\" class=\"num\">warning</th>",
        "<th scope=\"col\" class=\"num\">error</th>",
        "</tr></thead><tbody>"
    ));
    if view.pillar_rows.is_empty() {
        out.push_str("<tr><td colspan=\"7\">No pillars.</td></tr>");
    } else {
        for row in &view.pillar_rows {
            out.push_str(&pillar_row(row));
        }
    }
    out.push_str("</tbody></table></section>");
    out
}

/// Render one pillar as a table row.
///
/// `row` supplies the pillar label, grade class and letter, score, total findings and the advisory, warning and error counts.
/// Returns the `tr` element; a severity count is highlighted only when it is not zero.
fn pillar_row(row: &PillarRow) -> String {
    format!(
        concat!(
            "<tr>",
            "<td class=\"pillar-name\">{name}</td>",
            "<td class=\"num\"><span class=\"grade-pill {class}\">{letter}</span></td>",
            "<td class=\"num\">{score}</td>",
            "<td class=\"num\">{findings}</td>",
            "{advisory_cell}{warning_cell}{error_cell}",
            "</tr>"
        ),
        name = html_escape(pillar_label(row.pillar)),
        class = row.grade_class,
        letter = html_escape(&row.grade_letter),
        score = score_text(row.score),
        findings = row.findings,
        advisory_cell = severity_count_cell(row.advisories, "note"),
        warning_cell = severity_count_cell(row.warnings, "warn"),
        error_cell = severity_count_cell(row.errors, "fail"),
    )
}

/// Render one severity count cell for the pillars table.
///
/// `count` is the number shown and `tier` the CSS class that highlights it, applied only when `count` is not zero.
/// Returns the `td` element; `tier` is not HTML-escaped, so callers pass fixed class names.
fn severity_count_cell(count: usize, tier: &str) -> String {
    if count == 0 {
        format!("<td class=\"num\">{count}</td>")
    } else {
        format!("<td class=\"num {tier}\">{count}</td>")
    }
}

/// Render the top offenders table of files.
///
/// `view` supplies the offender rows, rendered in the order given.
/// Returns the section HTML; the table holds a single `No offenders found.` row when there are none.
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

/// Render one offending file as a table row.
///
/// `row` supplies the file path, its finding count and its grade class and letter.
/// Returns the `tr` element; the cyclomatic, cognitive and LOC cells always read `n/a`.
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

/// Render the complexity histogram section.
///
/// `view` supplies the metric label, distribution buckets, and summary sentence shown above the chart.
/// Returns the section HTML with one bar and one axis label per bucket, bar heights scaled to the largest bucket.
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
            "<h2 class=\"section-head\">distribution <span class=\"aside\">{label}</span></h2>",
            "<p class=\"chart-summary\">{summary}</p>",
            "<div class=\"chart-card\"><div class=\"title\">{label} · flagged methods</div>",
            "<div class=\"histogram\">{bars}</div>",
            "<div class=\"histogram-axis\">{axis}</div>",
            "</div></section>"
        ),
        label = html_escape(view.distribution_label),
        summary = html_escape(&view.distribution_summary),
        bars = bars,
        axis = axis,
    )
}

/// Find the largest bucket count, used to scale histogram bar heights.
///
/// `distribution` is the list of histogram buckets.
/// Returns that count, never less than 1, so an empty or all-zero distribution is still safe to divide by.
fn distribution_max(distribution: &[DistributionBar]) -> usize {
    distribution
        .iter()
        .map(|bucket_bar| bucket_bar.count)
        .max()
        .unwrap_or(0)
        .max(1)
}

/// Append one histogram bucket's bar and axis label to the chart HTML being built.
///
/// `bars` gains a bar `div` whose height comes from `distribution_bar_height` and that shows the count, and `axis` gains the bucket label.
/// `bucket_bar` supplies the class, count and label, and `max` is the largest bucket count the height is scaled against.
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

/// Compute a histogram bar's height as a percentage of the tallest bar.
///
/// `count` is the bucket's count and `max` the largest count, which `distribution_max` keeps at 1 or more.
/// Returns the rounded percentage, never below 4 so an empty bucket still shows a stub.
fn distribution_bar_height(count: usize, max: usize) -> i64 {
    if count == 0 {
        4
    } else {
        ((count as f64 / max as f64) * 100.0).round() as i64
    }
    .max(4)
}

/// Render the flagged findings list.
///
/// `findings` are rendered one row each in the order given; `total` is printed in the heading as the number of findings shown.
/// Returns the section HTML, with a `No findings.` placeholder when `findings` is empty.
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

/// Render one finding as a list entry.
///
/// `finding` supplies the severity, which picks the label and the `fail`, `warn` or `note` class, and the rule id, message, path, line and pillar.
/// Returns the escaped `div` element; the location is `path:line`, or the path alone when the finding has no line.
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

/// Render the report footer with the tool version and report schema version.
///
/// `view` supplies the tool version; the schema version is the `SCHEMA_VERSION` constant.
/// Returns the `footer` element.
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
