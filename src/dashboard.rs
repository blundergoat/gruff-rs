use super::*;

/// Serve the HTML dashboard on the requested host and port, running scans on request until the process is stopped.
///
/// `args` supplies the `host` and `port` to bind and the `project_root` that bounds and defaults every scan.
/// Its optional `deep_scan_budget` is the default budget override, which a request's `deepScanBudget` query value may replace.
///
/// Returns exit code 2 when the address cannot be bound; otherwise it handles connections one at a time and never stops on its own.
pub(crate) fn run_dashboard(args: DashboardArgs) -> ExitCode {
    let address = format!("{}:{}", args.host, args.port);
    let listener = match TcpListener::bind(&address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("gruff-rs: unable to bind {address}: {error}");
            return ExitCode::from(2);
        }
    };
    println!("gruff-rs dashboard listening at http://{address}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_dashboard_request(stream, &args.project_root, args.deep_scan_budget.as_ref())
            }
            Err(error) => eprintln!("gruff-rs: dashboard connection error: {error}"),
        }
    }

    ExitCode::SUCCESS
}

/// Read one HTTP request from a dashboard connection, route its target, and write the response back on the same connection.
///
/// `stream` is the accepted connection; one read of at most 4096 bytes is parsed, and a read error drops it without a response.
/// `default_root` is the dashboard root that bounds scans, and `deep_scan_budget` is the budget override used when a request omits one.
fn handle_dashboard_request(
    mut stream: TcpStream,
    default_root: &Path,
    deep_scan_budget: Option<&DeepScanBudgetOverride>,
) {
    let mut buffer = [0u8; 4096];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(bytes_read) => bytes_read,
        Err(_) => return,
    };
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default();
    let target = request_line.split_whitespace().nth(1).unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let response = dashboard_response_with_budget(path, query, default_root, deep_scan_budget);
    respond(
        &mut stream,
        response.status,
        response.content_type,
        &response.body,
    );
}

pub(crate) struct DashboardResponse {
    pub(crate) status: &'static str,
    pub(crate) content_type: &'static str,
    pub(crate) body: String,
}

#[cfg(test)]
pub(crate) fn dashboard_response(
    path: &str,
    query: &str,
    default_root: &Path,
) -> DashboardResponse {
    dashboard_response_with_budget(path, query, default_root, None)
}

/// Route one dashboard request path to the health check, scan, start page, or not-found response.
///
/// `path` is the request path without its query, and `query` is the raw query string, used only by `/scan`.
/// `default_root` is the dashboard root that bounds scans and pre-fills the start page form.
/// `deep_scan_budget` is the default budget override, also pre-filled in the start page form.
///
/// Returns `200 OK` HTML for `/`, plain `ok` for `/health`, the scan result for `/scan`, and a plain-text `404 Not Found` for any other path.
fn dashboard_response_with_budget(
    path: &str,
    query: &str,
    default_root: &Path,
    deep_scan_budget: Option<&DeepScanBudgetOverride>,
) -> DashboardResponse {
    match path {
        "/health" => health_response(),
        "/scan" => scan_response(query, default_root, deep_scan_budget),
        "/" => DashboardResponse {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            body: dashboard_index(default_root, deep_scan_budget),
        },
        _ => not_found_response(),
    }
}

/// Build the dashboard's `/health` liveness response.
///
/// Returns a `200 OK` plain-text response whose body is `ok`.
fn health_response() -> DashboardResponse {
    DashboardResponse {
        status: "200 OK",
        content_type: "text/plain; charset=utf-8",
        body: "ok".to_string(),
    }
}

/// Build the plain-text response for a dashboard path that has no handler.
///
/// Returns a `404 Not Found` plain-text response whose body is `not found`.
fn not_found_response() -> DashboardResponse {
    DashboardResponse {
        status: "404 Not Found",
        content_type: "text/plain; charset=utf-8",
        body: "not found".to_string(),
    }
}

/// Run one analysis requested through the dashboard's `/scan` form and render it as the HTML report.
///
/// `query` is the raw query string carrying the optional `projectRoot`, `path`, and `deepScanBudget` values.
/// `default_root` is the dashboard root a scan must stay inside, and `default_budget` is the budget override used when `deepScanBudget` is absent.
///
/// Returns `400 Bad Request` with the plain-text reason when the target or budget is invalid.
/// Otherwise it returns `200 OK` HTML holding the dashboard report, or the escaped config or analysis error inside a `pre` element.
fn scan_response(
    query: &str,
    default_root: &Path,
    default_budget: Option<&DeepScanBudgetOverride>,
) -> DashboardResponse {
    let params = parse_query(query);
    let (root, scan_path) = match dashboard_scan_target(&params, default_root) {
        Ok(target) => target,
        Err(message) => {
            return DashboardResponse {
                status: "400 Bad Request",
                content_type: "text/plain; charset=utf-8",
                body: message,
            };
        }
    };
    let deep_scan_budget = match dashboard_budget_override(&params, default_budget) {
        Ok(value) => value,
        Err(message) => {
            return DashboardResponse {
                status: "400 Bad Request",
                content_type: "text/plain; charset=utf-8",
                body: message,
            };
        }
    };
    let options = dashboard_scan_options(scan_path);
    let scope = RequestedScope::from_options(&options);
    let body = load_config(&root, &options)
        .and_then(|mut config| {
            config.apply_deep_scan_budget_override(deep_scan_budget.as_ref());
            run_analysis_in_project(&root, &options, &config)
        })
        .map(|report| dashboard_shell(&report, &scope, &root))
        .unwrap_or_else(|error| format!("<pre>{}</pre>", html_escape(&error)));
    DashboardResponse {
        status: "200 OK",
        content_type: "text/html; charset=utf-8",
        body,
    }
}

/// Choose the deep-scan budget override for one dashboard scan from its query values.
///
/// `params` holds the decoded query values, and `default` is the server's override used when `deepScanBudget` is absent.
///
/// Returns `Ok(None)` for a blank value, dropping the default; the parsed override for any other value; or a clone of `default` when absent.
/// A value that does not parse returns `Err` with the parse error message.
fn dashboard_budget_override(
    params: &HashMap<String, String>,
    default: Option<&DeepScanBudgetOverride>,
) -> Result<Option<DeepScanBudgetOverride>, String> {
    match params.get("deepScanBudget") {
        Some(value) if value.trim().is_empty() => Ok(None),
        Some(value) => value.parse().map(Some),
        None => Ok(default.cloned()),
    }
}

/// Resolve the project root and scan path a dashboard request asks for, keeping both inside the dashboard root.
///
/// `params` holds the decoded `projectRoot` and `path` query values, and `default_root` is the dashboard root, canonicalized here before use.
///
/// Returns the canonical project root and the relative scan path, or `Err` with a user-facing message when either is invalid or out of bounds.
fn dashboard_scan_target(
    params: &HashMap<String, String>,
    default_root: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    let default_root = default_root
        .canonicalize()
        .map_err(|_| "invalid projectRoot".to_string())?;
    let root = resolve_dashboard_root(params, &default_root)?;
    let scan_path = resolve_dashboard_scan_path(params, &root)?;
    Ok((root, scan_path))
}

/// Resolve the requested `projectRoot` and reject any directory outside the dashboard root.
///
/// `params` may hold a `projectRoot` value, either absolute or relative to `default_root`.
/// `default_root` is the canonical dashboard root, used as the project root when no `projectRoot` is given.
///
/// Returns the canonical root when it is a directory inside `default_root`.
/// An unresolvable path returns `Err` with `invalid projectRoot`; one outside the root or not a directory returns a containment error.
fn resolve_dashboard_root(
    params: &HashMap<String, String>,
    default_root: &Path,
) -> Result<PathBuf, String> {
    let requested = params
        .get("projectRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_root.to_path_buf());
    let candidate = if requested.is_absolute() {
        requested
    } else {
        default_root.join(requested)
    };
    let root = candidate
        .canonicalize()
        .map_err(|_| "invalid projectRoot".to_string())?;
    if !root.starts_with(default_root) || !root.is_dir() {
        return Err("projectRoot must stay inside the dashboard root".to_string());
    }
    Ok(root)
}

/// Validate the requested scan `path` so it names an existing location inside the project root.
///
/// `params` may hold a `path` value, defaulting to `.`, and `root` is the canonical project root it must resolve inside.
///
/// Returns the requested path as given, still relative, or `Err` when it is absolute, contains `..`, does not exist, or resolves outside `root`.
fn resolve_dashboard_scan_path(
    params: &HashMap<String, String>,
    root: &Path,
) -> Result<PathBuf, String> {
    let scan_path = params
        .get("path")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if scan_path.is_absolute() {
        return Err("path must be relative to projectRoot".to_string());
    }
    if scan_path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("path must not contain '..'".to_string());
    }
    let canonical_scan = root
        .join(&scan_path)
        .canonicalize()
        .map_err(|_| "path does not exist within projectRoot".to_string())?;
    if !canonical_scan.starts_with(root) {
        return Err("path must stay inside projectRoot".to_string());
    }
    Ok(scan_path)
}

/// Build dashboard scan options with HTML output, no fail threshold, and no explicit config, baseline, diff, or history file.
///
/// `scan_path` is the validated path, relative to the project root, that the scan covers.
///
/// Returns options whose `paths` holds only `scan_path`, with default execution and display selectors.
fn dashboard_scan_options(scan_path: PathBuf) -> AnalysisOptions {
    AnalysisOptions {
        paths: vec![scan_path],
        config: None,
        no_config: false,
        format: OutputFormat::Html,
        fail_on: FailThreshold::None,
        include_ignored: false,
        diff: None,
        history_file: None,
        baseline: None,
        generate_baseline: None,
        migrate_baseline: None,
        force_baseline_overwrite: false,
        no_baseline: false,
        execution: ExecutionSelectors::default(),
        display: DisplaySelectors::default(),
    }
}

/// Render the dashboard start page with a form that submits a scan to `/scan`.
///
/// `root` pre-fills the `projectRoot` field, and `deep_scan_budget` pre-fills the budget field in its CLI form, or leaves it empty when `None`.
///
/// Returns the complete HTML page with both values HTML-escaped.
fn dashboard_index(root: &Path, deep_scan_budget: Option<&DeepScanBudgetOverride>) -> String {
    let budget_value = deep_scan_budget
        .map(DeepScanBudgetOverride::as_cli_value)
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gruff-rs dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; background: #f7f8fa; color: #172026; }}
    header {{ background: #172026; color: white; padding: 20px 24px; }}
    main {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
    form {{ display: grid; gap: 12px; background: white; border: 1px solid #d9e0e7; border-radius: 8px; padding: 16px; }}
    input, button {{ font: inherit; padding: 10px; }}
    button {{ background: #146c5f; color: white; border: 0; border-radius: 6px; cursor: pointer; }}
  </style>
</head>
<body>
  <header><h1>gruff-rs dashboard</h1></header>
  <main>
    <form action="/scan" method="get">
      <label>Project root <input name="projectRoot" value="{root}"></label>
      <label>Path <input name="path" value="."></label>
      <label>Deep scan budget <input name="deepScanBudget" value="{budget}" placeholder="20000:2000000 or off"></label>
      <button type="submit">Run scan</button>
    </form>
  </main>
</body>
</html>"#,
        root = html_escape(&root.display().to_string()),
        budget = html_escape(&budget_value)
    )
}

/// Render a dashboard scan as the standard HTML report with a banner naming the project and linking back to the start page.
///
/// `report` holds the analysis results and `scope` the requested paths and diff label, both rendered by `html_report::render`.
/// `root` is the project root shown, HTML-escaped, in the banner.
///
/// Returns the report HTML with the banner inserted just after the first `<body>` tag, or prepended when the report has no `<body>` tag.
fn dashboard_shell(report: &AnalysisReport, scope: &RequestedScope, root: &Path) -> String {
    let report_html = html_report::render(report, scope);
    let banner = format!(
        r#"<div class="dashboard-banner" role="region" aria-label="Dashboard scan"><strong>Dashboard scan</strong> · Project: <code>{}</code> · <a href="/">Change target</a></div>"#,
        html_escape(&root.display().to_string())
    );
    if let Some(position) = report_html.find("<body>") {
        let insert_at = position + "<body>".len();
        let mut output = String::with_capacity(report_html.len() + banner.len());
        output.push_str(&report_html[..insert_at]);
        output.push_str(&banner);
        output.push_str(&report_html[insert_at..]);
        output
    } else {
        format!("{banner}{report_html}")
    }
}

/// Write one complete HTTP/1.1 response that closes the connection and forbids caching.
///
/// `stream` receives the whole response, and a write error is silently ignored.
/// `status` is the status text, such as `200 OK`, and `content_type` is the `Content-Type` header value.
/// `body` is sent as given, with its byte length as `Content-Length`.
fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Split a URL query string into the decoded parameters a dashboard request supplies.
///
/// `query` is the raw text after `?`, split on `&` into `key=value` pairs.
///
/// Returns the percent-decoded pairs, dropping any pair without `=`; when a key repeats, the last value wins.
fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

/// Decode URL percent escapes and plus signs in one query key or value.
///
/// `value` is the raw text; `%` followed by two hex digits becomes that byte, and `+` becomes a space.
///
/// Returns the decoded text, keeping malformed escapes as written and replacing invalid UTF-8 with U+FFFD.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Some(hex) = percent_hex(bytes[index + 1], bytes[index + 2]) {
                output.push(hex);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).to_string()
}

/// Combine the two hex digits of one percent escape into a byte.
///
/// `high` and `low` are the ASCII digits after `%`, most significant first.
///
/// Returns the byte value, or `None` when either is not a hex digit.
fn percent_hex(high: u8, low: u8) -> Option<u8> {
    Some(hex_nibble(high)? * 16 + hex_nibble(low)?)
}

/// Convert one ASCII hex digit to its numeric value.
///
/// `byte` is a character from a percent escape; upper- and lower-case letters are both accepted.
///
/// Returns the value 0 to 15, or `None` for any other byte.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
