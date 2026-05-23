use super::*;

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
            Ok(stream) => handle_dashboard_request(stream, &args.project_root),
            Err(error) => eprintln!("gruff-rs: dashboard connection error: {error}"),
        }
    }

    ExitCode::SUCCESS
}

fn handle_dashboard_request(mut stream: TcpStream, default_root: &Path) {
    let mut buffer = [0u8; 4096];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(bytes_read) => bytes_read,
        Err(_) => return,
    };
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default();
    let target = request_line.split_whitespace().nth(1).unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let response = dashboard_response(path, query, default_root);
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

pub(crate) fn dashboard_response(
    path: &str,
    query: &str,
    default_root: &Path,
) -> DashboardResponse {
    match path {
        "/health" => health_response(),
        "/scan" => scan_response(query, default_root),
        "/" => DashboardResponse {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            body: dashboard_index(default_root),
        },
        _ => not_found_response(),
    }
}

fn health_response() -> DashboardResponse {
    DashboardResponse {
        status: "200 OK",
        content_type: "text/plain; charset=utf-8",
        body: "ok".to_string(),
    }
}

fn not_found_response() -> DashboardResponse {
    DashboardResponse {
        status: "404 Not Found",
        content_type: "text/plain; charset=utf-8",
        body: "not found".to_string(),
    }
}

fn scan_response(query: &str, default_root: &Path) -> DashboardResponse {
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
    let options = dashboard_scan_options(scan_path);
    let scope = RequestedScope::from_options(&options);
    let body = run_analysis_in_project(&root, &options)
        .map(|report| dashboard_shell(&report, &scope, &root))
        .unwrap_or_else(|error| format!("<pre>{}</pre>", html_escape(&error)));
    DashboardResponse {
        status: "200 OK",
        content_type: "text/html; charset=utf-8",
        body,
    }
}

fn dashboard_scan_target(
    params: &HashMap<String, String>,
    default_root: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    let default_root = default_root
        .canonicalize()
        .map_err(|_| "invalid projectRoot".to_string())?;
    let root = params
        .get("projectRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_root.clone());
    let root = if root.is_absolute() {
        root
    } else {
        default_root.join(root)
    };
    let root = root
        .canonicalize()
        .map_err(|_| "invalid projectRoot".to_string())?;
    if !root.starts_with(&default_root) || !root.is_dir() {
        return Err("projectRoot must stay inside the dashboard root".to_string());
    }

    let scan_path = params
        .get("path")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if scan_path.is_absolute() {
        return Err("path must be relative to projectRoot".to_string());
    }
    if !path_stays_within_root(&root, &scan_path) {
        return Err("path must stay inside projectRoot".to_string());
    }
    Ok((root, scan_path))
}

fn path_stays_within_root(root: &Path, relative_path: &Path) -> bool {
    let candidate = root.join(relative_path);
    if candidate.exists() {
        return candidate
            .canonicalize()
            .ok()
            .is_some_and(|path| path.starts_with(root));
    }
    let mut depth = 0isize;
    for component in relative_path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return false,
        }
    }
    true
}

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
        no_baseline: false,
    }
}

fn dashboard_index(root: &Path) -> String {
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
      <button type="submit">Run scan</button>
    </form>
  </main>
</body>
</html>"#,
        root = html_escape(&root.display().to_string())
    )
}

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

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

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

fn percent_hex(high: u8, low: u8) -> Option<u8> {
    Some(hex_nibble(high)? * 16 + hex_nibble(low)?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
