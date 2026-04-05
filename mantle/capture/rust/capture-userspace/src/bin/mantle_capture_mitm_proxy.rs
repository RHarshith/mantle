use anyhow::{Context, Result};
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use clap::Parser;
use futures_util::TryStreamExt;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(about = "Rust MITM capture reverse proxy")]
struct Cli {
    #[arg(long, default_value_t = 8898)]
    listen_port: u16,
    #[arg(long)]
    capture_file: String,
    #[arg(long, default_value = "https://api.openai.com")]
    upstream_base: String,
}

#[derive(Clone)]
struct AppState {
    listen_port: u16,
    upstream_base: String,
    client: reqwest::Client,
    capture_file: Arc<Mutex<std::fs::File>>,
}

#[derive(Debug)]
struct TcpEntry {
    local_port: u16,
    remote_port: u16,
    inode: u64,
}

fn safe_i32(v: &str) -> i32 {
    v.parse::<i32>().unwrap_or(0)
}

fn parse_json_or_raw(raw: &str) -> Value {
    if raw.is_empty() {
        return json!({});
    }
    serde_json::from_str::<Value>(raw).unwrap_or_else(|_| json!({ "_raw": raw }))
}

fn now_ts() -> f64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as f64) + (f64::from(d.subsec_nanos()) / 1_000_000_000.0)
}

fn read_agent_root_pid() -> Option<i32> {
    if let Ok(raw) = std::env::var("MANTLE_AGENT_ROOT_PID") {
        let pid = safe_i32(raw.trim());
        if pid > 0 {
            return Some(pid);
        }
    }
    if let Ok(path) = std::env::var("MANTLE_AGENT_ROOT_PID_FILE") {
        if let Ok(raw) = fs::read_to_string(path) {
            let pid = safe_i32(raw.trim());
            if pid > 0 {
                return Some(pid);
            }
        }
    }
    None
}

fn parent_pid(pid: i32) -> i32 {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat = match fs::read_to_string(stat_path) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let end = match stat.rfind(')') {
        Some(v) => v,
        None => return 0,
    };
    let tail = &stat[(end + 2)..];
    let parts: Vec<&str> = tail.split_whitespace().collect();
    if parts.len() < 2 {
        return 0;
    }
    safe_i32(parts[1])
}

fn is_descendant_or_same(pid: i32, root_pid: i32) -> bool {
    let mut cur = pid;
    let mut seen: HashSet<i32> = HashSet::new();
    while cur > 0 && !seen.contains(&cur) {
        if cur == root_pid {
            return true;
        }
        seen.insert(cur);
        cur = parent_pid(cur);
    }
    false
}

fn read_tcp_entries() -> Vec<TcpEntry> {
    let mut out = Vec::new();
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let text = match fs::read_to_string(file) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let local = cols[1];
            let remote = cols[2];
            let inode = cols[9].parse::<u64>().unwrap_or(0);
            if inode == 0 {
                continue;
            }
            let local_port = local
                .split(':')
                .nth(1)
                .and_then(|h| u16::from_str_radix(h, 16).ok())
                .unwrap_or(0);
            let remote_port = remote
                .split(':')
                .nth(1)
                .and_then(|h| u16::from_str_radix(h, 16).ok())
                .unwrap_or(0);
            if local_port == 0 {
                continue;
            }
            out.push(TcpEntry {
                local_port,
                remote_port,
                inode,
            });
        }
    }
    out
}

fn pid_for_inode(inode: u64) -> Option<i32> {
    let needle = format!("socket:[{}]", inode);
    let proc = Path::new("/proc");
    for dir in fs::read_dir(proc).ok()? {
        let entry = match dir {
            Ok(v) => v,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid = safe_i32(&name);
        if pid <= 0 {
            continue;
        }
        let fd_dir = entry.path().join("fd");
        let iter = match fs::read_dir(fd_dir) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for fd in iter {
            let fd = match fd {
                Ok(v) => v,
                Err(_) => continue,
            };
            let link = match fs::read_link(fd.path()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if link.to_string_lossy() == needle {
                return Some(pid);
            }
        }
    }
    None
}

fn pid_for_ports(src_port: u16, dst_port: u16) -> Option<i32> {
    let entries = read_tcp_entries();
    let mut inode = None;
    for e in entries {
        if e.local_port != src_port {
            continue;
        }
        if e.remote_port != dst_port {
            continue;
        }
        inode = Some(e.inode);
        break;
    }
    pid_for_inode(inode?)
}

fn copy_headers(src: &HeaderMap, dest: &mut reqwest::header::HeaderMap) {
    for (k, v) in src {
        if k.as_str().eq_ignore_ascii_case("host") || k.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        dest.append(k, v.clone());
    }
}

fn copy_resp_headers(src: &reqwest::header::HeaderMap, dest: &mut HeaderMap) {
    for (k, v) in src {
        if k.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        dest.append(k, v.clone());
    }
}

async fn write_record(state: &AppState, record: &Value) -> Result<()> {
    let mut fh = state.capture_file.lock().await;
    fh.write_all(serde_json::to_string(record)?.as_bytes())?;
    fh.write_all(b"\n")?;
    fh.flush()?;
    Ok(())
}

async fn handle(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let path_q = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let url = format!("{}{}", state.upstream_base, path_q);
    let req_headers = req.headers().clone();

    let req_body = match to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("failed to read request body: {}", e)).into_response();
        }
    };
    let req_text = String::from_utf8_lossy(&req_body).to_string();

    let req_pid = pid_for_ports(addr.port(), state.listen_port);
    let root_pid = read_agent_root_pid();
    let should_capture = match (root_pid, req_pid) {
        (Some(root), Some(pid)) => is_descendant_or_same(pid, root),
        (Some(_), None) => false,
        (None, _) => true,
    };

    let req_body_json = parse_json_or_raw(&req_text);
    let req_record = json!({
        "ts": now_ts(),
        "direction": "request",
        "url": url,
        "method": method.as_str(),
        "pid": req_pid,
        "model": req_body_json.get("model").and_then(|v| v.as_str()).unwrap_or(""),
        "request_body": req_body_json,
    });

    let mut out_headers = reqwest::header::HeaderMap::new();
    copy_headers(&req_headers, &mut out_headers);

    let start = Instant::now();
    let upstream_resp = state
        .client
        .request(method.clone(), &url)
        .headers(out_headers)
        .body(req_body.clone())
        .send()
        .await;

    let upstream_resp = match upstream_resp {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, format!("upstream request failed: {}", e)).into_response();
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let is_event_stream = resp_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("text/event-stream"))
        .unwrap_or(false);

    if is_event_stream {
        let duration_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or(0);
        if should_capture {
            let model = req_record
                .get("request_body")
                .and_then(|v| v.get("model"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let resp_record = json!({
                "ts": now_ts(),
                "direction": "response",
                "url": url,
                "method": method.as_str(),
                "pid": req_pid,
                "status_code": status.as_u16(),
                "model": model,
                "duration_ms": duration_ms,
                "request_body": req_record.get("request_body").cloned().unwrap_or_else(|| json!({})),
                "response_body": {
                    "_streamed": true,
                    "_note": "event-stream passthrough; body not buffered"
                },
            });

            if let Err(e) = write_record(&state, &req_record).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write request record: {}", e)).into_response();
            }
            if let Err(e) = write_record(&state, &resp_record).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write response record: {}", e)).into_response();
            }
        }

        let stream = upstream_resp.bytes_stream().map_err(std::io::Error::other);
        let mut resp = Response::builder().status(status);
        let headers = resp.headers_mut().expect("response headers available");
        copy_resp_headers(&resp_headers, headers);
        return resp
            .body(Body::from_stream(stream))
            .expect("valid streaming response body");
    }

    let resp_body = match upstream_resp.bytes().await {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, format!("failed to read upstream response body: {}", e)).into_response();
        }
    };
    let duration_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or(0);
    let resp_text = String::from_utf8_lossy(&resp_body).to_string();
    let resp_body_json = parse_json_or_raw(&resp_text);

    if should_capture {
        let model = resp_body_json
            .get("model")
            .and_then(|v| v.as_str())
            .or_else(|| req_record.get("request_body").and_then(|v| v.get("model")).and_then(|v| v.as_str()))
            .unwrap_or("");

        let resp_record = json!({
            "ts": now_ts(),
            "direction": "response",
            "url": url,
            "method": method.as_str(),
            "pid": req_pid,
            "status_code": status.as_u16(),
            "model": model,
            "duration_ms": duration_ms,
            "request_body": req_record.get("request_body").cloned().unwrap_or_else(|| json!({})),
            "response_body": resp_body_json,
        });

        if let Err(e) = write_record(&state, &req_record).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write request record: {}", e)).into_response();
        }
        if let Err(e) = write_record(&state, &resp_record).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write response record: {}", e)).into_response();
        }
    }

    let mut resp = Response::builder().status(status);
    let headers = resp.headers_mut().expect("response headers available");
    copy_resp_headers(&resp_headers, headers);
    resp.body(Body::from(resp_body)).expect("valid response body")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(parent) = Path::new(&cli.capture_file).parent() {
        fs::create_dir_all(parent).with_context(|| format!("failed to create capture parent dir: {}", parent.display()))?;
    }

    let fh = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cli.capture_file)
        .with_context(|| format!("failed to open capture file: {}", cli.capture_file))?;

    let state = AppState {
        listen_port: cli.listen_port,
        upstream_base: cli.upstream_base,
        client: reqwest::Client::builder().build().context("failed to build reqwest client")?,
        capture_file: Arc::new(Mutex::new(fh)),
    };

    let app = Router::new().route("/*path", any(handle)).with_state(state);
    let listen = SocketAddr::from(([127, 0, 0, 1], cli.listen_port));

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {}", listen))?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("mitm proxy server failed")?;

    Ok(())
}
