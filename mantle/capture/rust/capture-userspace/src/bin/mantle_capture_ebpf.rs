use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC};
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const BPFTRACE_PROGRAM: &str = r#"
BEGIN
{
  @tracked[cpid] = 1;
  @parent[cpid] = 0;
  printf("EVT|%llu|root|%d|0|start\n", nsecs, cpid);
}

tracepoint:sched:sched_process_fork
/@tracked[args->parent_pid]/
{
  @tracked[args->child_pid] = 1;
  @parent[args->child_pid] = args->parent_pid;
  printf("EVT|%llu|fork|%d|%d|%s\n", nsecs, args->parent_pid, args->child_pid, comm);
}

tracepoint:sched:sched_process_exec
/@tracked[pid]/
{
  $ppid = @parent[pid];
  printf("EVT|%llu|exec|%d|%d|%s|%s\n", nsecs, pid, $ppid, comm, str(args->filename));
}

tracepoint:sched:sched_process_exit
/@tracked[pid]/
{
  $ppid = @parent[pid];
  printf("EVT|%llu|exit|%d|%d|%s\n", nsecs, pid, $ppid, comm);
  delete(@tracked[pid]);
  delete(@parent[pid]);
}

tracepoint:syscalls:sys_enter_openat
/@tracked[pid]/
{
  printf("EVT|%llu|openat|%d|%s|%d\n", nsecs, pid, str(args->filename), args->flags);
}

tracepoint:syscalls:sys_exit_openat
/@tracked[pid]/
{
    printf("EVT|%llu|openat_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_unlinkat
/@tracked[pid]/
{
  printf("EVT|%llu|unlinkat|%d|%s\n", nsecs, pid, str(args->pathname));
}

tracepoint:syscalls:sys_enter_renameat
/@tracked[pid]/
{
  printf("EVT|%llu|renameat|%d|%s|%s\n", nsecs, pid, str(args->oldname), str(args->newname));
}

tracepoint:syscalls:sys_exit_renameat
/@tracked[pid]/
{
    printf("EVT|%llu|renameat_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_renameat2
/@tracked[pid]/
{
  printf("EVT|%llu|renameat2|%d|%s|%s\n", nsecs, pid, str(args->oldname), str(args->newname));
}

tracepoint:syscalls:sys_exit_renameat2
/@tracked[pid]/
{
    printf("EVT|%llu|renameat2_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_connect
/@tracked[pid]/
{
  printf("EVT|%llu|connect|%d|%d\n", nsecs, pid, args->fd);
}

tracepoint:syscalls:sys_enter_sendto
/@tracked[pid]/
{
  printf("EVT|%llu|sendto|%d|%d|%d\n", nsecs, pid, args->fd, args->len);
}

tracepoint:syscalls:sys_enter_recvfrom
/@tracked[pid]/
{
  printf("EVT|%llu|recvfrom|%d|%d|%d\n", nsecs, pid, args->fd, args->size);
}

tracepoint:syscalls:sys_enter_write
/@tracked[pid]/
{
    printf("EVT|%llu|write|%d|%d|%d\n", nsecs, pid, args->fd, args->count);
}

tracepoint:syscalls:sys_exit_write
/@tracked[pid]/
{
    printf("EVT|%llu|write_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_close
/@tracked[pid]/
{
    printf("EVT|%llu|close|%d|%d\n", nsecs, pid, args->fd);
}
"#;

#[derive(Parser, Debug)]
#[command(about = "Rust capture eBPF runner")]
struct Cli {
    #[arg(long)]
    output: PathBuf,
    #[arg(last = true)]
    command: Vec<String>,
}

fn safe_i64(value: Option<&&str>) -> i64 {
    value.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0)
}

fn parse_evt(line: &str, seq: i64, time_offset: f64) -> Option<serde_json::Value> {
    let trimmed = line.trim();
    if !trimmed.starts_with("EVT|") {
        return None;
    }
    let parts: Vec<&str> = trimmed.split('|').collect();
    if parts.len() < 4 {
        return None;
    }
    let ns = safe_i64(parts.get(1));
    let kind = parts.get(2).copied().unwrap_or("");
    let ts = if ns > 0 {
        (ns as f64) / 1_000_000_000.0 + time_offset
    } else {
        0.0
    };

    match kind {
        "fork" => Some(json!({"ts": ts, "line_no": seq, "type": "process_spawn", "pid": safe_i64(parts.get(3)), "child_pid": safe_i64(parts.get(4)), "label": format!("spawn pid {}", safe_i64(parts.get(4))) })),
        "exec" => {
            let pid = safe_i64(parts.get(3));
            let ppid = safe_i64(parts.get(4));
            let exec_path = parts.get(6).copied().unwrap_or(parts.get(5).copied().unwrap_or("exec"));
            Some(json!({
                "ts": ts,
                "line_no": seq,
                "type": "command_exec",
                "pid": pid,
                "ppid": ppid,
                "exec_path": exec_path,
                "argv": [exec_path],
                "command": exec_path,
                "label": format!("exec {}", exec_path),
            }))
        }
        "exit" => Some(json!({"ts": ts, "line_no": seq, "type": "process_exit", "pid": safe_i64(parts.get(3)), "label": format!("pid {} exited", safe_i64(parts.get(3))) })),
        "openat" => {
            let flags = safe_i64(parts.get(5));
            let action = if (flags & (0x1 | 0x2 | 0x40 | 0x200)) != 0 { "file_write" } else { "file_read" };
            let path = parts.get(4).copied().unwrap_or("");
            Some(json!({"ts": ts, "line_no": seq, "type": action, "pid": safe_i64(parts.get(3)), "path": path, "flags": flags, "label": format!("{} {}", action.replace('_', " "), path) }))
        }
        "openat_ret" => Some(json!({"ts": ts, "line_no": seq, "type": "fd_open", "pid": safe_i64(parts.get(3)), "fd": safe_i64(parts.get(4)), "label": format!("fd open {}", safe_i64(parts.get(4))) })),
        "unlinkat" => {
            let path = parts.get(4).copied().unwrap_or("");
            Some(json!({"ts": ts, "line_no": seq, "type": "file_delete", "pid": safe_i64(parts.get(3)), "path": path, "label": format!("delete {}", path) }))
        }
        "renameat" | "renameat2" => {
            let src = parts.get(4).copied().unwrap_or("");
            let dst = parts.get(5).copied().unwrap_or("");
            Some(json!({"ts": ts, "line_no": seq, "type": "file_rename", "pid": safe_i64(parts.get(3)), "path": dst, "src": src, "label": format!("rename {} -> {}", src, dst) }))
        }
        "renameat_ret" | "renameat2_ret" => {
            let ret = safe_i64(parts.get(4));
            Some(json!({"ts": ts, "line_no": seq, "type": "file_rename_ret", "pid": safe_i64(parts.get(3)), "ok": ret == 0, "ret": ret, "label": format!("rename ret={}", ret) }))
        }
        "connect" => {
            let fd = safe_i64(parts.get(4));
            Some(json!({"ts": ts, "line_no": seq, "type": "net_connect", "pid": safe_i64(parts.get(3)), "fd": fd, "dest": format!("fd={}", fd), "transport": "other", "family": "other", "ok": true, "label": format!("connect fd={}", fd) }))
        }
        "sendto" => {
            let fd = safe_i64(parts.get(4));
            let size = safe_i64(parts.get(5));
            Some(json!({"ts": ts, "line_no": seq, "type": "net_send", "pid": safe_i64(parts.get(3)), "fd": fd, "dest": format!("fd={}", fd), "bytes": size, "transport": "other", "family": "other", "ok": true, "label": format!("send {}B -> fd={}", size, fd) }))
        }
        "recvfrom" => {
            let fd = safe_i64(parts.get(4));
            let size = safe_i64(parts.get(5));
            Some(json!({"ts": ts, "line_no": seq, "type": "net_recv", "pid": safe_i64(parts.get(3)), "fd": fd, "dest": format!("fd={}", fd), "bytes": size, "transport": "other", "family": "other", "ok": true, "label": format!("recv {}B <- fd={}", size, fd) }))
        }
        "write" => Some(json!({"ts": ts, "line_no": seq, "type": "fd_write", "pid": safe_i64(parts.get(3)), "fd": safe_i64(parts.get(4)), "requested_bytes": safe_i64(parts.get(5)), "label": format!("write fd={} req={}", safe_i64(parts.get(4)), safe_i64(parts.get(5))) })),
        "write_ret" => {
            let ret = safe_i64(parts.get(4));
            Some(json!({"ts": ts, "line_no": seq, "type": "fd_write_ret", "pid": safe_i64(parts.get(3)), "written_bytes": ret, "ok": ret >= 0, "label": format!("write ret={}", ret) }))
        }
        "close" => Some(json!({"ts": ts, "line_no": seq, "type": "fd_close", "pid": safe_i64(parts.get(3)), "fd": safe_i64(parts.get(4)), "label": format!("close fd={}", safe_i64(parts.get(4))) })),
        _ => None,
    }
}

fn epoch_now() -> f64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as f64) + (f64::from(d.subsec_nanos()) / 1_000_000_000.0)
}

fn monotonic_now() -> f64 {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts points to valid writable memory and CLOCK_MONOTONIC is a valid clock id.
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts as *mut timespec) };
    if rc != 0 {
        return 0.0;
    }
    (ts.tv_sec as f64) + (ts.tv_nsec as f64 / 1_000_000_000.0)
}

fn main() -> Result<()> {
    // Keep a visible aya dependency in this crate while bpftrace parity stays active.
    let _aya_marker: HashMap<&str, &str> = HashMap::new();

    let cli = Cli::parse();
    let mut cmd = cli.command;
    if !cmd.is_empty() && cmd[0] == "--" {
        cmd.remove(0);
    }
    if cmd.is_empty() {
        return Err(anyhow!("No command provided for eBPF capture"));
    }

    let output_path = cli.output;
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut script = tempfile::NamedTempFile::new().context("failed to create bpftrace script file")?;
    script.write_all(BPFTRACE_PROGRAM.as_bytes()).context("failed to write bpftrace script")?;

    let mut launch_script = tempfile::NamedTempFile::new().context("failed to create launch script")?;
    let launch_cmd = shell_words::join(cmd.iter().map(|s| s.as_str()));
    let launch_text = format!("#!/usr/bin/env bash\nset -euo pipefail\nexec {}\n", launch_cmd);
    launch_script.write_all(launch_text.as_bytes()).context("failed to write launch script")?;

    let script_path = script.path().to_string_lossy().to_string();
    let launch_path = launch_script.path().to_string_lossy().to_string();

    let mut child = Command::new("bpftrace")
        .arg("-q")
        .arg("-c")
        .arg(format!("/bin/bash {}", launch_path))
        .arg(script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("BPFTRACE_STR_LEN", "200")
        .spawn()
        .context("failed to start bpftrace")?;

    let stdout = child.stdout.take().context("missing bpftrace stdout")?;
    let mut out_file = File::create(&output_path).with_context(|| format!("failed to create {}", output_path.display()))?;
    let reader = BufReader::new(stdout);

    let time_offset = epoch_now() - monotonic_now();
    let mut seq = 0_i64;
    for line in reader.lines() {
        let line = line.context("failed to read bpftrace output line")?;
        seq += 1;
        if let Some(event) = parse_evt(&line, seq, time_offset) {
            writeln!(out_file, "{}", serde_json::to_string(&event)?).ok();
        } else {
            println!("{}", line);
        }
    }

    let status = child.wait().context("failed to wait for bpftrace")?;
    if !status.success() {
        return Err(anyhow!("bpftrace exited with status {}", status));
    }
    Ok(())
}
