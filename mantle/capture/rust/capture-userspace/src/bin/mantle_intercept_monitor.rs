use anyhow::{anyhow, Context, Result};
use clap::Parser;
use glob::Pattern;
use nix::cmsg_space;
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

static SIGCHLD_PIPE_WR: AtomicI32 = AtomicI32::new(-1);

extern "C" fn sigchld_handler(_sig: libc::c_int) {
    let fd = SIGCHLD_PIPE_WR.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe {
            let _ = libc::write(fd, [0u8].as_ptr() as *const libc::c_void, 1);
        }
    }
}

fn setup_sigchld_pipe() -> Result<RawFd> {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if rc < 0 {
        return Err(anyhow!(
            "pipe2 for SIGCHLD self-pipe failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    SIGCHLD_PIPE_WR.store(fds[1], Ordering::Relaxed);

    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = sigchld_handler as *const () as usize;
    sa.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    let rc = unsafe { libc::sigaction(libc::SIGCHLD, &sa, ptr::null_mut()) };
    if rc < 0 {
        return Err(anyhow!(
            "sigaction(SIGCHLD) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fds[0])
}

#[derive(Parser, Debug)]
#[command(about = "Seccomp-notify runtime interception monitor")]
struct Cli {
    #[arg(long, default_value = ".mantle/intercept.yaml")]
    policy_file: PathBuf,
    #[arg(long)]
    events_file: Option<PathBuf>,
    #[arg(long)]
    trace_id: Option<String>,
    #[arg(long)]
    ask_decisions_file: Option<PathBuf>,
    #[arg(long)]
    ask_current_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    ask_timeout_ms: u64,
    #[arg(last = true)]
    command: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Action {
    Allow,
    Deny,
    Notify,
    Ask,
}

#[derive(Debug, Deserialize)]
struct Defaults {
    unmatched: Action,
}

#[derive(Debug, Deserialize)]
struct FilesystemRule {
    path: String,
    #[serde(default)]
    ops: Vec<String>,
    action: Action,
}

#[derive(Debug, Deserialize)]
struct ProcessRule {
    command: String,
    action: Action,
}

#[derive(Debug, Deserialize)]
struct NetworkRule {
    destination: String,
    action: Action,
}

#[derive(Debug, Deserialize)]
struct Policy {
    defaults: Defaults,
    #[serde(default)]
    filesystem: Vec<FilesystemRule>,
    #[serde(default)]
    process: Vec<ProcessRule>,
    #[serde(default)]
    network: Vec<NetworkRule>,
}

struct JsonlEmitter {
    trace_id: String,
    session_id: String,
    seq: u64,
    file: File,
}

impl JsonlEmitter {
    fn new(trace_id: String, out: &Path) -> Result<Self> {
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create events dir: {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .with_context(|| format!("failed to open events file: {}", out.display()))?;
        Ok(Self {
            trace_id,
            session_id: Uuid::new_v4().to_string(),
            seq: 0,
            file,
        })
    }

    fn emit(&mut self, event_type: &str, payload: serde_json::Value) -> Result<()> {
        self.seq += 1;
        let record = json!({
            "ts": now_ts(),
            "monotonic_ns": monotonic_ns(),
            "trace_id": self.trace_id,
            "session_id": self.session_id,
            "seq": self.seq,
            "event_type": event_type,
            "payload": payload,
        });
        self.file.write_all(serde_json::to_string(&record)?.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        Ok(())
    }
}

#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const seccompiler::sock_filter,
}

const IOC_NRBITS: u64 = 8;
const IOC_TYPEBITS: u64 = 8;
const IOC_SIZEBITS: u64 = 14;
const IOC_NRSHIFT: u64 = 0;
const IOC_TYPESHIFT: u64 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u64 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u64 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;

#[cfg(target_arch = "x86_64")]
const EXTRA_MONITORED_SYSCALLS: &[i64] = &[
    libc::SYS_open,
    libc::SYS_unlink,
    libc::SYS_rename,
    libc::SYS_mkdir,
    libc::SYS_rmdir,
];
#[cfg(not(target_arch = "x86_64"))]
const EXTRA_MONITORED_SYSCALLS: &[i64] = &[];

fn ioc(dir: u64, ty: u64, nr: u64, size: u64) -> u64 {
    (dir << IOC_DIRSHIFT) | (ty << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

fn iowr(ty: u64, nr: u64, size: u64) -> u64 {
    ioc(IOC_READ | IOC_WRITE, ty, nr, size)
}

fn seccomp_ioctl_notif_recv(fd: RawFd, req: &mut libc::seccomp_notif) -> Result<()> {
    let request = iowr(b'!' as u64, 0, std::mem::size_of::<libc::seccomp_notif>() as u64);
    let rc = unsafe { libc::ioctl(fd, request as libc::c_ulong, req as *mut libc::seccomp_notif) };
    if rc < 0 {
        return Err(anyhow!(
            "SECCOMP_IOCTL_NOTIF_RECV failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn seccomp_ioctl_notif_send(fd: RawFd, resp: &mut libc::seccomp_notif_resp) -> Result<()> {
    let request = iowr(
        b'!' as u64,
        1,
        std::mem::size_of::<libc::seccomp_notif_resp>() as u64,
    );
    let rc = unsafe {
        libc::ioctl(
            fd,
            request as libc::c_ulong,
            resp as *mut libc::seccomp_notif_resp,
        )
    };
    if rc < 0 {
        return Err(anyhow!(
            "SECCOMP_IOCTL_NOTIF_SEND failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn now_ts() -> f64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as f64) + (f64::from(d.subsec_nanos()) / 1_000_000_000.0)
}

fn monotonic_ns() -> u128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts as *mut libc::timespec) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u128) * 1_000_000_000u128 + (ts.tv_nsec as u128)
}

fn patch_to_user_notif(mut bpf: BpfProgram) -> BpfProgram {
    for ins in &mut bpf {
        if ins.k == libc::SECCOMP_RET_TRACE {
            ins.k = libc::SECCOMP_RET_USER_NOTIF;
        }
    }
    bpf
}

fn monitored_filter() -> Result<BpfProgram> {
    let mut syscalls: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    let monitored = [
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_openat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_connect,
    ];
    for nr in monitored {
        syscalls.insert(nr, vec![]);
    }
    for nr in EXTRA_MONITORED_SYSCALLS {
        syscalls.insert(*nr, vec![]);
    }

    let filter = SeccompFilter::new(
        syscalls,
        SeccompAction::Allow,
        SeccompAction::Trace(0),
        seccompiler::TargetArch::try_from(std::env::consts::ARCH)
            .map_err(|e| anyhow!("unsupported arch for seccomp: {e}"))?,
    )?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow!("failed to compile seccomp filter: {e}"))?;
    Ok(patch_to_user_notif(bpf))
}

fn install_user_notif_filter(bpf_filter: &BpfProgram) -> Result<RawFd> {
    if bpf_filter.is_empty() {
        return Err(anyhow!("cannot install empty seccomp filter"));
    }
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(anyhow!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let prog = SockFprog {
        len: bpf_filter.len() as u16,
        filter: bpf_filter.as_ptr(),
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const SockFprog,
        )
    };

    if fd < 0 {
        return Err(anyhow!(
            "seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd as RawFd)
}

fn send_listener_fd(sock: &UnixStream, fd: RawFd) -> Result<()> {
    let buf = [0u8; 1];
    let iov = [std::io::IoSlice::new(&buf)];
    let cmsgs = [ControlMessage::ScmRights(&[fd])];
    sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)?;
    Ok(())
}

fn recv_listener_fd(sock: &UnixStream) -> Result<RawFd> {
    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut cmsgspace = cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgspace),
        MsgFlags::empty(),
    )?;

    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(fd) = fds.first() {
                return Ok(*fd);
            }
        }
    }
    Err(anyhow!("did not receive seccomp listener fd"))
}

fn read_remote(pid: i32, addr: u64, max_len: usize) -> Option<Vec<u8>> {
    if addr == 0 || max_len == 0 {
        return None;
    }
    let mut out = vec![0u8; max_len];
    let mut local = libc::iovec {
        iov_base: out.as_mut_ptr() as *mut libc::c_void,
        iov_len: out.len(),
    };
    let mut remote = libc::iovec {
        iov_base: addr as usize as *mut libc::c_void,
        iov_len: out.len(),
    };

    let nread = unsafe { libc::process_vm_readv(pid, &mut local, 1, &mut remote, 1, 0) };
    if nread <= 0 {
        return None;
    }
    out.truncate(nread as usize);
    Some(out)
}

fn read_cstring_remote(pid: i32, addr: u64) -> Option<String> {
    let bytes = read_remote(pid, addr, 4096)?;
    let nul_pos = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let raw = &bytes[..nul_pos];
    if raw.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(raw).to_string())
}

fn parse_connect_destination(pid: i32, sockaddr_ptr: u64, sockaddr_len: usize) -> Option<String> {
    let buf = read_remote(pid, sockaddr_ptr, sockaddr_len.max(16).min(128))?;
    if buf.len() < 2 {
        return None;
    }

    let family = u16::from_ne_bytes([buf[0], buf[1]]) as i32;
    if family == libc::AF_INET {
        if buf.len() < 8 {
            return None;
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        return Some(format!("{}:{}", ip, port));
    }

    if family == libc::AF_INET6 {
        if buf.len() < 28 {
            return None;
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&buf[8..24]);
        let ip = std::net::Ipv6Addr::from(octets);
        return Some(format!("[{}]:{}", ip, port));
    }

    None
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    Pattern::new(pattern)
        .map(|p| p.matches(value))
        .unwrap_or_else(|_| pattern == value)
}

fn eval_filesystem(policy: &Policy, op: &str, path: &str) -> Action {
    for rule in &policy.filesystem {
        if !rule.ops.iter().any(|x| x == op) {
            continue;
        }
        if wildcard_match(&rule.path, path) {
            return rule.action;
        }
    }
    policy.defaults.unmatched
}

fn eval_process(policy: &Policy, command: &str) -> Action {
    let base = Path::new(command)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or(command);
    for rule in &policy.process {
        if wildcard_match(&rule.command, base) || wildcard_match(&rule.command, command) {
            return rule.action;
        }
    }
    policy.defaults.unmatched
}

fn eval_network(policy: &Policy, destination: &str) -> Action {
    for rule in &policy.network {
        if wildcard_match(&rule.destination, destination) {
            return rule.action;
        }
    }
    policy.defaults.unmatched
}

#[cfg(target_arch = "x86_64")]
fn is_sys_open(nr: i64) -> bool {
    nr == libc::SYS_open
}
#[cfg(not(target_arch = "x86_64"))]
fn is_sys_open(_nr: i64) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn is_sys_unlink(nr: i64) -> bool {
    nr == libc::SYS_unlink
}
#[cfg(not(target_arch = "x86_64"))]
fn is_sys_unlink(_nr: i64) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn is_sys_rename(nr: i64) -> bool {
    nr == libc::SYS_rename
}
#[cfg(not(target_arch = "x86_64"))]
fn is_sys_rename(_nr: i64) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn is_sys_mkdir(nr: i64) -> bool {
    nr == libc::SYS_mkdir
}
#[cfg(not(target_arch = "x86_64"))]
fn is_sys_mkdir(_nr: i64) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn is_sys_rmdir(nr: i64) -> bool {
    nr == libc::SYS_rmdir
}
#[cfg(not(target_arch = "x86_64"))]
fn is_sys_rmdir(_nr: i64) -> bool {
    false
}

fn policy_decision(policy: &Policy, req: &libc::seccomp_notif) -> (Action, serde_json::Value) {
    let pid = req.pid as i32;
    let nr = req.data.nr as i64;
    let args = req.data.args;

    match nr {
        x if x == libc::SYS_execve => {
            let cmd = read_cstring_remote(pid, args[0]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_process(policy, &cmd);
            (action, json!({"category":"process","syscall":"execve","command":cmd}))
        }
        x if x == libc::SYS_execveat => {
            let cmd = read_cstring_remote(pid, args[1]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_process(policy, &cmd);
            (
                action,
                json!({"category":"process","syscall":"execveat","command":cmd}),
            )
        }
        x if is_sys_open(x) => {
            let path = read_cstring_remote(pid, args[0]).unwrap_or_else(|| "<unknown>".to_string());
            let flags = args[1] as i32;
            let write_like = (flags & libc::O_WRONLY != 0) || (flags & libc::O_RDWR != 0);
            let action = if write_like {
                eval_filesystem(policy, "write", &path)
            } else {
                policy.defaults.unmatched
            };
            (
                action,
                json!({"category":"filesystem","syscall":"open","path":path,"flags":flags,"op":"write"}),
            )
        }
        x if x == libc::SYS_openat => {
            let path = read_cstring_remote(pid, args[1]).unwrap_or_else(|| "<unknown>".to_string());
            let flags = args[2] as i32;
            let write_like = (flags & libc::O_WRONLY != 0) || (flags & libc::O_RDWR != 0);
            let action = if write_like {
                eval_filesystem(policy, "write", &path)
            } else {
                policy.defaults.unmatched
            };
            (
                action,
                json!({"category":"filesystem","syscall":"openat","path":path,"flags":flags,"op":"write"}),
            )
        }
        x if is_sys_unlink(x) => {
            let path = read_cstring_remote(pid, args[0]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_filesystem(policy, "delete", &path);
            (
                action,
                json!({"category":"filesystem","syscall":"unlink","path":path,"op":"delete"}),
            )
        }
        x if x == libc::SYS_unlinkat => {
            let path = read_cstring_remote(pid, args[1]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_filesystem(policy, "delete", &path);
            (
                action,
                json!({"category":"filesystem","syscall":"unlinkat","path":path,"op":"delete"}),
            )
        }
        x if is_sys_rename(x) => {
            let src = read_cstring_remote(pid, args[0]).unwrap_or_else(|| "<unknown>".to_string());
            let dst = read_cstring_remote(pid, args[1]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_filesystem(policy, "write", &dst);
            (
                action,
                json!({"category":"filesystem","syscall":"rename","src":src,"path":dst,"op":"write"}),
            )
        }
        x if x == libc::SYS_renameat => {
            let src = read_cstring_remote(pid, args[1]).unwrap_or_else(|| "<unknown>".to_string());
            let dst = read_cstring_remote(pid, args[3]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_filesystem(policy, "write", &dst);
            (
                action,
                json!({"category":"filesystem","syscall":"renameat","src":src,"path":dst,"op":"write"}),
            )
        }
        x if is_sys_mkdir(x) => {
            let path = read_cstring_remote(pid, args[0]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_filesystem(policy, "write", &path);
            (
                action,
                json!({"category":"filesystem","syscall":"mkdir","path":path,"op":"write"}),
            )
        }
        x if is_sys_rmdir(x) => {
            let path = read_cstring_remote(pid, args[0]).unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_filesystem(policy, "delete", &path);
            (
                action,
                json!({"category":"filesystem","syscall":"rmdir","path":path,"op":"delete"}),
            )
        }
        x if x == libc::SYS_connect => {
            let dest = parse_connect_destination(pid, args[1], args[2] as usize)
                .unwrap_or_else(|| "<unknown>".to_string());
            let action = eval_network(policy, &dest);
            (
                action,
                json!({"category":"network","syscall":"connect","destination":dest}),
            )
        }
        _ => (
            policy.defaults.unmatched,
            json!({"category":"unknown","syscall_nr":nr}),
        ),
    }
}

fn normalize_trace_id_for_match(trace_id: &str) -> &str {
    trace_id.strip_suffix(".ebpf.jsonl").unwrap_or(trace_id)
}

fn trace_ids_match(left: &str, right: &str) -> bool {
    normalize_trace_id_for_match(left) == normalize_trace_id_for_match(right)
}

fn parse_action_text(value: Option<&str>) -> Option<Action> {
    match value {
        Some("allow") => Some(Action::Allow),
        Some("deny") => Some(Action::Deny),
        Some("notify") => Some(Action::Notify),
        Some("ask") => Some(Action::Ask),
        _ => None,
    }
}

fn row_id_as_u64(v: &serde_json::Value) -> Option<u64> {
    v.get("id")
        .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse::<u64>().ok())))
}

fn read_ask_decision(decisions_path: &Path, trace_id: &str, req_id: u64) -> Result<Option<Action>> {
    if !decisions_path.exists() {
        return Ok(None);
    }
    let file = File::open(decisions_path)?;
    let reader = BufReader::new(file);

    let mut matched_for_trace: Option<Action> = None;
    let mut matched_without_trace: Option<Action> = None;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|_| json!({}));
        if row_id_as_u64(&v) != Some(req_id) {
            continue;
        }
        let decision = parse_action_text(v.get("decision").and_then(|x| x.as_str()));
        if decision.is_none() {
            continue;
        }
        let row_trace_id = v.get("trace_id").and_then(|x| x.as_str());
        if row_trace_id.is_some_and(|row| trace_ids_match(row, trace_id)) {
            matched_for_trace = decision;
        } else if row_trace_id.is_none() {
            matched_without_trace = decision;
        }
    }

    Ok(matched_for_trace.or(matched_without_trace))
}

fn read_current_trace_decision(current_dir: &Path, trace_id: &str, req_id: u64) -> Option<Action> {
    let candidates = [
        current_dir.join(format!("{}.json", trace_id)),
        current_dir.join(format!("{}.json", normalize_trace_id_for_match(trace_id))),
        current_dir.join(format!(
            "{}.ebpf.jsonl.json",
            normalize_trace_id_for_match(trace_id)
        )),
    ];
    for path in candidates {
        if !path.exists() {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(_) => continue,
        };

        if row_id_as_u64(&v) != Some(req_id) {
            continue;
        }
        let row_trace_id = v.get("trace_id").and_then(|x| x.as_str());
        if !row_trace_id.is_some_and(|row| trace_ids_match(row, trace_id)) {
            continue;
        }
        if let Some(action) = parse_action_text(v.get("decision").and_then(|x| x.as_str())) {
            return Some(action);
        }
    }
    None
}

fn send_seccomp_response(listener_fd: RawFd, req_id: u64, action: Action) -> Result<()> {
    let mut resp = libc::seccomp_notif_resp {
        id: req_id,
        val: 0,
        error: 0,
        flags: 0,
    };

    match action {
        Action::Allow | Action::Notify => {
            resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
        }
        Action::Deny => {
            resp.error = libc::EACCES;
        }
        Action::Ask => {
            resp.error = libc::EACCES;
        }
    }

    seccomp_ioctl_notif_send(listener_fd, &mut resp)?;
    Ok(())
}

fn child_exec(cmd: &[String], sock: &UnixStream) -> ! {
    let bpf = monitored_filter().expect("failed to build monitored filter");
    let listener_fd = install_user_notif_filter(&bpf).expect("failed to install seccomp user notify filter");
    send_listener_fd(sock, listener_fd).expect("failed to send listener fd");

    let c_cmd: Vec<CString> = cmd
        .iter()
        .map(|s| CString::new(s.as_str()).expect("invalid command arg"))
        .collect();
    let argv: Vec<*const libc::c_char> = c_cmd
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();

    unsafe {
        libc::execvp(c_cmd[0].as_ptr(), argv.as_ptr());
        libc::_exit(127);
    }
}

fn drain_pipe(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

fn monitor_loop(
    listener_fd: RawFd,
    child_pid: libc::pid_t,
    sigchld_pipe_rd: RawFd,
    trace_id: &str,
    policy: &Policy,
    emitter: &mut JsonlEmitter,
    ask_decisions_file: &Path,
    ask_current_dir: &Path,
    ask_timeout: Duration,
) -> Result<i32> {
    loop {
        let mut pollfds = [
            libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sigchld_pipe_rd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let poll_rc =
            unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 500) };
        if poll_rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow!("poll on seccomp listener failed: {err}"));
        }

        let mut status = 0;
        let wait = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
        if wait == child_pid {
            drain_pipe(sigchld_pipe_rd);
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
            return Ok(1);
        }
        if wait < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(anyhow!("waitpid(WNOHANG) failed: {err}"));
            }
        }

        if pollfds[1].revents & libc::POLLIN != 0 {
            drain_pipe(sigchld_pipe_rd);
            continue;
        }

        if pollfds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break;
        }

        if poll_rc == 0 || pollfds[0].revents & libc::POLLIN == 0 {
            continue;
        }

        let mut req: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        let recv_res = seccomp_ioctl_notif_recv(listener_fd, &mut req);
        if let Err(err) = recv_res {
            let err_str = err.to_string();
            if err_str.contains("Interrupted system call")
                || err_str.contains("No such file or directory")
                || err_str.contains("Bad file descriptor")
                || err_str.contains("Resource temporarily unavailable")
            {
                continue;
            }
            break;
        }

        let (mut action, details) = policy_decision(policy, &req);
        let payload = json!({
            "pid": req.pid,
            "request_id": req.id,
            "action": format!("{:?}", action).to_lowercase(),
            "details": details,
        });

        match action {
            Action::Allow => {
                send_seccomp_response(listener_fd, req.id, Action::Allow)?;
            }
            Action::Notify => {
                let _ = emitter.emit("intercept_observation", payload);
                send_seccomp_response(listener_fd, req.id, Action::Notify)?;
            }
            Action::Deny => {
                let _ = emitter.emit("intercept_violation", payload);
                send_seccomp_response(listener_fd, req.id, Action::Deny)?;
            }
            Action::Ask => {
                let _ = emitter.emit("intercept_ask", payload);
                let start = std::time::Instant::now();
                loop {
                    if let Some(decision) = read_current_trace_decision(ask_current_dir, trace_id, req.id) {
                        action = decision;
                        break;
                    }
                    if let Some(decision) = read_ask_decision(ask_decisions_file, trace_id, req.id)? {
                        action = decision;
                        break;
                    }
                    if ask_timeout.as_millis() > 0 && start.elapsed() >= ask_timeout {
                        action = Action::Deny;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }

                if action == Action::Notify {
                    let _ = emitter.emit(
                        "intercept_ask_resolved",
                        json!({"pid": req.pid, "request_id": req.id, "decision": "notify"}),
                    );
                    let _ = emitter.emit(
                        "intercept_observation",
                        json!({"pid": req.pid, "request_id": req.id, "reason": "ask_decision_notify"}),
                    );
                    send_seccomp_response(listener_fd, req.id, Action::Notify)?;
                } else if action == Action::Allow {
                    let _ = emitter.emit(
                        "intercept_ask_resolved",
                        json!({"pid": req.pid, "request_id": req.id, "decision": "allow"}),
                    );
                    send_seccomp_response(listener_fd, req.id, Action::Allow)?;
                } else {
                    let _ = emitter.emit(
                        "intercept_ask_resolved",
                        json!({"pid": req.pid, "request_id": req.id, "decision": "deny"}),
                    );
                    let _ = emitter.emit(
                        "intercept_violation",
                        json!({"pid": req.pid, "request_id": req.id, "reason": "ask_decision_deny"}),
                    );
                    send_seccomp_response(listener_fd, req.id, Action::Deny)?;
                }
            }
        }
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(child_pid, &mut status, 0) };
    if waited < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ECHILD) {
            return Ok(0);
        }
        return Err(anyhow!("waitpid failed: {err}"));
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(1)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cmd = cli.command;
    if !cmd.is_empty() && cmd[0] == "--" {
        cmd.remove(0);
    }
    if cmd.is_empty() {
        return Err(anyhow!("no command specified for interception monitor"));
    }

    let policy_text = std::fs::read_to_string(&cli.policy_file)
        .with_context(|| format!("failed to read policy file: {}", cli.policy_file.display()))?;
    let policy: Policy = serde_yaml::from_str(&policy_text)
        .with_context(|| format!("failed to parse policy file: {}", cli.policy_file.display()))?;

    let trace_id = cli
        .trace_id
        .or_else(|| std::env::var("AGENT_TRACE_ID").ok())
        .unwrap_or_else(|| format!("trace-{}", std::process::id()));

    let events_file = if let Some(path) = cli.events_file {
        path
    } else {
        let root = std::env::var("AGENT_OBS_ROOT").unwrap_or_else(|_| "obs".to_string());
        Path::new(&root)
            .join("events")
            .join(format!("{}.events.jsonl", trace_id))
    };

    let ask_decisions_file = cli
        .ask_decisions_file
        .unwrap_or_else(|| PathBuf::from(".mantle/intercept.decisions.jsonl"));
    let ask_current_dir = cli
        .ask_current_dir
        .unwrap_or_else(|| PathBuf::from(".mantle/intercept.decision-current"));

    let ask_timeout = Duration::from_millis(cli.ask_timeout_ms);
    let mut emitter = JsonlEmitter::new(trace_id.clone(), &events_file)?;
    let _ = emitter.emit(
        "intercept_monitor_started",
        json!({
            "policy_file": cli.policy_file,
            "events_file": events_file,
            "command": cmd,
        }),
    );

    let sigchld_pipe_rd = setup_sigchld_pipe()?;
    let (sock_parent, sock_child) = UnixStream::pair().context("failed to create unix socket pair")?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow!("fork failed: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        drop(sock_parent);
        child_exec(&cmd, &sock_child);
    }

    drop(sock_child);
    let listener_fd = recv_listener_fd(&sock_parent)?;
    let exit_code = monitor_loop(
        listener_fd,
        pid,
        sigchld_pipe_rd,
        &trace_id,
        &policy,
        &mut emitter,
        &ask_decisions_file,
        &ask_current_dir,
        ask_timeout,
    )?;

    let _ = emitter.emit("intercept_monitor_stopped", json!({"exit_code": exit_code}));
    std::process::exit(exit_code);
}
