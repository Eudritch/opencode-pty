use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(test)]
use std::fs::remove_dir_all;
use std::fs::{File, create_dir_all, remove_file, rename};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const READER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
#[cfg(unix)]
const TERMINATION_HARD_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bootstrap {
    command: String,
    args: Vec<String>,
    workdir: String,
    env: std::collections::BTreeMap<String, String>,
    redaction_secrets: Vec<String>,
    session_directory: String,
    worker_control_token: String,
    worker_id: String,
    timeout_seconds: u64,
    max_output_bytes: usize,
    mode: String,
    fault: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    pid: u32,
    start_identity: String,
    process_identity: String,
    endpoint: String,
    token: String,
    protocol_version: u32,
}

#[derive(Deserialize)]
struct Control {
    operation: String,
    token: String,
}

#[cfg(target_os = "linux")]
fn process_identity() -> Result<String, String> {
    let pid = std::process::id();
    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|error| error.to_string())?;
    let fields = stat
        .rsplit_once(')')
        .ok_or("invalid /proc/self/stat")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let start_time = fields.get(19).ok_or("missing /proc/self/stat start time")?;
    Ok(format!("posix:{pid}:{start_time}"))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_identity() -> Result<String, String> {
    // macOS has no /proc start-time identity. Its containment result remains unavailable.
    Ok(format!("posix:{}:unavailable", std::process::id()))
}

#[cfg(windows)]
fn process_identity() -> Result<String, String> {
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn GetProcessTimes(
            process: *mut std::ffi::c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }
    let mut creation = FileTime { low: 0, high: 0 };
    let mut exit = FileTime { low: 0, high: 0 };
    let mut kernel = FileTime { low: 0, high: 0 };
    let mut user = FileTime { low: 0, high: 0 };
    // GetProcessTimes binds the identity to the current process handle, never a PID lookup.
    let result = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let ticks = u64::from(creation.low) | (u64::from(creation.high) << 32);
    Ok(format!("windows:{}:{ticks}", std::process::id()))
}

#[derive(Default)]
struct State {
    stdout: String,
    stderr: String,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdout_truncated: bool,
    stderr_truncated: bool,
    next_sequence: usize,
    first_retained_sequence: usize,
    output_truncated: bool,
    exit_code: Option<i32>,
    exit_signal: Option<String>,
    exit_reason: Option<String>,
    started_at: String,
    exited_at: Option<String>,
    timed_out: bool,
    termination_requested: bool,
    termination_confirmed: bool,
    root_exited: bool,
    storage_failure: Option<String>,
    stdout_eof: bool,
    stderr_eof: bool,
    stdout_reader_error: Option<String>,
    stderr_reader_error: Option<String>,
    reader_drain_deadline: Option<SystemTime>,
    output_incomplete: bool,
    termination: Option<TerminationResult>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContainmentReport {
    platform: String,
    status: String,
    root_pid: u32,
    process_group_id: Option<u32>,
    session_id: Option<u32>,
    root_start_identity: String,
    root_identity_verified: bool,
    observed_group_pids: Vec<u32>,
    observed_session_pids: Vec<u32>,
    observed_escaped_descendant_pids: Vec<u32>,
    observed_escaped_descendants: Vec<ProcessIdentity>,
    verified_at: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessIdentity {
    pid: u32,
    start_identity: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminationResult {
    requested: bool,
    term_signal_sent: bool,
    kill_signal_sent: bool,
    root_exited: bool,
    containment: ContainmentReport,
}

struct Containment {
    root_pid: u32,
    process_group_id: Option<u32>,
    session_id: Option<u32>,
    root_start_identity: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    known_members: Mutex<BTreeMap<u32, String>>,
    // ponytail: retain only identities needed to prevent an observed escape from becoming empty.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    escaped_members: Mutex<BTreeMap<u32, String>>,
}

struct Worker {
    child: Mutex<Child>,
    state: Mutex<State>,
    secrets: Vec<String>,
    output_directory: PathBuf,
    max_output_bytes: usize,
    deadline: SystemTime,
    containment: Containment,
}

struct WorkerError {
    code: &'static str,
    message: String,
}

fn now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days algorithm, anchored at 1970-01-01.
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis()
    )
}

fn private_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn read_frame<R: Read>(input: &mut R) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|error| error.to_string())?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("bootstrap frame exceeds limit".into());
    }
    let mut data = vec![0; length];
    input
        .read_exact(&mut data)
        .map_err(|error| error.to_string())?;
    Ok(data)
}

fn control(input: &mut impl Read, token: &str) -> Result<Control, String> {
    let control: Control =
        serde_json::from_slice(&read_frame(input)?).map_err(|error| error.to_string())?;
    if control.token != token || (control.operation != "start" && control.operation != "rollback") {
        return Err("invalid worker control frame".into());
    }
    Ok(control)
}

fn redact(mut data: String, secrets: &[String]) -> String {
    for secret in secrets {
        if secret.len() >= 4 {
            data = data.replace(secret, "[REDACTED]");
        }
    }
    data
}

fn redact_stream(data: String, tail: &mut String, secrets: &[String], finish: bool) -> String {
    let combined = format!("{tail}{data}");
    let hold = if finish {
        0
    } else {
        secrets
            .iter()
            .map(|secret| secret.chars().count().saturating_sub(1))
            .max()
            .unwrap_or(0)
    };
    let characters: Vec<_> = combined.char_indices().collect();
    let mut split = characters.len().saturating_sub(hold);
    let initial_split = split;
    for secret in secrets {
        let secret: Vec<_> = secret.chars().collect();
        for start in 0..initial_split {
            let prefix = (characters.len() - start).min(secret.len());
            if start + secret.len() > split
                && characters[start..start + prefix]
                    .iter()
                    .map(|(_, character)| *character)
                    .eq(secret[..prefix].iter().copied())
            {
                split = start;
            }
        }
    }
    let byte = characters
        .get(split)
        .map(|(index, _)| *index)
        .unwrap_or(combined.len());
    let safe = combined[..byte].to_string();
    *tail = combined[byte..].to_string();
    let mut redacted = redact(safe, secrets);
    if finish {
        redacted.push_str(&redact(std::mem::take(tail), secrets));
    }
    redacted
}

fn write_atomic(path: &Path, data: &str) -> std::io::Result<()> {
    let temporary = path.with_extension(format!(
        "{}.tmp",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = File::create(&temporary)?;
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    drop(file);
    rename(&temporary, path)?;
    private_file(path)
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    pgid: u32,
    sid: u32,
    start_time: String,
}

#[cfg(target_os = "linux")]
struct ProcessScan {
    processes: Vec<ProcessInfo>,
    unreadable_pids: BTreeSet<u32>,
}

#[cfg(target_os = "linux")]
impl ProcessInfo {
    fn identity(&self) -> String {
        format!("posix:{}:{}", self.pid, self.start_time)
    }
}

#[cfg(target_os = "linux")]
fn linux_processes() -> Result<ProcessScan, String> {
    let mut processes = Vec::new();
    let mut unreadable_pids = BTreeSet::new();
    for entry in std::fs::read_dir("/proc").map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            // This PID existed in the directory scan but vanished or could not be inspected.
            // It may be a containment candidate, so the entire verification is unavailable.
            unreadable_pids.insert(pid);
            continue;
        };
        let Some((_, tail)) = stat.rsplit_once(')') else {
            unreadable_pids.insert(pid);
            continue;
        };
        let fields = tail.split_whitespace().collect::<Vec<_>>();
        let Some(ppid) = fields.get(1).and_then(|value| value.parse().ok()) else {
            unreadable_pids.insert(pid);
            continue;
        };
        let Some(pgid) = fields.get(2).and_then(|value| value.parse().ok()) else {
            unreadable_pids.insert(pid);
            continue;
        };
        let Some(sid) = fields.get(3).and_then(|value| value.parse().ok()) else {
            unreadable_pids.insert(pid);
            continue;
        };
        let Some(start_time) = fields.get(19) else {
            unreadable_pids.insert(pid);
            continue;
        };
        processes.push(ProcessInfo {
            pid,
            ppid,
            pgid,
            sid,
            start_time: (*start_time).into(),
        });
    }
    Ok(ProcessScan {
        processes,
        unreadable_pids,
    })
}

#[cfg(target_os = "linux")]
fn containment_report(containment: &Containment) -> ContainmentReport {
    let scan = match linux_processes() {
        Ok(scan) => scan,
        Err(_) => {
            return ContainmentReport {
                platform: "linux_proc".into(),
                status: "posix_containment_unknown".into(),
                root_pid: containment.root_pid,
                process_group_id: containment.process_group_id,
                session_id: containment.session_id,
                root_start_identity: containment.root_start_identity.clone(),
                root_identity_verified: false,
                observed_group_pids: Vec::new(),
                observed_session_pids: Vec::new(),
                observed_escaped_descendant_pids: Vec::new(),
                observed_escaped_descendants: observed_escapes(containment),
                verified_at: now(),
            };
        }
    };
    containment_report_from_scan(containment, &scan)
}

#[cfg(target_os = "linux")]
fn observed_escapes(containment: &Containment) -> Vec<ProcessIdentity> {
    containment
        .escaped_members
        .lock()
        .expect("escaped members lock")
        .iter()
        .map(|(pid, start_identity)| ProcessIdentity {
            pid: *pid,
            start_identity: start_identity.clone(),
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn containment_report_from_scan(
    containment: &Containment,
    scan: &ProcessScan,
) -> ContainmentReport {
    let processes = &scan.processes;
    let report = |status: &str,
                  root_identity_verified: bool,
                  group: Vec<u32>,
                  session: Vec<u32>,
                  escaped: Vec<u32>| ContainmentReport {
        platform: "linux_proc".into(),
        status: status.into(),
        root_pid: containment.root_pid,
        process_group_id: containment.process_group_id,
        session_id: containment.session_id,
        root_start_identity: containment.root_start_identity.clone(),
        root_identity_verified,
        observed_group_pids: group,
        observed_session_pids: session,
        observed_escaped_descendant_pids: escaped,
        observed_escaped_descendants: observed_escapes(containment),
        verified_at: now(),
    };
    // Every numeric /proc entry is a potential new group or session member until identified.
    if !scan.unreadable_pids.is_empty() {
        return report(
            "posix_containment_unknown",
            false,
            Vec::new(),
            Vec::new(),
            observed_escapes(containment)
                .into_iter()
                .map(|escape| escape.pid)
                .collect(),
        );
    }
    let reused_escape = {
        let mut escapes = containment
            .escaped_members
            .lock()
            .expect("escaped members lock");
        let mut reused = false;
        for (pid, identity) in escapes.clone() {
            match processes.iter().find(|process| process.pid == pid) {
                Some(process) if process.identity() == identity => {}
                Some(_) => {
                    reused = true;
                    break;
                }
                // A complete scan that does not list the PID explicitly resolves this escape.
                None => {
                    escapes.remove(&pid);
                }
            }
        }
        reused
    };
    if reused_escape {
        return report(
            "posix_containment_unknown",
            false,
            Vec::new(),
            Vec::new(),
            observed_escapes(containment)
                .into_iter()
                .map(|escape| escape.pid)
                .collect(),
        );
    }
    let root_pid = processes
        .iter()
        .find(|process| process.pid == containment.root_pid);
    let root = root_pid.filter(|process| process.identity() == containment.root_start_identity);
    if root_pid.is_some() && root.is_none() {
        return report(
            "posix_containment_unknown",
            false,
            Vec::new(),
            Vec::new(),
            observed_escapes(containment)
                .into_iter()
                .map(|escape| escape.pid)
                .collect(),
        );
    }
    let (Some(pgid), Some(sid)) = (containment.process_group_id, containment.session_id) else {
        return report(
            "posix_containment_unknown",
            false,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
    };
    if let Some(root) = root {
        if root.pgid != pgid || root.sid != sid {
            return report(
                "posix_containment_unknown",
                false,
                Vec::new(),
                Vec::new(),
                observed_escapes(containment)
                    .into_iter()
                    .map(|escape| escape.pid)
                    .collect(),
            );
        }
        let group = processes
            .iter()
            .filter(|process| process.pgid == pgid && process.sid == sid)
            .map(|process| process.pid)
            .collect::<Vec<_>>();
        let session = processes
            .iter()
            .filter(|process| process.sid == sid)
            .map(|process| process.pid)
            .collect::<Vec<_>>();
        let mut known = containment
            .known_members
            .lock()
            .expect("containment members lock");
        for process in processes.iter().filter(|process| process.sid == sid) {
            known.insert(process.pid, process.identity());
        }
        drop(known);
        let mut descendants = vec![root.pid];
        let mut index = 0;
        while index < descendants.len() {
            let parent = descendants[index];
            let children = processes
                .iter()
                .filter(|process| process.ppid == parent && !descendants.contains(&process.pid))
                .map(|process| process.pid)
                .collect::<Vec<_>>();
            descendants.extend(children);
            index += 1;
        }
        let escaped = descendants
            .iter()
            .copied()
            .filter(|pid| !group.contains(pid) && !session.contains(pid))
            .collect::<Vec<_>>();
        let mut observed = containment
            .escaped_members
            .lock()
            .expect("escaped members lock");
        for pid in escaped {
            let process = processes
                .iter()
                .find(|process| process.pid == pid)
                .expect("descendant is scanned");
            observed.insert(pid, process.identity());
        }
        let escaped = observed.keys().copied().collect::<Vec<_>>();
        drop(observed);
        return report(
            if !escaped.is_empty() {
                "posix_escape_observed"
            } else {
                "posix_processes_remaining"
            },
            true,
            group,
            session,
            escaped,
        );
    }
    let known = containment
        .known_members
        .lock()
        .expect("containment members lock");
    let candidates = processes
        .iter()
        .filter(|process| process.pgid == pgid || process.sid == sid)
        .collect::<Vec<_>>();
    let verified = candidates
        .iter()
        .filter(|process| known.get(&process.pid) == Some(&process.identity()))
        .map(|process| (*process).clone())
        .collect::<Vec<_>>();
    let unknown_member = candidates.len() != verified.len();
    let group: Vec<u32> = verified
        .iter()
        .filter(|process| process.pgid == pgid)
        .map(|process| process.pid)
        .collect();
    let session: Vec<u32> = verified.iter().map(|process| process.pid).collect();
    drop(known);
    let escaped = observed_escapes(containment)
        .into_iter()
        .map(|escape| escape.pid)
        .collect::<Vec<_>>();
    report(
        if unknown_member {
            "posix_containment_unknown"
        } else if !escaped.is_empty() {
            "posix_escape_observed"
        } else if group.is_empty() && session.is_empty() {
            "posix_best_effort_empty"
        } else {
            "posix_processes_remaining"
        },
        false,
        group,
        session,
        escaped,
    )
}

#[cfg(all(target_os = "linux", test))]
fn containment_report_from_processes(
    containment: &Containment,
    processes: &[ProcessInfo],
) -> ContainmentReport {
    containment_report_from_scan(
        containment,
        &ProcessScan {
            processes: processes.to_vec(),
            unreadable_pids: BTreeSet::new(),
        },
    )
}

#[cfg(not(target_os = "linux"))]
fn containment_report(containment: &Containment) -> ContainmentReport {
    ContainmentReport {
        platform: if cfg!(unix) {
            "posix_verification_unavailable"
        } else {
            "not_applicable"
        }
        .into(),
        status: if cfg!(unix) {
            "posix_containment_unknown"
        } else {
            "not_applicable"
        }
        .into(),
        root_pid: containment.root_pid,
        process_group_id: containment.process_group_id,
        session_id: containment.session_id,
        root_start_identity: containment.root_start_identity.clone(),
        root_identity_verified: false,
        observed_group_pids: Vec::new(),
        observed_session_pids: Vec::new(),
        observed_escaped_descendant_pids: Vec::new(),
        observed_escaped_descendants: Vec::new(),
        verified_at: now(),
    }
}

#[cfg(target_os = "linux")]
fn signal_group(group: u32, signal: i32) -> std::io::Result<()> {
    if unsafe { libc::kill(-(group as i32), signal) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn signal_contained(containment: &Containment, signal: i32) -> (bool, ContainmentReport) {
    signal_contained_with(containment, signal, linux_processes, signal_group)
}

#[cfg(target_os = "linux")]
fn signal_contained_with<S, G>(
    containment: &Containment,
    signal: i32,
    scan: S,
    send_group: G,
) -> (bool, ContainmentReport)
where
    S: FnOnce() -> Result<ProcessScan, String>,
    G: FnOnce(u32, i32) -> std::io::Result<()>,
{
    // Do not reuse a display snapshot: group IDs are PID-derived and must be checked at send time.
    let report = match scan() {
        Ok(scan) => containment_report_from_scan(containment, &scan),
        Err(_) => containment_report(containment),
    };
    let Some(group) = containment.process_group_id else {
        return (false, report);
    };
    if report.status == "posix_containment_unknown" || !report.root_identity_verified {
        return (false, report);
    }
    (send_group(group, signal).is_ok(), report)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn signal_contained(containment: &Containment, signal: i32) -> (bool, ContainmentReport) {
    let _ = (containment, signal);
    (false, containment_report(containment))
}

fn containment_drained(report: &ContainmentReport) -> bool {
    report.status == "posix_best_effort_empty" || report.status == "not_applicable"
}

fn refresh_termination_confirmed(worker: &Arc<Worker>) -> ContainmentReport {
    let report = containment_report(&worker.containment);
    let mut state = worker.state.lock().expect("state lock");
    state.termination_confirmed = state.root_exited && containment_drained(&report);
    report
}

fn terminate_contained(worker: &Arc<Worker>, reason: &str) {
    {
        let mut state = worker.state.lock().expect("state lock");
        if state.termination_requested {
            return;
        }
        state.termination_requested = true;
        state.exit_reason = Some(reason.into());
        state.timed_out = reason == "timeout";
    }
    #[cfg(unix)]
    {
        let (term_sent, before_term) = signal_contained(&worker.containment, libc::SIGTERM);
        if !term_sent {
            // Child is a handle we created, unlike a PID/group lookup; it is safe to reap the root.
            let _ = worker.child.lock().expect("child lock").kill();
        }
        let deadline = SystemTime::now() + TERMINATION_GRACE;
        while SystemTime::now() < deadline {
            observe_exit(worker);
            if worker
                .state
                .lock()
                .expect("state lock")
                .termination_confirmed
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let (kill_sent, before_kill) = signal_contained(&worker.containment, libc::SIGKILL);
        if !kill_sent {
            let _ = worker.child.lock().expect("child lock").kill();
        }
        let deadline = SystemTime::now() + TERMINATION_HARD_TIMEOUT;
        while SystemTime::now() < deadline {
            observe_exit(worker);
            if containment_drained(&refresh_termination_confirmed(worker)) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        observe_exit(worker);
        let root_exited = worker.state.lock().expect("state lock").root_exited;
        let mut report = refresh_termination_confirmed(worker);
        let escapes = if before_term.observed_escaped_descendant_pids.is_empty() {
            before_kill.observed_escaped_descendant_pids
        } else {
            before_term.observed_escaped_descendant_pids
        };
        if !escapes.is_empty() {
            report.status = "posix_escape_observed".into();
            report.observed_escaped_descendant_pids = escapes;
        }
        worker.state.lock().expect("state lock").termination = Some(TerminationResult {
            requested: true,
            term_signal_sent: term_sent,
            kill_signal_sent: kill_sent,
            root_exited,
            containment: report,
        });
    }
    #[cfg(not(unix))]
    {
        let _ = worker.child.lock().expect("child lock").kill();
    }
}

fn mark_termination(worker: &Arc<Worker>, reason: &str) {
    terminate_contained(worker, reason);
}

fn exit_signal(status: &ExitStatus) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(|signal| format!("SIG{signal}"))
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn record_exit(worker: &Arc<Worker>, exit: ExitStatus) {
    let mut state = worker.state.lock().expect("state lock");
    if state.root_exited {
        return;
    }
    state.exit_code = exit.code();
    state.exit_signal = exit_signal(&exit);
    if state.exit_reason.is_none() {
        state.exit_reason = if let Some(signal) = &state.exit_signal {
            Some(format!("signal:{signal}"))
        } else {
            Some("code".into())
        };
    }
    state.exited_at = Some(now());
    state.root_exited = true;
    state.reader_drain_deadline = Some(SystemTime::now() + READER_DRAIN_TIMEOUT);
    drop(state);
    let _ = refresh_termination_confirmed(worker);
}

fn observe_exit(worker: &Arc<Worker>) {
    let exit = worker
        .child
        .lock()
        .expect("child lock")
        .try_wait()
        .ok()
        .flatten();
    if let Some(exit) = exit {
        record_exit(worker, exit);
    }
    if worker.state.lock().expect("state lock").root_exited {
        let _ = refresh_termination_confirmed(worker);
    }
}

fn terminate_and_wait(worker: &Arc<Worker>, reason: &str) {
    mark_termination(worker, reason);
    if !worker.state.lock().expect("state lock").root_exited {
        let exit = worker.child.lock().expect("child lock").wait();
        if let Ok(exit) = exit {
            record_exit(worker, exit);
        }
    }
}

fn terminate_child_and_wait(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_contained_child_and_wait(child: &mut Child, containment: &Containment) {
    let (term_sent, _) = signal_contained(containment, libc::SIGTERM);
    if term_sent {
        thread::sleep(TERMINATION_GRACE);
        let _ = signal_contained(containment, libc::SIGKILL);
    } else {
        // macOS cannot verify group identity; this owned handle is still safe to terminate.
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn child_start_identity(pid: u32) -> Result<String, String> {
    let stat =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| error.to_string())?;
    let fields = stat
        .rsplit_once(')')
        .ok_or("invalid child /proc stat")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let start_time = fields.get(19).ok_or("missing child start time")?;
    Ok(format!("posix:{pid}:{start_time}"))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn child_start_identity(pid: u32) -> Result<String, String> {
    Ok(format!("posix:{pid}:unavailable"))
}

#[cfg(unix)]
fn contain_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(unix)]
fn verify_containment(pid: u32) -> Result<Containment, String> {
    let pgid = unsafe { libc::getpgid(pid as i32) };
    let sid = unsafe { libc::getsid(pid as i32) };
    if pgid < 1 || sid < 1 || pgid as u32 != pid || sid as u32 != pid {
        return Err("fresh POSIX session/process group verification failed".into());
    }
    Ok(Containment {
        root_pid: pid,
        process_group_id: Some(pgid as u32),
        session_id: Some(sid as u32),
        root_start_identity: child_start_identity(pid)?,
        known_members: Mutex::new(BTreeMap::new()),
        escaped_members: Mutex::new(BTreeMap::new()),
    })
}

#[cfg(not(unix))]
fn verify_containment(pid: u32) -> Result<Containment, String> {
    Ok(Containment {
        root_pid: pid,
        process_group_id: None,
        session_id: None,
        root_start_identity: format!("process:{pid}"),
        known_members: Mutex::new(BTreeMap::new()),
        escaped_members: Mutex::new(BTreeMap::new()),
    })
}

fn append_output(worker: &Arc<Worker>, stdout: bool, data: String) {
    if data.is_empty() {
        return;
    }
    let mut terminate = None;
    {
        let mut state = worker.state.lock().expect("state lock");
        if state.storage_failure.is_some() {
            return;
        }
        // Each stream owns its advertised cap; next_sequence remains the aggregate journal cursor.
        let available = if stdout {
            worker.max_output_bytes.saturating_sub(state.stdout_bytes)
        } else {
            worker.max_output_bytes.saturating_sub(state.stderr_bytes)
        };
        let mut end = available.min(data.len());
        while end < data.len() && end > 0 && (data.as_bytes()[end] & 0xc0) == 0x80 {
            end -= 1;
        }
        let kept = &data[..end];
        if kept.len() != data.len() {
            if stdout {
                state.stdout_truncated = true;
            } else {
                state.stderr_truncated = true;
            }
            state.output_truncated = true;
            terminate = Some("output_limit");
        }
        if !kept.is_empty() {
            let start = state.next_sequence;
            let end = start + kept.len();
            let chunk = json!({ "startSequence": start, "endSequence": end, "timestamp": now(), "data": kept });
            let path = worker.output_directory.join(format!("{start:020}.json"));
            if let Err(error) = write_atomic(&path, &chunk.to_string()) {
                state.storage_failure = Some(error.to_string());
                state.exit_reason = Some("storage_failure".into());
                terminate = Some("storage_failure");
            } else {
                state.next_sequence = end;
                if stdout {
                    state.stdout.push_str(kept);
                    state.stdout_bytes += kept.len();
                } else {
                    state.stderr.push_str(kept);
                    state.stderr_bytes += kept.len();
                }
            }
        }
    }
    if let Some(reason) = terminate {
        mark_termination(worker, reason);
    }
}

fn mark_reader_eof(worker: &Arc<Worker>, stdout: bool) {
    let mut state = worker.state.lock().expect("state lock");
    if stdout {
        state.stdout_eof = true;
    } else {
        state.stderr_eof = true;
    }
}

fn mark_reader_failure(state: &mut State, stdout: bool, error: String) {
    let diagnostic = format!(
        "{} reader error: {error}",
        if stdout { "stdout" } else { "stderr" }
    );
    if stdout {
        state.stdout_reader_error = Some(diagnostic);
    } else {
        state.stderr_reader_error = Some(diagnostic);
    }
    state.output_incomplete = true;
}

fn output_complete(state: &State) -> bool {
    state.stdout_eof
        && state.stderr_eof
        && state.stdout_reader_error.is_none()
        && state.stderr_reader_error.is_none()
}

fn update_reader_drain_state(state: &mut State) {
    if state.termination_confirmed
        && (!output_complete(state))
        && state
            .reader_drain_deadline
            .is_some_and(|deadline| SystemTime::now() >= deadline)
    {
        state.output_incomplete = true;
    }
}

fn update_reader_drain(worker: &Arc<Worker>) {
    let mut state = worker.state.lock().expect("state lock");
    update_reader_drain_state(&mut state);
}

fn reader(worker: Arc<Worker>, mut pipe: impl Read + Send + 'static, stdout: bool) {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        let mut tail = String::new();
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => {
                    append_output(
                        &worker,
                        stdout,
                        redact_stream(String::new(), &mut tail, &worker.secrets, true),
                    );
                    mark_reader_eof(&worker, stdout);
                    return;
                }
                Err(error) => {
                    append_output(
                        &worker,
                        stdout,
                        redact_stream(String::new(), &mut tail, &worker.secrets, true),
                    );
                    let mut state = worker.state.lock().expect("state lock");
                    mark_reader_failure(&mut state, stdout, error.to_string());
                    return;
                }
                Ok(size) => append_output(
                    &worker,
                    stdout,
                    redact_stream(
                        String::from_utf8_lossy(&buffer[..size]).into_owned(),
                        &mut tail,
                        &worker.secrets,
                        false,
                    ),
                ),
            }
        }
    });
}

fn monitor(worker: Arc<Worker>) {
    thread::spawn(move || {
        loop {
            observe_exit(&worker);
            update_reader_drain(&worker);
            let terminal = {
                let state = worker.state.lock().expect("state lock");
                state.termination_confirmed
                    && (state.output_incomplete || (state.stdout_eof && state.stderr_eof))
            };
            if terminal {
                return;
            }
            if SystemTime::now() >= worker.deadline {
                mark_termination(&worker, "timeout");
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
}

fn snapshot(worker: &Arc<Worker>) -> Value {
    observe_exit(worker);
    update_reader_drain(worker);
    let containment = containment_report(&worker.containment);
    let pid = worker.child.lock().expect("child lock").id();
    let state = worker.state.lock().expect("state lock");
    let output_complete = output_complete(&state);
    let reader_failure = state
        .stdout_reader_error
        .iter()
        .chain(state.stderr_reader_error.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let terminal = state.termination_confirmed && (output_complete || state.output_incomplete);
    let containment_unavailable = containment.status == "posix_containment_unknown";
    let status = if (terminal || (state.root_exited && containment_unavailable))
        && (state.storage_failure.is_some() || state.output_incomplete || containment_unavailable)
    {
        "lost"
    } else if terminal {
        "exited"
    } else {
        "running"
    };
    json!({
        "status": status, "pid": pid, "stdout": state.stdout, "stderr": state.stderr,
        "stdoutBytes": state.stdout_bytes, "stderrBytes": state.stderr_bytes,
        "stdoutTruncated": state.stdout_truncated, "stderrTruncated": state.stderr_truncated,
        "nextSequence": state.next_sequence, "firstRetainedSequence": state.first_retained_sequence,
        "outputTruncated": state.output_truncated, "exitCode": state.exit_code,
        "exitSignal": state.exit_signal, "exitReason": state.exit_reason,
        "startedAt": state.started_at, "exitedAt": state.exited_at, "timedOut": state.timed_out,
        "terminationRequested": state.termination_requested, "terminationConfirmed": state.termination_confirmed,
        "storageFailure": state.storage_failure, "stdoutEof": state.stdout_eof, "stderrEof": state.stderr_eof,
        "readerFailure": if reader_failure.is_empty() { Value::Null } else { Value::String(reader_failure) },
        "outputComplete": output_complete, "outputIncomplete": state.output_incomplete,
        "containment": containment, "termination": state.termination,
    })
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected read failure"))
        }
    }

    #[test]
    fn reader_error_is_not_eof_or_complete_output() {
        let mut state = State {
            termination_confirmed: true,
            ..State::default()
        };
        mark_reader_failure(&mut state, true, "injected read failure".into());
        assert!(!state.stdout_eof);
        assert!(!output_complete(&state));
        assert!(state.output_incomplete);
        assert!(
            state
                .stdout_reader_error
                .unwrap()
                .contains("injected read failure")
        );
    }

    #[test]
    fn reader_drain_timeout_marks_output_incomplete() {
        let mut state = State {
            termination_confirmed: true,
            reader_drain_deadline: Some(SystemTime::now() - Duration::from_millis(1)),
            ..State::default()
        };
        update_reader_drain_state(&mut state);
        assert!(state.output_incomplete);
        assert!(!output_complete(&state));
    }

    #[test]
    fn reader_error_keeps_monitoring_a_live_child_until_timeout() {
        #[cfg(unix)]
        let child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("start child");
        #[cfg(windows)]
        let child = Command::new("cmd")
            .args(["/C", "ping -n 31 127.0.0.1 > NUL"])
            .spawn()
            .expect("start child");
        let output_directory = std::env::temp_dir().join(format!(
            "opencode-pty-worker-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        create_dir_all(&output_directory).expect("create output directory");
        let worker = Arc::new(Worker {
            child: Mutex::new(child),
            state: Mutex::new(State {
                started_at: now(),
                ..State::default()
            }),
            secrets: Vec::new(),
            output_directory: output_directory.clone(),
            max_output_bytes: MAX_OUTPUT_BYTES,
            deadline: SystemTime::now() - Duration::from_millis(1),
            containment: Containment {
                root_pid: 0,
                process_group_id: None,
                session_id: None,
                root_start_identity: "test".into(),
                known_members: Mutex::new(BTreeMap::new()),
                escaped_members: Mutex::new(BTreeMap::new()),
            },
        });
        reader(worker.clone(), FailingReader, true);
        for _ in 0..1_000 {
            if worker
                .state
                .lock()
                .expect("state lock")
                .stdout_reader_error
                .is_some()
            {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            worker
                .state
                .lock()
                .expect("state lock")
                .stdout_reader_error
                .is_some()
        );
        assert!(
            worker
                .child
                .lock()
                .expect("child lock")
                .try_wait()
                .expect("check child")
                .is_none()
        );
        monitor(worker.clone());
        let result = wait_for_final_snapshot(&worker);
        assert_eq!(result["status"], "lost");
        assert_eq!(result["timedOut"], true);
        assert_eq!(result["terminationConfirmed"], true);
        remove_dir_all(output_directory).ok();
    }

    #[test]
    fn startup_cleanup_waits_for_the_direct_child() {
        #[cfg(unix)]
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("start child");
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 31 127.0.0.1 > NUL"])
            .spawn()
            .expect("start child");
        terminate_child_and_wait(&mut child);
        assert!(child.try_wait().expect("check child").is_some());
    }

    #[cfg(target_os = "linux")]
    fn test_containment() -> Containment {
        Containment {
            root_pid: 10,
            process_group_id: Some(10),
            session_id: Some(10),
            root_start_identity: "posix:10:root".into(),
            known_members: Mutex::new(BTreeMap::from([
                (10, "posix:10:root".into()),
                (11, "posix:11:member".into()),
            ])),
            escaped_members: Mutex::new(BTreeMap::new()),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reused_root_or_group_is_unknown_and_never_empty() {
        let report = containment_report_from_processes(
            &test_containment(),
            &[ProcessInfo {
                pid: 10,
                ppid: 1,
                pgid: 10,
                sid: 10,
                start_time: "reused".into(),
            }],
        );
        assert_eq!(report.status, "posix_containment_unknown");
        let report = containment_report_from_processes(
            &test_containment(),
            &[ProcessInfo {
                pid: 12,
                ppid: 1,
                pgid: 10,
                sid: 10,
                start_time: "unrelated".into(),
            }],
        );
        assert_eq!(report.status, "posix_containment_unknown");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn newly_unreadable_candidate_prevents_confirmation_and_signaling() {
        let containment = test_containment();
        let report = containment_report_from_scan(
            &containment,
            &ProcessScan {
                processes: vec![ProcessInfo {
                    pid: 10,
                    ppid: 1,
                    pgid: 10,
                    sid: 10,
                    start_time: "root".into(),
                }],
                unreadable_pids: BTreeSet::from([12]),
            },
        );
        assert_eq!(report.status, "posix_containment_unknown");
        let (sent, report) = signal_contained_with(
            &containment,
            libc::SIGTERM,
            || {
                Ok(ProcessScan {
                    processes: vec![ProcessInfo {
                        pid: 10,
                        ppid: 1,
                        pgid: 10,
                        sid: 10,
                        start_time: "root".into(),
                    }],
                    unreadable_pids: BTreeSet::from([12]),
                })
            },
            |_, _| panic!("must not signal with an unreadable candidate"),
        );
        assert!(!sent);
        assert_eq!(report.status, "posix_containment_unknown");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn escape_is_retained_until_a_complete_scan_resolves_its_identity() {
        let containment = test_containment();
        let escaped = ProcessInfo {
            pid: 12,
            ppid: 10,
            pgid: 12,
            sid: 12,
            start_time: "escape".into(),
        };
        let report = containment_report_from_processes(
            &containment,
            &[
                ProcessInfo {
                    pid: 10,
                    ppid: 1,
                    pgid: 10,
                    sid: 10,
                    start_time: "root".into(),
                },
                escaped.clone(),
            ],
        );
        assert_eq!(report.status, "posix_escape_observed");
        assert_eq!(
            report.observed_escaped_descendants[0].start_identity,
            "posix:12:escape"
        );
        let report = containment_report_from_scan(
            &containment,
            &ProcessScan {
                processes: Vec::new(),
                unreadable_pids: BTreeSet::from([12]),
            },
        );
        assert_eq!(report.status, "posix_containment_unknown");
        assert_eq!(report.observed_escaped_descendant_pids, vec![12]);
        let report = containment_report_from_processes(&containment, &[]);
        assert_eq!(report.status, "posix_best_effort_empty");
        assert!(report.observed_escaped_descendant_pids.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_member_after_root_exit_prevents_confirmation() {
        let report = containment_report_from_processes(
            &test_containment(),
            &[ProcessInfo {
                pid: 11,
                ppid: 1,
                pgid: 10,
                sid: 10,
                start_time: "member".into(),
            }],
        );
        assert_eq!(report.status, "posix_processes_remaining");
        assert!(!containment_drained(&report));
    }
}

fn wait_for_final_snapshot(worker: &Arc<Worker>) -> Value {
    loop {
        let result = snapshot(worker);
        if result["status"] != "running" {
            return result;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn handle(worker: &Arc<Worker>, request: Value) -> Result<(Value, bool), WorkerError> {
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .ok_or(WorkerError {
            code: "validation",
            message: "missing operation".into(),
        })?;
    match operation {
        "health" => Ok((json!({"protocolVersion": 1}), false)),
        "snapshot" => Ok((snapshot(worker), false)),
        "write" => {
            let data = request
                .get("data")
                .and_then(Value::as_str)
                .ok_or(WorkerError {
                    code: "validation",
                    message: "missing data".into(),
                })?;
            if data.len() > 64 * 1024 {
                return Err(WorkerError {
                    code: "validation",
                    message: "input exceeds limit".into(),
                });
            }
            if worker
                .state
                .lock()
                .expect("state lock")
                .storage_failure
                .is_some()
            {
                return Err(WorkerError {
                    code: "storage",
                    message: "worker output storage failed".into(),
                });
            }
            let mut child = worker.child.lock().expect("child lock");
            let input = child.stdin.as_mut().ok_or(WorkerError {
                code: "process",
                message: "process stdin is unavailable".into(),
            })?;
            input
                .write_all(data.as_bytes())
                .map_err(|error| WorkerError {
                    code: "process",
                    message: error.to_string(),
                })?;
            input.flush().map_err(|error| WorkerError {
                code: "process",
                message: error.to_string(),
            })?;
            Ok((json!({"acceptedBytes": data.len()}), false))
        }
        "wait" => {
            let timeout_ms = request
                .get("timeoutMs")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(3_600_000);
            let deadline = SystemTime::now() + Duration::from_millis(timeout_ms);
            loop {
                let result = snapshot(worker);
                if result["status"] != "running" || SystemTime::now() >= deadline {
                    return Ok((result, false));
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        "stop" => {
            terminate_and_wait(worker, "stopped");
            Ok((wait_for_final_snapshot(worker), false))
        }
        "shutdown" => {
            if !worker
                .state
                .lock()
                .expect("state lock")
                .termination_confirmed
            {
                terminate_and_wait(worker, "stopped");
            }
            Ok((wait_for_final_snapshot(worker), true))
        }
        _ => Err(WorkerError {
            code: "validation",
            message: "unsupported operation".into(),
        }),
    }
}

fn serve(mut stream: TcpStream, worker: Arc<Worker>, token: String, shutdown: Arc<AtomicBool>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut request_bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let size = match stream.read(&mut buffer) {
            Ok(size) if size > 0 => size,
            _ => return,
        };
        request_bytes.extend_from_slice(&buffer[..size]);
        if request_bytes.len() > MAX_FRAME_BYTES {
            return;
        }
        if let Some(end) = request_bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
        {
            break end + 4;
        }
    };
    let header = match std::str::from_utf8(&request_bytes[..header_end]) {
        Ok(header) => header.to_owned(),
        Err(_) => return,
    };
    let content_length = header
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if content_length == 0 || content_length > MAX_FRAME_BYTES {
        return;
    }
    while request_bytes.len() < header_end + content_length {
        let size = match stream.read(&mut buffer) {
            Ok(size) if size > 0 => size,
            _ => return,
        };
        request_bytes.extend_from_slice(&buffer[..size]);
        if request_bytes.len() > header_end + content_length {
            return;
        }
    }
    let request: Value = match serde_json::from_slice(&request_bytes[header_end..]) {
        Ok(value) => value,
        Err(_) => return,
    };
    let authenticated = header.lines().any(|line| {
        line == format!("Authorization: Bearer {token}")
            || line == format!("authorization: Bearer {token}")
    });
    let (response, stop_server) = if authenticated {
        match handle(&worker, request) {
            Ok((result, stop_server)) => (json!({"ok": true, "result": result}), stop_server),
            Err(error) => (
                json!({"ok": false, "error": {"code": error.code, "message": error.message}}),
                false,
            ),
        }
    } else {
        (
            json!({"ok": false, "error": {"code": "authentication", "message": "Invalid worker credential."}}),
            false,
        )
    };
    let payload = response.to_string();
    let status = if response["ok"] == true {
        "200 OK"
    } else {
        "400 Bad Request"
    };
    let _ = stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload).as_bytes());
    if stop_server {
        shutdown.store(true, Ordering::Release);
    }
}

fn main() -> Result<(), String> {
    let mut stdin = std::io::stdin();
    let bootstrap: Bootstrap =
        serde_json::from_slice(&read_frame(&mut stdin)?).map_err(|error| error.to_string())?;
    if bootstrap.mode != "exec" {
        return Err("only exec mode is supported".into());
    }
    if bootstrap.worker_control_token.len() < 16 {
        return Err("invalid worker token".into());
    }
    let session_directory = PathBuf::from(&bootstrap.session_directory);
    let output_directory = session_directory.join("output");
    create_dir_all(&output_directory).map_err(|error| error.to_string())?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let descriptor_path = session_directory.join("worker.json");
    if bootstrap.fault.as_deref() == Some("descriptor_write") {
        return Err("injected worker descriptor write failure".into());
    }
    let descriptor = Descriptor {
        pid: std::process::id(),
        start_identity: bootstrap.worker_id.clone(),
        process_identity: process_identity()?,
        endpoint: format!(
            "http://{}",
            listener.local_addr().map_err(|error| error.to_string())?
        ),
        token: bootstrap.worker_control_token.clone(),
        protocol_version: 1,
    };
    write_atomic(
        &descriptor_path,
        &serde_json::to_string(&descriptor).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if bootstrap.fault.as_deref() == Some("ready_stdout") {
        let _ = remove_file(&descriptor_path);
        return Err("injected worker ready stdout failure".into());
    }
    if bootstrap.fault.as_deref() == Some("missing_ready") {
        thread::sleep(Duration::from_millis(100));
    } else {
        if let Ok(delay) = std::env::var("OPENCODE_PTY_NATIVE_WORKER_READY_DELAY_MS")
            .unwrap_or_default()
            .parse::<u64>()
        {
            thread::sleep(Duration::from_millis(delay));
        }
        if bootstrap.fault.as_deref() == Some("split_ready") {
            print!("{{\"rea");
            std::io::stdout()
                .flush()
                .map_err(|error| error.to_string())?;
            thread::sleep(Duration::from_millis(10));
            println!("dy\":true}}");
        } else {
            println!("{{\"ready\":true}}");
        }
        if let Err(error) = std::io::stdout().flush() {
            let _ = remove_file(&descriptor_path);
            return Err(error.to_string());
        }
    }
    // The daemon controls command eligibility through this inherited pipe. Closing it before
    // `start` means no direct child can be created after a failed worker identity probe.
    match control(&mut stdin, &bootstrap.worker_control_token) {
        Ok(control) if control.operation == "start" => {}
        Ok(_) | Err(_) => {
            let _ = remove_file(&descriptor_path);
            return Ok(());
        }
    }
    let mut command = Command::new(&bootstrap.command);
    command
        .args(&bootstrap.args)
        .current_dir(&bootstrap.workdir)
        .env_clear()
        .envs(&bootstrap.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    contain_child(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = remove_file(&descriptor_path);
            return Err(error.to_string());
        }
    };
    let containment = match verify_containment(child.id()) {
        Ok(containment) => containment,
        Err(error) => {
            terminate_child_and_wait(&mut child);
            let _ = remove_file(&descriptor_path);
            return Err(error);
        }
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            #[cfg(unix)]
            terminate_contained_child_and_wait(&mut child, &containment);
            #[cfg(not(unix))]
            terminate_child_and_wait(&mut child);
            let _ = remove_file(&descriptor_path);
            return Err("missing stdout".into());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            #[cfg(unix)]
            terminate_contained_child_and_wait(&mut child, &containment);
            #[cfg(not(unix))]
            terminate_child_and_wait(&mut child);
            let _ = remove_file(&descriptor_path);
            return Err("missing stderr".into());
        }
    };
    let worker = Arc::new(Worker {
        child: Mutex::new(child),
        state: Mutex::new(State {
            started_at: now(),
            ..State::default()
        }),
        secrets: bootstrap
            .redaction_secrets
            .into_iter()
            .filter(|secret| secret.len() >= 4)
            .collect(),
        output_directory,
        max_output_bytes: bootstrap.max_output_bytes.min(MAX_OUTPUT_BYTES),
        deadline: SystemTime::now() + Duration::from_secs(bootstrap.timeout_seconds),
        containment,
    });
    reader(worker.clone(), stdout, true);
    reader(worker.clone(), stderr, false);
    monitor(worker.clone());
    let shutdown = Arc::new(AtomicBool::new(false));
    let rollback = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        let rollback = rollback.clone();
        let token = bootstrap.worker_control_token.clone();
        thread::spawn(move || {
            // EOF is parent death for this worker: reaping happens in the owner thread below.
            match control(&mut std::io::stdin(), &token) {
                Ok(control) if control.operation == "rollback" => {
                    rollback.store(true, Ordering::Release)
                }
                _ => rollback.store(true, Ordering::Release),
            }
            shutdown.store(true, Ordering::Release);
        });
    }
    if bootstrap.fault.as_deref() == Some("rpc_loss_after_start") {
        let shutdown = shutdown.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            shutdown.store(true, Ordering::Release);
        });
    }
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let worker = worker.clone();
                let token = bootstrap.worker_control_token.clone();
                let shutdown = shutdown.clone();
                thread::spawn(move || serve(stream, worker, token, shutdown));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(_) => break,
        }
    }
    if !worker
        .state
        .lock()
        .expect("state lock")
        .termination_confirmed
    {
        terminate_and_wait(&worker, "stopped");
    }
    if rollback.load(Ordering::Acquire) {
        let pid = worker.child.lock().expect("child lock").id();
        println!(
            "{{\"rollback\":true,\"token\":\"{}\",\"pid\":{pid}}}",
            bootstrap.worker_control_token
        );
        let _ = std::io::stdout().flush();
    }
    let _ = remove_file(descriptor_path);
    Ok(())
}
