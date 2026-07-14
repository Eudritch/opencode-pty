use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

#[cfg(unix)]
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
    storage_failure: Option<String>,
    stdout_eof: bool,
    stderr_eof: bool,
    stdout_reader_error: Option<String>,
    stderr_reader_error: Option<String>,
    reader_drain_deadline: Option<SystemTime>,
    output_incomplete: bool,
}

struct Worker {
    child: Mutex<Child>,
    state: Mutex<State>,
    secrets: Vec<String>,
    output_directory: PathBuf,
    max_output_bytes: usize,
    deadline: SystemTime,
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
        use std::os::unix::fs::{PermissionsExt, set_permissions};
        set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
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
    for secret in secrets {
        let secret: Vec<_> = secret.chars().collect();
        for start in 0..split {
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

fn mark_termination(worker: &Arc<Worker>, reason: &str) {
    let mut state = worker.state.lock().expect("state lock");
    if state.termination_requested {
        return;
    }
    state.termination_requested = true;
    state.exit_reason = Some(reason.into());
    state.timed_out = reason == "timeout";
    drop(state);
    let _ = worker.child.lock().expect("child lock").kill();
}

fn exit_signal(status: &ExitStatus) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        return status.signal().map(|signal| format!("SIG{signal}"));
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn record_exit(worker: &Arc<Worker>, exit: ExitStatus) {
    let mut state = worker.state.lock().expect("state lock");
    if state.termination_confirmed {
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
    state.termination_confirmed = true;
    state.reader_drain_deadline = Some(SystemTime::now() + READER_DRAIN_TIMEOUT);
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
}

fn terminate_and_wait(worker: &Arc<Worker>, reason: &str) {
    mark_termination(worker, reason);
    let exit = worker.child.lock().expect("child lock").wait();
    if let Ok(exit) = exit {
        record_exit(worker, exit);
    }
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
        if kept.is_empty() {
        } else {
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
    let status = if terminal && (state.storage_failure.is_some() || state.output_incomplete) {
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
    })
}

#[cfg(test)]
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
        });
        reader(worker.clone(), FailingReader, true);
        for _ in 0..50 {
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
    let bootstrap: Bootstrap = serde_json::from_slice(&read_frame(&mut std::io::stdin())?)
        .map_err(|error| error.to_string())?;
    if bootstrap.mode != "exec" {
        return Err("only exec mode is supported".into());
    }
    if bootstrap.worker_control_token.len() < 16 {
        return Err("invalid worker token".into());
    }
    let session_directory = PathBuf::from(&bootstrap.session_directory);
    let output_directory = session_directory.join("output");
    create_dir_all(&output_directory).map_err(|error| error.to_string())?;
    let mut command = Command::new(&bootstrap.command);
    command
        .args(&bootstrap.args)
        .current_dir(&bootstrap.workdir)
        .env_clear()
        .envs(&bootstrap.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdout = child.stdout.take().ok_or("missing stdout")?;
    let stderr = child.stderr.take().ok_or("missing stderr")?;
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
    });
    reader(worker.clone(), stdout, true);
    reader(worker.clone(), stderr, false);
    monitor(worker.clone());
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let descriptor_path = session_directory.join("worker.json");
    let descriptor = Descriptor {
        pid: std::process::id(),
        start_identity: bootstrap.worker_id,
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
    println!("{{\"ready\":true}}");
    std::io::stdout()
        .flush()
        .map_err(|error| error.to_string())?;
    let shutdown = Arc::new(AtomicBool::new(false));
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
    let _ = remove_file(descriptor_path);
    Ok(())
}
