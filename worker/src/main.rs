use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{File, create_dir_all, remove_file, rename};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    pid: u32,
    start_identity: String,
    endpoint: String,
    token: String,
    protocol_version: u32,
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
    started_at: String,
    exited_at: Option<String>,
    timed_out: bool,
    stop_requested: bool,
}

struct Worker {
    child: Mutex<Child>,
    state: Mutex<State>,
    secrets: Vec<String>,
    output_directory: PathBuf,
    max_output_bytes: usize,
    timeout: Duration,
}

fn now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

fn private_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
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
    let temporary = path.with_extension(format!("{}.tmp", now()));
    let mut file = File::create(&temporary)?;
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    drop(file);
    rename(&temporary, path)?;
    private_file(path)
}

fn append_output(worker: &Arc<Worker>, stream: bool, data: String) {
    if data.is_empty() {
        return;
    }
    let bytes = data.len();
    let mut state = worker.state.lock().expect("state lock");
    let stream_bytes = if stream {
        state.stdout_bytes
    } else {
        state.stderr_bytes
    };
    if stream_bytes >= worker.max_output_bytes || state.next_sequence + bytes > MAX_OUTPUT_BYTES {
        if stream {
            state.stdout_truncated = true
        } else {
            state.stderr_truncated = true
        }
        state.output_truncated = true;
        return;
    }
    let remaining = worker.max_output_bytes.saturating_sub(stream_bytes);
    let mut end = remaining.min(bytes);
    while end < bytes && end > 0 && (data.as_bytes()[end] & 0xc0) == 0x80 {
        end -= 1;
    }
    let kept = if bytes > remaining {
        &data[..end]
    } else {
        &data
    };
    if kept.len() != bytes {
        if stream {
            state.stdout_truncated = true
        } else {
            state.stderr_truncated = true
        }
        state.output_truncated = true;
    }
    if stream {
        state.stdout.push_str(kept);
        state.stdout_bytes += kept.len();
    } else {
        state.stderr.push_str(kept);
        state.stderr_bytes += kept.len();
    }
    if kept.is_empty() {
        return;
    }
    let start = state.next_sequence;
    state.next_sequence += kept.len();
    let chunk = json!({
        "startSequence": start,
        "endSequence": state.next_sequence,
        "timestamp": now(),
        "data": kept,
    });
    let path = worker.output_directory.join(format!("{:020}.json", start));
    let _ = write_atomic(&path, &chunk.to_string());
}

fn reader(worker: Arc<Worker>, mut pipe: impl Read + Send + 'static, stdout: bool) {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        let mut tail = String::new();
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) | Err(_) => {
                    append_output(
                        &worker,
                        stdout,
                        redact_stream(String::new(), &mut tail, &worker.secrets, true),
                    );
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

fn snapshot(worker: &Arc<Worker>) -> Value {
    let mut child = worker.child.lock().expect("child lock");
    let mut state = worker.state.lock().expect("state lock");
    if state.exit_code.is_none() {
        if let Ok(Some(exit)) = child.try_wait() {
            state.exit_code = exit.code();
            state.exited_at = Some(now());
        }
    }
    json!({
        "status": if state.exit_code.is_some() { "exited" } else { "running" },
        "pid": child.id(),
        "stdout": state.stdout,
        "stderr": state.stderr,
        "stdoutBytes": state.stdout_bytes,
        "stderrBytes": state.stderr_bytes,
        "stdoutTruncated": state.stdout_truncated,
        "stderrTruncated": state.stderr_truncated,
        "nextSequence": state.next_sequence,
        "firstRetainedSequence": state.first_retained_sequence,
        "outputTruncated": state.output_truncated,
        "exitCode": state.exit_code,
        "startedAt": state.started_at,
        "exitedAt": state.exited_at,
        "timedOut": state.timed_out,
    })
}

fn handle(worker: &Arc<Worker>, request: Value) -> Result<(Value, bool), String> {
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    match operation {
        "health" => Ok((json!({"protocolVersion": 1}), false)),
        "snapshot" => Ok((snapshot(worker), false)),
        "write" => {
            let data = request
                .get("data")
                .and_then(Value::as_str)
                .ok_or("missing data")?;
            if data.len() > 64 * 1024 {
                return Err("input exceeds limit".into());
            }
            let mut child = worker.child.lock().expect("child lock");
            let input = child.stdin.as_mut().ok_or("process stdin is unavailable")?;
            input
                .write_all(data.as_bytes())
                .map_err(|error| error.to_string())?;
            input.flush().map_err(|error| error.to_string())?;
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
                if result["status"] == "exited" {
                    return Ok((result, false));
                }
                if SystemTime::now() >= deadline {
                    return Ok((result, false));
                }
                thread::sleep(Duration::from_millis(20));
                let started = worker
                    .state
                    .lock()
                    .expect("state lock")
                    .started_at
                    .parse::<u128>()
                    .unwrap_or(0);
                let elapsed = now().parse::<u128>().unwrap_or(0).saturating_sub(started);
                if elapsed >= worker.timeout.as_millis() {
                    let mut child = worker.child.lock().expect("child lock");
                    let _ = child.kill();
                    let mut state = worker.state.lock().expect("state lock");
                    state.timed_out = true;
                }
            }
        }
        "stop" => {
            {
                let mut child = worker.child.lock().expect("child lock");
                let _ = child.kill();
                if let Ok(exit) = child.wait() {
                    let mut state = worker.state.lock().expect("state lock");
                    state.exit_code = exit.code();
                    state.exited_at = Some(now());
                }
            }
            let mut state = worker.state.lock().expect("state lock");
            state.stop_requested = true;
            drop(state);
            Ok((snapshot(worker), true))
        }
        _ => Err("unsupported operation".into()),
    }
}

fn serve(mut stream: TcpStream, worker: &Arc<Worker>, token: &str) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut request_bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let size = match stream.read(&mut buffer) {
            Ok(size) if size > 0 => size,
            _ => return false,
        };
        request_bytes.extend_from_slice(&buffer[..size]);
        if request_bytes.len() > MAX_FRAME_BYTES {
            return false;
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
        Err(_) => return false,
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
        return false;
    }
    while request_bytes.len() < header_end + content_length {
        let size = match stream.read(&mut buffer) {
            Ok(size) if size > 0 => size,
            _ => return false,
        };
        request_bytes.extend_from_slice(&buffer[..size]);
        if request_bytes.len() > header_end + content_length {
            return false;
        }
    }
    let body = match std::str::from_utf8(&request_bytes[header_end..]) {
        Ok(body) => body,
        Err(_) => return false,
    };
    let request: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let authenticated = header.lines().any(|line| {
        line == format!("Authorization: Bearer {token}")
            || line == format!("authorization: Bearer {token}")
    });
    let response = if authenticated {
        match handle(worker, request) {
            Ok((result, shutdown)) => {
                let payload = json!({"ok": true, "result": result}).to_string();
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload).as_bytes());
                return shutdown;
            }
            Err(error) => json!({"ok": false, "error": {"code": "validation", "message": error}}),
        }
    } else {
        json!({"ok": false, "error": {"code": "authentication", "message": "Invalid worker credential."}})
    };
    let payload = response.to_string();
    let _ = stream.write_all(format!("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload).as_bytes());
    false
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
        timeout: Duration::from_secs(bootstrap.timeout_seconds),
    });
    reader(worker.clone(), stdout, true);
    reader(worker.clone(), stderr, false);
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let descriptor_path = session_directory.join("worker.json");
    let descriptor = Descriptor {
        pid: std::process::id(),
        start_identity: bootstrap.worker_id,
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
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if serve(stream, &worker, &bootstrap.worker_control_token) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = remove_file(descriptor_path);
    Ok(())
}
