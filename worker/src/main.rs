use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(all(test, unix))]
use std::fs::remove_dir_all;
use std::fs::{File, create_dir_all, remove_file, rename};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(windows)]
use std::{
    mem::{size_of, size_of_val},
    ptr::{null, null_mut},
};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole},
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Pipes::CreatePipe,
        Threading::{
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
            InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
            TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const READER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(windows)]
const TERMINATION_HARD_TIMEOUT: Duration = Duration::from_secs(1);
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
    // Exec always has a deadline. PTYs only have one when explicitly requested.
    timeout_seconds: Option<u64>,
    max_output_bytes: usize,
    mode: String,
    #[cfg_attr(not(unix), allow(dead_code))]
    cols: Option<u16>,
    #[cfg_attr(not(unix), allow(dead_code))]
    rows: Option<u16>,
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
    retained_bytes: usize,
    chunks: Vec<JournalChunk>,
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
struct JournalChunk {
    start_sequence: usize,
    end_sequence: usize,
    timestamp: String,
    data: String,
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
    #[cfg_attr(windows, allow(dead_code))]
    process_group_id: Option<u32>,
    #[cfg_attr(windows, allow(dead_code))]
    session_id: Option<u32>,
    root_start_identity: String,
    #[cfg(windows)]
    job: usize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    known_members: Mutex<BTreeMap<u32, String>>,
    // ponytail: retain only identities needed to prevent an observed escape from becoming empty.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    escaped_members: Mutex<BTreeMap<u32, String>>,
}

struct Worker {
    #[cfg(unix)]
    child: Mutex<Child>,
    #[cfg(windows)]
    child: Mutex<WindowsChild>,
    #[cfg(unix)]
    terminal: Option<Mutex<File>>,
    // Serializes terminal reads with input acceptance so the cursor is taken immediately after
    // the terminal accepts input, excluding earlier output without missing an immediate reply.
    #[cfg(unix)]
    arrival: Mutex<()>,
    #[cfg(unix)]
    terminal_redaction_tail: Mutex<String>,
    #[cfg(unix)]
    pause_terminal_reader_until_write: AtomicBool,
    state: Mutex<State>,
    secrets: Vec<String>,
    output_directory: PathBuf,
    max_output_bytes: usize,
    deadline: Option<SystemTime>,
    containment: Containment,
    mode: String,
}

#[cfg(windows)]
struct WinHandle(HANDLE);

#[cfg(windows)]
impl WinHandle {
    fn new(handle: HANDLE) -> Result<Self, String> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(Self(handle))
        }
    }
    fn raw(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for WinHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
unsafe impl Send for WinHandle {}
#[cfg(windows)]
unsafe impl Sync for WinHandle {}

#[cfg(windows)]
impl Read for WinHandle {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut read = 0;
        let result = unsafe {
            ReadFile(
                self.0,
                buffer.as_mut_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                &mut read,
                null_mut(),
            )
        };
        if result == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }
}

#[cfg(windows)]
impl Write for WinHandle {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        let result = unsafe {
            WriteFile(
                self.0,
                buffer.as_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                &mut written,
                null_mut(),
            )
        };
        if result == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
struct WindowsPty {
    console: HPCON,
    input: WinHandle,
    output: Option<WinHandle>,
}

#[cfg(windows)]
impl Drop for WindowsPty {
    fn drop(&mut self) {
        unsafe {
            ClosePseudoConsole(self.console);
        }
    }
}

#[cfg(windows)]
struct WindowsChild {
    process: WinHandle,
    pid: u32,
    job: WinHandle,
    stdin: Option<WinHandle>,
    stdout: Option<WinHandle>,
    stderr: Option<WinHandle>,
    pty: Option<WindowsPty>,
    exit: Option<WindowsExit>,
}

#[cfg(windows)]
impl WindowsChild {
    fn id(&self) -> u32 {
        self.pid
    }
    fn try_wait(&mut self) -> std::io::Result<Option<WindowsExit>> {
        if let Some(exit) = self.exit {
            return Ok(Some(exit));
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(self.process.raw(), &mut code) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let exit = (code != 259).then_some(WindowsExit(code as i32));
        self.exit = exit;
        Ok(exit)
    }
    fn wait_for(&mut self, timeout: Duration) -> std::io::Result<Option<WindowsExit>> {
        match unsafe {
            WaitForSingleObject(
                self.process.raw(),
                timeout.as_millis().min(u32::MAX as u128) as u32,
            )
        } {
            WAIT_OBJECT_0 => self.try_wait(),
            WAIT_TIMEOUT => Ok(None),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
    fn terminate_job(&self) -> std::io::Result<()> {
        if unsafe { TerminateJobObject(self.job.raw(), 1) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct WindowsExit(i32);

#[cfg(windows)]
impl WindowsExit {
    fn code(&self) -> Option<i32> {
        Some(self.0)
    }
}

#[cfg(windows)]
fn wide(value: &str) -> Result<Vec<u16>, String> {
    if value.encode_utf16().any(|unit| unit == 0) {
        return Err("Windows command, cwd, and environment values cannot contain NUL".into());
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

#[cfg(windows)]
fn quote_windows_arg(argument: &str) -> String {
    if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
        return argument.into();
    }
    let mut quoted = String::from("\"");
    let mut slashes = 0;
    for character in argument.chars() {
        if character == '\\' {
            slashes += 1;
        } else if character == '"' {
            quoted.push_str(&"\\".repeat(slashes * 2 + 1));
            quoted.push('"');
            slashes = 0;
        } else {
            quoted.push_str(&"\\".repeat(slashes));
            quoted.push(character);
            slashes = 0;
        }
    }
    quoted.push_str(&"\\".repeat(slashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(windows)]
fn windows_environment(env: &BTreeMap<String, String>) -> Result<Vec<u16>, String> {
    for (key, value) in env {
        // Windows ordinal ignore-case is not Rust Unicode uppercasing. Restrict names to the
        // compatible ASCII subset; values remain fully Unicode.
        if key.is_empty()
            || !key.is_ascii()
            || key.contains('=')
            || key.encode_utf16().any(|unit| unit == 0)
            || value.encode_utf16().any(|unit| unit == 0)
        {
            return Err("invalid Windows environment entry".into());
        }
    }
    let mut entries = env.iter().collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| {
        left.to_ascii_uppercase()
            .cmp(&right.to_ascii_uppercase())
            .then_with(|| left.cmp(right))
    });
    let mut block = Vec::new();
    let mut previous: Option<&str> = None;
    for (key, value) in entries {
        if previous.is_some_and(|earlier| earlier.eq_ignore_ascii_case(key)) {
            return Err(format!("duplicate Windows environment key: {key}"));
        }
        previous = Some(key);
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(windows)]
struct WindowsAttributeList {
    _bytes: Vec<u8>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

#[cfg(windows)]
impl WindowsAttributeList {
    fn new(count: u32) -> Result<Self, String> {
        let mut size = 0;
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if size == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut bytes = vec![0; size];
        let list = bytes.as_mut_ptr().cast();
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut size) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self {
            _bytes: bytes,
            list,
        })
    }
}

#[cfg(windows)]
impl Drop for WindowsAttributeList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

#[cfg(windows)]
fn pipe(inherit_read: bool) -> Result<(WinHandle, WinHandle), String> {
    let mut read = null_mut();
    let mut write = null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let read = WinHandle::new(read)?;
    let write = WinHandle::new(write)?;
    let parent = if inherit_read {
        write.raw()
    } else {
        read.raw()
    };
    if unsafe { SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok((read, write))
}

#[cfg(windows)]
fn windows_job_empty(job: HANDLE) -> Result<bool, String> {
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    let result = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            &mut returned,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(accounting.ActiveProcesses == 0)
}

#[cfg(windows)]
fn wait_for_windows_job_drain(
    child: &mut WindowsChild,
    deadline: SystemTime,
) -> Result<bool, String> {
    loop {
        let root_exited = child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some();
        let empty = windows_job_empty(child.job.raw())?;
        if root_exited && empty {
            return Ok(true);
        }
        if SystemTime::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn windows_job() -> Result<WinHandle, String> {
    let job = WinHandle::new(unsafe { CreateJobObjectW(null(), null()) })?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(job)
}

#[cfg(windows)]
fn windows_spawn(bootstrap: &Bootstrap) -> Result<WindowsChild, String> {
    let job = windows_job()?;
    let application = wide(&bootstrap.command)?;
    let cwd = wide(&bootstrap.workdir)?;
    let environment = windows_environment(&bootstrap.env)?;
    let mut command_line = wide(
        &std::iter::once(bootstrap.command.as_str())
            .chain(bootstrap.args.iter().map(String::as_str))
            .map(quote_windows_arg)
            .collect::<Vec<_>>()
            .join(" "),
    )?;
    let (stdin, stdout, stderr, child_stdin, child_stdout, child_stderr, pty) =
        if bootstrap.mode == "pty" {
            let (console_input, parent_input) = pipe(true)?;
            let (parent_output, console_output) = pipe(false)?;
            let mut console = 0;
            let result = unsafe {
                CreatePseudoConsole(
                    COORD {
                        X: bootstrap.cols.unwrap_or(120).clamp(1, 1000) as i16,
                        Y: bootstrap.rows.unwrap_or(40).clamp(1, 1000) as i16,
                    },
                    console_input.raw(),
                    console_output.raw(),
                    0,
                    &mut console,
                )
            };
            drop(console_input);
            drop(console_output);
            if result < 0 {
                return Err(format!("CreatePseudoConsole failed: 0x{result:08x}"));
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                Some(WindowsPty {
                    console,
                    input: parent_input,
                    output: Some(parent_output),
                }),
            )
        } else {
            let (child_input, parent_input) = pipe(true)?;
            let (parent_output, child_output) = pipe(false)?;
            let (parent_error, child_error) = pipe(false)?;
            (
                Some(parent_input),
                Some(parent_output),
                Some(parent_error),
                Some(child_input),
                Some(child_output),
                Some(child_error),
                None,
            )
        };
    let mut inheritable_handles = [
        child_stdin.as_ref().map(WinHandle::raw),
        child_stdout.as_ref().map(WinHandle::raw),
        child_stderr.as_ref().map(WinHandle::raw),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let attribute_count = u32::from(pty.is_some()) + u32::from(!inheritable_handles.is_empty());
    let attribute_list = if attribute_count == 0 {
        None
    } else {
        Some(WindowsAttributeList::new(attribute_count)?)
    };
    let list = attribute_list
        .as_ref()
        .map(|attributes| attributes.list)
        .unwrap_or(null_mut());
    let mut pseudo_console = pty.as_ref().map(|pty| pty.console).unwrap_or(0);
    if pty.is_some()
        && unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                (&mut pseudo_console as *mut HPCON).cast(),
                size_of::<HPCON>(),
                null_mut(),
                null(),
            )
        } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if !inheritable_handles.is_empty()
        && unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inheritable_handles.as_mut_ptr().cast(),
                size_of_val(inheritable_handles.as_slice()),
                null_mut(),
                null(),
            )
        } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = list;
    if pty.is_none() {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_stdin.as_ref().expect("exec stdin").raw();
        startup.StartupInfo.hStdOutput = child_stdout.as_ref().expect("exec stdout").raw();
        startup.StartupInfo.hStdError = child_stderr.as_ref().expect("exec stderr").raw();
    }
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | if attribute_list.is_some() {
            EXTENDED_STARTUPINFO_PRESENT
        } else {
            0
        };
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            if inheritable_handles.is_empty() { 0 } else { 1 },
            flags,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    };
    drop(child_stdin);
    drop(child_stdout);
    drop(child_stderr);
    if created == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let process_handle = WinHandle::new(process.hProcess)?;
    let thread = WinHandle::new(process.hThread)?;
    if bootstrap.fault.as_deref() == Some("job_assign")
        || unsafe { AssignProcessToJobObject(job.raw(), process_handle.raw()) } == 0
    {
        // The child is still suspended and not in the Job. Kill and reap this owned handle.
        let _ = unsafe { TerminateProcess(process_handle.raw(), 1) };
        let _ = unsafe { WaitForSingleObject(process_handle.raw(), 1_000) };
        return Err("failed to assign suspended child to Job Object".into());
    }
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        let resume_error = std::io::Error::last_os_error().to_string();
        let mut child = WindowsChild {
            process: process_handle,
            pid: process.dwProcessId,
            job,
            stdin,
            stdout,
            stderr,
            pty,
            exit: None,
        };
        let cleanup = cleanup_unverified_windows_spawn(&mut child);
        return Err(format!("{resume_error}; {}", cleanup.message));
    }
    Ok(WindowsChild {
        process: process_handle,
        pid: process.dwProcessId,
        job,
        stdin,
        stdout,
        stderr,
        pty,
        exit: None,
    })
}

#[cfg(windows)]
struct WindowsSpawnCleanup {
    confirmed: bool,
    message: String,
}

#[cfg(windows)]
fn cleanup_unverified_windows_spawn(child: &mut WindowsChild) -> WindowsSpawnCleanup {
    let termination = child.terminate_job();
    let drained = wait_for_windows_job_drain(child, SystemTime::now() + TERMINATION_HARD_TIMEOUT);
    WindowsSpawnCleanup {
        confirmed: termination.is_ok() && drained == Ok(true),
        message: if termination.is_ok() && drained == Ok(true) {
            "unverified Windows spawn Job was terminated".into()
        } else {
            format!(
                "unverified Windows spawn cleanup is unknown: terminate={:?}; job={:?}",
                termination.as_ref().err(),
                drained
            )
        },
    }
}

#[cfg(unix)]
struct SpawnCleanup {
    confirmed: bool,
    direct_child_pid: u32,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpawnFailureReceipt {
    worker_id: String,
    worker_pid: u32,
    worker_process_identity: String,
    worker_control_token: String,
    direct_child_started: bool,
    direct_child_pid: Option<u32>,
    termination_confirmed: bool,
    message: String,
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

fn redact_tail(tail: String, secrets: &[String]) -> String {
    let characters: Vec<_> = tail.chars().collect();
    for secret in secrets {
        let secret: Vec<_> = secret.chars().collect();
        if characters.len() >= 4
            && characters.len() < secret.len()
            && characters == secret[..characters.len()]
        {
            return "[REDACTED]".into();
        }
    }
    redact(tail, secrets)
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
        redacted.push_str(&redact_tail(std::mem::take(tail), secrets));
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

fn write_spawn_failure(
    session_directory: &Path,
    bootstrap: &Bootstrap,
    descriptor: &Descriptor,
    direct_child_started: bool,
    direct_child_pid: Option<u32>,
    termination_confirmed: bool,
    message: &str,
) -> Result<(), String> {
    write_atomic(
        &session_directory.join("spawn-failure.json"),
        &serde_json::to_string(&SpawnFailureReceipt {
            worker_id: bootstrap.worker_id.clone(),
            worker_pid: std::process::id(),
            worker_process_identity: descriptor.process_identity.clone(),
            worker_control_token: bootstrap.worker_control_token.clone(),
            direct_child_started,
            direct_child_pid,
            termination_confirmed,
            message: message.into(),
        })
        .expect("spawn failure receipt serializes"),
    )
    .map_err(|error| format!("could not persist spawn failure receipt: {error}"))
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

#[cfg(all(not(target_os = "linux"), not(windows)))]
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

#[cfg(windows)]
fn containment_report(containment: &Containment) -> ContainmentReport {
    let drained = windows_job_empty(containment.job as HANDLE);
    ContainmentReport {
        platform: "windows_job".into(),
        status: match drained {
            Ok(true) => "windows_job_empty",
            Ok(false) => "windows_job_processes_remaining",
            Err(_) => "windows_job_unknown",
        }
        .into(),
        root_pid: containment.root_pid,
        process_group_id: None,
        session_id: None,
        root_start_identity: containment.root_start_identity.clone(),
        root_identity_verified: drained.is_ok(),
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
    report.status == "posix_best_effort_empty"
        || report.status == "windows_job_empty"
        || report.status == "not_applicable"
        // macOS has no process identity scan. A reaped direct child is terminal, but descendant
        // containment remains deliberately unavailable.
        || (cfg!(all(unix, not(target_os = "linux")))
            && report.status == "posix_containment_unknown")
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
    #[cfg(windows)]
    {
        let mut child = worker.child.lock().expect("child lock");
        let termination = child.terminate_job();
        let drained =
            wait_for_windows_job_drain(&mut child, SystemTime::now() + TERMINATION_HARD_TIMEOUT);
        drop(child);
        observe_exit(worker);
        let mut report = refresh_termination_confirmed(worker);
        let sent = termination.is_ok();
        match drained {
            Ok(true) => {}
            Ok(false) => report.status = "windows_job_processes_remaining".into(),
            Err(_) => report.status = "windows_job_unknown".into(),
        }
        let mut state = worker.state.lock().expect("state lock");
        state.termination_confirmed = state.root_exited && report.status == "windows_job_empty";
        drop(state);
        let root_exited = worker.state.lock().expect("state lock").root_exited;
        worker.state.lock().expect("state lock").termination = Some(TerminationResult {
            requested: true,
            term_signal_sent: sent,
            kill_signal_sent: sent,
            root_exited,
            containment: report,
        });
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = worker.child.lock().expect("child lock").kill();
    }
}

fn mark_termination(worker: &Arc<Worker>, reason: &str) {
    terminate_contained(worker, reason);
}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(|signal| format!("SIG{signal}"))
    }
}

#[cfg(windows)]
fn exit_signal(_: &WindowsExit) -> Option<String> {
    None
}

#[cfg(unix)]
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

#[cfg(windows)]
fn record_exit(worker: &Arc<Worker>, exit: WindowsExit) {
    let mut state = worker.state.lock().expect("state lock");
    if state.root_exited {
        return;
    }
    state.exit_code = exit.code();
    state.exit_signal = exit_signal(&exit);
    state.exit_reason.get_or_insert_with(|| "code".into());
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
    #[cfg(windows)]
    {
        let exit = worker
            .child
            .lock()
            .expect("child lock")
            .wait_for(TERMINATION_HARD_TIMEOUT);
        if let Ok(Some(exit)) = exit {
            record_exit(worker, exit);
        }
    }
    #[cfg(not(windows))]
    if !worker.state.lock().expect("state lock").root_exited {
        let exit = worker.child.lock().expect("child lock").wait();
        if let Ok(exit) = exit {
            record_exit(worker, exit);
        }
    }
}

#[cfg(unix)]
fn terminate_child_and_wait(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn cleanup_unverified_spawn(child: &mut Child) -> SpawnCleanup {
    let pid = child.id();
    #[cfg(target_os = "linux")]
    {
        let Some(identity) = child_start_identity(pid).ok() else {
            terminate_child_and_wait(child);
            return SpawnCleanup {
                confirmed: false,
                direct_child_pid: pid,
                message: "spawn containment could not verify the child identity; root was reaped but descendants are unknown".into(),
            };
        };
        let containment = Containment {
            root_pid: pid,
            process_group_id: Some(pid),
            session_id: Some(pid),
            root_start_identity: identity,
            known_members: Mutex::new(BTreeMap::new()),
            escaped_members: Mutex::new(BTreeMap::new()),
        };
        let (sent, _) = signal_contained(&containment, libc::SIGTERM);
        if sent {
            thread::sleep(TERMINATION_GRACE);
            let _ = signal_contained(&containment, libc::SIGKILL);
        } else {
            let _ = child.kill();
        }
        let _ = child.wait();
        let report = containment_report(&containment);
        return SpawnCleanup {
            confirmed: containment_drained(&report),
            direct_child_pid: pid,
            message: if containment_drained(&report) {
                "unverified spawn session was terminated".into()
            } else {
                format!(
                    "unverified spawn cleanup could not prove descendant termination: {}",
                    report.status
                )
            },
        };
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        terminate_child_and_wait(child);
        SpawnCleanup {
            confirmed: false,
            direct_child_pid: child.id(),
            message: "spawn containment verification is unavailable; direct child was reaped but descendants are unknown".into(),
        }
    }
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
fn pty_child(command: &mut Command, cols: u16, rows: u16) -> Result<(Child, File), String> {
    let mut master = -1;
    let mut slave = -1;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // openpty returned owned descriptors; every Command stream gets its own duplicate.
    let master = unsafe { File::from_raw_fd(master) };
    if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let slave = unsafe { File::from_raw_fd(slave) };
    let slave_fd = slave.as_raw_fd();
    let stdin = slave.try_clone().map_err(|error| error.to_string())?;
    let stdout = slave.try_clone().map_err(|error| error.to_string())?;
    let stderr = slave.try_clone().map_err(|error| error.to_string())?;
    command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|error| error.to_string())?;
    Ok((child, master))
}

#[cfg(unix)]
fn resize_terminal(worker: &Arc<Worker>, cols: u16, rows: u16) -> Result<(), WorkerError> {
    let terminal = worker.terminal.as_ref().ok_or(WorkerError {
        code: "process",
        message: "session is not a PTY".into(),
    })?;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe {
        libc::ioctl(
            terminal.lock().expect("terminal lock").as_raw_fd(),
            libc::TIOCSWINSZ,
            &size,
        )
    } == -1
    {
        return Err(WorkerError {
            code: "process",
            message: std::io::Error::last_os_error().to_string(),
        });
    }
    Ok(())
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

#[cfg(all(not(unix), not(windows)))]
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

#[cfg(windows)]
fn verify_containment(child: &mut WindowsChild) -> Result<Containment, String> {
    if windows_job_empty(child.job.raw())? {
        // A fast child can legitimately leave its assigned Job before this first query.
        child
            .try_wait()
            .map_err(|error| error.to_string())?
            .ok_or("assigned child is missing from its Job Object")?;
    }
    Ok(Containment {
        root_pid: child.id(),
        process_group_id: None,
        session_id: None,
        root_start_identity: format!("windows:{}:job", child.id()),
        job: child.job.raw() as usize,
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
        let available = if worker.mode == "exec" {
            worker.max_output_bytes.saturating_sub(state.retained_bytes)
        } else {
            data.len()
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
            let chunk = if let Some(previous) = state.chunks.last_mut() {
                if previous.end_sequence == start && previous.data.len() + kept.len() <= 64 * 1024 {
                    previous.end_sequence = end;
                    previous.timestamp = now();
                    previous.data.push_str(kept);
                    previous.clone()
                } else {
                    JournalChunk {
                        start_sequence: start,
                        end_sequence: end,
                        timestamp: now(),
                        data: kept.into(),
                    }
                }
            } else {
                JournalChunk {
                    start_sequence: start,
                    end_sequence: end,
                    timestamp: now(),
                    data: kept.into(),
                }
            };
            let path = worker
                .output_directory
                .join(format!("{:020}.json", chunk.start_sequence));
            if let Err(error) = write_atomic(
                &path,
                &serde_json::to_string(&chunk).expect("journal chunk serializes"),
            ) {
                state.storage_failure = Some(error.to_string());
                state.exit_reason = Some("storage_failure".into());
                terminate = Some("storage_failure");
            } else {
                if state
                    .chunks
                    .last()
                    .is_none_or(|previous| previous.start_sequence != chunk.start_sequence)
                {
                    state.chunks.push(chunk);
                }
                state.next_sequence = end;
                state.retained_bytes += kept.len();
                if worker.mode == "exec" {
                    if stdout {
                        state.stdout.push_str(kept);
                        state.stdout_bytes += kept.len();
                    } else {
                        state.stderr.push_str(kept);
                        state.stderr_bytes += kept.len();
                    }
                }
                while worker.mode == "pty" && state.retained_bytes > worker.max_output_bytes {
                    let removed = state.chunks.remove(0);
                    if let Err(error) = remove_file(
                        worker
                            .output_directory
                            .join(format!("{:020}.json", removed.start_sequence)),
                    ) {
                        state.storage_failure = Some(error.to_string());
                        state.exit_reason = Some("storage_failure".into());
                        terminate = Some("storage_failure");
                        break;
                    }
                    state.retained_bytes -= removed.data.len();
                    state.output_truncated = true;
                }
                state.first_retained_sequence = state
                    .chunks
                    .first()
                    .map(|chunk| chunk.start_sequence)
                    .unwrap_or(state.next_sequence);
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
                    if (worker.mode == "pty" && error.raw_os_error() == Some(libc::EIO))
                        || (cfg!(windows) && error.raw_os_error() == Some(109))
                    {
                        mark_reader_eof(&worker, stdout);
                    } else {
                        let mut state = worker.state.lock().expect("state lock");
                        mark_reader_failure(&mut state, stdout, error.to_string());
                    }
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

#[cfg(windows)]
fn terminal_reader_windows(worker: Arc<Worker>, mut output: WinHandle) {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        let mut tail = String::new();
        loop {
            match output.read(&mut buffer) {
                Ok(0) => {
                    append_output(
                        &worker,
                        true,
                        redact_stream(String::new(), &mut tail, &worker.secrets, true),
                    );
                    mark_reader_eof(&worker, true);
                    return;
                }
                Err(error) => {
                    append_output(
                        &worker,
                        true,
                        redact_stream(String::new(), &mut tail, &worker.secrets, true),
                    );
                    if error.raw_os_error() == Some(109) {
                        mark_reader_eof(&worker, true);
                    } else {
                        let mut state = worker.state.lock().expect("state lock");
                        mark_reader_failure(&mut state, true, error.to_string());
                    }
                    return;
                }
                Ok(size) => append_output(
                    &worker,
                    true,
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

#[cfg(unix)]
fn append_terminal_output(worker: &Arc<Worker>, data: String, finish: bool) {
    let mut tail = worker
        .terminal_redaction_tail
        .lock()
        .expect("terminal redaction tail lock");
    append_output(
        worker,
        true,
        redact_stream(data, &mut tail, &worker.secrets, finish),
    );
}

#[cfg(unix)]
fn flush_terminal_redaction_tail(worker: &Arc<Worker>) {
    append_terminal_output(worker, String::new(), true);
}

#[cfg(unix)]
fn terminal_reader(worker: Arc<Worker>, mut terminal: File) {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            let arrival = worker.arrival.lock().expect("arrival lock");
            if worker
                .pause_terminal_reader_until_write
                .load(Ordering::Acquire)
            {
                drop(arrival);
                thread::yield_now();
                continue;
            }
            match terminal.read(&mut buffer) {
                Ok(0) => {
                    append_terminal_output(&worker, String::new(), true);
                    mark_reader_eof(&worker, true);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    append_terminal_output(&worker, String::new(), true);
                    if error.raw_os_error() == Some(libc::EIO) {
                        mark_reader_eof(&worker, true);
                    } else {
                        let mut state = worker.state.lock().expect("state lock");
                        mark_reader_failure(&mut state, true, error.to_string());
                    }
                    return;
                }
                Ok(size) => append_terminal_output(
                    &worker,
                    String::from_utf8_lossy(&buffer[..size]).into_owned(),
                    false,
                ),
            }
            drop(arrival);
            thread::sleep(Duration::from_millis(1));
        }
    });
}

#[cfg(unix)]
fn drain_terminal(worker: &Arc<Worker>, terminal: &mut File) {
    let mut buffer = [0_u8; 8192];
    loop {
        match terminal.read(&mut buffer) {
            Ok(0) | Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(error) if error.raw_os_error() == Some(libc::EIO) => return,
            Err(error) => {
                let mut state = worker.state.lock().expect("state lock");
                mark_reader_failure(&mut state, true, error.to_string());
                return;
            }
            Ok(size) => append_terminal_output(
                worker,
                String::from_utf8_lossy(&buffer[..size]).into_owned(),
                false,
            ),
        }
    }
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
            if worker
                .deadline
                .is_some_and(|deadline| SystemTime::now() >= deadline)
            {
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
    let containment_unavailable = containment.status == "posix_containment_unknown"
        || containment.status == "windows_job_unknown";
    let macos_direct_exit = cfg!(all(unix, not(target_os = "linux"))) && state.root_exited;
    let status = if (terminal || (state.root_exited && containment_unavailable))
        && (state.storage_failure.is_some()
            || state.output_incomplete
            || (containment_unavailable && !macos_direct_exit))
    {
        "lost"
    } else if terminal {
        "exited"
    } else {
        "running"
    };
    json!({
        "status": status, "pid": pid, "mode": worker.mode, "stdout": state.stdout, "stderr": state.stderr,
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

    #[cfg(unix)]
    struct FailingReader;

    #[cfg(unix)]
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
    fn redaction_tail_flushes_before_an_input_boundary() {
        let mut tail = String::new();
        assert_eq!(
            redact_stream(
                "old-match".into(),
                &mut tail,
                &["tail-secret".into()],
                false
            ),
            ""
        );
        assert_eq!(
            redact_stream(String::new(), &mut tail, &["tail-secret".into()], true),
            "old-match"
        );
        assert!(tail.is_empty());
        assert_eq!(
            redact_stream("tail-sec".into(), &mut tail, &["tail-secret".into()], false),
            ""
        );
        assert_eq!(
            redact_stream(String::new(), &mut tail, &["tail-secret".into()], true),
            "[REDACTED]"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_environment_rejects_non_ascii_or_duplicate_keys_and_preserves_unicode_values() {
        let duplicate =
            BTreeMap::from([("PATH".into(), "one".into()), ("Path".into(), "two".into())]);
        assert!(windows_environment(&duplicate).is_err());
        assert!(
            windows_environment(&BTreeMap::from([("\u{96ea}".into(), "value".into())])).is_err()
        );
        let environment = windows_environment(&BTreeMap::from([
            ("Zebra".into(), "value".into()),
            ("alpha".into(), "snowman \u{2603}".into()),
        ]))
        .expect("build Unicode environment");
        let entries =
            String::from_utf16(&environment[..environment.len() - 1]).expect("decode environment");
        assert_eq!(entries, "alpha=snowman \u{2603}\0Zebra=value\0");
        assert_eq!(quote_windows_arg("\u{96ea} space"), "\"\u{96ea} space\"");
        assert_eq!(
            wide("C:\\tmp\\\u{96ea}")
                .expect("encode Unicode cwd")
                .last(),
            Some(&0)
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

    #[cfg(unix)]
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
            #[cfg(unix)]
            terminal: None,
            #[cfg(unix)]
            arrival: Mutex::new(()),
            #[cfg(unix)]
            terminal_redaction_tail: Mutex::new(String::new()),
            #[cfg(unix)]
            pause_terminal_reader_until_write: AtomicBool::new(false),
            state: Mutex::new(State {
                started_at: now(),
                ..State::default()
            }),
            secrets: Vec::new(),
            output_directory: output_directory.clone(),
            max_output_bytes: MAX_OUTPUT_BYTES,
            deadline: Some(SystemTime::now() - Duration::from_millis(1)),
            containment: Containment {
                root_pid: 0,
                process_group_id: None,
                session_id: None,
                root_start_identity: "test".into(),
                known_members: Mutex::new(BTreeMap::new()),
                escaped_members: Mutex::new(BTreeMap::new()),
            },
            mode: "exec".into(),
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

    #[cfg(unix)]
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

#[cfg(windows)]
fn wait_for_final_snapshot(worker: &Arc<Worker>) -> Value {
    // terminate_contained already performed the bounded Job drain poll.
    snapshot(worker)
}

#[cfg(not(windows))]
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
        "health" => Ok((json!({"protocolVersion": 3}), false)),
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
            #[cfg(unix)]
            if let Some(terminal) = &worker.terminal {
                let _arrival = worker.arrival.lock().expect("arrival lock");
                let mut terminal = terminal.lock().expect("terminal lock");
                drain_terminal(worker, &mut terminal);
                flush_terminal_redaction_tail(worker);
                terminal
                    .write_all(data.as_bytes())
                    .map_err(|error| WorkerError {
                        code: "process",
                        message: error.to_string(),
                    })?;
                terminal.flush().map_err(|error| WorkerError {
                    code: "process",
                    message: error.to_string(),
                })?;
                let arrival_sequence = worker.state.lock().expect("state lock").next_sequence;
                worker
                    .pause_terminal_reader_until_write
                    .store(false, Ordering::Release);
                return Ok((
                    json!({"acceptedBytes": data.len(), "arrivalSequence": arrival_sequence}),
                    false,
                ));
            }
            #[cfg(windows)]
            if let Some(pty) = worker.child.lock().expect("child lock").pty.as_ref() {
                let input = pty.input.raw();
                let mut written = 0;
                if unsafe {
                    WriteFile(
                        input,
                        data.as_ptr(),
                        data.len().min(u32::MAX as usize) as u32,
                        &mut written,
                        null_mut(),
                    )
                } == 0
                {
                    return Err(WorkerError {
                        code: "process",
                        message: std::io::Error::last_os_error().to_string(),
                    });
                }
                let arrival_sequence = worker.state.lock().expect("state lock").next_sequence;
                return Ok((
                    json!({"acceptedBytes": written, "arrivalSequence": arrival_sequence}),
                    false,
                ));
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
            let arrival_sequence = worker.state.lock().expect("state lock").next_sequence;
            Ok((
                json!({"acceptedBytes": data.len(), "arrivalSequence": arrival_sequence}),
                false,
            ))
        }
        "resize" => {
            if worker.mode != "pty" {
                return Err(WorkerError {
                    code: "process",
                    message: "session is not a PTY".into(),
                });
            }
            let cols = request
                .get("cols")
                .and_then(Value::as_u64)
                .filter(|value| (1..=1000).contains(value))
                .ok_or(WorkerError {
                    code: "validation",
                    message: "cols must be an integer from 1 to 1000".into(),
                })? as u16;
            let rows = request
                .get("rows")
                .and_then(Value::as_u64)
                .filter(|value| (1..=1000).contains(value))
                .ok_or(WorkerError {
                    code: "validation",
                    message: "rows must be an integer from 1 to 1000".into(),
                })? as u16;
            #[cfg(unix)]
            {
                resize_terminal(worker, cols, rows)?;
                Ok((json!({"cols": cols, "rows": rows}), false))
            }
            #[cfg(not(unix))]
            {
                #[cfg(windows)]
                {
                    let child = worker.child.lock().expect("child lock");
                    let pty = child.pty.as_ref().ok_or(WorkerError {
                        code: "process",
                        message: "session is not a PTY".into(),
                    })?;
                    let result = unsafe {
                        ResizePseudoConsole(
                            pty.console,
                            COORD {
                                X: cols as i16,
                                Y: rows as i16,
                            },
                        )
                    };
                    if result < 0 {
                        return Err(WorkerError {
                            code: "process",
                            message: format!("ResizePseudoConsole failed: 0x{result:08x}"),
                        });
                    }
                    Ok((json!({"cols": cols, "rows": rows}), false))
                }
                #[cfg(not(windows))]
                Err(WorkerError {
                    code: "process",
                    message: "native PTY resize is unavailable on this platform".into(),
                })
            }
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
    if bootstrap.mode != "exec" && bootstrap.mode != "pty" {
        return Err("mode must be exec or pty".into());
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
        protocol_version: 3,
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
    #[cfg(unix)]
    let mut command = Command::new(&bootstrap.command);
    #[cfg(unix)]
    command
        .args(&bootstrap.args)
        .current_dir(&bootstrap.workdir)
        .env_clear()
        .envs(&bootstrap.env);
    #[cfg(unix)]
    let spawned = if bootstrap.mode == "pty" {
        pty_child(
            &mut command,
            bootstrap.cols.unwrap_or(120).clamp(1, 1000),
            bootstrap.rows.unwrap_or(40).clamp(1, 1000),
        )
        .map(|(child, terminal)| (child, Some(terminal)))
    } else {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        contain_child(&mut command);
        command
            .spawn()
            .map(|child| (child, None))
            .map_err(|error| error.to_string())
    };
    #[cfg(windows)]
    let spawned = { windows_spawn(&bootstrap) };
    #[cfg(all(not(unix), not(windows)))]
    let spawned = Err("native worker is unavailable on this platform".into());
    #[cfg(unix)]
    let (mut child, terminal) = match spawned {
        Ok(spawned) => spawned,
        Err(error) => {
            write_spawn_failure(
                &session_directory,
                &bootstrap,
                &descriptor,
                false,
                None,
                true,
                &error,
            )?;
            let _ = remove_file(&descriptor_path);
            return Err(error);
        }
    };
    #[cfg(windows)]
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            write_spawn_failure(
                &session_directory,
                &bootstrap,
                &descriptor,
                false,
                None,
                true,
                &error,
            )?;
            let _ = remove_file(&descriptor_path);
            return Err(error);
        }
    };
    #[cfg(all(not(unix), not(windows)))]
    let mut child: Child = match spawned {
        Ok(child) => child,
        Err(error) => return Err(error),
    };
    let containment = match if bootstrap.fault.as_deref() == Some("unverified_containment") {
        Err("injected containment verification failure".into())
    } else {
        #[cfg(windows)]
        {
            verify_containment(&mut child)
        }
        #[cfg(not(windows))]
        {
            verify_containment(child.id())
        }
    } {
        Ok(containment) => containment,
        Err(error) => {
            #[cfg(windows)]
            let child_pid = child.id();
            #[cfg(unix)]
            let cleanup = cleanup_unverified_spawn(&mut child);
            #[cfg(windows)]
            {
                let cleanup = cleanup_unverified_windows_spawn(&mut child);
                write_spawn_failure(
                    &session_directory,
                    &bootstrap,
                    &descriptor,
                    true,
                    Some(child_pid),
                    cleanup.confirmed,
                    &format!("{error}; {}", cleanup.message),
                )?;
            }
            #[cfg(unix)]
            write_spawn_failure(
                &session_directory,
                &bootstrap,
                &descriptor,
                true,
                Some(cleanup.direct_child_pid),
                cleanup.confirmed,
                &cleanup.message,
            )?;
            let _ = remove_file(&descriptor_path);
            #[cfg(unix)]
            return Err(format!("{error}; {}", cleanup.message));
            #[cfg(windows)]
            return Err(error);
        }
    };
    #[cfg(windows)]
    let (stdout, stderr) = if bootstrap.mode == "pty" {
        (None, None)
    } else {
        (child.stdout.take(), child.stderr.take())
    };
    #[cfg(unix)]
    let (stdout, stderr) = if bootstrap.mode == "pty" {
        (None, None)
    } else {
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                #[cfg(unix)]
                let cleanup = cleanup_unverified_spawn(&mut child);
                #[cfg(windows)]
                {
                    let _ = child.terminate_job();
                    let _ = child.wait();
                }
                #[cfg(unix)]
                write_spawn_failure(
                    &session_directory,
                    &bootstrap,
                    &descriptor,
                    true,
                    Some(cleanup.direct_child_pid),
                    cleanup.confirmed,
                    &cleanup.message,
                )?;
                #[cfg(windows)]
                write_spawn_failure(
                    &session_directory,
                    &bootstrap,
                    &descriptor,
                    true,
                    Some(child.id()),
                    true,
                    "missing stdout",
                )?;
                let _ = remove_file(&descriptor_path);
                return Err("missing stdout".into());
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                #[cfg(unix)]
                let cleanup = cleanup_unverified_spawn(&mut child);
                #[cfg(windows)]
                {
                    let _ = child.terminate_job();
                    let _ = child.wait();
                }
                #[cfg(unix)]
                write_spawn_failure(
                    &session_directory,
                    &bootstrap,
                    &descriptor,
                    true,
                    Some(cleanup.direct_child_pid),
                    cleanup.confirmed,
                    &cleanup.message,
                )?;
                #[cfg(windows)]
                write_spawn_failure(
                    &session_directory,
                    &bootstrap,
                    &descriptor,
                    true,
                    Some(child.id()),
                    true,
                    "missing stderr",
                )?;
                let _ = remove_file(&descriptor_path);
                return Err("missing stderr".into());
            }
        };
        (Some(stdout), Some(stderr))
    };
    let worker = Arc::new(Worker {
        child: Mutex::new(child),
        #[cfg(unix)]
        terminal: terminal.map(Mutex::new),
        #[cfg(unix)]
        arrival: Mutex::new(()),
        #[cfg(unix)]
        terminal_redaction_tail: Mutex::new(String::new()),
        #[cfg(unix)]
        pause_terminal_reader_until_write: AtomicBool::new(
            bootstrap.fault.as_deref() == Some("pause_terminal_reader_until_write"),
        ),
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
        deadline: bootstrap
            .timeout_seconds
            .map(|seconds| SystemTime::now() + Duration::from_secs(seconds)),
        containment,
        mode: bootstrap.mode.clone(),
    });
    if bootstrap.mode == "pty" {
        #[cfg(unix)]
        {
            let terminal = match worker
                .terminal
                .as_ref()
                .expect("PTY terminal")
                .lock()
                .expect("terminal lock")
                .try_clone()
            {
                Ok(terminal) => terminal,
                Err(error) => {
                    let mut child = worker.child.lock().expect("child lock");
                    let cleanup = cleanup_unverified_spawn(&mut child);
                    write_spawn_failure(
                        &session_directory,
                        &bootstrap,
                        &descriptor,
                        true,
                        Some(cleanup.direct_child_pid),
                        cleanup.confirmed,
                        &cleanup.message,
                    )?;
                    let _ = remove_file(&descriptor_path);
                    return Err(error.to_string());
                }
            };
            terminal_reader(worker.clone(), terminal);
            mark_reader_eof(&worker, false); // A PTY intentionally has one merged output stream.
        }
        #[cfg(windows)]
        {
            let mut child = worker.child.lock().expect("child lock");
            let pty = child.pty.as_mut().expect("Windows PTY");
            let output = pty.output.take().expect("Windows PTY output");
            terminal_reader_windows(worker.clone(), output);
            mark_reader_eof(&worker, false);
        }
    } else {
        reader(worker.clone(), stdout.expect("exec stdout"), true);
        reader(worker.clone(), stderr.expect("exec stderr"), false);
    }
    monitor(worker.clone());
    let shutdown = Arc::new(AtomicBool::new(false));
    let rollback = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        let rollback = rollback.clone();
        let token = bootstrap.worker_control_token.clone();
        thread::spawn(move || {
            // The daemon may restart and close its inherited stdin. EOF is not worker ownership.
            match control(&mut std::io::stdin(), &token) {
                Ok(control) if control.operation == "rollback" => {
                    rollback.store(true, Ordering::Release)
                }
                _ => return,
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
