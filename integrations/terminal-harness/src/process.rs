use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, Command};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout_at};
use tracing::debug;

use crate::{HarnessError, Outcome, RunFailure, RunnerEvent, TRACE_TARGET};

const STDERR_CAPTURE_BYTES: usize = 4096;
const POST_EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(unix)]
struct ProcessGroupGuard {
    pgid: Option<i32>,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(child: &Child) -> Self {
        Self {
            pgid: child.id().and_then(|pid| i32::try_from(pid).ok()),
        }
    }

    // Observe exit without reaping: the unreaped leader reserves its PID/PGID
    // until we have signalled the group, even if every descendant exits first.
    fn has_exited(&self) -> std::io::Result<bool> {
        let pgid = self.pgid.expect("process group is still owned");
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pgid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn terminate(&self) {
        if let Some(pgid) = self.pgid {
            // The caller must not reap the leader until after this signal.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
    }

    fn disarm(&mut self) {
        self.pgid = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        let Some(pgid) = self.pgid else {
            return;
        };
        // Cancellation has no later await point for normal cleanup. Kill the
        // dedicated group, then synchronously reap its direct child.
        // Descendants are reparented and reaped by the host.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
            let mut status = 0;
            loop {
                let result = libc::waitpid(pgid, &mut status, 0);
                if result == pgid
                    || result == -1
                        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    break;
                }
            }
        }
    }
}

#[cfg(not(unix))]
struct ProcessGroupGuard;

#[cfg(not(unix))]
impl ProcessGroupGuard {
    fn new(_child: &Child) -> Self {
        Self
    }

    fn disarm(&mut self) {}
}

async fn wait_for_child_and_cleanup(
    child: &mut Child,
    process_group: &mut ProcessGroupGuard,
) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(unix)]
    {
        let mut delay = Duration::from_millis(10);
        while !process_group.has_exited()? {
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_millis(250));
        }
        process_group.terminate();
    }
    let status = child.wait().await?;
    process_group.disarm();
    Ok(status)
}

/// How one backend prompt reaches the child process.
pub enum PromptTransport {
    /// Write the prompt to the child's standard input and then close it.
    Stdin(String),
    /// Append an explicit option delimiter and the prompt to the argument list.
    DelimitedArgument {
        /// Backend-specific delimiter that prevents prompt option injection.
        delimiter: &'static str,
        /// Prompt appended immediately after `delimiter`.
        prompt: String,
    },
}

impl fmt::Debug for PromptTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdin(prompt) => formatter
                .debug_struct("Stdin")
                .field("prompt_len", &prompt.len())
                .finish(),
            Self::DelimitedArgument { prompt, .. } => formatter
                .debug_struct("DelimitedArgument")
                .field("prompt_len", &prompt.len())
                .finish(),
        }
    }
}

/// One process-local environment mutation applied before child spawn.
pub enum EnvironmentChange {
    /// Remove an inherited environment variable.
    Remove(&'static str),
    /// Set an environment variable for only the spawned child.
    Set {
        /// Environment variable name.
        name: &'static str,
        /// Environment variable value, excluded from diagnostics.
        value: String,
    },
}

/// Typed child-process configuration for one JSONL backend invocation.
pub struct ProcessSpec {
    /// Backend executable name or path.
    pub executable: String,
    /// Backend-specific arguments excluding a delimited prompt.
    pub args: Vec<String>,
    /// Validated working directory.
    pub cwd: PathBuf,
    /// Process-local environment changes.
    pub environment: Vec<EnvironmentChange>,
    /// Backend-specific prompt transport.
    pub prompt: PromptTransport,
    /// Privacy-safe tracing method name.
    pub trace_method: &'static str,
    /// Privacy-safe backend name.
    pub backend_name: &'static str,
    /// Total wall-clock budget, including reply-channel backpressure.
    pub total_timeout: Duration,
    /// Presentation-idle interval. Expiry reports unknown liveness but never kills work.
    pub idle_timeout: Duration,
}

impl fmt::Debug for ProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessSpec")
            .field("argument_count", &self.args.len())
            .field("environment_change_count", &self.environment.len())
            .field("prompt", &self.prompt)
            .field("trace_method", &self.trace_method)
            .field("backend_name", &self.backend_name)
            .field("total_timeout", &self.total_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

/// One strictly decoded backend JSONL event understood by the shared runner.
#[derive(PartialEq, Eq)]
pub enum ParsedEvent {
    /// A durable backend session id was observed.
    Session(String),
    /// One completed assistant-text item is ready for forwarding.
    Text(String),
    /// A sanitized backend failure classification was observed.
    Error {
        /// Optional session id carried by the backend's error event.
        session_id: Option<String>,
        /// Sanitized error classification; never a raw backend message.
        summary: String,
    },
    /// A failed turn whose backend contract explicitly proves no side effects occurred.
    FailedWithoutSideEffects {
        /// Optional durable session id.
        session_id: Option<String>,
        /// Sanitized error classification.
        summary: String,
    },
    /// A valid event that has no durable connector effect.
    Ignored,
}

impl fmt::Debug for ParsedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(_) => formatter
                .debug_struct("Session")
                .field("session_present", &true)
                .finish(),
            Self::Text(text) => formatter
                .debug_struct("Text")
                .field("text_len", &text.len())
                .finish(),
            Self::Error {
                session_id,
                summary,
            } => formatter
                .debug_struct("Error")
                .field("session_present", &session_id.is_some())
                .field("summary_len", &summary.len())
                .finish(),
            Self::FailedWithoutSideEffects {
                session_id,
                summary,
            } => formatter
                .debug_struct("FailedWithoutSideEffects")
                .field("session_present", &session_id.is_some())
                .field("summary_len", &summary.len())
                .finish(),
            Self::Ignored => formatter.write_str("Ignored"),
        }
    }
}

/// Runs one JSONL child process while keeping event decoding backend-specific.
pub async fn run_jsonl_process<Parse, ParseError>(
    spec: ProcessSpec,
    tx: mpsc::Sender<RunnerEvent>,
    mut parse_event: Parse,
) -> std::result::Result<Outcome, RunFailure>
where
    Parse: FnMut(&str) -> std::result::Result<ParsedEvent, ParseError>,
{
    let ProcessSpec {
        executable,
        args,
        cwd,
        environment,
        prompt,
        trace_method,
        backend_name,
        total_timeout,
        idle_timeout,
    } = spec;
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for change in environment {
        match change {
            EnvironmentChange::Remove(name) => {
                command.env_remove(name);
            }
            EnvironmentChange::Set { name, value } => {
                command.env(name, value);
            }
        }
    }
    match &prompt {
        PromptTransport::Stdin(_) => {
            command.stdin(Stdio::piped());
        }
        PromptTransport::DelimitedArgument { delimiter, prompt } => {
            command.arg(delimiter).arg(prompt).stdin(Stdio::null());
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().process_group(0);
    }

    let mut child = command.spawn().map_err(|_| RunFailure {
        error: HarnessError::BackendSpawn,
        observed_session: None,
    })?;
    let mut process_group = ProcessGroupGuard::new(&child);
    let total_deadline = Instant::now() + total_timeout;
    let mut writer_task = match prompt {
        PromptTransport::Stdin(prompt) => match child.stdin.take() {
            Some(stdin) => Some(write_stdin(stdin, prompt)),
            None => {
                kill_and_reap(&mut child, &mut process_group).await;
                return Err(spawn_failure());
            }
        },
        PromptTransport::DelimitedArgument { .. } => None,
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            cleanup_missing_pipe(&mut child, &mut process_group, writer_task.as_mut()).await;
            return Err(spawn_failure());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            cleanup_missing_pipe(&mut child, &mut process_group, writer_task.as_mut()).await;
            return Err(spawn_failure());
        }
    };
    let stderr_snapshot = Arc::new(Mutex::new(String::new()));
    let mut stderr_task = tokio::spawn(capture_stderr(stderr, stderr_snapshot.clone()));
    let started = StdInstant::now();
    let mut observed_session = None;
    let mut error_summary = None;
    let mut no_side_effects_proven = false;
    let mut idle_deadline = Instant::now() + idle_timeout;
    let mut reported_liveness_unknown = false;

    let lifecycle_result = timeout_at(total_deadline, async {
        let mut lines = BufReader::new(stdout).lines();
        let mut child_status = None;
        let mut post_exit_deadline = None;
        // Preserve exit polling and its backoff while stdout is active.
        let child_exit = wait_for_child_and_cleanup(&mut child, &mut process_group);
        tokio::pin!(child_exit);
        loop {
            // Buffered lines may complete without touching the I/O driver.
            // Keep timers and other tasks live even under continuous output.
            tokio::task::consume_budget().await;
            let line = tokio::select! {
                biased;
                _ = sleep_until(post_exit_deadline.unwrap_or(total_deadline)), if post_exit_deadline.is_some() => break,
                status = &mut child_exit, if child_status.is_none() => {
                    child_status = Some(status.map_err(HarnessError::from)?);
                    post_exit_deadline = Some(Instant::now() + POST_EXIT_DRAIN_TIMEOUT);
                    // The pipe can still contain final events even when its readiness
                    // notification loses the race to exit observation. Drain to EOF.
                    continue;
                },
                line = lines.next_line() => Some(line),
                _ = sleep_until(idle_deadline) => {
                    if !reported_liveness_unknown {
                        tx.send(RunnerEvent::LivenessUnknown)
                            .await
                            .map_err(|_| HarnessError::BackendStream)?;
                        reported_liveness_unknown = true;
                    }
                    idle_deadline = Instant::now() + idle_timeout;
                    continue;
                }
            };
            let line = match line.expect("line branch returns a value") {
                Err(_) => return Err(HarnessError::BackendStream),
                Ok(Some(line)) => line,
                Ok(None) => break,
            };
            if !line.is_empty() {
                match parse_event(&line) {
                    Ok(ParsedEvent::Session(session_id)) => {
                        if observed_session.is_none() && !session_id.is_empty() {
                            observed_session = Some(session_id);
                        }
                    }
                    Ok(ParsedEvent::Text(text)) => {
                        if !text.trim().is_empty() {
                            // Reset below only after bounded backpressure clears. The total
                            // deadline, not the idle deadline, covers intentional send waits.
                            tx.send(RunnerEvent::Text(text))
                                .await
                                .map_err(|_| HarnessError::BackendStream)?;
                        }
                    }
                    Ok(ParsedEvent::Error {
                        session_id,
                        summary,
                    }) => {
                        if observed_session.is_none()
                            && let Some(session_id) = session_id.filter(|id| !id.is_empty())
                        {
                            observed_session = Some(session_id);
                        }
                        if error_summary.is_none() {
                            error_summary = Some(summary);
                        }
                    }
                    Ok(ParsedEvent::FailedWithoutSideEffects {
                        session_id,
                        summary,
                    }) => {
                        if observed_session.is_none()
                            && let Some(session_id) = session_id.filter(|id| !id.is_empty())
                        {
                            observed_session = Some(session_id);
                        }
                        if error_summary.is_none() {
                            error_summary = Some(summary);
                        }
                        no_side_effects_proven = true;
                    }
                    Ok(ParsedEvent::Ignored) => {}
                    Err(_) => debug!(
                        target: TRACE_TARGET,
                        method = trace_method,
                        backend = backend_name,
                        error_kind = "json",
                        "dropping undecodable backend event"
                    ),
                }
            }
            idle_deadline = Instant::now() + idle_timeout;
        };

        let completion = async {
            let status = match child_status {
                Some(status) => status,
                None => (&mut child_exit).await.map_err(HarnessError::from)?,
            };
            let drain_deadline = post_exit_deadline
                .unwrap_or_else(|| Instant::now() + POST_EXIT_DRAIN_TIMEOUT);
            let drain = timeout_at(drain_deadline, async {
                let writer = async {
                    match writer_task.as_mut() {
                        Some(task) => Some(task.await),
                        None => None,
                    }
                };
                tokio::join!(writer, &mut stderr_task)
            }).await;
            let (writer, stderr) = match drain {
                Ok(drained) => drained,
                Err(_) => {
                    // Escaped descendants may retain pipe handles after their
                    // leader and owned process group are gone. Preserve the
                    // leader's outcome instead of holding its lane indefinitely.
                    if let Some(task) = writer_task.as_mut() {
                        task.abort();
                        if !task.is_finished() { let _ = task.await; }
                    }
                    stderr_task.abort();
                    if !stderr_task.is_finished() { let _ = (&mut stderr_task).await; }
                    return Ok((status, stderr_snapshot.lock().await.clone()));
                }
            };
            let stderr = stderr.map_err(HarnessError::from)?;
            if let Some(writer) = writer {
                match writer.map_err(HarnessError::from)? {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => debug!(
                        target: TRACE_TARGET,
                        method = trace_method,
                        backend = backend_name,
                        error_kind = "stdin_closed",
                        "backend closed stdin before draining the prompt"
                    ),
                    Err(_) => return Err(HarnessError::BackendStream),
                }
            }
            Ok::<_, HarnessError>((status, stderr))
        };
        tokio::pin!(completion);
        let (status, stderr) = loop {
            tokio::select! {
                result = &mut completion => break result?,
                _ = sleep_until(idle_deadline) => {
                    if !reported_liveness_unknown {
                        tx.send(RunnerEvent::LivenessUnknown)
                            .await
                            .map_err(|_| HarnessError::BackendStream)?;
                        reported_liveness_unknown = true;
                    }
                    idle_deadline = Instant::now() + idle_timeout;
                }
            }
        };
        Ok::<_, HarnessError>(Outcome {
            observed_session: observed_session.clone(),
            exit_code: status.code(),
            error_summary,
            no_side_effects_proven,
            stderr: strip_ansi(stderr.trim()),
            elapsed_ms: started.elapsed().as_millis(),
        })
    })
    .await;

    match lifecycle_result {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => {
            cleanup_failed_run(
                &mut child,
                &mut process_group,
                &mut stderr_task,
                writer_task.as_mut(),
            )
            .await;
            Err(RunFailure {
                error,
                observed_session,
            })
        }
        Err(_) => {
            cleanup_failed_run(
                &mut child,
                &mut process_group,
                &mut stderr_task,
                writer_task.as_mut(),
            )
            .await;
            Err(RunFailure {
                error: HarnessError::BackendTimedOut,
                observed_session,
            })
        }
    }
}

fn spawn_failure() -> RunFailure {
    RunFailure {
        error: HarnessError::BackendSpawn,
        observed_session: None,
    }
}

async fn cleanup_missing_pipe(
    child: &mut Child,
    process_group: &mut ProcessGroupGuard,
    writer_task: Option<&mut JoinHandle<std::io::Result<()>>>,
) {
    if let Some(task) = writer_task {
        task.abort();
    }
    kill_and_reap(child, process_group).await;
}

/// Writes and closes backend stdin concurrently with stdout consumption.
fn write_stdin(stdin: ChildStdin, prompt: String) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        let mut stdin = stdin;
        stdin.write_all(prompt.as_bytes()).await?;
        stdin.shutdown().await
    })
}

/// Captures a bounded prefix of backend stderr.
async fn capture_stderr(stderr: ChildStderr, captured: Arc<Mutex<String>>) -> String {
    capture_bounded_shared(stderr, captured).await
}

#[cfg(test)]
async fn capture_bounded(reader: impl AsyncRead + Unpin) -> String {
    capture_bounded_shared(reader, Arc::new(Mutex::new(String::new()))).await
}

async fn capture_bounded_shared(
    mut reader: impl AsyncRead + Unpin,
    captured: Arc<Mutex<String>>,
) -> String {
    let mut buf = [0_u8; 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let mut captured = captured.lock().await;
                if captured.len() < STDERR_CAPTURE_BYTES {
                    captured.push_str(&String::from_utf8_lossy(&buf[..read]));
                    truncate_to_char_boundary(&mut captured, STDERR_CAPTURE_BYTES);
                }
            }
        }
    }
    captured.lock().await.clone()
}

/// Aborts auxiliary tasks, terminates the child, and reaps it after failure.
async fn cleanup_failed_run(
    child: &mut Child,
    process_group: &mut ProcessGroupGuard,
    stderr_task: &mut JoinHandle<String>,
    writer_task: Option<&mut JoinHandle<std::io::Result<()>>>,
) {
    if let Some(task) = writer_task {
        task.abort();
    }
    stderr_task.abort();
    kill_and_reap(child, process_group).await;
    if !stderr_task.is_finished() {
        let _ = stderr_task.await;
    }
}

/// Best-effort terminates and reaps a backend child.
async fn kill_and_reap(child: &mut Child, process_group: &mut ProcessGroupGuard) {
    #[cfg(unix)]
    process_group.terminate();
    let _ = child.start_kill();
    let _ = child.wait().await;
    process_group.disarm();
}

/// Captures a small command response under one deadline for output and exit.
/// The child and its inherited-pipe descendants are terminated on every path.
#[cfg(unix)]
pub fn bounded_command_output(
    command: &mut std::process::Command,
    timeout: Duration,
    output_limit: usize,
) -> std::io::Result<(std::process::ExitStatus, Vec<u8>)> {
    use std::io::{Error, ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut group = ProcessGroupGuard {
        pgid: Some(i32::try_from(child.id()).expect("Unix PID fits i32")),
    };
    let mut stdout = child.stdout.take().expect("piped stdout");
    let fd = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(Error::last_os_error());
    }
    let deadline = StdInstant::now() + timeout;
    let mut output = Vec::new();
    let mut eof = false;
    loop {
        if StdInstant::now() >= deadline {
            return Err(Error::new(ErrorKind::TimedOut, "command probe timed out"));
        }
        let mut buffer = [0; 1024];
        if !eof {
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if count > output_limit.saturating_sub(output.len()) {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "command output too large",
                        ));
                    }
                    output.extend_from_slice(&buffer[..count]);
                    continue;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if eof && group.has_exited()? {
            group.terminate();
            let status = child.wait()?;
            group.disarm();
            return Ok((status, output));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Removes ANSI CSI control sequences from bounded stderr.
fn strip_ansi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn truncate_to_char_boundary(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_stripping_and_utf8_truncation_are_safe() {
        assert_eq!(strip_ansi("\u{1b}[31merror\u{1b}[0m"), "error");
        let mut value = "ééé".to_owned();
        truncate_to_char_boundary(&mut value, 5);
        assert_eq!(value, "éé");
    }

    #[tokio::test]
    async fn stderr_capture_bounds_one_long_line_while_draining_it() {
        let input = std::io::Cursor::new(vec![b'x'; STDERR_CAPTURE_BYTES * 100]);
        let captured = capture_bounded(input).await;
        assert_eq!(captured.len(), STDERR_CAPTURE_BYTES);
        assert!(captured.bytes().all(|byte| byte == b'x'));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn waiting_for_direct_child_disarms_process_group_guard() {
        let mut child = Command::new("true").spawn().unwrap();
        let mut guard = ProcessGroupGuard::new(&child);

        let status = wait_for_child_and_cleanup(&mut child, &mut guard)
            .await
            .unwrap();

        assert!(status.success());
        assert!(guard.pgid.is_none());
    }
}
