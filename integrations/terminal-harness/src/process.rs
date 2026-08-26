use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout_at};
use tracing::debug;

use crate::{HarnessError, Outcome, RunFailure, RunnerEvent, TRACE_TARGET};

const STDERR_CAPTURE_BYTES: usize = 4096;

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

    let mut child = command.spawn().map_err(|_| RunFailure {
        error: HarnessError::BackendSpawn,
        observed_session: None,
    })?;
    let total_deadline = Instant::now() + total_timeout;
    let mut writer_task = match prompt {
        PromptTransport::Stdin(prompt) => match child.stdin.take() {
            Some(stdin) => Some(write_stdin(stdin, prompt)),
            None => {
                kill_and_reap(&mut child).await;
                return Err(spawn_failure());
            }
        },
        PromptTransport::DelimitedArgument { .. } => None,
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            cleanup_missing_pipe(&mut child, writer_task.as_mut()).await;
            return Err(spawn_failure());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            cleanup_missing_pipe(&mut child, writer_task.as_mut()).await;
            return Err(spawn_failure());
        }
    };
    let mut stderr_task = tokio::spawn(capture_stderr(stderr));
    let started = StdInstant::now();
    let mut observed_session = None;
    let mut error_summary = None;
    let mut no_side_effects_proven = false;
    let mut idle_deadline = Instant::now() + idle_timeout;
    let mut reported_liveness_unknown = false;

    let lifecycle_result = timeout_at(total_deadline, async {
        let mut lines = BufReader::new(stdout).lines();
        loop {
            let line = match timeout_at(idle_deadline, lines.next_line()).await {
                Err(_) => {
                    if !reported_liveness_unknown {
                        tx.send(RunnerEvent::LivenessUnknown)
                            .await
                            .map_err(|_| HarnessError::BackendStream)?;
                        reported_liveness_unknown = true;
                    }
                    idle_deadline = Instant::now() + idle_timeout;
                    continue;
                }
                Ok(Err(_)) => return Err(HarnessError::BackendStream),
                Ok(Ok(Some(line))) => line,
                Ok(Ok(None)) => break,
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
        }

        let completion = async {
            let writer = async {
                match writer_task.as_mut() {
                    Some(task) => Some(task.await),
                    None => None,
                }
            };
            let (writer, status, stderr) = tokio::join!(writer, child.wait(), &mut stderr_task);
            let status = status.map_err(HarnessError::from)?;
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
            cleanup_failed_run(&mut child, &mut stderr_task, writer_task.as_mut()).await;
            Err(RunFailure {
                error,
                observed_session,
            })
        }
        Err(_) => {
            cleanup_failed_run(&mut child, &mut stderr_task, writer_task.as_mut()).await;
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
    writer_task: Option<&mut JoinHandle<std::io::Result<()>>>,
) {
    if let Some(task) = writer_task {
        task.abort();
    }
    kill_and_reap(child).await;
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
async fn capture_stderr(stderr: ChildStderr) -> String {
    capture_bounded(stderr).await
}

async fn capture_bounded(mut reader: impl AsyncRead + Unpin) -> String {
    let mut buf = [0_u8; 1024];
    let mut captured = String::new();
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) if captured.len() < STDERR_CAPTURE_BYTES => {
                captured.push_str(&String::from_utf8_lossy(&buf[..read]));
                truncate_to_char_boundary(&mut captured, STDERR_CAPTURE_BYTES);
            }
            Ok(_) => {}
        }
    }
    captured
}

/// Aborts auxiliary tasks, terminates the child, and reaps it after failure.
async fn cleanup_failed_run(
    child: &mut Child,
    stderr_task: &mut JoinHandle<String>,
    writer_task: Option<&mut JoinHandle<std::io::Result<()>>>,
) {
    if let Some(task) = writer_task {
        task.abort();
    }
    stderr_task.abort();
    kill_and_reap(child).await;
    if !stderr_task.is_finished() {
        let _ = stderr_task.await;
    }
}

/// Best-effort terminates and reaps a backend child.
async fn kill_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
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
}
