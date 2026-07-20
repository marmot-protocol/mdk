use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout_at;
use tracing::debug;

use crate::bridge::TRACE_TARGET;
use crate::error::{HarnessError, Result};

const STDERR_CAPTURE_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub(crate) struct Invocation {
    pub(crate) bin: String,
    pub(crate) timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) cwd: PathBuf,
    pub(crate) session_id: Option<String>,
    pub(crate) prompt: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) observed_session: Option<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) error_summary: Option<String>,
    pub(crate) stderr: String,
    pub(crate) elapsed_ms: u128,
}

#[derive(Debug)]
pub(crate) struct RunFailure {
    pub(crate) error: HarnessError,
    pub(crate) observed_session: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RunnerEvent {
    Text(String),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OpencodeEvent {
    StepStart {
        #[serde(rename = "sessionID")]
        session_id: Option<String>,
    },
    Text {
        part: TextPart,
    },
    Error {
        #[serde(rename = "sessionID")]
        session_id: Option<String>,
        error: OpencodeError,
    },
    StepFinish {},
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct TextPart {
    text: String,
}

#[derive(Debug, Deserialize)]
struct OpencodeError {
    name: Option<String>,
    data: Option<OpencodeErrorData>,
}

#[derive(Debug, Deserialize)]
struct OpencodeErrorData {
    #[serde(rename = "statusCode")]
    status_code: Option<u16>,
}

pub(crate) async fn run(
    invocation: Invocation,
    tx: mpsc::Sender<RunnerEvent>,
) -> std::result::Result<Outcome, RunFailure> {
    let mut command = Command::new(&invocation.bin);
    command
        .args(build_run_args(
            invocation.session_id.as_deref(),
            &invocation.prompt,
        ))
        .current_dir(&invocation.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|_| RunFailure {
        error: HarnessError::OpencodeSpawn,
        observed_session: None,
    })?;
    let total_deadline = tokio::time::Instant::now() + invocation.timeout;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            kill_and_reap(&mut child).await;
            return Err(RunFailure {
                error: HarnessError::OpencodeSpawn,
                observed_session: None,
            });
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            kill_and_reap(&mut child).await;
            return Err(RunFailure {
                error: HarnessError::OpencodeSpawn,
                observed_session: None,
            });
        }
    };
    let mut lines = BufReader::new(stdout).lines();
    let mut stderr_task = tokio::spawn(capture_stderr(stderr));
    let start = Instant::now();
    let mut observed_session: Option<String> = None;
    let mut error_summary: Option<String> = None;
    let mut idle_deadline = tokio::time::Instant::now() + invocation.idle_timeout;

    let lifecycle_result = timeout_at(total_deadline, async {
        loop {
            let Some(line) = next_stdout_line(&mut lines, idle_deadline).await? else {
                break;
            };

            if line.is_empty() {
                idle_deadline = tokio::time::Instant::now() + invocation.idle_timeout;
                continue;
            }
            match parse_event_line(&line) {
                Ok(Some(ParsedEvent::Text(text))) => {
                    if !text.trim().is_empty() {
                        // The idle clock measures actual stdout reads, not time intentionally
                        // spent applying bounded reply-channel backpressure. The total deadline
                        // still caps both operations.
                        tx.send(RunnerEvent::Text(text))
                            .await
                            .map_err(|_| HarnessError::OpencodeStream)?;
                    }
                }
                Ok(Some(ParsedEvent::Session(session_id))) => {
                    if observed_session.is_none() {
                        observed_session = Some(session_id);
                    }
                }
                Ok(Some(ParsedEvent::Error {
                    session_id,
                    summary,
                })) => {
                    if let Some(session_id) = session_id
                        && observed_session.is_none()
                    {
                        observed_session = Some(session_id);
                    }
                    if error_summary.is_none() {
                        error_summary = Some(summary);
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    debug!(
                        target: TRACE_TARGET,
                        method = "opencode_run",
                        error_kind = "json",
                        "dropping undecodable opencode event"
                    );
                }
            }
            idle_deadline = tokio::time::Instant::now() + invocation.idle_timeout;
        }

        let (status, stderr) = match timeout_at(idle_deadline, async {
            let status = child.wait().await.map_err(HarnessError::from)?;
            let stderr = (&mut stderr_task).await.map_err(HarnessError::from)?;
            Ok::<_, HarnessError>((status, stderr))
        })
        .await
        {
            Err(_) => return Err(HarnessError::OpencodeIdle),
            Ok(result) => result?,
        };
        Ok::<Outcome, HarnessError>(Outcome {
            observed_session: observed_session.clone(),
            exit_code: status.code(),
            error_summary,
            stderr: strip_ansi(stderr.trim()),
            elapsed_ms: start.elapsed().as_millis(),
        })
    })
    .await;

    match lifecycle_result {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => {
            cleanup_failed_run(&mut child, &mut stderr_task).await;
            Err(RunFailure {
                error,
                observed_session,
            })
        }
        Err(_) => {
            cleanup_failed_run(&mut child, &mut stderr_task).await;
            Err(RunFailure {
                error: HarnessError::OpencodeTimedOut,
                observed_session,
            })
        }
    }
}

async fn next_stdout_line(
    lines: &mut tokio::io::Lines<impl tokio::io::AsyncBufRead + Unpin>,
    idle_deadline: tokio::time::Instant,
) -> std::result::Result<Option<String>, HarnessError> {
    match timeout_at(idle_deadline, lines.next_line()).await {
        Err(_) => Err(HarnessError::OpencodeIdle),
        Ok(Err(_)) => Err(HarnessError::OpencodeStream),
        Ok(Ok(line)) => Ok(line),
    }
}

async fn cleanup_failed_run(child: &mut Child, stderr_task: &mut JoinHandle<String>) {
    stderr_task.abort();
    kill_and_reap(child).await;
    if !stderr_task.is_finished() {
        let _ = stderr_task.await;
    }
}

async fn kill_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

pub(crate) fn build_run_args(session_id: Option<&str>, prompt: &str) -> Vec<String> {
    let mut args = vec!["run".to_owned(), "--format".to_owned(), "json".to_owned()];
    if let Some(session_id) = session_id
        && !session_id.is_empty()
    {
        args.push("--session".to_owned());
        args.push(session_id.to_owned());
    }
    args.push("--".to_owned());
    args.push(prompt.to_owned());
    args
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedEvent {
    Text(String),
    Session(String),
    Error {
        session_id: Option<String>,
        summary: String,
    },
}

fn parse_event_line(line: &str) -> Result<Option<ParsedEvent>> {
    let event = serde_json::from_str::<OpencodeEvent>(line)?;
    Ok(match event {
        OpencodeEvent::Text { part } => Some(ParsedEvent::Text(part.text)),
        OpencodeEvent::Error { session_id, error } => Some(ParsedEvent::Error {
            session_id,
            summary: error.summary(),
        }),
        OpencodeEvent::StepStart {
            session_id: Some(session_id),
        } => Some(ParsedEvent::Session(session_id)),
        OpencodeEvent::StepStart { session_id: None }
        | OpencodeEvent::StepFinish {}
        | OpencodeEvent::Other => None,
    })
}

impl OpencodeError {
    fn summary(self) -> String {
        let mut summary = self.name.unwrap_or_else(|| "error".to_owned());
        if let Some(status_code) = self.data.and_then(|data| data.status_code) {
            summary.push_str(&format!(" status={status_code}"));
        }
        summary
    }
}

async fn capture_stderr(stderr: tokio::process::ChildStderr) -> String {
    let mut reader = BufReader::new(stderr);
    let mut buf = Vec::new();
    let mut captured = String::new();
    while let Ok(read) = reader.read_until(b'\n', &mut buf).await {
        if read == 0 {
            break;
        }
        if captured.len() < STDERR_CAPTURE_BYTES {
            captured.push_str(&String::from_utf8_lossy(&buf));
            if captured.len() > STDERR_CAPTURE_BYTES {
                truncate_to_char_boundary(&mut captured, STDERR_CAPTURE_BYTES);
            }
        }
        buf.clear();
    }
    captured
}

fn truncate_to_char_boundary(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

pub(crate) fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            while let Some(&next) = chars.peek() {
                chars.next();
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    fn mock_invocation(dir: &tempfile::TempDir, scenario: &str) -> Invocation {
        Invocation {
            bin: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/mock-opencode.sh"
            )
            .to_owned(),
            timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_millis(500),
            cwd: dir.path().to_path_buf(),
            session_id: None,
            prompt: scenario.to_owned(),
        }
    }

    #[test]
    fn build_run_args_separates_prompt_from_flags() {
        assert_eq!(
            build_run_args(Some("ses_123"), "--auto"),
            vec![
                "run",
                "--format",
                "json",
                "--session",
                "ses_123",
                "--",
                "--auto"
            ]
        );
    }

    #[test]
    fn parse_opencode_text_and_session_events() {
        assert_eq!(
            parse_event_line(r#"{"type":"step_start","sessionID":"ses_1"}"#).unwrap(),
            Some(ParsedEvent::Session("ses_1".to_owned()))
        );
        assert_eq!(
            parse_event_line(r#"{"type":"text","part":{"text":"hello"}}"#).unwrap(),
            Some(ParsedEvent::Text("hello".to_owned()))
        );
    }

    #[test]
    fn parse_opencode_error_event_summary() {
        assert_eq!(
            parse_event_line(
                r#"{"type":"error","sessionID":"ses_err","error":{"name":"APIError","data":{"statusCode":404}}}"#
            )
            .unwrap(),
            Some(ParsedEvent::Error {
                session_id: Some("ses_err".to_owned()),
                summary: "APIError status=404".to_owned()
            })
        );
    }

    #[test]
    fn strip_ansi_removes_csi_sequences() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m"), "red");
    }

    #[test]
    fn truncate_to_char_boundary_keeps_valid_utf8() {
        let mut value = "a".repeat(STDERR_CAPTURE_BYTES - 1);
        value.push('é');
        value.push_str("tail");
        truncate_to_char_boundary(&mut value, STDERR_CAPTURE_BYTES);
        assert!(value.is_char_boundary(value.len()));
        assert_eq!(value.len(), STDERR_CAPTURE_BYTES - 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_streams_text_from_mock_binary() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run(mock_invocation(&dir, "stream-text"), tx).await.unwrap();
        assert_eq!(outcome.observed_session, Some("ses_mock".to_owned()));
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.error_summary, None);
        assert!(matches!(
            rx.recv().await,
            Some(RunnerEvent::Text(text)) if text == "hello"
        ));
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_idle_timeout_fires_after_silence() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let failure = run(
            Invocation {
                idle_timeout: Duration::from_millis(200),
                ..mock_invocation(&dir, "idle")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::OpencodeIdle));
        assert_eq!(failure.observed_session.as_deref(), Some("ses_idle"));
    }

    #[tokio::test(start_paused = true)]
    async fn stdout_lines_reset_idle_past_old_wall_clock_deadline() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::sleep;

        const IDLE: Duration = Duration::from_secs(120);
        const GAP: Duration = Duration::from_secs(70);
        const TOTAL: Duration = Duration::from_secs(3600);
        const LINE_COUNT: usize = 6;

        let (mut writer, reader) = tokio::io::duplex(1024);
        let producer = tokio::spawn(async move {
            for index in 0..LINE_COUNT {
                if index != 0 {
                    sleep(GAP).await;
                }
                writer.write_all(b"line\n").await.unwrap();
            }
        });
        let mut lines = BufReader::new(reader).lines();
        let started = tokio::time::Instant::now();
        let received = tokio::time::timeout(TOTAL, async {
            let mut count = 0;
            let mut idle_deadline = tokio::time::Instant::now() + IDLE;
            while next_stdout_line(&mut lines, idle_deadline)
                .await
                .unwrap()
                .is_some()
            {
                count += 1;
                idle_deadline = tokio::time::Instant::now() + IDLE;
            }
            count
        })
        .await
        .unwrap();

        producer.await.unwrap();
        assert_eq!(received, LINE_COUNT);
        assert!(started.elapsed() > Duration::from_secs(300));
        assert!(started.elapsed() < TOTAL);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_total_cap_fires_despite_ongoing_lines() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let failure = run(
            Invocation {
                timeout: Duration::from_millis(1_500),
                idle_timeout: Duration::from_secs(1),
                ..mock_invocation(&dir, "total-cap")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(failure.error, HarnessError::OpencodeTimedOut),
            "expected total timeout, got {failure:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_idle_timeout_fires_after_stdout_eof_with_live_child() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let started = Instant::now();
        let failure = run(
            Invocation {
                timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_millis(200),
                ..mock_invocation(&dir, "stdout-close-live")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::OpencodeIdle));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_eof_keeps_remaining_idle_budget() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let started = Instant::now();
        let failure = run(
            Invocation {
                timeout: Duration::from_secs(10),
                idle_timeout: Duration::from_secs(1),
                ..mock_invocation(&dir, "stdout-close-near-idle")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::OpencodeIdle));
        assert!(
            started.elapsed() < Duration::from_millis(1_350),
            "stdout EOF must not reset the existing idle deadline"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_total_cap_includes_child_wait_after_stdout_closes() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let started = Instant::now();
        let failure = run(
            Invocation {
                timeout: Duration::from_millis(200),
                idle_timeout: Duration::from_secs(5),
                ..mock_invocation(&dir, "stdout-close-live")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::OpencodeTimedOut));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_failure_keeps_session_despite_channel_backpressure() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let failure = run(
            Invocation {
                timeout: Duration::from_millis(200),
                idle_timeout: Duration::from_secs(5),
                ..mock_invocation(&dir, "session-backpressure")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::OpencodeTimedOut));
        assert_eq!(
            failure.observed_session.as_deref(),
            Some("ses_backpressure")
        );
    }
}
