use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::debug;

use crate::bridge::TRACE_TARGET;
use crate::error::{HarnessError, Result};

const STDERR_CAPTURE_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub(crate) struct Invocation {
    pub(crate) bin: String,
    pub(crate) timeout: Duration,
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

pub(crate) async fn run(invocation: Invocation, tx: mpsc::Sender<RunnerEvent>) -> Result<Outcome> {
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

    let mut child = command.spawn().map_err(|_| HarnessError::OpencodeSpawn)?;
    let stdout = child.stdout.take().ok_or(HarnessError::OpencodeSpawn)?;
    let stderr = child.stderr.take().ok_or(HarnessError::OpencodeSpawn)?;
    let mut lines = BufReader::new(stdout).lines();
    let stderr_task = tokio::spawn(capture_stderr(stderr));
    let start = Instant::now();
    let mut observed_session: Option<String> = None;
    let mut error_summary: Option<String> = None;

    let stream_result = timeout(invocation.timeout, async {
        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|_| HarnessError::OpencodeStream)?
        {
            if line.is_empty() {
                continue;
            }
            match parse_event_line(&line) {
                Ok(Some(ParsedEvent::Text(text))) => {
                    if !text.trim().is_empty() && tx.send(RunnerEvent::Text(text)).await.is_err() {
                        break;
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
                    if observed_session.is_none() {
                        observed_session = session_id;
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
        }
        Ok::<(), HarnessError>(())
    })
    .await;

    match stream_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            let _ = child.kill().await;
            return Err(err);
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err(HarnessError::OpencodeTimedOut);
        }
    }

    let status = child.wait().await?;
    let stderr = stderr_task.await?;
    Ok(Outcome {
        observed_session,
        exit_code: status.code(),
        error_summary,
        stderr: strip_ansi(stderr.trim()),
        elapsed_ms: start.elapsed().as_millis(),
    })
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
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tokio::sync::mpsc;

    use super::*;

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
        let script = dir.path().join("mock-opencode");
        fs::write(
            &script,
            r#"#!/usr/bin/env bash
printf '%s\n' '{"type":"step_start","sessionID":"ses_mock"}'
printf '%s\n' '{"type":"text","part":{"text":"hello"}}'
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();

        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run(
            Invocation {
                bin: script.display().to_string(),
                timeout: Duration::from_secs(5),
                cwd: dir.path().to_path_buf(),
                session_id: None,
                prompt: "prompt".to_owned(),
            },
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.observed_session, Some("ses_mock".to_owned()));
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.error_summary, None);
        assert!(matches!(
            rx.recv().await,
            Some(RunnerEvent::Text(text)) if text == "hello"
        ));
        assert!(rx.recv().await.is_none());
    }
}
