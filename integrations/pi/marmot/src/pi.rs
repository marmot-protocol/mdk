use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use async_trait::async_trait;
use marmot_terminal_harness::{
    Backend, HarnessError, Invocation, Outcome, Result, RunFailure, RunnerEvent, TRACE_TARGET,
    process::{capture_stderr, cleanup_failed_run, next_stdout_line, strip_ansi, write_stdin},
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout_at;
use tracing::debug;

#[derive(Clone)]
pub(crate) struct PiBackend {
    pub(crate) bin: String,
    pub(crate) session_dir: std::path::PathBuf,
}

impl PiBackend {
    pub(crate) fn new(bin: String, session_dir: std::path::PathBuf) -> Result<Self> {
        fs_private::create_dir_all_private(&session_dir)?;
        Ok(Self { bin, session_dir })
    }
}

#[async_trait]
impl Backend for PiBackend {
    async fn run(
        &self,
        invocation: Invocation,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure> {
        run_with_bin(&self.bin, &self.session_dir, invocation, tx).await
    }
}

async fn run_with_bin(
    bin: &str,
    session_dir: &Path,
    invocation: Invocation,
    tx: mpsc::Sender<RunnerEvent>,
) -> std::result::Result<Outcome, RunFailure> {
    let mut command = Command::new(bin);
    command
        .args(build_run_args(
            session_dir,
            invocation.session_id.as_deref(),
        ))
        .current_dir(&invocation.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|_| RunFailure {
        error: HarnessError::BackendSpawn,
        observed_session: None,
    })?;
    let total_deadline = tokio::time::Instant::now() + invocation.timeout;
    let stdin = child.stdin.take().ok_or(RunFailure {
        error: HarnessError::BackendSpawn,
        observed_session: None,
    })?;
    let stdout = child.stdout.take().ok_or(RunFailure {
        error: HarnessError::BackendSpawn,
        observed_session: None,
    })?;
    let stderr = child.stderr.take().ok_or(RunFailure {
        error: HarnessError::BackendSpawn,
        observed_session: None,
    })?;
    let mut stderr_task = tokio::spawn(capture_stderr(stderr));
    let mut writer_task = write_stdin(stdin, invocation.prompt);
    let start = Instant::now();
    let mut observed_session = None;
    let mut error_summary = None;
    let mut idle_deadline = tokio::time::Instant::now() + invocation.idle_timeout;

    let lifecycle_result = timeout_at(total_deadline, async {
        let mut lines = BufReader::new(stdout).lines();
        loop {
            let Some(line) = next_stdout_line(&mut lines, idle_deadline).await? else {
                break;
            };
            if line.is_empty() {
                idle_deadline = tokio::time::Instant::now() + invocation.idle_timeout;
                continue;
            }
            match parse_event_line(&line) {
                Ok(Some(ParsedEvent::Session(session_id))) => {
                    if observed_session.is_none() {
                        observed_session = Some(session_id);
                    }
                }
                Ok(Some(ParsedEvent::Text(text))) => {
                    if !text.trim().is_empty() {
                        tx.send(RunnerEvent::Text(text))
                            .await
                            .map_err(|_| HarnessError::BackendStream)?;
                    }
                }
                Ok(Some(ParsedEvent::Error(summary))) => {
                    if error_summary.is_none() {
                        error_summary = Some(summary);
                    }
                }
                Ok(None) => {}
                Err(_) => debug!(
                    target: TRACE_TARGET,
                    method = "pi_run",
                    error_kind = "json",
                    "dropping undecodable Pi event"
                ),
            }
            idle_deadline = tokio::time::Instant::now() + invocation.idle_timeout;
        }

        let (status, stderr) = match timeout_at(idle_deadline, async {
            let (writer, status, stderr) =
                tokio::join!(&mut writer_task, child.wait(), &mut stderr_task,);
            let status = status.map_err(HarnessError::from)?;
            let stderr = stderr.map_err(HarnessError::from)?;
            match writer.map_err(HarnessError::from)? {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => debug!(
                    target: TRACE_TARGET,
                    method = "pi_run",
                    error_kind = "stdin_closed",
                    "backend closed stdin before draining the prompt"
                ),
                Err(_) => return Err(HarnessError::BackendStream),
            }
            Ok::<_, HarnessError>((status, stderr))
        })
        .await
        {
            Err(_) => return Err(HarnessError::BackendIdle),
            Ok(result) => result?,
        };
        Ok::<_, HarnessError>(Outcome {
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
            cleanup_failed_run(&mut child, &mut stderr_task, Some(&mut writer_task)).await;
            Err(RunFailure {
                error,
                observed_session,
            })
        }
        Err(_) => {
            cleanup_failed_run(&mut child, &mut stderr_task, Some(&mut writer_task)).await;
            Err(RunFailure {
                error: HarnessError::BackendTimedOut,
                observed_session,
            })
        }
    }
}

fn build_run_args(session_dir: &Path, session_id: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--mode".to_owned(),
        "json".to_owned(),
        "--session-dir".to_owned(),
        session_dir.to_string_lossy().into_owned(),
    ];
    if let Some(session_id) = session_id.filter(|value| !value.is_empty()) {
        args.push("--session-id".to_owned());
        args.push(session_id.to_owned());
    }
    args
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedEvent {
    Session(String),
    Text(String),
    Error(String),
}

fn parse_event_line(line: &str) -> serde_json::Result<Option<ParsedEvent>> {
    let value: Value = serde_json::from_str(line)?;
    let Some(event_type) = value.get("type").and_then(Value::as_str) else {
        return Ok(None);
    };
    if event_type == "session" {
        return Ok(value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| ParsedEvent::Session(id.to_owned())));
    }
    if event_type != "message_end" {
        return Ok(None);
    }
    let Some(message) = value.get("message") else {
        return Ok(None);
    };
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Ok(None);
    }
    let text = assistant_text(message.get("content"));
    if !text.is_empty() {
        return Ok(Some(ParsedEvent::Text(text)));
    }
    let stop_reason = message.get("stopReason").and_then(Value::as_str);
    if matches!(stop_reason, Some("error" | "aborted")) {
        return Ok(Some(ParsedEvent::Error(
            stop_reason.unwrap_or("error").to_owned(),
        )));
    }
    Ok(None)
}

fn assistant_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| {
                (part.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| part.get("text").and_then(Value::as_str))
                    .flatten()
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;

    #[test]
    fn args_select_json_session_dir_and_optional_session() {
        assert_eq!(
            build_run_args(Path::new("/private/sessions"), Some("abc-123")),
            vec![
                "--mode",
                "json",
                "--session-dir",
                "/private/sessions",
                "--session-id",
                "abc-123"
            ]
        );
    }

    #[test]
    fn parser_emits_session_and_completed_assistant_text_only() {
        assert_eq!(
            parse_event_line(r#"{"type":"session","version":3,"id":"pi-session"}"#).unwrap(),
            Some(ParsedEvent::Session("pi-session".to_owned()))
        );
        assert!(
            parse_event_line(r#"{"type":"message_update","assistantMessageEvent":{"type":"text_delta","delta":"partial"}}"#)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_event_line(r#"{"type":"message_end","message":{"role":"assistant","content":[{"type":"thinking","thinking":"secret"},{"type":"text","text":"hello "},{"type":"toolCall","name":"bash"},{"type":"text","text":"world"}],"stopReason":"stop"}}"#).unwrap(),
            Some(ParsedEvent::Text("hello world".to_owned()))
        );
        assert!(
            parse_event_line(r#"{"type":"message_end","message":{"role":"toolResult","content":[{"type":"text","text":"private output"}]}}"#)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parser_reports_textless_error_without_exposing_error_message() {
        assert_eq!(
            parse_event_line(r#"{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"secret"}}"#).unwrap(),
            Some(ParsedEvent::Error("error".to_owned()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn backend_constructor_creates_private_session_dir_once() {
        let root = tempfile::tempdir().unwrap();
        let session_dir = root.path().join("sessions");
        let backend = PiBackend::new("pi".to_owned(), session_dir.clone()).unwrap();
        assert_eq!(backend.session_dir, session_dir);
        assert_eq!(
            fs::metadata(&backend.session_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            fs_private::PRIVATE_DIR_MODE
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_pipes_prompt_and_streams_completed_text() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("fake-pi");
        fs::write(
            &script,
            r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "--mode" ] || [ "${2:-}" != "json" ]; then
  exit 64
fi
prompt="$(cat)"
printf '%s\n' '{"type":"session","version":3,"id":"pi-mock","cwd":"/tmp"}'
printf '%s\n' '{"type":"message_update","assistantMessageEvent":{"type":"text_delta","delta":"ignore"}}'
printf '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"reply: %s"}],"stopReason":"stop"}}\n' "$prompt"
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
        let session_dir = root.path().join("private-sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            &session_dir,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                session_name: "marmot-test".to_owned(),
                prompt: "--prompt-via-stdin".to_owned(),
                attachments: Vec::new(),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.observed_session.as_deref(), Some("pi-mock"));
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("reply: --prompt-via-stdin".to_owned()))
        );
        assert!(rx.recv().await.is_none());
        assert_eq!(
            fs::metadata(session_dir).unwrap().permissions().mode() & 0o777,
            fs_private::PRIVATE_DIR_MODE
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_reads_stdout_while_writing_a_large_prompt() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("chatty-pi");
        fs::write(
            &script,
            r#"#!/usr/bin/env bash
set -euo pipefail
for _ in $(seq 1 5000); do
  printf '%s\n' '{"type":"progress"}'
done
prompt="$(cat)"
printf '%s\n' '{"type":"session","version":3,"id":"pi-chatty"}'
printf '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"received:%s"}],"stopReason":"stop"}}\n' "${#prompt}"
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            &session_dir,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: Some("missing-session".to_owned()),
                session_name: "marmot-test".to_owned(),
                prompt: "p".repeat(60_000),
                attachments: Vec::new(),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.observed_session.as_deref(), Some("pi-chatty"));
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("received:60000".to_owned()))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_preserves_exit_and_stderr_when_backend_closes_stdin() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("early-exit-pi");
        fs::write(
            &script,
            r#"#!/usr/bin/env bash
printf '%s\n' 'authentication required' >&2
exit 64
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            &session_dir,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                session_name: "marmot-test".to_owned(),
                prompt: "p".repeat(60_000),
                attachments: Vec::new(),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.exit_code, Some(64));
        assert_eq!(outcome.stderr, "authentication required");
    }

    #[tokio::test]
    #[ignore = "requires authenticated Pi 0.79.6 and makes a real model request"]
    async fn real_pi_0_79_6_contract() {
        let version = std::process::Command::new("pi")
            .arg("--version")
            .output()
            .expect("run pi --version");
        assert_eq!(String::from_utf8_lossy(&version.stdout).trim(), "0.79.6");

        let root = tempfile::tempdir().unwrap();
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        let outcome = run_with_bin(
            "pi",
            &session_dir,
            Invocation {
                timeout: Duration::from_secs(120),
                idle_timeout: Duration::from_secs(30),
                cwd: root.path().to_path_buf(),
                session_id: Some("wn-pi-real-contract".to_owned()),
                session_name: "marmot-live-smoke".to_owned(),
                prompt: "Reply with exactly PI_CONNECTOR_OK and nothing else.".to_owned(),
                attachments: Vec::new(),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome.observed_session.as_deref(),
            Some("wn-pi-real-contract")
        );
        let mut reply = String::new();
        while let Some(RunnerEvent::Text(text)) = rx.recv().await {
            reply.push_str(&text);
        }
        assert_eq!(reply.trim(), "PI_CONNECTOR_OK");
    }
}
