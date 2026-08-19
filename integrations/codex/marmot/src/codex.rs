use std::process::Stdio;
use std::time::Instant;

use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Backend, ExecutionProfile, ExecutionSupport, HarnessError, Invocation,
    IsolationSupport, Outcome, RunFailure, RunnerEvent, TRACE_TARGET,
    process::{capture_stderr, cleanup_failed_run, next_stdout_line, strip_ansi, write_stdin},
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout_at;
use tracing::debug;

#[derive(Clone)]
pub(crate) struct CodexBackend {
    bin: String,
    execution_profile: ExecutionProfile,
}

impl CodexBackend {
    pub(crate) fn new(bin: String, execution_profile: ExecutionProfile) -> Self {
        Self {
            bin,
            execution_profile,
        }
    }
}

#[async_trait]
impl Backend for CodexBackend {
    fn execution_support(&self) -> ExecutionSupport {
        ExecutionSupport {
            approvals: match self.execution_profile {
                ExecutionProfile::Inherit => ApprovalSupport::Inherited,
                ExecutionProfile::Autonomous => ApprovalSupport::PreserveDenies,
                ExecutionProfile::Unrestricted => ApprovalSupport::Bypassed,
            },
            isolation: match self.execution_profile {
                ExecutionProfile::Unrestricted => IsolationSupport::Bypassed,
                ExecutionProfile::Inherit | ExecutionProfile::Autonomous => {
                    IsolationSupport::Inherited
                }
            },
        }
    }

    async fn run(
        &self,
        invocation: Invocation,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure> {
        run_with_bin(&self.bin, self.execution_profile, invocation, tx).await
    }
}

async fn run_with_bin(
    bin: &str,
    execution_profile: ExecutionProfile,
    invocation: Invocation,
    tx: mpsc::Sender<RunnerEvent>,
) -> std::result::Result<Outcome, RunFailure> {
    let mut command = Command::new(bin);
    command
        .args(build_exec_args(
            invocation.session_id.as_deref(),
            execution_profile,
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
                    method = "codex_exec",
                    error_kind = "json",
                    "dropping undecodable Codex event"
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
                    method = "codex_exec",
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

fn build_exec_args(session_id: Option<&str>, profile: ExecutionProfile) -> Vec<String> {
    let session_id = session_id.filter(|value| !value.is_empty());
    let mut args = vec!["exec".to_owned()];
    if session_id.is_some() {
        args.push("resume".to_owned());
    }
    match profile {
        ExecutionProfile::Inherit => {}
        ExecutionProfile::Autonomous => {
            args.extend(["-c".to_owned(), "approval_policy=\"never\"".to_owned()]);
        }
        ExecutionProfile::Unrestricted => {
            args.push("--dangerously-bypass-approvals-and-sandbox".to_owned());
        }
    }
    args.push("--json".to_owned());
    if let Some(session_id) = session_id {
        args.push(session_id.to_owned());
    }
    args.push("-".to_owned());
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
    match value.get("type").and_then(Value::as_str) {
        Some("thread.started") => Ok(value
            .get("thread_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| ParsedEvent::Session(id.to_owned()))),
        Some("item.completed") => {
            let Some(item) = value.get("item") else {
                return Ok(None);
            };
            if item.get("type").and_then(Value::as_str) != Some("agent_message") {
                return Ok(None);
            }
            Ok(item
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .map(|text| ParsedEvent::Text(text.to_owned())))
        }
        Some("turn.failed") => Ok(Some(ParsedEvent::Error("turn_failed".to_owned()))),
        Some("error") => Ok(Some(ParsedEvent::Error("error".to_owned()))),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use marmot_terminal_harness::ExecutionProfile;

    #[test]
    fn args_select_json_stdin_and_optional_resume() {
        assert_eq!(
            build_exec_args(None, ExecutionProfile::Inherit),
            vec!["exec", "--json", "-"]
        );
        assert_eq!(
            build_exec_args(Some("thread-123"), ExecutionProfile::Inherit),
            vec!["exec", "resume", "--json", "thread-123", "-"]
        );
        assert_eq!(
            build_exec_args(Some(""), ExecutionProfile::Inherit),
            vec!["exec", "--json", "-"]
        );
    }

    #[test]
    fn autonomous_preserves_configured_sandbox_and_network_for_new_and_resumed_threads() {
        assert_eq!(
            build_exec_args(None, ExecutionProfile::Autonomous),
            vec!["exec", "-c", "approval_policy=\"never\"", "--json", "-",]
        );
        assert_eq!(
            build_exec_args(Some("thread-123"), ExecutionProfile::Autonomous),
            vec![
                "exec",
                "resume",
                "-c",
                "approval_policy=\"never\"",
                "--json",
                "thread-123",
                "-",
            ]
        );
    }

    #[test]
    fn unrestricted_bypasses_approvals_and_sandbox_for_new_and_resumed_threads() {
        assert_eq!(
            build_exec_args(None, ExecutionProfile::Unrestricted),
            vec![
                "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "--json",
                "-",
            ]
        );
        assert_eq!(
            build_exec_args(Some("thread-123"), ExecutionProfile::Unrestricted),
            vec![
                "exec",
                "resume",
                "--dangerously-bypass-approvals-and-sandbox",
                "--json",
                "thread-123",
                "-",
            ]
        );
    }

    #[test]
    fn parser_emits_thread_and_completed_agent_messages_only() {
        assert_eq!(
            parse_event_line(r#"{"type":"thread.started","thread_id":"thread-123"}"#).unwrap(),
            Some(ParsedEvent::Session("thread-123".to_owned()))
        );
        assert_eq!(
            parse_event_line(r#"{"type":"item.completed","item":{"id":"item-1","type":"agent_message","text":"hello"}}"#).unwrap(),
            Some(ParsedEvent::Text("hello".to_owned()))
        );
        for line in [
            r#"{"type":"item.started","item":{"type":"agent_message","text":"partial"}}"#,
            r#"{"type":"item.completed","item":{"type":"reasoning","text":"secret"}}"#,
            r#"{"type":"item.completed","item":{"type":"command_execution","aggregated_output":"private"}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}"#,
        ] {
            assert!(parse_event_line(line).unwrap().is_none());
        }
    }

    #[test]
    fn parser_reports_failures_without_exposing_backend_messages() {
        assert_eq!(
            parse_event_line(r#"{"type":"turn.failed","error":{"message":"secret"}}"#).unwrap(),
            Some(ParsedEvent::Error("turn_failed".to_owned()))
        );
        assert_eq!(
            parse_event_line(r#"{"type":"error","message":"secret"}"#).unwrap(),
            Some(ParsedEvent::Error("error".to_owned()))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_pipes_prompt_and_streams_completed_text() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("fake-codex");
        fs::write(
            &script,
            r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "exec" ] || [ "${2:-}" != "--json" ] || [ "${3:-}" != "-" ]; then
  exit 64
fi
prompt="$(cat)"
printf '%s\n' '{"type":"thread.started","thread_id":"codex-mock"}'
printf '%s\n' '{"type":"item.completed","item":{"id":"reasoning","type":"reasoning","text":"ignore"}}'
printf '{"type":"item.completed","item":{"id":"message","type":"agent_message","text":"reply: %s"}}\n' "$prompt"
printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}'
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                prompt: "--prompt-via-stdin".to_owned(),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.observed_session.as_deref(), Some("codex-mock"));
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("reply: --prompt-via-stdin".to_owned()))
        );
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_resumes_session_and_reads_stdout_while_writing_large_prompt() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("chatty-codex");
        fs::write(
            &script,
            r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "exec" ] || [ "${2:-}" != "resume" ] || [ "${3:-}" != "--json" ] || [ "${4:-}" != "thread-123" ] || [ "${5:-}" != "-" ]; then
  exit 64
fi
for _ in $(seq 1 5000); do
  printf '%s\n' '{"type":"item.started","item":{"type":"command_execution"}}'
done
prompt="$(cat)"
printf '%s\n' '{"type":"thread.started","thread_id":"thread-123"}'
printf '{"type":"item.completed","item":{"type":"agent_message","text":"received:%s"}}\n' "${#prompt}"
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: Some("thread-123".to_owned()),
                prompt: "p".repeat(60_000),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.observed_session.as_deref(), Some("thread-123"));
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("received:60000".to_owned()))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_preserves_exit_and_stderr_when_backend_closes_stdin() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("early-exit-codex");
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
        let (tx, _rx) = mpsc::channel(1);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                prompt: "p".repeat(60_000),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.exit_code, Some(64));
        assert_eq!(outcome.stderr, "authentication required");
    }

    #[tokio::test]
    #[ignore = "requires authenticated Codex and makes a real model request"]
    async fn real_codex_exec_contract() {
        let version = std::process::Command::new("codex")
            .arg("--version")
            .output()
            .expect("run codex --version");
        assert!(version.status.success());
        assert!(
            String::from_utf8_lossy(&version.stdout).starts_with("codex-cli "),
            "unexpected Codex version output"
        );

        let (tx, mut rx) = mpsc::channel(8);
        let outcome = run_with_bin(
            "codex",
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(120),
                idle_timeout: Duration::from_secs(30),
                cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
                session_id: None,
                prompt: "Reply with exactly CODEX_CONNECTOR_OK and nothing else.".to_owned(),
            },
            tx,
        )
        .await
        .unwrap();

        assert!(outcome.observed_session.is_some());
        assert_eq!(outcome.exit_code, Some(0));
        let session_id = outcome.observed_session.unwrap();
        let mut reply = String::new();
        while let Some(RunnerEvent::Text(text)) = rx.recv().await {
            reply.push_str(&text);
        }
        assert_eq!(reply.trim(), "CODEX_CONNECTOR_OK");

        let (resume_tx, mut resume_rx) = mpsc::channel(8);
        let resumed = run_with_bin(
            "codex",
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(120),
                idle_timeout: Duration::from_secs(30),
                cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
                session_id: Some(session_id.clone()),
                prompt: "Reply with exactly CODEX_RESUME_OK and nothing else.".to_owned(),
            },
            resume_tx,
        )
        .await
        .unwrap();

        assert_eq!(
            resumed.observed_session.as_deref(),
            Some(session_id.as_str())
        );
        assert_eq!(resumed.exit_code, Some(0));
        let mut resumed_reply = String::new();
        while let Some(RunnerEvent::Text(text)) = resume_rx.recv().await {
            resumed_reply.push_str(&text);
        }
        assert_eq!(resumed_reply.trim(), "CODEX_RESUME_OK");
    }
}
