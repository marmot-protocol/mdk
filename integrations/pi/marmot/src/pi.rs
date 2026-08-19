use std::path::Path;

use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Backend, ExecutionProfile, ExecutionSupport, Invocation, IsolationSupport,
    Outcome, ParsedEvent, PromptTransport, Result, RunFailure, RunnerEvent,
    process::{ProcessSpec, run_jsonl_process},
};
use serde_json::Value;
use tokio::sync::mpsc;

#[derive(Clone)]
pub(crate) struct PiBackend {
    pub(crate) bin: String,
    pub(crate) session_dir: std::path::PathBuf,
    pub(crate) execution_profile: ExecutionProfile,
}

impl PiBackend {
    pub(crate) fn new(
        bin: String,
        session_dir: std::path::PathBuf,
        execution_profile: ExecutionProfile,
    ) -> Result<Self> {
        fs_private::create_dir_all_private(&session_dir)?;
        Ok(Self {
            bin,
            session_dir,
            execution_profile,
        })
    }
}

#[async_trait]
impl Backend for PiBackend {
    fn execution_support(&self) -> ExecutionSupport {
        ExecutionSupport {
            approvals: ApprovalSupport::NativeApprovalFree,
            isolation: IsolationSupport::NotProvided,
        }
    }

    async fn run(
        &self,
        invocation: Invocation,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure> {
        run_with_bin(
            &self.bin,
            &self.session_dir,
            self.execution_profile,
            invocation,
            tx,
        )
        .await
    }
}

async fn run_with_bin(
    bin: &str,
    session_dir: &Path,
    execution_profile: ExecutionProfile,
    invocation: Invocation,
    tx: mpsc::Sender<RunnerEvent>,
) -> std::result::Result<Outcome, RunFailure> {
    let Invocation {
        timeout,
        idle_timeout,
        cwd,
        session_id,
        prompt,
    } = invocation;
    run_jsonl_process(
        ProcessSpec {
            executable: bin.to_owned(),
            args: build_run_args(session_dir, session_id.as_deref(), execution_profile),
            cwd,
            environment: Vec::new(),
            prompt: PromptTransport::Stdin(prompt),
            trace_method: "pi_run",
            backend_name: "pi",
            total_timeout: timeout,
            idle_timeout,
        },
        tx,
        parse_event_line,
    )
    .await
}

fn build_run_args(
    session_dir: &Path,
    session_id: Option<&str>,
    _execution_profile: ExecutionProfile,
) -> Vec<String> {
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

fn parse_event_line(line: &str) -> serde_json::Result<ParsedEvent> {
    let value: Value = serde_json::from_str(line)?;
    let Some(event_type) = value.get("type").and_then(Value::as_str) else {
        return Ok(ParsedEvent::Ignored);
    };
    if event_type == "session" {
        return Ok(value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| ParsedEvent::Session(id.to_owned()))
            .unwrap_or(ParsedEvent::Ignored));
    }
    if event_type != "message_end" {
        return Ok(ParsedEvent::Ignored);
    }
    let Some(message) = value.get("message") else {
        return Ok(ParsedEvent::Ignored);
    };
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Ok(ParsedEvent::Ignored);
    }
    let text = assistant_text(message.get("content"));
    if !text.is_empty() {
        return Ok(ParsedEvent::Text(text));
    }
    let stop_reason = message.get("stopReason").and_then(Value::as_str);
    if matches!(stop_reason, Some("error" | "aborted")) {
        return Ok(ParsedEvent::Error {
            session_id: None,
            summary: stop_reason.unwrap_or("error").to_owned(),
        });
    }
    Ok(ParsedEvent::Ignored)
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
    use marmot_terminal_harness::ExecutionProfile;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use super::*;

    #[test]
    fn args_select_json_session_dir_and_optional_session() {
        assert_eq!(
            build_run_args(
                Path::new("/private/sessions"),
                Some("abc-123"),
                ExecutionProfile::Inherit,
            ),
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
            ParsedEvent::Session("pi-session".to_owned())
        );
        assert_eq!(
            parse_event_line(r#"{"type":"message_update","assistantMessageEvent":{"type":"text_delta","delta":"partial"}}"#)
                .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parse_event_line(r#"{"type":"message_end","message":{"role":"assistant","content":[{"type":"thinking","thinking":"secret"},{"type":"text","text":"hello "},{"type":"toolCall","name":"bash"},{"type":"text","text":"world"}],"stopReason":"stop"}}"#).unwrap(),
            ParsedEvent::Text("hello world".to_owned())
        );
        assert_eq!(
            parse_event_line(r#"{"type":"message_end","message":{"role":"toolResult","content":[{"type":"text","text":"private output"}]}}"#)
                .unwrap(),
            ParsedEvent::Ignored
        );
    }

    #[test]
    fn parser_reports_textless_error_without_exposing_error_message() {
        assert_eq!(
            parse_event_line(r#"{"type":"message_end","message":{"role":"assistant","content":[],"stopReason":"error","errorMessage":"secret"}}"#).unwrap(),
            ParsedEvent::Error {
                session_id: None,
                summary: "error".to_owned()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn backend_constructor_creates_private_session_dir_once() {
        let root = tempfile::tempdir().unwrap();
        let session_dir = root.path().join("sessions");
        let backend = PiBackend::new(
            "pi".to_owned(),
            session_dir.clone(),
            ExecutionProfile::Inherit,
        )
        .unwrap();
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
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: Some("missing-session".to_owned()),
                prompt: "p".repeat(60_000),
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
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(120),
                idle_timeout: Duration::from_secs(30),
                cwd: root.path().to_path_buf(),
                session_id: Some("wn-pi-real-contract".to_owned()),
                prompt: "Reply with exactly PI_CONNECTOR_OK and nothing else.".to_owned(),
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

    #[test]
    fn every_profile_uses_pis_native_approval_free_command_contract() {
        let session_dir = Path::new("/private/pi-sessions");
        for profile in [
            ExecutionProfile::Inherit,
            ExecutionProfile::Autonomous,
            ExecutionProfile::Unrestricted,
        ] {
            assert_eq!(
                build_run_args(session_dir, None, profile),
                vec!["--mode", "json", "--session-dir", "/private/pi-sessions"]
            );
            assert_eq!(
                build_run_args(session_dir, Some("session-123"), profile),
                vec![
                    "--mode",
                    "json",
                    "--session-dir",
                    "/private/pi-sessions",
                    "--session-id",
                    "session-123",
                ]
            );
        }
    }
}
