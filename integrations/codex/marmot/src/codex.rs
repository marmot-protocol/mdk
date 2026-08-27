use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, ArtifactSupport, Backend, ExecutionProfile, ExecutionSupport, HarnessError,
    Invocation, IsolationSupport, Outcome, ParsedEvent, PromptTransport, RunFailure, RunnerEvent,
    process::{EnvironmentChange, ProcessSpec, run_jsonl_process},
    read_artifact_output_manifest,
};
use serde_json::Value;
use tokio::sync::mpsc;

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

    fn artifact_support(&self) -> ArtifactSupport {
        ArtifactSupport::CompletionFile
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
    let Invocation {
        timeout,
        idle_timeout,
        cwd,
        session_id,
        mut prompt,
        artifact_output,
    } = invocation;
    let mut environment = Vec::new();
    if let Some(request) = &artifact_output {
        environment.push(EnvironmentChange::Set {
            name: "MARMOT_ARTIFACT_OUTPUT_FILE",
            value: request.manifest_path().to_string_lossy().into_owned(),
        });
        environment.push(EnvironmentChange::Set {
            name: "MARMOT_ARTIFACT_AUTHORIZATION_ID",
            value: request.authorization_id().to_owned(),
        });
        environment.push(EnvironmentChange::Set {
            name: "MARMOT_ARTIFACT_EXPORT_ROOT",
            value: request.export_root().to_string_lossy().into_owned(),
        });
        prompt.push_str("\n\nIf this task produces files for the requester, place them beneath $MARMOT_ARTIFACT_EXPORT_ROOT and write exactly one JSON object to $MARMOT_ARTIFACT_OUTPUT_FILE using this schema: {\"artifacts\":[{\"authorization_id\":\"value from $MARMOT_ARTIFACT_AUTHORIZATION_ID\",\"path\":\"relative/path\",\"media_type\":\"application/octet-stream\",\"file_name\":\"name.ext\"}]}. Paths must be relative to the export root. Use an empty artifacts array when there are no files. This structured file is the only artifact-delivery signal; do not rely on mentioning paths in chat text.");
    }
    let process_result = run_jsonl_process(
        ProcessSpec {
            executable: bin.to_owned(),
            args: build_exec_args(session_id.as_deref(), execution_profile),
            cwd,
            environment,
            prompt: PromptTransport::Stdin(prompt),
            trace_method: "codex_exec",
            backend_name: "codex",
            total_timeout: timeout,
            idle_timeout,
        },
        tx.clone(),
        parse_event_line,
    )
    .await;
    let outcome = match process_result {
        Ok(outcome) => outcome,
        Err(failure) => {
            if let Some(request) = &artifact_output {
                let _ = std::fs::remove_file(request.manifest_path());
            }
            return Err(failure);
        }
    };
    if let Some(request) = artifact_output {
        let artifacts_result = read_artifact_output_manifest(request.manifest_path());
        let _ = std::fs::remove_file(request.manifest_path());
        let artifacts = artifacts_result.map_err(|error| RunFailure {
            error,
            observed_session: outcome.observed_session.clone(),
        })?;
        if !artifacts.is_empty() {
            tx.send(RunnerEvent::Artifacts(artifacts))
                .await
                .map_err(|_| RunFailure {
                    error: HarnessError::BackendStream,
                    observed_session: outcome.observed_session.clone(),
                })?;
        }
    }
    Ok(outcome)
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

fn parse_event_line(line: &str) -> serde_json::Result<ParsedEvent> {
    let value: Value = serde_json::from_str(line)?;
    match value.get("type").and_then(Value::as_str) {
        Some("thread.started") => Ok(value
            .get("thread_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| ParsedEvent::Session(id.to_owned()))
            .unwrap_or(ParsedEvent::Ignored)),
        Some("item.completed") => {
            let Some(item) = value.get("item") else {
                return Ok(ParsedEvent::Ignored);
            };
            if item.get("type").and_then(Value::as_str) != Some("agent_message") {
                return Ok(ParsedEvent::Ignored);
            }
            Ok(item
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .map(|text| ParsedEvent::Text(text.to_owned()))
                .unwrap_or(ParsedEvent::Ignored))
        }
        Some("turn.failed") => Ok(ParsedEvent::Error {
            session_id: None,
            summary: "turn_failed".to_owned(),
        }),
        Some("error") => Ok(ParsedEvent::Error {
            session_id: None,
            summary: "error".to_owned(),
        }),
        _ => Ok(ParsedEvent::Ignored),
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
            ParsedEvent::Session("thread-123".to_owned())
        );
        assert_eq!(
            parse_event_line(r#"{"type":"item.completed","item":{"id":"item-1","type":"agent_message","text":"hello"}}"#).unwrap(),
            ParsedEvent::Text("hello".to_owned())
        );
        for line in [
            r#"{"type":"item.started","item":{"type":"agent_message","text":"partial"}}"#,
            r#"{"type":"item.completed","item":{"type":"reasoning","text":"secret"}}"#,
            r#"{"type":"item.completed","item":{"type":"command_execution","aggregated_output":"private"}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}"#,
        ] {
            assert_eq!(parse_event_line(line).unwrap(), ParsedEvent::Ignored);
        }
    }

    #[test]
    fn parser_reports_failures_without_exposing_backend_messages() {
        assert_eq!(
            parse_event_line(r#"{"type":"turn.failed","error":{"message":"secret"}}"#).unwrap(),
            ParsedEvent::Error {
                session_id: None,
                summary: "turn_failed".to_owned()
            }
        );
        assert_eq!(
            parse_event_line(r#"{"type":"error","message":"secret"}"#).unwrap(),
            ParsedEvent::Error {
                session_id: None,
                summary: "error".to_owned()
            }
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
                artifact_output: None,
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
    async fn runner_emits_artifacts_only_from_the_explicit_completion_file() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("artifact-codex");
        let artifact = root.path().join("report.pdf");
        fs::write(&artifact, b"pdf").unwrap();
        fs::write(
            &script,
            r#"#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
printf '{"artifacts":[{"authorization_id":"%s","path":"report.pdf","media_type":"application/pdf","file_name":"report.pdf"}]}' "$MARMOT_ARTIFACT_AUTHORIZATION_ID" >"$MARMOT_ARTIFACT_OUTPUT_FILE"
printf '%s\n' '{"type":"thread.started","thread_id":"codex-artifact"}'
printf '%s\n' '{"type":"item.completed","item":{"type":"agent_message","text":"Created report.pdf at /not/a/delivery/signal"}}'
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
        let manifest = root.path().join("manifest.json");
        fs::write(&manifest, br#"{"artifacts":[]}"#).unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                prompt: "create the report".to_owned(),
                artifact_output: Some(marmot_terminal_harness::ArtifactOutputRequest::new(
                    manifest,
                    "auth".to_owned(),
                    root.path().to_path_buf(),
                )),
            },
            tx,
        )
        .await
        .unwrap();
        assert!(matches!(rx.recv().await, Some(RunnerEvent::Text(_))));
        let Some(RunnerEvent::Artifacts(artifacts)) = rx.recv().await else {
            panic!("missing typed artifact event");
        };
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].authorization_id, "auth");
        assert_eq!(artifacts[0].path, std::path::PathBuf::from("report.pdf"));
        assert_eq!(artifacts[0].media_type, "application/pdf");
        assert_eq!(artifacts[0].file_name, "report.pdf");
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
                artifact_output: None,
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
        let manifest = root.path().join("manifest.json");
        fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({ "artifacts": [] })).unwrap(),
        )
        .unwrap();
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
                artifact_output: Some(marmot_terminal_harness::ArtifactOutputRequest::new(
                    manifest.clone(),
                    "auth".to_owned(),
                    root.path().to_path_buf(),
                )),
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.exit_code, Some(64));
        assert_eq!(outcome.stderr, "authentication required");
        assert!(!manifest.exists());
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
                artifact_output: None,
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
                artifact_output: None,
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
