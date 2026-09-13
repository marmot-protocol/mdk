use std::process::Command;

use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Backend, ExecutionProfile, ExecutionSupport, HarnessError, Invocation,
    IsolationSupport, Outcome, ParsedEvent, PromptTransport, Result, RunFailure, RunnerEvent,
    process::{ProcessSpec, run_jsonl_process},
};
use serde_json::Value;
use tokio::sync::mpsc;
use uuid::Uuid;

const MINIMUM_VERSION: (u64, u64, u64) = (2, 1, 0);

#[derive(Clone)]
pub(crate) struct ClaudeBackend {
    bin: String,
    execution_profile: ExecutionProfile,
}

impl ClaudeBackend {
    pub(crate) fn new(bin: String, execution_profile: ExecutionProfile) -> Result<Self> {
        validate_cli_version(&bin)?;
        Ok(Self {
            bin,
            execution_profile,
        })
    }
}

#[async_trait]
impl Backend for ClaudeBackend {
    fn execution_support(&self) -> ExecutionSupport {
        ExecutionSupport {
            approvals: match self.execution_profile {
                ExecutionProfile::Inherit => ApprovalSupport::Inherited,
                ExecutionProfile::Autonomous => ApprovalSupport::PreserveDenies,
                ExecutionProfile::Unrestricted => ApprovalSupport::Bypassed,
            },
            isolation: IsolationSupport::NotProvided,
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
    let Invocation {
        timeout,
        idle_timeout,
        cwd,
        session_id,
        prompt,
        artifact_output: _,
    } = invocation;
    let resume = session_id.is_some();
    let session_id = match session_id {
        Some(value) => normalize_session_id(&value).ok_or_else(invalid_session_failure)?,
        None => Uuid::new_v4().to_string(),
    };
    run_jsonl_process(
        ProcessSpec {
            executable: bin.to_owned(),
            args: build_run_args(&session_id, resume, execution_profile),
            cwd,
            environment: Vec::new(),
            prompt: PromptTransport::Stdin(prompt),
            trace_method: "claude_print",
            backend_name: "claude",
            total_timeout: timeout,
            idle_timeout,
        },
        tx,
        parse_event_line,
    )
    .await
}

fn invalid_session_failure() -> RunFailure {
    RunFailure {
        error: HarnessError::Config("Claude Code session id is not a UUID".to_owned()),
        observed_session: None,
    }
}

fn build_run_args(
    session_id: &str,
    resume: bool,
    execution_profile: ExecutionProfile,
) -> Vec<String> {
    let mut args = vec![
        "-p".to_owned(),
        "--output-format".to_owned(),
        "stream-json".to_owned(),
        "--verbose".to_owned(),
    ];
    match execution_profile {
        ExecutionProfile::Inherit => {}
        ExecutionProfile::Autonomous => {
            args.extend(["--permission-mode".to_owned(), "acceptEdits".to_owned()]);
        }
        ExecutionProfile::Unrestricted => {
            args.push("--dangerously-skip-permissions".to_owned());
        }
    }
    args.push(if resume {
        "--resume".to_owned()
    } else {
        "--session-id".to_owned()
    });
    args.push(session_id.to_owned());
    args
}

fn parse_event_line(line: &str) -> Result<ParsedEvent> {
    let value: Value = serde_json::from_str(line)?;
    let event_type = value.get("type").and_then(Value::as_str);
    match event_type {
        Some("system") if value.get("subtype").and_then(Value::as_str) == Some("init") => {
            parse_session_event(&value)
        }
        Some("result") => parse_result_event(&value),
        _ => Ok(ParsedEvent::Ignored),
    }
}

fn parse_session_event(value: &Value) -> Result<ParsedEvent> {
    let Some(session_id) = value.get("session_id").and_then(Value::as_str) else {
        return Ok(ParsedEvent::Ignored);
    };
    normalize_session_id(session_id)
        .map(ParsedEvent::Session)
        .ok_or(HarnessError::Json)
}

fn parse_result_event(value: &Value) -> Result<ParsedEvent> {
    let session_id = match value.get("session_id").and_then(Value::as_str) {
        Some(value) => Some(normalize_session_id(value).ok_or(HarnessError::Json)?),
        None => None,
    };
    let subtype = value.get("subtype").and_then(Value::as_str);
    let is_error = value
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(subtype != Some("success"));
    if is_error || subtype != Some("success") {
        return Ok(ParsedEvent::Error {
            session_id,
            summary: result_error_summary(subtype).to_owned(),
        });
    }
    Ok(value
        .get("result")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(|text| ParsedEvent::Text(text.to_owned()))
        .unwrap_or(ParsedEvent::Ignored))
}

fn result_error_summary(subtype: Option<&str>) -> &'static str {
    match subtype {
        Some("error_max_turns") => "max_turns",
        Some("error_max_budget_usd") => "max_budget",
        Some("error_max_structured_output_retries") => "structured_output_retries",
        Some("error_during_execution") => "execution",
        _ => "error",
    }
}

fn normalize_session_id(value: &str) -> Option<String> {
    Uuid::parse_str(value).ok().map(|uuid| uuid.to_string())
}

fn validate_cli_version(bin: &str) -> Result<()> {
    let output = Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|_| HarnessError::BackendSpawn)?;
    if !output.status.success() {
        return Err(HarnessError::Config(
            "Claude Code version check failed".to_owned(),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = parse_version(&stdout).ok_or_else(|| {
        HarnessError::Config("Claude Code returned an unsupported version string".to_owned())
    })?;
    if version < MINIMUM_VERSION {
        return Err(HarnessError::Config(
            "Claude Code 2.1.0 or newer is required".to_owned(),
        ));
    }
    Ok(())
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    value
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find_map(|candidate| {
            let mut parts = candidate.split('.');
            let major = parts.next()?.parse().ok()?;
            let minor = parts.next()?.parse().ok()?;
            let patch = parts.next()?.parse().ok()?;
            (parts.next().is_none()).then_some((major, minor, patch))
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::Path;
    use std::time::Duration;

    use super::*;

    const SESSION: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn args_use_explicit_session_ids_and_keep_prompts_out_of_argv() {
        assert_eq!(
            build_run_args(SESSION, false, ExecutionProfile::Inherit),
            vec![
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--session-id",
                SESSION,
            ]
        );
        assert_eq!(
            build_run_args(SESSION, true, ExecutionProfile::Inherit),
            vec![
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--resume",
                SESSION,
            ]
        );
    }

    #[test]
    fn args_apply_typed_permission_profiles() {
        let autonomous = build_run_args(SESSION, false, ExecutionProfile::Autonomous);
        assert!(
            autonomous
                .windows(2)
                .any(|pair| pair == ["--permission-mode", "acceptEdits"])
        );
        let unrestricted = build_run_args(SESSION, true, ExecutionProfile::Unrestricted);
        assert!(unrestricted.contains(&"--dangerously-skip-permissions".to_owned()));
        assert!(unrestricted.contains(&"--resume".to_owned()));
    }

    #[test]
    fn session_ids_are_uuid_validated_and_normalized() {
        assert_eq!(normalize_session_id(SESSION).as_deref(), Some(SESSION));
        assert_eq!(
            normalize_session_id("550E8400-E29B-41D4-A716-446655440000").as_deref(),
            Some(SESSION)
        );
        for invalid in ["", "latest", "../session.jsonl", "550e8400"] {
            assert_eq!(normalize_session_id(invalid), None);
        }
    }

    #[test]
    fn parser_emits_init_session_and_final_result_only() {
        assert_eq!(
            parse_event_line(&format!(
                r#"{{"type":"system","subtype":"init","session_id":"{SESSION}"}}"#
            ))
            .unwrap(),
            ParsedEvent::Session(SESSION.to_owned())
        );
        assert_eq!(
            parse_event_line(&format!(
                r#"{{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"{SESSION}"}}"#
            ))
            .unwrap(),
            ParsedEvent::Text("done".to_owned())
        );
        for line in [
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"secret"}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","input":"secret"}]}}"#,
            r#"{"type":"user","message":{"content":"prompt"}}"#,
            r#"{"type":"stream_event","event":{"type":"content_block_delta"}}"#,
        ] {
            assert_eq!(parse_event_line(line).unwrap(), ParsedEvent::Ignored);
        }
        assert!(parse_event_line("{").is_err());
    }

    #[test]
    fn parser_sanitizes_failures_and_rejects_non_uuid_sessions() {
        assert_eq!(
            parse_event_line(&format!(
                r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"result":"private failure","session_id":"{SESSION}"}}"#
            ))
            .unwrap(),
            ParsedEvent::Error {
                session_id: Some(SESSION.to_owned()),
                summary: "execution".to_owned(),
            }
        );
        assert!(
            parse_event_line(r#"{"type":"system","subtype":"init","session_id":"not-a-uuid"}"#)
                .is_err()
        );
    }

    #[test]
    fn version_parser_accepts_supported_cli_shapes() {
        assert_eq!(parse_version("2.1.270 (Claude Code)"), Some((2, 1, 270)));
        assert_eq!(parse_version("claude-code 2.1.0"), Some((2, 1, 0)));
        assert_eq!(parse_version("Claude Code"), None);
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn version_check_rejects_old_malformed_and_failing_clis() {
        let root = tempfile::tempdir().unwrap();
        for (name, body) in [
            ("old", "printf '%s\\n' '2.0.99 (Claude Code)'"),
            ("malformed", "printf '%s\\n' 'Claude Code'"),
            ("failing", "exit 64"),
        ] {
            let script = root.path().join(name);
            write_executable(&script, &format!("#!/usr/bin/env bash\n{body}\n"));
            assert!(
                validate_cli_version(script.to_str().unwrap()).is_err(),
                "accepted {name} Claude CLI"
            );
        }

        let supported = root.path().join("supported");
        write_executable(
            &supported,
            "#!/usr/bin/env bash\nprintf '%s\\n' '2.1.270 (Claude Code)'\n",
        );
        validate_cli_version(supported.to_str().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_pipes_prompt_and_returns_only_final_result() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("fake-claude");
        write_executable(
            &script,
            r#"#!/usr/bin/env bash
set -euo pipefail
test "$1" = "-p"
test "$2" = "--output-format"
test "$3" = "stream-json"
test "$4" = "--verbose"
test "$5" = "--session-id"
session="$6"
prompt="$(cat)"
printf '%s\n' '{"type":"system","subtype":"init","session_id":"'"$session"'"}'
printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"intermediate"}]}}'
printf '{"type":"result","subtype":"success","is_error":false,"result":"reply: %s","session_id":"%s"}\n' "$prompt" "$session"
"#,
        );
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                prompt: "--stdin-only".to_owned(),
                artifact_output: None,
            },
            tx,
        )
        .await
        .unwrap();

        assert!(outcome.observed_session.is_some());
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("reply: --stdin-only".to_owned()))
        );
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_preserves_nonzero_exit_and_bounded_stderr_contract() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("failing-claude");
        write_executable(
            &script,
            r#"#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' '{"type":"unknown","private":"ignored"}'
printf '%s\n' 'authentication required' >&2
exit 64
"#,
        );
        let (tx, _rx) = mpsc::channel(1);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                prompt: "private prompt".to_owned(),
                artifact_output: None,
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.exit_code, Some(64));
        assert_eq!(outcome.stderr, "authentication required");
        assert_eq!(outcome.observed_session, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_enforces_total_timeout() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("slow-claude");
        write_executable(
            &script,
            r#"#!/usr/bin/env bash
cat >/dev/null
sleep 5
"#,
        );
        let (tx, _rx) = mpsc::channel(1);
        let failure = run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_millis(100),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: None,
                prompt: "private prompt".to_owned(),
                artifact_output: None,
            },
            tx,
        )
        .await
        .unwrap_err();

        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert_eq!(failure.observed_session, None);
    }

    #[tokio::test]
    #[ignore = "requires authenticated Claude Code and makes a real model request"]
    async fn real_claude_code_contract() {
        validate_cli_version("claude").unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        let first = run_with_bin(
            "claude",
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(120),
                idle_timeout: Duration::from_secs(30),
                cwd: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
                session_id: None,
                prompt: "Reply with exactly CLAUDE_CONNECTOR_OK and nothing else.".to_owned(),
                artifact_output: None,
            },
            tx,
        )
        .await
        .unwrap();
        let session_id = first.observed_session.expect("session id");
        let mut reply = String::new();
        while let Some(RunnerEvent::Text(text)) = rx.recv().await {
            reply.push_str(&text);
        }
        assert_eq!(reply.trim(), "CLAUDE_CONNECTOR_OK");

        let (resume_tx, mut resume_rx) = mpsc::channel(8);
        let resumed = run_with_bin(
            "claude",
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(120),
                idle_timeout: Duration::from_secs(30),
                cwd: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
                session_id: Some(session_id.clone()),
                prompt: "Reply with exactly CLAUDE_RESUME_OK and nothing else.".to_owned(),
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
        let mut resumed_reply = String::new();
        while let Some(RunnerEvent::Text(text)) = resume_rx.recv().await {
            resumed_reply.push_str(&text);
        }
        assert_eq!(resumed_reply.trim(), "CLAUDE_RESUME_OK");
    }
}
