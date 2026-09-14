use std::process::Command;
use std::time::Duration;

use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Backend, ExecutionProfile, ExecutionSupport, HarnessError, Invocation,
    IsolationSupport, Outcome, ParsedEvent, PromptTransport, Result, RunFailure, RunnerEvent,
    process::{ProcessSpec, bounded_command_output, run_jsonl_process},
};
use serde_json::Value;
use tokio::sync::mpsc;
use uuid::Uuid;

const MINIMUM_VERSION: (u64, u64, u64) = (2, 1, 0);
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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
    let expected_session_id = session_id.clone();
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
        move |line| parse_event_line(line, &expected_session_id),
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

fn parse_event_line(line: &str, expected_session_id: &str) -> Result<ParsedEvent> {
    let value: Value = serde_json::from_str(line)?;
    let event_type = value.get("type").and_then(Value::as_str);
    match event_type {
        Some("system") if value.get("subtype").and_then(Value::as_str) == Some("init") => {
            parse_session_event(&value, expected_session_id)
        }
        Some("assistant") => parse_assistant_event(&value, expected_session_id),
        Some("result") => parse_result_event(&value, expected_session_id),
        _ => Ok(ParsedEvent::Ignored),
    }
}

fn parse_session_event(value: &Value, expected_session_id: &str) -> Result<ParsedEvent> {
    if has_mismatched_session_id(value, expected_session_id) {
        return Ok(session_mismatch_event());
    }
    validated_session_id(value, expected_session_id).map(ParsedEvent::Session)
}

fn parse_assistant_event(value: &Value, expected_session_id: &str) -> Result<ParsedEvent> {
    if value
        .get("parent_tool_use_id")
        .is_some_and(|parent| !parent.is_null())
    {
        return Ok(ParsedEvent::Ignored);
    }
    let Some(message) = value.get("message") else {
        return Ok(ParsedEvent::Ignored);
    };
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Ok(ParsedEvent::Ignored);
    }
    let text = assistant_text(message.get("content"));
    if text.trim().is_empty() {
        return Ok(ParsedEvent::Ignored);
    }
    if has_mismatched_session_id(value, expected_session_id) {
        return Ok(session_mismatch_event());
    }
    validated_session_id(value, expected_session_id)?;
    Ok(ParsedEvent::Text(text))
}

fn assistant_text(content: Option<&Value>) -> String {
    let Some(Value::Array(parts)) = content else {
        return String::new();
    };
    parts
        .iter()
        .filter_map(|part| {
            (part.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| part.get("text").and_then(Value::as_str))
                .flatten()
        })
        .collect::<Vec<_>>()
        .join("")
}

fn validated_session_id(value: &Value, expected_session_id: &str) -> Result<String> {
    let session_id = value
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(normalize_session_id)
        .ok_or(HarnessError::Json)?;
    if session_id != expected_session_id {
        return Err(HarnessError::Json);
    }
    Ok(session_id)
}

fn has_mismatched_session_id(value: &Value, expected_session_id: &str) -> bool {
    value
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(normalize_session_id)
        .is_some_and(|session_id| session_id != expected_session_id)
}

fn session_mismatch_event() -> ParsedEvent {
    ParsedEvent::Error {
        session_id: None,
        summary: "session_mismatch".to_owned(),
    }
}

fn parse_result_event(value: &Value, expected_session_id: &str) -> Result<ParsedEvent> {
    if has_mismatched_session_id(value, expected_session_id) {
        return Ok(session_mismatch_event());
    }
    let session_id = validated_session_id(value, expected_session_id)?;
    let subtype = value.get("subtype").and_then(Value::as_str);
    let is_error = value
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if is_error || subtype != Some("success") {
        return Ok(ParsedEvent::Error {
            session_id: Some(session_id),
            summary: result_error_summary(subtype).to_owned(),
        });
    }
    Ok(ParsedEvent::Ignored)
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
    validate_cli_version_with_timeout(bin, VERSION_PROBE_TIMEOUT)
}

fn validate_cli_version_with_timeout(bin: &str, timeout: Duration) -> Result<()> {
    let (status, stdout) =
        bounded_command_output(Command::new(bin).arg("--version"), timeout, 4096)
            .map_err(|_| HarnessError::BackendSpawn)?;
    if !status.success() {
        return Err(HarnessError::Config(
            "Claude Code version check failed".to_owned(),
        ));
    }
    let stdout = String::from_utf8(stdout).map_err(|_| HarnessError::BackendSpawn)?;
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
    let value = value.trim();
    let candidate = value
        .strip_suffix(" (Claude Code)")
        .or_else(|| value.strip_prefix("claude-code "))?;
    let mut parts = candidate.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

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
    fn parser_emits_main_assistant_text_without_result_duplication() {
        assert_eq!(
            parse_event_line(
                &format!(r#"{{"type":"system","subtype":"init","session_id":"{SESSION}"}}"#),
                SESSION
            )
            .unwrap(),
            ParsedEvent::Session(SESSION.to_owned())
        );
        assert_eq!(
            parse_event_line(&format!(
                r#"{{"type":"result","subtype":"success","is_error":false,"result":"done","session_id":"{SESSION}"}}"#
            ), SESSION)
            .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parse_event_line(
                &format!(r#"{{"type":"assistant","session_id":"{SESSION}","parent_tool_use_id":null,"message":{{"role":"assistant","content":[{{"type":"thinking","thinking":"secret"}},{{"type":"text","text":"checking "}},{{"type":"tool_use","name":"Read"}},{{"type":"text","text":"done"}}]}}}}"#),
                SESSION,
            )
            .unwrap(),
            ParsedEvent::Text("checking done".to_owned())
        );
        for line in [
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"secret"}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","input":"secret"}]}}"#,
            r#"{"type":"assistant","parent_tool_use_id":"tool-1","message":{"role":"assistant","content":[{"type":"text","text":"subagent text"}]}}"#,
            r#"{"type":"user","message":{"content":"prompt"}}"#,
            r#"{"type":"stream_event","event":{"type":"content_block_delta"}}"#,
        ] {
            assert_eq!(
                parse_event_line(line, SESSION).unwrap(),
                ParsedEvent::Ignored
            );
        }
        assert!(parse_event_line("{", SESSION).is_err());
    }

    #[test]
    fn parser_sanitizes_failures_and_rejects_non_uuid_sessions() {
        assert_eq!(
            parse_event_line(&format!(
                r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"result":"private failure","session_id":"{SESSION}"}}"#
            ), SESSION)
            .unwrap(),
            ParsedEvent::Error {
                session_id: Some(SESSION.to_owned()),
                summary: "execution".to_owned(),
            }
        );
        assert!(
            parse_event_line(
                r#"{"type":"system","subtype":"init","session_id":"not-a-uuid"}"#,
                SESSION
            )
            .is_err()
        );
    }

    #[test]
    fn parser_rejects_missing_and_reports_mismatched_session_identity_before_output() {
        let other = "123e4567-e89b-12d3-a456-426614174000";
        for line in [
            r#"{"type":"assistant","parent_tool_use_id":null,"message":{"role":"assistant","content":[{"type":"text","text":"unbound"}]}}"#.to_owned(),
            r#"{"type":"result","subtype":"error_during_execution","is_error":true}"#.to_owned(),
        ] {
            assert!(parse_event_line(&line, SESSION).is_err(), "accepted {line}");
        }
        for line in [
            format!(r#"{{"type":"system","subtype":"init","session_id":"{other}"}}"#),
            format!(
                r#"{{"type":"assistant","session_id":"{other}","parent_tool_use_id":null,"message":{{"role":"assistant","content":[{{"type":"text","text":"wrong lane"}}]}}}}"#
            ),
            format!(
                r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"{other}"}}"#
            ),
        ] {
            assert_eq!(
                parse_event_line(&line, SESSION).unwrap(),
                session_mismatch_event()
            );
        }
    }

    #[test]
    fn version_parser_accepts_supported_cli_shapes() {
        assert_eq!(parse_version("2.1.270 (Claude Code)"), Some((2, 1, 270)));
        assert_eq!(parse_version("claude-code 2.1.0"), Some((2, 1, 0)));
        assert_eq!(parse_version("Claude Code"), None);
        assert_eq!(parse_version("warning 9.0.0\nClaude Code"), None);
        assert_eq!(parse_version("warning 9.0.0\n2.1.270 (Claude Code)"), None);
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn wait_for_process_exit(pid: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_is_active(pid) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        !process_is_active(pid)
    }

    #[cfg(unix)]
    fn process_is_active(pid: &str) -> bool {
        let exists = Command::new("kill")
            .args(["-0", pid])
            .output()
            .is_ok_and(|output| output.status.success());
        if !exists {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            let state = fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| stat.rsplit_once(") ").map(|(_, rest)| rest.to_owned()))
                .and_then(|rest| rest.chars().next());
            state != Some('Z')
        }
        #[cfg(not(target_os = "linux"))]
        {
            Command::new("ps")
                .args(["-o", "state=", "-p", pid])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| {
                    output
                        .stdout
                        .into_iter()
                        .find(|byte| !byte.is_ascii_whitespace())
                })
                .is_some_and(|state| state != b'Z')
        }
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
    #[test]
    fn version_probe_times_out_and_reaps_a_hung_cli() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("hanging");
        let pid_path = root.path().join("descendant.pid");
        write_executable(
            &script,
            &format!(
                "#!/usr/bin/env bash\nsleep 30 &\necho $! > {}\nwait\n",
                pid_path.display()
            ),
        );
        let started = Instant::now();

        let error =
            validate_cli_version_with_timeout(script.to_str().unwrap(), Duration::from_secs(2))
                .expect_err("hung version probe must fail within the configured timeout");

        assert!(matches!(error, HarnessError::BackendSpawn));
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = fs::read_to_string(&pid_path).unwrap();
        let pid = pid.trim();
        assert!(
            wait_for_process_exit(pid),
            "version-probe descendant {pid} survived timeout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_deadline_covers_inherited_stdout_after_leader_exit() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("inherited-stdout");
        let pid_path = root.path().join("descendant.pid");
        write_executable(
            &script,
            &format!(
                "#!/bin/sh\nsleep 30 &\necho $! > {}\nprintf '%s\\n' '2.1.270 (Claude Code)'\nexit 0\n",
                pid_path.display()
            ),
        );
        let started = Instant::now();
        let result =
            validate_cli_version_with_timeout(script.to_str().unwrap(), Duration::from_secs(2));
        assert!(matches!(result, Err(HarnessError::BackendSpawn)));
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = fs::read_to_string(pid_path).unwrap();
        assert!(
            wait_for_process_exit(pid.trim()),
            "stdout holder survived timeout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_rejects_excess_output_without_filling_the_pipe() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("verbose-version");
        write_executable(
            &script,
            "#!/bin/sh\nwhile :; do printf '2.1.270 (Claude Code)'; done\n",
        );
        let started = Instant::now();
        let result =
            validate_cli_version_with_timeout(script.to_str().unwrap(), Duration::from_secs(2));
        assert!(matches!(result, Err(HarnessError::BackendSpawn)));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_pipes_prompt_and_returns_completed_assistant_messages() {
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
printf '%s\n' '{"type":"assistant","session_id":"'"$session"'","parent_tool_use_id":null,"message":{"role":"assistant","content":[{"type":"text","text":"intermediate"},{"type":"thinking","thinking":"secret"},{"type":"tool_use","name":"Read"}]}}'
printf '{"type":"assistant","session_id":"%s","parent_tool_use_id":null,"message":{"role":"assistant","content":[{"type":"text","text":"reply: %s"}]}}\n' "$session" "$prompt"
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
            Some(RunnerEvent::Text("intermediate".to_owned()))
        );
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
    async fn resumed_session_mismatch_is_reported_without_forwarding_text() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("mismatched-claude");
        let other = "123e4567-e89b-12d3-a456-426614174000";
        write_executable(
            &script,
            &format!(
                r#"#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' '{{"type":"system","subtype":"init","session_id":"{other}"}}'
printf '%s\n' '{{"type":"assistant","session_id":"{other}","parent_tool_use_id":null,"message":{{"role":"assistant","content":[{{"type":"text","text":"wrong lane"}}]}}}}'
printf '%s\n' '{{"type":"result","subtype":"success","is_error":false,"session_id":"{other}"}}'
"#
            ),
        );
        let (tx, mut rx) = mpsc::channel(2);

        let outcome = run_with_bin(
            script.to_str().unwrap(),
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(2),
                cwd: root.path().to_path_buf(),
                session_id: Some(SESSION.to_owned()),
                prompt: "resume".to_owned(),
                artifact_output: None,
            },
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.error_summary.as_deref(), Some("session_mismatch"));
        assert!(rx.recv().await.is_none());
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
