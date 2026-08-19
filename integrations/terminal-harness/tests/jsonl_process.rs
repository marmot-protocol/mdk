#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use marmot_terminal_harness::{
    ParsedEvent, PromptTransport, RunnerEvent,
    process::{EnvironmentChange, ProcessSpec, run_jsonl_process},
};
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

async fn process_test_permit() -> OwnedSemaphorePermit {
    static PROCESS_TESTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PROCESS_TESTS
        .get_or_init(|| Arc::new(Semaphore::new(1)))
        .clone()
        .acquire_owned()
        .await
        .unwrap()
}

fn executable_script(root: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = root.join(name);
    fs::write(&path, body).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

fn parse_event(line: &str) -> serde_json::Result<ParsedEvent> {
    let value: Value = serde_json::from_str(line)?;
    Ok(match value.get("type").and_then(Value::as_str) {
        Some("session") => value["id"]
            .as_str()
            .map(|id| ParsedEvent::Session(id.to_owned()))
            .unwrap_or(ParsedEvent::Ignored),
        Some("text") => value["text"]
            .as_str()
            .map(|text| ParsedEvent::Text(text.to_owned()))
            .unwrap_or(ParsedEvent::Ignored),
        Some("error") => ParsedEvent::Error {
            session_id: value["session_id"].as_str().map(str::to_owned),
            summary: value["class"]
                .as_str()
                .unwrap_or("classified_error")
                .to_owned(),
        },
        _ => ParsedEvent::Ignored,
    })
}

fn process_spec(
    executable: &std::path::Path,
    cwd: &std::path::Path,
    prompt: PromptTransport,
) -> ProcessSpec {
    ProcessSpec {
        executable: executable.to_string_lossy().into_owned(),
        args: Vec::new(),
        cwd: cwd.to_path_buf(),
        environment: Vec::new(),
        prompt,
        trace_method: "test_backend_run",
        backend_name: "test",
        total_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(2),
    }
}

#[tokio::test]
async fn shared_runner_supports_stdin_and_delimited_argument_prompts() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let stdin_script = executable_script(
        root.path(),
        "stdin-backend",
        r#"#!/bin/sh
prompt="$(cat)"
printf '%s\n' '{"type":"session","id":"first"}'
printf '{"type":"text","text":"stdin:%s"}\n' "$prompt"
"#,
    );
    let argument_script = executable_script(
        root.path(),
        "argument-backend",
        r#"#!/bin/sh
if [ "$1" != "--json" ] || [ "$2" != "--" ]; then exit 64; fi
printf '{"type":"text","text":"argument:%s"}\n' "$3"
"#,
    );

    for (executable, prompt, expected) in [
        (
            stdin_script,
            PromptTransport::Stdin("--stdin-prompt".to_owned()),
            "stdin:--stdin-prompt",
        ),
        (
            argument_script,
            PromptTransport::DelimitedArgument {
                delimiter: "--",
                prompt: "--argument-prompt".to_owned(),
            },
            "argument:--argument-prompt",
        ),
    ] {
        let (tx, mut rx) = mpsc::channel(2);
        let mut spec = process_spec(&executable, root.path(), prompt);
        spec.args = vec!["--json".to_owned()];
        let outcome = run_jsonl_process(spec, tx, parse_event).await.unwrap();

        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text(expected.to_owned()))
        );
        assert!(rx.recv().await.is_none());
    }
}

#[tokio::test]
async fn shared_runner_applies_process_local_environment_changes() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "environment-backend",
        r#"#!/bin/sh
if [ "${MARMOT_TEST_SET:-}" != "expected" ] || [ -n "${MARMOT_TEST_REMOVED:-}" ]; then
  exit 64
fi
printf '%s\n' '{"type":"text","text":"environment-ok"}'
"#,
    );
    let (tx, mut rx) = mpsc::channel(1);
    let mut spec = process_spec(&script, root.path(), PromptTransport::Stdin(String::new()));
    spec.environment = vec![
        EnvironmentChange::Set {
            name: "MARMOT_TEST_SET",
            value: "expected".to_owned(),
        },
        EnvironmentChange::Set {
            name: "MARMOT_TEST_REMOVED",
            value: "unexpected".to_owned(),
        },
        EnvironmentChange::Remove("MARMOT_TEST_REMOVED"),
    ];

    let outcome = run_jsonl_process(spec, tx, parse_event).await.unwrap();

    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(
        rx.recv().await,
        Some(RunnerEvent::Text("environment-ok".to_owned()))
    );
}

#[tokio::test]
async fn shared_runner_drops_malformed_and_ignored_events_and_keeps_first_session() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "event-backend",
        r#"#!/bin/sh
printf '%s\n' 'not-json'
printf '%s\n' '{"type":"progress","detail":"private"}'
printf '%s\n' '{"type":"session","id":""}'
printf '%s\n' '{"type":"session","id":"first"}'
printf '%s\n' '{"type":"session","id":"second"}'
printf '%s\n' '{"type":"error","session_id":"error-session","class":"first_error","message":"private"}'
printf '%s\n' '{"type":"error","class":"second_error","message":"also private"}'
printf '%s\n' '{"type":"text","text":"completed"}'
"#,
    );
    let (tx, mut rx) = mpsc::channel(2);
    let outcome = run_jsonl_process(
        process_spec(
            &script,
            root.path(),
            PromptTransport::DelimitedArgument {
                delimiter: "--",
                prompt: "prompt".to_owned(),
            },
        ),
        tx,
        parse_event,
    )
    .await
    .unwrap();

    assert_eq!(outcome.observed_session.as_deref(), Some("first"));
    assert_eq!(outcome.error_summary.as_deref(), Some("first_error"));
    assert_eq!(
        rx.recv().await,
        Some(RunnerEvent::Text("completed".to_owned()))
    );
}

#[tokio::test]
async fn stdout_reads_reset_the_idle_deadline() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "progress-backend",
        r#"#!/bin/sh
printf '%s\n' '{"type":"session","id":"progress"}'
sleep 0.1
printf '%s\n' '{"type":"progress"}'
sleep 0.1
printf '%s\n' '{"type":"text","text":"done"}'
"#,
    );
    let (tx, mut rx) = mpsc::channel(2);
    let mut spec = process_spec(&script, root.path(), PromptTransport::Stdin(String::new()));
    spec.idle_timeout = Duration::from_millis(500);
    let outcome = run_jsonl_process(spec, tx, parse_event).await.unwrap();

    assert_eq!(outcome.observed_session.as_deref(), Some("progress"));
    assert_eq!(rx.recv().await, Some(RunnerEvent::Text("done".to_owned())));
}

#[tokio::test]
async fn channel_backpressure_is_bounded_by_total_not_idle_timeout() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "backpressure-backend",
        r#"#!/bin/sh
printf '%s\n' '{"type":"session","id":"backpressure"}'
printf '%s\n' '{"type":"text","text":"first"}'
printf '%s\n' '{"type":"text","text":"second"}'
"#,
    );
    let (tx, _rx) = mpsc::channel(1);
    let mut spec = process_spec(&script, root.path(), PromptTransport::Stdin(String::new()));
    spec.total_timeout = Duration::from_secs(2);
    spec.idle_timeout = Duration::from_secs(10);
    let failure = run_jsonl_process(spec, tx, parse_event).await.unwrap_err();

    assert!(matches!(
        failure.error,
        marmot_terminal_harness::HarnessError::BackendTimedOut
    ));
    assert_eq!(failure.observed_session.as_deref(), Some("backpressure"));
}

#[tokio::test]
async fn total_timeout_covers_the_whole_lifecycle() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "total-timeout-backend",
        r#"#!/bin/sh
printf '%s\n' '{"type":"session","id":"total"}'
exec sleep 30
"#,
    );
    let (tx, _rx) = mpsc::channel(1);
    let mut spec = process_spec(&script, root.path(), PromptTransport::Stdin(String::new()));
    spec.total_timeout = Duration::from_secs(2);
    spec.idle_timeout = Duration::from_secs(5);
    let failure = run_jsonl_process(spec, tx, parse_event).await.unwrap_err();

    assert!(matches!(
        failure.error,
        marmot_terminal_harness::HarnessError::BackendTimedOut
    ));
    assert_eq!(failure.observed_session.as_deref(), Some("total"));
}

#[tokio::test]
async fn idle_timeout_applies_while_reading_output() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "output-idle-backend",
        r#"#!/bin/sh
printf '%s\n' '{"type":"session","id":"output-idle"}'
exec sleep 30
"#,
    );
    let (tx, _rx) = mpsc::channel(1);
    let mut spec = process_spec(&script, root.path(), PromptTransport::Stdin(String::new()));
    spec.idle_timeout = Duration::from_secs(2);
    let failure = run_jsonl_process(spec, tx, parse_event).await.unwrap_err();

    assert!(matches!(
        failure.error,
        marmot_terminal_harness::HarnessError::BackendIdle
    ));
    assert_eq!(failure.observed_session.as_deref(), Some("output-idle"));
}

#[tokio::test]
async fn idle_timeout_applies_after_stdout_eof_during_final_wait() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "wait-idle-backend",
        r#"#!/bin/sh
printf '%s\n' '{"type":"session","id":"wait-idle"}'
exec 1>&-
sleep 30
"#,
    );
    let (tx, _rx) = mpsc::channel(1);
    let mut spec = process_spec(
        &script,
        root.path(),
        PromptTransport::DelimitedArgument {
            delimiter: "--",
            prompt: "prompt".to_owned(),
        },
    );
    spec.idle_timeout = Duration::from_secs(2);
    let failure = run_jsonl_process(spec, tx, parse_event).await.unwrap_err();

    assert!(matches!(
        failure.error,
        marmot_terminal_harness::HarnessError::BackendIdle
    ));
    assert_eq!(failure.observed_session.as_deref(), Some("wait-idle"));
}

#[tokio::test]
async fn early_stdin_closure_preserves_exit_and_bounded_sanitized_stderr() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let script = executable_script(
        root.path(),
        "early-closure-backend",
        r#"#!/bin/sh
printf '\033[31m' >&2
i=0
while [ "$i" -lt 5000 ]; do printf x >&2; i=$((i + 1)); done
printf '\033[0m' >&2
exit 64
"#,
    );
    let (tx, _rx) = mpsc::channel(1);
    let outcome = run_jsonl_process(
        process_spec(
            &script,
            root.path(),
            PromptTransport::Stdin("p".repeat(60_000)),
        ),
        tx,
        parse_event,
    )
    .await
    .unwrap();

    assert_eq!(outcome.exit_code, Some(64));
    assert_eq!(outcome.stderr.len(), 4091);
    assert!(!outcome.stderr.contains('\u{1b}'));
}

#[tokio::test]
async fn timeout_terminates_and_reaps_the_child() {
    let _permit = process_test_permit().await;
    let root = tempfile::tempdir().unwrap();
    let pid_path = root.path().join("child.pid");
    let script = executable_script(
        root.path(),
        "reap-backend",
        r#"#!/bin/sh
printf '%s' "$$" > "$1"
exec sleep 30
"#,
    );
    let (tx, _rx) = mpsc::channel(1);
    let mut spec = process_spec(
        &script,
        root.path(),
        PromptTransport::DelimitedArgument {
            delimiter: "--",
            prompt: "prompt".to_owned(),
        },
    );
    spec.args = vec![pid_path.to_string_lossy().into_owned()];
    spec.total_timeout = Duration::from_secs(2);
    spec.idle_timeout = Duration::from_secs(5);
    let failure = run_jsonl_process(spec, tx, parse_event).await.unwrap_err();
    assert!(matches!(
        failure.error,
        marmot_terminal_harness::HarnessError::BackendTimedOut
    ));

    let pid = fs::read_to_string(pid_path).unwrap();
    let output = std::process::Command::new("kill")
        .args(["-0", pid.trim()])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "child process {pid} was not reaped"
    );
}

#[test]
fn process_debug_output_redacts_paths_arguments_prompts_and_events() {
    let spec = ProcessSpec {
        executable: "/secret/backend".to_owned(),
        args: vec!["secret-argument".to_owned()],
        cwd: "/secret/worktree".into(),
        environment: vec![EnvironmentChange::Set {
            name: "SECRET_ENVIRONMENT_NAME",
            value: "secret-environment-value".to_owned(),
        }],
        prompt: PromptTransport::Stdin("secret prompt".to_owned()),
        trace_method: "safe_method",
        backend_name: "safe_backend",
        total_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(2),
    };
    let debug = format!("{spec:?}");
    for secret in [
        "/secret/backend",
        "secret-argument",
        "/secret/worktree",
        "secret prompt",
        "SECRET_ENVIRONMENT_NAME",
        "secret-environment-value",
    ] {
        assert!(!debug.contains(secret));
    }
    assert!(
        !format!("{:?}", ParsedEvent::Session("secret-session".to_owned()))
            .contains("secret-session")
    );
    assert!(!format!("{:?}", ParsedEvent::Text("secret text".to_owned())).contains("secret text"));
}
