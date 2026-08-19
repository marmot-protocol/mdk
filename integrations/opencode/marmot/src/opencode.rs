use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Backend, ExecutionProfile, ExecutionSupport, Invocation, IsolationSupport,
    Outcome, ParsedEvent, PromptTransport, Result, RunFailure, RunnerEvent,
    process::{EnvironmentChange, ProcessSpec, run_jsonl_process},
};
use serde::Deserialize;
use tokio::sync::mpsc;

#[derive(Clone)]
pub(crate) struct OpencodeBackend {
    pub(crate) bin: String,
    pub(crate) execution_profile: ExecutionProfile,
}

#[async_trait]
impl Backend for OpencodeBackend {
    fn execution_support(&self) -> ExecutionSupport {
        ExecutionSupport {
            approvals: match self.execution_profile {
                ExecutionProfile::Inherit => ApprovalSupport::Inherited,
                ExecutionProfile::Autonomous => ApprovalSupport::PreserveDenies,
                ExecutionProfile::Unrestricted => ApprovalSupport::ForceAllow,
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
    } = invocation;
    let environment = config_overlay(execution_profile)
        .map(|(remove, name, value)| {
            vec![
                EnvironmentChange::Remove(remove),
                EnvironmentChange::Set {
                    name,
                    value: value.to_owned(),
                },
            ]
        })
        .unwrap_or_default();
    run_jsonl_process(
        ProcessSpec {
            executable: bin.to_owned(),
            args: build_run_args(session_id.as_deref(), execution_profile),
            cwd,
            environment,
            prompt: PromptTransport::Stdin(prompt),
            trace_method: "opencode_run",
            backend_name: "opencode",
            total_timeout: timeout,
            idle_timeout,
        },
        tx,
        parse_event_line,
    )
    .await
}

pub(crate) fn build_run_args(
    session_id: Option<&str>,
    execution_profile: ExecutionProfile,
) -> Vec<String> {
    let mut args = vec!["run".to_owned(), "--format".to_owned(), "json".to_owned()];
    if matches!(
        execution_profile,
        ExecutionProfile::Autonomous | ExecutionProfile::Unrestricted
    ) {
        args.push("--auto".to_owned());
    }
    if let Some(session_id) = session_id
        && !session_id.is_empty()
    {
        args.push("--session".to_owned());
        args.push(session_id.to_owned());
    }
    args
}

fn config_overlay(profile: ExecutionProfile) -> Option<(&'static str, &'static str, &'static str)> {
    (profile == ExecutionProfile::Unrestricted).then_some((
        "OPENCODE_PERMISSION",
        "OPENCODE_CONFIG_CONTENT",
        r#"{"permission":"allow"}"#,
    ))
}

fn parse_event_line(line: &str) -> Result<ParsedEvent> {
    let event = serde_json::from_str::<OpencodeEvent>(line)?;
    Ok(match event {
        OpencodeEvent::Text { part } => ParsedEvent::Text(part.text),
        OpencodeEvent::Error { session_id, error } => ParsedEvent::Error {
            session_id,
            summary: error.summary(),
        },
        OpencodeEvent::StepStart {
            session_id: Some(session_id),
        } => ParsedEvent::Session(session_id),
        OpencodeEvent::StepStart { session_id: None }
        | OpencodeEvent::StepFinish {}
        | OpencodeEvent::Other => ParsedEvent::Ignored,
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use marmot_terminal_harness::{ExecutionProfile, HarnessError};
    use tokio::sync::mpsc;

    use super::*;

    const MOCK_BIN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mock-opencode.sh"
    );

    async fn run(
        invocation: Invocation,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure> {
        run_with_bin(MOCK_BIN, ExecutionProfile::Inherit, invocation, tx).await
    }

    fn mock_invocation(dir: &tempfile::TempDir, scenario: &str) -> Invocation {
        Invocation {
            timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_millis(500),
            cwd: dir.path().to_path_buf(),
            session_id: None,
            prompt: scenario.to_owned(),
        }
    }

    #[test]
    fn build_run_args_keeps_prompt_out_of_process_arguments() {
        assert_eq!(
            build_run_args(Some("ses_123"), ExecutionProfile::Inherit),
            vec!["run", "--format", "json", "--session", "ses_123"]
        );
    }

    #[test]
    fn parse_opencode_text_and_session_events() {
        assert_eq!(
            parse_event_line(r#"{"type":"step_start","sessionID":"ses_1"}"#).unwrap(),
            ParsedEvent::Session("ses_1".to_owned())
        );
        assert_eq!(
            parse_event_line(r#"{"type":"text","part":{"text":"hello"}}"#).unwrap(),
            ParsedEvent::Text("hello".to_owned())
        );
    }

    #[test]
    fn parse_opencode_error_event_summary() {
        assert_eq!(
            parse_event_line(
                r#"{"type":"error","sessionID":"ses_err","error":{"name":"APIError","data":{"statusCode":404}}}"#
            )
            .unwrap(),
            ParsedEvent::Error {
                session_id: Some("ses_err".to_owned()),
                summary: "APIError status=404".to_owned()
            }
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_streams_text_from_mock_binary() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let mut invocation = mock_invocation(&dir, "stream-text");
        invocation.idle_timeout = Duration::from_secs(2);
        let outcome = run(invocation, tx).await.unwrap();
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
                // The mock child sleeps longer than this idle budget after the
                // session line so CI load cannot race idle timeout with normal exit.
                idle_timeout: Duration::from_secs(2),
                ..mock_invocation(&dir, "idle")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::BackendIdle));
        assert_eq!(failure.observed_session.as_deref(), Some("ses_idle"));
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
            matches!(failure.error, HarnessError::BackendTimedOut),
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
        assert!(matches!(failure.error, HarnessError::BackendIdle));
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
        assert!(matches!(failure.error, HarnessError::BackendIdle));
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
        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_failure_keeps_session_despite_channel_backpressure() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let failure = run(
            Invocation {
                // The mock is a spawned shell process. Leave enough startup
                // budget for it to emit the session before the total timeout
                // even when the full workspace suite is CPU-bound.
                timeout: Duration::from_secs(2),
                idle_timeout: Duration::from_secs(5),
                ..mock_invocation(&dir, "session-backpressure")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert_eq!(
            failure.observed_session.as_deref(),
            Some("ses_backpressure")
        );
    }

    #[test]
    fn args_apply_typed_permission_profiles_without_putting_prompt_in_args() {
        for (profile, permission_args) in [
            (ExecutionProfile::Inherit, Vec::<&str>::new()),
            (ExecutionProfile::Autonomous, vec!["--auto"]),
            (ExecutionProfile::Unrestricted, vec!["--auto"]),
        ] {
            let mut expected = vec!["run", "--format", "json"];
            expected.extend(permission_args.iter().copied());
            assert_eq!(build_run_args(None, profile), expected);

            let mut resumed = vec!["run", "--format", "json"];
            resumed.extend(permission_args.iter().copied());
            resumed.extend(["--session", "session-123"]);
            assert_eq!(build_run_args(Some("session-123"), profile), resumed);
        }
    }

    #[test]
    fn unrestricted_uses_a_process_local_config_overlay_only() {
        assert_eq!(config_overlay(ExecutionProfile::Inherit), None);
        assert_eq!(config_overlay(ExecutionProfile::Autonomous), None);
        assert_eq!(
            config_overlay(ExecutionProfile::Unrestricted),
            Some((
                "OPENCODE_PERMISSION",
                "OPENCODE_CONFIG_CONTENT",
                r#"{"permission":"allow"}"#
            ))
        );
    }
}
