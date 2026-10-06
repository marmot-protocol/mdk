use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Backend, ExecutionProfile, ExecutionSupport, HarnessError, Invocation,
    IsolationSupport, Outcome, ParsedEvent, PromptTransport, Result, RunFailure, RunnerEvent,
    process::{EnvironmentChange, ProcessSpec, bounded_command_output, run_jsonl_process},
};
use serde_json::Value;
use tokio::sync::mpsc;
use uuid::Uuid;

const MINIMUM_VERSION: (u64, u64, u64) = (1, 53, 0);
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Prefix for connector-generated Goose session names; the suffix is a random UUID.
const SESSION_NAME_PREFIX: &str = "wn-goose-";
/// Terminal error text Goose emits after handling SIGINT during a headless run.
const INTERRUPTED_ERROR: &str = "Headless run interrupted";

/// Connector-owned Goose permission override for one invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GoosePermission {
    /// Leave `GOOSE_MODE` and the operator's Goose config unchanged.
    Inherited,
    /// Set `GOOSE_MODE=auto` on the child only. Goose's auto mode approves every
    /// tool call and does not consult `never_allow` permissions.
    AutoApproveAll,
}

impl GoosePermission {
    fn from_profile(profile: ExecutionProfile) -> Result<Self> {
        match profile {
            ExecutionProfile::Inherit => Ok(Self::Inherited),
            ExecutionProfile::Unrestricted => Ok(Self::AutoApproveAll),
            // Goose's headless approve/smart_approve modes abort on the first ask, and its
            // auto mode ignores never_allow; no Goose mode avoids asks while keeping denies.
            ExecutionProfile::Autonomous => Err(HarnessError::Config(
                "Goose has no non-interactive mode that preserves tool denies; set \
                 MARMOT_HARNESS_EXECUTION_PROFILE to `inherit` or `unrestricted`"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Clone)]
pub(crate) struct GooseBackend {
    bin: String,
    permission: GoosePermission,
    path_root: Option<PathBuf>,
}

impl GooseBackend {
    pub(crate) fn new(
        bin: String,
        execution_profile: ExecutionProfile,
        path_root: Option<PathBuf>,
    ) -> Result<Self> {
        let permission = GoosePermission::from_profile(execution_profile)?;
        validate_cli_version(&bin)?;
        // Create (or tighten) the connector-owned Goose root only after every check passes.
        if let Some(path_root) = &path_root {
            fs_private::create_dir_all_private(path_root)?;
        }
        Ok(Self {
            bin,
            permission,
            path_root,
        })
    }
}

#[async_trait]
impl Backend for GooseBackend {
    fn execution_support(&self) -> ExecutionSupport {
        ExecutionSupport {
            approvals: match self.permission {
                GoosePermission::Inherited => ApprovalSupport::Inherited,
                GoosePermission::AutoApproveAll => ApprovalSupport::Bypassed,
            },
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
            self.permission,
            self.path_root.as_deref(),
            invocation,
            tx,
        )
        .await
    }
}

async fn run_with_bin(
    bin: &str,
    permission: GoosePermission,
    path_root: Option<&std::path::Path>,
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
    let session_name = match session_id {
        Some(value) => normalize_session_name(&value).ok_or_else(invalid_session_failure)?,
        None => format!("{SESSION_NAME_PREFIX}{}", Uuid::new_v4()),
    };
    let mut parser = GooseEventParser::new(session_name.clone());
    run_jsonl_process(
        ProcessSpec {
            executable: bin.to_owned(),
            args: build_run_args(&session_name, resume),
            cwd,
            environment: build_environment(permission, path_root),
            prompt: PromptTransport::Stdin(prompt),
            trace_method: "goose_run",
            backend_name: "goose",
            total_timeout: timeout,
            idle_timeout,
        },
        tx,
        move |line| parser.parse_line(line),
    )
    .await
}

fn invalid_session_failure() -> RunFailure {
    RunFailure {
        error: HarnessError::Config("Goose session name is not connector-generated".to_owned()),
        observed_session: None,
    }
}

/// Goose's stream-json output carries no session identity, so continuity relies on a
/// connector-generated, user-provided session name. Goose never auto-renames a session
/// whose name was user-provided, and without `--resume` `--name` always creates a session.
fn build_run_args(session_name: &str, resume: bool) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--instructions".to_owned(),
        "-".to_owned(),
        "--output-format".to_owned(),
        "stream-json".to_owned(),
        "--quiet".to_owned(),
    ];
    if resume {
        args.push("--resume".to_owned());
    }
    args.push("--name".to_owned());
    args.push(session_name.to_owned());
    args
}

fn build_environment(
    permission: GoosePermission,
    path_root: Option<&std::path::Path>,
) -> Vec<EnvironmentChange> {
    let mut environment = Vec::new();
    if permission == GoosePermission::AutoApproveAll {
        environment.push(EnvironmentChange::Set {
            name: "GOOSE_MODE",
            value: "auto".to_owned(),
        });
    }
    if let Some(path_root) = path_root {
        environment.push(EnvironmentChange::Set {
            name: "GOOSE_PATH_ROOT",
            value: path_root.to_string_lossy().into_owned(),
        });
    }
    environment
}

fn normalize_session_name(value: &str) -> Option<String> {
    let suffix = value.strip_prefix(SESSION_NAME_PREFIX)?;
    Uuid::parse_str(suffix)
        .ok()
        .map(|uuid| format!("{SESSION_NAME_PREFIX}{uuid}"))
}

/// Assistant text accumulated from stream chunks that share one Goose message id.
struct PendingText {
    id: Option<String>,
    text: String,
}

/// Stateful decoder for `goose run --output-format stream-json`.
///
/// Goose streams each assistant message as chunks that share a message id and carry text
/// deltas. A message is complete once a message with a different id arrives or the run
/// reports `complete`; text still pending at a terminal `error` is dropped as partial.
struct GooseEventParser {
    session_name: String,
    session_reported: bool,
    finished: bool,
    pending: Option<PendingText>,
}

impl GooseEventParser {
    fn new(session_name: String) -> Self {
        Self {
            session_name,
            session_reported: false,
            finished: false,
            pending: None,
        }
    }

    fn parse_line(&mut self, line: &str) -> Result<ParsedEvent> {
        let value: Value = serde_json::from_str(line)?;
        let event_type = value
            .get("type")
            .and_then(Value::as_str)
            .ok_or(HarnessError::Json)?;
        if self.finished {
            return Ok(ParsedEvent::Ignored);
        }
        let event = match event_type {
            "message" => self.parse_message(value.get("message").ok_or(HarnessError::Json)?)?,
            "complete" => {
                self.finished = true;
                self.flush()
            }
            "error" => {
                let summary = match value.get("error").and_then(Value::as_str) {
                    Some(INTERRUPTED_ERROR) => "interrupted",
                    Some(_) => "error",
                    None => return Err(HarnessError::Json),
                };
                self.finished = true;
                self.pending = None;
                // Goose emits stream events only after the named session exists.
                return Ok(ParsedEvent::Error {
                    session_id: Some(self.session_name.clone()),
                    summary: summary.to_owned(),
                });
            }
            // `notification` and future event types carry no reply text.
            _ => ParsedEvent::Ignored,
        };
        Ok(self.with_session(event))
    }

    /// Reports the session on the first valid event that carries nothing else. The first
    /// valid event never flushes text, because pending text implies an earlier message.
    fn with_session(&mut self, event: ParsedEvent) -> ParsedEvent {
        if self.session_reported || event != ParsedEvent::Ignored {
            return event;
        }
        self.session_reported = true;
        ParsedEvent::Session(self.session_name.clone())
    }

    fn parse_message(&mut self, message: &Value) -> Result<ParsedEvent> {
        let id = match message.get("id") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) => Some(id.clone()),
            Some(_) => return Err(HarnessError::Json),
        };
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .ok_or(HarnessError::Json)?;
        let Some(Value::Array(content)) = message.get("content") else {
            return Err(HarnessError::Json);
        };
        let user_visible = message
            .get("metadata")
            .and_then(|metadata| metadata.get("userVisible"))
            .and_then(Value::as_bool)
            .ok_or(HarnessError::Json)?;
        let text = user_visible_text(content)?;

        let is_assistant = role == "assistant";
        // Chunks of one message share an id. Id-less assistant chunks cannot be told apart,
        // so they are joined until a different message or a terminal event arrives.
        let continues_pending = is_assistant
            && self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.id == id);
        let flushed = if continues_pending {
            ParsedEvent::Ignored
        } else {
            self.flush()
        };
        if is_assistant && user_visible && !text.is_empty() {
            match &mut self.pending {
                Some(pending) if continues_pending => pending.text.push_str(&text),
                _ => self.pending = Some(PendingText { id, text }),
            }
        }
        Ok(flushed)
    }

    fn flush(&mut self) -> ParsedEvent {
        match self.pending.take() {
            Some(pending) if !pending.text.trim().is_empty() => ParsedEvent::Text(pending.text),
            _ => ParsedEvent::Ignored,
        }
    }
}

/// Joins `text` blocks meant for the user; thinking, tool, and notification blocks are
/// never forwarded, nor is text whose audience excludes the user. A malformed text block
/// rejects the whole event rather than defaulting to visible.
fn user_visible_text(content: &[Value]) -> Result<String> {
    let mut joined = String::new();
    for block in content {
        if block.get("type").and_then(Value::as_str) != Some("text") {
            continue;
        }
        let text = block
            .get("text")
            .and_then(Value::as_str)
            .ok_or(HarnessError::Json)?;
        let audience = match block.get("annotations") {
            None | Some(Value::Null) => None,
            Some(Value::Object(annotations)) => match annotations.get("audience") {
                None | Some(Value::Null) => None,
                Some(Value::Array(audience)) => Some(audience),
                Some(_) => return Err(HarnessError::Json),
            },
            Some(_) => return Err(HarnessError::Json),
        };
        if audience.is_none_or(|audience| audience.iter().any(|role| role == "user")) {
            joined.push_str(text);
        }
    }
    Ok(joined)
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
            "Goose version check failed".to_owned(),
        ));
    }
    let stdout = String::from_utf8(stdout).map_err(|_| HarnessError::BackendSpawn)?;
    let version = parse_version(&stdout).ok_or_else(|| {
        HarnessError::Config("Goose returned an unsupported version string".to_owned())
    })?;
    if version < MINIMUM_VERSION {
        return Err(HarnessError::Config(
            "Goose 1.53.0 or newer is required".to_owned(),
        ));
    }
    Ok(())
}

/// Goose sets an empty clap display name, so `--version` prints ` 1.53.0`; accept the
/// conventional `goose 1.53.0` shape as well.
fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.trim();
    let candidate = value.strip_prefix("goose ").unwrap_or(value).trim();
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
    use std::time::Instant;

    use super::*;

    const SESSION: &str = "wn-goose-550e8400-e29b-41d4-a716-446655440000";

    fn message(id: &str, role: &str, content: &str) -> String {
        format!(
            r#"{{"type":"message","message":{{"id":"{id}","role":"{role}","created":1,"content":{content},"metadata":{{"userVisible":true,"agentVisible":true}}}}}}"#
        )
    }

    fn text(value: &str) -> String {
        format!(r#"[{{"type":"text","text":"{value}"}}]"#)
    }

    #[test]
    fn args_keep_prompts_on_stdin_and_select_sessions_by_name() {
        assert_eq!(
            build_run_args(SESSION, false),
            vec![
                "run",
                "--instructions",
                "-",
                "--output-format",
                "stream-json",
                "--quiet",
                "--name",
                SESSION,
            ]
        );
        assert_eq!(
            build_run_args(SESSION, true),
            vec![
                "run",
                "--instructions",
                "-",
                "--output-format",
                "stream-json",
                "--quiet",
                "--resume",
                "--name",
                SESSION,
            ]
        );
    }

    #[test]
    fn profiles_map_to_child_only_goose_mode_and_reject_autonomous() {
        assert_eq!(
            GoosePermission::from_profile(ExecutionProfile::Inherit).unwrap(),
            GoosePermission::Inherited
        );
        assert_eq!(
            GoosePermission::from_profile(ExecutionProfile::Unrestricted).unwrap(),
            GoosePermission::AutoApproveAll
        );
        let error = GoosePermission::from_profile(ExecutionProfile::Autonomous).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("MARMOT_HARNESS_EXECUTION_PROFILE")
        );

        assert!(build_environment(GoosePermission::Inherited, None).is_empty());
        let unrestricted =
            build_environment(GoosePermission::AutoApproveAll, Some(Path::new("/goose")));
        assert!(matches!(
            unrestricted.as_slice(),
            [
                EnvironmentChange::Set { name: "GOOSE_MODE", value: mode },
                EnvironmentChange::Set { name: "GOOSE_PATH_ROOT", value: root },
            ] if mode == "auto" && root == "/goose"
        ));
    }

    #[test]
    fn session_names_are_connector_generated_and_normalized() {
        assert_eq!(normalize_session_name(SESSION).as_deref(), Some(SESSION));
        assert_eq!(
            normalize_session_name("wn-goose-550E8400-E29B-41D4-A716-446655440000").as_deref(),
            Some(SESSION)
        );
        for invalid in [
            "",
            "550e8400-e29b-41d4-a716-446655440000",
            "20261005_3",
            "wn-goose-",
            "wn-goose-../x",
            "--resume",
        ] {
            assert_eq!(normalize_session_name(invalid), None, "accepted {invalid}");
        }
    }

    #[test]
    fn parser_joins_chunks_by_message_id_and_forwards_only_user_text() {
        let mut parser = GooseEventParser::new(SESSION.to_owned());
        assert_eq!(
            parser
                .parse_line(&message(
                    "m1",
                    "assistant",
                    r#"[{"type":"thinking","thinking":"secret","signature":""}]"#
                ))
                .unwrap(),
            ParsedEvent::Session(SESSION.to_owned())
        );
        assert_eq!(
            parser
                .parse_line(&message("m1", "assistant", &text("checking ")))
                .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parser
                .parse_line(&message("m1", "assistant", &text("files")))
                .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parser
                .parse_line(&message(
                    "m1",
                    "assistant",
                    r#"[{"type":"toolRequest","id":"t1","toolCall":{"status":"success","value":{"name":"shell","arguments":{"command":"secret"}}}}]"#
                ))
                .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parser
                .parse_line(&message(
                    "m2",
                    "user",
                    r#"[{"type":"toolResponse","id":"t1","toolResult":{"status":"success","value":[]}}]"#
                ))
                .unwrap(),
            ParsedEvent::Text("checking files".to_owned())
        );
        assert_eq!(
            parser
                .parse_line(r#"{"type":"notification","extension_id":"developer","log":{"message":"secret"}}"#)
                .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parser
                .parse_line(&message(
                    "m3",
                    "assistant",
                    r#"[{"type":"text","text":"hidden","annotations":{"audience":["assistant"]}},{"type":"text","text":"done"}]"#
                ))
                .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parser
                .parse_line(r#"{"type":"complete","total_tokens":10}"#)
                .unwrap(),
            ParsedEvent::Text("done".to_owned())
        );
        assert_eq!(
            parser
                .parse_line(&message("m4", "assistant", &text("late")))
                .unwrap(),
            ParsedEvent::Ignored
        );
    }

    #[test]
    fn parser_joins_id_less_chunks_and_skips_hidden_messages() {
        let mut parser = GooseEventParser::new(SESSION.to_owned());
        let no_id = |role: &str, content: &str| {
            format!(
                r#"{{"type":"message","message":{{"id":null,"role":"{role}","created":1,"content":{content},"metadata":{{"userVisible":true,"agentVisible":true}}}}}}"#
            )
        };
        assert_eq!(
            parser
                .parse_line(&no_id("assistant", &text("one ")))
                .unwrap(),
            ParsedEvent::Session(SESSION.to_owned())
        );
        assert_eq!(
            parser
                .parse_line(&no_id("assistant", &text("reply")))
                .unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            parser
                .parse_line(&no_id(
                    "user",
                    r#"[{"type":"toolResponse","id":"t1","toolResult":{"status":"success","value":[]}}]"#
                ))
                .unwrap(),
            ParsedEvent::Text("one reply".to_owned())
        );
        assert_eq!(
            parser
                .parse_line(&no_id("assistant", &text("second")))
                .unwrap(),
            ParsedEvent::Ignored
        );
        let hidden = r#"{"type":"message","message":{"id":"h1","role":"assistant","created":1,"content":[{"type":"text","text":"internal"}],"metadata":{"userVisible":false,"agentVisible":true}}}"#;
        assert_eq!(
            parser.parse_line(hidden).unwrap(),
            ParsedEvent::Text("second".to_owned())
        );
        assert_eq!(
            parser.parse_line(r#"{"type":"complete"}"#).unwrap(),
            ParsedEvent::Ignored
        );
    }

    #[test]
    fn parser_sanitizes_errors_and_drops_partial_text() {
        let mut parser = GooseEventParser::new(SESSION.to_owned());
        parser
            .parse_line(&message("m1", "assistant", &text("partial")))
            .unwrap();
        assert_eq!(
            parser
                .parse_line(r#"{"type":"error","error":"private provider failure"}"#)
                .unwrap(),
            ParsedEvent::Error {
                session_id: Some(SESSION.to_owned()),
                summary: "error".to_owned(),
            }
        );
        assert_eq!(
            parser.parse_line(r#"{"type":"complete"}"#).unwrap(),
            ParsedEvent::Ignored
        );

        let mut interrupted = GooseEventParser::new(SESSION.to_owned());
        assert_eq!(
            interrupted
                .parse_line(r#"{"type":"error","error":"Headless run interrupted"}"#)
                .unwrap(),
            ParsedEvent::Error {
                session_id: Some(SESSION.to_owned()),
                summary: "interrupted".to_owned(),
            }
        );
    }

    #[test]
    fn parser_rejects_malformed_events_without_reporting_a_session() {
        let mut parser = GooseEventParser::new(SESSION.to_owned());
        for line in [
            "{",
            "not json",
            r#"{"message":{}}"#,
            r#"{"type":"message"}"#,
            r#"{"type":"message","message":{"id":7,"role":"assistant","content":[]}}"#,
            r#"{"type":"message","message":{"id":"m1","content":[]}}"#,
            r#"{"type":"message","message":{"id":"m1","role":"assistant","content":"text"}}"#,
            r#"{"type":"error"}"#,
            // Visibility must be explicit and well-formed; malformed markers never default to visible.
            r#"{"type":"message","message":{"id":"m1","role":"assistant","content":[{"type":"text","text":"x"}]}}"#,
            r#"{"type":"message","message":{"id":"m1","role":"assistant","content":[{"type":"text","text":"x"}],"metadata":{"userVisible":"false"}}}"#,
            r#"{"type":"message","message":{"id":"m1","role":"assistant","content":[{"type":"text","text":"x"}],"metadata":{"userVisible":null}}}"#,
            r#"{"type":"message","message":{"id":"m1","role":"assistant","content":[{"type":"text","text":"x","annotations":{"audience":"assistant"}}],"metadata":{"userVisible":true}}}"#,
            r#"{"type":"message","message":{"id":"m1","role":"assistant","content":[{"type":"text","text":"x","annotations":"assistant"}],"metadata":{"userVisible":true}}}"#,
            r#"{"type":"message","message":{"id":"m1","role":"assistant","content":[{"type":"text","text":7}],"metadata":{"userVisible":true}}}"#,
        ] {
            assert!(parser.parse_line(line).is_err(), "accepted {line}");
        }
        assert_eq!(
            parser.parse_line(r#"{"type":"future_event"}"#).unwrap(),
            ParsedEvent::Session(SESSION.to_owned())
        );
        assert_eq!(
            parser.parse_line(r#"{"type":"complete"}"#).unwrap(),
            ParsedEvent::Ignored
        );
    }

    #[test]
    fn version_parser_accepts_supported_cli_shapes() {
        assert_eq!(parse_version(" 1.53.0\n"), Some((1, 53, 0)));
        assert_eq!(parse_version("goose 1.60.2"), Some((1, 60, 2)));
        assert_eq!(parse_version("goose"), None);
        assert_eq!(parse_version("1.53"), None);
        assert_eq!(parse_version("warning 9.0.0\n1.53.0"), None);
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn invocation(root: &Path, session_id: Option<&str>, prompt: &str) -> Invocation {
        Invocation {
            timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(2),
            cwd: root.to_path_buf(),
            session_id: session_id.map(str::to_owned),
            prompt: prompt.to_owned(),
            artifact_output: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn version_check_rejects_old_malformed_and_failing_clis() {
        let root = tempfile::tempdir().unwrap();
        for (name, body) in [
            ("old", "printf '%s\\n' ' 1.52.9'"),
            ("malformed", "printf '%s\\n' 'goose'"),
            ("failing", "exit 64"),
        ] {
            let script = root.path().join(name);
            write_executable(&script, &format!("#!/usr/bin/env bash\n{body}\n"));
            assert!(
                validate_cli_version(script.to_str().unwrap()).is_err(),
                "accepted {name} Goose CLI"
            );
        }

        let supported = root.path().join("supported");
        write_executable(
            &supported,
            "#!/usr/bin/env bash\nprintf '%s\\n' ' 1.53.0'\n",
        );
        validate_cli_version(supported.to_str().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn version_probe_times_out_on_a_hung_cli() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("hanging");
        write_executable(&script, "#!/usr/bin/env bash\nsleep 30\n");
        let started = Instant::now();
        let error =
            validate_cli_version_with_timeout(script.to_str().unwrap(), Duration::from_secs(1))
                .expect_err("hung version probe must fail");
        assert!(matches!(error, HarnessError::BackendSpawn));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn backend_rejects_autonomous_before_probing_goose() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-goose");
        let error = GooseBackend::new(
            missing.to_string_lossy().into_owned(),
            ExecutionProfile::Autonomous,
            None,
        )
        .err()
        .expect("autonomous profile");
        assert!(matches!(error, HarnessError::Config(_)));
    }

    #[cfg(unix)]
    #[test]
    fn backend_creates_path_root_only_after_goose_validates() {
        let root = tempfile::tempdir().unwrap();
        let path_root = root.path().join("goose-root");
        let old = root.path().join("old-goose");
        write_executable(&old, "#!/usr/bin/env bash\nprintf '%s\\n' ' 1.52.0'\n");
        assert!(
            GooseBackend::new(
                old.to_string_lossy().into_owned(),
                ExecutionProfile::Inherit,
                Some(path_root.clone()),
            )
            .is_err()
        );
        assert!(
            !path_root.exists(),
            "rejected startup created the Goose root"
        );

        let supported = root.path().join("goose");
        write_executable(
            &supported,
            "#!/usr/bin/env bash\nprintf '%s\\n' ' 1.53.0'\n",
        );
        GooseBackend::new(
            supported.to_string_lossy().into_owned(),
            ExecutionProfile::Inherit,
            Some(path_root.clone()),
        )
        .unwrap();
        let mode = fs::metadata(&path_root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_pipes_prompt_and_returns_completed_assistant_messages() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("fake-goose");
        let args_path = root.path().join("args");
        let env_path = root.path().join("env");
        write_executable(
            &script,
            &format!(
                r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > {args}
printf '%s|%s\n' "${{GOOSE_MODE:-unset}}" "${{GOOSE_PATH_ROOT:-unset}}" > {env}
prompt="$(cat)"
emit() {{
  printf '{{"type":"message","message":{{"id":"%s","role":"%s","created":1,"content":%s,"metadata":{{"userVisible":true,"agentVisible":true}}}}}}\n' "$1" "$2" "$3"
}}
emit m1 assistant '[{{"type":"text","text":"inter"}}]'
emit m1 assistant '[{{"type":"text","text":"mediate"}}]'
emit m1 assistant '[{{"type":"toolRequest","id":"t1"}}]'
emit m2 user '[{{"type":"toolResponse","id":"t1"}}]'
emit m3 assistant "[{{\"type\":\"text\",\"text\":\"reply: $prompt\"}}]"
printf '%s\n' '{{"type":"complete","total_tokens":3}}'
"#,
                args = args_path.display(),
                env = env_path.display(),
            ),
        );
        let path_root = root.path().join("goose-root");
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            GoosePermission::AutoApproveAll,
            Some(&path_root),
            invocation(root.path(), None, "--stdin-only"),
            tx,
        )
        .await
        .unwrap();

        let session = outcome.observed_session.expect("session name");
        assert!(normalize_session_name(&session).is_some());
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.error_summary, None);
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("intermediate".to_owned()))
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("reply: --stdin-only".to_owned()))
        );
        assert!(rx.recv().await.is_none());

        let args = fs::read_to_string(&args_path).unwrap();
        let args: Vec<&str> = args.lines().collect();
        assert_eq!(
            args,
            [
                "run",
                "--instructions",
                "-",
                "--output-format",
                "stream-json",
                "--quiet",
                "--name",
                session.as_str(),
            ]
        );
        assert_eq!(
            fs::read_to_string(&env_path).unwrap().trim(),
            format!("auto|{}", path_root.display())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_resumes_the_stored_session_name() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("fake-goose");
        let args_path = root.path().join("args");
        let env_path = root.path().join("env");
        write_executable(
            &script,
            &format!(
                r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > {args}
printf '%s\n' "${{GOOSE_MODE:-unset}}" > {env}
cat >/dev/null
printf '%s\n' '{{"type":"message","message":{{"id":"m1","role":"assistant","created":1,"content":[{{"type":"text","text":"resumed"}}],"metadata":{{"userVisible":true,"agentVisible":true}}}}}}'
printf '%s\n' '{{"type":"complete"}}'
"#,
                args = args_path.display(),
                env = env_path.display(),
            ),
        );
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            GoosePermission::Inherited,
            None,
            invocation(root.path(), Some(SESSION), "again"),
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.observed_session.as_deref(), Some(SESSION));
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("resumed".to_owned()))
        );
        let args = fs::read_to_string(&args_path).unwrap();
        assert!(args.ends_with(&format!("--resume\n--name\n{SESSION}\n")));
        assert_eq!(fs::read_to_string(&env_path).unwrap().trim(), "unset");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_rejects_foreign_session_names_before_spawn() {
        let root = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let failure = run_with_bin(
            root.path().join("never-spawned").to_str().unwrap(),
            GoosePermission::Inherited,
            None,
            invocation(root.path(), Some("20261005_3"), "prompt"),
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::Config(_)));
        assert_eq!(failure.observed_session, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_reports_sanitized_errors_and_bounded_stderr() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("failing-goose");
        write_executable(
            &script,
            r#"#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' '{"type":"message","message":{"id":"m1","role":"assistant","created":1,"content":[{"type":"text","text":"partial"}],"metadata":{"userVisible":true,"agentVisible":true}}}'
printf '%s\n' '{"type":"error","error":"private provider failure"}'
printf '%s\n' 'Error: private provider failure' >&2
exit 1
"#,
        );
        let (tx, mut rx) = mpsc::channel(2);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            GoosePermission::Inherited,
            None,
            invocation(root.path(), None, "private prompt"),
            tx,
        )
        .await
        .unwrap();

        assert_eq!(outcome.exit_code, Some(1));
        assert_eq!(outcome.error_summary.as_deref(), Some("error"));
        assert!(outcome.observed_session.is_some());
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_does_not_claim_a_session_when_goose_fails_before_streaming() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("missing-session-goose");
        write_executable(
            &script,
            r#"#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' "Error: No session found with name 'x'" >&2
exit 1
"#,
        );
        let (tx, _rx) = mpsc::channel(1);
        let outcome = run_with_bin(
            script.to_str().unwrap(),
            GoosePermission::Inherited,
            None,
            invocation(root.path(), None, "prompt"),
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.exit_code, Some(1));
        assert_eq!(outcome.observed_session, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_enforces_total_timeout() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("slow-goose");
        write_executable(&script, "#!/usr/bin/env bash\ncat >/dev/null\nsleep 5\n");
        let (tx, _rx) = mpsc::channel(1);
        let mut slow = invocation(root.path(), None, "private prompt");
        slow.timeout = Duration::from_millis(100);
        let failure = run_with_bin(
            script.to_str().unwrap(),
            GoosePermission::Inherited,
            None,
            slow,
            tx,
        )
        .await
        .unwrap_err();

        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert_eq!(failure.observed_session, None);
    }

    #[tokio::test]
    #[ignore = "requires a configured Goose provider and makes real model requests"]
    async fn real_goose_contract() {
        validate_cli_version("goose").unwrap();
        let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let contract_invocation = |session_id: Option<String>, prompt: &str| Invocation {
            timeout: Duration::from_secs(180),
            idle_timeout: Duration::from_secs(60),
            cwd: cwd.clone(),
            session_id,
            prompt: prompt.to_owned(),
            artifact_output: None,
        };

        let (tx, mut rx) = mpsc::channel(8);
        let first = run_with_bin(
            "goose",
            GoosePermission::Inherited,
            None,
            contract_invocation(
                None,
                "Remember the word MARMOT. Reply with exactly GOOSE_CONNECTOR_OK and nothing else.",
            ),
            tx,
        )
        .await
        .unwrap();
        assert_eq!(first.exit_code, Some(0));
        let session_id = first.observed_session.expect("session name");
        let mut reply = String::new();
        while let Some(RunnerEvent::Text(text)) = rx.recv().await {
            reply.push_str(&text);
        }
        assert_eq!(reply.trim(), "GOOSE_CONNECTOR_OK");

        let (resume_tx, mut resume_rx) = mpsc::channel(8);
        let resumed = run_with_bin(
            "goose",
            GoosePermission::Inherited,
            None,
            contract_invocation(
                Some(session_id.clone()),
                "Reply with exactly the word I asked you to remember and nothing else.",
            ),
            resume_tx,
        )
        .await
        .unwrap();
        assert_eq!(resumed.exit_code, Some(0));
        assert_eq!(
            resumed.observed_session.as_deref(),
            Some(session_id.as_str())
        );
        let mut resumed_reply = String::new();
        while let Some(RunnerEvent::Text(text)) = resume_rx.recv().await {
            resumed_reply.push_str(&text);
        }
        assert_eq!(resumed_reply.trim(), "MARMOT");
    }
}
