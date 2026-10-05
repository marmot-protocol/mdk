use std::path::Path;

use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Attachment, Backend, ExecutionProfile, ExecutionSupport, HarnessError,
    Invocation, IsolationSupport, Outcome, ParsedEvent, PromptTransport, Result, RunFailure,
    RunnerEvent,
    attachment_preflight::{is_utf8_text, revalidate},
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
        run_with_bin(&self.bin, self.execution_profile, invocation, &[], tx).await
    }

    async fn run_with_attachments(
        &self,
        invocation: Invocation,
        attachments: Vec<Attachment>,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure> {
        run_with_bin(
            &self.bin,
            self.execution_profile,
            invocation,
            &attachments,
            tx,
        )
        .await
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
    attachments: &[Attachment],
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
    let files = prepare_attachments(attachments).map_err(|error| RunFailure {
        error,
        observed_session: None,
    })?;
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
            args: build_run_args(session_id.as_deref(), execution_profile, &files),
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

/// Builds `opencode run` argv. Staged files follow every option as repeated `--file <path>`
/// pairs, then `--` ends option parsing; the prompt itself is written to stdin.
fn build_run_args(
    session_id: Option<&str>,
    execution_profile: ExecutionProfile,
    files: &[String],
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
    if !files.is_empty() {
        for file in files {
            args.push("--file".to_owned());
            args.push(file.clone());
        }
        args.push("--".to_owned());
    }
    args
}

/// Revalidates every staged copy immediately before spawn and returns their absolute paths in
/// source order. Any file OpenCode would not deliver as its own content fails the whole batch.
fn prepare_attachments(attachments: &[Attachment]) -> Result<Vec<String>> {
    attachments
        .iter()
        .map(|attachment| {
            let revalidated = revalidate(attachment)?;
            if !opencode_reads_file(&revalidated.staged_path, &revalidated.bytes) {
                return Err(HarnessError::AttachmentUnsupported);
            }
            Ok(revalidated.staged_path)
        })
        .collect()
}

/// Bytes OpenCode's Read tool samples when classifying a file.
const READ_SAMPLE_BYTES: usize = 4096;

/// Extensions whose `mime-types` lookup yields a media type OpenCode sends as-is.
const MEDIA_EXTENSIONS: &[&str] = &["gif", "jpe", "jpeg", "jpg", "pdf", "png", "webp"];

/// Extensions OpenCode's Read tool refuses as binary regardless of content.
const BINARY_EXTENSIONS: &[&str] = &[
    "7z", "a", "bin", "class", "dat", "dll", "doc", "docx", "exe", "gz", "jar", "lib", "o", "obj",
    "odp", "ods", "odt", "ppt", "pptx", "pyc", "pyo", "so", "tar", "war", "wasm", "xls", "xlsx",
    "zip",
];

enum Sniffed {
    /// PNG, JPEG, GIF, WebP, or PDF: attached natively from the file bytes.
    Media,
    /// BMP: not a supported image, so OpenCode falls through to its text path.
    Bmp,
}

/// Mirrors OpenCode v1.18.18 `run --file` without `--attach`: every file is resolved through
/// the Read tool, which sniffs the first 4 KiB (`util/media.ts`), falls back to an extension
/// lookup, attaches PNG/JPEG/GIF/WebP/PDF natively, and reads everything else as text unless
/// it looks binary (`tool/read.ts`). Text must also be valid UTF-8 here so it reaches the model
/// unchanged. A Read failure would reach the model as an error note instead of the file.
fn opencode_reads_file(staged_path: &str, bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(READ_SAMPLE_BYTES)];
    let extension = Path::new(staged_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    let extension = extension.as_deref();
    match sniff_media(sample) {
        Some(Sniffed::Media) => return true,
        Some(Sniffed::Bmp) => {}
        None => {
            if extension.is_some_and(|extension| MEDIA_EXTENSIONS.contains(&extension)) {
                return false;
            }
        }
    }
    !extension.is_some_and(|extension| BINARY_EXTENSIONS.contains(&extension))
        && !looks_binary(sample)
        && is_utf8_text(bytes)
}

fn sniff_media(sample: &[u8]) -> Option<Sniffed> {
    if sample.starts_with(b"\x89PNG\r\n\x1a\n")
        || sample.starts_with(b"\xff\xd8\xff")
        || sample.starts_with(b"GIF8")
    {
        return Some(Sniffed::Media);
    }
    if sample.starts_with(b"BM") {
        return Some(Sniffed::Bmp);
    }
    if sample.starts_with(b"%PDF-")
        || (sample.starts_with(b"RIFF") && sample.get(8..12) == Some(b"WEBP".as_slice()))
    {
        return Some(Sniffed::Media);
    }
    None
}

/// OpenCode's binary heuristic: any NUL, or more than 30% control bytes outside `\t`..`\r`.
fn looks_binary(sample: &[u8]) -> bool {
    if sample.contains(&0) {
        return true;
    }
    let control = sample
        .iter()
        .filter(|&&byte| byte < 9 || (byte > 13 && byte < 32))
        .count();
    control * 10 > sample.len() * 3
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
        run_with_bin(MOCK_BIN, ExecutionProfile::Inherit, invocation, &[], tx).await
    }

    fn mock_invocation(dir: &tempfile::TempDir, scenario: &str) -> Invocation {
        Invocation {
            timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_millis(500),
            cwd: dir.path().to_path_buf(),
            session_id: None,
            prompt: scenario.to_owned(),
            artifact_output: None,
        }
    }

    #[test]
    fn build_run_args_keeps_prompt_out_of_process_arguments() {
        assert_eq!(
            build_run_args(Some("ses_123"), ExecutionProfile::Inherit, &[]),
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
    async fn run_presentation_idle_reports_unknown_and_waits_for_total_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let failure = run(
            Invocation {
                timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_millis(200),
                ..mock_invocation(&dir, "idle")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert_eq!(failure.observed_session.as_deref(), Some("ses_idle"));
        assert_eq!(rx.recv().await, Some(RunnerEvent::LivenessUnknown));
        assert!(rx.recv().await.is_none());
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
    async fn run_stdout_eof_reports_unknown_and_waits_for_total_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let started = Instant::now();
        let failure = run(
            Invocation {
                timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_millis(200),
                ..mock_invocation(&dir, "stdout-close-live")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert!(started.elapsed() >= Duration::from_millis(800));
        assert_eq!(rx.recv().await, Some(RunnerEvent::LivenessUnknown));
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_eof_keeps_original_presentation_idle_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let started = Instant::now();
        let failure = run(
            Invocation {
                timeout: Duration::from_millis(1_200),
                idle_timeout: Duration::from_secs(1),
                ..mock_invocation(&dir, "stdout-close-near-idle")
            },
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "stdout EOF must not reset the existing idle deadline"
        );
        assert_eq!(rx.recv().await, Some(RunnerEvent::LivenessUnknown));
        assert!(rx.recv().await.is_none());
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
            assert_eq!(build_run_args(None, profile, &[]), expected);

            let mut resumed = vec!["run", "--format", "json"];
            resumed.extend(permission_args.iter().copied());
            resumed.extend(["--session", "session-123"]);
            assert_eq!(build_run_args(Some("session-123"), profile, &[]), resumed);
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

    fn attachment(path: &std::path::Path) -> Attachment {
        Attachment {
            path: path.to_path_buf(),
            media_type: "application/octet-stream".to_owned(),
            file_name: path.file_name().unwrap().to_str().unwrap().to_owned(),
            size_bytes: std::fs::metadata(path).unwrap().len(),
        }
    }

    const SCENARIO_BIN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/mock-opencode-scenario.sh"
    );

    /// Writes the body that `SCENARIO_BIN` runs when invoked with `workdir` as its cwd.
    fn write_scenario(workdir: &std::path::Path, body: &str) {
        std::fs::write(
            workdir.join("opencode-scenario.sh"),
            format!("set -euo pipefail\n{body}"),
        )
        .unwrap();
    }

    /// Private staging layout matching the shared bridge: an owner-only batch directory.
    #[cfg(unix)]
    fn private_batch(root: &std::path::Path) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let staging = root.join("staging");
        std::fs::create_dir(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
        tempfile::Builder::new()
            .prefix("batch-")
            .tempdir_in(&staging)
            .unwrap()
    }

    fn file_invocation(cwd: &std::path::Path, session_id: Option<&str>) -> Invocation {
        Invocation {
            timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(5),
            cwd: cwd.to_path_buf(),
            session_id: session_id.map(str::to_owned),
            prompt: "caption: compare these files".to_owned(),
            artifact_output: None,
        }
    }

    fn read_lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn file_args_follow_options_in_source_order_for_every_profile_and_session() {
        let one = vec!["/staging/batch-a/000-notes.txt".to_owned()];
        let many = vec![
            "/staging/batch-a/000-z.png".to_owned(),
            "/staging/batch-a/001-a.pdf".to_owned(),
            "/staging/batch-a/002-caf\u{e9} na\u{ef}ve.txt".to_owned(),
            "/staging/batch-a/-leading-dash.txt".to_owned(),
        ];
        for (profile, permission_args) in [
            (ExecutionProfile::Inherit, Vec::<&str>::new()),
            (ExecutionProfile::Autonomous, vec!["--auto"]),
            (ExecutionProfile::Unrestricted, vec!["--auto"]),
        ] {
            for session in [None, Some("ses_existing")] {
                let mut base = vec!["run", "--format", "json"];
                base.extend(permission_args.iter().copied());
                if let Some(session) = session {
                    base.extend(["--session", session]);
                }
                assert_eq!(build_run_args(session, profile, &[]), base);
                for files in [&one, &many] {
                    let mut expected = base.clone();
                    for file in files {
                        expected.extend(["--file", file.as_str()]);
                    }
                    expected.push("--");
                    assert_eq!(build_run_args(session, profile, files), expected);
                }
            }
        }
    }

    #[test]
    fn staged_paths_are_absolute_so_a_leading_dash_leaf_stays_an_option_value() {
        let root = tempfile::tempdir().unwrap();
        let dashed = root.path().join("-rf.txt");
        std::fs::write(&dashed, b"notes\n").unwrap();
        let files = prepare_attachments(&[attachment(&dashed)]).unwrap();
        assert_eq!(files, vec![dashed.to_str().unwrap().to_owned()]);
        assert!(files[0].starts_with('/'));

        let relative = Attachment {
            path: std::path::PathBuf::from("-rf.txt"),
            ..attachment(&dashed)
        };
        assert!(matches!(
            prepare_attachments(&[relative]),
            Err(HarnessError::AttachmentInvalid)
        ));
    }

    #[test]
    fn file_matrix_mirrors_the_opencode_read_tool() {
        let mut bmp = b"BM".to_vec();
        bmp.extend([0_u8; 64]);
        for (name, bytes) in [
            ("000-notes.txt", b"plain notes\n".as_slice()),
            ("001-build.log", b"\x1b[31merror\x1b[0m\x0c\n"),
            ("002-README", "caf\u{e9} na\u{ef}ve\n".as_bytes()),
            ("003-empty.txt", b""),
            ("004-image.bin", b"\x89PNG\r\n\x1a\nimage"),
            ("005-photo.dat", b"\xff\xd8\xffjpeg"),
            ("006-anim.txt", b"GIF89a\x00\x00"),
            ("007-sticker", b"RIFF\x04\x00\x00\x00WEBPVP8 "),
            ("008-report.txt", b"%PDF-1.7\n\x00binary"),
            ("009-notes.png", b"BMW service notes\n"),
        ] {
            assert!(
                opencode_reads_file(name, bytes),
                "{name} should be accepted"
            );
        }
        for (name, bytes) in [
            ("010-fake.png", b"not an image".as_slice()),
            ("011-fake.PDF", b"not a pdf"),
            ("012-fake.jpeg", b""),
            ("013-notes.zip", b"plain text in a zip name"),
            ("014-letter.DOCX", b"plain text in a docx name"),
            ("015-nul.txt", b"text\0tail"),
            ("016-control.txt", b"\x01\x02\x03\x04ab"),
            ("017-latin1.txt", b"caf\xe9\n"),
            ("018-bitmap.bmp", bmp.as_slice()),
            (
                "019-sound.wav",
                b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00",
            ),
            ("020-archive", b"PK\x03\x04\x14\x00\x00\x00"),
        ] {
            assert!(
                !opencode_reads_file(name, bytes),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn binary_heuristic_uses_only_the_read_tool_sample() {
        let mut late_control = vec![b'a'; READ_SAMPLE_BYTES];
        late_control.extend([0x01_u8; READ_SAMPLE_BYTES]);
        assert!(opencode_reads_file("000-long.txt", &late_control));

        let mut boundary = vec![b'a'; 7];
        boundary.extend([0x01_u8; 3]);
        assert!(!looks_binary(&boundary));
        boundary[6] = 0x01;
        assert!(looks_binary(&boundary));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_attaches_every_staged_file_to_one_turn_and_keeps_the_prompt_on_stdin() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let expected_root = root.path().join("expected");
        std::fs::create_dir(&expected_root).unwrap();
        let fixtures = [
            ("000-notes.txt", b"private notes\n".as_slice()),
            ("001-report.pdf", b"%PDF-1.7\nprivate report"),
            ("002-pixel.png", b"\x89PNG\r\n\x1a\nfixture"),
            ("003-caf__na_ve_notes.md", "caf\u{e9}\n".as_bytes()),
            ("-leading-dash.txt", b"dash\n"),
        ];
        let mut attachments = Vec::new();
        let mut comparisons = Vec::new();
        for (name, bytes) in fixtures {
            let staged = batch.path().join(name);
            std::fs::write(&staged, bytes).unwrap();
            std::fs::write(expected_root.join(name), bytes).unwrap();
            attachments.push(attachment(&staged));
            comparisons.push(format!(
                "cmp -- '{}' '{}' || exit 65",
                staged.display(),
                expected_root.join(name).display()
            ));
        }
        let log = root.path().join("log");
        std::fs::create_dir(&log).unwrap();
        write_scenario(
            root.path(),
            &format!(
                r#"log='{log}'
printf '%s\n' "$@" > "$log/args"
printf '%s' "${{OPENCODE_CONFIG_CONTENT:-}}" > "$log/env"
cat > "$log/prompt"
printf 'x' >> "$log/count"
{comparisons}
session=ses_new
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--session" ]; then session="$2"; fi
  shift
done
printf '%s\n' "{{\"type\":\"step_start\",\"sessionID\":\"$session\"}}"
printf '%s\n' '{{"type":"reasoning","part":{{"text":"thinking"}}}}'
printf '%s\n' 'not json'
printf '%s\n' '{{"type":"tool_use","part":{{"tool":"read"}}}}'
printf '%s\n' '{{"type":"text","part":{{"text":"read every file"}}}}'
printf '%s\n' '{{"type":"step_finish"}}'
"#,
                log = log.display(),
                comparisons = comparisons.join("\n"),
            ),
        );
        let files = attachments
            .iter()
            .map(|attachment| attachment.path.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();

        let mut runs = 0;
        for profile in [
            ExecutionProfile::Inherit,
            ExecutionProfile::Autonomous,
            ExecutionProfile::Unrestricted,
        ] {
            for session in [None, Some("ses_existing")] {
                let (tx, mut rx) = mpsc::channel(8);
                let outcome = run_with_bin(
                    SCENARIO_BIN,
                    profile,
                    file_invocation(root.path(), session),
                    &attachments,
                    tx,
                )
                .await
                .unwrap();
                runs += 1;
                assert_eq!(outcome.exit_code, Some(0), "stderr: {}", outcome.stderr);
                assert_eq!(
                    outcome.observed_session.as_deref(),
                    Some(session.unwrap_or("ses_new"))
                );
                assert_eq!(
                    rx.recv().await,
                    Some(RunnerEvent::Text("read every file".to_owned()))
                );
                assert!(rx.recv().await.is_none());
                assert_eq!(
                    read_lines(&log.join("args")),
                    build_run_args(session, profile, &files)
                );
                assert_eq!(
                    std::fs::read_to_string(log.join("prompt")).unwrap(),
                    "caption: compare these files"
                );
                let overlay = config_overlay(profile).map_or("", |(_, _, value)| value);
                assert_eq!(std::fs::read_to_string(log.join("env")).unwrap(), overlay);
                assert_eq!(
                    std::fs::read_to_string(log.join("count")).unwrap().len(),
                    runs
                );
                assert!(
                    attachments
                        .iter()
                        .all(|attachment| attachment.path.is_file())
                );
            }
        }

        let batch_path = batch.path().to_path_buf();
        drop(batch);
        assert!(!batch_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unsupported_or_changed_file_rejects_the_whole_batch_before_opencode_starts() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let notes = batch.path().join("000-notes.txt");
        let opaque = batch.path().join("001-opaque.bin");
        std::fs::write(&notes, b"notes\n").unwrap();
        std::fs::write(&opaque, b"opaque\n").unwrap();
        let marker = root.path().join("started");
        write_scenario(root.path(), &format!("touch '{}'\n", marker.display()));

        let mut changed = attachment(&notes);
        changed.size_bytes += 1;
        for (batch_files, expected) in [
            (
                vec![attachment(&notes), attachment(&opaque)],
                "attachment_unsupported",
            ),
            (vec![attachment(&notes), changed], "attachment_invalid"),
        ] {
            let (tx, mut rx) = mpsc::channel(4);
            let failure = run_with_bin(
                SCENARIO_BIN,
                ExecutionProfile::Inherit,
                file_invocation(root.path(), Some("ses_existing")),
                &batch_files,
                tx,
            )
            .await
            .unwrap_err();
            assert_eq!(failure.error.privacy_safe_kind(), expected);
            assert_eq!(failure.observed_session, None);
            assert!(rx.recv().await.is_none());
            assert!(!marker.exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn opencode_rejection_with_files_is_reported_once_without_retry() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let notes = batch.path().join("000-notes.txt");
        std::fs::write(&notes, b"notes\n").unwrap();
        let count = root.path().join("count");
        write_scenario(
            root.path(),
            &format!(
                r#"cat >/dev/null
printf 'x' >> '{count}'
printf '%s\n' '{{"type":"step_start","sessionID":"ses_reject"}}'
printf '%s\n' '{{"type":"text","part":'
printf '%s\n' '{{"type":"error","sessionID":"ses_reject","error":{{"name":"UnknownError","data":{{"message":"secret path"}}}}}}'
echo 'Read tool failed' >&2
exit 1
"#,
                count = count.display()
            ),
        );

        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            SCENARIO_BIN,
            ExecutionProfile::Inherit,
            file_invocation(root.path(), None),
            &[attachment(&notes)],
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.exit_code, Some(1));
        assert_eq!(outcome.error_summary.as_deref(), Some("UnknownError"));
        assert_eq!(outcome.observed_session.as_deref(), Some("ses_reject"));
        assert!(rx.recv().await.is_none());
        assert_eq!(std::fs::read_to_string(&count).unwrap(), "x");
        assert!(notes.is_file());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_with_files_stops_the_single_turn_and_leaves_cleanup_to_the_batch_owner() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let notes = batch.path().join("000-notes.txt");
        std::fs::write(&notes, b"notes\n").unwrap();
        let count = root.path().join("count");
        write_scenario(
            root.path(),
            &format!(
                r#"cat >/dev/null
printf 'x' >> '{count}'
printf '%s\n' '{{"type":"step_start","sessionID":"ses_slow"}}'
exec sleep 30
"#,
                count = count.display()
            ),
        );

        let (tx, _rx) = mpsc::channel(4);
        let failure = run_with_bin(
            SCENARIO_BIN,
            ExecutionProfile::Inherit,
            Invocation {
                timeout: Duration::from_millis(1_500),
                ..file_invocation(root.path(), None)
            },
            &[attachment(&notes)],
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert_eq!(failure.observed_session.as_deref(), Some("ses_slow"));
        assert_eq!(std::fs::read_to_string(&count).unwrap(), "x");
        assert!(notes.is_file());
        let batch_path = batch.path().to_path_buf();
        drop(batch);
        assert!(!batch_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancelled_turn_terminates_opencode_before_batch_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let notes = batch.path().join("000-notes.txt");
        std::fs::write(&notes, b"notes\n").unwrap();
        let pid_file = root.path().join("pid");
        write_scenario(
            root.path(),
            &format!(
                "cat >/dev/null\nprintf '%s' \"$$\" > '{}'\nexec sleep 30\n",
                pid_file.display()
            ),
        );

        let (tx, _rx) = mpsc::channel(4);
        let invocation = file_invocation(root.path(), Some("ses_existing"));
        let attachments = vec![attachment(&notes)];
        let task = tokio::spawn(async move {
            run_with_bin(
                SCENARIO_BIN,
                ExecutionProfile::Inherit,
                invocation,
                &attachments,
                tx,
            )
            .await
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let pid = loop {
            if let Ok(pid) = std::fs::read_to_string(&pid_file)
                && !pid.is_empty()
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "fake OpenCode never started");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        // Gone, or a zombie awaiting reaping: either way it no longer runs.
        let proc_stat = std::path::PathBuf::from(format!("/proc/{pid}/stat"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(&proc_stat).is_ok_and(|stat| {
            stat.rsplit_once(") ")
                .is_some_and(|(_, rest)| !rest.starts_with('Z'))
        }) {
            assert!(
                Instant::now() < deadline,
                "fake OpenCode outlived cancellation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(notes.is_file());
        let batch_path = batch.path().to_path_buf();
        drop(batch);
        assert!(!batch_path.exists());
    }

    /// Opt-in contract against the installed OpenCode CLI, or `WN_OPENCODE_BIN` when set.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires authenticated OpenCode and makes real model requests"]
    async fn real_opencode_run_file_contract() {
        let bin = std::env::var("WN_OPENCODE_BIN").unwrap_or_else(|_| "opencode".to_owned());
        let version = std::process::Command::new(&bin)
            .arg("--version")
            .output()
            .expect("run opencode --version");
        assert!(version.status.success());
        assert!(!String::from_utf8_lossy(&version.stdout).trim().is_empty());

        let workdir = tempfile::tempdir().unwrap();
        let batch = private_batch(workdir.path());
        let first = batch.path().join("000-first-notes.txt");
        let second = batch.path().join("001-second-notes.txt");
        let first_token = "OPENCODE_FIRST_FILE_TOKEN_5C1E";
        let second_token = "OPENCODE_SECOND_FILE_TOKEN_9B7D";
        std::fs::write(&first, format!("{first_token}\n")).unwrap();
        std::fs::write(&second, format!("{second_token}\n")).unwrap();

        let turn = |session_id: Option<String>, prompt: &str| Invocation {
            timeout: Duration::from_secs(180),
            idle_timeout: Duration::from_secs(60),
            cwd: workdir.path().to_path_buf(),
            session_id,
            prompt: prompt.to_owned(),
            artifact_output: None,
        };
        async fn collect(mut rx: mpsc::Receiver<RunnerEvent>) -> String {
            let mut reply = String::new();
            while let Some(event) = rx.recv().await {
                if let RunnerEvent::Text(text) = event {
                    reply.push_str(&text);
                }
            }
            reply
        }

        let (tx, rx) = mpsc::channel(8);
        let outcome = run_with_bin(
            &bin,
            ExecutionProfile::Inherit,
            turn(
                None,
                "Reply with only the exact token contained in the attached file. The token is not in this prompt.",
            ),
            &[attachment(&first)],
            tx,
        )
        .await
        .unwrap();
        let reply = collect(rx).await;
        assert_eq!(outcome.exit_code, Some(0), "stderr: {}", outcome.stderr);
        assert_eq!(outcome.error_summary, None);
        assert!(reply.contains(first_token), "first reply: {reply:?}");
        let session_id = outcome.observed_session.expect("OpenCode session id");

        let (tx, rx) = mpsc::channel(8);
        let resumed = run_with_bin(
            &bin,
            ExecutionProfile::Inherit,
            turn(
                Some(session_id.clone()),
                "Reply with the token from the file attached to this message, then the token from the file attached to the previous message, separated by one space.",
            ),
            &[attachment(&second)],
            tx,
        )
        .await
        .unwrap();
        let reply = collect(rx).await;
        assert_eq!(resumed.exit_code, Some(0), "stderr: {}", resumed.stderr);
        assert_eq!(resumed.error_summary, None);
        assert_eq!(
            resumed.observed_session.as_deref(),
            Some(session_id.as_str())
        );
        assert!(
            reply.contains(second_token) && reply.contains(first_token),
            "resumed reply: {reply:?}"
        );
    }
}
