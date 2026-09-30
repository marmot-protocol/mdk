use std::path::Path;

use async_trait::async_trait;
use marmot_terminal_harness::{
    ApprovalSupport, Attachment, Backend, ExecutionProfile, ExecutionSupport, HarnessError,
    Invocation, IsolationSupport, Outcome, ParsedEvent, PromptTransport, Result, RunFailure,
    RunnerEvent,
    attachment_preflight::{Revalidated, is_utf8_text, revalidate},
    process::{ProcessSpec, run_jsonl_process},
};
use serde_json::Value;
use tokio::sync::mpsc;

/// Bytes Pi's `detectSupportedImageMimeTypeFromFile` sniffs from each `@file` operand.
const PI_IMAGE_SNIFF_BYTES: usize = 4100;
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
/// Sanitized summary when Pi's initial user message lacks an image it was given.
const ATTACHMENT_NOT_PROCESSED: &str = "an attachment it could not process";

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
            &[],
            tx,
        )
        .await
    }

    async fn run_with_attachments(
        &self,
        invocation: Invocation,
        attachments: Vec<Attachment>,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure> {
        run_with_bin(
            &self.bin,
            &self.session_dir,
            self.execution_profile,
            invocation,
            &attachments,
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
    let prepared = prepare_attachments(attachments).map_err(|error| RunFailure {
        error,
        observed_session: None,
    })?;
    let mut parser = PiEventParser::new(&prepared);
    run_jsonl_process(
        ProcessSpec {
            executable: bin.to_owned(),
            args: build_run_args(
                session_dir,
                session_id.as_deref(),
                execution_profile,
                &prepared,
            ),
            cwd,
            environment: Vec::new(),
            prompt: PromptTransport::Stdin(prompt),
            trace_method: "pi_run",
            backend_name: "pi",
            total_timeout: timeout,
            idle_timeout,
        },
        tx,
        |line| parser.parse(line),
    )
    .await
}

/// Pi options first, then one `@<absolute staged path>` operand per attachment in batch
/// order. Staged paths are absolute, so every operand starts with `@/` and Pi's parser
/// can only read it as a file argument. The prompt never appears here; it goes to stdin.
fn build_run_args(
    session_dir: &Path,
    session_id: Option<&str>,
    _execution_profile: ExecutionProfile,
    attachments: &[PreparedAttachment],
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
    args.extend(
        attachments
            .iter()
            .map(|attachment| attachment.operand.clone()),
    );
    args
}

/// How Pi's `@file` processor will consume one staged attachment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PiInput {
    /// Sent as typed image content.
    Image,
    /// Embedded as UTF-8 text in the initial user message.
    Text,
}

struct PreparedAttachment {
    operand: String,
    input: PiInput,
}

/// Revalidates each staged copy immediately before spawn and classifies it exactly as Pi
/// will, rejecting the whole batch when any file would be skipped or embedded as garbage.
fn prepare_attachments(attachments: &[Attachment]) -> Result<Vec<PreparedAttachment>> {
    attachments
        .iter()
        .map(|attachment| {
            let Revalidated { staged_path, bytes } = revalidate(attachment)?;
            // `revalidate` guarantees an absolute path; Pi still rewrites Unicode spaces
            // in `@file` operands before reading, which would open a different path.
            if staged_path.chars().any(is_pi_normalized_space) {
                return Err(HarnessError::AttachmentInvalid);
            }
            let input = if bytes.is_empty() {
                // Pi silently skips empty files.
                return Err(HarnessError::AttachmentUnsupported);
            } else if pi_detects_image(&bytes) {
                PiInput::Image
            } else if is_utf8_text(&bytes) {
                PiInput::Text
            } else {
                return Err(HarnessError::AttachmentUnsupported);
            };
            Ok(PreparedAttachment {
                operand: format!("@{staged_path}"),
                input,
            })
        })
        .collect()
}

fn is_pi_normalized_space(character: char) -> bool {
    matches!(
        character,
        '\u{00A0}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Mirrors Pi's `detectSupportedImageMimeType`. BMP is deliberately absent: Pi 0.79.6
/// reads BMP as text, so it is rejected as an unsupported binary.
fn pi_detects_image(bytes: &[u8]) -> bool {
    let header = &bytes[..bytes.len().min(PI_IMAGE_SNIFF_BYTES)];
    if header.starts_with(b"\xff\xd8\xff") {
        return header.get(3) != Some(&0xf7);
    }
    if header.starts_with(PNG_SIGNATURE) {
        return is_png(header) && !is_animated_png(header);
    }
    header.starts_with(b"GIF")
        || (header.starts_with(b"RIFF") && header.get(8..12) == Some(b"WEBP".as_slice()))
}

fn is_png(header: &[u8]) -> bool {
    header.len() >= 16
        && read_u32_be(header, PNG_SIGNATURE.len()) == 13
        && header.get(12..16) == Some(b"IHDR".as_slice())
}

fn is_animated_png(header: &[u8]) -> bool {
    let mut offset = PNG_SIGNATURE.len();
    while offset + 8 <= header.len() {
        let chunk_type = &header[offset + 4..offset + 8];
        if chunk_type == b"acTL" {
            return true;
        }
        if chunk_type == b"IDAT" {
            return false;
        }
        let next = offset as u64 + 12 + u64::from(read_u32_be(header, offset));
        if next > header.len() as u64 {
            return false;
        }
        offset = next as usize;
    }
    false
}

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    bytes.get(offset..offset + 4).map_or(0, |word| {
        u32::from_be_bytes([word[0], word[1], word[2], word[3]])
    })
}

/// Stateful Pi JSON-mode decoder for one invocation.
///
/// With attachments, Pi's first completed user message must carry exactly one image part
/// per accepted image. Pi replaces an image it cannot convert or resize with an
/// `[Image omitted: ...]` note instead of failing, so a mismatch fails the whole turn and
/// suppresses any later assistant text.
struct PiEventParser {
    input: InputCheck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputCheck {
    NotRequired,
    Pending { expected_images: usize },
    Verified,
    Rejected,
}

impl PiEventParser {
    fn new(attachments: &[PreparedAttachment]) -> Self {
        let input = if attachments.is_empty() {
            InputCheck::NotRequired
        } else {
            InputCheck::Pending {
                expected_images: attachments
                    .iter()
                    .filter(|attachment| attachment.input == PiInput::Image)
                    .count(),
            }
        };
        Self { input }
    }

    fn parse(&mut self, line: &str) -> serde_json::Result<ParsedEvent> {
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
        match message.get("role").and_then(Value::as_str) {
            Some("user") => Ok(self.check_user_input(message)),
            Some("assistant") => Ok(match self.input {
                InputCheck::NotRequired | InputCheck::Verified => assistant_event(message),
                InputCheck::Rejected => ParsedEvent::Ignored,
                InputCheck::Pending { .. } => {
                    self.input = InputCheck::Rejected;
                    attachment_not_processed()
                }
            }),
            _ => Ok(ParsedEvent::Ignored),
        }
    }

    fn check_user_input(&mut self, message: &Value) -> ParsedEvent {
        let InputCheck::Pending { expected_images } = self.input else {
            return ParsedEvent::Ignored;
        };
        let images = match message.get("content") {
            Some(Value::Array(parts)) => parts
                .iter()
                .filter(|part| part.get("type").and_then(Value::as_str) == Some("image"))
                .count(),
            _ => 0,
        };
        if images == expected_images {
            self.input = InputCheck::Verified;
            ParsedEvent::Ignored
        } else {
            self.input = InputCheck::Rejected;
            attachment_not_processed()
        }
    }
}

fn attachment_not_processed() -> ParsedEvent {
    ParsedEvent::Error {
        session_id: None,
        summary: ATTACHMENT_NOT_PROCESSED.to_owned(),
    }
}

fn assistant_event(message: &Value) -> ParsedEvent {
    let text = assistant_text(message.get("content"));
    if !text.is_empty() {
        return ParsedEvent::Text(text);
    }
    let stop_reason = message.get("stopReason").and_then(Value::as_str);
    if matches!(stop_reason, Some("error" | "aborted")) {
        return ParsedEvent::Error {
            session_id: None,
            summary: stop_reason.unwrap_or("error").to_owned(),
        };
    }
    ParsedEvent::Ignored
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

    fn parse_event_line(line: &str) -> serde_json::Result<ParsedEvent> {
        PiEventParser::new(&[]).parse(line)
    }

    #[test]
    fn args_select_json_session_dir_and_optional_session() {
        assert_eq!(
            build_run_args(
                Path::new("/private/sessions"),
                Some("abc-123"),
                ExecutionProfile::Inherit,
                &[],
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
                artifact_output: None,
            },
            &[],
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
                artifact_output: None,
            },
            &[],
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
                artifact_output: None,
            },
            &[],
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
                artifact_output: None,
            },
            &[],
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
                build_run_args(session_dir, None, profile, &[]),
                vec!["--mode", "json", "--session-dir", "/private/pi-sessions"]
            );
            assert_eq!(
                build_run_args(session_dir, Some("session-123"), profile, &[]),
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

    /// A decodable 2x2 RGB PNG, so real Pi can also resize and inline it.
    const PNG_2X2: &[u8] = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x02\x00\x00\x00\x02\x08\x02\x00\x00\x00\xfd\xd4\x9a\x73\x00\x00\x00\x10\x49\x44\x41\x54\x78\xda\x63\xf8\xcf\xc0\x00\x44\x0c\x10\x0a\x00\x1f\xee\x03\xfd\x63\x5e\xbb\x5b\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";
    const USER_WITH_ONE_IMAGE: &str = r#"{"type":"message_end","message":{"role":"user","content":[{"type":"text","text":"caption"},{"type":"image","mimeType":"image/png","data":""}]}}"#;
    const USER_WITHOUT_IMAGES: &str = r#"{"type":"message_end","message":{"role":"user","content":[{"type":"text","text":"[Image omitted: could not be resized below the inline image size limit.]"}]}}"#;
    const ASSISTANT_TEXT: &str = r#"{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"done"}],"stopReason":"stop"}}"#;

    fn staged(dir: &Path, name: &str, bytes: &[u8]) -> Attachment {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        Attachment {
            path,
            media_type: "application/octet-stream".to_owned(),
            file_name: name.to_owned(),
            size_bytes: bytes.len() as u64,
        }
    }

    fn private_batch(root: &Path) -> tempfile::TempDir {
        let batch = tempfile::Builder::new()
            .prefix("batch-")
            .tempdir_in(root)
            .unwrap();
        #[cfg(unix)]
        fs::set_permissions(batch.path(), fs::Permissions::from_mode(0o700)).unwrap();
        batch
    }

    #[cfg(unix)]
    fn write_script(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn invocation(cwd: &Path, session_id: Option<&str>, timeout: Duration) -> Invocation {
        Invocation {
            timeout,
            idle_timeout: Duration::from_secs(2),
            cwd: cwd.to_path_buf(),
            session_id: session_id.map(str::to_owned),
            prompt: "caption on stdin".to_owned(),
            artifact_output: None,
        }
    }

    fn operand(attachment: &Attachment) -> String {
        format!("@{}", attachment.path.to_str().unwrap())
    }

    #[test]
    fn args_append_one_ordered_file_operand_per_attachment_for_new_and_resumed_sessions() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        // Names as produced by the shared sanitizer from "--session-id", "@pixel.png",
        // and "a b;c.rs": option-looking or special-character names stay inert.
        let notes = staged(batch.path(), "000---session-id", b"notes\n");
        let pixel = staged(batch.path(), "001-pixel.png", PNG_2X2);
        let source = staged(batch.path(), "002-a_b_c.rs", b"fn main() {}\n");
        let session_dir = Path::new("/private/pi-sessions");
        let base = ["--mode", "json", "--session-dir", "/private/pi-sessions"];

        for files in [
            vec![],
            vec![pixel.clone()],
            vec![notes.clone(), pixel.clone(), source.clone()],
            vec![source.clone(), notes.clone()],
        ] {
            let prepared = prepare_attachments(&files).unwrap();
            let operands = files.iter().map(operand).collect::<Vec<_>>();
            assert!(operands.iter().all(|operand| operand.starts_with("@/")));

            let mut expected_new = base.map(str::to_owned).to_vec();
            expected_new.extend(operands.iter().cloned());
            assert_eq!(
                build_run_args(session_dir, None, ExecutionProfile::Inherit, &prepared),
                expected_new
            );

            let mut expected_resumed = base.map(str::to_owned).to_vec();
            expected_resumed.extend(["--session-id".to_owned(), "pi-session".to_owned()]);
            expected_resumed.extend(operands);
            assert_eq!(
                build_run_args(
                    session_dir,
                    Some("pi-session"),
                    ExecutionProfile::Unrestricted,
                    &prepared,
                ),
                expected_resumed
            );
        }
    }

    #[test]
    fn preflight_accepts_only_what_pis_file_processor_inlines() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let accepted = vec![
            staged(
                batch.path(),
                "000-notes.txt",
                "\u{feff}\x1b[31mlog\x1b[0m\r\nüñï\n".as_bytes(),
            ),
            staged(batch.path(), "001-pixel.png", PNG_2X2),
            staged(
                batch.path(),
                "002-photo.jpg",
                b"\xff\xd8\xff\xe0\x00\x10JFIF",
            ),
            staged(batch.path(), "003-anim.gif", b"GIF89a\x01\x00\x01\x00"),
            staged(
                batch.path(),
                "004-still.webp",
                b"RIFF\x04\x00\x00\x00WEBPVP8 ",
            ),
            // Pi sniffs a bare "GIF" prefix as an image even when the bytes are text.
            staged(batch.path(), "005-gif.txt", b"GIF is a format\n"),
        ];
        assert_eq!(
            prepare_attachments(&accepted)
                .unwrap()
                .iter()
                .map(|attachment| attachment.input)
                .collect::<Vec<_>>(),
            vec![
                PiInput::Text,
                PiInput::Image,
                PiInput::Image,
                PiInput::Image,
                PiInput::Image,
                PiInput::Image,
            ]
        );

        let mut apng = PNG_2X2[..33].to_vec();
        apng.extend_from_slice(
            b"\x00\x00\x00\x08acTL\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",
        );
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0x46, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0, 0x28, 0, 0, 0]);
        bmp.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 24, 0]);
        bmp.resize(70, 0);
        let unsupported: [(&str, &[u8]); 8] = [
            ("empty.txt", b""),
            ("nul.txt", b"text\0with nul"),
            ("latin1.txt", b"caf\xe9\n"),
            ("report.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"),
            ("bundle.zip", b"PK\x03\x04\x14\x00\x00\x00"),
            ("arith.jpg", b"\xff\xd8\xff\xf7\x00\x10"),
            ("anim.png", &apng),
            ("legacy.bmp", &bmp),
        ];
        for (index, (name, bytes)) in unsupported.into_iter().enumerate() {
            let mut mixed = accepted.clone();
            mixed.push(staged(
                batch.path(),
                &format!("{:03}-{name}", 100 + index),
                bytes,
            ));
            assert!(
                matches!(
                    prepare_attachments(&mixed),
                    Err(HarnessError::AttachmentUnsupported)
                ),
                "{name} must reject the whole batch"
            );
        }
    }

    #[test]
    fn preflight_rejects_paths_pi_would_rewrite_or_resolve_elsewhere() {
        let root = tempfile::tempdir().unwrap();
        let spaced = root.path().join("no\u{00a0}break");
        fs::create_dir(&spaced).unwrap();
        let rewritten = staged(&spaced, "000-notes.txt", b"notes\n");
        assert!(matches!(
            prepare_attachments(&[rewritten]),
            Err(HarnessError::AttachmentInvalid)
        ));

        let mut changed = staged(root.path(), "001-notes.txt", b"notes\n");
        changed.size_bytes += 1;
        assert!(matches!(
            prepare_attachments(&[changed]),
            Err(HarnessError::AttachmentInvalid)
        ));
    }

    #[test]
    fn parser_requires_pi_to_inline_every_accepted_image_before_forwarding_text() {
        let prepared = [
            PreparedAttachment {
                operand: "@/private/000-notes.txt".to_owned(),
                input: PiInput::Text,
            },
            PreparedAttachment {
                operand: "@/private/001-pixel.png".to_owned(),
                input: PiInput::Image,
            },
        ];
        let not_processed = ParsedEvent::Error {
            session_id: None,
            summary: ATTACHMENT_NOT_PROCESSED.to_owned(),
        };

        let mut verified = PiEventParser::new(&prepared);
        assert_eq!(
            verified.parse(USER_WITH_ONE_IMAGE).unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            verified.parse(ASSISTANT_TEXT).unwrap(),
            ParsedEvent::Text("done".to_owned())
        );

        let mut omitted = PiEventParser::new(&prepared);
        assert_eq!(omitted.parse(USER_WITHOUT_IMAGES).unwrap(), not_processed);
        assert_eq!(omitted.parse(ASSISTANT_TEXT).unwrap(), ParsedEvent::Ignored);

        let mut unverified = PiEventParser::new(&prepared);
        assert_eq!(unverified.parse(ASSISTANT_TEXT).unwrap(), not_processed);
        assert_eq!(
            unverified.parse(USER_WITH_ONE_IMAGE).unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            unverified.parse(ASSISTANT_TEXT).unwrap(),
            ParsedEvent::Ignored
        );

        let mut text_only = PiEventParser::new(&[]);
        assert_eq!(
            text_only.parse(USER_WITHOUT_IMAGES).unwrap(),
            ParsedEvent::Ignored
        );
        assert_eq!(
            text_only.parse(ASSISTANT_TEXT).unwrap(),
            ParsedEvent::Text("done".to_owned())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_pi_reads_every_staged_file_in_one_turn_and_batch_outlives_completion() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let expected_root = root.path().join("expected");
        fs::create_dir(&expected_root).unwrap();
        let fixtures: [(&str, &[u8]); 3] = [
            ("000---session-id", b"option-looking notes\n"),
            ("001-pixel.png", PNG_2X2),
            ("002-a_b_c.rs", b"fn main() {}\n"),
        ];
        let mut attachments = Vec::new();
        let mut checks = String::new();
        for (index, (name, bytes)) in fixtures.into_iter().enumerate() {
            let attachment = staged(batch.path(), name, bytes);
            let expected = expected_root.join(name);
            fs::write(&expected, bytes).unwrap();
            let position = index + 1;
            checks.push_str(&format!(
                "[ \"${{{position}}}\" = '{}' ] || exit 66\ncmp -- \"${{{position}#@}}\" '{}'\n",
                operand(&attachment),
                expected.display()
            ));
            attachments.push(attachment);
        }
        let script = root.path().join("fake-pi-files");
        write_script(
            &script,
            &format!(
                r#"#!/usr/bin/env bash
set -euo pipefail
[ "$1" = --mode ] && [ "$2" = json ] && [ "$3" = --session-dir ] || exit 64
shift 4
id=pi-files
if [ "${{1:-}}" = --session-id ]; then id="$2"; shift 2; fi
[ "$#" -eq 3 ] || exit 65
{checks}prompt="$(cat)"
[ "$prompt" = "caption on stdin" ] || exit 67
printf '{{"type":"session","version":3,"id":"%s"}}\n' "$id"
printf '%s\n' '{USER_WITH_ONE_IMAGE}'
printf '{{"type":"message_end","message":{{"role":"assistant","content":[{{"type":"text","text":"read %s files"}}],"stopReason":"stop"}}}}\n' "$#"
"#
            ),
        );
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();

        let mut session = None;
        for _ in 0..2 {
            let (tx, mut rx) = mpsc::channel(4);
            let outcome = run_with_bin(
                script.to_str().unwrap(),
                &session_dir,
                ExecutionProfile::Inherit,
                invocation(root.path(), session.as_deref(), Duration::from_secs(5)),
                &attachments,
                tx,
            )
            .await
            .unwrap();
            assert_eq!(outcome.exit_code, Some(0), "{}", outcome.stderr);
            assert_eq!(outcome.error_summary, None);
            assert_eq!(outcome.observed_session.as_deref(), Some("pi-files"));
            assert_eq!(
                rx.recv().await,
                Some(RunnerEvent::Text("read 3 files".to_owned()))
            );
            assert!(rx.recv().await.is_none());
            assert!(
                attachments
                    .iter()
                    .all(|attachment| attachment.path.exists())
            );
            session = outcome.observed_session;
        }

        let batch_path = batch.path().to_path_buf();
        drop(batch);
        assert!(!batch_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unsupported_binary_rejects_the_whole_batch_before_pi_starts() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let marker = root.path().join("turn-started");
        let script = root.path().join("fake-pi-marker");
        write_script(
            &script,
            &format!("#!/usr/bin/env bash\ntouch '{}'\n", marker.display()),
        );
        let (tx, mut rx) = mpsc::channel(1);
        let failure = PiBackend {
            bin: script.to_str().unwrap().to_owned(),
            session_dir: root.path().join("sessions"),
            execution_profile: ExecutionProfile::Inherit,
        }
        .run_with_attachments(
            invocation(root.path(), Some("pi-session"), Duration::from_secs(5)),
            vec![
                staged(batch.path(), "000-notes.txt", b"notes\n"),
                staged(batch.path(), "001-opaque.bin", b"\x00\x01\x02\xff"),
            ],
            tx,
        )
        .await
        .unwrap_err();

        assert!(matches!(failure.error, HarnessError::AttachmentUnsupported));
        assert!(!marker.exists());
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pi_file_processor_failures_fail_the_whole_turn_without_forwarding_text() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let attachments = vec![
            staged(batch.path(), "000-notes.txt", b"notes\n"),
            staged(batch.path(), "001-pixel.png", PNG_2X2),
        ];
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();

        let omitted = root.path().join("fake-pi-image-omitted");
        write_script(
            &omitted,
            &format!(
                "#!/usr/bin/env bash\ncat >/dev/null\nprintf '%s\\n' '{{\"type\":\"session\",\"version\":3,\"id\":\"pi-omitted\"}}' '{USER_WITHOUT_IMAGES}' '{ASSISTANT_TEXT}'\n"
            ),
        );
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            omitted.to_str().unwrap(),
            &session_dir,
            ExecutionProfile::Inherit,
            invocation(root.path(), None, Duration::from_secs(5)),
            &attachments,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            outcome.error_summary.as_deref(),
            Some(ATTACHMENT_NOT_PROCESSED)
        );
        assert_eq!(outcome.observed_session.as_deref(), Some("pi-omitted"));
        assert!(rx.recv().await.is_none());

        let unreadable = root.path().join("fake-pi-unreadable");
        write_script(
            &unreadable,
            "#!/usr/bin/env bash\nprintf '%s\\n' 'Error: Could not read file' >&2\nexit 1\n",
        );
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            unreadable.to_str().unwrap(),
            &session_dir,
            ExecutionProfile::Inherit,
            invocation(root.path(), None, Duration::from_secs(5)),
            &attachments,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.exit_code, Some(1));
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malformed_pi_json_is_dropped_and_never_verifies_attachments() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let attachments = vec![staged(batch.path(), "000-pixel.png", PNG_2X2)];
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();

        let noisy = root.path().join("fake-pi-noisy");
        write_script(
            &noisy,
            &format!(
                "#!/usr/bin/env bash\ncat >/dev/null\nprintf '%s\\n' 'not json' '{{\"type\":' '{{\"type\":\"message_end\",\"message\":{{\"role\":\"user\",\"content\":[{{\"type\":\"image\"' '{USER_WITH_ONE_IMAGE}' '{ASSISTANT_TEXT}'\n"
            ),
        );
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            noisy.to_str().unwrap(),
            &session_dir,
            ExecutionProfile::Inherit,
            invocation(root.path(), None, Duration::from_secs(5)),
            &attachments,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.error_summary, None);
        assert_eq!(rx.recv().await, Some(RunnerEvent::Text("done".to_owned())));

        let garbage = root.path().join("fake-pi-garbage");
        write_script(
            &garbage,
            "#!/usr/bin/env bash\ncat >/dev/null\nprintf '%s\\n' 'not json' '{\"message\":{\"role\":\"assistant\"}'\n",
        );
        let (tx, mut rx) = mpsc::channel(4);
        let outcome = run_with_bin(
            garbage.to_str().unwrap(),
            &session_dir,
            ExecutionProfile::Inherit,
            invocation(root.path(), None, Duration::from_secs(5)),
            &attachments,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.error_summary, None);
        assert!(rx.recv().await.is_none());
    }

    #[cfg(unix)]
    fn hanging_pi(root: &Path, pid_file: &Path) -> std::path::PathBuf {
        let script = root.join("fake-pi-hang");
        write_script(
            &script,
            &format!(
                "#!/usr/bin/env bash\nset -euo pipefail\nfor arg in \"$@\"; do case \"$arg\" in @*) cat -- \"${{arg#@}}\" >/dev/null ;; esac; done\ncat >/dev/null\nprintf '%s\\n' '{{\"type\":\"session\",\"version\":3,\"id\":\"pi-hang\"}}'\necho $$ > '{}.tmp'\nmv '{}.tmp' '{}'\nsleep 30\n",
                pid_file.display(),
                pid_file.display(),
                pid_file.display()
            ),
        );
        script
    }

    #[cfg(unix)]
    fn process_group_alive(pid: &str) -> bool {
        std::process::Command::new("kill")
            .args(["-0", "--", &format!("-{pid}")])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_pi_after_it_consumed_the_batch_and_leaves_cleanup_to_the_lease() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let attachments = vec![
            staged(batch.path(), "000-notes.txt", b"notes\n"),
            staged(batch.path(), "001-pixel.png", PNG_2X2),
        ];
        let pid_file = root.path().join("pi.pid");
        let script = hanging_pi(root.path(), &pid_file);
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let failure = run_with_bin(
            script.to_str().unwrap(),
            &session_dir,
            ExecutionProfile::Inherit,
            invocation(root.path(), None, Duration::from_secs(2)),
            &attachments,
            tx,
        )
        .await
        .unwrap_err();

        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        assert_eq!(failure.observed_session.as_deref(), Some("pi-hang"));
        let pid = fs::read_to_string(&pid_file).unwrap();
        assert!(!process_group_alive(pid.trim()));
        assert!(
            attachments
                .iter()
                .all(|attachment| attachment.path.exists())
        );
        let batch_path = batch.path().to_path_buf();
        drop(batch);
        assert!(!batch_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_kills_pi_and_leaves_cleanup_to_the_lease() {
        let root = tempfile::tempdir().unwrap();
        let batch = private_batch(root.path());
        let attachments = vec![staged(batch.path(), "000-notes.txt", b"notes\n")];
        let pid_file = root.path().join("pi.pid");
        let script = hanging_pi(root.path(), &pid_file);
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let run = tokio::spawn({
            let script = script.to_str().unwrap().to_owned();
            let cwd = root.path().to_path_buf();
            let attachments = attachments.clone();
            async move {
                run_with_bin(
                    &script,
                    &session_dir,
                    ExecutionProfile::Inherit,
                    invocation(&cwd, None, Duration::from_secs(30)),
                    &attachments,
                    tx,
                )
                .await
            }
        });
        let started = std::time::Instant::now();
        while !pid_file.exists() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "fake Pi never started"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let pid = fs::read_to_string(&pid_file).unwrap();
        assert!(process_group_alive(pid.trim()));

        run.abort();
        assert!(run.await.unwrap_err().is_cancelled());
        let stopped = std::time::Instant::now();
        while process_group_alive(pid.trim()) {
            assert!(
                stopped.elapsed() < Duration::from_secs(5),
                "fake Pi survived cancellation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(attachments[0].path.exists());
        let batch_path = batch.path().to_path_buf();
        drop(batch);
        assert!(!batch_path.exists());
    }

    #[tokio::test]
    #[ignore = "requires authenticated Pi >= 0.79.6 and makes real model requests"]
    async fn real_pi_attachment_contract() {
        let version = std::process::Command::new("pi")
            .arg("--version")
            .output()
            .expect("run pi --version");
        let version = String::from_utf8_lossy(&version.stdout);
        let version = version
            .lines()
            .last()
            .expect("pi --version output")
            .trim()
            .split('.')
            .map(|part| part.parse::<u64>().expect("numeric Pi version"))
            .collect::<Vec<_>>();
        assert!(version >= vec![0, 79, 6], "Pi {version:?} is below 0.79.6");

        let root = tempfile::tempdir().unwrap();
        let session_dir = root.path().join("sessions");
        fs_private::create_dir_all_private(&session_dir).unwrap();
        let batch = private_batch(root.path());
        let token = "PI_STAGED_FILE_TOKEN_4C9E1B";
        let attachments = vec![
            staged(
                batch.path(),
                "000-notes.txt",
                format!("{token}\n").as_bytes(),
            ),
            staged(batch.path(), "001-pixel.png", PNG_2X2),
        ];
        let turn = |session_id: Option<&str>, prompt: &str| Invocation {
            timeout: Duration::from_secs(180),
            idle_timeout: Duration::from_secs(30),
            cwd: root.path().to_path_buf(),
            session_id: session_id.map(str::to_owned),
            prompt: prompt.to_owned(),
            artifact_output: None,
        };

        let (tx, mut rx) = mpsc::channel(8);
        let outcome = run_with_bin(
            "pi",
            &session_dir,
            ExecutionProfile::Inherit,
            turn(
                Some("wn-pi-real-attachments"),
                "Reply with PI_ATTACHMENT_OK: followed by the exact token contained in the attached text file. The token is not present in this prompt.",
            ),
            &attachments,
            tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0), "{}", outcome.stderr);
        assert_eq!(outcome.error_summary, None);
        assert_eq!(
            outcome.observed_session.as_deref(),
            Some("wn-pi-real-attachments")
        );
        let mut reply = String::new();
        while let Some(RunnerEvent::Text(text)) = rx.recv().await {
            reply.push_str(&text);
        }
        assert!(
            reply.contains("PI_ATTACHMENT_OK") && reply.contains(token),
            "{reply}"
        );

        drop(batch);
        let (tx, mut rx) = mpsc::channel(8);
        let outcome = run_with_bin(
            "pi",
            &session_dir,
            ExecutionProfile::Inherit,
            turn(
                Some("wn-pi-real-attachments"),
                "Repeat only the token from the text file attached earlier in this session.",
            ),
            &[],
            tx,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.observed_session.as_deref(),
            Some("wn-pi-real-attachments")
        );
        let mut reply = String::new();
        while let Some(RunnerEvent::Text(text)) = rx.recv().await {
            reply.push_str(&text);
        }
        assert!(reply.contains(token), "{reply}");
    }
}
