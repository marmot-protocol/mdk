mod bridge;
mod chunking;
mod config;
mod control;
mod error;
pub mod process;
mod repo_picker;
mod store;
#[cfg(all(feature = "test-support", unix))]
pub mod test_support;

use std::collections::HashSet;
use std::env;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

/// One inbound Marmot attachment downloaded to a connector-host temp path.
#[derive(Clone, PartialEq, Eq)]
pub struct InvocationAttachment {
    pub path: PathBuf,
    pub media_type: String,
    pub file_name: String,
}

impl fmt::Debug for InvocationAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationAttachment")
            .field("media_type_present", &!self.media_type.is_empty())
            .field("file_name_present", &!self.file_name.is_empty())
            .finish_non_exhaustive()
    }
}

pub use bridge::run;
pub use config::{ConfigSpec, LoadedConfig, load_config_with};
pub use error::{HarnessError, Result};

/// Default maximum byte length for one Marmot reply chunk.
pub const DEFAULT_MAX_REPLY_BYTES: usize = 30_000;
/// Maximum plaintext byte length accepted by the Marmot message layer.
pub const MARMOT_MESSAGE_BYTES_CEILING: usize = 60_000;
/// Shared tracing target for bridge, control, and process lifecycle diagnostics.
pub const TRACE_TARGET: &str = "marmot_terminal_harness";

/// Fully validated configuration consumed by the shared terminal-harness bridge.
#[derive(Clone)]
pub struct Config {
    /// Local `wn-agent` control socket.
    pub socket: PathBuf,
    /// Optional control-socket authentication token.
    pub auth_token: Option<String>,
    /// Account ids permitted to submit prompts.
    pub allowed_senders: HashSet<String>,
    /// Optional explicit local Marmot account id.
    pub account_id_hex: Option<String>,
    /// Timeout for one control request.
    pub request_timeout: Duration,
    /// Maximum bytes in each final reply chunk.
    pub max_reply_bytes: usize,
    /// Maximum queued prompts for one group.
    pub max_pending_per_group: usize,
    /// Private session-mapping file.
    pub state_path: PathBuf,
    /// Total backend invocation timeout.
    pub backend_timeout: Duration,
    /// Maximum backend stdout silence.
    pub backend_idle_timeout: Duration,
    /// Optional QUIC broker candidates used for ephemeral live previews.
    pub quic_candidates: Vec<String>,
    /// Connector identity and naming.
    pub spec: ConfigSpec,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("auth_token_present", &self.auth_token.is_some())
            .field("allowed_senders_count", &self.allowed_senders.len())
            .field("account_id_present", &self.account_id_hex.is_some())
            .field("request_timeout", &self.request_timeout)
            .field("max_reply_bytes", &self.max_reply_bytes)
            .field("max_pending_per_group", &self.max_pending_per_group)
            .field("backend_timeout", &self.backend_timeout)
            .field("backend_idle_timeout", &self.backend_idle_timeout)
            .field("quic_candidate_count", &self.quic_candidates.len())
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// One backend invocation prepared by the shared bridge.
#[derive(Clone)]
pub struct Invocation {
    /// Total invocation timeout.
    pub timeout: Duration,
    /// Maximum stdout silence.
    pub idle_timeout: Duration,
    /// Validated working directory.
    pub cwd: PathBuf,
    /// Durable backend session id, when one is known.
    pub session_id: Option<String>,
    /// Stable privacy-safe backend session name derived from the Marmot group.
    pub session_name: String,
    /// Prompt plaintext passed only to the backend process.
    pub prompt: String,
    /// Decrypted inbound attachments available only on the connector host.
    pub attachments: Vec<InvocationAttachment>,
}

impl fmt::Debug for Invocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Invocation")
            .field("timeout", &self.timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("prompt_len", &self.prompt.len())
            .field("attachment_count", &self.attachments.len())
            .field("session_present", &self.session_id.is_some())
            .field("session_name_present", &!self.session_name.is_empty())
            .finish()
    }
}

/// Privacy-safe backend completion metadata.
#[derive(PartialEq, Eq)]
pub struct Outcome {
    /// Session id observed from the backend event stream.
    pub observed_session: Option<String>,
    /// Process exit code, or `None` when terminated by a signal.
    pub exit_code: Option<i32>,
    /// Sanitized backend error classification.
    pub error_summary: Option<String>,
    /// Bounded and ANSI-stripped stderr.
    pub stderr: String,
    /// Elapsed wall-clock milliseconds.
    pub elapsed_ms: u128,
}

impl fmt::Debug for Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Outcome")
            .field("session_present", &self.observed_session.is_some())
            .field("exit_code", &self.exit_code)
            .field("error_summary_present", &self.error_summary.is_some())
            .field("stderr_len", &self.stderr.len())
            .field("elapsed_ms", &self.elapsed_ms)
            .finish()
    }
}

/// Backend failure plus any session id observed before failure.
pub struct RunFailure {
    /// Shared failure classification.
    pub error: HarnessError,
    /// Session id observed before the failure.
    pub observed_session: Option<String>,
}

impl fmt::Debug for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunFailure")
            .field("error_kind", &self.error.privacy_safe_kind())
            .field("session_present", &self.observed_session.is_some())
            .finish()
    }
}

/// Completed backend output forwarded to the reply collector.
#[derive(PartialEq, Eq)]
pub enum RunnerEvent {
    /// Append-only assistant text delta suitable for an ephemeral live preview.
    Preview(String),
    /// Completed assistant text; never a thinking or tool delta.
    Text(String),
}

impl fmt::Debug for RunnerEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preview(text) => formatter
                .debug_struct("Preview")
                .field("text_len", &text.len())
                .finish(),
            Self::Text(text) => formatter
                .debug_struct("Text")
                .field("text_len", &text.len())
                .finish(),
        }
    }
}

/// Backend-specific command construction and event parsing boundary.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    /// Whether the backend consumes decrypted inbound attachments.
    fn accepts_attachments(&self) -> bool {
        false
    }

    /// Runs one prompt and streams completed assistant text to `tx`.
    async fn run(
        &self,
        invocation: Invocation,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure>;
}

/// Returns the current user's home directory or fails closed when it is unset.
pub(crate) fn dirs_home() -> Result<PathBuf> {
    env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| HarnessError::Config("$HOME is not set".to_owned()))
}

#[cfg(test)]
mod privacy_tests {
    use super::*;

    #[test]
    fn invocation_and_outcome_debug_redact_backend_content() {
        let invocation = Invocation {
            timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(10),
            cwd: PathBuf::from("/secret/worktree"),
            session_id: Some("secret-session".to_owned()),
            session_name: "secret-name".to_owned(),
            prompt: "secret prompt".to_owned(),
            attachments: vec![InvocationAttachment {
                path: PathBuf::from("/secret/image.png"),
                media_type: "image/png".to_owned(),
                file_name: "image.png".to_owned(),
            }],
        };
        let invocation_debug = format!("{invocation:?}");
        for secret in ["/secret", "secret-session", "secret-name", "secret prompt"] {
            assert!(!invocation_debug.contains(secret));
        }
        assert!(invocation_debug.contains("prompt_len: 13"));
        assert!(invocation_debug.contains("session_present: true"));

        let attachment_debug = format!("{:?}", invocation.attachments[0]);
        for secret in ["/secret", "image.png"] {
            assert!(!attachment_debug.contains(secret));
        }
        assert!(attachment_debug.contains("media_type_present: true"));

        let outcome = Outcome {
            observed_session: Some("secret-session".to_owned()),
            exit_code: Some(64),
            error_summary: Some("secret-summary".to_owned()),
            stderr: "secret stderr".to_owned(),
            elapsed_ms: 10,
        };
        let outcome_debug = format!("{outcome:?}");
        for secret in ["secret-session", "secret-summary", "secret stderr"] {
            assert!(!outcome_debug.contains(secret));
        }
        assert!(outcome_debug.contains("stderr_len: 13"));
    }

    #[test]
    fn runner_event_debug_reports_only_text_length() {
        let event = RunnerEvent::Text("secret reply".to_owned());
        let debug = format!("{event:?}");
        assert!(!debug.contains("secret reply"));
        assert!(debug.contains("text_len: 12"));
    }
}
