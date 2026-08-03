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
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

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
#[derive(Clone, Debug)]
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
    /// Connector identity and naming.
    pub spec: ConfigSpec,
}

/// One backend invocation prepared by the shared bridge.
#[derive(Clone, Debug)]
pub struct Invocation {
    /// Total invocation timeout.
    pub timeout: Duration,
    /// Maximum stdout silence.
    pub idle_timeout: Duration,
    /// Validated working directory.
    pub cwd: PathBuf,
    /// Durable backend session id, when one is known.
    pub session_id: Option<String>,
    /// Prompt plaintext passed only to the backend process.
    pub prompt: String,
}

/// Privacy-safe backend completion metadata.
#[derive(Debug, PartialEq, Eq)]
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

/// Backend failure plus any session id observed before failure.
#[derive(Debug)]
pub struct RunFailure {
    /// Shared failure classification.
    pub error: HarnessError,
    /// Session id observed before the failure.
    pub observed_session: Option<String>,
}

/// Completed backend output forwarded to the reply collector.
#[derive(Debug, PartialEq, Eq)]
pub enum RunnerEvent {
    /// Completed assistant text; never a thinking or tool delta.
    Text(String),
}

/// Backend-specific command construction and event parsing boundary.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
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
