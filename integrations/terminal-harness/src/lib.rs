mod bridge;
mod chunking;
mod control;
mod error;
mod repo_picker;
mod store;

use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

pub use bridge::run;
pub use chunking::split_reply_chunks;
pub use error::{HarnessError, Result};

pub const DEFAULT_MAX_REPLY_BYTES: usize = 30_000;
pub const MARMOT_MESSAGE_BYTES_CEILING: usize = 60_000;
pub const TRACE_TARGET: &str = "marmot_terminal_harness";

#[derive(Clone, Debug)]
pub struct Config {
    pub socket: PathBuf,
    pub auth_token: Option<String>,
    pub allowed_senders: HashSet<String>,
    pub account_id_hex: Option<String>,
    pub request_timeout: Duration,
    pub max_reply_bytes: usize,
    pub max_pending_per_group: usize,
    pub state_path: PathBuf,
    pub backend_timeout: Duration,
    pub backend_idle_timeout: Duration,
    pub display_name: &'static str,
    pub reply_prefix: &'static str,
    pub bin_env_name: &'static str,
}

#[derive(Clone, Debug)]
pub struct Invocation {
    pub timeout: Duration,
    pub idle_timeout: Duration,
    pub cwd: PathBuf,
    pub session_id: Option<String>,
    pub prompt: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub observed_session: Option<String>,
    pub exit_code: Option<i32>,
    pub error_summary: Option<String>,
    pub stderr: String,
    pub elapsed_ms: u128,
}

#[derive(Debug)]
pub struct RunFailure {
    pub error: HarnessError,
    pub observed_session: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RunnerEvent {
    Text(String),
}

#[async_trait]
pub trait Backend: Send + Sync + 'static {
    async fn run(
        &self,
        invocation: Invocation,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure>;
}

pub fn dirs_home() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}
