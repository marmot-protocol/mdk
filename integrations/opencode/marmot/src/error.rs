use std::io;

use agent_control::AgentControlError;
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, HarnessError>;

#[derive(Debug, Error)]
pub(crate) enum HarnessError {
    #[error("{0}")]
    Config(String),
    #[error("i/o error kind={kind:?}")]
    Io { kind: io::ErrorKind },
    #[error("json error")]
    Json,
    #[error("agent-control error")]
    AgentControl,
    #[error("control connection closed")]
    ControlClosed,
    #[error("control request timed out")]
    ControlTimedOut { method: &'static str },
    #[error("control response id mismatch")]
    ResponseIdMismatch { method: &'static str },
    #[error("unexpected control response for {method}: {response}")]
    UnexpectedResponse {
        method: &'static str,
        response: &'static str,
    },
    #[error("control request rejected for {method}: {code}")]
    ControlRejected { method: &'static str, code: String },
    #[error("opencode invocation timed out")]
    OpencodeTimedOut,
    #[error("opencode stream error")]
    OpencodeStream,
    #[error("opencode process failed to start")]
    OpencodeSpawn,
    #[error("task join error")]
    Join,
}

impl HarnessError {
    pub(crate) fn privacy_safe_kind(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Io { .. } => "io",
            Self::Json => "json",
            Self::AgentControl => "agent_control",
            Self::ControlClosed => "control_closed",
            Self::ControlTimedOut { .. } => "control_timeout",
            Self::ResponseIdMismatch { .. } => "response_id_mismatch",
            Self::UnexpectedResponse { .. } => "unexpected_response",
            Self::ControlRejected { .. } => "control_rejected",
            Self::OpencodeTimedOut => "opencode_timeout",
            Self::OpencodeStream => "opencode_stream",
            Self::OpencodeSpawn => "opencode_spawn",
            Self::Join => "join",
        }
    }

    pub(crate) fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Io { .. }
                | Self::AgentControl
                | Self::ControlClosed
                | Self::ControlTimedOut { .. }
        )
    }
}

impl From<io::Error> for HarnessError {
    fn from(value: io::Error) -> Self {
        Self::Io { kind: value.kind() }
    }
}

impl From<serde_json::Error> for HarnessError {
    fn from(_value: serde_json::Error) -> Self {
        Self::Json
    }
}

impl From<AgentControlError> for HarnessError {
    fn from(_value: AgentControlError) -> Self {
        Self::AgentControl
    }
}

impl From<tokio::task::JoinError> for HarnessError {
    fn from(_value: tokio::task::JoinError) -> Self {
        Self::Join
    }
}
