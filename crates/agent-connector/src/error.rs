//! Connector error type and its privacy-safe code/message projections.

use agent_control::AgentControlError;
use marmot_account::AccountHomeError;
use marmot_app::AppError;

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
    #[error(transparent)]
    App(#[from] AppError),
    #[error(transparent)]
    Control(#[from] AgentControlError),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("debug controls are disabled")]
    DebugControlsDisabled,
    #[error("agent control request is unauthorized")]
    Unauthorized,
    #[error("unsafe agent control plane configuration: {0}")]
    UnsafeControlPlaneConfig(&'static str),
    #[error("agent stream error: {0}")]
    Stream(String),
    #[error("invalid profile name: {0}")]
    InvalidProfileName(&'static str),
}

impl ConnectorError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AccountHome(_) => "account_home_error",
            Self::App(_) => "app_error",
            Self::Control(_) => "control_error",
            Self::Hex(_) => "invalid_hex",
            Self::Json(_) => "json_error",
            Self::Io(_) => "io_error",
            Self::DebugControlsDisabled => "debug_controls_disabled",
            Self::Unauthorized => "unauthorized",
            Self::UnsafeControlPlaneConfig(_) => "unsafe_control_plane_config",
            Self::Stream(_) => "stream_error",
            Self::InvalidProfileName(_) => "invalid_profile_name",
        }
    }

    pub fn client_message(&self) -> &'static str {
        match self {
            Self::DebugControlsDisabled => "debug controls are disabled",
            Self::Unauthorized => "agent control request is unauthorized",
            Self::UnsafeControlPlaneConfig(_) => "unsafe agent control plane configuration",
            Self::Hex(_) => "invalid hex value",
            Self::Json(_) | Self::Control(_) => "invalid control request",
            Self::Stream(_) => "agent stream request failed",
            Self::InvalidProfileName(_) => "invalid profile name",
            Self::Io(_) => "connector I/O failed",
            Self::AccountHome(_) | Self::App(_) => "connector request failed",
        }
    }

    pub fn privacy_safe_code(&self) -> &'static str {
        self.code()
    }
}
