//! Pairing-session identifiers, descriptors, state, and typed errors.
//!
//! The QR token is a short-lived bearer capability. Its `Debug` output is
//! deliberately redacted even though callers can access the raw bytes for QR
//! encoding.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Fixed engine-owned lifetime for one rendered pairing QR.
pub const DEFAULT_PAIRING_SESSION_TTL_MS: u64 = 30_000;

/// Random 256-bit identifier carried by a pairing QR.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PairingSessionId([u8; 32]);

impl PairingSessionId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for PairingSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSessionId(<redacted>)")
    }
}

/// Public QR material for one short-lived pairing session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSessionDescriptor {
    pub session_id: PairingSessionId,
    pub ephemeral_public_key: [u8; 32],
    pub expires_at_ms: u64,
}

impl fmt::Debug for PairingSessionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingSessionDescriptor")
            .field("session_id", &"<redacted>")
            .field("ephemeral_public_key", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Pairing-session lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingSessionState {
    Active,
    Scanned,
    Approved,
    Expired,
    Superseded,
    Rejected,
}

impl PairingSessionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Scanned => "scanned",
            Self::Approved => "approved",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Approved | Self::Expired | Self::Superseded | Self::Rejected
        )
    }
}

/// Typed pairing-session rejection. No variant displays the bearer token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingSessionError {
    #[error("pairing session expired")]
    Expired,
    #[error("pairing session was superseded")]
    Superseded,
    #[error("pairing session was already accepted")]
    AlreadyAccepted,
    #[error("pairing session was already scanned")]
    AlreadyScanned,
    #[error("pairing session was rejected")]
    Rejected,
    #[error("pairing session has not been scanned")]
    NotScanned,
}
