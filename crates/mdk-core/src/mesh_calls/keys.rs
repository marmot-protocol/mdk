//! MLS key derivation for mesh calls
//!
//! This module handles derivation of call keys from the MLS group state using
//! the MLS-Exporter function (RFC 9420 Section 8.5).

use super::types::{CallId, MeshCallError};

/// MLS exporter label for call base key
pub const CALL_BASE_KEY_LABEL: &str = "marmot-call-v1";

/// MLS exporter label for SFU authentication
pub const SFU_AUTH_LABEL: &str = "marmot-sfu-auth-v1";

/// Length of call base key in bytes
pub const CALL_BASE_KEY_LENGTH: usize = 32;

/// Length of SFU auth token in bytes
pub const SFU_AUTH_TOKEN_LENGTH: usize = 32;

/// SFU authentication token
#[derive(Debug, Clone)]
pub struct SfuAuthToken([u8; SFU_AUTH_TOKEN_LENGTH]);

impl SfuAuthToken {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; SFU_AUTH_TOKEN_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Get the bytes
    pub fn as_bytes(&self) -> &[u8; SFU_AUTH_TOKEN_LENGTH] {
        &self.0
    }

    /// Get as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Trait for types that can provide call key derivation
///
/// This is implemented by MDK to allow the call manager to derive keys
/// without directly accessing MLS internals.
pub trait CallKeyDerivation: Send + Sync {
    /// Derive call base key for a group
    fn derive_call_base_key(&self, call_id: &CallId) -> Result<[u8; 32], MeshCallError>;
    
    /// Derive SFU auth token for a group
    fn derive_sfu_auth_token(
        &self,
        call_id: &CallId,
        sfu_pubkey: &[u8; 32],
    ) -> Result<SfuAuthToken, MeshCallError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sfu_auth_token_roundtrip() {
        let bytes = [0x12u8; 32];
        let token = SfuAuthToken::from_bytes(bytes);
        assert_eq!(token.as_bytes(), &bytes);
        assert_eq!(token.to_hex(), "1212121212121212121212121212121212121212121212121212121212121212");
    }
}
