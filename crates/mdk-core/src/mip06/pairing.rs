//! MIP-06 pairing payload types.
//!
//! The pairing flow is a two-phase exchange between an existing device and a new device:
//!
//! Phase 1 (new → existing): New device sends its KeyPackage
//! Phase 2 (existing → new): Existing device adds the new device to groups and
//!   sends back Welcome messages

use tls_codec::{DeserializeBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::error::Error;

/// Data sent from the new device to the existing device (Phase 1).
///
/// Contains a single KeyPackage that the existing device will use to add
/// the new device to groups via standard MLS Add proposals.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct DevicePairingRequest {
    /// Version of the pairing request format.
    version: u16,
    /// TLS-serialized MLS KeyPackage for the new device.
    key_package: Vec<u8>,
}

impl DevicePairingRequest {
    /// Current version.
    pub const CURRENT_VERSION: u16 = 1;

    /// Create a new pairing request.
    pub fn new(key_package: Vec<u8>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            key_package,
        }
    }

    /// The KeyPackage bytes.
    pub fn key_package_bytes(&self) -> &[u8] {
        &self.key_package
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        use tls_codec::Serialize;
        let mut buf = Vec::new();
        self.tls_serialize(&mut buf)
            .map_err(|e| Error::PairingError(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize from bytes with version validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (req, _) = Self::tls_deserialize_bytes(bytes)
            .map_err(|e| Error::PairingError(format!("failed to deserialize pairing request: {e}")))?;
        match req.version {
            0 => Err(Error::PairingError("version 0 is reserved".to_string())),
            1 => Ok(req),
            v => Err(Error::PairingError(format!("unsupported version: {v}"))),
        }
    }
}

/// Per-group Welcome data sent from existing device to new device (Phase 2).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct GroupWelcomeData {
    /// The Welcome rumor (unsigned event JSON bytes) for this group.
    welcome_rumor: Vec<u8>,
    /// The commit event (signed event JSON bytes) the existing device published.
    /// The new device does NOT need to process this — it joins via Welcome.
    /// Included so the new device can track the event ID if needed.
    commit_event: Vec<u8>,
}

impl GroupWelcomeData {
    /// Create a new per-group welcome entry.
    pub fn new(welcome_rumor: Vec<u8>, commit_event: Vec<u8>) -> Self {
        Self {
            welcome_rumor,
            commit_event,
        }
    }

    /// The Welcome rumor bytes (JSON-serialized UnsignedEvent).
    pub fn welcome_rumor_bytes(&self) -> &[u8] {
        &self.welcome_rumor
    }

    /// The commit event bytes (JSON-serialized Event).
    pub fn commit_event_bytes(&self) -> &[u8] {
        &self.commit_event
    }
}

/// Response sent from existing device to new device (Phase 2).
///
/// Contains Welcome messages for each group the new device was added to.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct DevicePairingResponse {
    /// Version of the pairing response format.
    version: u16,
    /// One entry per group the new device was added to.
    groups: Vec<GroupWelcomeData>,
}

impl DevicePairingResponse {
    /// Current version.
    pub const CURRENT_VERSION: u16 = 1;

    /// Create a new pairing response.
    pub fn new(groups: Vec<GroupWelcomeData>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            groups,
        }
    }

    /// The per-group Welcome data.
    pub fn groups(&self) -> &[GroupWelcomeData] {
        &self.groups
    }

    /// Consume and return the group entries.
    pub fn into_groups(self) -> Vec<GroupWelcomeData> {
        self.groups
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        use tls_codec::Serialize;
        let mut buf = Vec::new();
        self.tls_serialize(&mut buf)
            .map_err(|e| Error::PairingError(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize from bytes with version validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (resp, _) = Self::tls_deserialize_bytes(bytes)
            .map_err(|e| Error::PairingError(format!("failed to deserialize pairing response: {e}")))?;
        match resp.version {
            0 => Err(Error::PairingError("version 0 is reserved".to_string())),
            1 => Ok(resp),
            v => Err(Error::PairingError(format!("unsupported version: {v}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_request_roundtrip() {
        let req = DevicePairingRequest::new(vec![1, 2, 3, 4, 5]);
        let bytes = req.to_bytes().unwrap();
        let decoded = DevicePairingRequest::from_bytes(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_pairing_response_roundtrip() {
        let groups = vec![
            GroupWelcomeData::new(vec![10; 50], vec![20; 100]),
            GroupWelcomeData::new(vec![30; 80], vec![40; 200]),
        ];
        let resp = DevicePairingResponse::new(groups);
        let bytes = resp.to_bytes().unwrap();
        let decoded = DevicePairingResponse::from_bytes(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_request_version_0_rejected() {
        let req = DevicePairingRequest { version: 0, key_package: vec![] };
        let bytes = req.to_bytes().unwrap();
        assert!(DevicePairingRequest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_response_version_99_rejected() {
        let resp = DevicePairingResponse { version: 99, groups: vec![] };
        let bytes = resp.to_bytes().unwrap();
        assert!(DevicePairingResponse::from_bytes(&bytes).is_err());
    }
}
