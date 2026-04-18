//! MIP-06 pairing payload types.
//!
//! Two payload formats exist:
//!
//! ## Spec-compliant (External Commit flow)
//! `PairingPayload` / `GroupPairingDataV1`: the new device receives GroupInfo,
//! group_event_key, and join_psk (exporter-derived External PSK), then self-joins
//! via External Commit.
//!
//! ## Add-based workaround
//! `DevicePairingRequest` / `DevicePairingResponse`: used while OpenMLS blockers
//! prevent the External Commit path. The existing device adds the new device via
//! standard Add proposals and sends back Welcome messages.

use std::fmt;

use mdk_storage_traits::Secret;
use tls_codec::{DeserializeBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::error::Error;

/// Validate the pairing protocol version field.
fn validate_pairing_version(version: u16) -> Result<(), Error> {
    match version {
        0 => Err(Error::PairingError("version 0 is reserved".to_string())),
        1 => Ok(()),
        v => Err(Error::PairingError(format!("unsupported version: {v}"))),
    }
}

/// Generate `to_bytes()` and `from_bytes()` for a TLS-serializable versioned pairing type.
///
/// Each type MUST implement `fn validate(&self) -> Result<(), Error>` for semantic
/// validation (e.g., non-empty groups, correct PSK length). `from_bytes` calls
/// `validate()` after version checking so deserialized data is always well-formed.
macro_rules! impl_versioned_pairing_bytes {
    ($ty:ty, $label:literal) => {
        impl $ty {
            /// Serialize to bytes.
            pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
                use tls_codec::Serialize;
                let mut buf = Vec::new();
                self.tls_serialize(&mut buf)
                    .map_err(|e| Error::PairingError(e.to_string()))?;
                Ok(buf)
            }

            /// Deserialize from bytes with version and semantic validation.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                let (val, remainder) = Self::tls_deserialize_bytes(bytes).map_err(|e| {
                    Error::PairingError(format!(
                        concat!("failed to deserialize ", $label, ": {e}"),
                        e = e
                    ))
                })?;
                if !remainder.is_empty() {
                    return Err(Error::PairingError(format!("trailing bytes in {}", $label)));
                }
                validate_pairing_version(val.version)?;
                val.validate()?;
                Ok(val)
            }
        }
    };
}

// ── Spec-compliant External Commit types ────────────────────────────────

/// Per-group data for External Commit–based joining (MIP-06 spec §Pairing Payload).
///
/// Contains everything a new device needs to construct an External Commit for one group.
///
/// ```tls
/// struct {
///     opaque group_event_key[32];
///     opaque join_psk<0..2^32-1>;
///     opaque group_info<1..2^32-1>;
/// } GroupPairingDataV1;
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct GroupPairingDataV1 {
    /// Exact 32-byte outer encryption key for `kind: 445` group-event encryption (MIP-03).
    /// Wrapped in `Secret` for zeroize-on-drop and redacted Debug.
    group_event_key: Secret<[u8; 32]>,
    /// Exporter-derived External PSK for MIP-06 join authorization.
    /// Length MUST equal `KDF.Nh` for the group ciphersuite.
    /// Derived via `MLS-Exporter("marmot-mip06-join-psk-v1", join_psk_id, KDF.Nh)`.
    /// Wrapped in `Secret` for zeroize-on-drop and redacted Debug.
    join_psk: Secret<Vec<u8>>,
    /// TLS-serialized `GroupInfo` for current epoch. MUST include `external_pub` and
    /// `ratchet_tree` extensions.
    group_info: Vec<u8>,
}

impl fmt::Debug for GroupPairingDataV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupPairingDataV1")
            .field("group_event_key", &"[REDACTED]")
            .field("join_psk", &"[REDACTED]")
            .field(
                "group_info",
                &format_args!("[{} bytes]", self.group_info.len()),
            )
            .finish()
    }
}

// ── Manual TLS codec impls (Secret<T> is not TLS-derivable) ──────────

impl tls_codec::Size for GroupPairingDataV1 {
    fn tls_serialized_len(&self) -> usize {
        self.group_event_key.as_ref().tls_serialized_len()
            + self.join_psk.as_ref().tls_serialized_len()
            + self.group_info.tls_serialized_len()
    }
}

impl tls_codec::Serialize for GroupPairingDataV1 {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.group_event_key.as_ref().tls_serialize(writer)?;
        written += self.join_psk.as_ref().tls_serialize(writer)?;
        written += self.group_info.tls_serialize(writer)?;
        Ok(written)
    }
}

impl tls_codec::DeserializeBytes for GroupPairingDataV1 {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (group_event_key, bytes) = <[u8; 32]>::tls_deserialize_bytes(bytes)?;
        let (join_psk, bytes) = <Vec<u8>>::tls_deserialize_bytes(bytes)?;
        let (group_info, bytes) = <Vec<u8>>::tls_deserialize_bytes(bytes)?;
        Ok((
            Self {
                group_event_key: Secret::new(group_event_key),
                join_psk: Secret::new(join_psk),
                group_info,
            },
            bytes,
        ))
    }
}

impl tls_codec::Deserialize for GroupPairingDataV1 {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let group_event_key = <[u8; 32]>::tls_deserialize(bytes)?;
        let join_psk = <Vec<u8>>::tls_deserialize(bytes)?;
        let group_info = <Vec<u8>>::tls_deserialize(bytes)?;
        Ok(Self {
            group_event_key: Secret::new(group_event_key),
            join_psk: Secret::new(join_psk),
            group_info,
        })
    }
}

// ── Public API ───────────────────────────────────────────────────────

impl GroupPairingDataV1 {
    /// Create a new per-group pairing entry.
    pub fn new(
        group_event_key: [u8; 32],
        join_psk: Vec<u8>,
        group_info: Vec<u8>,
    ) -> Result<Self, Error> {
        let val = Self {
            group_event_key: Secret::new(group_event_key),
            join_psk: Secret::new(join_psk),
            group_info,
        };
        val.validate()?;
        Ok(val)
    }

    /// Semantic validation: join_psk must be 32 bytes and group_info non-empty.
    fn validate(&self) -> Result<(), Error> {
        if self.join_psk.len() != 32 {
            return Err(Error::PairingError("join_psk must be 32 bytes".to_string()));
        }
        if self.group_info.is_empty() {
            return Err(Error::PairingError(
                "group_info must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// The 32-byte outer encryption key.
    pub fn group_event_key(&self) -> &[u8; 32] {
        self.group_event_key.as_ref()
    }

    /// The exporter-derived External PSK bytes.
    pub fn join_psk(&self) -> &[u8] {
        self.join_psk.as_ref()
    }

    /// The TLS-serialized `GroupInfo` bytes.
    pub fn group_info(&self) -> &[u8] {
        &self.group_info
    }
}

/// TLS-serialized pairing payload (MIP-06 spec §Pairing Payload Specification).
///
/// ```tls
/// struct {
///     uint16 version;
///     GroupPairingDataV1 groups<1..2^32-1>;
/// } PairingPayload;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct PairingPayload {
    /// Payload format version. Current: 1. Version 0 is reserved.
    version: u16,
    /// One entry per target group.
    groups: Vec<GroupPairingDataV1>,
}

impl PairingPayload {
    /// Current version.
    pub const CURRENT_VERSION: u16 = 1;

    /// Create a new pairing payload.
    pub fn new(groups: Vec<GroupPairingDataV1>) -> Result<Self, Error> {
        let val = Self {
            version: Self::CURRENT_VERSION,
            groups,
        };
        val.validate()?;
        Ok(val)
    }

    /// Semantic validation: must contain at least one group, each group valid.
    fn validate(&self) -> Result<(), Error> {
        if self.groups.is_empty() {
            return Err(Error::PairingError(
                "pairing payload must contain at least one group".to_string(),
            ));
        }
        for group in &self.groups {
            group.validate()?;
        }
        Ok(())
    }

    /// The per-group pairing data entries.
    pub fn groups(&self) -> &[GroupPairingDataV1] {
        &self.groups
    }

    /// Consume and return the group entries.
    pub fn into_groups(self) -> Vec<GroupPairingDataV1> {
        self.groups
    }
}

impl_versioned_pairing_bytes!(PairingPayload, "pairing payload");

// ── Add-based workaround types (pending OpenMLS External Commit support) ─

/// Data sent from the new device to the existing device (Phase 1, Add-based workaround).
///
/// Contains a JSON-serialized Nostr Event wrapping an MLS KeyPackage that the existing
/// device will use to add the new device to groups via standard MLS Add proposals.
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct DevicePairingRequest {
    /// Version of the pairing request format.
    version: u16,
    /// JSON-serialized Nostr Event containing the new device's MLS KeyPackage.
    /// Callers produce this via `event.as_json().into_bytes()` and consume it
    /// via `nostr::Event::from_json(std::str::from_utf8(bytes))`.
    key_package_event_json: Vec<u8>,
}

impl DevicePairingRequest {
    /// Current version.
    pub const CURRENT_VERSION: u16 = 1;

    /// Create a new pairing request from the JSON-serialized KeyPackage Nostr Event.
    pub fn new(key_package_event_json: Vec<u8>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            key_package_event_json,
        }
    }

    /// Semantic validation (version already checked by from_bytes).
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }

    /// The JSON-serialized Nostr Event bytes containing the KeyPackage.
    pub fn key_package_event_json(&self) -> &[u8] {
        &self.key_package_event_json
    }
}

impl_versioned_pairing_bytes!(DevicePairingRequest, "pairing request");

/// Per-group Welcome data sent from existing device to new device (Add-based workaround).
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
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

/// Response sent from existing device to new device (Add-based workaround).
///
/// Contains Welcome messages for each group the new device was added to.
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
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

    /// Semantic validation (version already checked by from_bytes).
    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }

    /// The per-group Welcome data.
    pub fn groups(&self) -> &[GroupWelcomeData] {
        &self.groups
    }

    /// Consume and return the group entries.
    pub fn into_groups(self) -> Vec<GroupWelcomeData> {
        self.groups
    }
}

impl_versioned_pairing_bytes!(DevicePairingResponse, "pairing response");

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
        let req = DevicePairingRequest {
            version: 0,
            key_package_event_json: vec![],
        };
        let bytes = req.to_bytes().unwrap();
        assert!(DevicePairingRequest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_response_version_99_rejected() {
        let resp = DevicePairingResponse {
            version: 99,
            groups: vec![],
        };
        let bytes = resp.to_bytes().unwrap();
        assert!(DevicePairingResponse::from_bytes(&bytes).is_err());
    }

    // ── Spec-compliant payload tests ────────────────────────────────

    #[test]
    fn test_group_pairing_data_v1_roundtrip() {
        use tls_codec::{DeserializeBytes, Serialize};

        let data = GroupPairingDataV1::new(
            [0xAA; 32],
            vec![0xBB; 32],  // join_psk (KDF.Nh = 32 for ciphersuite 0x0001)
            vec![0xCC; 200], // group_info
        )
        .unwrap();

        let mut bytes = Vec::new();
        data.tls_serialize(&mut bytes).unwrap();
        let (decoded, _) = GroupPairingDataV1::tls_deserialize_bytes(&bytes).unwrap();
        assert_eq!(data, decoded);
        assert_eq!(data.group_event_key(), &[0xAA; 32]);
        assert_eq!(data.join_psk().len(), 32);
        assert_eq!(data.group_info().len(), 200);
    }

    #[test]
    fn test_group_pairing_data_v1_rejects_empty_psk() {
        let result = GroupPairingDataV1::new([0; 32], vec![], vec![1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_group_pairing_data_v1_rejects_non_32_byte_psk() {
        let result = GroupPairingDataV1::new([0; 32], vec![1; 31], vec![1, 2, 3]);
        assert!(matches!(
            result,
            Err(Error::PairingError(ref msg)) if msg.contains("join_psk must be 32 bytes")
        ));
    }

    #[test]
    fn test_group_pairing_data_v1_rejects_empty_group_info() {
        let result = GroupPairingDataV1::new([0; 32], vec![1], vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pairing_payload_roundtrip() {
        let groups = vec![
            GroupPairingDataV1::new([1; 32], vec![2; 32], vec![3; 100]).unwrap(),
            GroupPairingDataV1::new([4; 32], vec![5; 32], vec![6; 150]).unwrap(),
        ];
        let payload = PairingPayload::new(groups).unwrap();
        let bytes = payload.to_bytes().unwrap();
        let decoded = PairingPayload::from_bytes(&bytes).unwrap();
        assert_eq!(payload, decoded);
        assert_eq!(decoded.groups().len(), 2);
    }

    #[test]
    fn test_pairing_payload_rejects_empty_groups() {
        let result = PairingPayload::new(vec![]);
        assert!(matches!(
            result,
            Err(Error::PairingError(ref msg)) if msg.contains("at least one group")
        ));
    }

    #[test]
    fn test_pairing_payload_rejects_trailing_bytes() {
        let payload = PairingPayload::new(vec![
            GroupPairingDataV1::new([1; 32], vec![2; 32], vec![3; 100]).unwrap(),
        ])
        .unwrap();
        let mut bytes = payload.to_bytes().unwrap();
        bytes.extend_from_slice(&[0xDE, 0xAD]);

        let result = PairingPayload::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(Error::PairingError(ref msg)) if msg.contains("trailing bytes")
        ));
    }

    #[test]
    fn test_pairing_payload_version_0_rejected() {
        let payload = PairingPayload {
            version: 0,
            groups: vec![],
        };
        let bytes = payload.to_bytes().unwrap();
        assert!(PairingPayload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_pairing_payload_version_99_rejected() {
        let payload = PairingPayload {
            version: 99,
            groups: vec![],
        };
        let bytes = payload.to_bytes().unwrap();
        assert!(PairingPayload::from_bytes(&bytes).is_err());
    }

    // ── Additional edge case tests ─────────────────────────────────────

    #[test]
    fn test_request_trailing_bytes_rejected() {
        let req = DevicePairingRequest::new(vec![1, 2, 3]);
        let mut bytes = req.to_bytes().unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            DevicePairingRequest::from_bytes(&bytes),
            Err(Error::PairingError(ref msg)) if msg.contains("trailing bytes")
        ));
    }

    #[test]
    fn test_response_trailing_bytes_rejected() {
        let resp = DevicePairingResponse::new(vec![GroupWelcomeData::new(vec![1], vec![2])]);
        let mut bytes = resp.to_bytes().unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            DevicePairingResponse::from_bytes(&bytes),
            Err(Error::PairingError(ref msg)) if msg.contains("trailing bytes")
        ));
    }

    #[test]
    fn test_request_empty_key_package_json_roundtrip() {
        let req = DevicePairingRequest::new(vec![]);
        let bytes = req.to_bytes().unwrap();
        let decoded = DevicePairingRequest::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key_package_event_json(), &[] as &[u8]);
    }

    #[test]
    fn test_group_welcome_data_roundtrip_and_getters() {
        use tls_codec::{DeserializeBytes, Serialize};

        let welcome = vec![10u8; 50];
        let commit = vec![20u8; 100];
        let data = GroupWelcomeData::new(welcome.clone(), commit.clone());

        assert_eq!(data.welcome_rumor_bytes(), &welcome[..]);
        assert_eq!(data.commit_event_bytes(), &commit[..]);

        // TLS roundtrip
        let mut bytes = Vec::new();
        data.tls_serialize(&mut bytes).unwrap();
        let (decoded, _) = GroupWelcomeData::tls_deserialize_bytes(&bytes).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_response_into_groups_consumes() {
        let groups = vec![
            GroupWelcomeData::new(vec![1], vec![2]),
            GroupWelcomeData::new(vec![3], vec![4]),
        ];
        let resp = DevicePairingResponse::new(groups.clone());
        let consumed = resp.into_groups();
        assert_eq!(consumed.len(), 2);
        assert_eq!(consumed[0].welcome_rumor_bytes(), &[1]);
        assert_eq!(consumed[1].commit_event_bytes(), &[4]);
    }

    #[test]
    fn test_payload_into_groups_consumes() {
        let groups = vec![GroupPairingDataV1::new([1; 32], vec![2; 32], vec![3; 100]).unwrap()];
        let payload = PairingPayload::new(groups).unwrap();
        let consumed = payload.into_groups();
        assert_eq!(consumed.len(), 1);
        assert_eq!(consumed[0].group_event_key(), &[1; 32]);
    }

    #[test]
    fn test_payload_with_invalid_inner_group_rejected() {
        // Build a payload where one of the inner groups has invalid join_psk length.
        // We construct manually to bypass GroupPairingDataV1::new() validation.
        let valid_group = GroupPairingDataV1::new([1; 32], vec![2; 32], vec![3; 50]).unwrap();
        let mut payload = PairingPayload {
            version: 1,
            groups: vec![valid_group],
        };
        // Corrupt the first group's join_psk to be wrong length
        payload.groups[0].join_psk = mdk_storage_traits::Secret::new(vec![0xFF; 16]);

        // Serializing is fine (no validation on serialize)
        let bytes = payload.to_bytes().unwrap();
        // But deserializing should fail because validate() runs on from_bytes
        assert!(PairingPayload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_request_version_2_rejected() {
        let req = DevicePairingRequest {
            version: 2,
            key_package_event_json: vec![1, 2],
        };
        let bytes = req.to_bytes().unwrap();
        assert!(matches!(
            DevicePairingRequest::from_bytes(&bytes),
            Err(Error::PairingError(ref msg)) if msg.contains("unsupported version: 2")
        ));
    }

    #[test]
    fn test_response_version_0_rejected() {
        let resp = DevicePairingResponse {
            version: 0,
            groups: vec![],
        };
        let bytes = resp.to_bytes().unwrap();
        assert!(matches!(
            DevicePairingResponse::from_bytes(&bytes),
            Err(Error::PairingError(ref msg)) if msg.contains("version 0 is reserved")
        ));
    }

    #[test]
    fn test_group_pairing_data_v1_rejects_oversized_psk() {
        let result = GroupPairingDataV1::new([0; 32], vec![1; 33], vec![1, 2, 3]);
        assert!(matches!(
            result,
            Err(Error::PairingError(ref msg)) if msg.contains("join_psk must be 32 bytes")
        ));
    }

    #[test]
    fn test_group_pairing_data_v1_getters() {
        let data = GroupPairingDataV1::new([0xAA; 32], vec![0xBB; 32], vec![0xCC; 10]).unwrap();
        assert_eq!(data.group_event_key(), &[0xAA; 32]);
        assert_eq!(data.join_psk(), &[0xBB; 32]);
        assert_eq!(data.group_info(), &[0xCC; 10]);
    }

    #[test]
    fn test_group_pairing_data_v1_debug_redacts_secrets() {
        let data = GroupPairingDataV1::new([0xAA; 32], vec![0xBB; 32], vec![0xCC; 10]).unwrap();
        let debug_str = format!("{:?}", data);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("0xAA"));
        assert!(!debug_str.contains("0xBB"));
        assert!(debug_str.contains("10 bytes"));
    }

    #[test]
    fn test_response_empty_groups() {
        let resp = DevicePairingResponse::new(vec![]);
        let bytes = resp.to_bytes().unwrap();
        let decoded = DevicePairingResponse::from_bytes(&bytes).unwrap();
        assert!(decoded.groups().is_empty());
    }

    #[test]
    fn test_validate_pairing_version_boundaries() {
        assert!(validate_pairing_version(0).is_err());
        assert!(validate_pairing_version(1).is_ok());
        assert!(validate_pairing_version(2).is_err());
        assert!(validate_pairing_version(u16::MAX).is_err());
    }

    #[test]
    fn test_request_large_key_package_json() {
        let large_json = vec![0xAB; 10_000];
        let req = DevicePairingRequest::new(large_json.clone());
        let bytes = req.to_bytes().unwrap();
        let decoded = DevicePairingRequest::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.key_package_event_json(), &large_json[..]);
    }

    #[test]
    fn test_group_pairing_data_v1_stream_deserialize_roundtrip() {
        use std::io::Cursor;
        use tls_codec::{Deserialize, Serialize};

        let data = GroupPairingDataV1::new([0xAA; 32], vec![0xBB; 32], vec![0xCC; 200]).unwrap();
        let mut bytes = Vec::new();
        data.tls_serialize(&mut bytes).unwrap();

        let mut cursor = Cursor::new(&bytes);
        let decoded = GroupPairingDataV1::tls_deserialize(&mut cursor).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_payload_multiple_groups_order_preserved() {
        let groups = vec![
            GroupPairingDataV1::new([1; 32], vec![11; 32], vec![21; 50]).unwrap(),
            GroupPairingDataV1::new([2; 32], vec![12; 32], vec![22; 60]).unwrap(),
            GroupPairingDataV1::new([3; 32], vec![13; 32], vec![23; 70]).unwrap(),
        ];
        let payload = PairingPayload::new(groups).unwrap();
        let bytes = payload.to_bytes().unwrap();
        let decoded = PairingPayload::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.groups().len(), 3);
        assert_eq!(decoded.groups()[0].group_event_key(), &[1; 32]);
        assert_eq!(decoded.groups()[1].group_event_key(), &[2; 32]);
        assert_eq!(decoded.groups()[2].group_event_key(), &[3; 32]);
    }
}
