//! MIP-06 join PSK: exporter-derived External PSK for External Commit authorization.
//!
//! Existing members derive a `join_psk` from the MLS exporter secret and register it
//! as an External PSK so that OpenMLS can verify the `confirmation_tag` when processing
//! an incoming External Commit. The joining device receives the raw PSK bytes via the
//! pairing payload and registers them under the same PSK ID before building its commit.
//!
//! ```text
//! join_psk_id = TLS-serialize(MarmotMultiDeviceJoinPskId {
//!     label: "marmot-mip06-join-psk-v1",
//!     group_context_hash: SHA-256(TLS-serialized GroupContext),
//! })
//!
//! join_psk = MLS-Exporter("marmot-mip06-join-psk-v1", join_psk_id, KDF.Nh)
//! ```

use sha2::{Digest, Sha256};
use tls_codec::{DeserializeBytes, Serialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::error::Error;

/// The 24-byte ASCII label used in the PSK ID and exporter derivation.
pub const JOIN_PSK_LABEL: &[u8; 24] = b"marmot-mip06-join-psk-v1";

/// The exporter label string (same content, used as the MLS-Exporter label parameter).
pub const JOIN_PSK_EXPORTER_LABEL: &str = "marmot-mip06-join-psk-v1";

/// PSK identifier for MIP-06 External Commit joins.
///
/// ```tls
/// struct {
///     opaque label[24];                  // ASCII("marmot-mip06-join-psk-v1")
///     opaque group_context_hash[32];     // SHA-256(TLS-serialized GroupContext)
/// } MarmotMultiDeviceJoinPskId;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct JoinPskId {
    label: [u8; 24],
    group_context_hash: [u8; 32],
}

impl JoinPskId {
    /// Build a `JoinPskId` from TLS-serialized `GroupContext` bytes.
    pub fn from_group_context_bytes(group_context_bytes: &[u8]) -> Self {
        let group_context_hash: [u8; 32] = Sha256::digest(group_context_bytes).into();
        Self {
            label: *JOIN_PSK_LABEL,
            group_context_hash,
        }
    }

    /// TLS-serialize this PSK ID to bytes (for use as `psk_id` in OpenMLS).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.tls_serialize(&mut buf)
            .map_err(|e| Error::PairingError(format!("failed to serialize JoinPskId: {e}")))?;
        Ok(buf)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (id, _) = Self::tls_deserialize_bytes(bytes)
            .map_err(|e| Error::PairingError(format!("failed to deserialize JoinPskId: {e}")))?;
        id.validate()?;
        Ok(id)
    }

    /// Validate the label field matches the expected constant.
    pub fn validate(&self) -> Result<(), Error> {
        if &self.label != JOIN_PSK_LABEL {
            return Err(Error::PairingError(format!(
                "invalid JoinPskId label: expected {:?}, got {:?}",
                JOIN_PSK_LABEL, &self.label
            )));
        }
        Ok(())
    }

    /// The 32-byte group context hash.
    pub fn group_context_hash(&self) -> &[u8; 32] {
        &self.group_context_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_psk_id_roundtrip() {
        let gc_bytes = b"fake-group-context-tls-bytes";
        let id = JoinPskId::from_group_context_bytes(gc_bytes);

        assert_eq!(&id.label, JOIN_PSK_LABEL);
        assert_eq!(
            id.group_context_hash(),
            &<[u8; 32]>::from(Sha256::digest(gc_bytes))
        );

        let bytes = id.to_bytes().unwrap();
        let decoded = JoinPskId::from_bytes(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_join_psk_id_fixed_size() {
        let id = JoinPskId::from_group_context_bytes(b"ctx");
        let bytes = id.to_bytes().unwrap();
        // 24 (label) + 32 (hash) = 56 bytes, no length prefixes for fixed-size arrays
        assert_eq!(bytes.len(), 56);
    }

    #[test]
    fn test_join_psk_id_deterministic() {
        let id1 = JoinPskId::from_group_context_bytes(b"same-context");
        let id2 = JoinPskId::from_group_context_bytes(b"same-context");
        assert_eq!(id1, id2);

        let id3 = JoinPskId::from_group_context_bytes(b"different-context");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_join_psk_id_invalid_label_rejected() {
        let mut id = JoinPskId::from_group_context_bytes(b"ctx");
        id.label[0] = b'X'; // corrupt label
        assert!(id.validate().is_err());
    }

    #[test]
    fn test_join_psk_id_empty_context() {
        let id = JoinPskId::from_group_context_bytes(b"");
        assert!(id.validate().is_ok());
        // Even empty context should produce a valid hash
        assert_eq!(
            id.group_context_hash(),
            &<[u8; 32]>::from(Sha256::digest(b""))
        );
    }

    #[test]
    fn test_join_psk_id_large_context() {
        let large_ctx = vec![0xAB; 100_000];
        let id = JoinPskId::from_group_context_bytes(&large_ctx);
        assert!(id.validate().is_ok());

        let bytes = id.to_bytes().unwrap();
        let decoded = JoinPskId::from_bytes(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_join_psk_id_label_matches_constant() {
        let id = JoinPskId::from_group_context_bytes(b"anything");
        assert_eq!(&id.label, JOIN_PSK_LABEL);
        assert_eq!(&id.label, b"marmot-mip06-join-psk-v1");
    }

    #[test]
    fn test_join_psk_id_from_bytes_validates_label() {
        let mut id = JoinPskId::from_group_context_bytes(b"ctx");
        id.label = [0xFF; 24]; // completely corrupt label

        let bytes = id.to_bytes().unwrap();
        assert!(matches!(
            JoinPskId::from_bytes(&bytes),
            Err(Error::PairingError(ref msg)) if msg.contains("invalid JoinPskId label")
        ));
    }

    #[test]
    fn test_join_psk_id_truncated_bytes_rejected() {
        let id = JoinPskId::from_group_context_bytes(b"ctx");
        let bytes = id.to_bytes().unwrap();

        // Truncate to less than 56 bytes
        assert!(JoinPskId::from_bytes(&bytes[..30]).is_err());
    }

    #[test]
    fn test_join_psk_id_different_contexts_different_hashes() {
        let id1 = JoinPskId::from_group_context_bytes(b"context-alpha");
        let id2 = JoinPskId::from_group_context_bytes(b"context-beta");

        assert_ne!(id1.group_context_hash(), id2.group_context_hash());
        // But labels should be the same
        assert_eq!(id1.label, id2.label);
    }
}
