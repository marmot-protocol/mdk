//! Authenticated account-to-account recovery control messages.
//!
//! These messages authorize no MLS change by themselves. The account runtime
//! binds their nonce, expiry and exact source to its durable recovery handshake.

use crate::{EpochId, GroupId, KeyPackage, MemberId, PeelerError};
use serde::{Deserialize, Serialize};

/// Maximum JSON control body accepted before deserialization.
pub const MAX_GROUP_RECOVERY_BODY_BYTES: usize = 128 * 1024;
/// Bound on the opaque MLS group identifier (not a transport routing id).
pub const MAX_GROUP_RECOVERY_GROUP_ID_BYTES: usize = 1024;
/// Maximum dedicated recovery KeyPackage TLS payload.
pub const MAX_GROUP_RECOVERY_KEY_PACKAGE_BYTES: usize = 16 * 1024;

/// An exact target leaf and coordinating device on an authenticated MLS branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRecoverySource {
    pub epoch: EpochId,
    pub epoch_authenticator_hash: [u8; 32],
    pub leaf_index: u32,
    pub leaf_hash: [u8; 32],
    /// SHA-256 of this device's persisted MLS signature public key. Unlike
    /// the leaf hash, this survives normal HPKE leaf self-updates.
    pub device_key_hash: [u8; 32],
    /// SHA-256 of the coordinating device's current MLS leaf signature public key.
    pub coordinator_key_hash: [u8; 32],
}

/// A member's authorized replacement of one exact leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMemberRecovery {
    pub member: MemberId,
    pub source: GroupRecoverySource,
    #[serde(with = "strict_key_package")]
    pub key_package: KeyPackage,
    pub request_id: [u8; 32],
    pub expires_at: u64,
    /// Ed25519 proof from the target device's persisted MLS signer.
    pub device_signature: Vec<u8>,
}

/// Version-independent recovery handshake payload; transports bind the version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRecoveryMessage {
    pub group_id: GroupId,
    pub request_id: [u8; 32],
    pub expires_at: u64,
    pub body: GroupRecoveryBody,
}

/// One step of the request/challenge/grant handshake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupRecoveryBody {
    Request {
        device_key_hash: [u8; 32],
    },
    Challenge {
        source: GroupRecoverySource,
    },
    Grant {
        source: GroupRecoverySource,
        #[serde(with = "strict_key_package")]
        key_package: KeyPackage,
        /// Ed25519 signature over [`group_recovery_grant_bytes`].
        device_signature: Vec<u8>,
    },
}

/// Control content bound to the verified account signer, not an outer carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedGroupRecovery {
    pub sender: MemberId,
    pub message: GroupRecoveryMessage,
}

impl GroupRecoveryMessage {
    /// Encode the bounded, strict JSON representation used inside private wraps.
    pub fn encode(&self) -> Result<Vec<u8>, PeelerError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| PeelerError::Malformed("invalid recovery body".into()))?;
        if bytes.len() > MAX_GROUP_RECOVERY_BODY_BYTES {
            return Err(PeelerError::Malformed("recovery body exceeds limit".into()));
        }
        Ok(bytes)
    }

    /// Decode only bounded JSON; duplicate/unknown fields and malformed nonces fail.
    pub fn decode(bytes: &[u8]) -> Result<Self, PeelerError> {
        if bytes.len() > MAX_GROUP_RECOVERY_BODY_BYTES {
            return Err(PeelerError::Malformed("recovery body exceeds limit".into()));
        }
        let message: Self = serde_json::from_slice(bytes)
            .map_err(|_| PeelerError::Malformed("invalid recovery body".into()))?;
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> Result<(), PeelerError> {
        if self.group_id.as_slice().is_empty()
            || self.group_id.as_slice().len() > MAX_GROUP_RECOVERY_GROUP_ID_BYTES
            || self.expires_at == 0
        {
            return Err(PeelerError::Malformed(
                "invalid recovery routing or expiry".into(),
            ));
        }
        if let GroupRecoveryBody::Grant {
            key_package,
            device_signature,
            ..
        } = &self.body
        {
            validate_key_package(key_package)?;
            if device_signature.len() != 64 {
                return Err(PeelerError::Malformed(
                    "invalid recovery device signature length".into(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_key_package(key_package: &KeyPackage) -> Result<(), PeelerError> {
    if key_package.bytes.is_empty()
        || key_package.bytes.len() > MAX_GROUP_RECOVERY_KEY_PACKAGE_BYTES
        || key_package
            .source
            .as_ref()
            .is_some_and(|source| source.event_id.as_slice().len() != 32)
    {
        return Err(PeelerError::Malformed(
            "invalid recovery key package".into(),
        ));
    }
    Ok(())
}

/// Canonical device-signed grant preimage, excluding the device signature.
///
/// Encoding: domain `mdk/group-recovery/grant/v1\0`; u32-big-endian-length
/// prefixed group ID and coordinator ID; 32-byte request ID; u64-big-endian
/// expiry; source epoch (u64 BE), authenticator hash (32 bytes), leaf index
/// (u32 BE), leaf hash (32 bytes), device-key hash (32 bytes), coordinator-key
/// hash (32 bytes); u32-BE-length prefixed KeyPackage bytes; profile byte
/// (legacy=0, current=1); provenance
/// presence byte (0 or 1), followed by the fixed 32-byte source event ID when
/// present. All lengths and integers have one representation. The signature
/// proves possession of the old device key, not possession of a public KP.
pub fn group_recovery_grant_bytes(
    group_id: &GroupId,
    coordinator: &MemberId,
    request_id: &[u8; 32],
    expires_at: u64,
    source: &GroupRecoverySource,
    key_package: &KeyPackage,
) -> Result<Vec<u8>, PeelerError> {
    const DOMAIN: &[u8] = b"mdk/group-recovery/grant/v1\0";
    if group_id.as_slice().is_empty()
        || group_id.as_slice().len() > MAX_GROUP_RECOVERY_GROUP_ID_BYTES
        || coordinator.as_slice().is_empty()
        || coordinator.as_slice().len() > MAX_GROUP_RECOVERY_GROUP_ID_BYTES
        || expires_at == 0
    {
        return Err(PeelerError::Malformed(
            "invalid recovery grant binding".into(),
        ));
    }
    validate_key_package(key_package)?;
    let provenance_len = key_package.source.as_ref().map_or(0, |_| 32);
    let mut bytes = Vec::with_capacity(
        DOMAIN.len()
            + 4
            + group_id.as_slice().len()
            + 4
            + coordinator.as_slice().len()
            + 32
            + 8
            + 8
            + 32
            + 4
            + 32
            + 32
            + 32
            + 4
            + key_package.bytes.len()
            + 1
            + 1
            + provenance_len,
    );
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(group_id.as_slice().len() as u32).to_be_bytes());
    bytes.extend_from_slice(group_id.as_slice());
    bytes.extend_from_slice(&(coordinator.as_slice().len() as u32).to_be_bytes());
    bytes.extend_from_slice(coordinator.as_slice());
    bytes.extend_from_slice(request_id);
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    bytes.extend_from_slice(&source.epoch.0.to_be_bytes());
    bytes.extend_from_slice(&source.epoch_authenticator_hash);
    bytes.extend_from_slice(&source.leaf_index.to_be_bytes());
    bytes.extend_from_slice(&source.leaf_hash);
    bytes.extend_from_slice(&source.device_key_hash);
    bytes.extend_from_slice(&source.coordinator_key_hash);
    bytes.extend_from_slice(&(key_package.bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&key_package.bytes);
    bytes.push(match key_package.protocol_profile {
        crate::group::ProtocolProfile::Legacy => 0,
        crate::group::ProtocolProfile::Current => 1,
    });
    match &key_package.source {
        None => bytes.push(0),
        Some(source) => {
            bytes.push(1);
            bytes.extend_from_slice(source.event_id.as_slice());
        }
    }
    Ok(bytes)
}

// KeyPackage's general storage serde is intentionally more permissive. The
// control-wire boundary rejects unknown fields at every nested object instead.
mod strict_key_package {
    use crate::group::ProtocolProfile;
    use crate::{KeyPackage, KeyPackageSource, MessageId};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Package {
        bytes: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<Source>,
        #[serde(default)]
        protocol_profile: ProtocolProfile,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Source {
        event_id: MessageId,
    }

    pub fn serialize<S: Serializer>(value: &KeyPackage, serializer: S) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<KeyPackage, D::Error> {
        let value = Package::deserialize(deserializer)?;
        Ok(KeyPackage {
            bytes: value.bytes,
            source: value.source.map(|source| KeyPackageSource {
                event_id: source.event_id,
            }),
            protocol_profile: value.protocol_profile,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> GroupRecoveryMessage {
        GroupRecoveryMessage {
            group_id: GroupId::new(vec![7; 16]),
            request_id: [8; 32],
            expires_at: 1234,
            body: GroupRecoveryBody::Request {
                device_key_hash: [9; 32],
            },
        }
    }

    #[test]
    fn recovery_codec_bounds() {
        let message = request();
        assert_eq!(
            GroupRecoveryMessage::decode(&message.encode().unwrap()).unwrap(),
            message
        );
        let value = serde_json::to_value(&message).unwrap();
        let mut unknown = value.clone();
        unknown["unknown"] = serde_json::json!(true);
        assert!(GroupRecoveryMessage::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let mut unknown_body = value.clone();
        unknown_body["body"]["unknown"] = serde_json::json!(true);
        assert!(GroupRecoveryMessage::decode(&serde_json::to_vec(&unknown_body).unwrap()).is_err());
        let mut obsolete_leaf = value.clone();
        obsolete_leaf["body"]["leaf_index"] = serde_json::json!(3);
        assert!(
            GroupRecoveryMessage::decode(&serde_json::to_vec(&obsolete_leaf).unwrap()).is_err()
        );
        let mut missing_device = value.clone();
        missing_device["body"]
            .as_object_mut()
            .unwrap()
            .remove("device_key_hash");
        assert!(
            GroupRecoveryMessage::decode(&serde_json::to_vec(&missing_device).unwrap()).is_err()
        );
        let mut bad_device = value.clone();
        bad_device["body"]["device_key_hash"] = serde_json::json!([1, 2]);
        assert!(GroupRecoveryMessage::decode(&serde_json::to_vec(&bad_device).unwrap()).is_err());
        let mut bad_nonce = value;
        bad_nonce["request_id"] = serde_json::json!([1, 2]);
        assert!(GroupRecoveryMessage::decode(&serde_json::to_vec(&bad_nonce).unwrap()).is_err());
        assert!(
            GroupRecoveryMessage::decode(&vec![b' '; MAX_GROUP_RECOVERY_BODY_BYTES + 1]).is_err()
        );
        let duplicate = String::from_utf8(message.encode().unwrap())
            .unwrap()
            .replacen(
                "\"expires_at\":1234",
                "\"expires_at\":1234,\"expires_at\":1234",
                1,
            );
        assert!(GroupRecoveryMessage::decode(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn recovery_codec_strict_package() {
        let mut message = request();
        message.body = GroupRecoveryBody::Grant {
            source: GroupRecoverySource {
                epoch: EpochId(4),
                epoch_authenticator_hash: [5; 32],
                leaf_index: 3,
                leaf_hash: [6; 32],
                device_key_hash: [9; 32],
                coordinator_key_hash: [11; 32],
            },
            key_package: KeyPackage::new(vec![1, 2, 3]),
            device_signature: vec![10; 64],
        };
        let mut value = serde_json::to_value(&message).unwrap();
        assert!(message.encode().is_ok());
        let mut missing_signature = value.clone();
        missing_signature["body"]
            .as_object_mut()
            .unwrap()
            .remove("device_signature");
        assert!(
            GroupRecoveryMessage::decode(&serde_json::to_vec(&missing_signature).unwrap()).is_err()
        );
        for length in [0, 63, 65] {
            let mut invalid = message.clone();
            if let GroupRecoveryBody::Grant {
                device_signature, ..
            } = &mut invalid.body
            {
                *device_signature = vec![0; length];
            }
            assert!(invalid.encode().is_err());
            assert!(GroupRecoveryMessage::decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut missing_device = value.clone();
        missing_device["body"]["source"]
            .as_object_mut()
            .unwrap()
            .remove("device_key_hash");
        assert!(
            GroupRecoveryMessage::decode(&serde_json::to_vec(&missing_device).unwrap()).is_err()
        );
        let mut bad_device = value.clone();
        bad_device["body"]["source"]["device_key_hash"] = serde_json::json!([1, 2]);
        assert!(GroupRecoveryMessage::decode(&serde_json::to_vec(&bad_device).unwrap()).is_err());
        let mut missing_coordinator = value.clone();
        missing_coordinator["body"]["source"]
            .as_object_mut()
            .unwrap()
            .remove("coordinator_key_hash");
        assert!(
            GroupRecoveryMessage::decode(&serde_json::to_vec(&missing_coordinator).unwrap())
                .is_err()
        );
        let mut bad_coordinator = value.clone();
        bad_coordinator["body"]["source"]["coordinator_key_hash"] = serde_json::json!([1, 2]);
        assert!(
            GroupRecoveryMessage::decode(&serde_json::to_vec(&bad_coordinator).unwrap()).is_err()
        );
        value["body"]["key_package"]["unknown"] = serde_json::json!(true);
        assert!(GroupRecoveryMessage::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        if let GroupRecoveryBody::Grant { key_package, .. } = &mut message.body {
            key_package.bytes = vec![0; MAX_GROUP_RECOVERY_KEY_PACKAGE_BYTES + 1];
        }
        assert!(message.encode().is_err());
    }

    #[test]
    fn recovery_grant_binds_inputs() {
        use crate::group::ProtocolProfile;
        use crate::{KeyPackageSource, MessageId};
        use sha2::{Digest, Sha256};

        let group = GroupId::new(vec![1; 16]);
        let coordinator = MemberId::new(vec![2; 32]);
        let nonce = [3; 32];
        let expiry = 1234;
        let source = GroupRecoverySource {
            epoch: EpochId(4),
            epoch_authenticator_hash: [5; 32],
            leaf_index: 6,
            leaf_hash: [7; 32],
            device_key_hash: [8; 32],
            coordinator_key_hash: [12; 32],
        };
        let package = KeyPackage::with_source_event_id(vec![9, 10], MessageId::new(vec![11; 32]));
        let expected = [
            b"mdk/group-recovery/grant/v1\0".as_slice(),
            &16_u32.to_be_bytes(),
            &[1; 16],
            &32_u32.to_be_bytes(),
            &[2; 32],
            &[3; 32],
            &1234_u64.to_be_bytes(),
            &4_u64.to_be_bytes(),
            &[5; 32],
            &6_u32.to_be_bytes(),
            &[7; 32],
            &[8; 32],
            &[12; 32],
            &2_u32.to_be_bytes(),
            &[9, 10],
            &[0, 1],
            &[11; 32],
        ]
        .concat();
        assert_eq!(
            group_recovery_grant_bytes(&group, &coordinator, &nonce, expiry, &source, &package)
                .unwrap(),
            expected
        );
        let digest = |group: &GroupId,
                      coordinator: &MemberId,
                      nonce: &[u8; 32],
                      expiry: u64,
                      source: &GroupRecoverySource,
                      package: &KeyPackage|
         -> [u8; 32] {
            Sha256::digest(
                group_recovery_grant_bytes(group, coordinator, nonce, expiry, source, package)
                    .unwrap(),
            )
            .into()
        };
        let original = digest(&group, &coordinator, &nonce, expiry, &source, &package);
        assert_eq!(
            original,
            digest(&group, &coordinator, &nonce, expiry, &source, &package)
        );
        assert_ne!(
            original,
            digest(
                &GroupId::new(vec![12; 16]),
                &coordinator,
                &nonce,
                expiry,
                &source,
                &package
            )
        );
        assert_ne!(
            original,
            digest(
                &group,
                &MemberId::new(vec![12; 32]),
                &nonce,
                expiry,
                &source,
                &package
            )
        );
        assert_ne!(
            original,
            digest(&group, &coordinator, &[12; 32], expiry, &source, &package)
        );
        assert_ne!(
            original,
            digest(&group, &coordinator, &nonce, expiry + 1, &source, &package)
        );
        for field in 0..6 {
            let mut altered = source.clone();
            match field {
                0 => altered.epoch.0 += 1,
                1 => altered.epoch_authenticator_hash[0] ^= 1,
                2 => altered.leaf_index += 1,
                3 => altered.leaf_hash[0] ^= 1,
                4 => altered.device_key_hash[0] ^= 1,
                5 => altered.coordinator_key_hash[0] ^= 1,
                _ => unreachable!(),
            }
            assert_ne!(
                original,
                digest(&group, &coordinator, &nonce, expiry, &altered, &package)
            );
        }
        for field in 0..4 {
            let mut altered = package.clone();
            match field {
                0 => altered.bytes[0] ^= 1,
                1 => altered.protocol_profile = ProtocolProfile::Current,
                2 => altered.source = None,
                3 => {
                    altered.source = Some(KeyPackageSource {
                        event_id: MessageId::new(vec![12; 32]),
                    })
                }
                _ => unreachable!(),
            }
            assert_ne!(
                original,
                digest(&group, &coordinator, &nonce, expiry, &source, &altered)
            );
        }
        // Length prefixes rule out ambiguous adjacent variable-width IDs.
        assert_ne!(
            digest(
                &GroupId::new(vec![1]),
                &MemberId::new(vec![2, 3]),
                &nonce,
                expiry,
                &source,
                &package
            ),
            digest(
                &GroupId::new(vec![1, 2]),
                &MemberId::new(vec![3]),
                &nonce,
                expiry,
                &source,
                &package
            ),
        );
        assert!(
            group_recovery_grant_bytes(&group, &coordinator, &nonce, 0, &source, &package).is_err()
        );
    }
}
