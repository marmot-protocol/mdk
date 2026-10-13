//! Local client identity — signer + credential bundle carried by the engine.
//!
//! Generated once per Marmot identity and persisted through the configured
//! storage backend so reopened account-device sessions keep the same MLS
//! signing key.

use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::{
    AccountDeviceSignerBinding, StorageProvider as CgkaStorageProvider, StorageResult,
};
use cgka_traits::types::MemberId;
use openmls::extensions::Extensions;
use openmls::group::MlsGroup;
use openmls::prelude::{
    BasicCredential, Credential, CredentialWithKey, LeafNode, LeafNodeIndex, ProcessedMessage,
    ProcessedMessageContent, Sender, SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::Ciphersuite;
use web_time::{SystemTime, UNIX_EPOCH};

/// Bundle of everything needed to sign + identify the local client.
pub struct Identity {
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) self_id: MemberId,
    /// Proof material minted for this engine session.
    ///
    /// Current-profile proofs bind a fresh `created_at`, so they are rebuilt
    /// whenever an [`Identity`] is constructed even when the persisted MLS
    /// signer is reused. Callers must not treat these bytes as durable across
    /// account-device session restarts.
    pub(crate) account_identity_proof: crate::account_identity_proof::AccountIdentityProofMaterial,
}

impl Identity {
    /// Load or create an identity with a basic credential whose `identity`
    /// field carries `identity_bytes` (opaque — typically a stable pubkey).
    pub fn load_or_generate<S>(
        ciphersuite: Ciphersuite,
        identity_bytes: Vec<u8>,
        storage: &S,
        protocol_profile: ProtocolProfile,
        proof_signer: &dyn crate::account_identity_proof::AccountIdentityProofSigner,
    ) -> Result<Self, String>
    where
        S: CgkaStorageProvider,
    {
        // foundation/identity.md: the local Marmot identity is a 32-byte x-only
        // secp256k1 public key. Reject anything else before it can become a
        // credential other clients would also reject.
        validate_credential_identity(&identity_bytes).map_err(|e| e.to_string())?;
        let scheme: SignatureScheme = ciphersuite.signature_algorithm();
        let self_id = MemberId::new(identity_bytes.clone());
        if let Some(binding) = storage_err(storage.account_device_signer(&self_id))? {
            let signer = SignatureKeyPair::read(
                storage.mls_storage(),
                &binding.mls_signature_public_key,
                scheme,
            )
            .ok_or_else(|| {
                "identity storage: local signer record exists, but OpenMLS keypair is missing"
                    .to_string()
            })?;
            return Self::from_signer(
                signer,
                identity_bytes,
                ciphersuite,
                protocol_profile,
                proof_signer,
            );
        }

        let signer = SignatureKeyPair::new(scheme).map_err(|e| format!("signer: {e}"))?;
        signer
            .store(storage.mls_storage())
            .map_err(|e| format!("store signer: {e:?}"))?;
        storage_err(
            storage.put_account_device_signer(&AccountDeviceSignerBinding {
                marmot_identity: self_id,
                mls_signature_public_key: signer.to_public_vec(),
            }),
        )?;
        Self::from_signer(
            signer,
            identity_bytes,
            ciphersuite,
            protocol_profile,
            proof_signer,
        )
    }

    fn from_signer(
        signer: SignatureKeyPair,
        identity_bytes: Vec<u8>,
        ciphersuite: Ciphersuite,
        protocol_profile: ProtocolProfile,
        proof_signer: &dyn crate::account_identity_proof::AccountIdentityProofSigner,
    ) -> Result<Self, String> {
        let credential = BasicCredential::new(identity_bytes.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
            .as_secs();
        let account_identity_proof =
            crate::account_identity_proof::account_identity_proof_material(
                &identity_bytes,
                &signer.to_public_vec(),
                ciphersuite,
                ciphersuite.signature_algorithm(),
                protocol_profile,
                created_at,
                proof_signer,
            )
            .map_err(|e| e.to_string())?;
        Ok(Self {
            signer,
            credential_with_key,
            self_id: MemberId::new(identity_bytes),
            account_identity_proof,
        })
    }

    pub fn self_id(&self) -> &MemberId {
        &self.self_id
    }

    pub(crate) fn protocol_profile(&self) -> ProtocolProfile {
        self.account_identity_proof.protocol_profile()
    }

    pub(crate) fn leaf_extensions(
        &self,
        supported_app_components: &cgka_traits::app_components::AppComponentSet,
    ) -> Result<Extensions<LeafNode>, EngineError> {
        let extensions = match &self.account_identity_proof {
            crate::account_identity_proof::AccountIdentityProofMaterial::LegacyExtension(
                extension,
            ) => vec![
                crate::app_components::leaf_app_components_extension(
                    supported_app_components,
                    None,
                )?,
                extension.clone(),
            ],
            crate::account_identity_proof::AccountIdentityProofMaterial::CurrentComponent(
                component,
            ) => vec![crate::app_components::leaf_app_components_extension(
                supported_app_components,
                Some(component),
            )?],
        };
        Extensions::from_vec(extensions)
            .map_err(|error| EngineError::Backend(format!("leaf extensions: {error:?}")))
    }
}

fn storage_err<T>(result: StorageResult<T>) -> Result<T, String> {
    result.map_err(|e| format!("identity storage: {e}"))
}

/// Validate that `identity` is a valid Marmot member-leaf credential identity.
///
/// Per `spec/foundation/identity.md` and `spec/foundation/key-packages.md`,
/// the identity MUST be exactly 32 bytes AND those bytes MUST encode a valid
/// x-only secp256k1 (BIP-340) public key, i.e. a field element `x < p` that
/// lifts to a point on secp256k1.
///
/// We validate with `k256::schnorr::VerifyingKey::from_bytes`, which performs
/// the BIP-340 `lift_x` decompaction and on-curve check. The length check is
/// performed first because the underlying field-element parser expects exactly
/// 32 bytes.
pub(crate) fn validate_credential_identity(identity: &[u8]) -> Result<(), EngineError> {
    if identity.len() != 32 {
        return Err(EngineError::InvalidCredentialIdentity(format!(
            "credential identity must be exactly 32 bytes; got {}",
            identity.len()
        )));
    }
    k256::schnorr::VerifyingKey::from_bytes(identity).map_err(|_| {
        EngineError::InvalidCredentialIdentity(
            "credential identity is not a valid x-only secp256k1 public key".to_string(),
        )
    })?;
    Ok(())
}

/// Extract the validated `MemberId` from an MLS `Credential`.
///
/// The credential MUST be a `BasicCredential` whose identity is a valid Marmot
/// account identity. Used at every credential ingress so a malformed identity
/// is rejected before it can be trusted as a member id.
pub(crate) fn validated_member_id(credential: &Credential) -> Result<MemberId, EngineError> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|e| {
        EngineError::InvalidCredentialIdentity(format!("not a BasicCredential: {e:?}"))
    })?;
    let identity = basic.identity();
    validate_credential_identity(identity)?;
    Ok(MemberId::new(identity.to_vec()))
}

/// Validate the credential identity carried by a `LeafNode` (KeyPackage leaf or
/// in-tree leaf). Returns the validated `MemberId`.
pub(crate) fn validated_member_id_of_leaf(leaf: &LeafNode) -> Result<MemberId, EngineError> {
    validated_member_id(leaf.credential())
}

/// Resolve a sender only after OpenMLS has authenticated the message.
///
/// Applications can arrive after removal or reuse of their sender's leaf. The
/// processed credential is authenticated against the message's source-epoch
/// tree; looking up that index in the live tree would lose or misattribute the
/// author. Keep non-member applications rejected and preserve the current-tree
/// lookup for proposals and commits, whose authorization uses that tree.
pub(crate) fn member_id_of_processed_message(
    processed: &ProcessedMessage,
    group: &MlsGroup,
) -> Option<MemberId> {
    if matches!(
        processed.content(),
        ProcessedMessageContent::ApplicationMessage(_)
    ) {
        match processed.sender() {
            Sender::Member(_) => validated_member_id(processed.credential()).ok(),
            _ => None,
        }
    } else {
        member_id_of_sender(processed.sender(), group)
    }
}

pub(crate) fn member_id_of_sender(sender: &Sender, group: &MlsGroup) -> Option<MemberId> {
    match sender {
        Sender::Member(leaf_idx) => member_id_at_leaf(group, *leaf_idx),
        _ => None,
    }
}

pub(crate) fn member_id_at_leaf(group: &MlsGroup, leaf_idx: LeafNodeIndex) -> Option<MemberId> {
    let member = group.member_at(leaf_idx)?;
    validated_member_id(&member.credential).ok()
}

/// The same MLS-local identity predicate serves removal healing and terminal-gated readers.
/// Durable group-record gates belong to the caller, since healing must ignore its old marker.
pub(crate) fn local_leaf_is_active(group: &MlsGroup, identity: &MemberId) -> bool {
    group.is_active()
        && group.own_leaf_node().is_some_and(|leaf| {
            BasicCredential::try_from(leaf.credential().clone())
                .is_ok_and(|credential| credential.identity() == identity.as_slice())
        })
}

/// Read-only view of the pinned OpenMLS MessageSecretsStore encoding. The
/// ProcessedMessage API discards the verified signature key, but OpenMLS's
/// public_group::parse_message authenticates historical senders against these
/// exact retained epoch leaves. Preserve field order for positional MessagePack
/// storage, skipping secrets and unused keys without retaining their contents.
#[derive(serde::Deserialize)]
struct RetainedSenderTrees {
    #[serde(rename = "max_epochs")]
    _max_epochs: serde::de::IgnoredAny,
    past_epoch_trees: Vec<RetainedSenderTree>,
    #[serde(rename = "message_secrets")]
    _message_secrets: serde::de::IgnoredAny,
}

#[derive(serde::Deserialize)]
struct RetainedSenderTree {
    epoch: u64,
    #[serde(rename = "message_secrets")]
    _message_secrets: serde::de::IgnoredAny,
    leaves: Vec<RetainedSenderLeaf>,
}

#[derive(serde::Deserialize)]
struct RetainedSenderLeaf {
    index: LeafNodeIndex,
    credential: Credential,
    #[serde(rename = "encryption_key")]
    _encryption_key: serde::de::IgnoredAny,
    signature_key: Vec<u8>,
}

// The storage Entity trait requires Serialize, but this view must never overwrite
// the complete OpenMLS record (which includes secrets we intentionally skipped).
impl serde::Serialize for RetainedSenderTrees {
    fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "retained sender trees are read-only",
        ))
    }
}

impl openmls_traits::storage::Entity<{ openmls_traits::storage::CURRENT_VERSION }>
    for RetainedSenderTrees
{
}
impl openmls_traits::storage::traits::MessageSecrets<{ openmls_traits::storage::CURRENT_VERSION }>
    for RetainedSenderTrees
{
}

/// Capture authenticated source-epoch evidence before consuming ProcessedMessage.
pub(crate) fn sender_device_of_processed_message<M>(
    processed: &ProcessedMessage,
    group: &MlsGroup,
    local_signature_key: &[u8],
    storage: &M,
) -> Result<cgka_traits::message::SenderDevice, M::Error>
where
    M: openmls_traits::storage::StorageProvider<{ openmls_traits::storage::CURRENT_VERSION }>,
{
    use cgka_traits::message::{SenderDevice, member_device_id};
    if !matches!(
        processed.content(),
        ProcessedMessageContent::ApplicationMessage(_)
    ) {
        return Ok(SenderDevice::Unknown);
    }
    let Sender::Member(index) = processed.sender() else {
        return Ok(SenderDevice::Unknown);
    };
    let member = if processed.epoch() == group.epoch() {
        group.member_at(*index).map(|member| RetainedSenderLeaf {
            index: member.index,
            credential: member.credential,
            _encryption_key: serde::de::IgnoredAny,
            signature_key: member.signature_key,
        })
    } else {
        storage
            .message_secrets::<_, RetainedSenderTrees>(group.group_id())?
            .and_then(|trees| {
                trees
                    .past_epoch_trees
                    .into_iter()
                    .find(|tree| tree.epoch == processed.epoch().as_u64())
            })
            .and_then(|tree| tree.leaves.into_iter().find(|leaf| leaf.index == *index))
    };
    // Missing retained evidence is unprovable; never fall back to the live leaf
    // at this index, which may now belong to another device (even of this account).
    let Some(member) = member else {
        return Ok(SenderDevice::Unknown);
    };
    let Some(sender) = validated_member_id(processed.credential()).ok() else {
        return Ok(SenderDevice::Unknown);
    };
    if validated_member_id(&member.credential).ok().as_ref() != Some(&sender) {
        return Ok(SenderDevice::Unknown);
    }
    Ok(SenderDevice::Exact {
        device_id: member_device_id(
            &cgka_traits::GroupId::new(group.group_id().as_slice().to_vec()),
            &member.signature_key,
        ),
        leaf_index: index.u32(),
        client_label: None,
        is_this_installation: member.index == group.own_leaf_index()
            && member.signature_key == local_signature_key,
    })
}

/// A replay without a source tree retains proof already captured for the exact
/// same authenticated envelope. Never consult today's member projection here.
pub(crate) fn retain_saved_sender_device(
    storage: &impl cgka_traits::storage::MessageStorage,
    incoming: &mut cgka_traits::GroupEvent,
) -> Result<(), cgka_traits::StorageError> {
    use cgka_traits::GroupEvent;
    let GroupEvent::MessageReceived {
        group_id,
        message_id,
        epoch,
        sender,
        payload,
        sender_device,
        ..
    } = incoming
    else {
        return Ok(());
    };
    if !sender_device.is_unknown() {
        return Ok(());
    }
    if let Some(GroupEvent::MessageReceived {
        group_id: old_group,
        epoch: old_epoch,
        sender: old_sender,
        payload: old_payload,
        sender_device: old_device,
        ..
    }) = storage.get_pending_application_event(message_id)?
        && *group_id == old_group
        && *epoch == old_epoch
        && *sender == old_sender
        && *payload == old_payload
    {
        *sender_device = old_device;
    }
    Ok(())
}

#[cfg(test)]
mod sender_device_tests {
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent, SendResult};
    use cgka_traits::message::SenderDevice;
    use cgka_traits::storage::MessageStorage;

    #[test]
    fn sender_device_lookup_is_application_only_and_does_not_scan_live_roster() {
        // Pin the cost boundary: member_at indexes the tree directly, whereas
        // members() clones every preceding leaf. Non-applications need no device.
        let source = include_str!("identity.rs");
        let helper = source
            .split("pub(crate) fn sender_device_of_processed_message")
            .nth(1)
            .unwrap()
            .split("pub(crate) fn retain_saved_sender_device")
            .next()
            .unwrap();
        assert!(!helper.contains("group.members()"));
        assert!(helper.contains("group.member_at(*index)"));
        assert!(
            helper.find("processed.content()").unwrap()
                < helper.find("processed.sender()").unwrap()
        );
    }

    #[tokio::test]
    async fn sender_device_saved_evidence_requires_the_same_authenticated_message() {
        let mut engine = crate::distributed_convergence::tests::test_engine();
        let (group, created) = engine
            .create_group(CreateGroupRequest {
                name: "sender evidence".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        if let SendResult::GroupCreated { pending, .. } = created {
            engine.confirm_published(pending).await.unwrap();
        }
        let payload = cgka_traits::MarmotAppEvent::new(
            hex::encode(engine.self_id().as_slice()),
            1,
            9,
            vec![],
            "saved",
        )
        .encode()
        .unwrap();
        let sent = engine
            .send(SendIntent::AppMessage {
                group_id: group.clone(),
                payload: payload.clone(),
                expected_epoch: None,
            })
            .await
            .unwrap();
        let SendResult::ApplicationMessage {
            msg,
            source_epoch,
            sender_device,
            retention,
            authority,
            ..
        } = sent
        else {
            panic!("expected application");
        };
        let exact = GroupEvent::MessageReceived {
            group_id: group,
            message_id: msg.id,
            epoch: source_epoch,
            sender: engine.self_id(),
            payload,
            sender_device,
            retention: Some(retention),
            authority,
            encrypted_media_secret: None,
        };
        engine
            .storage
            .put_pending_application_event(&exact)
            .unwrap();
        let mut replay = exact.clone();
        if let GroupEvent::MessageReceived { sender_device, .. } = &mut replay {
            *sender_device = SenderDevice::Unknown;
        }
        super::retain_saved_sender_device(&engine.storage, &mut replay).unwrap();
        assert_eq!(replay, exact);
        if let GroupEvent::MessageReceived {
            sender_device,
            payload,
            ..
        } = &mut replay
        {
            *sender_device = SenderDevice::Unknown;
            payload.push(0);
        }
        super::retain_saved_sender_device(&engine.storage, &mut replay).unwrap();
        assert!(matches!(
            replay,
            GroupEvent::MessageReceived {
                sender_device: SenderDevice::Unknown,
                ..
            }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::validate_credential_identity;
    use k256::schnorr::SigningKey;

    /// A deterministic valid x-only secp256k1 public key derived from a seed.
    fn valid_xonly(seed: &[u8]) -> [u8; 32] {
        let mut counter = 0u64;
        loop {
            let mut material = [0u8; 32];
            let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut hasher, b"cgka-engine-identity-test-v1");
            sha2::Digest::update(&mut hasher, seed);
            sha2::Digest::update(&mut hasher, counter.to_be_bytes());
            material.copy_from_slice(&sha2::Digest::finalize(hasher));
            if let Ok(sk) = SigningKey::from_bytes(&material) {
                return sk.verifying_key().to_bytes().into();
            }
            counter += 1;
        }
    }

    #[test]
    fn accepts_valid_x_only_pubkey() {
        let pk = valid_xonly(b"alice");
        assert!(validate_credential_identity(&pk).is_ok());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(validate_credential_identity(&[0u8; 31]).is_err());
        assert!(validate_credential_identity(&[0u8; 33]).is_err());
        assert!(validate_credential_identity(b"alice").is_err());
    }

    #[test]
    fn rejects_invalid_curve_point() {
        // `pad32(b"david")` is 32 bytes but not a valid x-only point: a
        // zero-padded label is not a curve point in general.
        let mut padded = vec![0u8; 32];
        padded[..5].copy_from_slice(b"david");
        assert!(validate_credential_identity(&padded).is_err());
    }

    #[test]
    fn rejects_all_zero_and_field_overflow() {
        // All-zero x is not a valid x-only point.
        assert!(validate_credential_identity(&[0u8; 32]).is_err());
        // x >= field prime p must be rejected (all-0xFF overflows p).
        assert!(validate_credential_identity(&[0xFFu8; 32]).is_err());
    }
}
