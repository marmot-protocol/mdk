use cgka_traits::{EngineError, MarmotAppEvent, MemberId};
use sha2::{Digest, Sha256};

pub(crate) fn source_authority(
    group: &openmls::group::MlsGroup,
    sender: &MemberId,
) -> Result<cgka_traits::app_event::AppMessageAuthority, EngineError> {
    let profile = crate::app_components::group_profile_of_group(group)?;
    let direct = group.members().count() == 2
        && profile
            .as_ref()
            .is_none_or(|(name, _)| name.trim().is_empty());
    let admins = crate::app_components::admins_of_group(group)?;
    Ok(cgka_traits::app_event::AppMessageAuthority {
        source_context: Sha256::digest(group.epoch_authenticator().as_slice()).into(),
        reporting_allowed: !direct,
        moderation_grant: !direct && admins.iter().any(|key| key.as_slice() == sender.as_slice()),
    })
}

/// Stable transient reference used when convergence reports a decrypted
/// application payload without retaining the plaintext itself.
pub(crate) fn decrypted_payload_ref(payload: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

/// Shared application-payload sender validation for every inbound seam
/// (direct ingest, stored-convergence/replay). An application message is
/// surfaced only when its inner event's author matches the MLS-authenticated
/// sender; an empty sender is rejected outright so an unattributable message
/// can never validate, regardless of what the inner event claims.
pub(crate) fn validate_app_payload_for_sender(
    payload: &[u8],
    sender: &MemberId,
) -> Result<MarmotAppEvent, EngineError> {
    if sender.as_slice().is_empty() {
        return Err(EngineError::InvalidAppMessagePayload(
            "application message has no authenticated member sender".into(),
        ));
    }
    let event = MarmotAppEvent::decode(payload)
        .map_err(|err| EngineError::InvalidAppMessagePayload(err.to_string()))?;
    let sender_hex = hex::encode(sender.as_slice());
    event
        .validate_sender(&sender_hex)
        .map_err(|err| EngineError::InvalidAppMessagePayload(err.to_string()))?;
    Ok(event)
}

/// Authenticate the ciphertext again in the retained source state before
/// consulting its policy. An epoch number alone never proves branch identity.
/// The guard restores live state (including ratchets) on every return path.
pub(crate) fn historical_authority<S: cgka_traits::StorageProvider>(
    storage: &S,
    group_id: &cgka_traits::GroupId,
    epoch: cgka_traits::EpochId,
    sender: &MemberId,
    wire: &[u8],
    payload: &[u8],
) -> Result<Option<cgka_traits::app_event::AppMessageAuthority>, EngineError> {
    Ok(historical_authority_and_payload(
        storage,
        group_id,
        epoch,
        sender,
        wire,
        &Sha256::digest(payload).into(),
    )?
    .map(|(authority, _)| authority))
}

fn historical_authority_and_payload<S: cgka_traits::StorageProvider>(
    storage: &S,
    group_id: &cgka_traits::GroupId,
    epoch: cgka_traits::EpochId,
    sender: &MemberId,
    wire: &[u8],
    expected_digest: &[u8; 32],
) -> Result<Option<(cgka_traits::app_event::AppMessageAuthority, Vec<u8>)>, EngineError> {
    use openmls::prelude::{MlsGroup, ProcessedMessageContent};
    use openmls_traits::OpenMlsProvider;
    let name = storage
        .list_group_snapshots(group_id)?
        .into_iter()
        .find(|name| {
            crate::openmls_projection::retained_anchor_epoch_from_snapshot_name(name)
                == Some(epoch.0)
        });
    let Some(name) = name else { return Ok(None) };
    let guard = crate::snapshot_guard::SnapshotRollbackGuard::create_group_state(
        storage,
        group_id.clone(),
        crate::snapshot_guard::RewindSite::RetentionSource,
        "moderation-authority",
    )?;
    storage.rollback_group_state_to_snapshot(group_id, &name)?;
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider = crate::provider::EngineOpenMlsProvider::<S>::new(&crypto, storage.mls_storage());
    let mut group = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .map_err(|_| EngineError::Backend("load moderation source state".into()))?
    .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
    let result = if group.epoch().as_u64() == epoch.0 {
        let (_, protocol) = crate::openmls_projection::project_protocol_message(wire)
            .map_err(|_| EngineError::Backend("decode moderation source message".into()))?;
        match protocol.and_then(|protocol| group.process_message(&provider, protocol).ok()) {
            Some(processed)
                if crate::identity::member_id_of_processed_message(&processed, &group).as_ref()
                    == Some(sender) =>
            {
                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(bytes) => {
                        let payload = bytes.into_bytes();
                        if <[u8; 32]>::from(Sha256::digest(&payload)) == *expected_digest {
                            Some((source_authority(&group, sender)?, payload))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    } else {
        None
    };
    guard.commit()?;
    Ok(result)
}

impl<S: cgka_traits::StorageProvider> crate::engine::Engine<S> {
    pub(crate) fn recover_pending_application_authority(&mut self) -> Result<(), EngineError> {
        use cgka_traits::engine::GroupEvent;
        use cgka_traits::message::{MessageState, StoredMessagePayload};
        let events = self
            .storage
            .pending_application_authority_batch(self.authority_recovery_cursor.as_ref(), 32)?;
        if events.is_empty() {
            self.authority_recovery_cursor = None;
            return Ok(());
        }
        for request in events {
            self.authority_recovery_cursor = Some(request.message_id.clone());
            let record = self.storage.get_message(&request.message_id)?;
            if record.state != MessageState::Processed {
                continue;
            }
            let stored = StoredMessagePayload::decode(&record.payload)
                .map_err(|_| EngineError::Backend("decode authority source record".into()))?;
            let Some(wire) = stored.as_openmls_wire() else {
                continue;
            };
            if let Some((authority, payload)) = historical_authority_and_payload(
                &self.storage,
                &request.group_id,
                request.epoch,
                &request.sender,
                &wire.payload,
                &request.payload_digest,
            )? {
                let event = GroupEvent::MessageReceived {
                    group_id: request.group_id,
                    message_id: request.message_id,
                    epoch: request.epoch,
                    sender: request.sender,
                    payload,
                    authority: Some(authority),
                    retention: request.retention,
                };
                self.storage.put_pending_application_event(&event)?;
                self.events_buf.push_back(event);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypted_payload_ref, validate_app_payload_for_sender};
    use cgka_traits::{EngineError, MarmotAppEvent, MemberId};

    fn payload_from(pubkey: &str) -> Vec<u8> {
        MarmotAppEvent::new(pubkey, 1, 9, vec![], "hello")
            .encode()
            .expect("encode app event")
    }

    #[test]
    fn empty_sender_is_rejected_even_when_event_pubkey_is_empty() {
        // Regression for the S3 replay-seam gap (#383): an event whose
        // `pubkey` is the empty string must not validate against an empty
        // (unresolvable) MLS sender.
        let payload = payload_from("");
        let result = validate_app_payload_for_sender(&payload, &MemberId::new(Vec::new()));
        assert!(matches!(
            result,
            Err(EngineError::InvalidAppMessagePayload(_))
        ));
    }

    #[test]
    fn pubkey_mismatch_is_rejected() {
        let sender = MemberId::new(vec![0x11; 32]);
        let payload = payload_from(&hex::encode([0x22; 32]));
        let result = validate_app_payload_for_sender(&payload, &sender);
        assert!(matches!(
            result,
            Err(EngineError::InvalidAppMessagePayload(_))
        ));
    }

    #[test]
    fn matching_sender_validates() {
        let sender = MemberId::new(vec![0x11; 32]);
        let payload = payload_from(&hex::encode([0x11; 32]));
        let event =
            validate_app_payload_for_sender(&payload, &sender).expect("matching sender validates");
        assert_eq!(event.content, "hello");
    }

    #[test]
    fn decrypted_payload_reference_format_is_stable() {
        assert_eq!(
            decrypted_payload_ref(b"hello"),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
