use cgka_traits::{EngineError, MarmotAppEvent, MemberId};
use sha2::{Digest, Sha256};

pub(crate) fn source_authority(
    group: &openmls::group::MlsGroup,
    sender: &MemberId,
) -> Result<cgka_traits::app_event::AppMessageAuthority, EngineError> {
    let profile = crate::app_components::group_profile_of_group(group)?;
    let members = group
        .members()
        .map(|member| crate::identity::validated_member_id(&member.credential))
        .collect::<Result<std::collections::HashSet<_>, _>>()?;
    let reporting_allowed = cgka_traits::reporting::group_reporting_allowed(
        members.len(),
        profile.as_ref().map(|(name, _)| name.as_str()),
    );
    let admins = crate::app_components::admins_of_group(group)?;
    Ok(cgka_traits::app_event::AppMessageAuthority {
        source_context: Sha256::digest(group.epoch_authenticator().as_slice()).into(),
        reporting_allowed,
        moderation_grant: reporting_allowed
            && members.contains(sender)
            && admins.iter().any(|key| key.as_slice() == sender.as_slice()),
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

/// Source policy authenticated by replaying the exact ciphertext. Retention and
/// moderation use the same snapshot visit, so delayed controls pay one rewind.
pub(crate) struct HistoricalSource {
    pub authority: cgka_traits::app_event::AppMessageAuthority,
    pub retention_seconds: u64,
    pub payload: Vec<u8>,
}

pub(crate) fn retained_source_snapshot<S: cgka_traits::StorageProvider>(
    storage: &S,
    group_id: &cgka_traits::GroupId,
    epoch: cgka_traits::EpochId,
) -> Result<Option<String>, EngineError> {
    Ok(storage
        .list_group_snapshots(group_id)?
        .into_iter()
        .find(|name| {
            crate::openmls_projection::retained_anchor_epoch_from_snapshot_name(name)
                == Some(epoch.0)
        }))
}

/// Authentication failure against a retained branch is unresolved, not a
/// rejection: another branch at the same epoch may supply the missing proof.
/// The guard restores live state and ratchets on every return path.
pub(crate) fn historical_source<S: cgka_traits::StorageProvider>(
    storage: &S,
    crypto: &openmls_rust_crypto::RustCrypto,
    request: &cgka_traits::app_event::PendingAppMessageAuthority,
    snapshot: &str,
    wire: &[u8],
) -> Result<Option<HistoricalSource>, EngineError> {
    use cgka_traits::storage::StorageError;
    use openmls::prelude::{MlsGroup, ProcessedMessageContent};
    use openmls_traits::OpenMlsProvider;
    let guard = crate::snapshot_guard::SnapshotRollbackGuard::create_group_state(
        storage,
        request.group_id.clone(),
        crate::snapshot_guard::RewindSite::ModerationSource,
        &format!("{:032x}", rand::random::<u128>()),
    )?;
    match storage.rollback_group_state_to_snapshot(&request.group_id, snapshot) {
        Ok(()) => {}
        Err(StorageError::SnapshotMissing(_)) => {
            guard.commit()?;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    }
    let provider = crate::provider::EngineOpenMlsProvider::<S>::new(crypto, storage.mls_storage());
    let group = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(request.group_id.as_slice()),
    )
    .map_err(|_| EngineError::Backend("load moderation source state".into()))?;
    let result = if let Some(mut group) = group.filter(|g| g.epoch().as_u64() == request.epoch.0) {
        let (_, protocol) = crate::openmls_projection::project_protocol_message(wire)
            .map_err(|_| EngineError::Backend("decode moderation source message".into()))?;
        match protocol.and_then(|protocol| group.process_message(&provider, protocol).ok()) {
            Some(processed)
                if crate::identity::member_id_of_processed_message(&processed, &group).as_ref()
                    == Some(&request.sender) =>
            {
                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(bytes) => {
                        let payload = bytes.into_bytes();
                        if <[u8; 32]>::from(Sha256::digest(&payload)) == request.payload_digest {
                            Some(HistoricalSource {
                                authority: source_authority(&group, &request.sender)?,
                                retention_seconds:
                                    crate::app_components::message_retention_seconds_of_group(
                                        &group,
                                    )?
                                    .unwrap_or(0),
                                payload,
                            })
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
    /// Retry at most 32 unresolved moderation controls on the maintenance rail.
    /// Event draining is deliberately free of database reads and MLS rewinds.
    pub fn recover_pending_application_authority(&mut self) -> Result<(), EngineError> {
        use cgka_traits::engine::GroupEvent;
        use cgka_traits::message::{MessageState, StoredMessagePayload};
        let events = self
            .storage
            .pending_application_authority_batch(self.authority_recovery_cursor.as_ref(), 32)?;
        if events.is_empty() {
            self.authority_recovery_cursor = None;
            self.authority_recovery_attempts
                .retain(|id, _| self.authority_recovery_seen.contains(id));
            self.authority_recovery_seen.clear();
            return Ok(());
        }
        for request in events {
            self.authority_recovery_cursor = Some(request.message_id.clone());
            self.authority_recovery_seen
                .insert(request.message_id.clone());
            let record = match self.storage.get_message(&request.message_id) {
                Ok(record) => record,
                Err(cgka_traits::storage::StorageError::NotFound) => continue,
                Err(error) => return Err(error.into()),
            };
            if record.state != MessageState::Processed {
                continue;
            }
            let Some(snapshot) =
                retained_source_snapshot(&self.storage, &request.group_id, request.epoch)?
            else {
                continue;
            };
            // This secret-derived digest is only an in-memory retry key, never
            // a policy verdict or durable evidence. A replacement under the
            // same snapshot name must permit authentication again.
            let fingerprint = self
                .storage
                .group_snapshot_fingerprint(&request.group_id, &snapshot)?;
            if fingerprint.is_some()
                && self.authority_recovery_attempts.get(&request.message_id) == fingerprint.as_ref()
            {
                continue;
            }
            let stored = StoredMessagePayload::decode(&record.payload)
                .map_err(|_| EngineError::Backend("decode authority source record".into()))?;
            let Some(wire) = stored.as_openmls_wire() else {
                continue;
            };
            if let Some(source) = historical_source(
                &self.storage,
                &self.crypto,
                &request,
                &snapshot,
                &wire.payload,
            )? {
                let app_event = validate_app_payload_for_sender(&source.payload, &request.sender)?;
                let event = GroupEvent::MessageReceived {
                    group_id: request.group_id,
                    message_id: request.message_id.clone(),
                    epoch: request.epoch,
                    sender: request.sender,
                    payload: source.payload,
                    authority: Some(source.authority),
                    retention: request.retention.or_else(|| {
                        Some(cgka_traits::app_event::AppMessageRetentionDecision::new(
                            app_event.created_at,
                            source.retention_seconds,
                        ))
                    }),
                };
                self.storage.put_pending_application_event(&event)?;
                self.authority_recovery_attempts.remove(&request.message_id);
                self.events_buf.push_back(event);
            } else if let Some(fingerprint) = fingerprint {
                self.authority_recovery_attempts
                    .insert(request.message_id, fingerprint);
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
    fn vanished_source_snapshot_stays_unresolved_and_restores_live_state() {
        use cgka_traits::storage::{GroupStorage, MessageStorage};
        use cgka_traits::{EpochId, GroupId, MessageId};
        let storage = storage_sqlite::SqliteAccountStorage::in_memory().unwrap();
        let group_id = GroupId::new(vec![7; 16]);
        let group = cgka_traits::group::Group {
            id: group_id.clone(),
            name: "live".into(),
            description: String::new(),
            epoch: EpochId(3),
            members: Vec::new(),
            required_capabilities: Default::default(),
            protocol_profile: cgka_traits::group::ProtocolProfile::Legacy,
            removed: false,
            unrecoverable: false,
            disbanded: None,
            join_epoch: EpochId(0),
            local_copy_install_epoch: EpochId(0),
        };
        storage.put_group(&group).unwrap();
        let request = cgka_traits::app_event::PendingAppMessageAuthority {
            group_id: group_id.clone(),
            message_id: MessageId::new(vec![1; 32]),
            epoch: EpochId(1),
            sender: MemberId::new(vec![2; 32]),
            payload_digest: [0; 32],
            retention: None,
        };
        assert!(
            super::historical_source(
                &storage,
                &openmls_rust_crypto::RustCrypto::default(),
                &request,
                "pruned-after-listing",
                &[]
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(storage.get_group(&group_id).unwrap().name, "live");
        assert!(storage.list_group_snapshots(&group_id).unwrap().is_empty());
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
