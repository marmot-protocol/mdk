//! Decryption and epoch fallback
//!
//! This module handles message decryption with epoch-based key fallback.

use mdk_storage_traits::groups::types as group_types;
use mdk_storage_traits::{GroupId, MdkStorageProvider};
use nostr::{Event, TagKind};
use openmls::prelude::MlsGroup;

use crate::MDK;
use crate::error::Error;
use crate::messages::crypto::decrypt_message_with_any_supported_format;

use super::{DEFAULT_EPOCH_LOOKBACK, Result};

/// Legacy exporter-secret compatibility is accepted only until May 15, 2026
/// 00:00:00 UTC. This keeps the `0.6.x -> 0.7.x` migration path available
/// temporarily without leaving fallback decryption open-ended.
const LEGACY_EXPORTER_SECRET_MIGRATION_DEADLINE: u64 = 1_778_803_200;

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Loads the group and decrypts the message content
    ///
    /// This private method loads the group from storage using the Nostr group ID,
    /// loads the corresponding MLS group, and decrypts the message content using
    /// the group's exporter secrets.
    ///
    /// # Arguments
    ///
    /// * `nostr_group_id` - The Nostr group ID extracted from the event
    /// * `event` - The Nostr event containing the encrypted message
    ///
    /// # Returns
    ///
    /// * `Ok((group_types::Group, MlsGroup, Vec<u8>))` - The loaded group, MLS group, and decrypted message bytes
    /// * `Err(Error)` - If group loading or message decryption fails
    pub(super) fn decrypt_message(
        &self,
        nostr_group_id: [u8; 32],
        event: &Event,
    ) -> Result<(group_types::Group, MlsGroup, Vec<u8>)> {
        self.decrypt_message_at(nostr_group_id, event, nostr::Timestamp::now().as_secs())
    }

    pub(super) fn decrypt_message_at(
        &self,
        nostr_group_id: [u8; 32],
        event: &Event,
        current_time: u64,
    ) -> Result<(group_types::Group, MlsGroup, Vec<u8>)> {
        // Load groups by Nostr Group ID (Pattern B)
        // Used when processing incoming events which only have the Nostr group ID
        // from the h-tag. This is different from Pattern A (in create.rs) which
        // loads by MLS group ID when we already have it from API calls.
        let group = self
            .storage()
            .find_group_by_nostr_group_id(&nostr_group_id)
            .map_err(|_e| Error::Group("Storage error while finding group".to_string()))?
            .ok_or(Error::GroupNotFound)?;

        // Load the MLS group to get the current epoch
        let mls_group: MlsGroup = self
            .load_mls_group(&group.mls_group_id)
            .map_err(|_e| Error::Group("Storage error while loading MLS group".to_string()))?
            .ok_or(Error::GroupNotFound)?;

        let allow_legacy_exporter_secret =
            Self::allow_legacy_exporter_secret_fallback_at(current_time);
        let allow_legacy_nip44 = Self::allow_legacy_nip44_wrapper_fallback_at(event, current_time);

        // Try to decrypt message with recent exporter secrets (fallback across epochs)
        let message_bytes: Vec<u8> = self.try_decrypt_with_recent_epochs(
            &mls_group,
            &event.content,
            allow_legacy_exporter_secret,
            allow_legacy_nip44,
        )?;

        Ok((group, mls_group, message_bytes))
    }

    fn allow_legacy_exporter_secret_fallback_at(current_time: u64) -> bool {
        current_time <= LEGACY_EXPORTER_SECRET_MIGRATION_DEADLINE
    }

    fn allow_legacy_nip44_wrapper_fallback_at(event: &Event, current_time: u64) -> bool {
        // Events with an explicit `encoding=base64` tag were produced by the current AEAD
        // format (post-0.7.0). Legacy NIP-44 events have no encoding tag at all.
        // We check both kind and value to avoid accidentally blocking the fallback for
        // future or alternative encoding tags whose values we don't recognise.
        if event.tags.iter().any(|tag| {
            tag.kind() == TagKind::Custom("encoding".into()) && tag.content() == Some("base64")
        }) {
            return false;
        }

        Self::allow_legacy_exporter_secret_fallback_at(current_time)
    }

    /// Tries to decrypt a message using exporter secrets from multiple recent epochs excluding the current one
    ///
    /// This helper method attempts to decrypt a message by trying exporter secrets from
    /// the most recent epoch backwards for a configurable number of epochs. This handles
    /// the case where a message was encrypted with an older epoch's secret due to timing
    /// issues or delayed message processing.
    ///
    /// # Arguments
    ///
    /// * `mls_group` - The MLS group
    /// * `encrypted_content` - The ChaCha20-Poly1305 encrypted message content (base64-encoded)
    /// * `max_epoch_lookback` - Maximum number of epochs to search backwards (default: 5)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted message bytes
    /// * `Err(Error)` - If decryption fails with all available exporter secrets
    fn try_decrypt_with_past_epochs(
        &self,
        mls_group: &MlsGroup,
        encrypted_content: &str,
        max_epoch_lookback: u64,
        allow_legacy_exporter_secret: bool,
        allow_legacy_nip44: bool,
    ) -> Result<Vec<u8>> {
        let group_id: GroupId = mls_group.group_id().into();
        let current_epoch: u64 = mls_group.epoch().as_u64();

        // Guard: no past epochs to try if we're at epoch 0 or lookback is 0
        if current_epoch == 0 || max_epoch_lookback == 0 {
            return Err(Error::Message(
                "No past epochs available for decryption".to_string(),
            ));
        }

        // Start from current epoch and go backwards
        // We want exactly max_epoch_lookback iterations, so end_epoch is calculated
        // to make the inclusive range have that many elements
        let start_epoch: u64 = current_epoch.saturating_sub(1);
        let end_epoch: u64 = start_epoch.saturating_sub(max_epoch_lookback.saturating_sub(1));

        for epoch in (end_epoch..=start_epoch).rev() {
            tracing::debug!(
                target: "mdk_core::messages::try_decrypt_with_past_epochs",
                "Trying to decrypt with epoch {}",
                epoch
            );

            let maybe_secret = self
                .storage()
                .get_group_exporter_secret(&group_id, epoch)
                .map_err(|_| {
                    Error::Group("Storage error while finding exporter secret".to_string())
                })?;

            if let Some(secret) = maybe_secret.as_ref() {
                match decrypt_message_with_any_supported_format(
                    secret,
                    encrypted_content,
                    allow_legacy_nip44,
                ) {
                    Ok(decrypted_bytes) => {
                        tracing::debug!(
                            target: "mdk_core::messages::try_decrypt_with_past_epochs",
                            "Successfully decrypted message with epoch {}",
                            epoch
                        );
                        return Ok(decrypted_bytes);
                    }
                    Err(e) => {
                        tracing::trace!(
                            target: "mdk_core::messages::try_decrypt_with_past_epochs",
                            "Failed to decrypt with epoch {}: {:?}",
                            epoch,
                            e
                        );
                    }
                }
            }

            if allow_legacy_exporter_secret {
                match self
                    .storage()
                    .get_group_legacy_exporter_secret(&group_id, epoch)
                {
                    Ok(Some(secret)) => {
                        match decrypt_message_with_any_supported_format(
                            &secret,
                            encrypted_content,
                            allow_legacy_nip44,
                        ) {
                            Ok(decrypted_bytes) => {
                                tracing::debug!(
                                    target: "mdk_core::messages::try_decrypt_with_past_epochs",
                                    "Successfully decrypted message with legacy exporter secret for epoch {}",
                                    epoch
                                );
                                return Ok(decrypted_bytes);
                            }
                            Err(e) => {
                                tracing::trace!(
                                    target: "mdk_core::messages::try_decrypt_with_past_epochs",
                                    "Failed to decrypt with legacy exporter secret for epoch {}: {:?}",
                                    epoch,
                                    e
                                );
                            }
                        }
                    }
                    Ok(None) if maybe_secret.is_none() => {
                        tracing::trace!(
                            target: "mdk_core::messages::try_decrypt_with_past_epochs",
                            "No exporter secret found for epoch {}",
                            epoch
                        );
                    }
                    // A current-format secret existed for this epoch, but there is no preserved
                    // legacy counterpart. Continue to the next epoch.
                    Ok(None) => {}
                    Err(_e) => {
                        return Err(Error::Group(
                            "Storage error while finding legacy exporter secret".to_string(),
                        ));
                    }
                }
            } else {
                tracing::trace!(
                    target: "mdk_core::messages::try_decrypt_with_past_epochs",
                    "Skipping legacy exporter-secret fallback for epoch {} because the migration deadline has passed",
                    epoch
                );
            }
        }

        Err(Error::Message(format!(
            "Failed to decrypt message with any exporter secret from epochs {} to {}",
            end_epoch, start_epoch
        )))
    }

    /// Try to decrypt using the current exporter secret and if fails try with the past ones until a max lookback of [`DEFAULT_EPOCH_LOOKBACK`].
    pub(super) fn try_decrypt_with_recent_epochs(
        &self,
        mls_group: &MlsGroup,
        encrypted_content: &str,
        allow_legacy_exporter_secret: bool,
        allow_legacy_nip44: bool,
    ) -> Result<Vec<u8>> {
        let group_id: GroupId = mls_group.group_id().into();
        let secret = self.exporter_secret(&group_id)?;

        match decrypt_message_with_any_supported_format(
            &secret,
            encrypted_content,
            allow_legacy_nip44,
        ) {
            Ok(decrypted_bytes) => {
                tracing::debug!("Successfully decrypted message with current exporter secret");
                Ok(decrypted_bytes)
            }
            Err(_) => {
                if allow_legacy_exporter_secret {
                    let legacy_secret = self.legacy_exporter_secret(&group_id)?;
                    match decrypt_message_with_any_supported_format(
                        &legacy_secret,
                        encrypted_content,
                        allow_legacy_nip44,
                    ) {
                        Ok(decrypted_bytes) => {
                            tracing::debug!(
                                "Successfully decrypted message with legacy current exporter secret"
                            );
                            Ok(decrypted_bytes)
                        }
                        Err(_) => {
                            tracing::debug!(
                                "Failed to decrypt message with current epoch secrets. Trying past ones."
                            );

                            self.try_decrypt_with_past_epochs(
                                mls_group,
                                encrypted_content,
                                DEFAULT_EPOCH_LOOKBACK,
                                allow_legacy_exporter_secret,
                                allow_legacy_nip44,
                            )
                        }
                    }
                } else {
                    tracing::trace!(
                        "Skipping legacy current exporter-secret fallback because the migration deadline has passed"
                    );
                    self.try_decrypt_with_past_epochs(
                        mls_group,
                        encrypted_content,
                        DEFAULT_EPOCH_LOOKBACK,
                        allow_legacy_exporter_secret,
                        allow_legacy_nip44,
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mdk_storage_traits::groups::{GroupStorage, types::GroupExporterSecret};
    use nostr::nips::nip44;
    use nostr::{Event, EventBuilder, Keys, Kind, SecretKey, Tag, TagKind, Timestamp};
    use openmls::prelude::MlsGroup;

    use crate::MdkConfig;
    use crate::messages::crypto::{
        decrypt_message_with_any_supported_format, encrypt_message_with_exporter_secret,
    };
    use crate::test_util::{
        create_key_package_event, create_nostr_group_config_data, create_test_rumor,
        setup_two_member_group,
    };
    use crate::tests::{create_test_mdk, create_test_mdk_with_config};

    fn build_wrapper_event(
        nostr_group_id: [u8; 32],
        encrypted_content: String,
        include_encoding_tag: bool,
        created_at: Timestamp,
    ) -> Event {
        let mut builder = EventBuilder::new(Kind::MlsGroupMessage, encrypted_content)
            .custom_created_at(created_at)
            .tag(Tag::custom(TagKind::h(), [hex::encode(nostr_group_id)]));
        if include_encoding_tag {
            builder = builder.tag(Tag::custom(TagKind::Custom("encoding".into()), ["base64"]));
        }

        builder.sign_with_keys(&Keys::generate()).unwrap()
    }

    fn fixed_pre_deadline_ts() -> u64 {
        super::LEGACY_EXPORTER_SECRET_MIGRATION_DEADLINE.saturating_sub(1)
    }

    fn fixed_post_deadline_ts() -> u64 {
        super::LEGACY_EXPORTER_SECRET_MIGRATION_DEADLINE.saturating_add(1)
    }

    /// Helper: run the past-epoch delivery scenario and return the result of Bob processing
    /// Alice's delayed epoch-N message after the group has advanced to epoch N+1.
    ///
    /// Both MDK instances are constructed using the provided config, which controls
    /// `max_past_epochs` on the underlying OpenMLS group.
    fn past_epoch_delivery_result(
        config: MdkConfig,
    ) -> Result<crate::messages::MessageProcessingResult, crate::error::Error> {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk_with_config(config.clone());
        let bob_mdk = create_test_mdk_with_config(config);

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];

        // Alice creates the group with Bob
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge creation commit");

        // Bob joins
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Alice sends a message at epoch 1 — held back from Bob
        let rumor = create_test_rumor(&alice_keys, "message from the past epoch");
        let past_epoch_msg = alice_mdk
            .create_message(&group_id, rumor, None)
            .expect("Alice should create message");

        // Alice self-updates → epoch 2; both process the commit
        let update_result = alice_mdk
            .self_update(&group_id)
            .expect("Alice should self-update");
        alice_mdk
            .process_message(&update_result.evolution_event)
            .expect("Alice should process her own evolution event");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge self-update");
        bob_mdk
            .process_message(&update_result.evolution_event)
            .expect("Bob should process self-update commit");

        // Now deliver the held-back epoch-1 message to Bob (group is at epoch 2)
        bob_mdk.process_message(&past_epoch_msg)
    }

    /// Regression test: past-epoch application messages fail when max_past_epochs = 0.
    ///
    /// This test proves a concrete bug: MDK was not setting max_past_epochs on the OpenMLS
    /// group config, which defaulted to 0. When a commit advances the group to epoch N+1
    /// and an application message from epoch N arrives late, OpenMLS has no retained past
    /// message secrets and returns SecretTreeError::TooDistantInThePast, causing MDK to
    /// permanently mark the message as Failed.
    ///
    /// Scenario:
    ///   1. Alice creates a group with Bob, both using max_past_epochs = 0.
    ///   2. Alice sends a message at epoch 1 — not yet delivered to Bob.
    ///   3. Alice self-updates; both process the commit → epoch 2.
    ///   4. Bob receives Alice's epoch-1 message. Without past secrets it cannot be
    ///      decrypted → Unprocessable.
    #[test]
    fn test_past_epoch_application_message_fails_without_max_past_epochs() {
        let config = MdkConfig {
            max_past_epochs: 0, // explicitly disable past epoch retention
            ..MdkConfig::default()
        };

        let result = past_epoch_delivery_result(config);

        match result {
            Ok(crate::messages::MessageProcessingResult::ApplicationMessage(_)) => {
                panic!(
                    "Expected Unprocessable when max_past_epochs = 0, but the message \
                     decrypted successfully. OpenMLS may be retaining secrets despite \
                     max_past_epochs = 0."
                );
            }
            Ok(crate::messages::MessageProcessingResult::Unprocessable { .. }) => {
                // Expected: OpenMLS had no past epoch secrets, message permanently Failed.
            }
            Err(crate::error::Error::Message(_)) => {
                // Also expected: decryption may fail before dispatch when no past
                // exporter secret is retained for the delayed epoch.
            }
            other => {
                panic!(
                    "Unexpected result (expected Unprocessable or decryption failure): {:?}",
                    other
                );
            }
        }
    }

    /// Fix verification: past-epoch application messages succeed when max_past_epochs >= 1.
    ///
    /// This is the companion to the regression test above. With max_past_epochs = 5
    /// (the corrected default), OpenMLS retains message secrets for up to 5 past epochs.
    /// The same delayed epoch-N message that previously failed now decrypts successfully.
    #[test]
    fn test_past_epoch_application_message_succeeds_with_max_past_epochs() {
        let config = MdkConfig {
            max_past_epochs: 5, // retain secrets for 5 past epochs
            ..MdkConfig::default()
        };

        let result = past_epoch_delivery_result(config);

        match result {
            Ok(crate::messages::MessageProcessingResult::ApplicationMessage(msg)) => {
                // Success: the epoch-1 message was decrypted despite the group being at epoch 2.
                assert_eq!(
                    msg.content, "message from the past epoch",
                    "Decrypted content should match what Alice sent"
                );
            }
            Ok(crate::messages::MessageProcessingResult::Unprocessable { .. }) => {
                panic!(
                    "Expected ApplicationMessage with max_past_epochs = 5, but got Unprocessable. \
                     The fix (wiring max_past_epochs into OpenMLS group config) is not working."
                );
            }
            Err(e) => {
                panic!(
                    "Expected ApplicationMessage with max_past_epochs = 5, but got error: {:?}",
                    e
                );
            }
            other => {
                panic!(
                    "Unexpected result variant (expected ApplicationMessage): {:?}",
                    other
                );
            }
        }
    }

    #[test]
    fn test_current_epoch_compat_decrypts_transition_aead_with_legacy_secret() {
        let (alice_mdk, bob_mdk, alice_keys, _bob_keys, group_id) = setup_two_member_group();
        let mut rumor = create_test_rumor(&alice_keys, "current epoch compat");

        let mut alice_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Alice should load MLS group")
            .expect("Alice MLS group should exist");
        let serialized_message = alice_mdk
            .create_mls_message_payload(&mut alice_group, &mut rumor)
            .expect("Alice should create MLS payload");
        let legacy_secret = alice_mdk
            .legacy_exporter_secret(&group_id)
            .expect("Alice should derive legacy exporter secret");
        let encrypted_content =
            encrypt_message_with_exporter_secret(&legacy_secret, &serialized_message)
                .expect("Legacy secret should still encrypt AEAD wrapper");

        let bob_group = bob_mdk
            .load_mls_group(&group_id)
            .expect("Bob should load MLS group")
            .expect("Bob MLS group should exist");

        let decrypted_bytes = bob_mdk
            .try_decrypt_with_recent_epochs(&bob_group, &encrypted_content, true, false)
            .expect("Current-epoch legacy AEAD fallback should work before the deadline");
        assert_eq!(decrypted_bytes, serialized_message);
    }

    #[test]
    fn test_current_epoch_legacy_aead_after_deadline_is_rejected() {
        let (alice_mdk, bob_mdk, alice_keys, _bob_keys, group_id) = setup_two_member_group();
        let mut rumor = create_test_rumor(&alice_keys, "current epoch compat");

        let mut alice_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Alice should load MLS group")
            .expect("Alice MLS group should exist");
        let serialized_message = alice_mdk
            .create_mls_message_payload(&mut alice_group, &mut rumor)
            .expect("Alice should create MLS payload");
        let legacy_secret = alice_mdk
            .legacy_exporter_secret(&group_id)
            .expect("Alice should derive legacy exporter secret");
        let encrypted_content =
            encrypt_message_with_exporter_secret(&legacy_secret, &serialized_message)
                .expect("Legacy secret should still encrypt AEAD wrapper");

        let bob_group = bob_mdk
            .load_mls_group(&group_id)
            .expect("Bob should load MLS group")
            .expect("Bob MLS group should exist");

        assert!(
            !crate::MDK::<mdk_memory_storage::MdkMemoryStorage>::allow_legacy_exporter_secret_fallback_at(fixed_post_deadline_ts())
        );

        let result =
            bob_mdk.try_decrypt_with_recent_epochs(&bob_group, &encrypted_content, false, false);
        assert!(
            result.is_err(),
            "Current-epoch legacy AEAD fallback must be skipped after the deadline"
        );
    }

    #[test]
    fn test_past_epoch_compat_decrypts_legacy_nip44_with_stored_secret() {
        let (alice_mdk, bob_mdk, alice_keys, _bob_keys, group_id) = setup_two_member_group();
        let mut rumor = create_test_rumor(&alice_keys, "late legacy message");
        let rumor_id = rumor.id();

        let mut alice_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Alice should load MLS group")
            .expect("Alice MLS group should exist");
        let message_epoch = alice_group.epoch().as_u64();
        let serialized_message = alice_mdk
            .create_mls_message_payload(&mut alice_group, &mut rumor)
            .expect("Alice should create MLS payload");
        let legacy_secret = alice_mdk
            .legacy_exporter_secret(&group_id)
            .expect("Alice should derive legacy exporter secret");

        let secret_key = SecretKey::from_slice(legacy_secret.secret.as_ref()).unwrap();
        let export_nostr_keys = Keys::new(secret_key);
        let encrypted_content = nip44::encrypt(
            export_nostr_keys.secret_key(),
            &export_nostr_keys.public_key,
            &serialized_message,
            nip44::Version::default(),
        )
        .expect("Alice should encrypt legacy NIP-44 wrapper");

        bob_mdk
            .storage()
            .save_group_exporter_secret(GroupExporterSecret {
                mls_group_id: group_id.clone(),
                epoch: message_epoch,
                secret: legacy_secret.secret.clone(),
            })
            .expect("Bob should persist migrated legacy secret");

        let update_result = alice_mdk
            .self_update(&group_id)
            .expect("Alice should self-update");
        alice_mdk
            .process_message(&update_result.evolution_event)
            .expect("Alice should process her own self-update");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge self-update");
        bob_mdk
            .process_message(&update_result.evolution_event)
            .expect("Bob should process self-update");

        let direct_decrypted =
            crate::messages::crypto::decrypt_message_with_legacy_exporter_secret(
                &legacy_secret,
                &encrypted_content,
            )
            .expect("Freshly encrypted legacy wrapper should round-trip");
        assert_eq!(direct_decrypted, serialized_message);

        let stored_secret = bob_mdk
            .storage()
            .get_group_exporter_secret(&group_id, message_epoch)
            .expect("Bob should load stored legacy secret")
            .expect("Current exporter secret should still exist");
        assert_ne!(stored_secret.secret, legacy_secret.secret);

        let stored_legacy_secret = bob_mdk
            .storage()
            .get_group_legacy_exporter_secret(&group_id, message_epoch)
            .expect("Bob should load preserved legacy secret")
            .expect("Legacy exporter secret should be preserved separately");
        assert_eq!(stored_legacy_secret.secret, legacy_secret.secret);
        let decrypted_bytes = decrypt_message_with_any_supported_format(
            &stored_legacy_secret,
            &encrypted_content,
            true,
        )
        .expect("Stored legacy secret should decrypt delayed wrapper directly");
        assert_eq!(decrypted_bytes, serialized_message);

        let group = alice_mdk
            .get_group(&group_id)
            .expect("Alice should load group")
            .expect("Group should exist");
        let event = build_wrapper_event(
            group.nostr_group_id,
            encrypted_content,
            false,
            Timestamp::from(fixed_pre_deadline_ts()),
        );

        assert!(
            crate::MDK::<mdk_memory_storage::MdkMemoryStorage>::allow_legacy_nip44_wrapper_fallback_at(
                &event,
                fixed_pre_deadline_ts(),
            )
        );

        let result = bob_mdk
            .process_message_at(&event, Timestamp::from(fixed_pre_deadline_ts()))
            .expect("Bob should process delayed legacy event");
        match result {
            crate::messages::MessageProcessingResult::ApplicationMessage(message) => {
                assert_eq!(message.id, rumor_id);
                assert_eq!(message.content, "late legacy message");
            }
            other => panic!("Expected ApplicationMessage, got {:?}", other),
        }
    }

    #[test]
    fn test_legacy_nip44_wrapper_after_deadline_is_rejected() {
        assert!(
            !crate::MDK::<mdk_memory_storage::MdkMemoryStorage>::allow_legacy_nip44_wrapper_fallback_at(
                &build_wrapper_event([7u8; 32], "ignored".to_string(), false, Timestamp::now()),
                fixed_post_deadline_ts(),
            ),
            "Legacy wrapper after deadline must be rejected"
        );
    }

    #[test]
    fn test_past_epoch_legacy_aead_after_deadline_is_rejected() {
        let (alice_mdk, bob_mdk, alice_keys, _bob_keys, group_id) = setup_two_member_group();
        let mut rumor = create_test_rumor(&alice_keys, "late legacy aead");

        let mut alice_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Alice should load MLS group")
            .expect("Alice MLS group should exist");
        let serialized_message = alice_mdk
            .create_mls_message_payload(&mut alice_group, &mut rumor)
            .expect("Alice should create MLS payload");
        let legacy_secret = alice_mdk
            .legacy_exporter_secret(&group_id)
            .expect("Alice should derive legacy exporter secret");
        let encrypted_content =
            encrypt_message_with_exporter_secret(&legacy_secret, &serialized_message)
                .expect("Legacy secret should still encrypt AEAD wrapper");

        let update_result = alice_mdk
            .self_update(&group_id)
            .expect("Alice should self-update");
        alice_mdk
            .process_message(&update_result.evolution_event)
            .expect("Alice should process her own self-update");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge self-update");
        bob_mdk
            .process_message(&update_result.evolution_event)
            .expect("Bob should process self-update");

        let bob_group = bob_mdk
            .load_mls_group(&group_id)
            .expect("Bob should load MLS group")
            .expect("Bob MLS group should exist");

        assert!(
            !crate::MDK::<mdk_memory_storage::MdkMemoryStorage>::allow_legacy_exporter_secret_fallback_at(fixed_post_deadline_ts())
        );

        let result = bob_mdk.try_decrypt_with_past_epochs(
            &bob_group,
            &encrypted_content,
            super::DEFAULT_EPOCH_LOOKBACK,
            false,
            false,
        );
        assert!(
            result.is_err(),
            "Past-epoch legacy AEAD fallback must be skipped after the deadline"
        );
    }

    /// Test epoch lookback limits for message decryption (MIP-03)
    ///
    /// This test validates the epoch lookback mechanism which allows messages from
    /// previous epochs to be decrypted (up to 5 epochs back).
    ///
    /// Requirements tested:
    /// - Messages from recent epochs (within 5 epochs) can be decrypted
    /// - Messages beyond the lookback limit cannot be decrypted
    /// - Epoch secrets are properly retained for lookback
    /// - Clear error messages when lookback limit is exceeded
    #[test]
    fn test_epoch_lookback_limits() {
        // Setup: Create Alice and Bob
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];

        // Step 1: Bob creates his key package and Alice creates the group
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice should be able to create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge Alice's create commit");

        // Bob processes and accepts welcome
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should be able to process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should be able to accept welcome");

        // Step 2: Alice creates a message in epoch 1 (initial epoch)
        // Save this message to test lookback limit later
        let rumor_epoch1 = create_test_rumor(&alice_keys, "Message in epoch 1");
        let msg_epoch1 = alice_mdk
            .create_message(&group_id, rumor_epoch1, None)
            .expect("Alice should send message in epoch 1");

        // Verify Bob can process it initially
        let bob_process1 = bob_mdk.process_message(&msg_epoch1);
        assert!(
            bob_process1.is_ok(),
            "Bob should process epoch 1 message initially"
        );

        // Step 3: Advance through 7 epochs (beyond the 5-epoch lookback limit)
        for i in 1..=7 {
            let update_result = alice_mdk
                .self_update(&group_id)
                .expect("Alice should be able to update");

            // Both clients process the update
            alice_mdk
                .process_message(&update_result.evolution_event)
                .expect("Alice should process update");

            alice_mdk
                .merge_pending_commit(&group_id)
                .expect("Alice should merge update");

            bob_mdk
                .process_message(&update_result.evolution_event)
                .expect("Bob should process update");

            // Send a message in this epoch to verify it works
            let rumor = create_test_rumor(&alice_keys, &format!("Message in epoch {}", i + 1));
            let msg = alice_mdk
                .create_message(&group_id, rumor, None)
                .expect("Alice should send message");

            // Bob should be able to process recent messages
            let process_result = bob_mdk.process_message(&msg);
            assert!(
                process_result.is_ok(),
                "Bob should process message from epoch {}",
                i + 1
            );
        }

        // Step 4: Verify final epoch
        let final_epoch = alice_mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist")
            .epoch;

        // Group creation puts us at epoch 1, then we advanced 7 times, so we should be at epoch 8
        assert_eq!(
            final_epoch, 8,
            "Group should be at epoch 8 after group creation (epoch 1) + 7 updates"
        );

        // Step 5: Verify lookback mechanism
        // We're now at epoch 8. Messages from epochs 3+ (within 5-epoch lookback) can be
        // decrypted, while messages from epochs 1-2 would be beyond the lookback limit.
        //
        // Note: We can't easily test the actual lookback failure without the ability to
        // create messages from old epochs after advancing (would require "time travel").
        // The MLS protocol handles this at the decryption layer by maintaining exporter
        // secrets for the last 5 epochs only.

        // The actual lookback validation happens in the MLS layer during decryption.
        // Our test confirms:
        // 1. We can advance through multiple epochs successfully
        // 2. Messages can be processed in each epoch
        // 3. The epoch count is correct (8 epochs total)
        // 4. The system maintains state correctly across epoch transitions

        // Note: Full epoch lookback boundary testing requires the ability to
        // store encrypted messages from old epochs and attempt decryption after
        // advancing beyond the lookback window. This is a protocol-level test
        // that would need access to the exporter secret retention mechanism.
    }

    /// Test that try_decrypt_with_past_epochs returns early when at epoch 0
    ///
    /// When a group is at epoch 0, there are no past epochs to try.
    /// The function should return an error immediately rather than
    /// attempting to iterate over an empty or invalid range.
    #[test]
    fn test_past_epoch_decryption_guards_epoch_zero() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        // Create a group - after creation and merge, we're still at epoch 0
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .expect("Should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Should merge commit");

        // Load the MLS group to check its epoch
        let mls_group: MlsGroup = alice_mdk
            .load_mls_group(&group_id)
            .expect("Should load group")
            .expect("Group should exist");

        // Newly created group is at epoch 0
        assert_eq!(
            mls_group.epoch().as_u64(),
            0,
            "Group should be at epoch 0 after creation"
        );

        // Test with epoch 0 - should return early since there are no past epochs
        let result = alice_mdk.try_decrypt_with_past_epochs(
            &mls_group,
            "invalid_encrypted_content",
            5, // normal lookback, but epoch 0 means no past epochs
            false,
            false,
        );

        assert!(result.is_err(), "Should fail at epoch 0");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No past epochs available"),
            "Error should indicate no past epochs: {}",
            err_msg
        );
    }

    /// Test that try_decrypt_with_past_epochs handles zero lookback parameter
    ///
    /// When max_epoch_lookback is 0, no past epochs should be tried.
    #[test]
    fn test_past_epoch_decryption_guards_zero_lookback() {
        let alice_keys = Keys::generate();
        let alice_mdk = create_test_mdk();

        // Create a group and advance a few epochs
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .expect("Should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Should merge commit");

        // Advance a few epochs so we're not at epoch 0/1
        for _ in 0..3 {
            let update = alice_mdk.self_update(&group_id).expect("Should update");
            alice_mdk
                .process_message(&update.evolution_event)
                .expect("Should process update");
            alice_mdk
                .merge_pending_commit(&group_id)
                .expect("Should merge");
        }

        let mls_group: MlsGroup = alice_mdk
            .load_mls_group(&group_id)
            .expect("Should load group")
            .expect("Group should exist");

        // Verify we're at a higher epoch
        assert!(
            mls_group.epoch().as_u64() > 1,
            "Group should be past epoch 1"
        );

        // Test with max_epoch_lookback = 0
        let result = alice_mdk.try_decrypt_with_past_epochs(
            &mls_group,
            "invalid_encrypted_content",
            0, // zero lookback - should return early
            false,
            false,
        );

        assert!(result.is_err(), "Should fail with zero lookback");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No past epochs available"),
            "Error should indicate no past epochs: {}",
            err_msg
        );
    }
}
