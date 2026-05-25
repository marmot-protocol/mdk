//! Proposal message processing
//!
//! This module handles processing of MLS proposal messages.

use mdk_storage_traits::messages::types as message_types;
use mdk_storage_traits::{GroupId, MdkStorageProvider};
use nostr::Event;
use openmls::prelude::{
    BasicCredential, LeafNodeIndex, MlsGroup, Proposal, QueuedProposal, Sender,
};
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as TlsSerialize;

use crate::MDK;
use crate::error::Error;
use crate::groups::UpdateGroupResult;

use super::{MessageProcessingResult, Result};

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Processes a proposal message from a group member
    ///
    /// This internal function handles MLS proposal messages according to the Marmot protocol:
    ///
    /// - **Add/Remove member proposals**: Always stored as pending for admin approval via manual commit
    /// - **Self-remove (leave) proposals**: Legacy Remove-based: auto-committed by admins, pending for non-admins
    /// - **SelfRemove proposals**: Auto-committed by any member (new protocol, MLS Extensions draft)
    /// - **Extension/ciphersuite proposals**: Ignored with warning (admins should create commits directly)
    /// - **Update proposals**: Out of scope (see issue #59)
    ///
    /// # Arguments
    ///
    /// * `mls_group` - The MLS group to process the proposal for
    /// * `event` - The wrapper Nostr event containing the encrypted proposal
    /// * `staged_proposal` - The validated MLS proposal to process
    ///
    /// # Returns
    ///
    /// * `Ok(MessageProcessingResult::Proposal)` - Self-remove auto-committed by admin
    /// * `Ok(MessageProcessingResult::PendingProposal)` - Proposal stored for admin approval
    /// * `Ok(MessageProcessingResult::IgnoredProposal)` - Proposal ignored (extensions, etc.)
    /// * `Err(Error)` - If proposal processing fails or sender is not a member
    pub(super) fn process_proposal(
        &self,
        mls_group: &mut MlsGroup,
        event: &Event,
        staged_proposal: QueuedProposal,
    ) -> Result<MessageProcessingResult> {
        match staged_proposal.sender() {
            Sender::Member(sender_leaf_index) => {
                let member = mls_group.member_at(*sender_leaf_index);

                match member {
                    Some(_member) => {
                        let group_id: GroupId = mls_group.group_id().into();
                        let own_leaf = mls_group.own_leaf().ok_or(Error::OwnLeafNotFound)?;
                        let receiver_is_admin = self.is_leaf_node_admin(&group_id, own_leaf)?;

                        // Determine proposal type and how to handle it
                        match staged_proposal.proposal() {
                            Proposal::Add(_) => {
                                // Add proposals: always store as pending for admin approval
                                self.store_pending_proposal(
                                    mls_group,
                                    event,
                                    staged_proposal,
                                    &group_id,
                                )?;

                                tracing::debug!(
                                    target: "mdk_core::messages::process_proposal",
                                    "Stored Add proposal as pending for admin approval"
                                );

                                Ok(MessageProcessingResult::PendingProposal {
                                    mls_group_id: group_id,
                                })
                            }
                            Proposal::Remove(remove_proposal) => {
                                // Check if this is a self-remove (leave) proposal
                                let removed_leaf_index = remove_proposal.removed();
                                let is_self_remove = *sender_leaf_index == removed_leaf_index;

                                if is_self_remove && receiver_is_admin {
                                    if let Some(result) = self.validate_self_remove_allowed(
                                        mls_group,
                                        event,
                                        &group_id,
                                        *sender_leaf_index,
                                        "legacy Remove(self)",
                                    )? {
                                        return Ok(result);
                                    }

                                    // OpenMLS returns a QueuedProposal here, but it only enters
                                    // the proposal store when store_pending_proposal is called.
                                    // The admin path intentionally drops the queued legacy
                                    // proposal and builds an equivalent admin-authored removal,
                                    // avoiding the SelfRemove-only pending-store filter.
                                    self.auto_commit_legacy_self_remove(
                                        mls_group,
                                        event,
                                        removed_leaf_index,
                                        &group_id,
                                    )
                                } else {
                                    // Either not self-remove, or receiver is not admin
                                    // Store as pending for admin approval
                                    self.store_pending_proposal(
                                        mls_group,
                                        event,
                                        staged_proposal,
                                        &group_id,
                                    )?;

                                    if is_self_remove {
                                        tracing::debug!(
                                            target: "mdk_core::messages::process_proposal",
                                            "Non-admin receiver stored self-remove proposal as pending"
                                        );
                                    } else {
                                        tracing::debug!(
                                            target: "mdk_core::messages::process_proposal",
                                            "Stored Remove proposal as pending for admin approval"
                                        );
                                    }

                                    Ok(MessageProcessingResult::PendingProposal {
                                        mls_group_id: group_id,
                                    })
                                }
                            }
                            Proposal::Update(_) => {
                                // Update proposals (self key rotation) - out of scope for this issue
                                // See: https://github.com/marmot-protocol/mdk/issues/59
                                tracing::warn!(
                                    target: "mdk_core::messages::process_proposal",
                                    "Ignoring Update proposal - self-update handling not yet implemented (see issue #59)"
                                );

                                self.mark_processed(event, &group_id, mls_group.epoch().as_u64())?;

                                Ok(MessageProcessingResult::IgnoredProposal {
                                    mls_group_id: group_id,
                                    reason: "Update proposals not yet supported (see issue #59)"
                                        .to_string(),
                                })
                            }
                            Proposal::GroupContextExtensions(_) => {
                                // Extension proposals should be ignored - admins create commits directly
                                tracing::warn!(
                                    target: "mdk_core::messages::process_proposal",
                                    "Ignoring GroupContextExtensions proposal - admins should create commits directly"
                                );

                                self.mark_processed(event, &group_id, mls_group.epoch().as_u64())?;

                                Ok(MessageProcessingResult::IgnoredProposal {
                                    mls_group_id: group_id,
                                    reason: "Extension proposals not allowed - admins should create commits directly".to_string(),
                                })
                            }
                            Proposal::SelfRemove => {
                                if let Some(result) = self.validate_self_remove_allowed(
                                    mls_group,
                                    event,
                                    &group_id,
                                    *sender_leaf_index,
                                    "SelfRemove",
                                )? {
                                    return Ok(result);
                                }

                                // Non-admin SelfRemove: any member can commit, so auto-commit.
                                self.auto_commit_self_remove_proposal(
                                    mls_group,
                                    event,
                                    staged_proposal,
                                    &group_id,
                                )
                            }
                            _ => {
                                // Other proposal types (PreSharedKey, ReInit, ExternalInit, etc.)
                                tracing::warn!(
                                    target: "mdk_core::messages::process_proposal",
                                    "Ignoring unsupported proposal type"
                                );

                                self.mark_processed(event, &group_id, mls_group.epoch().as_u64())?;

                                Ok(MessageProcessingResult::IgnoredProposal {
                                    mls_group_id: group_id,
                                    reason: "Unsupported proposal type".to_string(),
                                })
                            }
                        }
                    }
                    None => {
                        tracing::warn!(target: "mdk_core::messages::process_mls_message", "Received proposal from non-member.");
                        Err(Error::MessageFromNonMember)
                    }
                }
            }
            Sender::External(_) => {
                // TODO: FUTURE Handle external proposals from external proposal extensions
                Err(Error::NotImplemented("Processing external proposals from external proposal extensions is not supported".to_string()))
            }
            Sender::NewMemberCommit => {
                // TODO: FUTURE Handle new member from external member commits.
                Err(Error::NotImplemented(
                    "Processing external proposals for new member commits is not supported"
                        .to_string(),
                ))
            }
            Sender::NewMemberProposal => {
                // TODO: FUTURE Handle new member from external member proposals.
                Err(Error::NotImplemented(
                    "Processing external proposals for new member proposals is not supported"
                        .to_string(),
                ))
            }
        }
    }

    /// Stores a proposal as pending and marks the event as processed
    ///
    /// This stores the proposal in the MLS group's pending proposal queue
    /// for later commit by an admin, and marks the wrapper event as processed
    /// to prevent reprocessing.
    pub(super) fn store_pending_proposal(
        &self,
        mls_group: &mut MlsGroup,
        event: &Event,
        staged_proposal: QueuedProposal,
        group_id: &GroupId,
    ) -> Result<()> {
        mls_group
            .store_pending_proposal(self.provider.storage(), staged_proposal)
            .map_err(|_e| Error::Message("Failed to store pending proposal".to_string()))?;

        self.mark_processed(event, group_id, mls_group.epoch().as_u64())
    }

    /// Marks an event as processed to prevent reprocessing
    ///
    /// # Arguments
    ///
    /// * `event` - The wrapper Nostr event to mark as processed
    /// * `mls_group_id` - The MLS group ID for context
    /// * `epoch` - The current epoch from the MLS group
    pub(super) fn mark_processed(
        &self,
        event: &Event,
        mls_group_id: &GroupId,
        epoch: u64,
    ) -> Result<()> {
        let processed_message = super::create_processed_message_record(
            event.id,
            None,
            Some(epoch),
            Some(mls_group_id.clone()),
            message_types::ProcessedMessageState::Processed,
            None,
        );

        self.save_processed_message_record(processed_message)
    }

    /// Validates shared MIP-03 self-remove constraints before auto-commit.
    fn validate_self_remove_allowed(
        &self,
        mls_group: &MlsGroup,
        event: &Event,
        group_id: &GroupId,
        sender_leaf_index: LeafNodeIndex,
        proposal_label: &str,
    ) -> Result<Option<MessageProcessingResult>> {
        // Per MIP-03, admins MUST NOT leave via SelfRemove-style proposals.
        // They must self-demote first so the admin set changes explicitly.
        let sender_member = mls_group
            .member_at(sender_leaf_index)
            .ok_or(Error::MessageFromNonMember)?;
        let sender_cred = BasicCredential::try_from(sender_member.credential)?;
        let sender_pubkey = self.parse_credential_identity(sender_cred.identity())?;
        let group_data = crate::extension::NostrGroupDataExtension::from_group(mls_group)?;

        if group_data.admins.contains(&sender_pubkey) {
            tracing::warn!(
                target: "mdk_core::messages::process_proposal",
                "Rejecting {} from admin — must self-demote first",
                proposal_label
            );
            self.mark_processed(event, group_id, mls_group.epoch().as_u64())?;
            return Ok(Some(MessageProcessingResult::IgnoredProposal {
                mls_group_id: group_id.clone(),
                reason: format!("{proposal_label} rejected: sender is an admin"),
            }));
        }

        // Check the current admin set against live members after this sender's
        // leaf departs. If no active admin would remain, the leave is invalid
        // and should not be stored for a later commit.
        if let Err(e) = self.validate_admin_depletion(mls_group, &[sender_leaf_index]) {
            tracing::warn!(
                target: "mdk_core::messages::process_proposal",
                "Rejecting {}: {}",
                proposal_label,
                e
            );
            self.mark_processed(event, group_id, mls_group.epoch().as_u64())?;
            return Ok(Some(MessageProcessingResult::IgnoredProposal {
                mls_group_id: group_id.clone(),
                reason: format!("{proposal_label} rejected: {e}"),
            }));
        }

        Ok(None)
    }

    /// Stores a `SelfRemove` proposal and immediately auto-commits it.
    ///
    /// Uses the commit builder with a SelfRemove-only filter to ensure no other
    /// pending proposals (Add, Remove, etc.) are accidentally included in the
    /// commit. This prevents non-admin committers from creating commits that
    /// violate MIP-03 authorization rules.
    pub(super) fn auto_commit_self_remove_proposal(
        &self,
        mls_group: &mut MlsGroup,
        event: &Event,
        staged_proposal: QueuedProposal,
        group_id: &GroupId,
    ) -> Result<MessageProcessingResult> {
        mls_group
            .store_pending_proposal(self.provider.storage(), staged_proposal)
            .map_err(|_e| Error::Message("Failed to store pending proposal".to_string()))?;

        let mls_signer = self.load_mls_signer(mls_group)?;

        // Build a commit containing ONLY SelfRemove proposals from the pending store.
        // Other pending proposals (Add, Remove, etc.) are excluded to prevent
        // non-admin committers from bundling unauthorized proposals.
        let (commit_message, _welcomes, _group_info) = mls_group
            .commit_builder()
            .consume_proposal_store(true)
            .load_psks(self.provider.storage())
            .map_err(|e| Error::Group(e.to_string()))?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &mls_signer,
                |queued| matches!(queued.proposal(), Proposal::SelfRemove),
            )
            .map_err(|e| Error::Group(e.to_string()))?
            .stage_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?
            .into_contents();

        let serialized_commit_message = commit_message
            .tls_serialize_detached()
            .map_err(|_e| Error::Group("Failed to serialize commit message".to_string()))?;

        let commit_event = self.build_message_event(group_id, serialized_commit_message, None)?;

        // Record the epoch after staging the generated commit. Rollback
        // invalidation treats this proposal as part of the staged epoch branch.
        self.mark_processed(event, group_id, mls_group.epoch().as_u64())?;

        tracing::debug!(
            target: "mdk_core::messages::process_proposal",
            "Auto-committed self-remove proposal"
        );

        Ok(MessageProcessingResult::Proposal(UpdateGroupResult {
            evolution_event: commit_event,
            welcome_rumors: None,
            mls_group_id: group_id.clone(),
        }))
    }

    /// Auto-commits a legacy `Remove(self)` leave proposal received by an admin.
    ///
    /// The original proposal is already validated before this method is called.
    /// Unlike `SelfRemove`, legacy `Remove` is not committable by arbitrary
    /// non-admin receivers, so the admin commits an equivalent removal directly
    /// instead of routing it through the SelfRemove-only proposal-store filter.
    pub(super) fn auto_commit_legacy_self_remove(
        &self,
        mls_group: &mut MlsGroup,
        event: &Event,
        removed_leaf_index: LeafNodeIndex,
        group_id: &GroupId,
    ) -> Result<MessageProcessingResult> {
        let mls_signer = self.load_mls_signer(mls_group)?;

        let (commit_message, _welcomes, _group_info) = mls_group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_removals([removed_leaf_index])
            .load_psks(self.provider.storage())
            .map_err(|e| Error::Group(e.to_string()))?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &mls_signer,
                |_| true,
            )
            .map_err(|e| Error::Group(e.to_string()))?
            .stage_commit(&self.provider)
            .map_err(|e| Error::Group(e.to_string()))?
            .into_contents();

        let serialized_commit_message = commit_message
            .tls_serialize_detached()
            .map_err(|_e| Error::Group("Failed to serialize commit message".to_string()))?;

        let commit_event = self.build_message_event(group_id, serialized_commit_message, None)?;

        // Record the epoch after staging the generated commit. Rollback
        // invalidation treats this proposal as part of the staged epoch branch.
        self.mark_processed(event, group_id, mls_group.epoch().as_u64())?;

        tracing::debug!(
            target: "mdk_core::messages::process_proposal",
            "Auto-committed legacy self-remove proposal"
        );

        Ok(MessageProcessingResult::Proposal(UpdateGroupResult {
            evolution_event: commit_event,
            welcome_rumors: None,
            mls_group_id: group_id.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use nostr::Keys;
    use openmls::prelude::{
        MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
        MlsGroupJoinConfig, ProposalType, SenderRatchetConfiguration,
    };
    use tls_codec::Serialize as TlsSerialize;

    use crate::messages::MessageProcessingResult;
    use crate::test_util::{
        create_key_package_event, create_legacy_key_package_event, create_nostr_group_config_data,
    };
    use crate::tests::create_test_mdk;

    /// Tests that self-leave proposals are auto-committed when processed by an admin.
    /// Per the Marmot protocol, admins should auto-commit self-leave proposals.
    #[test]
    fn test_self_leave_proposal_auto_committed_by_admin() {
        // Setup: Alice (admin), Bob (non-admin member)
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

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
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome = &create_result.welcome_rumors[0];
        let bob_welcome_preview = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome_preview)
            .expect("Bob should accept welcome");

        // Bob leaves the group (creates a leave proposal)
        let bob_leave_result = bob_mdk
            .leave_group(&group_id)
            .expect("Bob should be able to leave");

        // Alice (admin) processes Bob's leave proposal
        // This should auto-commit and return Proposal variant
        let process_result = alice_mdk
            .process_message(&bob_leave_result.evolution_event)
            .expect("Alice should process Bob's leave");

        // Verify it returns Proposal (indicating auto-commit happened)
        assert!(
            matches!(process_result, MessageProcessingResult::Proposal(_)),
            "Admin processing self-leave should return Proposal (auto-committed), got: {:?}",
            process_result
        );

        // Extract the commit event from the result
        let _commit_event = match process_result {
            MessageProcessingResult::Proposal(update_result) => update_result.evolution_event,
            _ => panic!("Expected Proposal variant"),
        };

        // The pending proposal is cleared after merge_pending_commit is called
        // (which happens after the commit is published to relays)
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Should merge pending commit");

        // Verify no pending proposals remain after merge
        let pending = alice_mdk
            .pending_removed_members_pubkeys(&group_id)
            .expect("Should get pending");
        assert!(pending.is_empty(), "No pending removals after merge");
    }

    /// Tests that SelfRemove proposals are auto-committed by any member, including non-admins.
    ///
    /// With SelfRemove (new protocol), any member can commit the proposal — not just admins.
    /// This is the key behavioral difference from the legacy Remove-based self-leave.
    #[test]
    fn test_self_remove_proposal_auto_committed_by_non_admin() {
        // Setup: Alice (admin), Bob (non-admin), Charlie (non-admin)
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package, charlie_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob and Charlie join
        let bob_welcome = &create_result.welcome_rumors[0];
        let charlie_welcome = &create_result.welcome_rumors[1];

        let bob_welcome_preview = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome_preview)
            .expect("Bob should accept welcome");

        let charlie_welcome_preview = charlie_mdk
            .process_welcome(&nostr::EventId::all_zeros(), charlie_welcome)
            .expect("Charlie should process welcome");
        charlie_mdk
            .accept_welcome(&charlie_welcome_preview)
            .expect("Charlie should accept welcome");

        // Bob leaves (sends SelfRemove proposal)
        let bob_leave_result = bob_mdk.leave_group(&group_id).expect("Bob should leave");

        // Charlie (non-admin) processes Bob's SelfRemove proposal
        // With SelfRemove, any member auto-commits — no admin required
        let process_result = charlie_mdk
            .process_message(&bob_leave_result.evolution_event)
            .expect("Charlie should process Bob's SelfRemove");

        assert!(
            matches!(process_result, MessageProcessingResult::Proposal(_)),
            "Non-admin processing SelfRemove should auto-commit, got: {:?}",
            process_result
        );
    }

    /// Tests that admins are blocked from calling leave_group.
    ///
    /// Per MIP-03, admins MUST self-demote before sending a SelfRemove.
    /// leave_group enforces this on the sending side.
    #[test]
    fn test_admin_leave_group_rejected() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key()];

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
            .expect("Alice should merge commit");

        // Alice (admin) tries to leave without self-demoting — should fail
        let result = alice_mdk.leave_group(&group_id);
        assert!(
            result.is_err(),
            "Admin should not be able to leave without self-demoting admin status"
        );
        assert!(
            result.unwrap_err().to_string().contains("self-demote"),
            "Error should mention self-demotion"
        );
    }

    /// Tests that the receiving side rejects SelfRemove from an admin sender.
    ///
    /// Simulates a non-compliant client: an admin bypasses the sending-side check
    /// and sends a SelfRemove without self-demoting. The receiver sees the sender
    /// is in admin_pubkeys and rejects the proposal per MIP-03.
    #[test]
    fn test_receiving_side_rejects_admin_self_remove() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Alice is the sole admin
        let admins = vec![alice_keys.public_key()];

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
            .expect("Alice should merge commit");

        // create_group returns welcomes in invitee order; Bob's KeyPackage was first.
        let bob_preview = bob_mdk
            .process_welcome(
                &nostr::EventId::all_zeros(),
                &create_result.welcome_rumors[0],
            )
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_preview)
            .expect("Bob should accept welcome");

        // Simulate non-compliant client: Alice (admin) sends SelfRemove
        // by bypassing leave_group's admin check and using internal APIs.
        let mut mls_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("load group")
            .expect("group exists");

        let signer = alice_mdk.load_mls_signer(&mls_group).expect("load signer");

        // Temporarily switch to plaintext for SelfRemove
        let plaintext_config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .build();

        mls_group
            .set_configuration(alice_mdk.storage(), &plaintext_config)
            .expect("switch config");

        let leave_msg = mls_group
            .leave_group_via_self_remove(&alice_mdk.provider, &signer)
            .expect("SelfRemove should succeed at MLS level");

        // Restore config
        let ciphertext_config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .build();

        let _ = mls_group.set_configuration(alice_mdk.storage(), &ciphertext_config);

        let serialized = leave_msg.tls_serialize_detached().expect("serialize");

        let event = alice_mdk
            .build_message_event(&group_id, serialized, None)
            .expect("build event");

        // Bob processes Alice's SelfRemove — should reject because Alice is admin
        let result = bob_mdk
            .process_message(&event)
            .expect("Bob should process without panic");

        assert!(
            matches!(
                &result,
                MessageProcessingResult::IgnoredProposal { reason, .. }
                if reason.contains("sender is an admin")
            ),
            "Receiver should reject SelfRemove from admin, got: {:?}",
            result
        );
    }

    /// Tests that the receiving side rejects legacy Remove(self) from an
    /// admin sender even when another admin receives the proposal.
    #[test]
    fn test_receiving_side_rejects_admin_legacy_remove_self() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let legacy_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let legacy_mdk = create_test_mdk();

        // Alice and Bob are admins. The legacy invitee forces the group to
        // omit SelfRemove from RequiredCapabilities so this exercises the
        // legacy Remove(self) path.
        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let legacy_key_package = create_legacy_key_package_event(&legacy_mdk, &legacy_keys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package, legacy_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice should create mixed group");
        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        let bob_preview = bob_mdk
            .process_welcome(
                &nostr::EventId::all_zeros(),
                &create_result.welcome_rumors[0],
            )
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_preview)
            .expect("Bob should accept welcome");

        let required_proposals = bob_mdk
            .group_required_proposals(&group_id)
            .expect("Bob reads required proposals");
        assert!(
            !required_proposals.contains(&ProposalType::SelfRemove),
            "mixed group must not require SelfRemove before legacy Remove(self)"
        );

        // Simulate non-compliant client: Alice (admin) sends legacy
        // Remove(self) by bypassing leave_group's admin check and using
        // OpenMLS directly.
        let mut mls_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("load group")
            .expect("group exists");
        let signer = alice_mdk.load_mls_signer(&mls_group).expect("load signer");
        let leave_msg = mls_group
            .leave_group(&alice_mdk.provider, &signer)
            .expect("legacy Remove(self) should succeed at MLS level");
        let serialized = leave_msg.tls_serialize_detached().expect("serialize");
        let event = alice_mdk
            .build_message_event(&group_id, serialized, None)
            .expect("build event");

        let result = bob_mdk
            .process_message(&event)
            .expect("Bob should process without panic");

        assert!(
            matches!(
                &result,
                MessageProcessingResult::IgnoredProposal { reason, .. }
                if reason.contains("sender is an admin")
            ),
            "Receiver should reject legacy Remove(self) from admin, got: {:?}",
            result
        );
    }

    /// Test that self-update commits from non-admin members are ALLOWED (Issue #44, #59)
    ///
    /// Per the Marmot protocol specification, any member can create a self-update
    /// commit to rotate their own key material. This is different from add/remove
    /// commits which require admin privileges.
    ///
    /// Scenario:
    /// 1. Alice (admin) creates a group with Charlie (non-admin member)
    /// 2. Charlie creates a self-update commit
    /// 3. Alice processes Charlie's commit successfully
    #[test]
    fn test_self_update_commit_from_non_admin_is_allowed() {
        // Setup: Alice (admin) and Charlie (non-admin member)
        let alice_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        // Create key package for Charlie
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        // Alice creates the group with Charlie as a non-admin member
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![charlie_key_package],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Charlie joins the group via welcome message
        let charlie_welcome_rumor = &create_result.welcome_rumors[0];
        let charlie_welcome = charlie_mdk
            .process_welcome(&nostr::EventId::all_zeros(), charlie_welcome_rumor)
            .expect("Charlie should process welcome");
        charlie_mdk
            .accept_welcome(&charlie_welcome)
            .expect("Charlie should accept welcome");

        // Verify: Charlie is NOT an admin
        let group_state = charlie_mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert!(
            !group_state
                .admin_pubkeys
                .contains(&charlie_keys.public_key()),
            "Charlie should NOT be an admin"
        );

        // Charlie creates a self-update commit (allowed for any member)
        let charlie_update_result = charlie_mdk
            .self_update(&group_id)
            .expect("Charlie can create self-update commit");

        // Get the commit event that Charlie would broadcast
        let charlie_commit_event = charlie_update_result.evolution_event;

        // Alice tries to process Charlie's self-update commit
        // This should SUCCEED because self-update commits are allowed from any member
        let result = alice_mdk.process_message(&charlie_commit_event);

        assert!(
            result.is_ok(),
            "Self-update commit from non-admin should succeed, got error: {:?}",
            result.err()
        );

        // Verify the result is a Commit
        assert!(
            matches!(result.unwrap(), MessageProcessingResult::Commit { .. }),
            "Result should be a Commit"
        );
    }

    /// Test that non-admin trying to update group extensions fails at client level
    ///
    /// This verifies the client-side check prevents non-admins from creating
    /// extension update commits. The server-side check in `is_pure_self_update_commit`
    /// provides defense-in-depth for malformed messages.
    #[test]
    fn test_non_admin_extension_update_rejected_at_client() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group with Bob
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges and Bob joins
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Bob (non-admin) tries to update group extensions
        let update =
            crate::groups::NostrGroupDataUpdate::new().name("Hacked Group Name".to_string());
        let result = bob_mdk.update_group_data(&group_id, update);

        assert!(
            matches!(result, Err(crate::Error::NotAdmin)),
            "Error should be typed admin permission denial, got: {:?}",
            result
        );
    }

    /// Marmot-security #106: a non-admin's Add proposal MUST NOT ride into an
    /// admin's unrelated commit.
    ///
    /// Bob (non-admin) proposes Add(Mallory). Alice (admin) processes the
    /// proposal — pre-fix it sat in the OpenMLS pending-proposal store. Alice
    /// then renames the group; pre-fix, the rename commit consumes the whole
    /// proposal store with `|_| true`, smuggling Bob's Add into Alice's
    /// admin-signed commit and adding Mallory group-wide.
    ///
    /// Post-fix: Alice's rename commit MUST exclude Bob's unauthorized Add,
    /// and Mallory MUST NOT become a member on either Alice's or Carol's side.
    #[test]
    fn ctf_nonadmin_add_proposal_smuggled_into_admin_commit() {
        use crate::groups::NostrGroupDataUpdate;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let carol_keys = Keys::generate();
        let mallory_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let carol_mdk = create_test_mdk();
        let mallory_mdk = create_test_mdk();

        // Only Alice is admin.
        let admins = vec![alice_keys.public_key()];
        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);
        let carol_kp = create_key_package_event(&carol_mdk, &carol_keys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_kp, carol_kp],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice should create group");
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice merges initial commit");

        for (mdk, idx) in [(&bob_mdk, 0usize), (&carol_mdk, 1usize)] {
            let w = mdk
                .process_welcome(
                    &nostr::EventId::all_zeros(),
                    &create_result.welcome_rumors[idx],
                )
                .expect("process welcome");
            mdk.accept_welcome(&w).expect("accept welcome");
        }

        let before = alice_mdk.get_members(&group_id).expect("members");
        assert!(!before.contains(&mallory_keys.public_key()));
        assert_eq!(before.len(), 3);

        // ATTACK: Bob (non-admin) crafts an Add proposal for outsider Mallory
        // and publishes it. Bob reaches around MDK's API to call OpenMLS
        // directly, exactly as a lightly modified client would.
        let mallory_kp_event = create_key_package_event(&mallory_mdk, &mallory_keys);
        let mallory_kp = bob_mdk
            .parse_key_package(&mallory_kp_event)
            .expect("parse Mallory KeyPackage");
        let mut bob_group = bob_mdk
            .load_mls_group(&group_id)
            .expect("load")
            .expect("exists");
        let bob_signer = bob_mdk.load_mls_signer(&bob_group).expect("signer");
        let (proposal_msg, _ref) = bob_group
            .propose_add_member(&bob_mdk.provider, &bob_signer, &mallory_kp)
            .expect("Bob crafts Add proposal");
        let serialized = proposal_msg.tls_serialize_detached().expect("serialize");
        let proposal_event = bob_mdk
            .build_message_event(&group_id, serialized, None)
            .expect("wrap proposal");

        // Alice and Carol both store Bob's proposal as pending.
        let res = alice_mdk
            .process_message(&proposal_event)
            .expect("Alice processes");
        assert!(matches!(
            res,
            MessageProcessingResult::PendingProposal { .. }
        ));
        carol_mdk
            .process_message(&proposal_event)
            .expect("Carol processes");

        // Alice does an UNRELATED admin action: rename the group.
        let rename = alice_mdk
            .update_group_data(&group_id, NostrGroupDataUpdate::new().name("Renamed"))
            .expect("Alice renames the group");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice merges rename");
        carol_mdk
            .process_message(&rename.evolution_event)
            .expect("Carol processes Alice's rename");

        // Post-fix: Mallory MUST NOT be a member, and the legitimate rename MUST
        // still apply on both sides.
        let alice_members = alice_mdk.get_members(&group_id).expect("alice members");
        let carol_members = carol_mdk.get_members(&group_id).expect("carol members");
        assert!(
            !alice_members.contains(&mallory_keys.public_key()),
            "FIX: Mallory must not be smuggled into Alice's view via the rename commit",
        );
        assert!(
            !carol_members.contains(&mallory_keys.public_key()),
            "FIX: Mallory must not be smuggled into Carol's view via the rename commit",
        );
        assert_eq!(
            alice_members.len(),
            3,
            "Alice's member count must still be 3 (Alice, Bob, Carol)"
        );
        assert_eq!(
            carol_members.len(),
            3,
            "Carol's member count must still be 3 (Alice, Bob, Carol)"
        );
    }

    /// marmot-security #106 receive-side defense-in-depth.
    ///
    /// Simulates a non-conformant admin client that skips MDK's build-side
    /// prune and consumes the entire pending-proposal store the way OpenMLS
    /// did by default. The smuggled commit is signed by an admin, so a peer
    /// that only checked the committer would accept it. The receive-side
    /// guard added in `validate_committed_proposal_authorship` MUST reject it.
    #[test]
    fn receive_side_rejects_admin_commit_with_smuggled_nonadmin_add() {
        use crate::MDK;
        use crate::error::Error;
        use crate::extension::NostrGroupDataExtension;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let carol_keys = Keys::generate();
        let mallory_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let carol_mdk = create_test_mdk();
        let mallory_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key()];
        let bob_kp = create_key_package_event(&bob_mdk, &bob_keys);
        let carol_kp = create_key_package_event(&carol_mdk, &carol_keys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_kp, carol_kp],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice creates group");
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        for (mdk, idx) in [(&bob_mdk, 0usize), (&carol_mdk, 1usize)] {
            let w = mdk
                .process_welcome(
                    &nostr::EventId::all_zeros(),
                    &create_result.welcome_rumors[idx],
                )
                .unwrap();
            mdk.accept_welcome(&w).unwrap();
        }

        // Bob's Add(Mallory) lands in Alice's and Carol's pending stores.
        let mallory_kp_event = create_key_package_event(&mallory_mdk, &mallory_keys);
        let mallory_kp = bob_mdk.parse_key_package(&mallory_kp_event).unwrap();
        let mut bob_group = bob_mdk.load_mls_group(&group_id).unwrap().unwrap();
        let bob_signer = bob_mdk.load_mls_signer(&bob_group).unwrap();
        let (proposal_msg, _) = bob_group
            .propose_add_member(&bob_mdk.provider, &bob_signer, &mallory_kp)
            .unwrap();
        let proposal_event = bob_mdk
            .build_message_event(
                &group_id,
                proposal_msg.tls_serialize_detached().unwrap(),
                None,
            )
            .unwrap();
        alice_mdk.process_message(&proposal_event).unwrap();
        carol_mdk.process_message(&proposal_event).unwrap();

        // Simulate a malicious / non-conformant admin client: build a rename
        // commit by calling OpenMLS directly with no pre-drain. This sweeps
        // Bob's pending Add(Mallory) into Alice's admin-signed commit.
        let mut alice_mls = alice_mdk.load_mls_group(&group_id).unwrap().unwrap();
        let alice_signer = alice_mdk.load_mls_signer(&alice_mls).unwrap();
        let mut group_data = NostrGroupDataExtension::from_group(&alice_mls).unwrap();
        group_data.name = "Renamed".to_string();
        let extension =
            MDK::<mdk_memory_storage::MdkMemoryStorage>::get_unknown_extension_from_group_data(
                &group_data,
            )
            .unwrap();
        let mut extensions = alice_mls.extensions().clone();
        extensions.add_or_replace(extension).unwrap();
        let (message_out, _, _) = alice_mls
            .update_group_context_extensions(&alice_mdk.provider, extensions, &alice_signer)
            .expect("non-conformant admin builds a smuggled commit");
        let evolution_event = alice_mdk
            .build_message_event(
                &group_id,
                message_out.tls_serialize_detached().unwrap(),
                None,
            )
            .unwrap();

        // Carol's receive-side guard MUST reject the smuggled commit. MDK's
        // top-level processor turns commit-validation errors into a recorded
        // failure + `Unprocessable`, so the surface shape is Ok-Unprocessable,
        // not Err — the load-bearing invariant is that Carol does NOT advance
        // into the smuggled state.
        let carol_result = carol_mdk
            .process_message(&evolution_event)
            .expect("process_message itself does not panic");
        assert!(
            matches!(carol_result, MessageProcessingResult::Unprocessable { .. }),
            "expected Unprocessable (commit rejected), got: {:?}",
            carol_result,
        );

        let carol_members = carol_mdk.get_members(&group_id).unwrap();
        assert!(
            !carol_members.contains(&mallory_keys.public_key()),
            "Mallory must not be added to Carol's view"
        );
        assert_eq!(
            carol_members.len(),
            3,
            "Carol's member count must remain 3 (Alice, Bob, Carol)"
        );

        // Ties the rejection back to *our* receive-side guard rather than the
        // generic catch-all: MDK records a sanitized reason category for
        // every Failed message; `UnauthorizedProposalInCommit` maps to
        // `authorization_failed`, the same category as `CommitFromNonAdmin`.
        use mdk_storage_traits::messages::MessageStorage;
        let record = carol_mdk
            .storage()
            .find_processed_message_by_event_id(&evolution_event.id)
            .expect("storage lookup")
            .expect("processed record exists for the rejected commit");
        let reason = record.failure_reason.unwrap_or_default();
        assert_eq!(
            reason, "authorization_failed",
            "expected receive-side guard rejection (authorization_failed), got: {reason:?}",
        );
        // Hold a live reference to the variant so removing it breaks this test.
        let _ = Error::UnauthorizedProposalInCommit(String::new());
    }

    /// Test that a commit with only the update path (no explicit proposals) from non-admin succeeds
    ///
    /// In MLS, a commit can update the sender's leaf via the "update path" without
    /// including explicit Update proposals. This tests that such commits from
    /// non-admins are correctly identified as self-updates and allowed.
    #[test]
    fn test_non_admin_empty_self_update_commit_succeeds() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group with Bob
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Verify Bob is not admin
        let group_state = bob_mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert!(
            !group_state.admin_pubkeys.contains(&bob_keys.public_key()),
            "Bob should NOT be an admin"
        );

        // Bob performs multiple self-updates to verify the pattern is consistently allowed
        for i in 0..3 {
            let bob_update_result = bob_mdk
                .self_update(&group_id)
                .unwrap_or_else(|e| panic!("Bob self-update {} should succeed: {:?}", i + 1, e));

            // Alice processes Bob's self-update
            let result = alice_mdk.process_message(&bob_update_result.evolution_event);
            assert!(
                result.is_ok(),
                "Non-admin self-update {} should succeed, got: {:?}",
                i + 1,
                result.err()
            );

            // Bob merges his own commit
            bob_mdk
                .merge_pending_commit(&group_id)
                .unwrap_or_else(|e| panic!("Bob should merge self-update {}: {:?}", i + 1, e));
        }
    }
}
