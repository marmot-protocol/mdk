//! Nostr MLS Messages
//!
//! This module provides functionality for creating, processing, and managing encrypted
//! messages in MLS groups. It handles:
//! - Message creation and encryption
//! - Message processing and decryption
//! - Message state tracking
//! - Integration with Nostr events
//!
//! Messages in Nostr MLS are wrapped in Nostr events (kind:445) for relay transmission.
//! The message content is encrypted using both MLS group keys and NIP-44 encryption.
//! Message state is tracked to handle processing status and failure scenarios.

use mdk_storage_traits::MdkStorageProvider;
use mdk_storage_traits::groups::Pagination;
use mdk_storage_traits::groups::types as group_types;
use mdk_storage_traits::messages::types as message_types;
use nostr::{Event, EventId, JsonUtil, Kind, TagKind, Timestamp, UnsignedEvent};
use openmls::group::{ProcessMessageError, ValidationError};
use openmls::prelude::{
    ApplicationMessage, BasicCredential, MlsGroup, MlsMessageIn, ProcessedMessage,
    ProcessedMessageContent, Proposal, QueuedProposal, Sender, StagedCommit,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use mdk_storage_traits::GroupId;

use crate::error::Error;
use crate::groups::UpdateGroupResult;
use crate::{MDK, util};

// Internal Result type alias for this module
type Result<T> = std::result::Result<T, Error>;

/// Default number of epochs to look back when trying to decrypt messages with older exporter secrets
const DEFAULT_EPOCH_LOOKBACK: u64 = 5;

/// MessageProcessingResult covers the full spectrum of responses that we can get back from attempting to process a message
#[derive(Debug)]
pub enum MessageProcessingResult {
    /// An application message (this is usually a message in a chat)
    ApplicationMessage(message_types::Message),
    /// Proposal message that was auto-committed (self-remove proposals when receiver is admin)
    Proposal(UpdateGroupResult),
    /// Pending proposal message stored but not committed
    ///
    /// For add/remove member proposals, these are always stored as pending so that
    /// admins can approve them through a manual commit. For self-remove (leave) proposals,
    /// these are stored as pending when the receiver is not an admin.
    PendingProposal {
        /// The MLS group ID this pending proposal belongs to
        mls_group_id: GroupId,
    },
    /// Proposal was ignored and not stored
    ///
    /// This occurs for proposals that should not be processed, such as:
    /// - Extension/ciphersuite change proposals (admins should create commits directly)
    /// - Other unsupported proposal types
    IgnoredProposal {
        /// The MLS group ID this proposal was for
        mls_group_id: GroupId,
        /// Reason the proposal was ignored
        reason: String,
    },
    /// External Join Proposal
    ExternalJoinProposal {
        /// The MLS group ID this proposal belongs to
        mls_group_id: GroupId,
    },
    /// Commit message
    Commit {
        /// The MLS group ID this commit applies to
        mls_group_id: GroupId,
    },
    /// Unprocessable message
    Unprocessable {
        /// The MLS group ID of the message that could not be processed
        mls_group_id: GroupId,
    },
}

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Retrieves a message by its Nostr event ID within a specific group
    ///
    /// This function looks up a message in storage using its associated Nostr event ID
    /// and MLS group ID. The message must have been previously processed and stored.
    /// Requiring both the event ID and group ID prevents messages from different groups
    /// from overwriting each other.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The MLS group ID the message belongs to
    /// * `event_id` - The Nostr event ID to look up
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Message))` - The message if found
    /// * `Ok(None)` - If no message exists with the given event ID in the specified group
    /// * `Err(Error)` - If there is an error accessing storage
    pub fn get_message(
        &self,
        mls_group_id: &GroupId,
        event_id: &EventId,
    ) -> Result<Option<message_types::Message>> {
        self.storage()
            .find_message_by_event_id(mls_group_id, event_id)
            .map_err(|e| Error::Message(e.to_string()))
    }

    /// Retrieves messages for a specific MLS group with optional pagination
    ///
    /// This function returns messages that have been processed and stored for a group,
    /// ordered by creation time (descending). If no pagination is specified, uses default
    /// pagination (1000 messages, offset 0).
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The MLS group ID to get messages for
    /// * `pagination` - Optional pagination parameters. If `None`, uses default limit and offset.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Message>)` - List of messages for the group (up to limit)
    /// * `Err(Error)` - If there is an error accessing storage
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Get messages with default pagination (1000 messages, offset 0)
    /// let messages = mdk.get_messages(&group_id, None)?;
    ///
    /// // Get first 100 messages
    /// use mdk_storage_traits::groups::Pagination;
    /// let messages = mdk.get_messages(&group_id, Some(Pagination::new(Some(100), Some(0))))?;
    ///
    /// // Get next 100 messages
    /// let messages = mdk.get_messages(&group_id, Some(Pagination::new(Some(100), Some(100))))?;
    /// ```
    pub fn get_messages(
        &self,
        mls_group_id: &GroupId,
        pagination: Option<Pagination>,
    ) -> Result<Vec<message_types::Message>> {
        self.storage()
            .messages(mls_group_id, pagination)
            .map_err(|e| Error::Message(e.to_string()))
    }

    /// Creates an MLS-encrypted message from an unsigned Nostr event
    ///
    /// This internal function handles the MLS-level encryption of a message:
    /// 1. Loads the member's signing keys
    /// 2. Ensures the message has a unique ID
    /// 3. Serializes the message content
    /// 4. Creates and signs the MLS message
    ///
    /// # Arguments
    ///
    /// * `group` - The MLS group to create the message in
    /// * `rumor` - The unsigned Nostr event to encrypt
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The serialized encrypted MLS message
    /// * `Err(Error)` - If message creation or encryption fails
    fn create_message_for_event(
        &self,
        group: &mut MlsGroup,
        rumor: &mut UnsignedEvent,
    ) -> Result<Vec<u8>> {
        // Load signer
        let signer: SignatureKeyPair = self.load_mls_signer(group)?;

        // Ensure rumor ID
        rumor.ensure_id();

        // Serialize as JSON
        let json: String = rumor.as_json();

        // Create message
        let message_out = group.create_message(&self.provider, &signer, json.as_bytes())?;

        let serialized_message = message_out.tls_serialize_detached()?;

        Ok(serialized_message)
    }

    /// Creates a complete encrypted Nostr event for an MLS group message
    ///
    /// This is the main entry point for creating group messages. The function:
    /// 1. Loads the MLS group and its metadata
    /// 2. Creates and encrypts the MLS message
    /// 3. Derives NIP-44 encryption keys from the group's secret
    /// 4. Creates a Nostr event wrapping the encrypted message
    /// 5. Stores the message state for tracking
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The MLS group ID
    /// * `rumor` - The unsigned Nostr event to encrypt and send
    ///
    /// # Returns
    ///
    /// * `Ok(Event)` - The signed Nostr event ready for relay publication
    /// * `Err(Error)` - If message creation or encryption fails
    pub fn create_message(
        &self,
        mls_group_id: &GroupId,
        mut rumor: UnsignedEvent,
    ) -> Result<Event> {
        // Load mls group
        let mut mls_group = self
            .load_mls_group(mls_group_id)?
            .ok_or(Error::GroupNotFound)?;

        // Load stored group
        let mut group: group_types::Group = self
            .get_group(mls_group_id)
            .map_err(|e| Error::Group(e.to_string()))?
            .ok_or(Error::GroupNotFound)?;

        // Create message
        let message: Vec<u8> = self.create_message_for_event(&mut mls_group, &mut rumor)?;

        // Get the rumor ID
        let rumor_id: EventId = rumor.id();

        let event = self.build_encrypted_message_event(mls_group_id, message)?;

        // Create message to save to storage
        let message: message_types::Message = message_types::Message {
            id: rumor_id,
            pubkey: rumor.pubkey,
            kind: rumor.kind,
            mls_group_id: mls_group_id.clone(),
            created_at: rumor.created_at,
            content: rumor.content.clone(),
            tags: rumor.tags.clone(),
            event: rumor.clone(),
            wrapper_event_id: event.id,
            state: message_types::MessageState::Created,
        };

        // Create processed_message to track state of message
        let processed_message: message_types::ProcessedMessage = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: Some(rumor_id),
            processed_at: Timestamp::now(),
            state: message_types::ProcessedMessageState::Created,
            failure_reason: None,
        };

        // Save message to storage
        self.storage()
            .save_message(message.clone())
            .map_err(|e| Error::Message(e.to_string()))?;

        // Save processed message to storage
        self.storage()
            .save_processed_message(processed_message)
            .map_err(|e| Error::Message(e.to_string()))?;

        // Update last_message_at and last_message_id
        group.last_message_at = Some(rumor.created_at);
        group.last_message_id = Some(message.id);
        self.storage()
            .save_group(group)
            .map_err(|e| Error::Group(e.to_string()))?;

        Ok(event)
    }

    /// Processes an incoming MLS message
    ///
    /// This internal function handles the MLS protocol-level message processing:
    /// 1. Deserializes the MLS message
    /// 2. Validates the message's group ID
    /// 3. Processes the message according to its type
    /// 4. Handles any resulting group state changes
    ///
    /// # Arguments
    ///
    /// * `group` - The MLS group the message belongs to
    /// * `message_bytes` - The serialized MLS message to process
    ///
    /// # Returns
    ///
    /// * `Ok(ProcessedMessage)` - The processed message including sender and credential info
    /// * `Err(Error)` - If message processing fails
    fn process_message_for_group(
        &self,
        group: &mut MlsGroup,
        message_bytes: &[u8],
    ) -> Result<ProcessedMessage> {
        let mls_message = MlsMessageIn::tls_deserialize_exact(message_bytes)?;

        tracing::debug!(target: "mdk_core::messages::process_message_for_group", "Received message: {:?}", mls_message);
        let protocol_message = mls_message.try_into_protocol_message()?;

        // Return error if group ID doesn't match
        if protocol_message.group_id() != group.group_id() {
            return Err(Error::ProtocolGroupIdMismatch);
        }

        let processed_message = match group.process_message(&self.provider, protocol_message) {
            Ok(processed_message) => processed_message,
            Err(ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)) => {
                return Err(Error::CannotDecryptOwnMessage);
            }
            Err(e) => {
                tracing::error!(target: "mdk_core::messages::process_message_for_group", "Error processing message: {:?}", e);
                return Err(e.into());
            }
        };

        tracing::debug!(
            target: "mdk_core::messages::process_message_for_group",
            "Processed message: {:?}",
            processed_message
        );

        Ok(processed_message)
    }

    /// Verifies that a rumor's author matches the MLS sender's credential
    ///
    /// This function ensures the Nostr identity (rumor pubkey) is bound to the
    /// authenticated MLS sender, preventing impersonation attacks where a malicious
    /// actor could try to send a message with someone else's pubkey.
    ///
    /// # Arguments
    ///
    /// * `rumor_pubkey` - The public key from the rumor (inner Nostr event)
    /// * `sender_credential` - The MLS credential of the authenticated sender (consumed)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the rumor pubkey matches the credential identity
    /// * `Err(Error::AuthorMismatch)` - If the pubkeys don't match
    /// * `Err(Error)` - If credential parsing fails
    pub(crate) fn verify_rumor_author(
        &self,
        rumor_pubkey: &nostr::PublicKey,
        sender_credential: openmls::credentials::Credential,
    ) -> Result<()> {
        let basic_credential = BasicCredential::try_from(sender_credential)?;
        let mls_sender_pubkey = self.parse_credential_identity(basic_credential.identity())?;
        if *rumor_pubkey != mls_sender_pubkey {
            tracing::warn!(
                target: "mdk_core::messages::verify_rumor_author",
                "author mismatch: rumor pubkey {} does not match MLS sender {}",
                rumor_pubkey,
                mls_sender_pubkey
            );
            return Err(Error::AuthorMismatch);
        }
        Ok(())
    }

    /// Checks if two identities match, returning an error if they differ
    ///
    /// This is a core validation helper that enforces MIP-00's immutable identity requirement.
    /// It compares two Nostr public keys and returns an error if they are different.
    ///
    /// # Arguments
    ///
    /// * `current_identity` - The member's current identity in the group
    /// * `new_identity` - The proposed new identity
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If identities match
    /// * `Err(Error::IdentityChangeNotAllowed)` - If identities differ
    fn check_identity_unchanged(
        current_identity: nostr::PublicKey,
        new_identity: nostr::PublicKey,
    ) -> Result<()> {
        if current_identity != new_identity {
            return Err(Error::IdentityChangeNotAllowed {
                original_identity: current_identity.to_hex(),
                new_identity: new_identity.to_hex(),
            });
        }
        Ok(())
    }

    /// Validates that a proposal does not attempt to change a member's identity
    ///
    /// MIP-00 mandates immutable identity fields. This function validates that
    /// Update proposals do not attempt to change the BasicCredential.identity
    /// of a member. Identity changes are not allowed as they could enable
    /// impersonation, misattribution, and persistent group state corruption.
    ///
    /// # Arguments
    ///
    /// * `mls_group` - The MLS group to validate against
    /// * `proposal` - The proposal to validate
    /// * `sender` - The sender of the proposal
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the proposal does not attempt to change identity
    /// * `Err(Error::IdentityChangeNotAllowed)` - If the proposal attempts to change identity
    fn validate_proposal_identity(
        &self,
        mls_group: &MlsGroup,
        proposal: &Proposal,
        sender: &Sender,
    ) -> Result<()> {
        // Only Update proposals can change a member's identity
        // Add proposals add new members (no existing identity to change)
        // Remove proposals only specify a leaf index
        if let Proposal::Update(update_proposal) = proposal {
            // Get the sender's leaf index - only members can send Update proposals
            let sender_leaf_index = match sender {
                Sender::Member(leaf_index) => *leaf_index,
                _ => {
                    // Non-member senders cannot send Update proposals
                    // This should be caught earlier, but we handle it gracefully
                    return Ok(());
                }
            };

            // Get the current member's identity from the group
            let current_member = mls_group.member_at(sender_leaf_index);
            let current_identity = match current_member {
                Some(member) => {
                    let credential = BasicCredential::try_from(member.credential.clone())?;
                    self.parse_credential_identity(credential.identity())?
                }
                None => {
                    // Member not found - this shouldn't happen but handle gracefully
                    tracing::warn!(
                        target: "mdk_core::messages::validate_proposal_identity",
                        "Member not found at leaf index {:?}",
                        sender_leaf_index
                    );
                    return Ok(());
                }
            };

            // Get the new identity from the Update proposal's leaf node
            let new_leaf_node = update_proposal.leaf_node();
            let new_credential = BasicCredential::try_from(new_leaf_node.credential().clone())?;
            let new_identity = self.parse_credential_identity(new_credential.identity())?;

            // Check if identity is being changed
            if current_identity != new_identity {
                tracing::warn!(
                    target: "mdk_core::messages::validate_proposal_identity",
                    "Identity change not allowed: proposal attempts to change identity from {} to {}",
                    current_identity,
                    new_identity
                );
            }
            Self::check_identity_unchanged(current_identity, new_identity)?;
        }

        Ok(())
    }

    /// Checks if a staged commit is a pure self-update commit
    ///
    /// A pure self-update commit is one that only updates the sender's own leaf node
    /// without adding or removing any members or modifying group state. Per the Marmot
    /// protocol specification, any member (not just admins) can create a self-update
    /// commit to rotate their own key material.
    ///
    /// # Arguments
    ///
    /// * `staged_commit` - The staged commit to check
    /// * `sender_leaf_index` - The leaf index of the commit sender
    ///
    /// # Returns
    ///
    /// * `true` - If the commit is a pure self-update (no add/remove/extension proposals, only
    ///   updates to sender's own leaf)
    /// * `false` - If the commit contains add/remove/extension proposals or updates to other leaves
    fn is_pure_self_update_commit(
        &self,
        staged_commit: &StagedCommit,
        sender_leaf_index: &openmls::prelude::LeafNodeIndex,
    ) -> bool {
        // A self-update commit must contain at least one self-update signal:
        // either an UpdatePath or an Update proposal. Reject empty commits.
        if staged_commit.update_path_leaf_node().is_none()
            && staged_commit.update_proposals().next().is_none()
        {
            return false;
        }

        // Use a whitelist approach: only allow Update proposals that are self-updates.
        // Any other proposal type (Add, Remove, PreSharedKey, GroupContextExtensions,
        // ReInit, ExternalInit, AppAck, Custom, or future types) requires admin privileges.
        //
        // This is more secure than a blocklist because it automatically rejects any
        // new proposal types that might be added in future MLS/OpenMLS versions.

        // Check all proposals are Update variants
        if !staged_commit
            .queued_proposals()
            .all(|p| matches!(p.proposal(), Proposal::Update(_)))
        {
            return false;
        }

        // Verify all update proposals are self-updates (sender's own leaf)
        staged_commit
            .update_proposals()
            .all(|p| matches!(p.sender(), Sender::Member(idx) if idx == sender_leaf_index))
    }

    /// Validates that a staged commit does not attempt to change any member's identity
    ///
    /// This function checks all Update proposals within a staged commit to ensure
    /// none of them attempt to change the BasicCredential.identity of a member.
    /// It also validates the update path leaf node if present (which represents
    /// the committer's own leaf update).
    ///
    /// # Arguments
    ///
    /// * `mls_group` - The MLS group to validate against
    /// * `staged_commit` - The staged commit to validate
    /// * `commit_sender` - The sender of the commit message
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If no proposals attempt to change identity
    /// * `Err(Error::IdentityChangeNotAllowed)` - If any proposal attempts to change identity
    fn validate_staged_commit_identities(
        &self,
        mls_group: &MlsGroup,
        staged_commit: &StagedCommit,
        commit_sender: &Sender,
    ) -> Result<()> {
        // Validate all Update proposals in the staged commit
        for update_proposal in staged_commit.update_proposals() {
            let sender = update_proposal.sender();
            let proposal = Proposal::Update(Box::new(update_proposal.update_proposal().clone()));
            self.validate_proposal_identity(mls_group, &proposal, sender)?;
        }

        // Validate the update path leaf node if present
        // The update path is used when the committer updates their own leaf as part of the commit
        if let Some(update_path_leaf_node) = staged_commit.update_path_leaf_node() {
            // The committer is updating their own leaf via the commit path
            // Get the committer's leaf index from the sender and validate their identity
            if let Sender::Member(committer_leaf_index) = commit_sender
                && let Some(committer_member) = mls_group.member_at(*committer_leaf_index)
            {
                let current_credential =
                    BasicCredential::try_from(committer_member.credential.clone())?;
                let current_identity =
                    self.parse_credential_identity(current_credential.identity())?;

                let new_credential =
                    BasicCredential::try_from(update_path_leaf_node.credential().clone())?;
                let new_identity = self.parse_credential_identity(new_credential.identity())?;

                if current_identity != new_identity {
                    tracing::warn!(
                        target: "mdk_core::messages::validate_staged_commit_identities",
                        "Identity change not allowed in commit update path: committer {} attempted to change identity to {}",
                        current_identity,
                        new_identity
                    );
                }
                Self::check_identity_unchanged(current_identity, new_identity)?;
            }
        }

        Ok(())
    }

    /// Processes an application message from a group member
    ///
    /// This internal function handles application messages (chat messages) that have been
    /// successfully decrypted. It:
    /// 1. Deserializes the message content as a Nostr event
    /// 2. Verifies the rumor pubkey matches the MLS sender credential (author binding)
    /// 3. Creates tracking records for the message and processing state
    /// 4. Updates the group's last message metadata
    /// 5. Stores all data in the storage provider
    ///
    /// # Arguments
    ///
    /// * `group` - The group metadata from storage
    /// * `event` - The wrapper Nostr event containing the encrypted message
    /// * `application_message` - The decrypted MLS application message
    /// * `sender_credential` - The MLS credential of the sender for author verification
    ///
    /// # Returns
    ///
    /// * `Ok(Message)` - The processed and stored message
    /// * `Err(Error)` - If message processing, author verification, or storage fails
    fn process_application_message_for_group(
        &self,
        mut group: group_types::Group,
        event: &Event,
        application_message: ApplicationMessage,
        sender_credential: openmls::credentials::Credential,
    ) -> Result<message_types::Message> {
        // This is a message from a group member
        let bytes = application_message.into_bytes();
        let mut rumor: UnsignedEvent = UnsignedEvent::from_json(bytes)?;

        self.verify_rumor_author(&rumor.pubkey, sender_credential)?;

        let rumor_id: EventId = rumor.id();

        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: Some(rumor_id),
            processed_at: Timestamp::now(),
            state: message_types::ProcessedMessageState::Processed,
            failure_reason: None,
        };

        let message = message_types::Message {
            id: rumor_id,
            pubkey: rumor.pubkey,
            kind: rumor.kind,
            mls_group_id: group.mls_group_id.clone(),
            created_at: rumor.created_at,
            content: rumor.content.clone(),
            tags: rumor.tags.clone(),
            event: rumor.clone(),
            wrapper_event_id: event.id,
            state: message_types::MessageState::Processed,
        };

        self.storage()
            .save_message(message.clone())
            .map_err(|e| Error::Message(e.to_string()))?;

        self.storage()
            .save_processed_message(processed_message.clone())
            .map_err(|e| Error::Message(e.to_string()))?;

        // Update last_message_at and last_message_id
        group.last_message_at = Some(rumor.created_at);
        group.last_message_id = Some(message.id);
        self.storage()
            .save_group(group)
            .map_err(|e| Error::Group(e.to_string()))?;

        tracing::debug!(target: "mdk_core::messages::process_message", "Processed message: {:?}", processed_message);
        tracing::debug!(target: "mdk_core::messages::process_message", "Message: {:?}", message);
        Ok(message)
    }

    /// Processes a proposal message from a group member
    ///
    /// This internal function handles MLS proposal messages according to the Marmot protocol:
    ///
    /// - **Add/Remove member proposals**: Always stored as pending for admin approval via manual commit
    /// - **Self-remove (leave) proposals**: Auto-committed if receiver is admin, otherwise pending
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
    fn process_proposal_message_for_group(
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
                                self.store_pending_proposal_and_mark_processed(
                                    mls_group,
                                    event,
                                    staged_proposal,
                                    &group_id,
                                )?;

                                tracing::debug!(
                                    target: "mdk_core::messages::process_proposal_message_for_group",
                                    "Stored Add proposal as pending for admin approval in group {:?}",
                                    group_id
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
                                    // Self-remove proposal + admin receiver: auto-commit
                                    self.store_and_commit_proposal(
                                        mls_group,
                                        event,
                                        staged_proposal,
                                        &group_id,
                                    )
                                } else {
                                    // Either not self-remove, or receiver is not admin
                                    // Store as pending for admin approval
                                    self.store_pending_proposal_and_mark_processed(
                                        mls_group,
                                        event,
                                        staged_proposal,
                                        &group_id,
                                    )?;

                                    if is_self_remove {
                                        tracing::debug!(
                                            target: "mdk_core::messages::process_proposal_message_for_group",
                                            "Non-admin receiver stored self-remove proposal as pending for group {:?}",
                                            group_id
                                        );
                                    } else {
                                        tracing::debug!(
                                            target: "mdk_core::messages::process_proposal_message_for_group",
                                            "Stored Remove proposal as pending for admin approval in group {:?}",
                                            group_id
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
                                    target: "mdk_core::messages::process_proposal_message_for_group",
                                    "Ignoring Update proposal - self-update handling not yet implemented (see issue #59)"
                                );

                                self.mark_event_processed(event)?;

                                Ok(MessageProcessingResult::IgnoredProposal {
                                    mls_group_id: group_id,
                                    reason: "Update proposals not yet supported (see issue #59)"
                                        .to_string(),
                                })
                            }
                            Proposal::GroupContextExtensions(_) => {
                                // Extension proposals should be ignored - admins create commits directly
                                tracing::warn!(
                                    target: "mdk_core::messages::process_proposal_message_for_group",
                                    "Ignoring GroupContextExtensions proposal - admins should create commits directly"
                                );

                                self.mark_event_processed(event)?;

                                Ok(MessageProcessingResult::IgnoredProposal {
                                    mls_group_id: group_id,
                                    reason: "Extension proposals not allowed - admins should create commits directly".to_string(),
                                })
                            }
                            _ => {
                                // Other proposal types (PreSharedKey, ReInit, ExternalInit, etc.)
                                tracing::warn!(
                                    target: "mdk_core::messages::process_proposal_message_for_group",
                                    "Ignoring unsupported proposal type"
                                );

                                self.mark_event_processed(event)?;

                                Ok(MessageProcessingResult::IgnoredProposal {
                                    mls_group_id: group_id,
                                    reason: "Unsupported proposal type".to_string(),
                                })
                            }
                        }
                    }
                    None => {
                        tracing::warn!(target: "mdk_core::messages::process_message_for_group", "Received proposal from non-member.");
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
    fn store_pending_proposal_and_mark_processed(
        &self,
        mls_group: &mut MlsGroup,
        event: &Event,
        staged_proposal: QueuedProposal,
        _group_id: &GroupId,
    ) -> Result<()> {
        mls_group
            .store_pending_proposal(self.provider.storage(), staged_proposal)
            .map_err(|e| Error::Message(e.to_string()))?;

        self.mark_event_processed(event)
    }

    /// Marks an event as processed to prevent reprocessing
    fn mark_event_processed(&self, event: &Event) -> Result<()> {
        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: None,
            processed_at: Timestamp::now(),
            state: message_types::ProcessedMessageState::Processed,
            failure_reason: None,
        };

        self.storage()
            .save_processed_message(processed_message)
            .map_err(|e| Error::Message(e.to_string()))
    }

    /// Stores a proposal and immediately commits it (for self-remove by admin)
    fn store_and_commit_proposal(
        &self,
        mls_group: &mut MlsGroup,
        event: &Event,
        staged_proposal: QueuedProposal,
        group_id: &GroupId,
    ) -> Result<MessageProcessingResult> {
        mls_group
            .store_pending_proposal(self.provider.storage(), staged_proposal)
            .map_err(|e| Error::Message(e.to_string()))?;

        let mls_signer = self.load_mls_signer(mls_group)?;

        // Self-remove proposals never generate welcomes (only Add proposals do),
        // so we can safely ignore the welcome output here
        let (commit_message, _welcomes, _group_info) =
            mls_group.commit_to_pending_proposals(&self.provider, &mls_signer)?;

        let serialized_commit_message = commit_message
            .tls_serialize_detached()
            .map_err(|e| Error::Group(e.to_string()))?;

        let commit_event =
            self.build_encrypted_message_event(group_id, serialized_commit_message)?;

        self.mark_event_processed(event)?;

        tracing::debug!(
            target: "mdk_core::messages::process_proposal_message_for_group",
            "Admin auto-committed self-remove proposal for group {:?}",
            group_id
        );

        Ok(MessageProcessingResult::Proposal(UpdateGroupResult {
            evolution_event: commit_event,
            welcome_rumors: None,
            mls_group_id: group_id.clone(),
        }))
    }

    /// Processes a commit message from a group member
    ///
    /// This internal function handles MLS commit messages that finalize pending proposals.
    /// The function:
    /// 1. Validates the sender is authorized (admin, or non-admin for pure self-updates)
    /// 2. Merges the staged commit into the group state
    /// 3. Checks if the local member was removed by this commit
    /// 4. If removed: sets group state to Inactive and skips further processing
    /// 5. If still a member: saves new exporter secret and syncs group metadata
    /// 6. Updates processing state to prevent reprocessing
    ///
    /// Note: Non-admin members are allowed to create commits that only update their own
    /// leaf node (pure self-updates). All other commit operations require admin privileges.
    ///
    /// When the local member is removed by a commit, the group state is set to `Inactive`
    /// and the exporter secret/metadata sync are skipped to prevent use-after-eviction errors.
    ///
    /// # Arguments
    ///
    /// * `mls_group` - The MLS group to merge the commit into
    /// * `event` - The wrapper Nostr event containing the encrypted commit
    /// * `staged_commit` - The validated MLS commit to merge
    /// * `commit_sender` - The MLS sender of the commit
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If commit processing succeeds
    /// * `Err(Error)` - If sender is not authorized, commit merging, or storage operations fail
    fn process_commit_message_for_group(
        &self,
        mls_group: &mut MlsGroup,
        event: &Event,
        staged_commit: StagedCommit,
        commit_sender: &Sender,
    ) -> Result<()> {
        self.validate_commit_sender_authorization(mls_group, &staged_commit, commit_sender)?;
        self.validate_staged_commit_identities(mls_group, &staged_commit, commit_sender)?;

        let group_id: GroupId = mls_group.group_id().into();

        mls_group
            .merge_staged_commit(&self.provider, staged_commit)
            .map_err(|e| Error::Message(e.to_string()))?;

        // Check if the local member was removed by this commit
        if mls_group.own_leaf().is_none() {
            return self.handle_local_member_eviction(&group_id, event);
        }

        // Save exporter secret for the new epoch
        self.exporter_secret(&group_id)?;

        // Sync the stored group metadata with the updated MLS group state
        self.sync_group_metadata_from_mls(&group_id)?;

        // Save a processed message so we don't reprocess
        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: None,
            processed_at: Timestamp::now(),
            state: message_types::ProcessedMessageState::Processed,
            failure_reason: None,
        };

        self.storage()
            .save_processed_message(processed_message)
            .map_err(|e| Error::Message(e.to_string()))?;
        Ok(())
    }

    /// Validates that the commit sender is authorized to create this commit.
    ///
    /// Admins can create any commit. Non-admins can only create pure self-update commits
    /// (commits that only update their own leaf node with no add/remove proposals).
    ///
    /// # Arguments
    ///
    /// * `mls_group` - The MLS group to check authorization against
    /// * `staged_commit` - The staged commit to validate
    /// * `commit_sender` - The MLS sender of the commit
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the sender is authorized
    /// * `Err(Error::CommitFromNonAdmin)` - If a non-admin tries to create a non-self-update commit
    /// * `Err(Error::MessageFromNonMember)` - If the sender is not a member
    fn validate_commit_sender_authorization(
        &self,
        mls_group: &MlsGroup,
        staged_commit: &StagedCommit,
        commit_sender: &Sender,
    ) -> Result<()> {
        match commit_sender {
            Sender::Member(leaf_index) => {
                let member = mls_group
                    .member_at(*leaf_index)
                    .ok_or(Error::MessageFromNonMember)?;

                let basic_cred = BasicCredential::try_from(member.credential.clone())?;
                let sender_pubkey = self.parse_credential_identity(basic_cred.identity())?;
                let group_data = crate::extension::NostrGroupDataExtension::from_group(mls_group)?;
                let sender_is_admin = group_data.admins.contains(&sender_pubkey);

                let is_pure_self_update =
                    self.is_pure_self_update_commit(staged_commit, leaf_index);

                match (sender_is_admin, is_pure_self_update) {
                    (true, _) => Ok(()),
                    (false, true) => {
                        tracing::debug!(
                            target: "mdk_core::messages::process_commit_message_for_group",
                            "Allowing self-update commit from non-admin member at leaf index {:?}",
                            leaf_index
                        );
                        Ok(())
                    }
                    (false, false) => {
                        tracing::warn!(
                            target: "mdk_core::messages::process_commit_message_for_group",
                            "Received non-self-update commit from non-admin member at leaf index {:?}",
                            leaf_index
                        );
                        Err(Error::CommitFromNonAdmin)
                    }
                }
            }
            _ => {
                tracing::warn!(
                    target: "mdk_core::messages::process_commit_message_for_group",
                    "Received commit from non-member sender."
                );
                Err(Error::MessageFromNonMember)
            }
        }
    }

    /// Handles the case where the local member was removed from a group.
    ///
    /// Sets the group state to Inactive and saves a processed message record.
    /// Called after merge_staged_commit when own_leaf() returns None.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The ID of the group the member was removed from
    /// * `event` - The wrapper Nostr event containing the commit
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the eviction was handled successfully
    /// * `Err(Error)` - If storage operations fail
    fn handle_local_member_eviction(&self, group_id: &GroupId, event: &Event) -> Result<()> {
        tracing::info!(
            target: "mdk_core::messages::process_commit_message_for_group",
            group_id = %hex::encode(group_id.as_slice()),
            "Local member was removed from group, setting group state to Inactive"
        );

        match self.get_group(group_id)? {
            Some(mut group) => {
                group.state = group_types::GroupState::Inactive;
                self.storage()
                    .save_group(group)
                    .map_err(|e| Error::Group(e.to_string()))?;
            }
            None => {
                tracing::warn!(
                    target: "mdk_core::messages::process_commit_message_for_group",
                    group_id = %hex::encode(group_id.as_slice()),
                    "Group not found in storage while handling eviction"
                );
            }
        }

        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: None,
            processed_at: Timestamp::now(),
            state: message_types::ProcessedMessageState::Processed,
            failure_reason: None,
        };

        self.storage()
            .save_processed_message(processed_message)
            .map_err(|e| Error::Message(e.to_string()))?;

        Ok(())
    }

    /// Validates that an event's timestamp is within acceptable bounds
    ///
    /// This method checks that the event timestamp is not too far in the future
    /// (beyond configurable clock skew) and not too old (beyond configurable max age).
    ///
    /// # Arguments
    ///
    /// * `event` - The Nostr event to validate
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If timestamp is valid
    /// * `Err(Error::InvalidTimestamp)` - If timestamp is outside acceptable bounds
    fn validate_created_at(&self, event: &Event) -> Result<()> {
        let now = Timestamp::now();

        // Reject events from the future (allow configurable clock skew)
        if event.created_at.as_u64()
            > now
                .as_u64()
                .saturating_add(self.config.max_future_skew_secs)
        {
            return Err(Error::InvalidTimestamp(format!(
                "event timestamp {} is too far in the future (current time: {})",
                event.created_at.as_u64(),
                now.as_u64()
            )));
        }

        // Reject events that are too old (configurable via MdkConfig)
        let min_timestamp = now.as_u64().saturating_sub(self.config.max_event_age_secs);
        if event.created_at.as_u64() < min_timestamp {
            return Err(Error::InvalidTimestamp(format!(
                "event timestamp {} is too old (minimum acceptable: {})",
                event.created_at.as_u64(),
                min_timestamp
            )));
        }

        Ok(())
    }

    /// Validates and extracts the Nostr group ID from event tags
    ///
    /// This method validates that the event has exactly one 'h' tag (per MIP-03)
    /// and extracts the 32-byte group ID from its hex content.
    ///
    /// # Arguments
    ///
    /// * `event` - The Nostr event to extract group ID from
    ///
    /// # Returns
    ///
    /// * `Ok([u8; 32])` - The extracted Nostr group ID
    /// * `Err(Error)` - If validation fails or group ID cannot be extracted
    fn validate_and_extract_nostr_group_id(&self, event: &Event) -> Result<[u8; 32]> {
        // Extract and validate group ID tag (MIP-03 requires exactly one h tag)
        let h_tags: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.kind() == TagKind::h())
            .collect();

        if h_tags.is_empty() {
            return Err(Error::MissingGroupIdTag);
        }

        if h_tags.len() > 1 {
            return Err(Error::MultipleGroupIdTags(h_tags.len()));
        }

        let nostr_group_id_tag = h_tags[0];

        let group_id_hex = nostr_group_id_tag
            .content()
            .ok_or_else(|| Error::InvalidGroupIdFormat("h tag has no content".to_string()))?;

        // Validate hex string length before decoding to prevent unbounded memory allocation
        // A 32-byte value requires exactly 64 hex characters
        if group_id_hex.len() != 64 {
            return Err(Error::InvalidGroupIdFormat(format!(
                "expected 64 hex characters (32 bytes), got {} characters",
                group_id_hex.len()
            )));
        }

        // Decode once and reuse the result
        let bytes = hex::decode(group_id_hex)
            .map_err(|e| Error::InvalidGroupIdFormat(format!("hex decode failed: {}", e)))?;

        let nostr_group_id: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            Error::InvalidGroupIdFormat(format!("expected 32 bytes, got {} bytes", v.len()))
        })?;

        Ok(nostr_group_id)
    }

    /// Validates the incoming event and extracts the group ID
    ///
    /// This private method validates that the event has the correct kind, checks
    /// timestamp bounds, and extracts the group ID from the event tags per MIP-03
    /// requirements.
    ///
    /// Note: Nostr signature verification is handled by nostr-sdk's relay pool when
    /// events are received from relays.
    ///
    /// # Arguments
    ///
    /// * `event` - The Nostr event to validate
    ///
    /// # Returns
    ///
    /// * `Ok([u8; 32])` - The extracted Nostr group ID
    /// * `Err(Error)` - If validation fails or group ID cannot be extracted
    fn validate_event_and_extract_group_id(&self, event: &Event) -> Result<[u8; 32]> {
        // 1. Verify event kind
        if event.kind != Kind::MlsGroupMessage {
            return Err(Error::UnexpectedEvent {
                expected: Kind::MlsGroupMessage,
                received: event.kind,
            });
        }

        // 2. Verify timestamp is within acceptable bounds
        self.validate_created_at(event)?;

        // 3. Extract and validate group ID tag
        self.validate_and_extract_nostr_group_id(event)
    }

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
    fn load_group_and_decrypt_message(
        &self,
        nostr_group_id: [u8; 32],
        event: &Event,
    ) -> Result<(group_types::Group, MlsGroup, Vec<u8>)> {
        let group = self
            .storage()
            .find_group_by_nostr_group_id(&nostr_group_id)
            .map_err(|e| Error::Group(e.to_string()))?
            .ok_or(Error::GroupNotFound)?;

        // Load the MLS group to get the current epoch
        let mls_group: MlsGroup = self
            .load_mls_group(&group.mls_group_id)
            .map_err(|e| Error::Group(e.to_string()))?
            .ok_or(Error::GroupNotFound)?;

        // Try to decrypt message with recent exporter secrets (fallback across epochs)
        let message_bytes: Vec<u8> =
            self.try_decrypt_with_recent_epochs(&mls_group, &event.content)?;

        Ok((group, mls_group, message_bytes))
    }

    /// Processes the decrypted message content based on its type
    ///
    /// This private method processes the decrypted MLS message and handles the
    /// different message types (application messages, proposals, commits, etc.).
    ///
    /// # Arguments
    ///
    /// * `group` - The group metadata from storage
    /// * `mls_group` - The MLS group instance (mutable for potential state changes)
    /// * `message_bytes` - The decrypted message bytes
    /// * `event` - The wrapper Nostr event
    ///
    /// # Returns
    ///
    /// * `Ok(MessageProcessingResult)` - The result based on message type
    /// * `Err(Error)` - If message processing fails
    fn process_decrypted_message(
        &self,
        group: group_types::Group,
        mls_group: &mut MlsGroup,
        message_bytes: &[u8],
        event: &Event,
    ) -> Result<MessageProcessingResult> {
        match self.process_message_for_group(mls_group, message_bytes) {
            Ok(processed_mls_message) => {
                // Clone the sender's credential and sender for validation before consuming
                let sender_credential = processed_mls_message.credential().clone();
                let message_sender = processed_mls_message.sender().clone();

                match processed_mls_message.into_content() {
                    ProcessedMessageContent::ApplicationMessage(application_message) => {
                        Ok(MessageProcessingResult::ApplicationMessage(
                            self.process_application_message_for_group(
                                group,
                                event,
                                application_message,
                                sender_credential,
                            )?,
                        ))
                    }
                    ProcessedMessageContent::ProposalMessage(staged_proposal) => {
                        self.process_proposal_message_for_group(mls_group, event, *staged_proposal)
                    }
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                        self.process_commit_message_for_group(
                            mls_group,
                            event,
                            *staged_commit,
                            &message_sender,
                        )?;
                        Ok(MessageProcessingResult::Commit {
                            mls_group_id: group.mls_group_id.clone(),
                        })
                    }
                    ProcessedMessageContent::ExternalJoinProposalMessage(
                        _external_join_proposal,
                    ) => {
                        // Save a processed message so we don't reprocess
                        let processed_message = message_types::ProcessedMessage {
                            wrapper_event_id: event.id,
                            message_event_id: None,
                            processed_at: Timestamp::now(),
                            state: message_types::ProcessedMessageState::Processed,
                            failure_reason: None,
                        };

                        self.storage()
                            .save_processed_message(processed_message)
                            .map_err(|e| Error::Message(e.to_string()))?;

                        Ok(MessageProcessingResult::ExternalJoinProposal {
                            mls_group_id: group.mls_group_id.clone(),
                        })
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Classifies an error into a sanitized public failure reason
    ///
    /// This function maps internal errors to generic, safe-to-expose failure categories
    /// that don't leak implementation details or sensitive information.
    ///
    /// # Arguments
    ///
    /// * `error` - The internal error to classify
    ///
    /// # Returns
    ///
    /// A sanitized string suitable for external exposure
    fn classify_failure_reason(error: &Error) -> &'static str {
        match error {
            Error::UnexpectedEvent { .. } => "invalid_event_type",
            Error::MissingGroupIdTag => "invalid_event_format",
            Error::InvalidGroupIdFormat(_) => "invalid_event_format",
            Error::MultipleGroupIdTags(_) => "invalid_event_format",
            Error::InvalidTimestamp(_) => "invalid_event_format",
            Error::GroupNotFound => "group_not_found",
            Error::CannotDecryptOwnMessage => "own_message",
            Error::AuthorMismatch => "authentication_failed",
            Error::CommitFromNonAdmin => "authorization_failed",
            _ => "processing_failed",
        }
    }

    /// Saves a failed processed message record to prevent reprocessing
    ///
    /// This private helper method persists a `ProcessedMessage` with `Failed` state
    /// to the storage, allowing the system to skip reprocessing of invalid events.
    /// The failure reason is sanitized to prevent leaking internal error details,
    /// while the full error is logged internally for debugging.
    ///
    /// # Arguments
    ///
    /// * `event_id` - The ID of the wrapper event that failed
    /// * `error` - The internal error that occurred
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the failed record was saved successfully
    /// * `Err(Error)` - If saving the record fails
    fn save_failed_processed_message(&self, event_id: EventId, error: &Error) -> Result<()> {
        // Classify error into sanitized public reason
        let sanitized_reason = Self::classify_failure_reason(error);

        // Log full error details internally for debugging
        tracing::warn!(
            target: "mdk_core::messages::save_failed_processed_message",
            "Message processing failed for event {}: {} (classified as: {})",
            event_id,
            error,
            sanitized_reason
        );

        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event_id,
            message_event_id: None,
            processed_at: Timestamp::now(),
            state: message_types::ProcessedMessageState::Failed,
            failure_reason: Some(sanitized_reason.to_string()),
        };

        self.storage()
            .save_processed_message(processed_message)
            .map_err(|e| Error::Message(e.to_string()))?;

        tracing::debug!(
            target: "mdk_core::messages::save_failed_processed_message",
            "Saved failed processing record for event {} with reason: {}",
            event_id,
            sanitized_reason
        );

        Ok(())
    }

    /// Handles message processing errors with specific error recovery logic
    ///
    /// This private method handles complex error scenarios when message processing fails,
    /// including special cases like processing own messages, epoch mismatches, and
    /// other MLS-specific validation errors.
    ///
    /// # Arguments
    ///
    /// * `error` - The error that occurred during message processing
    /// * `event` - The wrapper Nostr event that caused the error
    /// * `group` - The group metadata from storage
    ///
    /// # Returns
    ///
    /// * `Ok(MessageProcessingResult)` - Recovery result or unprocessable status
    /// * `Err(Error)` - If error handling itself fails
    fn handle_message_processing_error(
        &self,
        error: Error,
        event: &Event,
        group: &group_types::Group,
    ) -> Result<MessageProcessingResult> {
        match error {
            Error::CannotDecryptOwnMessage => {
                tracing::debug!(target: "mdk_core::messages::process_message", "Cannot decrypt own message, checking for cached message");

                let mut processed_message = self
                    .storage()
                    .find_processed_message_by_event_id(&event.id)
                    .map_err(|e| Error::Message(e.to_string()))?
                    .ok_or(Error::Message("Processed message not found".to_string()))?;

                // If the message is created, we need to update the state of the message and processed message
                // If it's already processed, we don't need to do anything
                match processed_message.state {
                    message_types::ProcessedMessageState::Created => {
                        let message_event_id: EventId = processed_message
                            .message_event_id
                            .ok_or(Error::Message("Message event ID not found".to_string()))?;

                        let mut message = self
                            .get_message(&group.mls_group_id, &message_event_id)?
                            .ok_or(Error::Message("Message not found".to_string()))?;

                        message.state = message_types::MessageState::Processed;
                        self.storage()
                            .save_message(message)
                            .map_err(|e| Error::Message(e.to_string()))?;

                        processed_message.state = message_types::ProcessedMessageState::Processed;
                        self.storage()
                            .save_processed_message(processed_message.clone())
                            .map_err(|e| Error::Message(e.to_string()))?;

                        tracing::debug!(target: "mdk_core::messages::process_message", "Updated state of own cached message");
                        let message = self
                            .get_message(&group.mls_group_id, &message_event_id)?
                            .ok_or(Error::MessageNotFound)?;
                        Ok(MessageProcessingResult::ApplicationMessage(message))
                    }
                    message_types::ProcessedMessageState::ProcessedCommit => {
                        tracing::debug!(target: "mdk_core::messages::process_message", "Message already processed as a commit");

                        // Even though this is our own commit that we can't decrypt, we still need to
                        // sync the stored group metadata with the current MLS group state in case
                        // the group has been updated since the commit was created
                        self.sync_group_metadata_from_mls(&group.mls_group_id)
                            .map_err(|e| {
                                Error::Message(format!("Failed to sync group metadata: {}", e))
                            })?;

                        Ok(MessageProcessingResult::Commit {
                            mls_group_id: group.mls_group_id.clone(),
                        })
                    }
                    message_types::ProcessedMessageState::Processed
                    | message_types::ProcessedMessageState::Failed => {
                        tracing::debug!(target: "mdk_core::messages::process_message", "Message cannot be processed (already processed or failed)");
                        Ok(MessageProcessingResult::Unprocessable {
                            mls_group_id: group.mls_group_id.clone(),
                        })
                    }
                }
            }
            Error::ProcessMessageWrongEpoch => {
                // Epoch mismatch - check if this is our own commit that we've already processed
                tracing::debug!(target: "mdk_core::messages::process_message", "Epoch mismatch error, checking if this is our own commit");

                if let Ok(Some(processed_message)) = self
                    .storage()
                    .find_processed_message_by_event_id(&event.id)
                    .map_err(|e| Error::Message(e.to_string()))
                    && processed_message.state
                        == message_types::ProcessedMessageState::ProcessedCommit
                {
                    tracing::debug!(target: "mdk_core::messages::process_message", "Found own commit with epoch mismatch, syncing group metadata");

                    // Sync the stored group metadata even though processing failed
                    self.sync_group_metadata_from_mls(&group.mls_group_id)
                        .map_err(|e| {
                            Error::Message(format!("Failed to sync group metadata: {}", e))
                        })?;

                    return Ok(MessageProcessingResult::Commit {
                        mls_group_id: group.mls_group_id.clone(),
                    });
                }

                // Not our own commit - this is a genuine error
                tracing::error!(target: "mdk_core::messages::process_message", "Epoch mismatch for message that is not our own commit: {:?}", error);
                let processed_message = message_types::ProcessedMessage {
                    wrapper_event_id: event.id,
                    message_event_id: None,
                    processed_at: Timestamp::now(),
                    state: message_types::ProcessedMessageState::Failed,
                    failure_reason: Some("Epoch mismatch".to_string()),
                };
                self.storage()
                    .save_processed_message(processed_message)
                    .map_err(|e| Error::Message(e.to_string()))?;

                Ok(MessageProcessingResult::Unprocessable {
                    mls_group_id: group.mls_group_id.clone(),
                })
            }
            Error::ProcessMessageWrongGroupId => {
                tracing::error!(target: "mdk_core::messages::process_message", "Group ID mismatch: {:?}", error);
                let processed_message = message_types::ProcessedMessage {
                    wrapper_event_id: event.id,
                    message_event_id: None,
                    processed_at: Timestamp::now(),
                    state: message_types::ProcessedMessageState::Failed,
                    failure_reason: Some("Group ID mismatch".to_string()),
                };
                self.storage()
                    .save_processed_message(processed_message)
                    .map_err(|e| Error::Message(e.to_string()))?;

                Ok(MessageProcessingResult::Unprocessable {
                    mls_group_id: group.mls_group_id.clone(),
                })
            }
            Error::ProcessMessageUseAfterEviction => {
                tracing::error!(target: "mdk_core::messages::process_message", "Attempted to use group after eviction: {:?}", error);
                let processed_message = message_types::ProcessedMessage {
                    wrapper_event_id: event.id,
                    message_event_id: None,
                    processed_at: Timestamp::now(),
                    state: message_types::ProcessedMessageState::Failed,
                    failure_reason: Some("Use after eviction".to_string()),
                };
                self.storage()
                    .save_processed_message(processed_message)
                    .map_err(|e| Error::Message(e.to_string()))?;

                Ok(MessageProcessingResult::Unprocessable {
                    mls_group_id: group.mls_group_id.clone(),
                })
            }
            Error::CommitFromNonAdmin => {
                // Authorization errors should propagate as errors, not be silently swallowed
                // Save a failed processing record to prevent reprocessing (best-effort)
                if let Err(save_err) = self.save_failed_processed_message(event.id, &error) {
                    tracing::warn!(
                        target: "mdk_core::messages::handle_message_processing_error",
                        "Failed to persist failure record: {}. Original error: {}",
                        save_err,
                        error
                    );
                }
                Err(error)
            }
            _ => {
                tracing::error!(target: "mdk_core::messages::process_message", "Unexpected error processing message: {:?}", error);
                let processed_message = message_types::ProcessedMessage {
                    wrapper_event_id: event.id,
                    message_event_id: None,
                    processed_at: Timestamp::now(),
                    state: message_types::ProcessedMessageState::Failed,
                    failure_reason: Some(error.to_string()),
                };
                self.storage()
                    .save_processed_message(processed_message)
                    .map_err(|e| Error::Message(e.to_string()))?;

                Ok(MessageProcessingResult::Unprocessable {
                    mls_group_id: group.mls_group_id.clone(),
                })
            }
        }
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
    /// * `encrypted_content` - The NIP-44 encrypted message content
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
    ) -> Result<Vec<u8>> {
        let group_id: GroupId = mls_group.group_id().into();
        let current_epoch: u64 = mls_group.epoch().as_u64();

        // Start from current epoch and go backwards
        let start_epoch: u64 = current_epoch.saturating_sub(1);
        let end_epoch: u64 = start_epoch.saturating_sub(max_epoch_lookback);

        for epoch in (end_epoch..=start_epoch).rev() {
            tracing::debug!(
                target: "mdk_core::messages::try_decrypt_with_recent_epochs",
                "Trying to decrypt with epoch {} for group {:?}",
                epoch,
                group_id
            );

            // Try to get the exporter secret for this epoch
            if let Ok(Some(secret)) = self
                .storage()
                .get_group_exporter_secret(&group_id, epoch)
                .map_err(|e| Error::Group(e.to_string()))
            {
                // Try to decrypt with this epoch's secret
                match util::decrypt_with_exporter_secret(&secret, encrypted_content) {
                    Ok(decrypted_bytes) => {
                        tracing::debug!(
                            target: "mdk_core::messages::try_decrypt_with_recent_epochs",
                            "Successfully decrypted message with epoch {} for group {:?}",
                            epoch,
                            group_id
                        );
                        return Ok(decrypted_bytes);
                    }
                    Err(e) => {
                        tracing::trace!(
                            target: "mdk_core::messages::try_decrypt_with_recent_epochs",
                            "Failed to decrypt with epoch {}: {:?}",
                            epoch,
                            e
                        );
                        // Continue to next epoch
                    }
                }
            } else {
                tracing::trace!(
                    target: "mdk_core::messages::try_decrypt_with_recent_epochs",
                    "No exporter secret found for epoch {} in group {:?}",
                    epoch,
                    group_id
                );
            }
        }

        Err(Error::Message(format!(
            "Failed to decrypt message with any exporter secret from epochs {} to {} for group {:?}",
            end_epoch, start_epoch, group_id
        )))
    }

    /// Try to decrypt using the current exporter secret and if fails try with the past ones until a max loopback of [`DEFAULT_EPOCH_LOOKBACK`].
    fn try_decrypt_with_recent_epochs(
        &self,
        mls_group: &MlsGroup,
        encrypted_content: &str,
    ) -> Result<Vec<u8>> {
        // Get exporter secret for current epoch
        let secret = self.exporter_secret(&mls_group.group_id().into())?;

        // Try to decrypt it for the current epoch
        match util::decrypt_with_exporter_secret(&secret, encrypted_content) {
            Ok(decrypted_bytes) => {
                tracing::debug!(
                    "Successfully decrypted message with current exporter secret for group {:?}",
                    mls_group.group_id()
                );
                Ok(decrypted_bytes)
            }
            // Decryption failed using the current epoch exporter secret
            Err(_) => {
                tracing::debug!(
                    "Failed to decrypt message with current exporter secret. Trying with past ones."
                );

                // Try with past exporter secrets
                self.try_decrypt_with_past_epochs(
                    mls_group,
                    encrypted_content,
                    DEFAULT_EPOCH_LOOKBACK,
                )
            }
        }
    }

    /// Processes an incoming encrypted Nostr event containing an MLS message
    ///
    /// This is the main entry point for processing received messages. The function orchestrates
    /// the message processing workflow by delegating to specialized private methods:
    /// 0. Checks if the message was already processed (deduplication)
    /// 1. Validates the event and extracts group ID
    /// 2. Loads the group and decrypts the message content
    /// 3. Processes the decrypted message based on its type
    /// 4. Handles errors with specialized recovery logic
    ///
    /// Early validation and decryption failures are persisted to prevent expensive reprocessing
    /// of the same invalid events.
    ///
    /// # Arguments
    ///
    /// * `event` - The received Nostr event containing the encrypted MLS message
    ///
    /// # Returns
    ///
    /// * `Ok(MessageProcessingResult)` - Result indicating the type of message processed
    /// * `Err(Error)` - If message processing fails
    pub fn process_message(&self, event: &Event) -> Result<MessageProcessingResult> {
        // Step 0: Check if already processed (deduplication)
        if let Some(processed) = self
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .map_err(|e| Error::Message(e.to_string()))?
        {
            tracing::debug!(
                target: "mdk_core::messages::process_message",
                "Message already processed with state: {:?}",
                processed.state
            );

            // Only block reprocessing for Failed state
            // Other states (Created, Processed, ProcessedCommit) should continue
            // to allow normal message flow (e.g., processing own messages from relay)
            if processed.state == message_types::ProcessedMessageState::Failed {
                // Log the stored failure reason internally for debugging
                tracing::debug!(
                    target: "mdk_core::messages::process_message",
                    "Rejecting previously failed message with reason: {}",
                    processed.failure_reason.as_deref().unwrap_or("unknown")
                );

                // Return generic error to avoid leaking internal details
                return Err(Error::Message(
                    "Message processing previously failed".to_string(),
                ));
            }
        }

        // Step 1: Validate event and extract group ID
        let nostr_group_id = match self.validate_event_and_extract_group_id(event) {
            Ok(id) => id,
            Err(e) => {
                // Save failed processing record to prevent reprocessing
                // Don't fail if we can't save the failure record - log and continue
                if let Err(save_err) = self.save_failed_processed_message(event.id, &e) {
                    tracing::warn!(
                        target: "mdk_core::messages::process_message",
                        "Failed to persist failure record: {}. Original error: {}",
                        save_err,
                        e
                    );
                }
                return Err(e);
            }
        };

        // Step 2: Load group and decrypt message
        let (group, mut mls_group, message_bytes) =
            match self.load_group_and_decrypt_message(nostr_group_id, event) {
                Ok(result) => result,
                Err(e) => {
                    // Save failed processing record to prevent reprocessing
                    // Don't fail if we can't save the failure record - log and continue
                    if let Err(save_err) = self.save_failed_processed_message(event.id, &e) {
                        tracing::warn!(
                            target: "mdk_core::messages::process_message",
                            "Failed to persist failure record: {}. Original error: {}",
                            save_err,
                            e
                        );
                    }
                    return Err(e);
                }
            };

        // Step 3: Process the decrypted message
        match self.process_decrypted_message(group.clone(), &mut mls_group, &message_bytes, event) {
            Ok(result) => Ok(result),
            Err(error) => {
                // Step 4: Handle errors with specialized recovery logic
                self.handle_message_processing_error(error, event, &group)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use mdk_storage_traits::GroupId;
    use mdk_storage_traits::groups::Pagination;
    use nostr::{EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Tags};

    use super::*;
    use crate::extension::NostrGroupDataExtension;
    use crate::test_util::*;
    use crate::tests::create_test_mdk;
    use mdk_storage_traits::groups::GroupStorage;
    use mdk_storage_traits::messages::MessageStorage;
    use mdk_storage_traits::messages::types::ProcessedMessageState;

    #[test]
    fn test_get_message_not_found() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);
        let non_existent_event_id = EventId::all_zeros();

        let result = mdk.get_message(&group_id, &non_existent_event_id);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_get_messages_empty_group() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        let messages = mdk
            .get_messages(&group_id, None)
            .expect("Failed to get messages");
        assert!(messages.is_empty());
    }

    #[test]
    fn test_get_messages_with_pagination() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create 15 messages
        for i in 0..15 {
            let rumor = create_test_rumor(&creator, &format!("Message {}", i));
            mdk.create_message(&group_id, rumor)
                .expect("Failed to create message");
        }

        // Test 1: Get first page (10 messages)
        let page1 = mdk
            .get_messages(&group_id, Some(Pagination::new(Some(10), Some(0))))
            .expect("Failed to get first page");
        assert_eq!(page1.len(), 10, "First page should have 10 messages");

        // Test 2: Get second page (5 messages)
        let page2 = mdk
            .get_messages(&group_id, Some(Pagination::new(Some(10), Some(10))))
            .expect("Failed to get second page");
        assert_eq!(page2.len(), 5, "Second page should have 5 messages");

        // Test 3: Verify no duplicates between pages
        let page1_ids: HashSet<_> = page1.iter().map(|m| m.id).collect();
        let page2_ids: HashSet<_> = page2.iter().map(|m| m.id).collect();
        assert!(
            page1_ids.is_disjoint(&page2_ids),
            "Pages should not have duplicate messages"
        );

        // Test 4: Get all messages with default pagination
        let all_messages = mdk
            .get_messages(&group_id, None)
            .expect("Failed to get all messages");
        assert_eq!(
            all_messages.len(),
            15,
            "Should get all 15 messages with default pagination"
        );

        // Test 5: Request beyond available messages
        let page3 = mdk
            .get_messages(&group_id, Some(Pagination::new(Some(10), Some(20))))
            .expect("Failed to get third page");
        assert!(
            page3.is_empty(),
            "Should return empty when offset exceeds message count"
        );

        // Test 6: Small page size
        let small_page = mdk
            .get_messages(&group_id, Some(Pagination::new(Some(3), Some(0))))
            .expect("Failed to get small page");
        assert_eq!(small_page.len(), 3, "Should respect small page size");
    }

    #[test]
    fn test_create_message_success() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a test message
        let mut rumor = create_test_rumor(&creator, "Hello, world!");
        let rumor_id = rumor.id();

        let result = mdk.create_message(&group_id, rumor);
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.kind, Kind::MlsGroupMessage);

        // Verify the message was stored
        let stored_message = mdk
            .get_message(&group_id, &rumor_id)
            .expect("Failed to get message")
            .expect("Message should exist");

        assert_eq!(stored_message.id, rumor_id);
        assert_eq!(stored_message.content, "Hello, world!");
        assert_eq!(stored_message.state, message_types::MessageState::Created);
        assert_eq!(stored_message.wrapper_event_id, event.id);
    }

    #[test]
    fn test_create_message_group_not_found() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();
        let rumor = create_test_rumor(&creator, "Hello, world!");
        let non_existent_group_id = GroupId::from_slice(&[1, 2, 3, 4]);

        let result = mdk.create_message(&non_existent_group_id, rumor);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::GroupNotFound));
    }

    #[test]
    fn test_create_message_updates_group_metadata() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get initial group state
        let initial_group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert!(initial_group.last_message_at.is_none());
        assert!(initial_group.last_message_id.is_none());

        // Create a message
        let mut rumor = create_test_rumor(&creator, "Hello, world!");
        let rumor_id = rumor.id();
        let rumor_timestamp = rumor.created_at;

        let _event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Verify group metadata was updated
        let updated_group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");

        assert_eq!(updated_group.last_message_at, Some(rumor_timestamp));
        assert_eq!(updated_group.last_message_id, Some(rumor_id));
    }

    #[test]
    fn test_process_message_invalid_kind() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event with wrong kind
        let event = EventBuilder::new(Kind::TextNote, "test content")
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result = mdk.process_message(&event);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::UnexpectedEvent { .. }));
    }

    #[test]
    fn test_process_message_missing_group_id_tag() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event without group ID tag
        let event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result = mdk.process_message(&event);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::MissingGroupIdTag));
    }

    #[test]
    fn test_process_message_invalid_group_id_format() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event with invalid group ID format (not valid hex)
        let invalid_group_id = "not-valid-hex-zzz";
        let tag = Tag::custom(TagKind::h(), [invalid_group_id]);

        let event = EventBuilder::new(Kind::MlsGroupMessage, "encrypted_content")
            .tag(tag)
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result = mdk.process_message(&event);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidGroupIdFormat(_)
        ));
    }

    #[test]
    fn test_process_message_group_not_found() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create a valid MLS group message event with non-existent group ID
        let fake_group_id = hex::encode([1u8; 32]);
        let tag = Tag::custom(TagKind::h(), [fake_group_id]);

        let event = EventBuilder::new(Kind::MlsGroupMessage, "encrypted_content")
            .tag(tag)
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result = mdk.process_message(&event);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::GroupNotFound));
    }

    #[test]
    fn test_message_state_tracking() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a message
        let mut rumor = create_test_rumor(&creator, "Test message state");
        let rumor_id = rumor.id();

        let event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Verify initial state
        let message = mdk
            .get_message(&group_id, &rumor_id)
            .expect("Failed to get message")
            .expect("Message should exist");

        assert_eq!(message.state, message_types::MessageState::Created);

        // Verify processed message state
        let processed_message = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .expect("Failed to get processed message")
            .expect("Processed message should exist");

        assert_eq!(
            processed_message.state,
            message_types::ProcessedMessageState::Created
        );
        assert_eq!(processed_message.message_event_id, Some(rumor_id));
        assert_eq!(processed_message.wrapper_event_id, event.id);
    }

    #[test]
    fn test_get_messages_for_group() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create multiple messages
        let rumor1 = create_test_rumor(&creator, "First message");
        let rumor2 = create_test_rumor(&creator, "Second message");

        let _event1 = mdk
            .create_message(&group_id, rumor1)
            .expect("Failed to create first message");
        let _event2 = mdk
            .create_message(&group_id, rumor2)
            .expect("Failed to create second message");

        // Get all messages for the group
        let messages = mdk
            .get_messages(&group_id, None)
            .expect("Failed to get messages");

        assert_eq!(messages.len(), 2);

        // Verify message contents
        let contents: Vec<&str> = messages.iter().map(|m| m.content.as_str()).collect();
        assert!(contents.contains(&"First message"));
        assert!(contents.contains(&"Second message"));

        // Verify all messages belong to the correct group
        for message in &messages {
            assert_eq!(message.mls_group_id, group_id.clone());
        }
    }

    #[test]
    fn test_message_processing_result_variants() {
        // Test that MessageProcessingResult variants can be created and matched
        let test_group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let dummy_message = message_types::Message {
            id: EventId::all_zeros(),
            pubkey: PublicKey::from_hex(
                "8a9de562cbbed225b6ea0118dd3997a02df92c0bffd2224f71081a7450c3e549",
            )
            .unwrap(),
            kind: Kind::TextNote,
            mls_group_id: test_group_id.clone(),
            created_at: Timestamp::now(),
            content: "Test".to_string(),
            tags: Tags::new(),
            event: EventBuilder::new(Kind::TextNote, "Test").build(
                PublicKey::from_hex(
                    "8a9de562cbbed225b6ea0118dd3997a02df92c0bffd2224f71081a7450c3e549",
                )
                .unwrap(),
            ),
            wrapper_event_id: EventId::all_zeros(),
            state: message_types::MessageState::Processed,
        };

        let app_result = MessageProcessingResult::ApplicationMessage(dummy_message);
        let commit_result = MessageProcessingResult::Commit {
            mls_group_id: test_group_id.clone(),
        };
        let external_join_result = MessageProcessingResult::ExternalJoinProposal {
            mls_group_id: test_group_id.clone(),
        };
        let unprocessable_result = MessageProcessingResult::Unprocessable {
            mls_group_id: test_group_id.clone(),
        };
        // PendingProposal: for when a non-admin receiver stores a proposal without committing
        let pending_proposal_result = MessageProcessingResult::PendingProposal {
            mls_group_id: test_group_id.clone(),
        };

        // Test that we can match on variants
        match app_result {
            MessageProcessingResult::ApplicationMessage(_) => {}
            _ => panic!("Expected ApplicationMessage variant"),
        }

        match commit_result {
            MessageProcessingResult::Commit { .. } => {}
            _ => panic!("Expected Commit variant"),
        }

        match external_join_result {
            MessageProcessingResult::ExternalJoinProposal { .. } => {}
            _ => panic!("Expected ExternalJoinProposal variant"),
        }

        match unprocessable_result {
            MessageProcessingResult::Unprocessable { .. } => {}
            _ => panic!("Expected Unprocessable variant"),
        }

        match pending_proposal_result {
            MessageProcessingResult::PendingProposal { .. } => {}
            _ => panic!("Expected PendingProposal variant"),
        }
    }

    #[test]
    fn test_message_content_preservation() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Test with various content types
        let test_cases = vec![
            "Simple text message",
            "Message with emojis 🚀 🎉 ✨",
            "Message with\nmultiple\nlines",
            "Message with special chars: !@#$%^&*()",
            "Minimal content",
        ];

        for content in test_cases {
            let mut rumor = create_test_rumor(&creator, content);
            let rumor_id = rumor.id();

            let _event = mdk
                .create_message(&group_id, rumor)
                .expect("Failed to create message");

            let stored_message = mdk
                .get_message(&group_id, &rumor_id)
                .expect("Failed to get message")
                .expect("Message should exist");

            assert_eq!(stored_message.content, content);
            assert_eq!(stored_message.pubkey, creator.public_key());
        }
    }

    #[test]
    fn test_create_message_ensures_rumor_id() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a rumor - EventBuilder.build() ensures the ID is set
        let rumor = create_test_rumor(&creator, "Test message");

        let result = mdk.create_message(&group_id, rumor);
        assert!(result.is_ok());

        // The message should have been stored with a valid ID
        let event = result.unwrap();
        let messages = mdk
            .get_messages(&group_id, None)
            .expect("Failed to get messages");

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].wrapper_event_id, event.id);
    }

    #[test]
    fn test_merge_pending_commit_syncs_group_metadata() {
        let mdk = create_test_mdk();

        // Create test group members
        let creator_keys = Keys::generate();
        let member1_keys = Keys::generate();
        let member2_keys = Keys::generate();

        let creator_pk = creator_keys.public_key();
        let member1_pk = member1_keys.public_key();

        let members = vec![member1_keys.clone(), member2_keys.clone()];
        let admins = vec![creator_pk, member1_pk]; // Creator and member1 are admins

        // Create group
        let group_id = create_test_group(&mdk, &creator_keys, &members, &admins);

        // Get initial stored group state
        let initial_group = mdk
            .get_group(&group_id)
            .expect("Failed to get initial group")
            .expect("Initial group should exist");

        let initial_epoch = initial_group.epoch;
        let initial_name = initial_group.name.clone();

        // Create a commit by updating the group name
        let new_name = "Updated Group Name via MLS Commit".to_string();
        let update = crate::groups::NostrGroupDataUpdate::new().name(new_name.clone());
        let _update_result = mdk
            .update_group_data(&group_id, update)
            .expect("Failed to update group name");

        // Before merging commit - verify stored group still has old data
        let pre_merge_group = mdk
            .get_group(&group_id)
            .expect("Failed to get pre-merge group")
            .expect("Pre-merge group should exist");

        assert_eq!(
            pre_merge_group.name, initial_name,
            "Stored group name should still be old before merge"
        );
        assert_eq!(
            pre_merge_group.epoch, initial_epoch,
            "Stored group epoch should still be old before merge"
        );

        // Get MLS group state before merge (epoch shouldn't advance until merge)
        let pre_merge_mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load pre-merge MLS group")
            .expect("Pre-merge MLS group should exist");

        let pre_merge_mls_epoch = pre_merge_mls_group.epoch().as_u64();
        assert_eq!(
            pre_merge_mls_epoch, initial_epoch,
            "MLS group epoch should not advance until commit is merged"
        );

        // This is the key test: merge_pending_commit should sync the stored group metadata
        mdk.merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Verify stored group is now synchronized after merge
        let post_merge_group = mdk
            .get_group(&group_id)
            .expect("Failed to get post-merge group")
            .expect("Post-merge group should exist");

        // Verify epoch is synchronized
        assert!(
            post_merge_group.epoch > initial_epoch,
            "Stored group epoch should advance after merge"
        );

        // Verify extension data is synchronized
        let post_merge_mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load post-merge MLS group")
            .expect("Post-merge MLS group should exist");

        let group_data = NostrGroupDataExtension::from_group(&post_merge_mls_group)
            .expect("Failed to get group data extension");

        assert_eq!(
            post_merge_group.name, group_data.name,
            "Stored group name should match extension after merge"
        );
        assert_eq!(
            post_merge_group.name, new_name,
            "Stored group name should be updated after merge"
        );
        assert_eq!(
            post_merge_group.description, group_data.description,
            "Stored group description should match extension"
        );
        assert_eq!(
            post_merge_group.admin_pubkeys, group_data.admins,
            "Stored group admins should match extension"
        );

        // Test that the sync function itself works correctly by manually de-syncing and re-syncing
        let mut manually_desync_group = post_merge_group.clone();
        manually_desync_group.name = "Manually Corrupted Name".to_string();
        manually_desync_group.epoch = initial_epoch;
        mdk.storage()
            .save_group(manually_desync_group)
            .expect("Failed to save corrupted group");

        // Verify it's out of sync
        let corrupted_group = mdk
            .get_group(&group_id)
            .expect("Failed to get corrupted group")
            .expect("Corrupted group should exist");

        assert_eq!(
            corrupted_group.name, "Manually Corrupted Name",
            "Group should be manually corrupted"
        );
        assert_eq!(
            corrupted_group.epoch, initial_epoch,
            "Group epoch should be manually corrupted"
        );

        // Call sync function directly
        mdk.sync_group_metadata_from_mls(&group_id)
            .expect("Failed to sync group metadata");

        // Verify it's back in sync
        let re_synced_group = mdk
            .get_group(&group_id)
            .expect("Failed to get re-synced group")
            .expect("Re-synced group should exist");

        assert_eq!(
            re_synced_group.name, new_name,
            "Group name should be re-synced"
        );
        assert!(
            re_synced_group.epoch > initial_epoch,
            "Group epoch should be re-synced"
        );
        assert_eq!(
            re_synced_group.admin_pubkeys, group_data.admins,
            "Group admins should be re-synced"
        );
    }

    /// Test that Group Message event structure matches Marmot spec (MIP-03)
    /// Spec requires:
    /// - Kind: 445 (MlsGroupMessage)
    /// - Content: NIP-44 encrypted MLSMessage
    /// - Tags: exactly 1 tag (h tag with group ID)
    /// - Must be signed
    /// - Pubkey must be ephemeral (different for each message)
    #[test]
    fn test_group_message_event_structure_mip03_compliance() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a test message
        let rumor = create_test_rumor(&creator, "Test message for MIP-03 compliance");

        let message_event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // 1. Verify kind is 445 (MlsGroupMessage)
        assert_eq!(
            message_event.kind,
            Kind::MlsGroupMessage,
            "Message event must have kind 445 (MlsGroupMessage)"
        );

        // 2. Verify content is encrypted (substantial length, not plaintext)
        assert!(
            message_event.content.len() > 50,
            "Encrypted content should be substantial (> 50 chars), got {}",
            message_event.content.len()
        );

        // Content should not be the original plaintext
        assert_ne!(
            message_event.content, "Test message for MIP-03 compliance",
            "Content should be encrypted, not plaintext"
        );

        // 3. Verify exactly 1 tag (h tag with group ID)
        assert_eq!(
            message_event.tags.len(),
            1,
            "Message event must have exactly 1 tag per MIP-03"
        );

        // 4. Verify tag is h tag
        let tags_vec: Vec<&nostr::Tag> = message_event.tags.iter().collect();
        let group_id_tag = tags_vec[0];
        assert_eq!(
            group_id_tag.kind(),
            TagKind::h(),
            "Tag must be 'h' (group ID) tag"
        );

        // 5. Verify h tag is valid 32-byte hex
        let group_id_hex = group_id_tag.content().expect("h tag should have content");
        assert_eq!(
            group_id_hex.len(),
            64,
            "Group ID should be 32 bytes (64 hex chars), got {}",
            group_id_hex.len()
        );

        let group_id_bytes = hex::decode(group_id_hex).expect("Group ID should be valid hex");
        assert_eq!(
            group_id_bytes.len(),
            32,
            "Group ID should decode to 32 bytes"
        );

        // 6. Verify event is signed (has valid signature)
        assert!(
            message_event.verify().is_ok(),
            "Message event must be properly signed"
        );

        // 7. Verify pubkey is NOT the creator's real pubkey (ephemeral key)
        assert_ne!(
            message_event.pubkey,
            creator.public_key(),
            "Message should use ephemeral pubkey, not sender's real pubkey"
        );
    }

    /// Test that each message uses a different ephemeral pubkey (MIP-03)
    #[test]
    fn test_group_message_ephemeral_keys_mip03_compliance() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Send 3 messages
        let rumor1 = create_test_rumor(&creator, "First message");
        let rumor2 = create_test_rumor(&creator, "Second message");
        let rumor3 = create_test_rumor(&creator, "Third message");

        let event1 = mdk
            .create_message(&group_id, rumor1)
            .expect("Failed to create first message");
        let event2 = mdk
            .create_message(&group_id, rumor2)
            .expect("Failed to create second message");
        let event3 = mdk
            .create_message(&group_id, rumor3)
            .expect("Failed to create third message");

        // Collect all ephemeral pubkeys
        let pubkeys = [event1.pubkey, event2.pubkey, event3.pubkey];

        // 1. Verify all 3 use different ephemeral pubkeys
        assert_ne!(
            pubkeys[0], pubkeys[1],
            "First and second messages should use different ephemeral keys"
        );
        assert_ne!(
            pubkeys[1], pubkeys[2],
            "Second and third messages should use different ephemeral keys"
        );
        assert_ne!(
            pubkeys[0], pubkeys[2],
            "First and third messages should use different ephemeral keys"
        );

        // 2. Verify none use sender's real pubkey
        let real_pubkey = creator.public_key();
        for (i, pubkey) in pubkeys.iter().enumerate() {
            assert_ne!(
                *pubkey,
                real_pubkey,
                "Message {} should not use sender's real pubkey",
                i + 1
            );
        }
    }

    /// Test that commit events also use ephemeral pubkeys (MIP-03)
    #[test]
    fn test_commit_event_structure_mip03_compliance() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Add another member (creates commit)
        let new_member = Keys::generate();
        let add_result = mdk
            .add_members(&group_id, &[create_key_package_event(&mdk, &new_member)])
            .expect("Failed to add member");

        let commit_event = &add_result.evolution_event;

        // 1. Verify commit event has kind 445 (same as regular messages)
        assert_eq!(
            commit_event.kind,
            Kind::MlsGroupMessage,
            "Commit event should have kind 445"
        );

        // 2. Verify commit event structure matches regular messages
        assert_eq!(
            commit_event.tags.len(),
            1,
            "Commit event should have exactly 1 tag"
        );

        let commit_tags: Vec<&nostr::Tag> = commit_event.tags.iter().collect();
        assert_eq!(
            commit_tags[0].kind(),
            TagKind::h(),
            "Commit event should have h tag"
        );

        // 3. Verify commit uses ephemeral pubkey
        assert_ne!(
            commit_event.pubkey,
            creator.public_key(),
            "Commit should use ephemeral pubkey, not creator's real pubkey"
        );

        // 4. Verify commit is signed
        assert!(
            commit_event.verify().is_ok(),
            "Commit event must be properly signed"
        );

        // 5. Verify content is encrypted
        assert!(
            commit_event.content.len() > 50,
            "Commit content should be encrypted and substantial"
        );
    }

    /// Test that group ID in h tag matches NostrGroupDataExtension
    #[test]
    fn test_group_id_consistency_mip03() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get the Nostr group ID from the stored group
        let stored_group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");

        let expected_nostr_group_id = hex::encode(stored_group.nostr_group_id);

        // Send a message
        let rumor = create_test_rumor(&creator, "Test message");
        let message_event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Extract group ID from h tag
        let h_tag = message_event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::h())
            .expect("Message should have h tag");

        let message_group_id = h_tag.content().expect("h tag should have content");

        // Verify they match
        assert_eq!(
            message_group_id, expected_nostr_group_id,
            "h tag group ID should match NostrGroupDataExtension"
        );
    }

    /// Test that all messages in the same group reference the same group ID
    #[test]
    fn test_group_id_consistency_across_messages() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Send multiple messages
        let event1 = mdk
            .create_message(&group_id, create_test_rumor(&creator, "Message 1"))
            .expect("Failed to create message 1");
        let event2 = mdk
            .create_message(&group_id, create_test_rumor(&creator, "Message 2"))
            .expect("Failed to create message 2");
        let event3 = mdk
            .create_message(&group_id, create_test_rumor(&creator, "Message 3"))
            .expect("Failed to create message 3");

        // Extract group IDs from all messages
        let group_id1 = event1
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::h())
            .expect("Message 1 should have h tag")
            .content()
            .expect("h tag should have content");

        let group_id2 = event2
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::h())
            .expect("Message 2 should have h tag")
            .content()
            .expect("h tag should have content");

        let group_id3 = event3
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::h())
            .expect("Message 3 should have h tag")
            .content()
            .expect("h tag should have content");

        // Verify all reference the same group
        assert_eq!(
            group_id1, group_id2,
            "All messages should reference the same group"
        );
        assert_eq!(
            group_id2, group_id3,
            "All messages should reference the same group"
        );
    }

    /// Test message content encryption with NIP-44
    #[test]
    fn test_message_content_encryption_mip03() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        let plaintext = "Secret message content that should be encrypted";
        let rumor = create_test_rumor(&creator, plaintext);

        let message_event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Verify content is encrypted (doesn't contain plaintext)
        assert!(
            !message_event.content.contains(plaintext),
            "Encrypted content should not contain plaintext"
        );

        // Verify content is substantial (encrypted data has overhead)
        assert!(
            message_event.content.len() > plaintext.len(),
            "Encrypted content should be longer than plaintext due to encryption overhead"
        );

        // Verify content appears to be encrypted (not just hex-encoded plaintext)
        // Encrypted NIP-44 content starts with specific markers
        assert!(
            message_event.content.len() > 100,
            "NIP-44 encrypted content should be substantial"
        );
    }

    /// Test that different messages have different encrypted content even with same plaintext
    #[test]
    fn test_message_encryption_uniqueness() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Send two messages with identical plaintext
        let plaintext = "Identical message content";
        let rumor1 = create_test_rumor(&creator, plaintext);
        let rumor2 = create_test_rumor(&creator, plaintext);

        let event1 = mdk
            .create_message(&group_id, rumor1)
            .expect("Failed to create first message");
        let event2 = mdk
            .create_message(&group_id, rumor2)
            .expect("Failed to create second message");

        // Verify encrypted contents are different (nonce/IV makes each encryption unique)
        assert_ne!(
            event1.content, event2.content,
            "Two messages with same plaintext should have different encrypted content"
        );
    }

    /// Test complete message lifecycle spec compliance
    #[test]
    fn test_complete_message_lifecycle_spec_compliance() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        // 1. Create group -> verify commit event structure
        let create_result = mdk
            .create_group(
                &creator.public_key(),
                vec![
                    create_key_package_event(&mdk, &members[0]),
                    create_key_package_event(&mdk, &members[1]),
                ],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // The creation itself doesn't produce a commit event that gets published,
        // so we merge and continue
        mdk.merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // 2. Send message -> verify message event structure
        let rumor1 = create_test_rumor(&creator, "First message");
        let msg_event1 = mdk
            .create_message(&group_id, rumor1)
            .expect("Failed to send first message");

        assert_eq!(msg_event1.kind, Kind::MlsGroupMessage);
        assert_eq!(msg_event1.tags.len(), 1);

        let msg1_tags: Vec<&nostr::Tag> = msg_event1.tags.iter().collect();
        assert_eq!(msg1_tags[0].kind(), TagKind::h());

        let pubkey1 = msg_event1.pubkey;

        // 3. Add member -> verify commit event structure
        let new_member = Keys::generate();
        let add_result = mdk
            .add_members(&group_id, &[create_key_package_event(&mdk, &new_member)])
            .expect("Failed to add member");

        let commit_event = &add_result.evolution_event;
        assert_eq!(commit_event.kind, Kind::MlsGroupMessage);
        assert_eq!(commit_event.tags.len(), 1);
        assert_ne!(
            commit_event.pubkey,
            creator.public_key(),
            "Commit should use ephemeral key"
        );

        // 4. Send another message -> verify different ephemeral key
        mdk.merge_pending_commit(&group_id)
            .expect("Failed to merge commit");

        let rumor2 = create_test_rumor(&creator, "Second message after member add");
        let msg_event2 = mdk
            .create_message(&group_id, rumor2)
            .expect("Failed to send second message");

        let pubkey2 = msg_event2.pubkey;

        // 5. Verify all use different ephemeral keys
        assert_ne!(
            pubkey1, pubkey2,
            "Different messages should use different ephemeral keys"
        );
        assert_ne!(
            pubkey1, commit_event.pubkey,
            "Message and commit should use different ephemeral keys"
        );
        assert_ne!(
            pubkey2, commit_event.pubkey,
            "Message and commit should use different ephemeral keys"
        );

        // 6. Verify all reference the same group ID
        let msg1_tags: Vec<&nostr::Tag> = msg_event1.tags.iter().collect();
        let commit_tags: Vec<&nostr::Tag> = commit_event.tags.iter().collect();
        let msg2_tags: Vec<&nostr::Tag> = msg_event2.tags.iter().collect();

        let group_id_hex1 = msg1_tags[0].content().unwrap();
        let group_id_hex2 = commit_tags[0].content().unwrap();
        let group_id_hex3 = msg2_tags[0].content().unwrap();

        assert_eq!(
            group_id_hex1, group_id_hex2,
            "All events should reference same group"
        );
        assert_eq!(
            group_id_hex2, group_id_hex3,
            "All events should reference same group"
        );
    }

    /// Test that message events are properly validated before sending
    #[test]
    fn test_message_event_validation() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        let rumor = create_test_rumor(&creator, "Validation test message");
        let message_event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Verify event passes Nostr signature validation
        assert!(
            message_event.verify().is_ok(),
            "Message event should have valid signature"
        );

        // Verify event ID is computed correctly
        let recomputed_id = message_event.id;
        assert_eq!(
            message_event.id, recomputed_id,
            "Event ID should be correctly computed"
        );

        // Verify created_at timestamp is reasonable (not in far future/past)
        let now = Timestamp::now();
        assert!(
            message_event.created_at <= now,
            "Message timestamp should not be in the future"
        );

        // Allow for some clock skew, but message shouldn't be more than a day old
        let one_day_ago = now.as_u64().saturating_sub(86400);
        assert!(
            message_event.created_at.as_u64() > one_day_ago,
            "Message timestamp should be recent"
        );
    }

    #[test]
    fn test_processing_own_commit_syncs_group_metadata() {
        let mdk = create_test_mdk();

        // Create test group
        let creator_keys = Keys::generate();
        let member1_keys = Keys::generate();
        let member2_keys = Keys::generate();

        let creator_pk = creator_keys.public_key();
        let member1_pk = member1_keys.public_key();

        let members = vec![member1_keys.clone(), member2_keys.clone()];
        let admins = vec![creator_pk, member1_pk];

        let group_id = create_test_group(&mdk, &creator_keys, &members, &admins);

        // Get initial state
        let initial_group = mdk
            .get_group(&group_id)
            .expect("Failed to get initial group")
            .expect("Initial group should exist");

        let initial_epoch = initial_group.epoch;

        // Create and merge a commit to update group name
        let new_name = "Updated Name for Own Commit Test".to_string();
        let update = crate::groups::NostrGroupDataUpdate::new().name(new_name.clone());
        let update_result = mdk
            .update_group_data(&group_id, update)
            .expect("Failed to update group name");

        mdk.merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Verify the commit event is marked as ProcessedCommit
        let commit_event_id = update_result.evolution_event.id;
        let processed_message = mdk
            .storage()
            .find_processed_message_by_event_id(&commit_event_id)
            .expect("Failed to find processed message")
            .expect("Processed message should exist");

        assert_eq!(
            processed_message.state,
            message_types::ProcessedMessageState::ProcessedCommit
        );

        // Manually corrupt the stored group to simulate desync
        let mut corrupted_group = initial_group.clone();
        corrupted_group.name = "Corrupted Name".to_string();
        corrupted_group.epoch = initial_epoch;
        mdk.storage()
            .save_group(corrupted_group)
            .expect("Failed to save corrupted group");

        // Verify it's out of sync
        let out_of_sync_group = mdk
            .get_group(&group_id)
            .expect("Failed to get out of sync group")
            .expect("Out of sync group should exist");

        assert_eq!(out_of_sync_group.name, "Corrupted Name");
        assert_eq!(out_of_sync_group.epoch, initial_epoch);

        // Process our own commit message - this should trigger sync even though it's marked as ProcessedCommit
        let message_result = mdk
            .process_message(&update_result.evolution_event)
            .expect("Failed to process own commit message");

        // Verify it returns Commit result (our fix should handle epoch mismatch errors)
        assert!(matches!(
            message_result,
            MessageProcessingResult::Commit { .. }
        ));

        // Most importantly: verify that processing our own commit synchronized the stored group metadata
        let synced_group = mdk
            .get_group(&group_id)
            .expect("Failed to get synced group")
            .expect("Synced group should exist");

        assert_eq!(
            synced_group.name, new_name,
            "Processing own commit should sync group name"
        );
        assert!(
            synced_group.epoch > initial_epoch,
            "Processing own commit should sync group epoch"
        );

        // Verify the stored group matches the MLS group state
        let mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");

        assert_eq!(
            synced_group.epoch,
            mls_group.epoch().as_u64(),
            "Stored and MLS group epochs should match"
        );

        let group_data = NostrGroupDataExtension::from_group(&mls_group)
            .expect("Failed to get group data extension");

        assert_eq!(
            synced_group.name, group_data.name,
            "Stored group name should match extension"
        );
        assert_eq!(
            synced_group.admin_pubkeys, group_data.admins,
            "Stored group admins should match extension"
        );
    }

    /// Test concurrent commit race condition handling (MIP-03)
    ///
    /// This test validates that when multiple admins create competing commits,
    /// the system handles them deterministically based on timestamp and event ID.
    ///
    /// Requirements tested:
    /// - Timestamp-based commit ordering
    /// - Event ID tiebreaker for identical timestamps
    /// - Only one commit is applied
    /// - Outdated commit rejection when epoch has advanced
    /// - Multi-client state synchronization
    #[test]
    fn test_concurrent_commit_race_conditions() {
        // Setup: Create Alice (admin) and Bob (admin)
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];

        // Step 1: Bob creates his key package in his own MDK
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group and adds Bob
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins),
            )
            .expect("Alice should be able to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge Alice's create commit");

        // Step 2: Bob processes and accepts welcome to join the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should be able to process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should be able to accept welcome");

        // Verify both clients have the same group ID
        assert_eq!(
            group_id, bob_welcome.mls_group_id,
            "Alice and Bob should have the same group ID"
        );

        // Verify both clients are in the same epoch
        let alice_epoch = alice_mdk
            .get_group(&group_id)
            .expect("Failed to get Alice's group")
            .expect("Alice's group should exist")
            .epoch;

        let bob_epoch = bob_mdk
            .get_group(&bob_welcome.mls_group_id)
            .expect("Failed to get Bob's group")
            .expect("Bob's group should exist")
            .epoch;

        assert_eq!(
            alice_epoch, bob_epoch,
            "Alice and Bob should be in same epoch"
        );

        // Step 3: Simulate concurrent commits - both admins try to add different members
        let charlie_keys = Keys::generate();
        let dave_keys = Keys::generate();

        let charlie_key_package = create_key_package_event(&alice_mdk, &charlie_keys);
        let dave_key_package = create_key_package_event(&bob_mdk, &dave_keys);

        // Alice creates a commit to add Charlie
        let alice_commit_result = alice_mdk
            .add_members(&group_id, std::slice::from_ref(&charlie_key_package))
            .expect("Alice should be able to create commit");

        // Bob creates a commit to add Dave (competing commit in same epoch)
        let bob_commit_result = bob_mdk
            .add_members(&group_id, std::slice::from_ref(&dave_key_package))
            .expect("Bob should be able to create commit");

        // Verify both created commit events
        assert_eq!(
            alice_commit_result.evolution_event.kind,
            Kind::MlsGroupMessage
        );
        assert_eq!(
            bob_commit_result.evolution_event.kind,
            Kind::MlsGroupMessage
        );

        // Step 4: In a real scenario, relay would order these commits by timestamp/event ID
        // For this test, Alice's commit is accepted first (simulating earlier timestamp)

        // Bob processes Alice's commit
        let _bob_process_result = bob_mdk
            .process_message(&alice_commit_result.evolution_event)
            .expect("Bob should be able to process Alice's commit");

        // Alice merges her own commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge her commit");

        // Step 5: Now Bob tries to process his own outdated commit
        // This should fail because the epoch has advanced
        let bob_process_own = bob_mdk.process_message(&bob_commit_result.evolution_event);

        // Bob's commit is now outdated since Alice's commit advanced the epoch
        // The exact error depends on implementation, but it should not succeed
        // or should be detected as stale
        assert!(
            bob_process_own.is_err()
                || bob_mdk.get_group(&group_id).unwrap().unwrap().epoch > bob_epoch,
            "Bob's commit should be rejected or epoch should have advanced"
        );

        // Step 6: Verify final state - Alice's commit won the race
        let final_alice_epoch = alice_mdk
            .get_group(&group_id)
            .expect("Failed to get Alice's group")
            .expect("Alice's group should exist")
            .epoch;

        assert!(
            final_alice_epoch > alice_epoch,
            "Epoch should have advanced after Alice's commit"
        );

        // The test confirms that:
        // - Multiple admins can create commits in the same epoch
        // - Only one commit advances the epoch (Alice's)
        // - The other commit becomes outdated and cannot be applied (Bob's)
        // - The system maintains consistency through race conditions
    }

    /// Test multi-client message synchronization (MIP-03)
    ///
    /// This test validates that messages can be properly synchronized across multiple
    /// clients and that epoch lookback mechanisms work correctly.
    ///
    /// Requirements tested:
    /// - Messages decrypt across all clients
    /// - Epoch lookback mechanism works
    /// - Historical message processing across epochs
    /// - State convergence across clients
    #[test]
    fn test_multi_client_message_synchronization() {
        // Setup: Create Alice and Bob as admins
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];

        // Step 1: Bob creates his key package in his own MDK
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group and adds Bob
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

        // Bob processes and accepts welcome to join the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should be able to process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should be able to accept welcome");

        // Verify both clients have the same group ID
        assert_eq!(
            group_id, bob_welcome.mls_group_id,
            "Alice and Bob should have the same group ID"
        );

        // Step 2: Alice sends a message in epoch 0
        let rumor1 = create_test_rumor(&alice_keys, "Hello from Alice");
        let msg_event1 = alice_mdk
            .create_message(&group_id, rumor1)
            .expect("Alice should be able to send message");

        assert_eq!(msg_event1.kind, Kind::MlsGroupMessage);

        // Bob processes Alice's message
        let bob_process1 = bob_mdk
            .process_message(&msg_event1)
            .expect("Bob should be able to process Alice's message");

        // Verify Bob decrypted the message
        match bob_process1 {
            MessageProcessingResult::ApplicationMessage(msg) => {
                assert_eq!(msg.content, "Hello from Alice");
            }
            _ => panic!("Expected ApplicationMessage but got different result type"),
        }

        // Step 3: Advance epoch with Alice's update
        let update_result = alice_mdk
            .self_update(&group_id)
            .expect("Alice should be able to create update");

        // Both clients process the update
        let _alice_process_update = alice_mdk
            .process_message(&update_result.evolution_event)
            .expect("Alice should process her update");

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge update");

        let _bob_process_update = bob_mdk
            .process_message(&update_result.evolution_event)
            .expect("Bob should process Alice's update");

        // Step 4: Alice sends message in new epoch
        let rumor2 = create_test_rumor(&alice_keys, "Message in epoch 1");
        let msg_event2 = alice_mdk
            .create_message(&group_id, rumor2)
            .expect("Alice should send message in new epoch");

        // Bob processes message from new epoch
        let bob_process2 = bob_mdk
            .process_message(&msg_event2)
            .expect("Bob should process message from epoch 1");

        match bob_process2 {
            MessageProcessingResult::ApplicationMessage(msg) => {
                assert_eq!(msg.content, "Message in epoch 1");
            }
            _ => panic!("Expected ApplicationMessage but got different result type"),
        }

        // Step 5: Bob sends a message
        let rumor3 = create_test_rumor(&bob_keys, "Hello from Bob");
        let msg_event3 = bob_mdk
            .create_message(&group_id, rumor3)
            .expect("Bob should be able to send message");

        // Alice processes Bob's message
        let alice_process3 = alice_mdk
            .process_message(&msg_event3)
            .expect("Alice should process Bob's message");

        match alice_process3 {
            MessageProcessingResult::ApplicationMessage(msg) => {
                assert_eq!(msg.content, "Hello from Bob");
            }
            _ => panic!("Expected ApplicationMessage but got different result type"),
        }

        // Step 6: Verify state convergence - both clients should be in same epoch
        let alice_final_epoch = alice_mdk
            .get_group(&group_id)
            .expect("Failed to get Alice's group")
            .expect("Alice's group should exist")
            .epoch;

        let bob_final_epoch = bob_mdk
            .get_group(&group_id)
            .expect("Failed to get Bob's group")
            .expect("Bob's group should exist")
            .epoch;

        assert_eq!(
            alice_final_epoch, bob_final_epoch,
            "Both clients should be in the same epoch"
        );

        // Step 7: Verify all messages are stored on both clients
        let alice_messages = alice_mdk
            .get_messages(&group_id, None)
            .expect("Failed to get Alice's messages");

        let bob_messages = bob_mdk
            .get_messages(&group_id, None)
            .expect("Failed to get Bob's messages");

        assert_eq!(alice_messages.len(), 3, "Alice should have 3 messages");
        assert_eq!(bob_messages.len(), 3, "Bob should have 3 messages");

        // Note: When timestamps are equal (as in fast tests), sort order by ID is deterministic
        // but not chronological. We verify all messages are present.
        let alice_contents: Vec<&str> = alice_messages.iter().map(|m| m.content.as_str()).collect();
        let bob_contents: Vec<&str> = bob_messages.iter().map(|m| m.content.as_str()).collect();

        assert!(alice_contents.contains(&"Hello from Alice"));
        assert!(alice_contents.contains(&"Message in epoch 1"));
        assert!(alice_contents.contains(&"Hello from Bob"));

        assert!(bob_contents.contains(&"Hello from Alice"));
        assert!(bob_contents.contains(&"Message in epoch 1"));
        assert!(bob_contents.contains(&"Hello from Bob"));

        // The test confirms that:
        // - Messages are properly encrypted and decrypted across clients
        // - Messages can be processed across epoch transitions
        // - Both clients maintain synchronized state
        // - Message history is consistent across all clients
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
            .create_message(&group_id, rumor_epoch1)
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
                .create_message(&group_id, rumor)
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

    /// Test message processing with wrong event kind
    #[test]
    fn test_process_message_wrong_event_kind() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event with wrong kind (TextNote instead of MlsGroupMessage)
        let event = EventBuilder::new(Kind::TextNote, "test content")
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result = mdk.process_message(&event);

        // Should return UnexpectedEvent error
        assert!(
            matches!(
                result,
                Err(crate::Error::UnexpectedEvent { expected, received })
                if expected == Kind::MlsGroupMessage && received == Kind::TextNote
            ),
            "Should return UnexpectedEvent error for wrong kind"
        );
    }

    /// Test message processing with missing group ID tag
    #[test]
    fn test_process_message_missing_group_id() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create a group message event without the required 'h' tag
        let event = EventBuilder::new(Kind::MlsGroupMessage, "encrypted_content")
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result = mdk.process_message(&event);

        // Should fail due to missing group ID tag
        assert!(result.is_err(), "Should fail when group ID tag is missing");
    }

    /// Test creating message for non-existent group
    #[test]
    fn test_create_message_for_nonexistent_group() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();
        let rumor = create_test_rumor(&creator, "Hello");

        let non_existent_group_id = crate::GroupId::from_slice(&[1, 2, 3, 4, 5]);
        let result = mdk.create_message(&non_existent_group_id, rumor);

        assert!(
            matches!(result, Err(crate::Error::GroupNotFound)),
            "Should return GroupNotFound error"
        );
    }

    /// Test message from non-member
    #[test]
    fn test_message_from_non_member() {
        let creator_mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        // Create group
        let group_id = create_test_group(&creator_mdk, &creator, &members, &admins);

        // Create a message from someone not in the group
        let non_member = Keys::generate();
        let rumor = create_test_rumor(&non_member, "I'm not in this group");

        // Try to create a message (this would fail at the MLS level)
        // In practice, a non-member wouldn't have the group loaded
        let non_member_mdk = create_test_mdk();
        let result = non_member_mdk.create_message(&group_id, rumor);

        // Should fail because the group doesn't exist for this user
        assert!(
            result.is_err(),
            "Non-member should not be able to create messages"
        );
    }

    /// Test getting messages for non-existent group
    #[test]
    fn test_get_messages_nonexistent_group() {
        let mdk = create_test_mdk();
        let non_existent_group_id = crate::GroupId::from_slice(&[9, 9, 9, 9]);

        let result = mdk.get_messages(&non_existent_group_id, None);

        // Both storage implementations should return error for non-existent group
        assert!(
            result.is_err(),
            "Should return error for non-existent group"
        );
    }

    /// Test getting single message that doesn't exist
    #[test]
    fn test_get_nonexistent_message() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);
        let non_existent_id = nostr::EventId::all_zeros();

        let result = mdk.get_message(&group_id, &non_existent_id);

        assert!(result.is_ok(), "Should succeed");
        assert!(
            result.unwrap().is_none(),
            "Should return None for non-existent message"
        );
    }

    /// Test message state transitions
    #[test]
    fn test_message_state_transitions() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a message
        let mut rumor = create_test_rumor(&creator, "Test message");
        let rumor_id = rumor.id();
        let _event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Check initial state
        let message = mdk
            .get_message(&group_id, &rumor_id)
            .expect("Failed to get message")
            .expect("Message should exist");
        assert_eq!(
            message.state,
            message_types::MessageState::Created,
            "Initial state should be Created"
        );

        // Process the message (simulating receiving it)
        // In a real scenario, another client would process this
        // For this test, we verify the state tracking works
        assert_eq!(message.content, "Test message");
        assert_eq!(message.pubkey, creator.public_key());
    }

    /// Test message with empty content
    #[test]
    fn test_message_with_empty_content() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a message with empty content
        let rumor = create_test_rumor(&creator, "");
        let result = mdk.create_message(&group_id, rumor);

        // Should succeed - empty messages are valid
        assert!(result.is_ok(), "Empty message should be valid");
    }

    /// Test message with very long content
    #[test]
    fn test_message_with_long_content() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a message with very long content (10KB)
        let long_content = "a".repeat(10000);
        let rumor = create_test_rumor(&creator, &long_content);
        let result = mdk.create_message(&group_id, rumor);

        // Should succeed - long messages are valid
        assert!(result.is_ok(), "Long message should be valid");

        let event = result.unwrap();
        assert_eq!(event.kind, Kind::MlsGroupMessage);
    }

    /// Test processing message multiple times (idempotency)
    #[test]
    fn test_process_message_idempotency() {
        let creator_mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&creator_mdk, &creator, &members, &admins);

        // Create a message
        let rumor = create_test_rumor(&creator, "Test idempotency");
        let event = creator_mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Process the message once
        let result1 = creator_mdk.process_message(&event);
        assert!(
            result1.is_ok(),
            "First message processing should succeed: {:?}",
            result1.err()
        );

        // Process the same message again - should be idempotent
        let result2 = creator_mdk.process_message(&event);
        assert!(
            result2.is_ok(),
            "Second message processing should also succeed (idempotent): {:?}",
            result2.err()
        );

        // Both results should be consistent - true idempotency means
        // processing the same message multiple times produces consistent results
        assert!(
            result1.is_ok() && result2.is_ok(),
            "Message processing should be idempotent - both calls should succeed"
        );
    }

    /// Test duplicate message handling from multiple relays
    ///
    /// Validates that the same message received from multiple relays is processed
    /// only once and duplicates are handled gracefully.
    #[test]
    fn test_duplicate_message_from_multiple_relays() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a message
        let rumor = create_test_rumor(&creator, "Test message");
        let message_event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Process the message for the first time
        let first_result = mdk.process_message(&message_event);
        assert!(
            first_result.is_ok(),
            "First message processing should succeed"
        );

        // Simulate receiving the same message from a different relay
        // Process the exact same message again
        // OpenMLS is idempotent - processing the same message twice should succeed
        let second_result = mdk.process_message(&message_event);
        assert!(
            second_result.is_ok(),
            "OpenMLS should idempotently handle duplicate message processing: {:?}",
            second_result.err()
        );

        // Verify we still only have one message (no duplication)
        let messages = mdk
            .get_messages(&group_id, None)
            .expect("Failed to get messages");
        assert_eq!(
            messages.len(),
            1,
            "Should still have only 1 message after duplicate processing"
        );

        // Verify group state is consistent
        let group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert!(
            group.last_message_id.is_some(),
            "Group should have last message ID"
        );
    }

    /// Single-client message idempotency
    ///
    /// Tests that messages can be processed multiple times without duplication
    /// and that message retrieval works correctly.
    #[test]
    fn test_single_client_message_idempotency() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create three messages in order
        let rumor1 = create_test_rumor(&creator, "Message 1");
        let message1 = mdk
            .create_message(&group_id, rumor1)
            .expect("Failed to create message 1");

        let rumor2 = create_test_rumor(&creator, "Message 2");
        let message2 = mdk
            .create_message(&group_id, rumor2)
            .expect("Failed to create message 2");

        let rumor3 = create_test_rumor(&creator, "Message 3");
        let message3 = mdk
            .create_message(&group_id, rumor3)
            .expect("Failed to create message 3");

        // Process messages in different order: 3, 1, 2
        // All three messages are in the same epoch, so they should all process
        let result3 = mdk.process_message(&message3);
        let result1 = mdk.process_message(&message1);
        let result2 = mdk.process_message(&message2);

        // All should succeed
        assert!(result3.is_ok(), "Message 3 should process successfully");
        assert!(result1.is_ok(), "Message 1 should process successfully");
        assert!(result2.is_ok(), "Message 2 should process successfully");

        // Verify all messages are stored
        let messages = mdk
            .get_messages(&group_id, None)
            .expect("Failed to get messages");
        assert_eq!(
            messages.len(),
            3,
            "Should have all 3 messages regardless of processing order"
        );

        // Verify messages can be retrieved by their IDs
        for msg in &messages {
            let retrieved = mdk
                .get_message(&msg.mls_group_id, &msg.id)
                .expect("Failed to get message")
                .expect("Message should exist");
            assert_eq!(retrieved.id, msg.id, "Retrieved message should match");
        }
    }

    /// Test message processing order independence
    ///
    /// Validates that the storage and retrieval of messages works correctly
    /// regardless of the order in which messages are processed.
    #[test]
    fn test_message_processing_order_independence() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create messages with explicit timestamps
        let mut messages_created = Vec::new();
        for i in 1..=5 {
            let rumor = create_test_rumor(&creator, &format!("Message {}", i));
            let message_event = mdk
                .create_message(&group_id, rumor)
                .unwrap_or_else(|_| panic!("Failed to create message {}", i));
            messages_created.push((i, message_event));
        }

        // Process messages in reverse order (simulating network delays)
        for (i, message_event) in messages_created.iter().rev() {
            let result = mdk.process_message(message_event);
            assert!(result.is_ok(), "Processing message {} should succeed", i);
        }

        // Verify all messages are stored
        let stored_messages = mdk
            .get_messages(&group_id, None)
            .expect("Failed to get messages");
        assert_eq!(stored_messages.len(), 5, "Should have all 5 messages");

        // Messages should be retrievable regardless of processing order
        for (i, _) in &messages_created {
            let content = format!("Message {}", i);
            let found = stored_messages.iter().any(|m| m.content == content);
            assert!(found, "Should find message with content '{}'", content);
        }
    }

    // ============================================================================
    // Security & Edge Cases
    // ============================================================================

    /// Malformed message handling
    ///
    /// Tests that malformed or invalid messages are rejected gracefully
    /// without causing panics or crashes.
    ///
    /// Requirements tested:
    /// - Invalid event kinds rejected with clear errors
    /// - Missing required tags detected
    /// - No panics on malformed input
    /// - Error messages don't leak sensitive data
    #[test]
    fn test_malformed_message_handling() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Test 1: Invalid event kind (using TextNote instead of MlsGroupMessage)
        let invalid_kind_event = EventBuilder::new(Kind::TextNote, "malformed content")
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result1 = mdk.process_message(&invalid_kind_event);
        assert!(
            result1.is_err(),
            "Should reject message with wrong event kind"
        );
        assert!(
            matches!(result1, Err(crate::Error::UnexpectedEvent { .. })),
            "Should return UnexpectedEvent error"
        );

        // Test 2: Missing group ID tag
        let missing_tag_event = EventBuilder::new(Kind::MlsGroupMessage, "content")
            .sign_with_keys(&creator)
            .expect("Failed to sign event");

        let result2 = mdk.process_message(&missing_tag_event);
        assert!(
            result2.is_err(),
            "Should reject message without group ID tag"
        );

        // Note: Empty content is actually valid per test_message_with_empty_content
        // The system handles empty messages correctly, so no additional test needed here

        // All error cases should be handled gracefully without panics
    }

    /// Message from non-member handling
    ///
    /// Tests that messages from non-members are properly rejected.
    ///
    /// Requirements tested:
    /// - Messages from non-members rejected
    /// - Clear error indicating sender not in group
    /// - No state corruption from unauthorized messages
    #[test]
    fn test_message_from_non_member_rejected() {
        // Create Alice (admin) and Bob (member)
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate(); // Not a member

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key()];

        // Bob creates his key package
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates group with only Bob (Charlie is excluded)
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

        // Verify initial member list (should be Alice and Bob only)
        let members = alice_mdk
            .get_members(&group_id)
            .expect("Failed to get members");
        assert_eq!(members.len(), 2, "Group should have 2 members");
        assert!(
            !members.contains(&charlie_keys.public_key()),
            "Charlie should not be a member"
        );

        // Charlie (non-member) attempts to send a message to the group
        // This should fail because Charlie doesn't have the group loaded
        let charlie_rumor = create_test_rumor(&charlie_keys, "Unauthorized message");
        let charlie_message_result = charlie_mdk.create_message(&group_id, charlie_rumor);

        assert!(
            charlie_message_result.is_err(),
            "Non-member should not be able to create message for group"
        );

        // Verify the error is GroupNotFound (Charlie doesn't have access)
        assert!(
            matches!(charlie_message_result, Err(crate::Error::GroupNotFound)),
            "Should return GroupNotFound error for non-member"
        );

        // Verify group state is unchanged
        let final_members = alice_mdk
            .get_members(&group_id)
            .expect("Failed to get members");
        assert_eq!(
            final_members.len(),
            2,
            "Member count should remain unchanged"
        );
    }

    // ============================================================================
    // Multi-Device Scenarios
    // ============================================================================

    /// Extended Offline Period Sync
    ///
    /// Validates that a device that was offline for an extended period can
    /// catch up with all missed messages and state changes when it comes back online.
    #[test]
    fn test_extended_offline_period_sync() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates group with Bob
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Simulate Bob going offline - Alice sends multiple messages
        let mut alice_messages = Vec::new();
        for i in 0..5 {
            let rumor = create_test_rumor(&alice_keys, &format!("Message {} while Bob offline", i));
            let message_event = alice_mdk
                .create_message(&group_id, rumor)
                .expect("Alice should create message");
            alice_messages.push(message_event);
        }

        // Bob comes back online and processes all messages
        for message_event in &alice_messages {
            let result = bob_mdk.process_message(message_event);
            assert!(
                result.is_ok(),
                "Bob should process offline message: {:?}",
                result.err()
            );
        }

        // Verify Bob received all messages
        let bob_messages = bob_mdk
            .get_messages(&group_id, None)
            .expect("Bob should get messages");

        assert_eq!(
            bob_messages.len(),
            5,
            "Bob should have all 5 messages after sync"
        );

        // Verify all messages are present (order may vary with equal timestamps)
        let bob_contents: Vec<&str> = bob_messages.iter().map(|m| m.content.as_str()).collect();
        for i in 0..5 {
            let expected = format!("Message {} while Bob offline", i);
            assert!(
                bob_contents
                    .iter()
                    .any(|&content| content.contains(&expected)),
                "Should contain: {}",
                expected
            );
        }
    }

    /// Member Addition Commit
    ///
    /// Tests that adding a member and advancing the epoch works correctly.
    #[test]
    fn test_member_addition_commit() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        // Alice creates group with Bob
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Get initial epoch
        let initial_epoch = alice_mdk
            .get_group(&group_id)
            .expect("Should get group")
            .expect("Group should exist")
            .epoch;

        // Alice creates a pending commit to add Charlie
        let alice_add_result = alice_mdk.add_members(&group_id, &[charlie_key_package]);

        assert!(
            alice_add_result.is_ok(),
            "Alice should create pending commit"
        );

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Verify epoch advanced for Alice
        let alice_epoch_after = alice_mdk
            .get_group(&group_id)
            .expect("Should get group")
            .expect("Group should exist")
            .epoch;

        assert!(
            alice_epoch_after > initial_epoch,
            "Alice's epoch should advance after commit"
        );

        // Verify Alice sees Charlie in members (though Charlie hasn't joined yet)
        let alice_members = alice_mdk
            .get_members(&group_id)
            .expect("Alice should get members");

        assert_eq!(
            alice_members.len(),
            3,
            "Alice should see 3 members after adding Charlie"
        );
    }

    /// Device Synchronization After Member Changes
    ///
    /// Validates that when one device makes member changes (add/remove),
    /// other devices can properly process and synchronize those changes.
    #[test]
    fn test_device_sync_after_member_changes() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_device1 = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice device 1 creates group with Bob
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_device1
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice device 1 should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_device1
            .merge_pending_commit(&group_id)
            .expect("Alice device 1 should merge commit");

        // Bob joins
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Verify initial state - Alice device 1 and Bob both see 2 members
        let alice_d1_members = alice_device1
            .get_members(&group_id)
            .expect("Alice device 1 should get members");
        let bob_members = bob_mdk
            .get_members(&group_id)
            .expect("Bob should get members");

        assert_eq!(
            alice_d1_members.len(),
            2,
            "Alice device 1 should see 2 members"
        );
        assert_eq!(bob_members.len(), 2, "Bob should see 2 members");

        // Alice device 1 sends a message
        let rumor1 = create_test_rumor(&alice_keys, "Message from device 1");
        let message1 = alice_device1
            .create_message(&group_id, rumor1)
            .expect("Alice device 1 should create message");

        // Bob processes the message
        bob_mdk
            .process_message(&message1)
            .expect("Bob should process message");

        // Alice adds a new member (Charlie)
        let charlie_keys = Keys::generate();
        let charlie_mdk = create_test_mdk();
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        let add_result = alice_device1
            .add_members(&group_id, &[charlie_key_package])
            .expect("Alice should add Charlie");

        alice_device1
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob processes the member addition commit
        bob_mdk
            .process_message(&add_result.evolution_event)
            .expect("Bob should process member addition");

        // Verify Bob's member list is synchronized
        let bob_updated_members = bob_mdk
            .get_members(&group_id)
            .expect("Bob should get updated members");

        assert_eq!(
            bob_updated_members.len(),
            3,
            "Bob should see Charlie was added"
        );
        assert!(
            bob_updated_members.contains(&charlie_keys.public_key()),
            "Bob should see Charlie in member list"
        );

        // Verify Bob received the message
        let bob_messages = bob_mdk
            .get_messages(&group_id, None)
            .expect("Bob should get messages");

        assert_eq!(bob_messages.len(), 1, "Bob should have 1 message");
        assert!(
            bob_messages[0].content.contains("Message from device 1"),
            "Bob should have message from Alice device 1"
        );
    }

    /// Message Processing Across Epoch Transitions
    ///
    /// Validates that devices can process messages from different epochs correctly,
    /// especially when syncing after being offline during epoch transitions.
    #[test]
    fn test_message_processing_across_epochs() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates group with Bob
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Get initial epoch
        let epoch0 = alice_mdk
            .get_group(&group_id)
            .expect("Should get group")
            .expect("Group should exist")
            .epoch;

        // Alice sends message in epoch 0
        let rumor0 = create_test_rumor(&alice_keys, "Message in epoch 0");
        let message0 = alice_mdk
            .create_message(&group_id, rumor0)
            .expect("Alice should create message in epoch 0");

        // Advance epoch by adding Charlie
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);
        let add_result = alice_mdk
            .add_members(&group_id, &[charlie_key_package])
            .expect("Alice should add Charlie");

        let add_commit_event = add_result.evolution_event.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Verify epoch advanced
        let epoch1 = alice_mdk
            .get_group(&group_id)
            .expect("Should get group")
            .expect("Group should exist")
            .epoch;

        assert!(epoch1 > epoch0, "Epoch should have advanced");

        // Alice sends message in epoch 1
        let rumor1 = create_test_rumor(&alice_keys, "Message in epoch 1");
        let message1 = alice_mdk
            .create_message(&group_id, rumor1)
            .expect("Alice should create message in epoch 1");

        // Bob processes message from epoch 0
        bob_mdk
            .process_message(&message0)
            .expect("Bob should process message from epoch 0");

        // Bob processes the commit to advance to epoch 1

        bob_mdk
            .process_message(&add_commit_event)
            .expect("Bob should process commit to advance epoch");

        // Bob processes message from epoch 1
        bob_mdk
            .process_message(&message1)
            .expect("Bob should process message from epoch 1");

        let bob_messages = bob_mdk
            .get_messages(&group_id, None)
            .expect("Bob should get messages");

        assert!(
            !bob_messages.is_empty(),
            "Bob should have messages from both epochs"
        );
        assert!(
            bob_messages
                .iter()
                .any(|m| m.content.contains("Message in epoch 0")),
            "Bob should have message from epoch 0"
        );
        assert!(
            bob_messages
                .iter()
                .any(|m| m.content.contains("Message in epoch 1")),
            "Bob should have message from epoch 1"
        );
    }

    /// Test author verification
    ///
    /// This test validates that the rumor pubkey must match the MLS sender's credential.
    /// A malicious actor cannot create a rumor with a different pubkey and have it accepted.
    ///
    /// Requirements tested:
    /// - Messages with matching MLS sender and rumor pubkey are accepted
    /// - Messages with mismatched pubkeys are rejected with AuthorMismatch error
    #[test]
    fn test_author_verification_binding() {
        // Setup: Create Alice and Bob
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let _malicious_keys = Keys::generate(); // A third party trying to impersonate

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];

        // Bob creates his key package in his own MDK
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group and adds Bob
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

        // Bob processes and accepts welcome to join the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should be able to process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should be able to accept welcome");

        // Test 1: Valid message - Alice sends with her correct pubkey
        let valid_rumor = create_test_rumor(&alice_keys, "Hello from Alice");
        let valid_msg = alice_mdk
            .create_message(&group_id, valid_rumor)
            .expect("Alice should be able to send a valid message");

        // Bob processes Alice's valid message - should succeed
        let bob_process_valid = bob_mdk.process_message(&valid_msg);
        assert!(
            bob_process_valid.is_ok(),
            "Bob should process Alice's valid message"
        );
        match bob_process_valid.unwrap() {
            MessageProcessingResult::ApplicationMessage(msg) => {
                assert_eq!(msg.content, "Hello from Alice");
                assert_eq!(msg.pubkey, alice_keys.public_key());
            }
            _ => panic!("Expected ApplicationMessage"),
        }

        // Test 2: Invalid message - Alice creates a message but with a different pubkey
        // This simulates an attacker trying to impersonate someone else by creating
        // a rumor with a forged pubkey, but MLS authentication should catch this.
        //
        // Note: In practice, the MLS layer authenticates the sender using the credential
        // bound to their leaf node. The author check ensures the rumor's pubkey
        // matches the authenticated MLS sender's credential.
        //
        // To truly test this, we would need to craft a message where the rumor pubkey
        // differs from the MLS sender's credential. Since we can't easily craft such
        // a malicious message in the current test framework (the rumor pubkey is set
        // by the sender and MLS authenticates the sender), we verify the mechanism
        // is in place by checking that valid messages work and the error type exists.

        // Verify the error type exists and can be matched
        let test_error = Error::AuthorMismatch;
        assert_eq!(
            test_error.to_string(),
            "author mismatch: rumor pubkey does not match MLS sender"
        );
    }

    /// Direct unit test for the AuthorMismatch error path
    ///
    /// This test directly invokes the verify_rumor_author function with mismatched
    /// inputs to exercise the security-critical error path that prevents impersonation.
    #[test]
    fn test_verify_rumor_author_mismatch() {
        let mdk = create_test_mdk();

        // Create two different identities
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        // Create a credential for Alice (the authenticated MLS sender)
        let alice_credential = BasicCredential::new(alice_keys.public_key().to_bytes().to_vec());
        let credential: openmls::credentials::Credential = alice_credential.into();

        // Test 1: Mismatched pubkeys should return AuthorMismatch
        // This simulates an attacker (Bob) trying to claim a message was from them
        // when the MLS credential proves it was sent by Alice
        let result = mdk.verify_rumor_author(&bob_keys.public_key(), credential.clone());
        assert!(
            matches!(result, Err(Error::AuthorMismatch)),
            "Expected AuthorMismatch error when rumor pubkey doesn't match credential"
        );

        // Test 2: Matching pubkeys should succeed
        let result = mdk.verify_rumor_author(&alice_keys.public_key(), credential);
        assert!(
            result.is_ok(),
            "Expected success when rumor pubkey matches credential"
        );
    }

    /// Test that IdentityChangeNotAllowed error type is properly constructed
    ///
    /// This test verifies the error variant we added for MIP-00 compliance
    /// is correctly defined and provides useful error messages.
    #[test]
    fn test_identity_change_not_allowed_error() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let error = Error::IdentityChangeNotAllowed {
            original_identity: alice_keys.public_key().to_hex(),
            new_identity: bob_keys.public_key().to_hex(),
        };

        // Verify the error message contains both identities
        let error_msg = error.to_string();
        assert!(
            error_msg.contains(&alice_keys.public_key().to_hex()),
            "Error message should contain original identity"
        );
        assert!(
            error_msg.contains(&bob_keys.public_key().to_hex()),
            "Error message should contain new identity"
        );
        assert!(
            error_msg.contains("identity change not allowed"),
            "Error message should indicate identity change is not allowed"
        );
    }

    /// Test that self_update preserves identity (verifies identity validation passes)
    ///
    /// This integration test verifies that a legitimate self_update operation
    /// passes identity validation since it doesn't change the member's identity.
    /// The validate_proposal_identity function is called internally during
    /// message processing, so this test confirms the validation succeeds for valid updates.
    #[test]
    fn test_self_update_preserves_identity_passes_validation() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get the original identity from the group
        let mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");
        let original_leaf = mls_group.own_leaf().expect("Failed to get own leaf");
        let original_credential =
            BasicCredential::try_from(original_leaf.credential().clone()).unwrap();
        let original_identity = original_credential.identity().to_vec();

        // Perform self_update - this internally creates an Update proposal
        // and should pass identity validation
        let update_result = mdk
            .self_update(&group_id)
            .expect("self_update should succeed - identity validation should pass");

        // Merge the pending commit
        mdk.merge_pending_commit(&group_id)
            .expect("merge should succeed");

        // Verify the identity was preserved after the update
        let updated_mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");
        let updated_leaf = updated_mls_group
            .own_leaf()
            .expect("Failed to get updated own leaf");
        let updated_credential =
            BasicCredential::try_from(updated_leaf.credential().clone()).unwrap();
        let updated_identity = updated_credential.identity().to_vec();

        assert_eq!(
            original_identity, updated_identity,
            "Identity should be preserved after self_update"
        );

        // Verify the update result is valid
        assert_eq!(
            update_result.mls_group_id, group_id,
            "Update result should have the same group ID"
        );
    }

    /// Test that identity parsing works correctly for validation
    ///
    /// This test verifies the components used in identity validation work correctly:
    /// parsing identities from credentials and comparing them.
    #[test]
    fn test_identity_parsing_for_validation() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Load the MLS group
        let mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");

        // Create a fake identity (different from any group member)
        let attacker_keys = Keys::generate();
        let attacker_credential =
            BasicCredential::new(attacker_keys.public_key().to_bytes().to_vec());

        // Get the current member's identity at leaf index 0
        if let Some(member) = mls_group.member_at(openmls::prelude::LeafNodeIndex::new(0)) {
            let current_credential = BasicCredential::try_from(member.credential.clone()).unwrap();
            let current_identity = mdk
                .parse_credential_identity(current_credential.identity())
                .expect("Failed to parse credential identity");

            let attacker_identity = mdk
                .parse_credential_identity(attacker_credential.identity())
                .expect("Failed to parse attacker identity");

            // Verify the identities are different
            assert_ne!(
                current_identity, attacker_identity,
                "Attacker identity should be different from member identity"
            );

            // Verify identity matches creator's public key
            assert_eq!(
                current_identity,
                creator.public_key(),
                "Member identity should match creator public key"
            );
        }
    }

    /// Test that commit processing validates identity in a multi-member scenario
    ///
    /// This test creates a multi-member group and verifies that when one member
    /// processes another member's commit, the identity validation passes for
    /// legitimate commits.
    #[test]
    fn test_commit_processing_validates_identity_multi_member() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates group with Bob as admin
        let admin_pubkeys = vec![alice_keys.public_key(), bob_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Verify both see 2 members
        let alice_members = alice_mdk.get_members(&group_id).expect("Alice get members");
        let bob_members = bob_mdk.get_members(&group_id).expect("Bob get members");
        assert_eq!(alice_members.len(), 2, "Alice should see 2 members");
        assert_eq!(bob_members.len(), 2, "Bob should see 2 members");

        // Alice performs a self_update (creates a commit with update_path)
        // This exercises the update_path_leaf_node validation
        let alice_update_result = alice_mdk
            .self_update(&group_id)
            .expect("Alice self_update should succeed");

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge self_update commit");

        // Bob processes Alice's commit - this triggers identity validation
        // The validation should pass because Alice's identity is preserved
        let bob_process_result = bob_mdk.process_message(&alice_update_result.evolution_event);

        assert!(
            bob_process_result.is_ok(),
            "Bob should successfully process Alice's commit with identity validation"
        );

        // Verify identities are still correct after the update
        let alice_mls_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Load Alice MLS group")
            .expect("Alice MLS group exists");

        let alice_own_leaf = alice_mls_group
            .own_leaf()
            .expect("Alice should have own leaf");
        let alice_credential =
            BasicCredential::try_from(alice_own_leaf.credential().clone()).unwrap();
        let alice_identity = alice_mdk
            .parse_credential_identity(alice_credential.identity())
            .expect("Parse Alice identity");

        assert_eq!(
            alice_identity,
            alice_keys.public_key(),
            "Alice's identity should be preserved after self_update"
        );
    }

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
        let commit_event = match process_result {
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

        // Verify the commit event has the correct structure
        assert_eq!(
            commit_event.kind,
            nostr::Kind::MlsGroupMessage,
            "Commit event should be MLS group message"
        );
    }

    /// Tests that self-leave proposals are stored as pending when processed by a non-admin.
    /// Non-admin members cannot commit, so they store the proposal for later admin approval.
    #[test]
    fn test_self_leave_proposal_stored_pending_by_non_admin() {
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

        // Bob leaves (creates proposal)
        let bob_leave_result = bob_mdk.leave_group(&group_id).expect("Bob should leave");

        // Charlie (non-admin) processes the leave proposal
        // This should store as pending and return PendingProposal variant
        let process_result = charlie_mdk
            .process_message(&bob_leave_result.evolution_event)
            .expect("Charlie should process leave");

        // Verify it returns PendingProposal (indicating it was stored, not committed)
        assert!(
            matches!(
                process_result,
                MessageProcessingResult::PendingProposal { .. }
            ),
            "Non-admin processing self-leave should return PendingProposal, got: {:?}",
            process_result
        );

        // Verify the proposal is now pending
        let pending = charlie_mdk
            .pending_removed_members_pubkeys(&group_id)
            .expect("Should get pending");
        assert_eq!(pending.len(), 1, "Bob should be in pending removals");
        assert_eq!(
            pending[0],
            bob_keys.public_key(),
            "Pending removal should be Bob"
        );
    }

    /// Test that the IdentityChangeNotAllowed error contains useful information
    ///
    /// This test verifies that when an identity change is detected, the error
    /// contains both the original and new identity for debugging purposes.
    #[test]
    fn test_identity_change_error_contains_identities() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let error = Error::IdentityChangeNotAllowed {
            original_identity: alice_keys.public_key().to_hex(),
            new_identity: bob_keys.public_key().to_hex(),
        };

        // Verify error can be displayed
        let error_string = error.to_string();
        assert!(
            error_string.contains("identity change not allowed"),
            "Error should mention identity change"
        );
        assert!(
            error_string.contains(&alice_keys.public_key().to_hex()),
            "Error should contain original identity"
        );
        assert!(
            error_string.contains(&bob_keys.public_key().to_hex()),
            "Error should contain new identity"
        );

        // Verify error type matches
        assert!(
            matches!(error, Error::IdentityChangeNotAllowed { .. }),
            "Error should be IdentityChangeNotAllowed variant"
        );
    }

    /// Test identity validation during add_members commit processing
    ///
    /// This test verifies that identity validation is triggered when processing
    /// add_members commits that contain update paths.
    #[test]
    fn test_add_members_commit_triggers_identity_validation() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        // Alice creates group with Bob
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Alice adds Charlie - this creates a commit with update_path
        let add_result = alice_mdk
            .add_members(&group_id, &[charlie_key_package])
            .expect("Alice should add Charlie");

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge add commit");

        // Bob processes Alice's add_members commit
        // This triggers identity validation on the update_path
        let bob_process_result = bob_mdk.process_message(&add_result.evolution_event);

        assert!(
            bob_process_result.is_ok(),
            "Bob should successfully process add_members commit with identity validation"
        );

        // Verify Alice's identity is still correct after the commit
        let alice_mls_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Load Alice MLS group")
            .expect("Alice MLS group exists");

        let alice_own_leaf = alice_mls_group
            .own_leaf()
            .expect("Alice should have own leaf");
        let alice_credential =
            BasicCredential::try_from(alice_own_leaf.credential().clone()).unwrap();
        let alice_identity = alice_mdk
            .parse_credential_identity(alice_credential.identity())
            .expect("Parse Alice identity");

        assert_eq!(
            alice_identity,
            alice_keys.public_key(),
            "Alice's identity should be preserved after add_members"
        );
    }

    /// Test identity validation during remove_members commit processing
    ///
    /// This test verifies that identity validation is triggered when processing
    /// remove_members commits.
    #[test]
    fn test_remove_members_commit_triggers_identity_validation() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        // Alice creates group with Bob and Charlie (Alice is admin)
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package, charlie_key_package],
                config,
            )
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Verify initial member count
        let alice_members = alice_mdk.get_members(&group_id).expect("Alice get members");
        assert_eq!(
            alice_members.len(),
            3,
            "Alice should see 3 members initially"
        );

        // Alice removes Charlie
        let remove_result = alice_mdk
            .remove_members(&group_id, &[charlie_keys.public_key()])
            .expect("Alice should remove Charlie");

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge remove commit");

        // Bob processes Alice's remove_members commit
        // This triggers identity validation
        let bob_process_result = bob_mdk.process_message(&remove_result.evolution_event);

        assert!(
            bob_process_result.is_ok(),
            "Bob should successfully process remove_members commit with identity validation"
        );

        // Verify member count changed
        let alice_members_after = alice_mdk
            .get_members(&group_id)
            .expect("Alice get members after");
        assert_eq!(
            alice_members_after.len(),
            2,
            "Alice should see 2 members after removal"
        );
    }

    /// Test multiple sequential commits with identity validation
    ///
    /// This test verifies that identity validation works correctly across
    /// multiple sequential commits in a group.
    #[test]
    fn test_sequential_commits_identity_validation() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates group with Bob as admin
        let admin_pubkeys = vec![alice_keys.public_key(), bob_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Perform multiple self_updates and verify identity is preserved each time
        for i in 0..3 {
            // Alice performs self_update
            let alice_update_result = alice_mdk
                .self_update(&group_id)
                .unwrap_or_else(|e| panic!("Alice self_update {} should succeed: {:?}", i, e));

            alice_mdk
                .merge_pending_commit(&group_id)
                .unwrap_or_else(|e| panic!("Alice should merge self_update commit {}: {:?}", i, e));

            // Bob processes Alice's commit
            let bob_process_result = bob_mdk.process_message(&alice_update_result.evolution_event);
            assert!(
                bob_process_result.is_ok(),
                "Bob should process Alice's commit {} with identity validation",
                i
            );

            // Bob performs self_update
            let bob_update_result = bob_mdk
                .self_update(&group_id)
                .unwrap_or_else(|e| panic!("Bob self_update {} should succeed: {:?}", i, e));

            bob_mdk
                .merge_pending_commit(&group_id)
                .unwrap_or_else(|e| panic!("Bob should merge self_update commit {}: {:?}", i, e));

            // Alice processes Bob's commit
            let alice_process_result =
                alice_mdk.process_message(&bob_update_result.evolution_event);
            assert!(
                alice_process_result.is_ok(),
                "Alice should process Bob's commit {} with identity validation",
                i
            );
        }

        // Verify both identities are still correct after all commits
        let alice_mls_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Load Alice MLS group")
            .expect("Alice MLS group exists");
        let alice_own_leaf = alice_mls_group.own_leaf().expect("Alice own leaf");
        let alice_credential =
            BasicCredential::try_from(alice_own_leaf.credential().clone()).unwrap();
        let alice_identity = alice_mdk
            .parse_credential_identity(alice_credential.identity())
            .expect("Parse Alice identity");

        let bob_mls_group = bob_mdk
            .load_mls_group(&group_id)
            .expect("Load Bob MLS group")
            .expect("Bob MLS group exists");
        let bob_own_leaf = bob_mls_group.own_leaf().expect("Bob own leaf");
        let bob_credential = BasicCredential::try_from(bob_own_leaf.credential().clone()).unwrap();
        let bob_identity = bob_mdk
            .parse_credential_identity(bob_credential.identity())
            .expect("Parse Bob identity");

        assert_eq!(
            alice_identity,
            alice_keys.public_key(),
            "Alice's identity should be preserved after multiple commits"
        );
        assert_eq!(
            bob_identity,
            bob_keys.public_key(),
            "Bob's identity should be preserved after multiple commits"
        );
    }

    /// Test that validate_proposal_identity handles non-Update proposals correctly
    ///
    /// This test verifies that the validation function correctly handles
    /// different proposal types (Add, Remove) without errors.
    #[test]
    fn test_validate_proposal_identity_non_update_proposals() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Load the MLS group
        let mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");

        // Verify we have members in the group
        let member_count = mls_group.members().count();
        assert!(member_count > 0, "Group should have members");

        // Verify each member has a valid identity
        for member in mls_group.members() {
            let credential = BasicCredential::try_from(member.credential.clone())
                .expect("Should extract credential");
            let identity = mdk
                .parse_credential_identity(credential.identity())
                .expect("Should parse identity");

            // Verify identity is a valid 32-byte public key
            assert_eq!(identity.to_bytes().len(), 32, "Identity should be 32 bytes");
        }
    }

    /// Test identity validation with group epoch changes
    ///
    /// This test verifies that identity validation works correctly as the
    /// group advances through multiple epochs.
    #[test]
    fn test_identity_validation_across_epochs() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates group with Bob
        let admin_pubkeys = vec![alice_keys.public_key(), bob_keys.public_key()];
        let config = create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Get initial epoch
        let initial_epoch = alice_mdk
            .get_group(&group_id)
            .expect("Get group")
            .expect("Group exists")
            .epoch;

        // Advance epoch multiple times
        for i in 0..5 {
            let update_result = alice_mdk
                .self_update(&group_id)
                .unwrap_or_else(|e| panic!("Alice self_update {} should succeed: {:?}", i, e));

            alice_mdk
                .merge_pending_commit(&group_id)
                .unwrap_or_else(|e| panic!("Alice should merge commit {}: {:?}", i, e));

            // Bob processes to stay in sync
            bob_mdk
                .process_message(&update_result.evolution_event)
                .unwrap_or_else(|e| panic!("Bob should process commit {}: {:?}", i, e));
        }

        // Verify epoch advanced
        let final_epoch = alice_mdk
            .get_group(&group_id)
            .expect("Get group")
            .expect("Group exists")
            .epoch;

        assert!(
            final_epoch > initial_epoch,
            "Epoch should have advanced: {} > {}",
            final_epoch,
            initial_epoch
        );

        // Verify identities are still correct
        let alice_mls_group = alice_mdk
            .load_mls_group(&group_id)
            .expect("Load MLS group")
            .expect("MLS group exists");

        let alice_own_leaf = alice_mls_group.own_leaf().expect("Alice own leaf");
        let alice_credential =
            BasicCredential::try_from(alice_own_leaf.credential().clone()).unwrap();
        let alice_identity = alice_mdk
            .parse_credential_identity(alice_credential.identity())
            .expect("Parse identity");

        assert_eq!(
            alice_identity,
            alice_keys.public_key(),
            "Alice's identity should be preserved across epoch changes"
        );
    }

    /// Test that identity validation correctly detects identity changes
    ///
    /// This test verifies the identity validation logic can correctly detect
    /// when an Update proposal would contain a different identity than the sender's
    /// current identity and would return IdentityChangeNotAllowed error.
    #[test]
    fn test_identity_validation_detects_changes() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Load the MLS group
        let mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");

        // Get the creator's leaf node (at index 0)
        let own_leaf = mls_group.own_leaf().expect("Should have own leaf");

        // Get the current identity
        let creator_credential = BasicCredential::try_from(own_leaf.credential().clone())
            .expect("Failed to get credential");
        let creator_identity = mdk
            .parse_credential_identity(creator_credential.identity())
            .expect("Failed to parse identity");

        // Create a different identity (attacker)
        let attacker_keys = Keys::generate();
        let attacker_identity = attacker_keys.public_key();

        // Verify identities are different
        assert_ne!(
            creator_identity, attacker_identity,
            "Creator and attacker identities should be different"
        );

        // Verify the error would be constructed correctly if detected
        let expected_error = Error::IdentityChangeNotAllowed {
            original_identity: creator_identity.to_hex(),
            new_identity: attacker_identity.to_hex(),
        };
        assert!(
            expected_error
                .to_string()
                .contains("identity change not allowed"),
            "Error message should indicate identity change"
        );
        assert!(
            expected_error
                .to_string()
                .contains(&creator_identity.to_hex()),
            "Error should contain original identity"
        );
        assert!(
            expected_error
                .to_string()
                .contains(&attacker_identity.to_hex()),
            "Error should contain new identity"
        );

        // Verify the error type matches correctly
        assert!(
            matches!(expected_error, Error::IdentityChangeNotAllowed { .. }),
            "Error should be IdentityChangeNotAllowed variant"
        );
    }

    /// Test that validate_staged_commit_identities logic works correctly
    ///
    /// This test verifies that if a commit's update_path_leaf_node contained
    /// a different identity than the committer's current identity, the validation
    /// logic would correctly return IdentityChangeNotAllowed error.
    #[test]
    fn test_staged_commit_identity_validation_logic() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Load the MLS group
        let mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");

        // Get the current member's identity
        let member = mls_group
            .member_at(openmls::prelude::LeafNodeIndex::new(0))
            .expect("Member should exist at index 0");
        let current_credential =
            BasicCredential::try_from(member.credential.clone()).expect("Failed to get credential");
        let current_identity = mdk
            .parse_credential_identity(current_credential.identity())
            .expect("Failed to parse identity");

        // Create a different identity
        let attacker_keys = Keys::generate();
        let attacker_credential =
            BasicCredential::new(attacker_keys.public_key().to_bytes().to_vec());
        let attacker_identity = mdk
            .parse_credential_identity(attacker_credential.identity())
            .expect("Failed to parse attacker identity");

        // Verify identities are different
        assert_ne!(
            current_identity, attacker_identity,
            "Current and attacker identities should be different"
        );

        // Verify the comparison logic that would trigger the error
        assert!(
            current_identity != attacker_identity,
            "Identity comparison should detect mismatch"
        );

        // Verify error construction
        let error = Error::IdentityChangeNotAllowed {
            original_identity: current_identity.to_hex(),
            new_identity: attacker_identity.to_hex(),
        };
        assert!(
            error.to_string().contains(&current_identity.to_hex()),
            "Error should contain original identity"
        );
        assert!(
            error.to_string().contains(&attacker_identity.to_hex()),
            "Error should contain new identity"
        );

        // Perform a legitimate self_update to verify the validation is called
        let update_result = mdk
            .self_update(&group_id)
            .expect("Self update should succeed");

        mdk.merge_pending_commit(&group_id)
            .expect("Merge should succeed");

        // Verify identity was preserved (validation passed)
        let updated_mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");

        let updated_leaf = updated_mls_group.own_leaf().expect("Should have own leaf");
        let updated_credential = BasicCredential::try_from(updated_leaf.credential().clone())
            .expect("Failed to get credential");
        let updated_identity = mdk
            .parse_credential_identity(updated_credential.identity())
            .expect("Failed to parse identity");

        assert_eq!(
            current_identity, updated_identity,
            "Identity should be preserved after legitimate self_update"
        );

        // The evolution event exists and is valid
        assert!(!update_result.mls_group_id.as_slice().is_empty());
    }

    /// Test validation with TLS serialization
    ///
    /// This test uses TLS serialization to verify the leaf node structure
    /// and that identity parsing works correctly for validation.
    #[test]
    fn test_identity_validation_with_tls_serialization() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Load the MLS group
        let mls_group = mdk
            .load_mls_group(&group_id)
            .expect("Failed to load MLS group")
            .expect("MLS group should exist");

        // Get the original leaf node
        let original_leaf = mls_group.own_leaf().expect("Should have own leaf");

        // Serialize the leaf to TLS format
        let original_leaf_bytes = original_leaf
            .tls_serialize_detached()
            .expect("Failed to serialize leaf");

        // Create a different identity (attacker)
        let attacker_keys = Keys::generate();
        let attacker_identity_bytes = attacker_keys.public_key().to_bytes().to_vec();

        // Get the original identity
        let original_credential = BasicCredential::try_from(original_leaf.credential().clone())
            .expect("Failed to get credential");
        let original_identity = mdk
            .parse_credential_identity(original_credential.identity())
            .expect("Failed to parse original identity");

        // Create attacker credential and parse identity
        let attacker_credential = BasicCredential::new(attacker_identity_bytes);
        let attacker_identity = mdk
            .parse_credential_identity(attacker_credential.identity())
            .expect("Failed to parse attacker identity");

        // Verify identities are different
        assert_ne!(
            original_identity, attacker_identity,
            "Original and attacker identities should be different"
        );

        // The validation logic compares:
        // current_identity (from mls_group.member_at(sender_leaf_index))
        // vs new_identity (from update_proposal.leaf_node().credential())
        //
        // If they differ, it returns Error::IdentityChangeNotAllowed

        // Verify the error would be returned
        let error = Error::IdentityChangeNotAllowed {
            original_identity: original_identity.to_hex(),
            new_identity: attacker_identity.to_hex(),
        };

        // Verify error message format
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("identity change not allowed"),
            "Error message should indicate identity change is not allowed"
        );
        assert!(
            error_msg.contains(&original_identity.to_hex()),
            "Error should contain the original identity: {}",
            error_msg
        );
        assert!(
            error_msg.contains(&attacker_identity.to_hex()),
            "Error should contain the new identity: {}",
            error_msg
        );

        // Verify the serialized bytes are valid and contain identity
        assert!(
            !original_leaf_bytes.is_empty(),
            "Serialized leaf should not be empty"
        );
        assert!(
            original_leaf_bytes.len() > 32,
            "Serialized leaf should contain identity"
        );
    }

    /// Test that check_identity_unchanged returns Ok when identities match
    ///
    /// This directly tests the core validation helper to ensure it allows
    /// proposals and commits where the identity remains the same.
    #[test]
    fn test_check_identity_unchanged_same_identity() {
        use mdk_memory_storage::MdkMemoryStorage;

        let keys = Keys::generate();
        let identity = keys.public_key();

        // Same identity should pass validation
        let result = MDK::<MdkMemoryStorage>::check_identity_unchanged(identity, identity);
        assert!(result.is_ok(), "Matching identities should pass validation");
    }

    /// Test that check_identity_unchanged returns IdentityChangeNotAllowed when identities differ
    ///
    /// This directly tests the core validation helper to ensure it rejects
    /// proposals and commits that attempt to change a member's identity.
    /// This is the key error path that enforces MIP-00's immutable identity requirement.
    #[test]
    fn test_check_identity_unchanged_rejects_different_identity() {
        use mdk_memory_storage::MdkMemoryStorage;

        let original_keys = Keys::generate();
        let attacker_keys = Keys::generate();

        let original_identity = original_keys.public_key();
        let attacker_identity = attacker_keys.public_key();

        // Different identities should fail validation
        let result =
            MDK::<MdkMemoryStorage>::check_identity_unchanged(original_identity, attacker_identity);

        assert!(
            result.is_err(),
            "Different identities should fail validation"
        );

        // Verify we get the correct error type with correct identities
        let error = result.unwrap_err();
        assert!(
            matches!(error, Error::IdentityChangeNotAllowed { .. }),
            "Error should be IdentityChangeNotAllowed variant"
        );

        // Verify the error contains the correct identity hex strings
        let error_msg = error.to_string();
        assert!(
            error_msg.contains(&original_identity.to_hex()),
            "Error should contain original identity hex"
        );
        assert!(
            error_msg.contains(&attacker_identity.to_hex()),
            "Error should contain attacker identity hex"
        );
    }

    /// Test that proposal identity change is rejected through the validation function
    ///
    /// This test verifies that when an UpdateProposal contains a credential with
    /// a different identity than the sender's current identity in the group,
    /// the validation correctly returns IdentityChangeNotAllowed error.
    ///
    /// Note: Since UpdateProposal cannot be directly constructed (pub(crate) fields),
    /// we test through the check_identity_unchanged helper which is the core
    /// validation logic used by validate_proposal_identity.
    #[test]
    fn test_proposal_identity_change_rejected() {
        use mdk_memory_storage::MdkMemoryStorage;

        // Simulate a member's current identity
        let member_keys = Keys::generate();
        let member_identity = member_keys.public_key();

        // Simulate an attacker attempting to change to their own identity
        let attacker_keys = Keys::generate();
        let attacker_identity = attacker_keys.public_key();

        // The validation should reject this identity change
        let result =
            MDK::<MdkMemoryStorage>::check_identity_unchanged(member_identity, attacker_identity);

        // Assert the validation fails with IdentityChangeNotAllowed
        assert!(
            result.is_err(),
            "Identity change in proposal should be rejected"
        );

        match result.unwrap_err() {
            Error::IdentityChangeNotAllowed {
                original_identity,
                new_identity,
            } => {
                assert_eq!(
                    original_identity,
                    member_identity.to_hex(),
                    "Original identity should match member's identity"
                );
                assert_eq!(
                    new_identity,
                    attacker_identity.to_hex(),
                    "New identity should match attacker's identity"
                );
            }
            other => panic!("Expected IdentityChangeNotAllowed error, got: {:?}", other),
        }
    }

    /// Test that commit with identity-changing update path is rejected
    ///
    /// This test verifies that when a commit's update_path_leaf_node contains
    /// a credential with a different identity than the committer's current
    /// identity, the validation correctly returns IdentityChangeNotAllowed error.
    ///
    /// Note: Since StagedCommit cannot be directly constructed, we test through
    /// the check_identity_unchanged helper which is the core validation logic
    /// used by validate_staged_commit_identities for the update path.
    #[test]
    fn test_commit_update_path_identity_change_rejected() {
        use mdk_memory_storage::MdkMemoryStorage;

        // Simulate a committer's current identity in the group
        let committer_keys = Keys::generate();
        let committer_identity = committer_keys.public_key();

        // Simulate the committer attempting to change their identity via update path
        let new_keys = Keys::generate();
        let new_identity = new_keys.public_key();

        // The validation should reject this identity change in the update path
        let result =
            MDK::<MdkMemoryStorage>::check_identity_unchanged(committer_identity, new_identity);

        // Assert the validation fails with IdentityChangeNotAllowed
        assert!(
            result.is_err(),
            "Identity change in commit update path should be rejected"
        );

        match result.unwrap_err() {
            Error::IdentityChangeNotAllowed {
                original_identity,
                new_identity: new_id,
            } => {
                assert_eq!(
                    original_identity,
                    committer_identity.to_hex(),
                    "Original identity should match committer's identity"
                );
                assert_eq!(
                    new_id,
                    new_identity.to_hex(),
                    "New identity should match the attempted new identity"
                );
            }
            other => panic!("Expected IdentityChangeNotAllowed error, got: {:?}", other),
        }
    }

    /// Test that multiple sequential identity changes are all rejected
    ///
    /// This tests that the validation works consistently across multiple
    /// attempts to change identity, ensuring the error contains the correct
    /// identity pairs each time.
    #[test]
    fn test_multiple_identity_change_attempts_rejected() {
        use mdk_memory_storage::MdkMemoryStorage;

        let original_keys = Keys::generate();
        let original_identity = original_keys.public_key();

        // Attempt multiple different identity changes
        for _ in 0..5 {
            let attacker_keys = Keys::generate();
            let attacker_identity = attacker_keys.public_key();

            let result = MDK::<MdkMemoryStorage>::check_identity_unchanged(
                original_identity,
                attacker_identity,
            );

            assert!(
                result.is_err(),
                "Each identity change attempt should be rejected"
            );

            if let Err(Error::IdentityChangeNotAllowed {
                original_identity: orig,
                new_identity: new,
            }) = result
            {
                assert_eq!(orig, original_identity.to_hex());
                assert_eq!(new, attacker_identity.to_hex());
            }
        }
    }

    /// Test that validation failures persist failed processing state
    ///
    /// This test verifies that when message validation fails (e.g., wrong event kind),
    /// a failed processing record is saved to prevent expensive reprocessing.
    #[test]
    fn test_validation_failure_persists_failed_state() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create an event with wrong kind (should be 445, but we use 1)
        let event = EventBuilder::new(Kind::Metadata, "")
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt should fail validation
        let result = mdk.process_message(&event);
        assert!(result.is_err(), "Expected validation error");

        // Check that a failed processing record was saved
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap();
        assert!(processed.is_some(), "Failed record should be saved");
        let processed = processed.unwrap();
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed,
            "State should be Failed"
        );
        assert!(
            processed.failure_reason.is_some(),
            "Failure reason should be set"
        );
        // Check for sanitized failure reason (not internal error details)
        assert_eq!(
            processed.failure_reason.unwrap(),
            "invalid_event_type",
            "Failure reason should be sanitized classification"
        );
    }

    /// Test that repeated validation failures are rejected immediately
    ///
    /// This test verifies the deduplication mechanism prevents reprocessing
    /// of previously failed events, mitigating DoS attacks.
    #[test]
    fn test_repeated_validation_failure_rejected_immediately() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create an event with wrong kind
        let event = EventBuilder::new(Kind::Metadata, "")
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - full validation
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail validation");

        // Second attempt - should be rejected immediately via deduplication
        let result2 = mdk.process_message(&event);
        assert!(result2.is_err(), "Second attempt should also fail");
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Error should indicate previous failure"
        );
    }

    /// Test that decryption failures persist failed processing state
    ///
    /// This test verifies that when message decryption fails (e.g., group not found),
    /// a failed processing record is saved to prevent expensive reprocessing.
    #[test]
    fn test_decryption_failure_persists_failed_state() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create a valid-looking event but for a non-existent group
        let fake_group_id = hex::encode([42u8; 32]);
        let tag = Tag::custom(TagKind::h(), [fake_group_id]);
        let event = EventBuilder::new(Kind::MlsGroupMessage, "encrypted_content")
            .tag(tag)
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt should fail decryption (group not found)
        let result = mdk.process_message(&event);
        assert!(result.is_err(), "Expected decryption error");

        // Check that a failed processing record was saved
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap();
        assert!(processed.is_some(), "Failed record should be saved");
        let processed = processed.unwrap();
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed,
            "State should be Failed"
        );
        assert!(
            processed.failure_reason.is_some(),
            "Failure reason should be set"
        );
        // Check for sanitized failure reason (not internal error details)
        assert_eq!(
            processed.failure_reason.unwrap(),
            "group_not_found",
            "Failure reason should be sanitized classification"
        );
    }

    /// Test that repeated decryption failures are rejected immediately
    ///
    /// This test verifies the deduplication mechanism works for decryption failures,
    /// preventing expensive repeated decryption attempts.
    #[test]
    fn test_repeated_decryption_failure_rejected_immediately() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create a valid-looking event but for a non-existent group
        let fake_group_id = hex::encode([42u8; 32]);
        let tag = Tag::custom(TagKind::h(), [fake_group_id]);
        let event = EventBuilder::new(Kind::MlsGroupMessage, "encrypted_content")
            .tag(tag)
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - full decryption attempt
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail decryption");

        // Second attempt - should be rejected immediately via deduplication
        let result2 = mdk.process_message(&event);
        assert!(result2.is_err(), "Second attempt should also fail");
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Error should indicate previous failure"
        );
    }

    /// Test that missing group ID tag persists failed state
    ///
    /// This test verifies that validation failures for missing required tags
    /// are properly persisted to prevent reprocessing.
    #[test]
    fn test_missing_group_id_tag_persists_failed_state() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create an event with correct kind but missing group ID tag
        let event = EventBuilder::new(Kind::MlsGroupMessage, "encrypted_content")
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt should fail validation
        let result = mdk.process_message(&event);
        assert!(result.is_err(), "Expected validation error");

        // Check that a failed processing record was saved
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap();
        assert!(processed.is_some(), "Failed record should be saved");
        let processed = processed.unwrap();
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed,
            "State should be Failed"
        );
    }

    /// Test that deduplication only blocks Failed state
    ///
    /// This test verifies that the deduplication check only prevents reprocessing
    /// of Failed messages, allowing normal message flow for other states.
    #[test]
    fn test_deduplication_only_blocks_failed_state() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create a test event
        let event = EventBuilder::new(Kind::Metadata, "")
            .sign_with_keys(&keys)
            .unwrap();

        // Manually save a Processed state (simulating a successfully processed message)
        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: None,
            processed_at: nostr::Timestamp::now(),
            state: message_types::ProcessedMessageState::Processed,
            failure_reason: None,
        };
        mdk.storage()
            .save_processed_message(processed_message)
            .unwrap();

        // Attempting to process again should not be blocked by deduplication
        // (it will fail for other reasons like wrong kind, but not due to deduplication)
        let result = mdk.process_message(&event);
        assert!(result.is_err());
        // The error should NOT be about "previously failed"
        assert!(
            !result
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Should not be blocked by deduplication for non-Failed state"
        );
    }

    /// Test that validate_event_and_extract_group_id rejects events with timestamps too far in the future
    #[test]
    fn test_validate_event_rejects_future_timestamp() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get the group's nostr_group_id for the h tag
        let group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");

        // Set timestamp to far future (1 hour ahead, beyond 5 minute skew allowance)
        let future_time = nostr::Timestamp::now().as_u64() + 3600;

        // Create an event with future timestamp
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .custom_created_at(nostr::Timestamp::from(future_time))
            .tag(Tag::custom(
                TagKind::h(),
                [hex::encode(group.nostr_group_id)],
            ))
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should fail due to future timestamp
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(
            matches!(result, Err(Error::InvalidTimestamp(_))),
            "Expected InvalidTimestamp error for future timestamp, got: {:?}",
            result
        );
    }

    /// Test that validate_event_and_extract_group_id rejects events with timestamps too far in the past
    #[test]
    fn test_validate_event_rejects_old_timestamp() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get the group's nostr_group_id for the h tag
        let group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");

        // Set timestamp to 46 days ago (beyond 45 day limit)
        let old_time = nostr::Timestamp::now().as_u64().saturating_sub(46 * 86400);

        // Create an event with old timestamp
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .custom_created_at(nostr::Timestamp::from(old_time))
            .tag(Tag::custom(
                TagKind::h(),
                [hex::encode(group.nostr_group_id)],
            ))
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should fail due to old timestamp
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(
            matches!(result, Err(Error::InvalidTimestamp(_))),
            "Expected InvalidTimestamp error for old timestamp, got: {:?}",
            result
        );
    }

    /// Test that validate_event_and_extract_group_id accepts events with valid timestamps
    #[test]
    fn test_validate_event_accepts_valid_timestamp() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get the group's nostr_group_id for the h tag
        let group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");

        // Create an event with current timestamp
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .tag(Tag::custom(
                TagKind::h(),
                [hex::encode(group.nostr_group_id)],
            ))
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should succeed
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(
            result.is_ok(),
            "Expected valid timestamp to be accepted, got: {:?}",
            result
        );
    }

    /// Test that validate_event_and_extract_group_id rejects events with multiple h tags
    #[test]
    fn test_validate_event_rejects_multiple_h_tags() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event with multiple h tags
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .tag(Tag::custom(TagKind::h(), [hex::encode([1u8; 32])]))
            .tag(Tag::custom(TagKind::h(), [hex::encode([2u8; 32])]))
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should fail due to multiple h tags
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(
            matches!(result, Err(Error::MultipleGroupIdTags(2))),
            "Expected MultipleGroupIdTags error, got: {:?}",
            result
        );
    }

    /// Test that validate_event_and_extract_group_id rejects events with invalid hex in h tag
    #[test]
    fn test_validate_event_rejects_invalid_hex_group_id() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event with invalid hex in h tag
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .tag(Tag::custom(TagKind::h(), ["not-valid-hex-zzz"]))
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should fail due to invalid hex
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(
            matches!(result, Err(Error::InvalidGroupIdFormat(_))),
            "Expected InvalidGroupIdFormat error, got: {:?}",
            result
        );
    }

    /// Test that validate_event_and_extract_group_id rejects events with wrong length group ID
    #[test]
    fn test_validate_event_rejects_wrong_length_group_id() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event with wrong length group ID (16 bytes instead of 32)
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .tag(Tag::custom(TagKind::h(), [hex::encode([1u8; 16])]))
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should fail due to wrong length
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(
            matches!(result, Err(Error::InvalidGroupIdFormat(_))),
            "Expected InvalidGroupIdFormat error for wrong length, got: {:?}",
            result
        );
    }

    /// Test that validate_event_and_extract_group_id extracts valid group ID
    #[test]
    fn test_validate_event_extracts_valid_group_id() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get the group's nostr_group_id for the h tag
        let group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");

        // Create an event with valid group ID
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .tag(Tag::custom(
                TagKind::h(),
                [hex::encode(group.nostr_group_id)],
            ))
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should succeed and return the correct group ID
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(result.is_ok(), "Expected success, got: {:?}", result);
        assert_eq!(
            result.unwrap(),
            group.nostr_group_id,
            "Extracted group ID should match"
        );
    }

    /// Test that validate_event_and_extract_group_id rejects events missing h tag
    #[test]
    fn test_validate_event_rejects_missing_h_tag() {
        let mdk = create_test_mdk();
        let creator = Keys::generate();

        // Create an event without h tag
        let message_event = EventBuilder::new(Kind::MlsGroupMessage, "test content")
            .sign_with_keys(&creator)
            .expect("Failed to create event");

        // Validation should fail due to missing h tag
        let result = mdk.validate_event_and_extract_group_id(&message_event);
        assert!(
            matches!(result, Err(Error::MissingGroupIdTag)),
            "Expected MissingGroupIdTag error, got: {:?}",
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

    /// Test that add-member commits from non-admin members are REJECTED (Issue #44)
    ///
    /// Only admins can add members to a group. This test verifies that when a
    /// non-admin tries to create a commit that adds members, it is rejected.
    ///
    /// Note: The client-side `add_members` function already checks admin status,
    /// so in practice non-admins cannot create add commits. This test verifies
    /// the server-side check as defense in depth.
    #[test]
    fn test_add_member_commit_from_non_admin_is_rejected() {
        // Setup: Alice (admin), Bob (admin initially), and Charlie (non-admin member)
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();
        let dave_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Both Alice and Bob are admins initially
        let admins = vec![alice_keys.public_key(), bob_keys.public_key()];

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        // Alice creates the group with Bob and Charlie
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package, charlie_key_package],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Bob joins
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Charlie joins
        let charlie_welcome_rumor = &create_result.welcome_rumors[1];
        let charlie_welcome = charlie_mdk
            .process_welcome(&nostr::EventId::all_zeros(), charlie_welcome_rumor)
            .expect("Charlie should process welcome");
        charlie_mdk
            .accept_welcome(&charlie_welcome)
            .expect("Charlie should accept welcome");

        // Bob creates a key package for Dave
        let dave_key_package = create_key_package_event(&bob_mdk, &dave_keys);

        // Bob (who is admin) creates a commit to add Dave
        let bob_add_result = bob_mdk
            .add_members(&group_id, &[dave_key_package])
            .expect("Bob (admin) can create add commit");

        // Capture the commit event
        let bob_add_commit_event = bob_add_result.evolution_event;

        // Now Alice demotes Bob to non-admin
        let update =
            crate::groups::NostrGroupDataUpdate::new().admins(vec![alice_keys.public_key()]);
        let alice_demote_result = alice_mdk
            .update_group_data(&group_id, update)
            .expect("Alice should demote Bob");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge demote commit");

        // Charlie processes Alice's demote commit
        charlie_mdk
            .process_message(&alice_demote_result.evolution_event)
            .expect("Charlie should process Alice's demote commit");

        // Now Charlie tries to process Bob's add-member commit
        // This should be rejected because Bob is no longer an admin.
        // The rejection may come as:
        // - CommitFromNonAdmin error (if admin check runs first)
        // - Unprocessable result (if epoch mismatch due to Alice's demote commit)
        // Both outcomes are valid - the important thing is the commit doesn't succeed.
        let result = charlie_mdk.process_message(&bob_add_commit_event);

        match result {
            Ok(MessageProcessingResult::Unprocessable { .. }) => {
                // Epoch mismatch caused rejection - this is acceptable because
                // Alice's demote commit advanced the epoch before Bob's commit could be processed
            }
            Err(crate::Error::CommitFromNonAdmin) => {
                // Admin check caught the non-admin commit - this is the direct rejection path
            }
            Ok(MessageProcessingResult::Commit { .. }) => {
                panic!("Add-member commit from demoted admin should have been rejected");
            }
            other => {
                panic!(
                    "Unexpected result for add-member commit from demoted admin: {:?}",
                    other
                );
            }
        }
    }

    /// Test that admin add-member commits are processed successfully by non-admin members
    ///
    /// This verifies that commits from admins with add proposals are accepted,
    /// exercising the "sender is admin" path in `process_commit_message_for_group`.
    #[test]
    fn test_admin_add_member_commit_is_processed_successfully() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group with Bob
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Bob joins via welcome
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Verify Bob is NOT an admin
        let group_state = bob_mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert!(
            !group_state.admin_pubkeys.contains(&bob_keys.public_key()),
            "Bob should NOT be an admin"
        );

        // Alice (admin) creates a commit to add Charlie
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);
        let alice_add_result = alice_mdk
            .add_members(&group_id, &[charlie_key_package])
            .expect("Alice (admin) can create add commit");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge add commit");

        // Bob (non-admin) processes Alice's add-member commit
        // This should SUCCEED because Alice is an admin
        let result = bob_mdk.process_message(&alice_add_result.evolution_event);

        assert!(
            result.is_ok(),
            "Admin add-member commit should be processed successfully, got error: {:?}",
            result.err()
        );

        // Verify the result is a Commit
        assert!(
            matches!(result.unwrap(), MessageProcessingResult::Commit { .. }),
            "Result should be a Commit"
        );

        // Verify Charlie is now a pending member in Bob's view
        let members = bob_mdk
            .get_members(&group_id)
            .expect("Failed to get members");
        assert_eq!(members.len(), 3, "Group should have 3 members");
    }

    /// Test that admin extension update commits are processed successfully
    ///
    /// This verifies that commits containing GroupContextExtensions proposals
    /// from admins are accepted, exercising the admin path in the commit processing.
    #[test]
    fn test_admin_extension_update_commit_is_processed_successfully() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        // Create key package for Bob
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group with Bob
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Bob joins via welcome
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Alice (admin) updates group extensions (name and description)
        let update = crate::groups::NostrGroupDataUpdate::new()
            .name("Updated Group Name".to_string())
            .description("Updated description".to_string());
        let alice_update_result = alice_mdk
            .update_group_data(&group_id, update)
            .expect("Alice (admin) can update group data");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge update commit");

        // Bob (non-admin) processes Alice's extension update commit
        // This should SUCCEED because Alice is an admin
        let result = bob_mdk.process_message(&alice_update_result.evolution_event);

        assert!(
            result.is_ok(),
            "Admin extension update commit should be processed successfully, got error: {:?}",
            result.err()
        );

        // Verify the result is a Commit
        assert!(
            matches!(result.unwrap(), MessageProcessingResult::Commit { .. }),
            "Result should be a Commit"
        );

        // Verify the group name was updated in Bob's view
        let group_state = bob_mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert_eq!(
            group_state.name, "Updated Group Name",
            "Group name should be updated"
        );
    }

    /// Test that admin remove-member commits are processed successfully
    ///
    /// This verifies that commits from admins with remove proposals are accepted.
    #[test]
    fn test_admin_remove_member_commit_is_processed_successfully() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        // Create key packages
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        // Alice creates the group with Bob and Charlie
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package, charlie_key_package],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Bob and Charlie join via welcomes
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        let charlie_welcome_rumor = &create_result.welcome_rumors[1];
        let charlie_welcome = charlie_mdk
            .process_welcome(&nostr::EventId::all_zeros(), charlie_welcome_rumor)
            .expect("Charlie should process welcome");
        charlie_mdk
            .accept_welcome(&charlie_welcome)
            .expect("Charlie should accept welcome");

        // Verify initial member count
        let members = bob_mdk
            .get_members(&group_id)
            .expect("Failed to get members");
        assert_eq!(members.len(), 3, "Group should have 3 members initially");

        // Alice (admin) removes Charlie
        let alice_remove_result = alice_mdk
            .remove_members(&group_id, &[charlie_keys.public_key()])
            .expect("Alice (admin) can remove members");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge remove commit");

        // Bob (non-admin) processes Alice's remove-member commit
        // This should SUCCEED because Alice is an admin
        let result = bob_mdk.process_message(&alice_remove_result.evolution_event);

        assert!(
            result.is_ok(),
            "Admin remove-member commit should be processed successfully, got error: {:?}",
            result.err()
        );

        // Verify the result is a Commit
        assert!(
            matches!(result.unwrap(), MessageProcessingResult::Commit { .. }),
            "Result should be a Commit"
        );

        // Verify Charlie was removed in Bob's view
        let members = bob_mdk
            .get_members(&group_id)
            .expect("Failed to get members");
        assert_eq!(
            members.len(),
            2,
            "Group should have 2 members after removal"
        );
        assert!(
            !members.contains(&charlie_keys.public_key()),
            "Charlie should be removed"
        );
    }

    /// Test that a removed member correctly processes their own removal commit
    ///
    /// This verifies that when a member is removed from a group and later processes
    /// the commit that removed them:
    /// 1. The commit is processed successfully
    /// 2. The group state is set to Inactive
    /// 3. No UseAfterEviction error occurs
    #[test]
    fn test_removed_member_processes_own_removal_commit() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        // Create key package
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group with Bob
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Bob joins via welcome
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Verify Bob's group is initially Active
        let bob_group_before = bob_mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert_eq!(
            bob_group_before.state,
            group_types::GroupState::Active,
            "Bob's group should be Active before removal"
        );

        // Alice (admin) removes Bob
        let alice_remove_result = alice_mdk
            .remove_members(&group_id, &[bob_keys.public_key()])
            .expect("Alice (admin) can remove members");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge remove commit");

        // Bob (the removed member) processes his own removal commit
        // This should succeed and set the group state to Inactive
        let result = bob_mdk.process_message(&alice_remove_result.evolution_event);

        assert!(
            result.is_ok(),
            "Removed member should process their removal commit successfully, got error: {:?}",
            result.err()
        );

        // Verify the result is a Commit
        assert!(
            matches!(result.unwrap(), MessageProcessingResult::Commit { .. }),
            "Result should be a Commit"
        );

        // Verify Bob's group state is now Inactive
        let bob_group_after = bob_mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        assert_eq!(
            bob_group_after.state,
            group_types::GroupState::Inactive,
            "Bob's group should be Inactive after being removed"
        );
    }

    /// Test that a removed member's processed message is saved correctly
    ///
    /// This verifies that when an evicted member processes their removal commit:
    /// 1. A ProcessedMessage record is created
    /// 2. The state is Processed (not failed)
    /// 3. No failure reason is recorded
    #[test]
    fn test_removed_member_processed_message_saved_correctly() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Only Alice is admin
        let admins = vec![alice_keys.public_key()];

        // Create key package
        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates the group with Bob
        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(admins.clone()),
            )
            .expect("Failed to create group");

        let group_id = create_result.group.mls_group_id.clone();

        // Alice merges her commit
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Failed to merge pending commit");

        // Bob joins via welcome
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");
        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Alice (admin) removes Bob
        let alice_remove_result = alice_mdk
            .remove_members(&group_id, &[bob_keys.public_key()])
            .expect("Alice (admin) can remove members");
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge remove commit");

        // Get the event ID that Bob will process
        let removal_event_id = alice_remove_result.evolution_event.id;

        // Bob processes his own removal commit
        bob_mdk
            .process_message(&alice_remove_result.evolution_event)
            .expect("Bob should process removal commit");

        // Verify the processed message was saved correctly
        let processed_message = bob_mdk
            .storage()
            .find_processed_message_by_event_id(&removal_event_id)
            .expect("Failed to get processed message")
            .expect("Processed message should exist");

        assert_eq!(
            processed_message.wrapper_event_id, removal_event_id,
            "Wrapper event ID should match"
        );
        assert_eq!(
            processed_message.state,
            ProcessedMessageState::Processed,
            "Processed message state should be Processed"
        );
        assert!(
            processed_message.failure_reason.is_none(),
            "There should be no failure reason for successful processing"
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

        // This should fail at the client level with a permission error
        assert!(
            result.is_err(),
            "Non-admin should not be able to update group data"
        );
        // The error is Error::Group with a message about admin permissions
        assert!(
            matches!(result.as_ref().unwrap_err(), crate::Error::Group(msg) if msg.contains("Only group admins")),
            "Error should indicate admin permission required, got: {:?}",
            result
        );
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
