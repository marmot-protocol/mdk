//! Error recovery and failure persistence
//!
//! This module handles error recovery logic and saving failed message records.

use mdk_storage_traits::groups::types as group_types;
use mdk_storage_traits::messages::types as message_types;
use mdk_storage_traits::{GroupId, MdkStorageProvider};
use nostr::{Event, EventId, Timestamp};

use crate::MDK;
use crate::error::Error;

use super::{MessageProcessingResult, Result};

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Sanitizes an error into a safe-to-expose failure reason
    ///
    /// This function maps internal errors to generic, safe-to-expose failure categories
    /// that don't leak implementation details or sensitive information.
    ///
    /// # Arguments
    ///
    /// * `error` - The internal error to sanitize
    ///
    /// # Returns
    ///
    /// A sanitized string suitable for external exposure
    pub(super) fn sanitize_error_reason(error: &Error) -> &'static str {
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

    /// Records a failed message processing attempt to prevent reprocessing
    ///
    /// This method saves a failed processing record with a sanitized error reason.
    /// If `group` is provided, epoch and group_id are taken from it.
    /// Otherwise, falls back to any existing record's context.
    ///
    /// # Arguments
    ///
    /// * `event_id` - The event ID of the failed message
    /// * `error` - The error that caused the failure (will be sanitized for storage)
    /// * `group` - Optional group context for epoch/group_id
    pub(super) fn record_failure(
        &self,
        event_id: EventId,
        error: &Error,
        group: Option<&group_types::Group>,
    ) -> Result<()> {
        let sanitized_reason = Self::sanitize_error_reason(error);

        tracing::warn!(
            target: "mdk_core::messages::record_failure",
            "Message processing failed for event {}: {}",
            event_id,
            sanitized_reason
        );

        // Try to fetch existing record to preserve message_event_id and other context
        let existing_record = match self.storage().find_processed_message_by_event_id(&event_id) {
            Ok(record) => record,
            Err(e) => {
                tracing::warn!(
                    target: "mdk_core::messages::record_failure",
                    "Failed to fetch existing record for context preservation: {}",
                    e
                );
                None
            }
        };

        let message_event_id = existing_record.as_ref().and_then(|r| r.message_event_id);

        // Use group context if provided, otherwise fallback to existing record
        let (epoch, mls_group_id) = match group {
            Some(g) => (Some(g.epoch), Some(g.mls_group_id.clone())),
            None => (
                existing_record.as_ref().and_then(|r| r.epoch),
                existing_record
                    .as_ref()
                    .and_then(|r| r.mls_group_id.clone()),
            ),
        };

        let processed_message = super::create_processed_message_record(
            event_id,
            message_event_id,
            epoch,
            mls_group_id,
            message_types::ProcessedMessageState::Failed,
            Some(sanitized_reason.to_string()),
        );

        self.save_processed_message_record(processed_message)?;

        Ok(())
    }

    /// Records a failure and returns an Unprocessable result
    ///
    /// Convenience method combining failure recording with returning Unprocessable.
    pub(super) fn fail_unprocessable(
        &self,
        event_id: EventId,
        error: &Error,
        group: &group_types::Group,
    ) -> Result<MessageProcessingResult> {
        self.record_failure(event_id, error, Some(group))?;

        Ok(MessageProcessingResult::Unprocessable {
            mls_group_id: group.mls_group_id.clone(),
        })
    }

    /// Returns a Commit result for our own already-processed commit
    ///
    /// Syncs group metadata and returns a Commit result. Used when we encounter
    /// our own commit that we've already processed.
    pub(super) fn return_own_commit(
        &self,
        group: &group_types::Group,
    ) -> Result<MessageProcessingResult> {
        self.sync_group_metadata_from_mls(&group.mls_group_id)
            .map_err(|e| Error::Message(format!("Failed to sync group metadata: {}", e)))?;

        Ok(MessageProcessingResult::Commit {
            mls_group_id: group.mls_group_id.clone(),
        })
    }

    /// Handles processing errors with specific error recovery logic
    ///
    /// This method handles complex error scenarios when message processing fails,
    /// including special cases like processing own messages, epoch mismatches, and
    /// other MLS-specific validation errors.
    ///
    /// # Arguments
    ///
    /// * `error` - The error that occurred during processing
    /// * `event` - The wrapper Nostr event that caused the error
    /// * `group` - The group metadata from storage
    ///
    /// # Returns
    ///
    /// * `Ok(MessageProcessingResult)` - Recovery result or unprocessable status
    /// * `Err(Error)` - If error handling itself fails
    pub(super) fn handle_processing_error(
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
                    message_types::ProcessedMessageState::Retryable => {
                        // Retryable messages are ones that previously failed due to wrong epoch keys
                        // but have been marked for retry after a rollback. For our own messages,
                        // we should have cached content - try to retrieve and return it.
                        tracing::debug!(target: "mdk_core::messages::process_message", "Retrying own message after rollback");

                        if let Some(message_event_id) = processed_message.message_event_id {
                            match self
                                .get_message(&group.mls_group_id, &message_event_id)
                                .map_err(|e| Error::Message(e.to_string()))?
                            {
                                Some(mut message) => {
                                    // Update states to mark as successfully processed
                                    message.state = message_types::MessageState::Processed;
                                    self.storage()
                                        .save_message(message)
                                        .map_err(|e| Error::Message(e.to_string()))?;

                                    processed_message.state =
                                        message_types::ProcessedMessageState::Processed;
                                    processed_message.failure_reason = None;
                                    processed_message.processed_at = Timestamp::now();
                                    self.storage()
                                        .save_processed_message(processed_message.clone())
                                        .map_err(|e| Error::Message(e.to_string()))?;

                                    tracing::info!(
                                        target: "mdk_core::messages::process_message",
                                        "Successfully retried own cached message after rollback"
                                    );
                                    let message = self
                                        .get_message(&group.mls_group_id, &message_event_id)
                                        .map_err(|e| Error::Message(e.to_string()))?
                                        .ok_or(Error::MessageNotFound)?;
                                    return Ok(MessageProcessingResult::ApplicationMessage(
                                        message,
                                    ));
                                }
                                None => {
                                    // No cached content available - fall through to Unprocessable
                                }
                            }
                        }

                        // No cached content available - this shouldn't happen for our own messages,
                        // but if it does, we can't recover
                        tracing::warn!(
                            target: "mdk_core::messages::process_message",
                            "Retryable own message has no cached content - cannot recover"
                        );
                        Ok(MessageProcessingResult::Unprocessable {
                            mls_group_id: group.mls_group_id.clone(),
                        })
                    }
                    message_types::ProcessedMessageState::ProcessedCommit => {
                        tracing::debug!(target: "mdk_core::messages::process_message", "Message already processed as a commit");
                        self.return_own_commit(group)
                    }
                    message_types::ProcessedMessageState::Processed
                    | message_types::ProcessedMessageState::Failed
                    | message_types::ProcessedMessageState::EpochInvalidated => {
                        tracing::debug!(target: "mdk_core::messages::process_message", "Message cannot be processed (already processed, failed, or epoch invalidated)");
                        Ok(MessageProcessingResult::Unprocessable {
                            mls_group_id: group.mls_group_id.clone(),
                        })
                    }
                }
            }
            Error::ProcessMessageWrongEpoch(msg_epoch) => {
                // Check if this commit is "better" than what we have for this epoch
                let is_better = self.epoch_snapshots.is_better_candidate(
                    self.storage(),
                    &group.mls_group_id,
                    msg_epoch,
                    event.created_at.as_secs(),
                    &event.id,
                );

                if is_better {
                    tracing::info!("Found better commit for epoch {}. Rolling back.", msg_epoch);

                    match self.epoch_snapshots.rollback_to_epoch(
                        self.storage(),
                        &group.mls_group_id,
                        msg_epoch,
                    ) {
                        Ok(_) => {
                            tracing::info!("Rollback successful. Re-processing better commit.");

                            // Invalidate messages from epochs after the rollback target
                            // These are messages processed with the wrong commit's keys - they
                            // can never be decrypted again and should be marked as invalidated
                            let invalidated_messages = self
                                .storage()
                                .invalidate_messages_after_epoch(&group.mls_group_id, msg_epoch)
                                .unwrap_or_default();

                            // Also invalidate processed_messages from wrong epochs
                            let _ = self.storage().invalidate_processed_messages_after_epoch(
                                &group.mls_group_id,
                                msg_epoch,
                            );

                            // Find messages that failed to decrypt because we had the wrong
                            // commit's keys. Now that we've rolled back and will apply the
                            // correct commit, these can potentially be decrypted.
                            let messages_needing_refetch = self
                                .storage()
                                .find_failed_messages_for_retry(&group.mls_group_id)
                                .unwrap_or_default();

                            // Mark these messages as Retryable so they can pass through
                            // deduplication when the application re-fetches and reprocesses them
                            for event_id in &messages_needing_refetch {
                                if self
                                    .storage()
                                    .mark_processed_message_retryable(event_id)
                                    .is_err()
                                {
                                    tracing::warn!(
                                        target: "mdk_core::messages::process_message",
                                        "Failed to mark message {} as retryable",
                                        event_id
                                    );
                                }
                            }

                            if let Some(cb) = &self.callback {
                                cb.on_rollback(&crate::RollbackInfo {
                                    group_id: group.mls_group_id.clone(),
                                    target_epoch: msg_epoch,
                                    new_head_event: event.id,
                                    invalidated_messages,
                                    messages_needing_refetch,
                                });
                            }

                            // Recursively call process_message now that state is rolled back.
                            // This will reload the group and apply the new commit.
                            return self.process_message(event);
                        }
                        Err(_) => {
                            tracing::error!("Rollback failed");
                            // Fall through to standard error handling
                        }
                    }
                }

                // Epoch mismatch - check if this is our own commit that we've already processed
                if let Ok(Some(processed_message)) =
                    self.storage().find_processed_message_by_event_id(&event.id)
                    && processed_message.state
                        == message_types::ProcessedMessageState::ProcessedCommit
                {
                    tracing::debug!(target: "mdk_core::messages::process_message", "Found own commit with epoch mismatch, syncing group metadata");
                    return self.return_own_commit(group);
                }

                // Not our own commit - this is a genuine error
                tracing::error!(target: "mdk_core::messages::process_message", "Epoch mismatch for message that is not our own commit");
                self.fail_unprocessable(event.id, &error, group)
            }
            Error::ProcessMessageWrongGroupId => {
                tracing::error!(target: "mdk_core::messages::process_message", "Group ID mismatch");
                self.fail_unprocessable(event.id, &error, group)
            }
            Error::ProcessMessageUseAfterEviction => {
                tracing::error!(target: "mdk_core::messages::process_message", "Attempted to use group after eviction");
                self.fail_unprocessable(event.id, &error, group)
            }
            Error::CommitFromNonAdmin => {
                // Authorization errors should propagate as errors, not be silently swallowed
                // Save a failed processing record to prevent reprocessing (best-effort)
                if let Err(_save_err) = self.record_failure(event.id, &error, Some(group)) {
                    tracing::warn!(
                        target: "mdk_core::messages::handle_processing_error",
                        "Failed to persist failure record for commit from non-admin"
                    );
                }
                Err(error)
            }
            _ => {
                tracing::error!(target: "mdk_core::messages::process_message", "Unexpected error processing message");
                self.fail_unprocessable(event.id, &error, group)
            }
        }
    }

    /// Extracts the MLS group ID from an event's h-tag
    ///
    /// This helper extracts the Nostr group ID from the event's h-tag and looks up
    /// the corresponding MLS group ID in storage.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to extract the group ID from
    ///
    /// # Returns
    ///
    /// `Some(GroupId)` if the group is found in storage,
    /// `None` if the h-tag is missing/malformed or the group isn't in storage.
    pub(super) fn extract_mls_group_id_from_event(&self, event: &Event) -> Option<GroupId> {
        let nostr_group_id = self.extract_nostr_group_id(event).ok()?;

        self.storage()
            .find_group_by_nostr_group_id(&nostr_group_id)
            .ok()
            .flatten()
            .map(|group| group.mls_group_id)
    }
}

#[cfg(test)]
mod tests {
    use mdk_storage_traits::GroupId;
    use mdk_storage_traits::messages::MessageStorage;
    use mdk_storage_traits::messages::types as message_types;
    use nostr::{EventBuilder, EventId, Keys, Kind, Tag, TagKind, Timestamp};

    use crate::error::Error;
    use crate::test_util::*;
    use crate::tests::create_test_mdk;

    use super::super::MessageProcessingResult;

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
    ///
    /// When a previously failed message cannot provide a valid group_id (missing or
    /// malformed h-tag), we return an error to be explicit about the failure.
    #[test]
    fn test_repeated_validation_failure_rejected_immediately() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create an event with wrong kind (no group_id tag)
        let event = EventBuilder::new(Kind::Metadata, "")
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - full validation
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail validation");

        // Second attempt - should be rejected immediately via deduplication
        // Returns error because group_id cannot be extracted from malformed event
        let result2 = mdk.process_message(&event);
        assert!(
            result2.is_err(),
            "Second attempt should return error for malformed event without valid h-tag"
        );
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Should indicate message previously failed"
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
    /// preventing expensive repeated decryption attempts. When the group doesn't exist
    /// in storage, we return an error since we can't determine the MLS group ID.
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

        // Second attempt - should return error because group isn't in storage
        // (we can't determine the MLS group ID from just the Nostr group ID)
        let result2 = mdk.process_message(&event);
        assert!(
            result2.is_err(),
            "Second attempt should return error when group not in storage"
        );
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Should indicate message previously failed"
        );
    }

    /// Test that previously failed message without group in storage returns error
    ///
    /// This test verifies that when a previously failed message has a valid h-tag
    /// but the group doesn't exist in storage, we return an error since we can't
    /// determine the MLS group ID (Nostr group ID != MLS group ID).
    #[test]
    fn test_previously_failed_message_without_group_in_storage() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create a valid nostr_group_id but don't create the group in storage
        let nostr_group_id_bytes = [42u8; 32];
        let nostr_group_id_hex = hex::encode(nostr_group_id_bytes);

        // Create an event with valid h-tag but group doesn't exist
        let tag = Tag::custom(TagKind::h(), [nostr_group_id_hex.clone()]);
        let event = EventBuilder::new(Kind::MlsGroupMessage, "invalid_encrypted_content")
            .tag(tag)
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - will fail (group doesn't exist)
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail");

        // Verify failed state was persisted
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap()
            .expect("Failed record should exist");
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed,
            "State should be Failed"
        );

        // Second attempt - should return error because we can't determine MLS group ID
        let result2 = mdk.process_message(&event);
        assert!(
            result2.is_err(),
            "Second attempt should return error when group not in storage"
        );
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Should indicate message previously failed"
        );
    }

    /// Test that previously failed message with oversized hex in h-tag returns error
    ///
    /// This test verifies that when a previously failed message has an oversized hex string
    /// in the h-tag (potential DoS vector), the size check prevents decoding and returns
    /// an explicit error.
    #[test]
    fn test_previously_failed_message_with_oversized_hex() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create an oversized hex string (128 chars instead of 64)
        let oversized_hex = "a".repeat(128);
        let tag = Tag::custom(TagKind::h(), [oversized_hex]);
        let event = EventBuilder::new(Kind::MlsGroupMessage, "invalid_content")
            .tag(tag)
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - will fail
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail");

        // Verify failed state was persisted
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap()
            .expect("Failed record should exist");
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed
        );

        // Second attempt - should return error due to malformed h-tag
        let result2 = mdk.process_message(&event);
        assert!(
            result2.is_err(),
            "Second attempt should return error for oversized hex"
        );
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Should indicate message previously failed"
        );
    }

    /// Test that previously failed message with undersized hex in h-tag returns error
    ///
    /// This test verifies that when a previously failed message has an undersized hex string
    /// in the h-tag, the size check prevents decoding and returns an explicit error.
    #[test]
    fn test_previously_failed_message_with_undersized_hex() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create an undersized hex string (32 chars instead of 64)
        let undersized_hex = "a".repeat(32);
        let tag = Tag::custom(TagKind::h(), [undersized_hex]);
        let event = EventBuilder::new(Kind::MlsGroupMessage, "invalid_content")
            .tag(tag)
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - will fail
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail");

        // Verify failed state was persisted
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap()
            .expect("Failed record should exist");
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed
        );

        // Second attempt - should return error due to malformed h-tag
        let result2 = mdk.process_message(&event);
        assert!(
            result2.is_err(),
            "Second attempt should return error for undersized hex"
        );
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Should indicate message previously failed"
        );
    }

    /// Test that previously failed message with group in storage returns correct MLS group ID
    ///
    /// This test verifies that when a group exists in storage, the code looks up and returns
    /// the actual MLS group ID (not just the Nostr group ID).
    #[test]
    fn test_previously_failed_message_with_group_in_storage() {
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();

        // Create a real group in storage
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Get the group to extract its nostr_group_id
        let group = mdk
            .get_group(&group_id)
            .expect("Failed to get group")
            .expect("Group should exist");
        let nostr_group_id_hex = hex::encode(group.nostr_group_id);

        // Create an event with the group's nostr_group_id but invalid content
        let keys = Keys::generate();
        let tag = Tag::custom(TagKind::h(), [nostr_group_id_hex]);
        let event = EventBuilder::new(Kind::MlsGroupMessage, "invalid_encrypted_content")
            .tag(tag)
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - will fail (invalid content)
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail");

        // Verify failed state was persisted
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap()
            .expect("Failed record should exist");
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed
        );

        // Second attempt - should return Unprocessable with the MLS group ID from storage
        let result2 = mdk.process_message(&event);
        assert!(
            result2.is_ok(),
            "Second attempt should return Ok(Unprocessable)"
        );

        match result2.unwrap() {
            MessageProcessingResult::Unprocessable { mls_group_id } => {
                // Verify it returned the actual MLS group ID from storage
                assert_eq!(
                    mls_group_id, group_id,
                    "Should return MLS group ID from storage, not Nostr group ID"
                );
            }
            other => panic!("Expected Unprocessable, got: {:?}", other),
        }
    }

    /// Test that previously failed message with invalid hex characters returns error
    ///
    /// This test verifies that when hex::decode fails due to invalid characters,
    /// the code returns an explicit error.
    #[test]
    fn test_previously_failed_message_with_invalid_hex_chars() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create invalid hex string (64 chars but contains non-hex characters like 'z')
        let invalid_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(
            invalid_hex.len(),
            64,
            "Should be 64 chars to pass length check"
        );

        let tag = Tag::custom(TagKind::h(), [invalid_hex]);
        let event = EventBuilder::new(Kind::MlsGroupMessage, "invalid_content")
            .tag(tag)
            .sign_with_keys(&keys)
            .unwrap();

        // First attempt - will fail
        let result1 = mdk.process_message(&event);
        assert!(result1.is_err(), "First attempt should fail");

        // Verify failed state was persisted
        let processed = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap()
            .expect("Failed record should exist");
        assert_eq!(
            processed.state,
            message_types::ProcessedMessageState::Failed
        );

        // Second attempt - should return error due to invalid hex
        let result2 = mdk.process_message(&event);
        assert!(
            result2.is_err(),
            "Second attempt should return error for invalid hex chars"
        );
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Message processing previously failed"),
            "Should indicate message previously failed"
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
            processed_at: Timestamp::now(),
            epoch: None,
            mls_group_id: None,
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

    #[test]
    fn test_previously_failed_message_returns_unprocessable_not_error() {
        // Setup: Create MDK and a test group
        let mdk = create_test_mdk();
        let (creator, members, admins) = create_test_group_members();
        let group_id = create_test_group(&mdk, &creator, &members, &admins);

        // Create a test message event
        let rumor = create_test_rumor(&creator, "Test message");
        let event = mdk
            .create_message(&group_id, rumor)
            .expect("Failed to create message");

        // Manually mark the message as failed in storage
        // This simulates a message that previously failed processing
        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: None,
            processed_at: Timestamp::now(),
            epoch: None,
            mls_group_id: None,
            state: message_types::ProcessedMessageState::Failed,
            failure_reason: Some("Simulated failure for test".to_string()),
        };

        mdk.storage()
            .save_processed_message(processed_message)
            .expect("Failed to save processed message");

        // Try to process the message again
        // Before the fix: This would return Err() and crash apps
        // After the fix: This should return Ok(Unprocessable)
        let result = mdk.process_message(&event);

        // Assert: Should return Ok with Unprocessable, not Err
        assert!(
            result.is_ok(),
            "Should not throw error for previously failed message, got error: {:?}",
            result.as_ref().err()
        );

        // Verify it returns Unprocessable variant
        match result.unwrap() {
            MessageProcessingResult::Unprocessable { mls_group_id } => {
                // Just verify we got a valid group_id (not empty)
                assert!(
                    !mls_group_id.as_slice().is_empty(),
                    "Should return a non-empty group ID"
                );
            }
            other => panic!(
                "Expected MessageProcessingResult::Unprocessable, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_record_failure_preserves_message_event_id() {
        let mdk = create_test_mdk();
        let keys = Keys::generate();

        // Create a test event
        let event = EventBuilder::new(Kind::Metadata, "")
            .sign_with_keys(&keys)
            .unwrap();

        // Create a fake message event ID
        let message_event_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        // Manually save a Created state with message_event_id (simulating a message we created/sent)
        let processed_message = message_types::ProcessedMessage {
            wrapper_event_id: event.id,
            message_event_id: Some(message_event_id),
            processed_at: Timestamp::now(),
            epoch: Some(123),
            mls_group_id: Some(GroupId::from_slice(&[1, 2, 3, 4])),
            state: message_types::ProcessedMessageState::Created,
            failure_reason: None,
        };
        mdk.storage()
            .save_processed_message(processed_message)
            .unwrap();

        // Now simulate a failure (e.g. decryption failed for own message)
        let error = Error::CannotDecryptOwnMessage;
        mdk.record_failure(event.id, &error, None).unwrap();

        // Verify the message_event_id is preserved
        let updated_record = mdk
            .storage()
            .find_processed_message_by_event_id(&event.id)
            .unwrap()
            .expect("Record should exist");

        assert_eq!(
            updated_record.state,
            message_types::ProcessedMessageState::Failed
        );
        assert_eq!(
            updated_record.message_event_id,
            Some(message_event_id),
            "message_event_id should be preserved"
        );
        assert_eq!(updated_record.epoch, Some(123), "epoch should be preserved");
        assert_eq!(
            updated_record.mls_group_id,
            Some(GroupId::from_slice(&[1, 2, 3, 4])),
            "mls_group_id should be preserved"
        );
    }
}
