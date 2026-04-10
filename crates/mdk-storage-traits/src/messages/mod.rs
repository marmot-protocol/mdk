//! Messages module
//!
//! This module is responsible for storing and retrieving messages
//!
//! The messages are stored in the database and can be retrieved by event ID
//!
//! Here we also define the storage traits that are used to store and retrieve messages

use crate::GroupId;
use nostr::{EventId, Timestamp};

pub mod error;
pub mod types;

use self::error::MessageError;
use self::types::*;

/// Storage traits for the messages module
pub trait MessageStorage {
    /// Save a message
    fn save_message(&self, message: Message) -> Result<(), MessageError>;

    /// Find a message by event ID within a specific group
    ///
    /// This method requires both the event ID and the MLS group ID to prevent
    /// messages from different groups from overwriting each other.
    fn find_message_by_event_id(
        &self,
        mls_group_id: &GroupId,
        event_id: &EventId,
    ) -> Result<Option<Message>, MessageError>;

    /// Save a processed message
    fn save_processed_message(
        &self,
        processed_message: ProcessedMessage,
    ) -> Result<(), MessageError>;

    /// Find a processed message by event ID
    fn find_processed_message_by_event_id(
        &self,
        event_id: &EventId,
    ) -> Result<Option<ProcessedMessage>, MessageError>;

    /// Mark messages with epoch > target as EpochInvalidated
    /// Returns EventIds of invalidated messages
    fn invalidate_messages_after_epoch(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Vec<EventId>, MessageError>;

    /// Mark processed_messages with epoch > target as EpochInvalidated
    /// Returns wrapper EventIds of invalidated records
    fn invalidate_processed_messages_after_epoch(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Vec<EventId>, MessageError>;

    /// Find failed processed messages that may be retryable after a rollback.
    ///
    /// After a commit race rollback, messages that failed to decrypt (because they
    /// were encrypted with the correct winner's keys, but we had applied the wrong
    /// commit's keys) can now potentially be decrypted. This method finds those
    /// messages by looking for:
    /// - state = Failed
    /// - mls_group_id matches the given group
    /// - epoch is NULL (decryption failed before epoch could be determined)
    ///
    /// Returns wrapper EventIds that should be re-fetched and reprocessed.
    fn find_failed_messages_for_retry(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<EventId>, MessageError>;

    /// Find messages in EpochInvalidated state (for UI filtering or reprocessing)
    fn find_invalidated_messages(&self, group_id: &GroupId) -> Result<Vec<Message>, MessageError>;

    /// Find processed_messages in EpochInvalidated state
    fn find_invalidated_processed_messages(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProcessedMessage>, MessageError>;

    /// Mark a processed message as retryable.
    ///
    /// This is called during rollback when group state has been corrected and
    /// previously failed messages may now be processable. Only messages in
    /// `Failed` state can be marked as `Retryable`.
    ///
    /// Returns `Ok(())` if the message was successfully marked as retryable,
    /// or `Err(MessageError::NotFound)` if no failed message with that event ID exists.
    fn mark_processed_message_retryable(&self, event_id: &EventId) -> Result<(), MessageError>;

    /// Find the epoch of a message whose tags contain the given substring.
    ///
    /// This is used by encrypted media decryption to look up the epoch at which
    /// a file was originally shared, avoiding brute-force iteration over all
    /// historical epoch secrets. The caller typically searches for the IMETA tag's
    /// `x <hex_hash>` field which uniquely identifies the media file.
    ///
    /// `content_substring` is treated as a literal substring match. SQL backends
    /// must escape `%` and `_` characters to prevent LIKE wildcard expansion.
    ///
    /// Returns `Ok(Some(epoch))` if a matching message with a non-null epoch is found,
    /// `Ok(None)` if no match exists.
    fn find_message_epoch_by_tag_content(
        &self,
        group_id: &GroupId,
        content_substring: &str,
    ) -> Result<Option<u64>, MessageError>;

    /// Delete all stored messages for a group.
    ///
    /// Removes decrypted message content from local storage. Does not affect
    /// processed message records (which act as deduplication guards to prevent
    /// reprocessing), the group's MLS state, or epoch secrets.
    ///
    /// Returns the number of messages deleted. Deleting messages for a group
    /// with no messages returns `Ok(0)`.
    fn delete_messages_for_group(&self, group_id: &GroupId) -> Result<usize, MessageError>;

    /// Delete a single message by event ID within a group.
    ///
    /// Removes the decrypted message content from local storage. Does not
    /// affect processed message records, the group's MLS state, or epoch
    /// secrets.
    ///
    /// Returns `Ok(true)` if the message was found and deleted, `Ok(false)`
    /// if no message with the given event ID exists in the group.
    fn delete_message(&self, group_id: &GroupId, event_id: &EventId) -> Result<bool, MessageError>;

    /// Delete all messages in a group that were created before the given
    /// timestamp.
    ///
    /// This is intended for disappearing-message cleanup: the caller
    /// computes `now - duration` and passes it as `before`. All messages
    /// with `created_at < before` are removed.
    ///
    /// Returns the number of messages deleted.
    fn delete_messages_before_timestamp(
        &self,
        group_id: &GroupId,
        before: Timestamp,
    ) -> Result<usize, MessageError>;

    /// Delete all processed message records for a group.
    ///
    /// Removes tracking metadata (wrapper event IDs, epochs, processing
    /// state) from local storage. This means previously-seen events may be
    /// reprocessed if encountered again.
    ///
    /// Returns the number of processed message records deleted.
    fn delete_processed_messages_for_group(
        &self,
        group_id: &GroupId,
    ) -> Result<usize, MessageError>;
}
