//! Messages module
//!
//! This module is responsible for storing and retrieving messages
//!
//! The messages are stored in the database and can be retrieved by event ID
//!
//! Here we also define the storage traits that are used to store and retrieve messages

use crate::GroupId;
use nostr::EventId;

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
}
