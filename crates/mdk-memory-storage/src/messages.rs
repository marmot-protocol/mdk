//! Memory-based storage implementation of the MdkStorageProvider trait for Nostr MLS messages

use mdk_storage_traits::groups::GroupStorage;
use mdk_storage_traits::messages::MessageStorage;
use mdk_storage_traits::messages::error::MessageError;
use mdk_storage_traits::messages::types::*;
use nostr::EventId;

use crate::MdkMemoryStorage;

impl MessageStorage for MdkMemoryStorage {
    fn save_message(&self, message: Message) -> Result<(), MessageError> {
        // Verify that the group exists before saving the message
        match self.find_group_by_mls_group_id(&message.mls_group_id) {
            Ok(Some(_)) => {
                // Group exists, proceed with saving
            }
            Ok(None) => {
                return Err(MessageError::InvalidParameters(
                    "Group not found".to_string(),
                ));
            }
            Err(e) => {
                return Err(MessageError::InvalidParameters(format!(
                    "Failed to verify group existence: {}",
                    e
                )));
            }
        }

        // Save in the messages cache
        let mut cache = self.messages_cache.write();
        cache.put(message.id, message.clone());

        // Save in the messages_by_group cache
        let mut group_cache = self.messages_by_group_cache.write();
        match group_cache.get_mut(&message.mls_group_id) {
            Some(group_messages) => {
                // TODO: time complexity here is O(n). We probably want to use another data struct here.

                // Find and update existing message or add new one
                match group_messages.iter().position(|m| m.id == message.id) {
                    Some(idx) => {
                        group_messages[idx] = message;
                    }
                    None => {
                        group_messages.push(message);
                    }
                }
            }
            // Not found, insert new (group exists, verified above)
            None => {
                group_cache.put(message.mls_group_id.clone(), vec![message]);
            }
        }

        Ok(())
    }

    fn find_message_by_event_id(
        &self,
        event_id: &EventId,
    ) -> Result<Option<Message>, MessageError> {
        let cache = self.messages_cache.read();
        Ok(cache.peek(event_id).cloned())
    }

    fn find_processed_message_by_event_id(
        &self,
        event_id: &EventId,
    ) -> Result<Option<ProcessedMessage>, MessageError> {
        let cache = self.processed_messages_cache.read();
        Ok(cache.peek(event_id).cloned())
    }

    fn save_processed_message(
        &self,
        processed_message: ProcessedMessage,
    ) -> Result<(), MessageError> {
        let mut cache = self.processed_messages_cache.write();
        cache.put(processed_message.wrapper_event_id, processed_message);

        Ok(())
    }
}
