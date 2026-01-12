//! Memory-based storage implementation of the MdkStorageProvider trait for Nostr MLS messages

use std::collections::HashMap;

use nostr::EventId;
#[cfg(test)]
use nostr::{Kind, PublicKey, Tags, Timestamp, UnsignedEvent};
#[cfg(test)]
use openmls_memory_storage::MemoryStorage;

#[cfg(test)]
use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::GroupStorage;
use mdk_storage_traits::messages::MessageStorage;
use mdk_storage_traits::messages::error::MessageError;
use mdk_storage_traits::messages::types::*;

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

        // Save in the messages_by_group cache using HashMap for O(1) insert/update
        let mut group_cache = self.messages_by_group_cache.write();
        match group_cache.get_mut(&message.mls_group_id) {
            Some(group_messages) => {
                // O(1) insert or update using HashMap
                group_messages.insert(message.id, message);
            }
            None => {
                // Create new HashMap for this group
                let mut messages = HashMap::new();
                let group_id = message.mls_group_id.clone();
                messages.insert(message.id, message);
                group_cache.put(group_id, messages);
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mdk_storage_traits::groups::GroupStorage;
    use mdk_storage_traits::groups::types::{Group, GroupState};

    use super::*;

    fn create_test_group(group_id: GroupId) -> Group {
        Group {
            mls_group_id: group_id.clone(),
            nostr_group_id: [0u8; 32],
            name: "Test Group".to_string(),
            description: "A test group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        }
    }

    fn create_test_message(
        event_id: EventId,
        group_id: GroupId,
        content: &str,
        timestamp: u64,
    ) -> Message {
        let pubkey = PublicKey::from_slice(&[1u8; 32]).unwrap();
        let wrapper_event_id = EventId::from_slice(&[200u8; 32]).unwrap();

        Message {
            id: event_id,
            pubkey,
            kind: Kind::from(1u16),
            mls_group_id: group_id,
            created_at: Timestamp::from(timestamp),
            content: content.to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::from(timestamp),
                Kind::from(9u16),
                vec![],
                content.to_string(),
            ),
            wrapper_event_id,
            state: MessageState::Created,
        }
    }

    /// Test that saving a message with the same EventId updates the existing message
    /// rather than creating a duplicate. This verifies the O(1) update behavior
    /// of the HashMap-based implementation.
    #[test]
    fn test_save_message_update_existing() {
        let storage = MdkMemoryStorage::new(MemoryStorage::default());

        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let event_id = EventId::from_slice(&[10u8; 32]).unwrap();

        // Create the group first
        let group = create_test_group(group_id.clone());
        storage.save_group(group).unwrap();

        // Save initial message
        let message1 = create_test_message(event_id, group_id.clone(), "Original content", 1000);
        storage.save_message(message1).unwrap();

        // Verify initial message is saved
        let found = storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.content, "Original content");

        // Verify the group cache has exactly 1 message
        {
            let cache = storage.messages_by_group_cache.read();
            let group_messages = cache.peek(&group_id).unwrap();
            assert_eq!(group_messages.len(), 1);
        }

        // Save updated message with same EventId but different content
        let message2 = create_test_message(event_id, group_id.clone(), "Updated content", 1001);
        storage.save_message(message2).unwrap();

        // Verify the message was updated, not duplicated
        let found = storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.content, "Updated content");
        assert_eq!(found.created_at, Timestamp::from(1001u64));

        // Verify the group cache still has exactly 1 message (no duplicates)
        {
            let cache = storage.messages_by_group_cache.read();
            let group_messages = cache.peek(&group_id).unwrap();
            assert_eq!(
                group_messages.len(),
                1,
                "Should have exactly 1 message after update, not 2"
            );
            assert_eq!(
                group_messages.get(&event_id).unwrap().content,
                "Updated content"
            );
        }
    }

    /// Test that messages are properly isolated between different groups
    #[test]
    fn test_save_message_multiple_groups() {
        let storage = MdkMemoryStorage::new(MemoryStorage::default());

        let group1_id = GroupId::from_slice(&[1, 1, 1, 1]);
        let group2_id = GroupId::from_slice(&[2, 2, 2, 2]);

        // Create the groups first
        let group1 = create_test_group(group1_id.clone());
        storage.save_group(group1).unwrap();
        let group2 = create_test_group(group2_id.clone());
        storage.save_group(group2).unwrap();

        // Save messages to group 1
        for i in 0..3 {
            let event_id = EventId::from_slice(&[i as u8; 32]).unwrap();
            let message = create_test_message(
                event_id,
                group1_id.clone(),
                &format!("Group1 Message {}", i),
                1000 + i as u64,
            );
            storage.save_message(message).unwrap();
        }

        // Save messages to group 2
        for i in 0..5 {
            let event_id = EventId::from_slice(&[100 + i as u8; 32]).unwrap();
            let message = create_test_message(
                event_id,
                group2_id.clone(),
                &format!("Group2 Message {}", i),
                2000 + i as u64,
            );
            storage.save_message(message).unwrap();
        }

        // Verify group 1 has 3 messages
        {
            let cache = storage.messages_by_group_cache.read();
            let group1_messages = cache.peek(&group1_id).unwrap();
            assert_eq!(group1_messages.len(), 3);
        }

        // Verify group 2 has 5 messages
        {
            let cache = storage.messages_by_group_cache.read();
            let group2_messages = cache.peek(&group2_id).unwrap();
            assert_eq!(group2_messages.len(), 5);
        }

        // Verify messages are correctly associated with their groups
        let event_id_group1 = EventId::from_slice(&[0u8; 32]).unwrap();
        let found = storage
            .find_message_by_event_id(&event_id_group1)
            .unwrap()
            .unwrap();
        assert_eq!(found.mls_group_id, group1_id);
        assert!(found.content.contains("Group1"));

        let event_id_group2 = EventId::from_slice(&[100u8; 32]).unwrap();
        let found = storage
            .find_message_by_event_id(&event_id_group2)
            .unwrap()
            .unwrap();
        assert_eq!(found.mls_group_id, group2_id);
        assert!(found.content.contains("Group2"));
    }

    /// Test that multiple updates to the same message work correctly
    #[test]
    fn test_save_message_multiple_updates() {
        let storage = MdkMemoryStorage::new(MemoryStorage::default());

        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let event_id = EventId::from_slice(&[50u8; 32]).unwrap();

        // Create the group first
        let group = create_test_group(group_id.clone());
        storage.save_group(group).unwrap();

        // Perform multiple updates to the same message
        for i in 0..10 {
            let message = create_test_message(
                event_id,
                group_id.clone(),
                &format!("Version {}", i),
                1000 + i as u64,
            );
            storage.save_message(message).unwrap();
        }

        // Verify only the final version exists
        let found = storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.content, "Version 9");

        // Verify the group cache has exactly 1 message
        {
            let cache = storage.messages_by_group_cache.read();
            let group_messages = cache.peek(&group_id).unwrap();
            assert_eq!(
                group_messages.len(),
                1,
                "Should have exactly 1 message after 10 updates"
            );
        }
    }

    /// Test that updating message state works correctly
    #[test]
    fn test_save_message_state_update() {
        let storage = MdkMemoryStorage::new(MemoryStorage::default());

        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let event_id = EventId::from_slice(&[75u8; 32]).unwrap();

        // Create the group first
        let group = create_test_group(group_id.clone());
        storage.save_group(group).unwrap();

        // Save message with Created state
        let mut message = create_test_message(event_id, group_id.clone(), "Test content", 1000);
        message.state = MessageState::Created;
        storage.save_message(message).unwrap();

        // Verify initial state
        let found = storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.state, MessageState::Created);

        // Update message with Processed state
        let mut message = create_test_message(event_id, group_id.clone(), "Test content", 1000);
        message.state = MessageState::Processed;
        storage.save_message(message).unwrap();

        // Verify state was updated
        let found = storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.state, MessageState::Processed);

        // Verify still only 1 message in the group
        {
            let cache = storage.messages_by_group_cache.read();
            let group_messages = cache.peek(&group_id).unwrap();
            assert_eq!(group_messages.len(), 1);
        }
    }
}
