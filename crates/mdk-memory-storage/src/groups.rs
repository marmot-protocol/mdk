//! Memory-based storage implementation of the MdkStorageProvider trait for Nostr MLS groups

use std::collections::BTreeSet;

use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::error::GroupError;
use mdk_storage_traits::groups::types::*;
use mdk_storage_traits::groups::{GroupStorage, MAX_MESSAGE_LIMIT, Pagination};
use mdk_storage_traits::messages::types::Message;
use nostr::{PublicKey, RelayUrl};

use crate::MdkMemoryStorage;

impl GroupStorage for MdkMemoryStorage {
    fn save_group(&self, group: Group) -> Result<(), GroupError> {
        // Store in the MLS group ID cache
        {
            let mut cache = self.groups_cache.write();
            cache.put(group.mls_group_id.clone(), group.clone());
        }

        // Store in the Nostr group ID cache
        {
            let mut cache = self.groups_by_nostr_id_cache.write();
            cache.put(group.nostr_group_id, group);
        }

        Ok(())
    }

    fn all_groups(&self) -> Result<Vec<Group>, GroupError> {
        let cache = self.groups_cache.read();
        // Convert the values from the cache to a Vec
        let groups: Vec<Group> = cache.iter().map(|(_, v)| v.clone()).collect();
        Ok(groups)
    }

    fn find_group_by_mls_group_id(
        &self,
        mls_group_id: &GroupId,
    ) -> Result<Option<Group>, GroupError> {
        let cache = self.groups_cache.read();
        Ok(cache.peek(mls_group_id).cloned())
    }

    fn find_group_by_nostr_group_id(
        &self,
        nostr_group_id: &[u8; 32],
    ) -> Result<Option<Group>, GroupError> {
        let cache = self.groups_by_nostr_id_cache.read();
        Ok(cache.peek(nostr_group_id).cloned())
    }

    fn messages(
        &self,
        mls_group_id: &GroupId,
        pagination: Option<Pagination>,
    ) -> Result<Vec<Message>, GroupError> {
        let pagination = pagination.unwrap_or_default();
        let limit = pagination.limit();
        let offset = pagination.offset();

        // Validate limit is within allowed range
        if !(1..=MAX_MESSAGE_LIMIT).contains(&limit) {
            return Err(GroupError::InvalidParameters(format!(
                "Limit must be between 1 and {}, got {}",
                MAX_MESSAGE_LIMIT, limit
            )));
        }

        // Check if the group exists first
        if self.find_group_by_mls_group_id(mls_group_id)?.is_none() {
            return Err(GroupError::InvalidParameters("Group not found".to_string()));
        }

        let cache = self.messages_by_group_cache.read();
        match cache.peek(mls_group_id) {
            Some(messages_map) => {
                // Collect values from IndexMap into a Vec for sorting
                let mut messages: Vec<Message> = messages_map.values().cloned().collect();

                // Sort by created_at DESC (newest first)
                messages.sort_by(|a, b| b.created_at.cmp(&a.created_at));

                // Apply pagination
                let start = offset.min(messages.len());
                let end = (offset + limit).min(messages.len());

                Ok(messages[start..end].to_vec())
            }
            // If not in cache but group exists, return empty vector
            None => Ok(Vec::new()),
        }
    }

    fn admins(&self, mls_group_id: &GroupId) -> Result<BTreeSet<PublicKey>, GroupError> {
        match self.find_group_by_mls_group_id(mls_group_id)? {
            Some(group) => Ok(group.admin_pubkeys),
            None => Err(GroupError::InvalidParameters(format!(
                "Group with MLS ID {:?} not found",
                mls_group_id
            ))),
        }
    }

    fn group_relays(&self, mls_group_id: &GroupId) -> Result<BTreeSet<GroupRelay>, GroupError> {
        // Check if the group exists first
        if self.find_group_by_mls_group_id(mls_group_id)?.is_none() {
            return Err(GroupError::InvalidParameters("Group not found".to_string()));
        }

        let cache = self.group_relays_cache.read();
        match cache.peek(mls_group_id).cloned() {
            Some(relays) => Ok(relays),
            // If not in cache but group exists, return empty set
            None => Ok(BTreeSet::new()),
        }
    }

    fn replace_group_relays(
        &self,
        group_id: &GroupId,
        relays: BTreeSet<RelayUrl>,
    ) -> Result<(), GroupError> {
        // Check if the group exists first
        if self.find_group_by_mls_group_id(group_id)?.is_none() {
            return Err(GroupError::InvalidParameters("Group not found".to_string()));
        }

        let mut cache = self.group_relays_cache.write();

        // Convert RelayUrl set to GroupRelay set
        let group_relays: BTreeSet<GroupRelay> = relays
            .into_iter()
            .map(|relay_url| GroupRelay {
                mls_group_id: group_id.clone(),
                relay_url,
            })
            .collect();

        // Replace the entire relay set for this group
        cache.put(group_id.clone(), group_relays);

        Ok(())
    }

    fn get_group_exporter_secret(
        &self,
        mls_group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<GroupExporterSecret>, GroupError> {
        // Check if the group exists first
        if self.find_group_by_mls_group_id(mls_group_id)?.is_none() {
            return Err(GroupError::InvalidParameters("Group not found".to_string()));
        }

        let cache = self.group_exporter_secrets_cache.read();
        // Use tuple (GroupId, epoch) as key
        Ok(cache.peek(&(mls_group_id.clone(), epoch)).cloned())
    }

    fn save_group_exporter_secret(
        &self,
        group_exporter_secret: GroupExporterSecret,
    ) -> Result<(), GroupError> {
        // Check if the group exists first
        if self
            .find_group_by_mls_group_id(&group_exporter_secret.mls_group_id)?
            .is_none()
        {
            return Err(GroupError::InvalidParameters("Group not found".to_string()));
        }

        let mut cache = self.group_exporter_secrets_cache.write();
        // Use tuple (GroupId, epoch) as key
        let key = (
            group_exporter_secret.mls_group_id.clone(),
            group_exporter_secret.epoch,
        );
        cache.put(key, group_exporter_secret);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdk_storage_traits::groups::types::GroupState;
    use mdk_storage_traits::messages::MessageStorage;
    use mdk_storage_traits::messages::types::{Message, MessageState};
    use nostr::{EventId, Kind, PublicKey, Tags, Timestamp, UnsignedEvent};
    use openmls_memory_storage::MemoryStorage;

    #[test]
    fn test_messages_pagination_memory() {
        let storage = MdkMemoryStorage::new(MemoryStorage::default());

        // Create a test group
        let mls_group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let nostr_group_id = [1u8; 32];

        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
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
        };

        storage.save_group(group).unwrap();

        // Create 25 test messages
        let pubkey = PublicKey::from_slice(&[1u8; 32]).unwrap();
        for i in 0..25 {
            let event_id = EventId::from_slice(&[i as u8; 32]).unwrap();
            let wrapper_event_id = EventId::from_slice(&[100 + i as u8; 32]).unwrap();

            let message = Message {
                id: event_id,
                pubkey,
                kind: Kind::from(1u16),
                mls_group_id: mls_group_id.clone(),
                created_at: Timestamp::from((1000 + i) as u64),
                content: format!("Message {}", i),
                tags: Tags::new(),
                event: UnsignedEvent::new(
                    pubkey,
                    Timestamp::from((1000 + i) as u64),
                    Kind::from(9u16),
                    vec![],
                    format!("content {}", i),
                ),
                wrapper_event_id,
                state: MessageState::Created,
            };

            storage.save_message(message).unwrap();
        }

        // Test 1: Get all messages with default limit
        let all_messages = storage.messages(&mls_group_id, None).unwrap();
        assert_eq!(all_messages.len(), 25);

        // Test 2: Get first 10 messages
        let page1 = storage
            .messages(&mls_group_id, Some(Pagination::new(Some(10), Some(0))))
            .unwrap();
        assert_eq!(page1.len(), 10);
        // Should be newest first (highest timestamp)
        assert_eq!(page1[0].content, "Message 24");

        // Test 3: Get next 10 messages (offset 10)
        let page2 = storage
            .messages(&mls_group_id, Some(Pagination::new(Some(10), Some(10))))
            .unwrap();
        assert_eq!(page2.len(), 10);
        assert_eq!(page2[0].content, "Message 14");

        // Test 4: Get last 5 messages (offset 20)
        let page3 = storage
            .messages(&mls_group_id, Some(Pagination::new(Some(10), Some(20))))
            .unwrap();
        assert_eq!(page3.len(), 5);
        assert_eq!(page3[0].content, "Message 4");

        // Test 5: Offset beyond available messages returns empty
        let beyond = storage
            .messages(&mls_group_id, Some(Pagination::new(Some(10), Some(30))))
            .unwrap();
        assert_eq!(beyond.len(), 0);

        // Test 6: Verify no overlap between pages
        let first_id = page1[0].id;
        let second_page_ids: Vec<EventId> = page2.iter().map(|m| m.id).collect();
        assert!(
            !second_page_ids.contains(&first_id),
            "Pages should not overlap"
        );

        // Test 7: Verify ordering is descending by created_at
        for i in 0..page1.len() - 1 {
            assert!(
                page1[i].created_at >= page1[i + 1].created_at,
                "Messages should be ordered by created_at descending"
            );
        }

        // Test 8: Limit of 0 should return error
        let result = storage.messages(&mls_group_id, Some(Pagination::new(Some(0), Some(0))));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be between 1 and")
        );

        // Test 9: Limit exceeding MAX should return error
        let result = storage.messages(&mls_group_id, Some(Pagination::new(Some(20000), Some(0))));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be between 1 and")
        );

        // Test 10: Non-existent group returns error
        let fake_group_id = GroupId::from_slice(&[99, 99, 99, 99]);
        let result = storage.messages(&fake_group_id, Some(Pagination::new(Some(10), Some(0))));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        // Test 11: Empty results when group has no messages
        let empty_group_id = GroupId::from_slice(&[5, 6, 7, 8]);
        let empty_group = Group {
            mls_group_id: empty_group_id.clone(),
            nostr_group_id: [2u8; 32],
            name: "Empty Group".to_string(),
            description: "A group with no messages".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        storage.save_group(empty_group).unwrap();

        let empty = storage
            .messages(&empty_group_id, Some(Pagination::new(Some(10), Some(0))))
            .unwrap();
        assert_eq!(empty.len(), 0);

        // Test 12: Large offset should work (no MAX_OFFSET validation)
        let result = storage.messages(
            &mls_group_id,
            Some(Pagination::new(Some(10), Some(2_000_000))),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0); // No results at that offset
    }
}
