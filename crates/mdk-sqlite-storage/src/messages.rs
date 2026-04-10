//! Implementation of MessageStorage trait for SQLite storage.

use mdk_storage_traits::messages::MessageStorage;
use mdk_storage_traits::messages::error::MessageError;
use mdk_storage_traits::messages::types::{Message, ProcessedMessage};
use nostr::{EventId, JsonUtil, Timestamp};
use rusqlite::{OptionalExtension, params};

use crate::validation::{
    MAX_EVENT_JSON_SIZE, MAX_MESSAGE_CONTENT_SIZE, MAX_TAGS_JSON_SIZE, validate_size,
    validate_string_length,
};
use crate::{MdkSqliteStorage, db};

db_error_fn!(into_message_err, MessageError);

impl MessageStorage for MdkSqliteStorage {
    fn save_message(&self, message: Message) -> Result<(), MessageError> {
        // Validate content size
        validate_string_length(
            &message.content,
            MAX_MESSAGE_CONTENT_SIZE,
            "Message content",
        )
        .map_err(|e| MessageError::InvalidParameters(e.to_string()))?;

        // Serialize complex types to JSON
        let tags_json: String = serde_json::to_string(&message.tags)
            .map_err(|e| MessageError::DatabaseError(format!("Failed to serialize tags: {}", e)))?;

        // Validate tags JSON size
        validate_size(tags_json.as_bytes(), MAX_TAGS_JSON_SIZE, "Tags JSON")
            .map_err(|e| MessageError::InvalidParameters(e.to_string()))?;

        // Serialize event to JSON
        let event_json = message.event.as_json();

        // Validate event JSON size
        validate_size(event_json.as_bytes(), MAX_EVENT_JSON_SIZE, "Event JSON")
            .map_err(|e| MessageError::InvalidParameters(e.to_string()))?;

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO messages
             (id, pubkey, kind, mls_group_id, created_at, processed_at, content, tags, event, wrapper_event_id, epoch, state)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(mls_group_id, id) DO UPDATE SET
                 pubkey = excluded.pubkey,
                 kind = excluded.kind,
                 created_at = excluded.created_at,
                 processed_at = excluded.processed_at,
                 content = excluded.content,
                 tags = excluded.tags,
                 event = excluded.event,
                 wrapper_event_id = excluded.wrapper_event_id,
                 epoch = excluded.epoch,
                 state = excluded.state",
                params![
                    message.id.as_bytes(),
                    message.pubkey.as_bytes(),
                    message.kind.as_u16(),
                    message.mls_group_id.as_slice(),
                    message.created_at.as_secs(),
                    message.processed_at.as_secs(),
                    &message.content,
                    &tags_json,
                    &event_json,
                    message.wrapper_event_id.as_bytes(),
                    message.epoch,
                    message.state.as_str(),
                ],
            )
            .map_err(into_message_err)?;

            Ok(())
        })
    }

    fn find_message_by_event_id(
        &self,
        mls_group_id: &mdk_storage_traits::GroupId,
        event_id: &EventId,
    ) -> Result<Option<Message>, MessageError> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM messages WHERE mls_group_id = ? AND id = ?")
                .map_err(into_message_err)?;

            stmt.query_row(
                params![mls_group_id.as_slice(), event_id.to_bytes()],
                db::row_to_message,
            )
            .optional()
            .map_err(into_message_err)
        })
    }

    fn save_processed_message(
        &self,
        processed_message: ProcessedMessage,
    ) -> Result<(), MessageError> {
        // Convert message_event_id to bytes if it exists
        let message_event_id = processed_message
            .message_event_id
            .as_ref()
            .map(|id| id.to_bytes());

        // Convert mls_group_id to bytes if it exists
        let mls_group_id = processed_message
            .mls_group_id
            .as_ref()
            .map(|id| id.as_slice().to_vec());

        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO processed_messages
             (wrapper_event_id, message_event_id, processed_at, epoch, mls_group_id, state, failure_reason)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    &processed_message.wrapper_event_id.to_bytes(),
                    &message_event_id,
                    &processed_message.processed_at.as_secs(),
                    &processed_message.epoch,
                    &mls_group_id,
                    &processed_message.state.to_string(),
                    &processed_message.failure_reason
                ],
            )
            .map_err(into_message_err)?;

            Ok(())
        })
    }

    fn find_processed_message_by_event_id(
        &self,
        event_id: &EventId,
    ) -> Result<Option<ProcessedMessage>, MessageError> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM processed_messages WHERE wrapper_event_id = ?")
                .map_err(into_message_err)?;

            stmt.query_row(params![event_id.to_bytes()], db::row_to_processed_message)
                .optional()
                .map_err(into_message_err)
        })
    }

    fn invalidate_messages_after_epoch(
        &self,
        group_id: &mdk_storage_traits::GroupId,
        epoch: u64,
    ) -> Result<Vec<EventId>, MessageError> {
        self.with_connection(|conn| {
            // First, get the event IDs that will be invalidated
            let mut stmt = conn
                .prepare(
                    "SELECT id FROM messages
                     WHERE mls_group_id = ? AND epoch > ?",
                )
                .map_err(into_message_err)?;

            let event_ids: Vec<EventId> = stmt
                .query_map(params![group_id.as_slice(), epoch], |row| {
                    let id_blob: Vec<u8> = row.get(0)?;
                    Ok(id_blob)
                })
                .map_err(into_message_err)?
                .filter_map(|r| r.ok())
                .filter_map(|id_blob| EventId::from_slice(&id_blob).ok())
                .collect();

            // Then update the state to epoch_invalidated
            conn.execute(
                "UPDATE messages SET state = 'epoch_invalidated'
                 WHERE mls_group_id = ? AND epoch > ?",
                params![group_id.as_slice(), epoch],
            )
            .map_err(into_message_err)?;

            Ok(event_ids)
        })
    }

    fn invalidate_processed_messages_after_epoch(
        &self,
        group_id: &mdk_storage_traits::GroupId,
        epoch: u64,
    ) -> Result<Vec<EventId>, MessageError> {
        self.with_connection(|conn| {
            // First, get the wrapper event IDs that will be invalidated
            let mut stmt = conn
                .prepare(
                    "SELECT wrapper_event_id FROM processed_messages
                     WHERE mls_group_id = ? AND epoch > ?",
                )
                .map_err(into_message_err)?;

            let event_ids: Vec<EventId> = stmt
                .query_map(params![group_id.as_slice(), epoch], |row| {
                    let id_blob: Vec<u8> = row.get(0)?;
                    Ok(id_blob)
                })
                .map_err(into_message_err)?
                .filter_map(|r| r.ok())
                .filter_map(|id_blob| EventId::from_slice(&id_blob).ok())
                .collect();

            // Then update the state to epoch_invalidated
            conn.execute(
                "UPDATE processed_messages SET state = 'epoch_invalidated'
                 WHERE mls_group_id = ? AND epoch > ?",
                params![group_id.as_slice(), epoch],
            )
            .map_err(into_message_err)?;

            Ok(event_ids)
        })
    }

    fn find_invalidated_messages(
        &self,
        group_id: &mdk_storage_traits::GroupId,
    ) -> Result<Vec<Message>, MessageError> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM messages
                     WHERE mls_group_id = ? AND state = 'epoch_invalidated'",
                )
                .map_err(into_message_err)?;

            let messages: Vec<Message> = stmt
                .query_map(params![group_id.as_slice()], db::row_to_message)
                .map_err(into_message_err)?
                .filter_map(|r| r.ok())
                .collect();

            Ok(messages)
        })
    }

    fn find_invalidated_processed_messages(
        &self,
        group_id: &mdk_storage_traits::GroupId,
    ) -> Result<Vec<ProcessedMessage>, MessageError> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM processed_messages
                     WHERE mls_group_id = ? AND state = 'epoch_invalidated'",
                )
                .map_err(into_message_err)?;

            let messages: Vec<ProcessedMessage> = stmt
                .query_map(params![group_id.as_slice()], db::row_to_processed_message)
                .map_err(into_message_err)?
                .filter_map(|r| r.ok())
                .collect();

            Ok(messages)
        })
    }

    fn find_failed_messages_for_retry(
        &self,
        group_id: &mdk_storage_traits::GroupId,
    ) -> Result<Vec<EventId>, MessageError> {
        self.with_connection(|conn| {
            // Find processed messages that:
            // - Are for this group
            // - Have state = Failed
            // - Have epoch IS NULL (decryption failed before epoch could be determined)
            let mut stmt = conn
                .prepare(
                    "SELECT wrapper_event_id FROM processed_messages
                     WHERE mls_group_id = ? AND state = 'failed' AND epoch IS NULL",
                )
                .map_err(into_message_err)?;

            let event_ids: Vec<EventId> = stmt
                .query_map(params![group_id.as_slice()], |row| {
                    let id_blob: Vec<u8> = row.get(0)?;
                    Ok(id_blob)
                })
                .map_err(into_message_err)?
                .filter_map(|r| r.ok())
                .filter_map(|id_blob| EventId::from_slice(&id_blob).ok())
                .collect();

            Ok(event_ids)
        })
    }

    fn mark_processed_message_retryable(&self, event_id: &EventId) -> Result<(), MessageError> {
        self.with_connection(|conn| {
            // Only update messages that are currently in Failed state
            let rows_affected = conn
                .execute(
                    "UPDATE processed_messages SET state = 'retryable'
                     WHERE wrapper_event_id = ? AND state = 'failed'",
                    params![event_id.to_bytes()],
                )
                .map_err(into_message_err)?;

            if rows_affected == 0 {
                return Err(MessageError::NotFound);
            }

            Ok(())
        })
    }

    fn find_message_epoch_by_tag_content(
        &self,
        group_id: &mdk_storage_traits::GroupId,
        content_substring: &str,
    ) -> Result<Option<u64>, MessageError> {
        let escaped = content_substring
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{}%", escaped);
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT epoch FROM messages
                     WHERE mls_group_id = ? AND tags LIKE ? ESCAPE '\\' AND epoch IS NOT NULL
                     LIMIT 1",
                )
                .map_err(into_message_err)?;

            stmt.query_row(params![group_id.as_slice(), &pattern], |row| {
                row.get::<_, u64>(0)
            })
            .optional()
            .map_err(into_message_err)
        })
    }

    fn delete_messages_for_group(
        &self,
        group_id: &mdk_storage_traits::GroupId,
    ) -> Result<usize, MessageError> {
        self.with_connection(|conn| {
            conn.execute(
                "DELETE FROM messages WHERE mls_group_id = ?",
                params![group_id.as_slice()],
            )
            .map_err(into_message_err)
        })
    }

    fn delete_message(
        &self,
        group_id: &mdk_storage_traits::GroupId,
        event_id: &EventId,
    ) -> Result<bool, MessageError> {
        self.with_connection(|conn| {
            let rows = conn
                .execute(
                    "DELETE FROM messages WHERE mls_group_id = ? AND id = ?",
                    params![group_id.as_slice(), event_id.as_bytes()],
                )
                .map_err(into_message_err)?;

            Ok(rows > 0)
        })
    }

    fn delete_messages_before_timestamp(
        &self,
        group_id: &mdk_storage_traits::GroupId,
        before: Timestamp,
    ) -> Result<usize, MessageError> {
        self.with_connection(|conn| {
            conn.execute(
                "DELETE FROM messages WHERE mls_group_id = ? AND created_at < ?",
                params![group_id.as_slice(), before.as_secs()],
            )
            .map_err(into_message_err)
        })
    }

    fn delete_processed_messages_for_group(
        &self,
        group_id: &mdk_storage_traits::GroupId,
    ) -> Result<usize, MessageError> {
        self.with_connection(|conn| {
            conn.execute(
                "DELETE FROM processed_messages WHERE mls_group_id = ?",
                params![group_id.as_slice()],
            )
            .map_err(into_message_err)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mdk_storage_traits::GroupId;
    use mdk_storage_traits::groups::GroupStorage;
    use mdk_storage_traits::groups::types::{Group, GroupState, SelfUpdateState};
    use mdk_storage_traits::messages::types::{MessageState, ProcessedMessageState};
    use nostr::{EventId, Kind, PublicKey, Tags, Timestamp, UnsignedEvent};

    use super::*;

    #[test]
    fn test_save_and_find_message() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // First create a group (messages require a valid group foreign key)
        let mls_group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let mut nostr_group_id = [0u8; 32];
        nostr_group_id[0..13].copy_from_slice(b"test_group_12");

        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Test Group".to_string(),
            description: "A test group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            last_message_processed_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            self_update_state: SelfUpdateState::Required,
            disappearing_message_duration_secs: None,
        };

        // Save the group
        let result = storage.save_group(group);
        assert!(result.is_ok());

        // Create a test message
        let event_id =
            EventId::parse("6a2affe9878ebcf50c10cf74c7b25aad62e0db9fb347f6aafeda30e9f578f260")
                .unwrap();
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let wrapper_event_id =
            EventId::parse("3287abd422284bc3679812c373c52ed4aa0af4f7c57b9c63ec440f6c3ed6c3a2")
                .unwrap();

        let now = Timestamp::now();
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::from(1u16),
            mls_group_id: mls_group_id.clone(),
            created_at: now,
            processed_at: now,
            content: "Test message content".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(pubkey, now, Kind::from(9u16), vec![], "content".to_string()),
            wrapper_event_id,
            epoch: Some(1),
            state: MessageState::Created,
        };

        // Save the message
        let result = storage.save_message(message.clone());
        assert!(result.is_ok());

        // Find by event ID
        let found_message = storage
            .find_message_by_event_id(&mls_group_id, &event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_message.id, event_id);
        assert_eq!(found_message.pubkey, pubkey);
        assert_eq!(found_message.content, "Test message content");
    }

    #[test]
    fn test_processed_message() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // Create a test processed message
        let wrapper_event_id =
            EventId::parse("3287abd422284bc3679812c373c52ed4aa0af4f7c57b9c63ec440f6c3ed6c3a2")
                .unwrap();
        let message_event_id =
            EventId::parse("6a2affe9878ebcf50c10cf74c7b25aad62e0db9fb347f6aafeda30e9f578f260")
                .unwrap();

        let processed_message = ProcessedMessage {
            wrapper_event_id,
            message_event_id: Some(message_event_id),
            processed_at: Timestamp::from(1_000_000_000u64),
            epoch: Some(1),
            mls_group_id: None,
            state: ProcessedMessageState::Processed,
            failure_reason: None,
        };

        // Save the processed message
        let result = storage.save_processed_message(processed_message.clone());
        assert!(result.is_ok());

        // Find by event ID
        let found_processed_message = storage
            .find_processed_message_by_event_id(&wrapper_event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_processed_message.wrapper_event_id, wrapper_event_id);
        assert_eq!(
            found_processed_message.message_event_id.unwrap(),
            message_event_id
        );
        assert_eq!(
            found_processed_message.state,
            ProcessedMessageState::Processed
        );
    }

    #[test]
    fn test_message_content_size_validation() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // Create a group first
        let mls_group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let mut nostr_group_id = [0u8; 32];
        nostr_group_id[0..13].copy_from_slice(b"test_group_12");

        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Test Group".to_string(),
            description: "Test".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            last_message_processed_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            self_update_state: SelfUpdateState::Required,
            disappearing_message_duration_secs: None,
        };
        storage.save_group(group).unwrap();

        // Create a message with content exceeding the limit (1 MB)
        let oversized_content = "x".repeat(1024 * 1024 + 1);

        let event_id = EventId::all_zeros();
        let pubkey = PublicKey::from_slice(&[1u8; 32]).unwrap();
        let wrapper_event_id =
            EventId::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let now = Timestamp::now();
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::from(1u16),
            mls_group_id: mls_group_id.clone(),
            created_at: now,
            processed_at: now,
            content: oversized_content,
            tags: Tags::new(),
            event: UnsignedEvent::new(pubkey, now, Kind::from(9u16), vec![], "content".to_string()),
            wrapper_event_id,
            epoch: None,
            state: MessageState::Created,
        };

        // Should fail due to content size
        let result = storage.save_message(message);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Message content exceeds maximum"));
    }

    #[test]
    fn test_messages_cannot_overwrite_across_groups() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // Create two different groups
        let mls_group_id_1 = GroupId::from_slice(&[1, 2, 3, 4]);
        let mls_group_id_2 = GroupId::from_slice(&[5, 6, 7, 8]);

        let mut nostr_group_id_1 = [0u8; 32];
        nostr_group_id_1[0..12].copy_from_slice(b"test_group_1");
        let mut nostr_group_id_2 = [0u8; 32];
        nostr_group_id_2[0..12].copy_from_slice(b"test_group_2");

        let group_1 = Group {
            mls_group_id: mls_group_id_1.clone(),
            nostr_group_id: nostr_group_id_1,
            name: "Test Group 1".to_string(),
            description: "First test group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            last_message_processed_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            self_update_state: SelfUpdateState::Required,
            disappearing_message_duration_secs: None,
        };

        let group_2 = Group {
            mls_group_id: mls_group_id_2.clone(),
            nostr_group_id: nostr_group_id_2,
            name: "Test Group 2".to_string(),
            description: "Second test group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            last_message_processed_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            self_update_state: SelfUpdateState::Required,
            disappearing_message_duration_secs: None,
        };

        storage.save_group(group_1).unwrap();
        storage.save_group(group_2).unwrap();

        // Create two messages with the same event ID but different groups
        let same_event_id =
            EventId::parse("6a2affe9878ebcf50c10cf74c7b25aad62e0db9fb347f6aafeda30e9f578f260")
                .unwrap();
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let wrapper_event_id_1 =
            EventId::parse("3287abd422284bc3679812c373c52ed4aa0af4f7c57b9c63ec440f6c3ed6c3a1")
                .unwrap();
        let wrapper_event_id_2 =
            EventId::parse("3287abd422284bc3679812c373c52ed4aa0af4f7c57b9c63ec440f6c3ed6c3a2")
                .unwrap();

        let now = Timestamp::now();
        let message_1 = Message {
            id: same_event_id,
            pubkey,
            kind: Kind::from(1u16),
            mls_group_id: mls_group_id_1.clone(),
            created_at: now,
            processed_at: now,
            content: "Message in group 1".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(pubkey, now, Kind::from(9u16), vec![], "content".to_string()),
            wrapper_event_id: wrapper_event_id_1,
            epoch: Some(1),
            state: MessageState::Created,
        };

        let message_2 = Message {
            id: same_event_id,
            pubkey,
            kind: Kind::from(1u16),
            mls_group_id: mls_group_id_2.clone(),
            created_at: now,
            processed_at: now,
            content: "Message in group 2".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(pubkey, now, Kind::from(9u16), vec![], "content".to_string()),
            wrapper_event_id: wrapper_event_id_2,
            epoch: Some(2),
            state: MessageState::Created,
        };

        // Save both messages
        storage.save_message(message_1.clone()).unwrap();
        storage.save_message(message_2.clone()).unwrap();

        // Verify both messages exist and are distinct
        let found_message_1 = storage
            .find_message_by_event_id(&mls_group_id_1, &same_event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_message_1.content, "Message in group 1");
        assert_eq!(found_message_1.mls_group_id, mls_group_id_1);

        let found_message_2 = storage
            .find_message_by_event_id(&mls_group_id_2, &same_event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_message_2.content, "Message in group 2");
        assert_eq!(found_message_2.mls_group_id, mls_group_id_2);

        // Verify that looking up the same event ID in group 2 returns group 2's message
        let wrong_group_lookup = storage
            .find_message_by_event_id(&mls_group_id_2, &same_event_id)
            .unwrap();
        assert!(wrong_group_lookup.is_some());
        let wrong_group_message = wrong_group_lookup.unwrap();
        assert_eq!(wrong_group_message.mls_group_id, mls_group_id_2);

        // Verify that looking up the event ID in group 1 still returns group 1's message
        let group_1_lookup = storage
            .find_message_by_event_id(&mls_group_id_1, &same_event_id)
            .unwrap();
        assert!(group_1_lookup.is_some());
        let group_1_message = group_1_lookup.unwrap();
        assert_eq!(group_1_message.mls_group_id, mls_group_id_1);
        assert_eq!(group_1_message.content, "Message in group 1");
    }

    #[test]
    fn test_mark_processed_message_retryable() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // Create a failed processed message
        let wrapper_event_id =
            EventId::parse("3287abd422284bc3679812c373c52ed4aa0af4f7c57b9c63ec440f6c3ed6c3a2")
                .unwrap();

        let processed_message = ProcessedMessage {
            wrapper_event_id,
            message_event_id: None,
            processed_at: Timestamp::from(1_000_000_000u64),
            epoch: None,
            mls_group_id: Some(GroupId::from_slice(&[1, 2, 3, 4])),
            state: ProcessedMessageState::Failed,
            failure_reason: Some("Decryption failed".to_string()),
        };

        // Save the failed processed message
        storage
            .save_processed_message(processed_message)
            .expect("Failed to save processed message");

        // Verify it's in Failed state
        let found = storage
            .find_processed_message_by_event_id(&wrapper_event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.state, ProcessedMessageState::Failed);

        // Mark as retryable
        storage
            .mark_processed_message_retryable(&wrapper_event_id)
            .expect("Failed to mark message as retryable");

        // Verify state changed to Retryable
        let found = storage
            .find_processed_message_by_event_id(&wrapper_event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.state, ProcessedMessageState::Retryable);

        // Verify failure_reason is preserved
        assert_eq!(found.failure_reason, Some("Decryption failed".to_string()));
    }

    #[test]
    fn test_mark_nonexistent_message_retryable_fails() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        let wrapper_event_id =
            EventId::parse("3287abd422284bc3679812c373c52ed4aa0af4f7c57b9c63ec440f6c3ed6c3a2")
                .unwrap();

        // Attempt to mark a non-existent message as retryable
        let result = storage.mark_processed_message_retryable(&wrapper_event_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MessageError::NotFound));
    }

    #[test]
    fn test_mark_non_failed_message_retryable_fails() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        // Create a processed message in Processed state (not Failed)
        let wrapper_event_id =
            EventId::parse("3287abd422284bc3679812c373c52ed4aa0af4f7c57b9c63ec440f6c3ed6c3a2")
                .unwrap();

        let processed_message = ProcessedMessage {
            wrapper_event_id,
            message_event_id: None,
            processed_at: Timestamp::from(1_000_000_000u64),
            epoch: Some(1),
            mls_group_id: Some(GroupId::from_slice(&[1, 2, 3, 4])),
            state: ProcessedMessageState::Processed,
            failure_reason: None,
        };

        storage
            .save_processed_message(processed_message)
            .expect("Failed to save processed message");

        // Attempt to mark a Processed message as retryable should fail
        let result = storage.mark_processed_message_retryable(&wrapper_event_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MessageError::NotFound));

        // Verify state is unchanged
        let found = storage
            .find_processed_message_by_event_id(&wrapper_event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found.state, ProcessedMessageState::Processed);
    }

    /// Verifies that %, _, and \ in content_substring are treated as literal
    /// characters and not as SQL LIKE wildcards.
    #[test]
    fn test_find_message_epoch_by_tag_content_escapes_like_wildcards() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();

        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let mut nostr_group_id = [0u8; 32];
        nostr_group_id[0..4].copy_from_slice(&[1, 2, 3, 4]);

        let group = Group {
            mls_group_id: group_id.clone(),
            nostr_group_id,
            name: "Test Group".to_string(),
            description: "A test group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            last_message_processed_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            self_update_state: SelfUpdateState::Required,
            disappearing_message_duration_secs: None,
        };
        storage.save_group(group).unwrap();

        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let event_id = EventId::from_slice(&[10u8; 32]).unwrap();
        let wrapper_event_id = EventId::from_slice(&[200u8; 32]).unwrap();

        // Store a message with tags containing "x abc" (no wildcards)
        let tags = Tags::parse(vec![vec!["imeta", "x abc"]]).unwrap();
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::from(445u16),
            mls_group_id: group_id.clone(),
            created_at: Timestamp::from(1000u64),
            processed_at: Timestamp::from(1000u64),
            content: "".to_string(),
            tags: tags.clone(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::from(1000u64),
                Kind::from(445u16),
                tags,
                "".to_string(),
            ),
            wrapper_event_id,
            epoch: Some(42),
            state: MessageState::Processed,
        };
        storage.save_message(message).unwrap();

        // Searching for exact content should find it
        let result = storage
            .find_message_epoch_by_tag_content(&group_id, "x abc")
            .unwrap();
        assert_eq!(result, Some(42), "Exact substring should match");

        // Searching with SQL wildcard % should NOT match (treated literally)
        let result = storage
            .find_message_epoch_by_tag_content(&group_id, "x%abc")
            .unwrap();
        assert_eq!(
            result, None,
            "% must be treated as a literal, not a wildcard"
        );

        // Searching with SQL wildcard _ should NOT match (treated literally)
        let result = storage
            .find_message_epoch_by_tag_content(&group_id, "x_abc")
            .unwrap();
        assert_eq!(
            result, None,
            "_ must be treated as a literal, not a wildcard"
        );

        // Searching with backslash should NOT match (treated literally)
        let result = storage
            .find_message_epoch_by_tag_content(&group_id, "x\\abc")
            .unwrap();
        assert_eq!(
            result, None,
            "\\ must be treated as a literal, not an escape"
        );
    }

    /// Create a test group and save it to storage, returning its GroupId.
    fn create_test_group(storage: &MdkSqliteStorage, id_bytes: &[u8]) -> GroupId {
        let group_id = GroupId::from_slice(id_bytes);
        let mut nostr_group_id = [0u8; 32];
        nostr_group_id[..id_bytes.len().min(32)]
            .copy_from_slice(&id_bytes[..id_bytes.len().min(32)]);
        let group = Group {
            mls_group_id: group_id.clone(),
            nostr_group_id,
            name: "Test Group".to_string(),
            description: "".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            last_message_processed_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
            self_update_state: SelfUpdateState::Required,
            disappearing_message_duration_secs: None,
        };
        storage.save_group(group).unwrap();
        group_id
    }

    /// Create and save a test message for the given group, returning its EventId.
    fn create_test_message(
        storage: &MdkSqliteStorage,
        group_id: &GroupId,
        event_id_hex: &str,
    ) -> EventId {
        let event_id = EventId::parse(event_id_hex).unwrap();
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let wrapper_event_id = EventId::all_zeros();
        let now = Timestamp::now();
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::from(1u16),
            mls_group_id: group_id.clone(),
            created_at: now,
            processed_at: now,
            content: "test".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(pubkey, now, Kind::from(9u16), vec![], "test".to_string()),
            wrapper_event_id,
            epoch: Some(1),
            state: MessageState::Created,
        };
        storage.save_message(message).unwrap();
        event_id
    }

    #[test]
    fn delete_messages_removes_all_messages_for_group() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_id = create_test_group(&storage, &[10, 20, 30]);
        create_test_message(
            &storage,
            &group_id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        create_test_message(
            &storage,
            &group_id,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        create_test_message(
            &storage,
            &group_id,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );

        let deleted = storage.delete_messages_for_group(&group_id).unwrap();

        assert_eq!(deleted, 3);
        let messages = storage.messages(&group_id, None).unwrap();
        assert!(messages.is_empty());
        // Group itself still exists
        assert!(
            storage
                .find_group_by_mls_group_id(&group_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn delete_messages_is_idempotent_on_empty_group() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_id = create_test_group(&storage, &[11, 22, 33]);

        let deleted = storage.delete_messages_for_group(&group_id).unwrap();

        assert_eq!(deleted, 0);
    }

    #[test]
    fn delete_messages_preserves_processed_messages() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_id = create_test_group(&storage, &[44, 55, 66]);
        create_test_message(
            &storage,
            &group_id,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        );

        let wrapper_eid =
            EventId::parse("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                .unwrap();
        let pm = mdk_storage_traits::messages::types::ProcessedMessage {
            wrapper_event_id: wrapper_eid,
            message_event_id: None,
            processed_at: Timestamp::now(),
            epoch: Some(1),
            mls_group_id: Some(group_id.clone()),
            state: ProcessedMessageState::Processed,
            failure_reason: None,
        };
        storage.save_processed_message(pm).unwrap();

        storage.delete_messages_for_group(&group_id).unwrap();

        // Processed messages are preserved (deduplication guard)
        assert!(
            storage
                .find_processed_message_by_event_id(&wrapper_eid)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn delete_messages_does_not_affect_other_groups() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_a = create_test_group(&storage, &[1, 1, 1]);
        let group_b = create_test_group(&storage, &[2, 2, 2]);
        create_test_message(
            &storage,
            &group_a,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        create_test_message(
            &storage,
            &group_b,
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        storage.delete_messages_for_group(&group_a).unwrap();

        assert!(storage.messages(&group_a, None).unwrap().is_empty());
        assert_eq!(storage.messages(&group_b, None).unwrap().len(), 1);
    }

    #[test]
    fn delete_single_message() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_id = create_test_group(&storage, &[10, 20, 30]);
        let eid1 = create_test_message(
            &storage,
            &group_id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let eid2 = create_test_message(
            &storage,
            &group_id,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );

        let deleted = storage.delete_message(&group_id, &eid1).unwrap();
        assert!(deleted);

        // eid1 is gone, eid2 remains
        assert!(
            storage
                .find_message_by_event_id(&group_id, &eid1)
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .find_message_by_event_id(&group_id, &eid2)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn delete_single_message_not_found() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_id = create_test_group(&storage, &[10, 20, 30]);

        let missing_eid =
            EventId::parse("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        let deleted = storage.delete_message(&group_id, &missing_eid).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn delete_messages_before_timestamp() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_id = create_test_group(&storage, &[10, 20, 30]);

        // Create messages with specific timestamps
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let wrapper_event_id = EventId::all_zeros();

        let eid1 =
            EventId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let eid2 =
            EventId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let eid3 =
            EventId::parse("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
                .unwrap();

        for (eid, ts) in [(eid1, 100u64), (eid2, 200), (eid3, 300)] {
            let now = Timestamp::from(ts);
            let message = Message {
                id: eid,
                pubkey,
                kind: Kind::from(1u16),
                mls_group_id: group_id.clone(),
                created_at: now,
                processed_at: now,
                content: "test".to_string(),
                tags: Tags::new(),
                event: UnsignedEvent::new(
                    pubkey,
                    now,
                    Kind::from(9u16),
                    vec![],
                    "test".to_string(),
                ),
                wrapper_event_id,
                epoch: Some(1),
                state: MessageState::Created,
            };
            storage.save_message(message).unwrap();
        }

        // Delete messages created before timestamp 250
        let deleted = storage
            .delete_messages_before_timestamp(&group_id, Timestamp::from(250u64))
            .unwrap();
        assert_eq!(deleted, 2);

        // Only the newest message remains
        assert!(
            storage
                .find_message_by_event_id(&group_id, &eid1)
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .find_message_by_event_id(&group_id, &eid2)
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .find_message_by_event_id(&group_id, &eid3)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn delete_processed_messages_for_group() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let group_a = create_test_group(&storage, &[1, 1, 1]);
        let group_b = create_test_group(&storage, &[2, 2, 2]);

        let pm_a_eid =
            EventId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let pm_b_eid =
            EventId::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();

        let pm_a = ProcessedMessage {
            wrapper_event_id: pm_a_eid,
            message_event_id: None,
            processed_at: Timestamp::now(),
            epoch: Some(1),
            mls_group_id: Some(group_a.clone()),
            state: ProcessedMessageState::Processed,
            failure_reason: None,
        };
        let pm_b = ProcessedMessage {
            wrapper_event_id: pm_b_eid,
            message_event_id: None,
            processed_at: Timestamp::now(),
            epoch: Some(1),
            mls_group_id: Some(group_b.clone()),
            state: ProcessedMessageState::Processed,
            failure_reason: None,
        };
        storage.save_processed_message(pm_a).unwrap();
        storage.save_processed_message(pm_b).unwrap();

        let deleted = storage
            .delete_processed_messages_for_group(&group_a)
            .unwrap();
        assert_eq!(deleted, 1);

        // group_a's processed message is gone
        assert!(
            storage
                .find_processed_message_by_event_id(&pm_a_eid)
                .unwrap()
                .is_none()
        );
        // group_b's processed message still exists
        assert!(
            storage
                .find_processed_message_by_event_id(&pm_b_eid)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn secure_delete_pragma_is_enabled() {
        let storage = MdkSqliteStorage::new_in_memory().unwrap();
        let value: i64 = storage.with_connection(|conn| {
            conn.query_row("PRAGMA secure_delete", [], |row| row.get(0))
                .unwrap()
        });
        assert_eq!(value, 1, "PRAGMA secure_delete should be ON (1)");
    }
}
