//! Test utilities for cross-storage consistency testing

/// Random data generation utilities for testing MLS group features
pub mod crypto_utils {
    use nostr::secp256k1::rand::{RngCore, rngs::OsRng};

    /// Generates random bytes as `Vec<u8>` of the specified length
    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        let mut rng = OsRng;
        rng.fill_bytes(&mut bytes);
        bytes
    }
}

/// Cross-storage consistency testing utilities
pub mod cross_storage {
    use std::collections::BTreeSet;

    use crate::GroupId;
    use nostr::{EventId, Timestamp};

    use crate::groups::types::{Group, GroupState, SelfUpdateState};
    use crate::messages::types::{Message, MessageState, ProcessedMessage, ProcessedMessageState};
    use crate::welcomes::types::{ProcessedWelcome, ProcessedWelcomeState, Welcome, WelcomeState};

    /// Creates a test group with the given ID for testing purposes
    pub fn create_test_group(mls_group_id: GroupId) -> Group {
        let mut nostr_group_id = [0u8; 32];
        // Use first 4 bytes of mls_group_id to make nostr_group_id somewhat unique
        let mls_bytes = mls_group_id.as_slice();
        if mls_bytes.len() >= 4 {
            nostr_group_id[0..4].copy_from_slice(&mls_bytes[0..4]);
        }

        Group {
            mls_group_id,
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
        }
    }

    /// Creates a test message for testing purposes
    pub fn create_test_message(mls_group_id: GroupId, event_id: EventId) -> Message {
        use nostr::{Kind, PublicKey, Tags, Timestamp, UnsignedEvent};

        let pubkey =
            PublicKey::parse("npub1a6awmmklxfmspwdv52qq58sk5c07kghwc4v2eaudjx2ju079cdqs2452ys")
                .unwrap();
        let created_at = Timestamp::now();
        let content = "Test message content".to_string();
        let tags = Tags::new();

        let event = UnsignedEvent {
            id: Some(event_id),
            pubkey,
            created_at,
            kind: Kind::Custom(445),
            tags: tags.clone(),
            content: content.clone(),
        };

        Message {
            id: event_id,
            pubkey,
            kind: Kind::Custom(445),
            mls_group_id,
            created_at,
            processed_at: created_at,
            content,
            tags,
            event,
            wrapper_event_id: event_id,
            state: MessageState::Processed,
            epoch: None,
        }
    }

    /// Creates a test processed message for testing purposes
    pub fn create_test_processed_message(
        wrapper_event_id: EventId,
        message_event_id: Option<EventId>,
    ) -> ProcessedMessage {
        ProcessedMessage {
            wrapper_event_id,
            message_event_id,
            processed_at: Timestamp::now(),
            epoch: None,
            mls_group_id: None,
            state: ProcessedMessageState::Processed,
            failure_reason: None,
        }
    }

    /// Creates a test welcome for testing purposes
    pub fn create_test_welcome(mls_group_id: GroupId, event_id: EventId) -> Welcome {
        use nostr::{Kind, PublicKey, RelayUrl, Tags, Timestamp, UnsignedEvent};

        let pubkey =
            PublicKey::parse("npub1a6awmmklxfmspwdv52qq58sk5c07kghwc4v2eaudjx2ju079cdqs2452ys")
                .unwrap();
        let created_at = Timestamp::now();
        let content = "Test welcome content".to_string();
        let tags = Tags::new();

        let event = UnsignedEvent {
            id: Some(event_id),
            pubkey,
            created_at,
            kind: Kind::Custom(444),
            tags,
            content,
        };

        Welcome {
            id: event_id,
            event,
            mls_group_id,
            nostr_group_id: [0u8; 32],
            group_name: "Test Group".to_string(),
            group_description: "A test group".to_string(),
            group_image_hash: None,
            group_image_key: None,
            group_image_nonce: None,
            group_admin_pubkeys: BTreeSet::from([pubkey]),
            group_relays: BTreeSet::from([RelayUrl::parse("wss://relay.example.com").unwrap()]),
            welcomer: pubkey,
            member_count: 1,
            state: WelcomeState::Pending,
            wrapper_event_id: event_id,
        }
    }

    /// Creates a test processed welcome for testing purposes
    pub fn create_test_processed_welcome(
        wrapper_event_id: EventId,
        welcome_event_id: Option<EventId>,
    ) -> ProcessedWelcome {
        ProcessedWelcome {
            wrapper_event_id,
            welcome_event_id,
            processed_at: Timestamp::now(),
            state: ProcessedWelcomeState::Processed,
            failure_reason: None,
        }
    }
}
