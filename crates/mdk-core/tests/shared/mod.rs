//! Shared test utilities and functions for storage testing
//!
//! These functions are used by multiple integration test binaries.
//! Not all test binaries use all functions, so we allow unused here.

#![allow(unused)]

use std::collections::BTreeSet;

use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::types::{Group, GroupState, SelfUpdateState};
use mdk_storage_traits::messages::types::{
    Message, MessageState, ProcessedMessage, ProcessedMessageState,
};
use mdk_storage_traits::welcomes::types::{
    ProcessedWelcome, ProcessedWelcomeState, Welcome, WelcomeState,
};
use nostr::{EventId, PublicKey, RelayUrl, Timestamp};

pub mod group_tests;
pub mod message_tests;
pub mod welcome_tests;

/// Creates a test group with the given ID for testing purposes
pub fn create_test_group(mls_group_id: GroupId) -> Group {
    let mut nostr_group_id = [0u8; 32];
    // Use first 4 bytes of mls_group_id to make nostr_group_id somewhat unique
    let id_bytes = mls_group_id.as_slice();
    let copy_len = std::cmp::min(id_bytes.len(), 4);
    nostr_group_id[0..copy_len].copy_from_slice(&id_bytes[0..copy_len]);

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
    use nostr::{Kind, Tags, UnsignedEvent};

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
    use nostr::{Kind, Tags, UnsignedEvent};

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

/// Generates all storage backend integration tests for a given storage constructor.
///
/// Each integration test binary is its own crate, so test function names don't
/// need a backend suffix — the binary name (`storage_traits_memory` vs
/// `storage_traits_sqlite`) already provides the namespace.
#[macro_export]
macro_rules! storage_backend_tests {
    ($storage_expr:expr) => {
        // Group functionality tests
        #[test]
        fn test_save_and_find_group() {
            let storage = $storage_expr;
            shared::group_tests::test_save_and_find_group(storage);
        }

        #[test]
        fn test_all_groups() {
            let storage = $storage_expr;
            shared::group_tests::test_all_groups(storage);
        }

        #[test]
        fn test_group_exporter_secret() {
            let storage = $storage_expr;
            shared::group_tests::test_group_exporter_secret(storage);
        }

        #[test]
        fn test_group_mip04_exporter_secret() {
            let storage = $storage_expr;
            shared::group_tests::test_group_mip04_exporter_secret(storage);
        }

        #[test]
        fn test_exporter_secret_label_isolation() {
            let storage = $storage_expr;
            shared::group_tests::test_exporter_secret_label_isolation(storage);
        }

        #[test]
        fn test_exporter_secret_pruning_by_epoch() {
            let storage = $storage_expr;
            shared::group_tests::test_exporter_secret_pruning_by_epoch(storage);
        }

        #[test]
        fn test_basic_group_relays() {
            let storage = $storage_expr;
            shared::group_tests::test_basic_group_relays(storage);
        }

        #[test]
        fn test_group_edge_cases() {
            let storage = $storage_expr;
            shared::group_tests::test_group_edge_cases(storage);
        }

        #[test]
        fn test_replace_relays_edge_cases() {
            let storage = $storage_expr;
            shared::group_tests::test_replace_relays_edge_cases(storage);
        }

        // Comprehensive relay tests
        #[test]
        fn test_replace_group_relays_comprehensive() {
            let storage = $storage_expr;
            shared::group_tests::test_replace_group_relays_comprehensive(storage);
        }

        #[test]
        fn test_replace_group_relays_error_cases() {
            let storage = $storage_expr;
            shared::group_tests::test_replace_group_relays_error_cases(storage);
        }

        #[test]
        fn test_replace_group_relays_duplicate_handling() {
            let storage = $storage_expr;
            shared::group_tests::test_replace_group_relays_duplicate_handling(storage);
        }

        // Admin functionality tests
        #[test]
        fn test_admins() {
            let storage = $storage_expr;
            shared::group_tests::test_admins(storage);
        }

        #[test]
        fn test_admins_error_for_nonexistent_group() {
            let storage = $storage_expr;
            shared::group_tests::test_admins_error_for_nonexistent_group(storage);
        }

        // Message functionality tests
        #[test]
        fn test_save_and_find_message() {
            let storage = $storage_expr;
            shared::message_tests::test_save_and_find_message(storage);
        }

        #[test]
        fn test_processed_message() {
            let storage = $storage_expr;
            shared::message_tests::test_processed_message(storage);
        }

        #[test]
        fn test_messages_for_group() {
            let storage = $storage_expr;
            shared::group_tests::test_messages_for_group(storage);
        }

        #[test]
        fn test_messages_error_for_nonexistent_group() {
            let storage = $storage_expr;
            shared::group_tests::test_messages_error_for_nonexistent_group(storage);
        }

        #[test]
        fn test_group_relays_error_for_nonexistent_group() {
            let storage = $storage_expr;
            shared::group_tests::test_group_relays_error_for_nonexistent_group(storage);
        }

        #[test]
        fn test_messages_sort_order() {
            let storage = $storage_expr;
            shared::group_tests::test_messages_sort_order(storage);
        }

        #[test]
        fn test_messages_sort_order_pagination() {
            let storage = $storage_expr;
            shared::group_tests::test_messages_sort_order_pagination(storage);
        }

        #[test]
        fn test_last_message() {
            let storage = $storage_expr;
            shared::group_tests::test_last_message(storage);
        }

        #[test]
        fn test_groups_needing_self_update() {
            let storage = $storage_expr;
            shared::group_tests::test_groups_needing_self_update(storage);
        }

        // Welcome functionality tests
        #[test]
        fn test_save_and_find_welcome() {
            let storage = $storage_expr;
            shared::welcome_tests::test_save_and_find_welcome(storage);
        }

        #[test]
        fn test_processed_welcome() {
            let storage = $storage_expr;
            shared::welcome_tests::test_processed_welcome(storage);
        }
    };
}
