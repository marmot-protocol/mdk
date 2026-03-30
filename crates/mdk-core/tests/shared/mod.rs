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
