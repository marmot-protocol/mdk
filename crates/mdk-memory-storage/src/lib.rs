//! Memory-based storage implementation for Nostr MLS.
//!
//! This module provides a memory-based storage implementation for the Nostr MLS (Messaging Layer Security)
//! crate. It implements the `MdkStorageProvider` trait, allowing it to be used within the Nostr MLS context.
//!
//! Memory-based storage is non-persistent and will be cleared when the application terminates.
//! It's useful for testing or ephemeral applications where persistence isn't required.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroUsize;

use lru::LruCache;
use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::types::{Group, GroupExporterSecret, GroupRelay};
use mdk_storage_traits::messages::types::{Message, ProcessedMessage};
use mdk_storage_traits::welcomes::types::{ProcessedWelcome, Welcome};
use mdk_storage_traits::{Backend, MdkStorageProvider};
use nostr::EventId;
use openmls_memory_storage::MemoryStorage;
use parking_lot::RwLock;

mod groups;
mod messages;
mod welcomes;

/// Default cache size for each LRU cache
const DEFAULT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

/// A memory-based storage implementation for Nostr MLS.
///
/// This struct wraps an OpenMLS storage implementation to provide memory-based
/// storage functionality for Nostr MLS operations.
///
/// ## Caching Strategy
///
/// This implementation uses an LRU (Least Recently Used) caching mechanism to store
/// frequently accessed objects in memory for faster retrieval. The caches are protected
/// by `RwLock`s to ensure thread safety while allowing concurrent reads.
///
/// - Each cache has a configurable size limit (default: 1000 items)
/// - When a cache reaches its size limit, the least recently used items will be evicted
///
/// ## Thread Safety
///
/// All caches are protected by `RwLock`s, which allow:
/// - Multiple concurrent readers (for find/get operations)
/// - Exclusive writers (for create/save/delete operations)
///
/// This approach optimizes for read-heavy workloads while still ensuring data consistency.
#[derive(Debug)]
pub struct MdkMemoryStorage {
    /// The underlying storage implementation that conforms to OpenMLS's `StorageProvider`
    openmls_storage: MemoryStorage,
    /// LRU Cache for Group objects, keyed by MLS group ID (GroupId)
    groups_cache: RwLock<LruCache<GroupId, Group>>,
    /// LRU Cache for Group objects, keyed by Nostr group ID ([u8; 32])
    groups_by_nostr_id_cache: RwLock<LruCache<[u8; 32], Group>>,
    /// LRU Cache for GroupRelay objects, keyed by MLS group ID (GroupId)
    group_relays_cache: RwLock<LruCache<GroupId, BTreeSet<GroupRelay>>>,
    /// LRU Cache for Welcome objects, keyed by Event ID
    welcomes_cache: RwLock<LruCache<EventId, Welcome>>,
    /// LRU Cache for ProcessedWelcome objects, keyed by Event ID
    processed_welcomes_cache: RwLock<LruCache<EventId, ProcessedWelcome>>,
    /// LRU Cache for Message objects, keyed by Event ID
    messages_cache: RwLock<LruCache<EventId, Message>>,
    /// LRU Cache for Messages by Group ID, using HashMap for O(1) lookups by EventId
    messages_by_group_cache: RwLock<LruCache<GroupId, HashMap<EventId, Message>>>,
    /// LRU Cache for ProcessedMessage objects, keyed by Event ID
    processed_messages_cache: RwLock<LruCache<EventId, ProcessedMessage>>,
    /// LRU Cache for GroupExporterSecret objects, keyed by a tuple of (GroupId, epoch)
    group_exporter_secrets_cache: RwLock<LruCache<(GroupId, u64), GroupExporterSecret>>,
}

impl Default for MdkMemoryStorage {
    /// Creates a new `MdkMemoryStorage` with a default OpenMLS memory storage implementation.
    ///
    /// # Returns
    ///
    /// A new instance of `MdkMemoryStorage` with the default configuration.
    fn default() -> Self {
        Self::new(MemoryStorage::default())
    }
}

impl MdkMemoryStorage {
    /// Creates a new `MdkMemoryStorage` with the provided storage implementation.
    ///
    /// # Arguments
    ///
    /// * `storage_implementation` - An implementation of the OpenMLS `StorageProvider` trait.
    ///
    /// # Returns
    ///
    /// A new instance of `MdkMemoryStorage` wrapping the provided storage implementation.
    pub fn new(storage_implementation: MemoryStorage) -> Self {
        Self::with_cache_size(storage_implementation, DEFAULT_CACHE_SIZE)
    }

    /// Creates a new `MdkMemoryStorage` with the provided storage implementation and cache size.
    ///
    /// # Arguments
    ///
    /// * `storage_implementation` - An implementation of the OpenMLS `StorageProvider` trait.
    /// * `cache_size` - The maximum number of items to store in each LRU cache.
    ///
    /// # Returns
    ///
    /// A new instance of `MdkMemoryStorage` wrapping the provided storage implementation.
    pub fn with_cache_size(
        storage_implementation: MemoryStorage,
        cache_size: NonZeroUsize,
    ) -> Self {
        MdkMemoryStorage {
            openmls_storage: storage_implementation,
            groups_cache: RwLock::new(LruCache::new(cache_size)),
            groups_by_nostr_id_cache: RwLock::new(LruCache::new(cache_size)),
            group_relays_cache: RwLock::new(LruCache::new(cache_size)),
            welcomes_cache: RwLock::new(LruCache::new(cache_size)),
            processed_welcomes_cache: RwLock::new(LruCache::new(cache_size)),
            messages_cache: RwLock::new(LruCache::new(cache_size)),
            messages_by_group_cache: RwLock::new(LruCache::new(cache_size)),
            processed_messages_cache: RwLock::new(LruCache::new(cache_size)),
            group_exporter_secrets_cache: RwLock::new(LruCache::new(cache_size)),
        }
    }
}

/// Implementation of `MdkStorageProvider` for memory-based storage.
impl MdkStorageProvider for MdkMemoryStorage {
    type OpenMlsStorageProvider = MemoryStorage;

    /// Returns the backend type.
    ///
    /// # Returns
    ///
    /// [`Backend::Memory`] indicating this is a memory-based storage implementation.
    fn backend(&self) -> Backend {
        Backend::Memory
    }

    /// Get a reference to the openmls storage provider.
    ///
    /// This method provides access to the underlying OpenMLS storage provider.
    /// This is primarily useful for internal operations and testing.
    ///
    /// # Returns
    ///
    /// A reference to the openmls storage implementation.
    fn openmls_storage(&self) -> &Self::OpenMlsStorageProvider {
        &self.openmls_storage
    }

    /// Get a mutable reference to the openmls storage provider.
    ///
    /// This method provides mutable access to the underlying OpenMLS storage provider.
    /// This is primarily useful for internal operations and testing.
    ///
    /// # Returns
    ///
    /// A mutable reference to the openmls storage implementation.
    fn openmls_storage_mut(&mut self) -> &mut Self::OpenMlsStorageProvider {
        &mut self.openmls_storage
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mdk_storage_traits::GroupId;
    use mdk_storage_traits::Secret;
    use mdk_storage_traits::groups::GroupStorage;
    use mdk_storage_traits::groups::types::{Group, GroupExporterSecret, GroupState};
    use mdk_storage_traits::messages::MessageStorage;
    use mdk_storage_traits::messages::error::MessageError;
    use mdk_storage_traits::messages::types::{Message, MessageState, ProcessedMessageState};
    use mdk_storage_traits::test_utils::crypto_utils::generate_random_bytes;
    use mdk_storage_traits::welcomes::WelcomeStorage;
    use mdk_storage_traits::welcomes::types::{ProcessedWelcomeState, Welcome, WelcomeState};
    use nostr::{EventId, Kind, PublicKey, RelayUrl, Tags, Timestamp, UnsignedEvent};
    use openmls_memory_storage::MemoryStorage;

    use super::*;

    fn create_test_group_id() -> GroupId {
        GroupId::from_slice(&[1, 2, 3, 4])
    }

    #[test]
    fn test_new_with_storage() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        assert_eq!(nostr_storage.backend(), Backend::Memory);
    }

    #[test]
    fn test_backend_type() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        assert_eq!(nostr_storage.backend(), Backend::Memory);
        assert!(!nostr_storage.backend().is_persistent());
    }

    #[test]
    fn test_storage_is_memory_based() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        assert!(!nostr_storage.backend().is_persistent());
    }

    #[test]
    fn test_compare_backend_types() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let memory_backend = nostr_storage.backend();
        assert_eq!(memory_backend, Backend::Memory);
        assert_ne!(memory_backend, Backend::SQLite);
    }

    #[test]
    fn test_create_multiple_instances() {
        let storage1 = MemoryStorage::default();
        let storage2 = MemoryStorage::default();
        let nostr_storage1 = MdkMemoryStorage::new(storage1);
        let nostr_storage2 = MdkMemoryStorage::new(storage2);

        assert_eq!(nostr_storage1.backend(), nostr_storage2.backend());
        assert_eq!(nostr_storage1.backend(), Backend::Memory);
        assert_eq!(nostr_storage2.backend(), Backend::Memory);
    }

    #[test]
    fn test_group_cache() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let image_hash = Some(generate_random_bytes(32).try_into().unwrap());
        let image_key = Some(Secret::new(generate_random_bytes(32).try_into().unwrap()));
        let image_nonce = Some(Secret::new(generate_random_bytes(12).try_into().unwrap()));
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
            image_hash,
            image_key,
            image_nonce,
        };
        nostr_storage.save_group(group.clone()).unwrap();
        let found_group = nostr_storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_group.mls_group_id, mls_group_id);
        assert_eq!(found_group.nostr_group_id, nostr_group_id);

        // Verify the group is in the cache
        {
            let cache = nostr_storage.groups_cache.read();
            assert!(cache.contains(&mls_group_id));
        }
        {
            let cache = nostr_storage.groups_by_nostr_id_cache.read();
            assert!(cache.contains(&nostr_group_id));
        }
    }

    #[test]
    fn test_group_relays() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let image_hash = Some(generate_random_bytes(32).try_into().unwrap());
        let image_key = Some(Secret::new(generate_random_bytes(32).try_into().unwrap()));
        let image_nonce = Some(Secret::new(generate_random_bytes(12).try_into().unwrap()));
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Another Test Group".to_string(),
            description: "Another test group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash,
            image_key,
            image_nonce,
        };
        nostr_storage.save_group(group.clone()).unwrap();
        let relay_url1 = RelayUrl::parse("wss://relay1.example.com").unwrap();
        let relay_url2 = RelayUrl::parse("wss://relay2.example.com").unwrap();
        let relays = BTreeSet::from([relay_url1, relay_url2]);
        nostr_storage
            .replace_group_relays(&mls_group_id, relays)
            .unwrap();
        let found_relays = nostr_storage.group_relays(&mls_group_id).unwrap();
        assert_eq!(found_relays.len(), 2);

        // Check that they're in the cache
        {
            let cache = nostr_storage.group_relays_cache.read();
            assert!(cache.contains(&mls_group_id));
            if let Some(relays) = cache.peek(&mls_group_id) {
                assert_eq!(relays.len(), 2);
            } else {
                panic!("Group relays not found in cache");
            }
        }
    }

    #[test]
    fn test_group_exporter_secret_cache() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let image_hash = Some(generate_random_bytes(32).try_into().unwrap());
        let image_key = Some(Secret::new(generate_random_bytes(32).try_into().unwrap()));
        let image_nonce = Some(Secret::new(generate_random_bytes(12).try_into().unwrap()));
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
            image_hash,
            image_key,
            image_nonce,
        };
        nostr_storage.save_group(group.clone()).unwrap();
        let group_exporter_secret_0 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 0,
            secret: Secret::new([0u8; 32]),
        };
        let group_exporter_secret_1 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 1,
            secret: Secret::new([0u8; 32]),
        };
        nostr_storage
            .save_group_exporter_secret(group_exporter_secret_0.clone())
            .unwrap();
        nostr_storage
            .save_group_exporter_secret(group_exporter_secret_1.clone())
            .unwrap();
        let found_secret_0 = nostr_storage
            .get_group_exporter_secret(&mls_group_id, 0)
            .unwrap()
            .unwrap();
        assert_eq!(found_secret_0, group_exporter_secret_0);
        let found_secret_1 = nostr_storage
            .get_group_exporter_secret(&mls_group_id, 1)
            .unwrap()
            .unwrap();
        assert_eq!(found_secret_1, group_exporter_secret_1);
        let non_existent_secret = nostr_storage
            .get_group_exporter_secret(&mls_group_id, 999)
            .unwrap();
        assert!(non_existent_secret.is_none());

        // Check cache
        {
            let cache = nostr_storage.group_exporter_secrets_cache.read();
            assert!(cache.contains(&(mls_group_id.clone(), 0)));
            assert!(cache.contains(&(mls_group_id.clone(), 1)));
            assert!(!cache.contains(&(mls_group_id.clone(), 999)));
        }
    }

    #[test]
    fn test_welcome_cache() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);

        // Create a test event ID
        let event_id = EventId::all_zeros();
        let wrapper_id = EventId::all_zeros();

        // Create a test pubkey
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();

        // Create a test welcome
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let welcome = Welcome {
            id: event_id,
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsWelcome,
                Tags::new(),
                "test".to_string(),
            ),
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            group_name: "Test Welcome Group".to_string(),
            group_description: "A test welcome group".to_string(),
            group_image_key: None,
            group_image_hash: None,
            group_image_nonce: None,
            group_admin_pubkeys: BTreeSet::from([pubkey]),
            group_relays: BTreeSet::from([RelayUrl::parse("wss://relay.example.com").unwrap()]),
            welcomer: pubkey,
            member_count: 2,
            state: WelcomeState::Pending,
            wrapper_event_id: wrapper_id,
        };

        // Save the welcome
        let result = nostr_storage.save_welcome(welcome.clone());
        assert!(result.is_ok());

        // Find the welcome by event ID
        let found_welcome = nostr_storage.find_welcome_by_event_id(&event_id);
        assert!(found_welcome.is_ok());
        let found_welcome = found_welcome.unwrap().unwrap();
        assert_eq!(found_welcome.id, event_id);
        assert_eq!(found_welcome.mls_group_id, mls_group_id);

        // Check that it's in the cache
        {
            let cache = nostr_storage.welcomes_cache.read();
            assert!(cache.contains(&event_id));
        }

        // Create a test processed welcome
        let processed_welcome = ProcessedWelcome {
            wrapper_event_id: wrapper_id,
            welcome_event_id: Some(event_id),
            processed_at: Timestamp::now(),
            state: ProcessedWelcomeState::Processed,
            failure_reason: None,
        };

        // Save the processed welcome
        let result = nostr_storage.save_processed_welcome(processed_welcome.clone());
        assert!(result.is_ok());

        // Find the processed welcome by event ID
        let found_processed_welcome = nostr_storage.find_processed_welcome_by_event_id(&wrapper_id);
        assert!(found_processed_welcome.is_ok());
        let found_processed_welcome = found_processed_welcome.unwrap().unwrap();
        assert_eq!(found_processed_welcome.wrapper_event_id, wrapper_id);
        assert_eq!(found_processed_welcome.welcome_event_id, Some(event_id));

        // Check that it's in the cache
        {
            let cache = nostr_storage.processed_welcomes_cache.read();
            assert!(cache.contains(&wrapper_id));
        }
    }

    #[test]
    fn test_message_cache() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let image_hash = Some(generate_random_bytes(32).try_into().unwrap());
        let image_key = Some(Secret::new(generate_random_bytes(32).try_into().unwrap()));
        let image_nonce = Some(Secret::new(generate_random_bytes(12).try_into().unwrap()));
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Message Test Group".to_string(),
            description: "A group for testing messages".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash,
            image_key,
            image_nonce,
        };
        nostr_storage.save_group(group.clone()).unwrap();
        let event_id = EventId::all_zeros();
        let wrapper_id = EventId::all_zeros();
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::MlsGroupMessage,
            mls_group_id: mls_group_id.clone(),
            created_at: Timestamp::now(),
            content: "Hello, world!".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "Hello, world!".to_string(),
            ),
            wrapper_event_id: wrapper_id,
            state: MessageState::Created,
        };
        nostr_storage.save_message(message.clone()).unwrap();
        let found_message = nostr_storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_message.id, event_id);
        assert_eq!(found_message.mls_group_id, mls_group_id);

        // Check caches
        {
            let cache = nostr_storage.messages_cache.read();
            assert!(cache.contains(&event_id));
        }
        {
            // Verify save_message populated the messages_by_group_cache correctly
            let cache = nostr_storage.messages_by_group_cache.read();
            assert!(cache.contains(&mls_group_id));
            if let Some(msgs) = cache.peek(&mls_group_id) {
                assert_eq!(msgs.len(), 1);
                assert!(msgs.contains_key(&event_id));
                assert_eq!(msgs.get(&event_id).unwrap().id, event_id);
            } else {
                panic!("Messages not found in group cache");
            }
        }
        let processed_message = ProcessedMessage {
            wrapper_event_id: wrapper_id,
            message_event_id: Some(event_id),
            processed_at: Timestamp::now(),
            state: ProcessedMessageState::Processed,
            failure_reason: None,
        };
        nostr_storage
            .save_processed_message(processed_message.clone())
            .unwrap();
        let found_processed = nostr_storage
            .find_processed_message_by_event_id(&wrapper_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_processed.wrapper_event_id, wrapper_id);
        {
            let cache = nostr_storage.processed_messages_cache.read();
            assert!(cache.contains(&wrapper_id));
        }
    }

    #[test]
    fn test_save_message_for_nonexistent_group() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let nonexistent_group_id = create_test_group_id();
        let event_id = EventId::all_zeros();
        let wrapper_id = EventId::all_zeros();
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::MlsGroupMessage,
            mls_group_id: nonexistent_group_id.clone(),
            created_at: Timestamp::now(),
            content: "Hello, world!".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "Hello, world!".to_string(),
            ),
            wrapper_event_id: wrapper_id,
            state: MessageState::Created,
        };

        // Attempting to save a message for a non-existent group should return an error
        let result = nostr_storage.save_message(message);
        assert!(result.is_err());
        match result.unwrap_err() {
            MessageError::InvalidParameters(msg) => {
                assert!(msg.contains("not found"));
            }
            _ => panic!("Expected InvalidParameters error"),
        }

        // Verify the message was not added to the cache
        {
            let cache = nostr_storage.messages_by_group_cache.read();
            assert!(!cache.contains(&nonexistent_group_id));
        }
    }

    #[test]
    fn test_update_existing_message() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Update Test Group".to_string(),
            description: "A group for testing message updates".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        nostr_storage.save_group(group).unwrap();

        let event_id = EventId::all_zeros();
        let wrapper_id = EventId::all_zeros();
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();
        let original_message = Message {
            id: event_id,
            pubkey,
            kind: Kind::MlsGroupMessage,
            mls_group_id: mls_group_id.clone(),
            created_at: Timestamp::now(),
            content: "Original message".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "Original message".to_string(),
            ),
            wrapper_event_id: wrapper_id,
            state: MessageState::Created,
        };

        // Save the original message
        nostr_storage
            .save_message(original_message.clone())
            .unwrap();

        // Verify the original message is stored
        let found_message = nostr_storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_message.content, "Original message");

        // Update the message with new content
        let updated_message = Message {
            content: "Updated message".to_string(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "Updated message".to_string(),
            ),
            ..original_message.clone()
        };

        // Save the updated message
        nostr_storage.save_message(updated_message.clone()).unwrap();

        // Verify the message was updated in the messages cache
        let found_message = nostr_storage
            .find_message_by_event_id(&event_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_message.content, "Updated message");

        // Verify the message was updated in the group cache
        {
            let cache = nostr_storage.messages_by_group_cache.read();
            let group_messages = cache.peek(&mls_group_id).unwrap();
            assert_eq!(group_messages.len(), 1);
            let msg = group_messages.get(&event_id).unwrap();
            assert_eq!(msg.content, "Updated message");
            assert_eq!(msg.id, event_id);
        }
    }

    #[test]
    fn test_save_multiple_messages_for_same_group() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Multiple Messages Group".to_string(),
            description: "A group for testing multiple messages".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        nostr_storage.save_group(group).unwrap();

        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();

        // Create and save first message
        let event_id_1 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let wrapper_id_1 = EventId::all_zeros();
        let message_1 = Message {
            id: event_id_1,
            pubkey,
            kind: Kind::MlsGroupMessage,
            mls_group_id: mls_group_id.clone(),
            created_at: Timestamp::now(),
            content: "First message".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "First message".to_string(),
            ),
            wrapper_event_id: wrapper_id_1,
            state: MessageState::Created,
        };
        nostr_storage.save_message(message_1.clone()).unwrap();

        // Create and save second message
        let event_id_2 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let wrapper_id_2 = EventId::all_zeros();
        let message_2 = Message {
            id: event_id_2,
            pubkey,
            kind: Kind::MlsGroupMessage,
            mls_group_id: mls_group_id.clone(),
            created_at: Timestamp::now(),
            content: "Second message".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "Second message".to_string(),
            ),
            wrapper_event_id: wrapper_id_2,
            state: MessageState::Created,
        };
        nostr_storage.save_message(message_2.clone()).unwrap();

        // Verify both messages are in the messages cache
        let found_message_1 = nostr_storage
            .find_message_by_event_id(&event_id_1)
            .unwrap()
            .unwrap();
        assert_eq!(found_message_1.content, "First message");

        let found_message_2 = nostr_storage
            .find_message_by_event_id(&event_id_2)
            .unwrap()
            .unwrap();
        assert_eq!(found_message_2.content, "Second message");

        // Verify both messages are in the group cache
        {
            let cache = nostr_storage.messages_by_group_cache.read();
            let group_messages = cache.peek(&mls_group_id).unwrap();
            assert_eq!(group_messages.len(), 2);
            assert_eq!(
                group_messages.get(&event_id_1).unwrap().content,
                "First message"
            );
            assert_eq!(
                group_messages.get(&event_id_2).unwrap().content,
                "Second message"
            );
        }
    }

    #[test]
    fn test_save_message_verifies_group_existence_before_cache_insertion() {
        let storage = MemoryStorage::default();
        let nostr_storage = MdkMemoryStorage::new(storage);
        let mls_group_id = create_test_group_id();
        let nonexistent_group_id = GroupId::from_slice(&[9, 9, 9, 9]);
        let event_id = EventId::all_zeros();
        let wrapper_id = EventId::all_zeros();
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();

        // Create a group
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
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
        nostr_storage.save_group(group).unwrap();

        // Try to save a message for a non-existent group
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::MlsGroupMessage,
            mls_group_id: nonexistent_group_id.clone(),
            created_at: Timestamp::now(),
            content: "Hello, world!".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "Hello, world!".to_string(),
            ),
            wrapper_event_id: wrapper_id,
            state: MessageState::Created,
        };

        let result = nostr_storage.save_message(message);
        assert!(result.is_err());

        // Verify the message was not added to either cache
        {
            let cache = nostr_storage.messages_cache.read();
            assert!(!cache.contains(&event_id));
        }
        {
            let cache = nostr_storage.messages_by_group_cache.read();
            assert!(!cache.contains(&nonexistent_group_id));
        }

        // Verify the existing group's cache is still empty (no messages were added)
        {
            let cache = nostr_storage.messages_by_group_cache.read();
            if let Some(messages) = cache.peek(&mls_group_id) {
                assert!(messages.is_empty());
            }
        }
    }

    #[test]
    fn test_with_custom_cache_size() {
        let storage = MemoryStorage::default();
        let custom_size = NonZeroUsize::new(50).unwrap();
        let nostr_storage = MdkMemoryStorage::with_cache_size(storage, custom_size);

        // Create a test group to verify the cache works
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let image_hash = Some(generate_random_bytes(32).try_into().unwrap());
        let image_key = Some(Secret::new(generate_random_bytes(32).try_into().unwrap()));
        let image_nonce = Some(Secret::new(generate_random_bytes(12).try_into().unwrap()));
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Custom Cache Group".to_string(),
            description: "A group for testing custom cache size".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash,
            image_key,
            image_nonce,
        };

        // Save the group
        nostr_storage.save_group(group.clone()).unwrap();

        // Find the group by MLS group ID
        let found_group = nostr_storage.find_group_by_mls_group_id(&mls_group_id);
        assert!(found_group.is_ok());
        let found_group = found_group.unwrap().unwrap();
        assert_eq!(found_group.mls_group_id, mls_group_id);
    }

    #[test]
    fn test_default_implementation() {
        let nostr_storage = MdkMemoryStorage::default();

        // Create a test group to verify the default implementation works
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let image_hash = Some(generate_random_bytes(32).try_into().unwrap());
        let image_key = Some(Secret::new(generate_random_bytes(32).try_into().unwrap()));
        let image_nonce = Some(Secret::new(generate_random_bytes(12).try_into().unwrap()));

        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Default Implementation Group".to_string(),
            description: "A group for testing default implementation".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash,
            image_key,
            image_nonce,
        };

        // Save the group
        nostr_storage.save_group(group.clone()).unwrap();

        // Find the group by MLS group ID
        let found_group = nostr_storage.find_group_by_mls_group_id(&mls_group_id);
        assert!(found_group.is_ok());
        let found_group = found_group.unwrap().unwrap();
        assert_eq!(found_group.mls_group_id, mls_group_id);
    }
}
