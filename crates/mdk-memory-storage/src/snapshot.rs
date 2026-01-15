//! Snapshot and rollback support for memory storage.
//!
//! This module provides the ability to create snapshots of all in-memory state
//! and restore them later. This provides functionality analogous to SQLite
//! savepoints for testing and rollback scenarios.
//!
//! # Concurrency Warning
//!
//! Snapshot creation and restoration are **not atomic** with respect to concurrent
//! operations. These operations acquire multiple independent locks sequentially,
//! which means:
//!
//! - During `create_snapshot()`: Concurrent writes may result in an inconsistent
//!   snapshot (some changes captured, others not).
//! - During `restore_snapshot()`: Concurrent reads may observe partial state
//!   (some data restored, some still from before the restore).
//!
//! **Callers must ensure no concurrent operations are in progress when creating
//! or restoring snapshots.** This is typically achieved by using snapshots only
//! in single-threaded test scenarios or by holding an external synchronization
//! primitive.

use std::collections::{BTreeSet, HashMap};

use lru::LruCache;
use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::types::{Group, GroupExporterSecret, GroupRelay};
use mdk_storage_traits::messages::types::{Message, ProcessedMessage};
use mdk_storage_traits::welcomes::types::{ProcessedWelcome, Welcome};
use nostr::EventId;

use crate::mls_storage::GroupDataType;

/// A snapshot of all in-memory state that can be restored later.
///
/// This enables rollback functionality similar to SQLite savepoints,
/// allowing you to:
/// 1. Create a snapshot before an operation
/// 2. Attempt the operation
/// 3. Restore the snapshot if the operation fails or needs to be undone
///
/// # Concurrency Warning
///
/// Snapshot creation and restoration are **not atomic** with respect to
/// concurrent operations. Callers must ensure no concurrent operations are
/// in progress when creating or restoring snapshots.
///
/// # Example
///
/// ```ignore
/// let storage = MdkMemoryStorage::default();
///
/// // Make some changes
/// storage.save_group(group)?;
///
/// // Create a snapshot (ensure no concurrent operations)
/// let snapshot = storage.create_snapshot();
///
/// // Try an operation that might need rollback
/// storage.save_message(message)?;
///
/// // If we need to undo (ensure no concurrent operations):
/// storage.restore_snapshot(snapshot);
/// ```
#[derive(Clone)]
pub struct MemoryStorageSnapshot {
    // MLS data
    pub(crate) mls_group_data: HashMap<(Vec<u8>, GroupDataType), Vec<u8>>,
    pub(crate) mls_own_leaf_nodes: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    pub(crate) mls_proposals: HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>,
    pub(crate) mls_key_packages: HashMap<Vec<u8>, Vec<u8>>,
    pub(crate) mls_psks: HashMap<Vec<u8>, Vec<u8>>,
    pub(crate) mls_signature_keys: HashMap<Vec<u8>, Vec<u8>>,
    pub(crate) mls_encryption_keys: HashMap<Vec<u8>, Vec<u8>>,
    pub(crate) mls_epoch_key_pairs: HashMap<(Vec<u8>, Vec<u8>, u32), Vec<u8>>,

    // MDK data - cloned from LRU caches
    pub(crate) groups: HashMap<GroupId, Group>,
    pub(crate) groups_by_nostr_id: HashMap<[u8; 32], Group>,
    pub(crate) group_relays: HashMap<GroupId, BTreeSet<GroupRelay>>,
    pub(crate) group_exporter_secrets: HashMap<(GroupId, u64), GroupExporterSecret>,
    pub(crate) welcomes: HashMap<EventId, Welcome>,
    pub(crate) processed_welcomes: HashMap<EventId, ProcessedWelcome>,
    pub(crate) messages: HashMap<EventId, Message>,
    pub(crate) messages_by_group: HashMap<GroupId, HashMap<EventId, Message>>,
    pub(crate) processed_messages: HashMap<EventId, ProcessedMessage>,
}

#[cfg(test)]
impl MemoryStorageSnapshot {
    /// Create a new empty snapshot for testing.
    pub(crate) fn new() -> Self {
        Self {
            mls_group_data: HashMap::new(),
            mls_own_leaf_nodes: HashMap::new(),
            mls_proposals: HashMap::new(),
            mls_key_packages: HashMap::new(),
            mls_psks: HashMap::new(),
            mls_signature_keys: HashMap::new(),
            mls_encryption_keys: HashMap::new(),
            mls_epoch_key_pairs: HashMap::new(),
            groups: HashMap::new(),
            groups_by_nostr_id: HashMap::new(),
            group_relays: HashMap::new(),
            group_exporter_secrets: HashMap::new(),
            welcomes: HashMap::new(),
            processed_welcomes: HashMap::new(),
            messages: HashMap::new(),
            messages_by_group: HashMap::new(),
            processed_messages: HashMap::new(),
        }
    }
}

/// Helper trait to clone LRU cache contents into a HashMap.
pub(crate) trait LruCacheExt<K, V> {
    /// Clone all entries from the LRU cache into a HashMap.
    fn clone_to_hashmap(&self) -> HashMap<K, V>
    where
        K: Clone + std::hash::Hash + Eq,
        V: Clone;
}

impl<K, V> LruCacheExt<K, V> for LruCache<K, V> {
    fn clone_to_hashmap(&self) -> HashMap<K, V>
    where
        K: Clone + std::hash::Hash + Eq,
        V: Clone,
    {
        self.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

/// Helper trait to restore HashMap contents back into an LRU cache.
pub(crate) trait HashMapToLruExt<K, V> {
    /// Restore entries from a HashMap into an LRU cache.
    fn restore_to_lru(&self, cache: &mut LruCache<K, V>)
    where
        K: Clone + std::hash::Hash + Eq,
        V: Clone;
}

impl<K, V> HashMapToLruExt<K, V> for HashMap<K, V> {
    fn restore_to_lru(&self, cache: &mut LruCache<K, V>)
    where
        K: Clone + std::hash::Hash + Eq,
        V: Clone,
    {
        cache.clear();
        for (k, v) in self.iter() {
            cache.put(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;

    #[test]
    fn test_lru_cache_clone_to_hashmap() {
        let mut cache: LruCache<String, i32> = LruCache::new(NonZeroUsize::new(10).unwrap());
        cache.put("a".to_string(), 1);
        cache.put("b".to_string(), 2);
        cache.put("c".to_string(), 3);

        let map = cache.clone_to_hashmap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("a"), Some(&1));
        assert_eq!(map.get("b"), Some(&2));
        assert_eq!(map.get("c"), Some(&3));
    }

    #[test]
    fn test_hashmap_restore_to_lru() {
        let mut map = HashMap::new();
        map.insert("x".to_string(), 10);
        map.insert("y".to_string(), 20);

        let mut cache: LruCache<String, i32> = LruCache::new(NonZeroUsize::new(10).unwrap());
        cache.put("old".to_string(), 999);

        map.restore_to_lru(&mut cache);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&"x".to_string()), Some(&10));
        assert_eq!(cache.get(&"y".to_string()), Some(&20));
        assert!(cache.get(&"old".to_string()).is_none());
    }

    #[test]
    fn test_empty_snapshot() {
        let snapshot = MemoryStorageSnapshot::new();
        assert!(snapshot.mls_group_data.is_empty());
        assert!(snapshot.groups.is_empty());
        assert!(snapshot.messages.is_empty());
    }
}
