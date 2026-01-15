//! Memory-based storage implementation for Nostr MLS.
//!
//! This module provides a memory-based storage implementation for the Nostr MLS (Messaging Layer Security)
//! crate. It implements the `MdkStorageProvider` trait, allowing it to be used within the Nostr MLS context.
//!
//! Memory-based storage is non-persistent and will be cleared when the application terminates.
//! It's useful for testing or ephemeral applications where persistence isn't required.
//!
//! # Unified Storage Architecture
//!
//! This implementation stores all MLS and MDK state in-memory. It supports
//! snapshot and restore operations for rollback scenarios, analogous to SQLite
//! savepoints.
//!
//! **Note:** Snapshot and restore operations are not atomic with respect to
//! concurrent access. Callers must ensure no other operations are in progress
//! when creating or restoring snapshots.

//! ## Memory Exhaustion Protection
//!
//! This implementation includes input validation to prevent memory exhaustion attacks.
//! The following limits are enforced (with configurable defaults via [`ValidationLimits`]):
//!
//! - [`DEFAULT_MAX_RELAYS_PER_GROUP`]: Maximum number of relays per group
//! - [`DEFAULT_MAX_MESSAGES_PER_GROUP`]: Maximum messages stored per group in the cache
//! - [`DEFAULT_MAX_GROUP_NAME_LENGTH`]: Maximum length of group name in bytes
//! - [`DEFAULT_MAX_GROUP_DESCRIPTION_LENGTH`]: Maximum length of group description in bytes
//! - [`DEFAULT_MAX_ADMINS_PER_GROUP`]: Maximum number of admin pubkeys per group
//! - [`DEFAULT_MAX_RELAYS_PER_WELCOME`]: Maximum number of relays in a welcome message
//! - [`DEFAULT_MAX_ADMINS_PER_WELCOME`]: Maximum number of admin pubkeys in a welcome message
//! - [`DEFAULT_MAX_RELAY_URL_LENGTH`]: Maximum length of a relay URL in bytes
//!
//! ## Customizing Limits
//!
//! You can customize these limits using [`ValidationLimits`] and the builder pattern:
//!
//! ```rust
//! use mdk_memory_storage::{MdkMemoryStorage, ValidationLimits};
//!
//! let limits = ValidationLimits::default()
//!     .with_cache_size(2000)
//!     .with_max_messages_per_group(5000)
//!     .with_max_relays_per_group(50);
//!
//! let storage = MdkMemoryStorage::with_limits(limits);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::num::NonZeroUsize;

use lru::LruCache;
use mdk_storage_traits::GroupId;
use mdk_storage_traits::groups::types::{Group, GroupExporterSecret, GroupRelay};
use mdk_storage_traits::messages::types::{Message, ProcessedMessage};
use mdk_storage_traits::welcomes::types::{ProcessedWelcome, Welcome};
use mdk_storage_traits::{Backend, MdkStorageError, MdkStorageProvider};
use nostr::EventId;
use openmls_traits::storage::{StorageProvider, traits};
use parking_lot::RwLock;

mod groups;
mod messages;
mod mls_storage;
mod snapshot;
mod welcomes;

use self::mls_storage::{
    GroupDataType, MlsEncryptionKeys, MlsEpochKeyPairs, MlsGroupData, MlsKeyPackages,
    MlsOwnLeafNodes, MlsProposals, MlsPsks, MlsSignatureKeys, STORAGE_PROVIDER_VERSION,
};
pub use self::snapshot::MemoryStorageSnapshot;
use self::snapshot::{HashMapToLruExt, LruCacheExt};

/// Default cache size for each LRU cache
const DEFAULT_CACHE_SIZE: NonZeroUsize = match NonZeroUsize::new(1000) {
    Some(v) => v,
    None => panic!("cache size must be non-zero"),
};

/// Default maximum number of relays allowed per group to prevent memory exhaustion.
/// This limit prevents attackers from growing a single cache entry unboundedly.
pub const DEFAULT_MAX_RELAYS_PER_GROUP: usize = 100;

/// Default maximum number of messages stored per group in the messages_by_group_cache.
/// When this limit is reached, the oldest messages are evicted from the per-group cache.
/// This prevents a single hot group from consuming excessive memory.
pub const DEFAULT_MAX_MESSAGES_PER_GROUP: usize = 10000;

/// Default maximum length of a group name in bytes (not characters).
/// Multi-byte UTF-8 characters count as multiple bytes toward this limit.
/// This prevents oversized group metadata from consuming excessive memory.
pub const DEFAULT_MAX_GROUP_NAME_LENGTH: usize = 256;

/// Default maximum length of a group description in bytes (not characters).
/// Multi-byte UTF-8 characters count as multiple bytes toward this limit.
/// This prevents oversized group metadata from consuming excessive memory.
pub const DEFAULT_MAX_GROUP_DESCRIPTION_LENGTH: usize = 4096;

/// Default maximum number of admin pubkeys allowed per group.
/// This prevents unbounded growth of the admin set.
pub const DEFAULT_MAX_ADMINS_PER_GROUP: usize = 100;

/// Default maximum number of relays allowed in a welcome message.
/// This prevents oversized welcome messages from consuming excessive memory.
pub const DEFAULT_MAX_RELAYS_PER_WELCOME: usize = 100;

/// Default maximum number of admin pubkeys allowed in a welcome message.
/// This prevents oversized welcome messages from consuming excessive memory.
pub const DEFAULT_MAX_ADMINS_PER_WELCOME: usize = 100;

/// Default maximum length of a relay URL in bytes.
/// This prevents oversized relay URLs from consuming excessive memory.
pub const DEFAULT_MAX_RELAY_URL_LENGTH: usize = 512;

/// Configurable validation limits for memory storage.
///
/// This struct allows customization of the various limits used to prevent
/// memory exhaustion attacks. All limits have sensible defaults that can
/// be overridden using the builder pattern.
///
/// # Example
///
/// ```rust
/// use mdk_memory_storage::ValidationLimits;
///
/// let limits = ValidationLimits::default()
///     .with_cache_size(2000)
///     .with_max_messages_per_group(5000)
///     .with_max_relays_per_group(50);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ValidationLimits {
    /// Maximum number of items in each LRU cache
    pub cache_size: usize,
    /// Maximum number of relays allowed per group
    pub max_relays_per_group: usize,
    /// Maximum number of messages stored per group
    pub max_messages_per_group: usize,
    /// Maximum length of a group name in bytes
    pub max_group_name_length: usize,
    /// Maximum length of a group description in bytes
    pub max_group_description_length: usize,
    /// Maximum number of admin pubkeys per group
    pub max_admins_per_group: usize,
    /// Maximum number of relays in a welcome message
    pub max_relays_per_welcome: usize,
    /// Maximum number of admin pubkeys in a welcome message
    pub max_admins_per_welcome: usize,
    /// Maximum length of a relay URL in bytes
    pub max_relay_url_length: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            cache_size: DEFAULT_CACHE_SIZE.get(),
            max_relays_per_group: DEFAULT_MAX_RELAYS_PER_GROUP,
            max_messages_per_group: DEFAULT_MAX_MESSAGES_PER_GROUP,
            max_group_name_length: DEFAULT_MAX_GROUP_NAME_LENGTH,
            max_group_description_length: DEFAULT_MAX_GROUP_DESCRIPTION_LENGTH,
            max_admins_per_group: DEFAULT_MAX_ADMINS_PER_GROUP,
            max_relays_per_welcome: DEFAULT_MAX_RELAYS_PER_WELCOME,
            max_admins_per_welcome: DEFAULT_MAX_ADMINS_PER_WELCOME,
            max_relay_url_length: DEFAULT_MAX_RELAY_URL_LENGTH,
        }
    }
}

impl ValidationLimits {
    /// Creates a new `ValidationLimits` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of items in each LRU cache.
    ///
    /// # Panics
    ///
    /// Panics if `size` is 0.
    pub fn with_cache_size(mut self, size: usize) -> Self {
        assert!(size > 0, "cache_size must be greater than 0");
        self.cache_size = size;
        self
    }

    /// Sets the maximum number of relays allowed per group.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_relays_per_group(mut self, limit: usize) -> Self {
        assert!(limit > 0, "max_relays_per_group must be greater than 0");
        self.max_relays_per_group = limit;
        self
    }

    /// Sets the maximum number of messages stored per group.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_messages_per_group(mut self, limit: usize) -> Self {
        assert!(limit > 0, "max_messages_per_group must be greater than 0");
        self.max_messages_per_group = limit;
        self
    }

    /// Sets the maximum length of a group name in bytes.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_group_name_length(mut self, limit: usize) -> Self {
        assert!(limit > 0, "max_group_name_length must be greater than 0");
        self.max_group_name_length = limit;
        self
    }

    /// Sets the maximum length of a group description in bytes.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_group_description_length(mut self, limit: usize) -> Self {
        assert!(
            limit > 0,
            "max_group_description_length must be greater than 0"
        );
        self.max_group_description_length = limit;
        self
    }

    /// Sets the maximum number of admin pubkeys per group.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_admins_per_group(mut self, limit: usize) -> Self {
        assert!(limit > 0, "max_admins_per_group must be greater than 0");
        self.max_admins_per_group = limit;
        self
    }

    /// Sets the maximum number of relays in a welcome message.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_relays_per_welcome(mut self, limit: usize) -> Self {
        assert!(limit > 0, "max_relays_per_welcome must be greater than 0");
        self.max_relays_per_welcome = limit;
        self
    }

    /// Sets the maximum number of admin pubkeys in a welcome message.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_admins_per_welcome(mut self, limit: usize) -> Self {
        assert!(limit > 0, "max_admins_per_welcome must be greater than 0");
        self.max_admins_per_welcome = limit;
        self
    }

    /// Sets the maximum length of a relay URL in bytes.
    ///
    /// # Panics
    ///
    /// Panics if `limit` is 0.
    pub fn with_max_relay_url_length(mut self, limit: usize) -> Self {
        assert!(limit > 0, "max_relay_url_length must be greater than 0");
        self.max_relay_url_length = limit;
        self
    }
}

/// A memory-based storage implementation for Nostr MLS.
///
/// This struct implements both the OpenMLS `StorageProvider<1>` trait and MDK storage
/// traits directly, providing unified storage for MLS cryptographic state and
/// MDK-specific data (groups, messages, welcomes).
///
/// ## Unified Storage Architecture
///
/// This implementation stores all MLS and MDK state in-memory, providing:
/// - Snapshot/restore operations for rollback scenarios
/// - Thread-safe access through `RwLock` protected data structures
/// - LRU caching for frequently accessed MDK objects
///
/// **Important:** Snapshot and restore operations read/write multiple independent
/// locks and are not atomic with respect to concurrent operations. Callers must
/// ensure no other operations are in progress when creating or restoring snapshots.
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
///
/// ## Configurable Validation Limits
///
/// You can customize validation limits using [`ValidationLimits`]:
///
/// ```rust
/// use mdk_memory_storage::{MdkMemoryStorage, ValidationLimits};
///
/// let limits = ValidationLimits::default()
///     .with_cache_size(2000)
///     .with_max_messages_per_group(5000);
///
/// let storage = MdkMemoryStorage::with_limits(limits);
/// ```
pub struct MdkMemoryStorage {
    // ========================================================================
    // MLS Storage (replaces openmls_memory_storage)
    // ========================================================================
    /// MLS group data (join config, tree, context, etc.)
    mls_group_data: MlsGroupData,
    /// MLS own leaf nodes for each group
    mls_own_leaf_nodes: MlsOwnLeafNodes,
    /// MLS proposals queue
    mls_proposals: MlsProposals,
    /// MLS key packages
    mls_key_packages: MlsKeyPackages,
    /// MLS pre-shared keys
    mls_psks: MlsPsks,
    /// MLS signature key pairs
    mls_signature_keys: MlsSignatureKeys,
    /// MLS HPKE encryption key pairs
    mls_encryption_keys: MlsEncryptionKeys,
    /// MLS epoch encryption key pairs
    mls_epoch_key_pairs: MlsEpochKeyPairs,

    // ========================================================================
    // MDK Storage (groups, messages, welcomes)
    // ========================================================================
    /// Configurable validation limits
    limits: ValidationLimits,

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

impl fmt::Debug for MdkMemoryStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact all caches that contain GroupId keys to prevent sensitive identifier exposure
        f.debug_struct("MdkMemoryStorage")
            .field("mls_group_data", &"[REDACTED]")
            .field("mls_own_leaf_nodes", &"[REDACTED]")
            .field("mls_proposals", &"[REDACTED]")
            .field("mls_key_packages", &"[REDACTED]")
            .field("mls_psks", &"[REDACTED]")
            .field("mls_signature_keys", &"[REDACTED]")
            .field("mls_encryption_keys", &"[REDACTED]")
            .field("mls_epoch_key_pairs", &"[REDACTED]")
            .field("limits", &self.limits)
            .field("groups_cache", &"[REDACTED]")
            .field("groups_by_nostr_id_cache", &"[REDACTED]")
            .field("group_relays_cache", &"[REDACTED]")
            .field("welcomes_cache", &"[REDACTED]")
            .field("processed_welcomes_cache", &"[REDACTED]")
            .field("messages_cache", &"[REDACTED]")
            .field("messages_by_group_cache", &"[REDACTED]")
            .field("processed_messages_cache", &"[REDACTED]")
            .field("group_exporter_secrets_cache", &"[REDACTED]")
            .finish()
    }
}

impl Default for MdkMemoryStorage {
    /// Creates a new `MdkMemoryStorage` with default configuration.
    ///
    /// # Returns
    ///
    /// A new instance of `MdkMemoryStorage` with the default cache size.
    fn default() -> Self {
        Self::new()
    }
}

impl MdkMemoryStorage {
    /// Creates a new `MdkMemoryStorage` with the default configuration.
    ///
    /// # Returns
    ///
    /// A new instance of `MdkMemoryStorage` with the default cache size.
    pub fn new() -> Self {
        Self::with_cache_size(DEFAULT_CACHE_SIZE)
    }

    /// Creates a new `MdkMemoryStorage` with the specified cache size.
    ///
    /// # Arguments
    ///
    /// * `cache_size` - The maximum number of items to store in each LRU cache.
    ///
    /// # Returns
    ///
    /// A new instance of `MdkMemoryStorage` with the specified cache size.
    pub fn with_cache_size(cache_size: NonZeroUsize) -> Self {
        Self::with_limits(ValidationLimits::default().with_cache_size(cache_size.get()))
    }

    /// Creates a new `MdkMemoryStorage` with the provided validation limits.
    ///
    /// # Arguments
    ///
    /// * `limits` - Custom validation limits for memory exhaustion protection.
    ///
    /// # Returns
    ///
    /// A new instance of `MdkMemoryStorage`.
    pub fn with_limits(limits: ValidationLimits) -> Self {
        let cache_size =
            NonZeroUsize::new(limits.cache_size).expect("cache_size must be greater than 0");
        MdkMemoryStorage {
            // MLS storage
            mls_group_data: MlsGroupData::new(),
            mls_own_leaf_nodes: MlsOwnLeafNodes::new(),
            mls_proposals: MlsProposals::new(),
            mls_key_packages: MlsKeyPackages::new(),
            mls_psks: MlsPsks::new(),
            mls_signature_keys: MlsSignatureKeys::new(),
            mls_encryption_keys: MlsEncryptionKeys::new(),
            mls_epoch_key_pairs: MlsEpochKeyPairs::new(),
            // MDK storage
            limits,

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

    // ========================================================================
    // Snapshot and Restore Support
    // ========================================================================

    /// Creates a snapshot of all in-memory state.
    ///
    /// This enables rollback functionality similar to SQLite savepoints,
    /// allowing you to:
    /// 1. Create a snapshot before an operation
    /// 2. Attempt the operation
    /// 3. Restore the snapshot if the operation fails or needs to be undone
    ///
    /// # Concurrency Warning
    ///
    /// This method acquires multiple independent locks sequentially. If other
    /// threads are performing operations concurrently, the snapshot may capture
    /// an inconsistent state. **Callers must ensure no concurrent operations
    /// are in progress when creating a snapshot.**
    ///
    /// # Returns
    ///
    /// A `MemoryStorageSnapshot` containing cloned copies of all state.
    ///
    /// # Example
    ///
    /// ```
    /// use mdk_memory_storage::MdkMemoryStorage;
    ///
    /// let storage = MdkMemoryStorage::default();
    ///
    /// // Create a snapshot before an operation
    /// let snapshot = storage.create_snapshot();
    ///
    /// // ... perform operations that might need rollback ...
    ///
    /// // If something goes wrong, restore the snapshot
    /// storage.restore_snapshot(snapshot);
    /// ```
    pub fn create_snapshot(&self) -> MemoryStorageSnapshot {
        MemoryStorageSnapshot {
            // MLS data
            mls_group_data: self.mls_group_data.clone_data(),
            mls_own_leaf_nodes: self.mls_own_leaf_nodes.clone_data(),
            mls_proposals: self.mls_proposals.clone_data(),
            mls_key_packages: self.mls_key_packages.clone_data(),
            mls_psks: self.mls_psks.clone_data(),
            mls_signature_keys: self.mls_signature_keys.clone_data(),
            mls_encryption_keys: self.mls_encryption_keys.clone_data(),
            mls_epoch_key_pairs: self.mls_epoch_key_pairs.clone_data(),
            // MDK data
            groups: self.groups_cache.read().clone_to_hashmap(),
            groups_by_nostr_id: self.groups_by_nostr_id_cache.read().clone_to_hashmap(),
            group_relays: self.group_relays_cache.read().clone_to_hashmap(),
            group_exporter_secrets: self.group_exporter_secrets_cache.read().clone_to_hashmap(),
            welcomes: self.welcomes_cache.read().clone_to_hashmap(),
            processed_welcomes: self.processed_welcomes_cache.read().clone_to_hashmap(),
            messages: self.messages_cache.read().clone_to_hashmap(),
            messages_by_group: self.messages_by_group_cache.read().clone_to_hashmap(),
            processed_messages: self.processed_messages_cache.read().clone_to_hashmap(),
        }
    }

    /// Restores state from a previously created snapshot.
    ///
    /// This replaces all current in-memory state with the state from the snapshot.
    ///
    /// # Concurrency Warning
    ///
    /// This method acquires multiple independent locks sequentially. If other
    /// threads are performing operations concurrently, they may observe partial
    /// restore state (some data restored, some not yet). **Callers must ensure
    /// no concurrent operations are in progress when restoring a snapshot.**
    ///
    /// # Arguments
    ///
    /// * `snapshot` - The snapshot to restore from.
    pub fn restore_snapshot(&self, snapshot: MemoryStorageSnapshot) {
        // Restore MLS data
        self.mls_group_data.restore_data(snapshot.mls_group_data);
        self.mls_own_leaf_nodes
            .restore_data(snapshot.mls_own_leaf_nodes);
        self.mls_proposals.restore_data(snapshot.mls_proposals);
        self.mls_key_packages
            .restore_data(snapshot.mls_key_packages);
        self.mls_psks.restore_data(snapshot.mls_psks);
        self.mls_signature_keys
            .restore_data(snapshot.mls_signature_keys);
        self.mls_encryption_keys
            .restore_data(snapshot.mls_encryption_keys);
        self.mls_epoch_key_pairs
            .restore_data(snapshot.mls_epoch_key_pairs);

        // Restore MDK data
        snapshot
            .groups
            .restore_to_lru(&mut self.groups_cache.write());
        snapshot
            .groups_by_nostr_id
            .restore_to_lru(&mut self.groups_by_nostr_id_cache.write());
        snapshot
            .group_relays
            .restore_to_lru(&mut self.group_relays_cache.write());
        snapshot
            .group_exporter_secrets
            .restore_to_lru(&mut self.group_exporter_secrets_cache.write());
        snapshot
            .welcomes
            .restore_to_lru(&mut self.welcomes_cache.write());
        snapshot
            .processed_welcomes
            .restore_to_lru(&mut self.processed_welcomes_cache.write());
        snapshot
            .messages
            .restore_to_lru(&mut self.messages_cache.write());
        snapshot
            .messages_by_group
            .restore_to_lru(&mut self.messages_by_group_cache.write());
        snapshot
            .processed_messages
            .restore_to_lru(&mut self.processed_messages_cache.write());
    }

    /// Returns the current validation limits.
    pub fn limits(&self) -> &ValidationLimits {
        &self.limits
    }
}

/// Implementation of `MdkStorageProvider` for memory-based storage.
impl MdkStorageProvider for MdkMemoryStorage {
    /// Returns the backend type.
    ///
    /// # Returns
    ///
    /// [`Backend::Memory`] indicating this is a memory-based storage implementation.
    fn backend(&self) -> Backend {
        Backend::Memory
    }
}

// ============================================================================
// OpenMLS StorageProvider<1> Implementation
// ============================================================================

impl StorageProvider<STORAGE_PROVIDER_VERSION> for MdkMemoryStorage {
    type Error = MdkStorageError;

    // ========================================================================
    // Write Methods
    // ========================================================================

    fn write_mls_join_config<GroupId, MlsGroupJoinConfig>(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .write(group_id, GroupDataType::JoinGroupConfig, config)
    }

    fn append_own_leaf_node<GroupId, LeafNode>(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_own_leaf_nodes.append(group_id, leaf_node)
    }

    fn queue_proposal<GroupId, ProposalRef, QueuedProposal>(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_proposals.queue(group_id, proposal_ref, proposal)
    }

    fn write_tree<GroupId, TreeSync>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .write(group_id, GroupDataType::Tree, tree)
    }

    fn write_interim_transcript_hash<GroupId, InterimTranscriptHash>(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data.write(
            group_id,
            GroupDataType::InterimTranscriptHash,
            interim_transcript_hash,
        )
    }

    fn write_context<GroupId, GroupContext>(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .write(group_id, GroupDataType::Context, group_context)
    }

    fn write_confirmation_tag<GroupId, ConfirmationTag>(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .write(group_id, GroupDataType::ConfirmationTag, confirmation_tag)
    }

    fn write_group_state<GroupState, GroupId>(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error>
    where
        GroupState: traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .write(group_id, GroupDataType::GroupState, group_state)
    }

    fn write_message_secrets<GroupId, MessageSecrets>(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .write(group_id, GroupDataType::MessageSecrets, message_secrets)
    }

    fn write_resumption_psk_store<GroupId, ResumptionPskStore>(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data.write(
            group_id,
            GroupDataType::ResumptionPskStore,
            resumption_psk_store,
        )
    }

    fn write_own_leaf_index<GroupId, LeafNodeIndex>(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .write(group_id, GroupDataType::OwnLeafIndex, own_leaf_index)
    }

    fn write_group_epoch_secrets<GroupId, GroupEpochSecrets>(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data.write(
            group_id,
            GroupDataType::GroupEpochSecrets,
            group_epoch_secrets,
        )
    }

    fn write_signature_key_pair<SignaturePublicKey, SignatureKeyPair>(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error>
    where
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_signature_keys
            .write(public_key, signature_key_pair)
    }

    fn write_encryption_key_pair<EncryptionKey, HpkeKeyPair>(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error>
    where
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_encryption_keys.write(public_key, key_pair)
    }

    fn write_encryption_epoch_key_pairs<GroupId, EpochKey, HpkeKeyPair>(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_epoch_key_pairs
            .write(group_id, epoch, leaf_index, key_pairs)
    }

    fn write_key_package<HashReference, KeyPackage>(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error>
    where
        HashReference: traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_key_packages.write(hash_ref, key_package)
    }

    fn write_psk<PskId, PskBundle>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error>
    where
        PskId: traits::PskId<STORAGE_PROVIDER_VERSION>,
        PskBundle: traits::PskBundle<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_psks.write(psk_id, psk)
    }

    // ========================================================================
    // Read Methods
    // ========================================================================

    fn mls_group_join_config<GroupId, MlsGroupJoinConfig>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::JoinGroupConfig)
    }

    fn own_leaf_nodes<GroupId, LeafNode>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_own_leaf_nodes.read(group_id)
    }

    fn queued_proposal_refs<GroupId, ProposalRef>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_proposals.read_refs(group_id)
    }

    fn queued_proposals<GroupId, ProposalRef, QueuedProposal>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_proposals.read_proposals(group_id)
    }

    fn tree<GroupId, TreeSync>(&self, group_id: &GroupId) -> Result<Option<TreeSync>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data.read(group_id, GroupDataType::Tree)
    }

    fn group_context<GroupId, GroupContext>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data.read(group_id, GroupDataType::Context)
    }

    fn interim_transcript_hash<GroupId, InterimTranscriptHash>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::InterimTranscriptHash)
    }

    fn confirmation_tag<GroupId, ConfirmationTag>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::ConfirmationTag)
    }

    fn group_state<GroupState, GroupId>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error>
    where
        GroupState: traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::GroupState)
    }

    fn message_secrets<GroupId, MessageSecrets>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::MessageSecrets)
    }

    fn resumption_psk_store<GroupId, ResumptionPskStore>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::ResumptionPskStore)
    }

    fn own_leaf_index<GroupId, LeafNodeIndex>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::OwnLeafIndex)
    }

    fn group_epoch_secrets<GroupId, GroupEpochSecrets>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .read(group_id, GroupDataType::GroupEpochSecrets)
    }

    fn signature_key_pair<SignaturePublicKey, SignatureKeyPair>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error>
    where
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_signature_keys.read(public_key)
    }

    fn encryption_key_pair<HpkeKeyPair, EncryptionKey>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error>
    where
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_encryption_keys.read(public_key)
    }

    fn encryption_epoch_key_pairs<GroupId, EpochKey, HpkeKeyPair>(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_epoch_key_pairs.read(group_id, epoch, leaf_index)
    }

    fn key_package<HashReference, KeyPackage>(
        &self,
        hash_ref: &HashReference,
    ) -> Result<Option<KeyPackage>, Self::Error>
    where
        HashReference: traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_key_packages.read(hash_ref)
    }

    fn psk<PskBundle, PskId>(&self, psk_id: &PskId) -> Result<Option<PskBundle>, Self::Error>
    where
        PskBundle: traits::PskBundle<STORAGE_PROVIDER_VERSION>,
        PskId: traits::PskId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_psks.read(psk_id)
    }

    // ========================================================================
    // Delete Methods
    // ========================================================================

    fn remove_proposal<GroupId, ProposalRef>(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_proposals.remove(group_id, proposal_ref)
    }

    fn delete_own_leaf_nodes<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_own_leaf_nodes.delete(group_id)
    }

    fn delete_group_config<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::JoinGroupConfig)
    }

    fn delete_tree<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data.delete(group_id, GroupDataType::Tree)
    }

    fn delete_confirmation_tag<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::ConfirmationTag)
    }

    fn delete_group_state<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::GroupState)
    }

    fn delete_context<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data.delete(group_id, GroupDataType::Context)
    }

    fn delete_interim_transcript_hash<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::InterimTranscriptHash)
    }

    fn delete_message_secrets<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::MessageSecrets)
    }

    fn delete_all_resumption_psk_secrets<GroupId>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::ResumptionPskStore)
    }

    fn delete_own_leaf_index<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::OwnLeafIndex)
    }

    fn delete_group_epoch_secrets<GroupId>(&self, group_id: &GroupId) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_group_data
            .delete(group_id, GroupDataType::GroupEpochSecrets)
    }

    fn clear_proposal_queue<GroupId, ProposalRef>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_proposals.clear(group_id)
    }

    fn delete_signature_key_pair<SignaturePublicKey>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error>
    where
        SignaturePublicKey: traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_signature_keys.delete(public_key)
    }

    fn delete_encryption_key_pair<EncryptionKey>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error>
    where
        EncryptionKey: traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_encryption_keys.delete(public_key)
    }

    fn delete_encryption_epoch_key_pairs<GroupId, EpochKey>(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error>
    where
        GroupId: traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: traits::EpochKey<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_epoch_key_pairs.delete(group_id, epoch, leaf_index)
    }

    fn delete_key_package<HashReference>(&self, hash_ref: &HashReference) -> Result<(), Self::Error>
    where
        HashReference: traits::HashReference<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_key_packages.delete(hash_ref)
    }

    fn delete_psk<PskId>(&self, psk_id: &PskId) -> Result<(), Self::Error>
    where
        PskId: traits::PskId<STORAGE_PROVIDER_VERSION>,
    {
        self.mls_psks.delete(psk_id)
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

    use super::*;

    fn create_test_group_id() -> GroupId {
        GroupId::from_slice(&[1, 2, 3, 4])
    }

    #[test]
    fn test_new() {
        let nostr_storage = MdkMemoryStorage::new();
        assert_eq!(nostr_storage.backend(), Backend::Memory);
    }

    #[test]
    fn test_default() {
        let nostr_storage = MdkMemoryStorage::default();
        assert_eq!(nostr_storage.backend(), Backend::Memory);
    }

    #[test]
    fn test_backend_type() {
        let nostr_storage = MdkMemoryStorage::default();
        assert_eq!(nostr_storage.backend(), Backend::Memory);
        assert!(!nostr_storage.backend().is_persistent());
    }

    #[test]
    fn test_storage_is_memory_based() {
        let nostr_storage = MdkMemoryStorage::default();
        assert!(!nostr_storage.backend().is_persistent());
    }

    #[test]
    fn test_compare_backend_types() {
        let nostr_storage = MdkMemoryStorage::default();
        let memory_backend = nostr_storage.backend();
        assert_eq!(memory_backend, Backend::Memory);
        assert_ne!(memory_backend, Backend::SQLite);
    }

    #[test]
    fn test_create_multiple_instances() {
        let nostr_storage1 = MdkMemoryStorage::new();
        let nostr_storage2 = MdkMemoryStorage::new();

        assert_eq!(nostr_storage1.backend(), nostr_storage2.backend());
        assert_eq!(nostr_storage1.backend(), Backend::Memory);
        assert_eq!(nostr_storage2.backend(), Backend::Memory);
    }

    #[test]
    fn test_group_cache() {
        let nostr_storage = MdkMemoryStorage::default();
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
        let nostr_storage = MdkMemoryStorage::default();
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
        let nostr_storage = MdkMemoryStorage::default();
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
        let nostr_storage = MdkMemoryStorage::default();

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
        let nostr_storage = MdkMemoryStorage::default();
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
            .find_message_by_event_id(&mls_group_id, &event_id)
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
        let nostr_storage = MdkMemoryStorage::default();
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
        let nostr_storage = MdkMemoryStorage::default();
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
            .find_message_by_event_id(&mls_group_id, &event_id)
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
            .find_message_by_event_id(&mls_group_id, &event_id)
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
        let nostr_storage = MdkMemoryStorage::default();
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
            .find_message_by_event_id(&mls_group_id, &event_id_1)
            .unwrap()
            .unwrap();
        assert_eq!(found_message_1.content, "First message");

        let found_message_2 = nostr_storage
            .find_message_by_event_id(&mls_group_id, &event_id_2)
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
        let nostr_storage = MdkMemoryStorage::default();
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
        let custom_size = NonZeroUsize::new(50).unwrap();
        let nostr_storage = MdkMemoryStorage::with_cache_size(custom_size);

        // Verify the cache size is set correctly
        assert_eq!(nostr_storage.limits().cache_size, 50);

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

    #[test]
    fn test_snapshot_and_restore() {
        let storage = MdkMemoryStorage::default();

        // Create and save a group
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Snapshot Test Group".to_string(),
            description: "A group for testing snapshots".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        storage.save_group(group.clone()).unwrap();

        // Create a snapshot
        let snapshot = storage.create_snapshot();

        // Modify the group
        let modified_group = Group {
            name: "Modified Group Name".to_string(),
            epoch: 5,
            ..group.clone()
        };
        storage.save_group(modified_group.clone()).unwrap();

        // Verify the modification
        let found_group = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(found_group.name, "Modified Group Name");
        assert_eq!(found_group.epoch, 5);

        // Restore the snapshot
        storage.restore_snapshot(snapshot);

        // Verify the original state is restored
        let restored_group = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(restored_group.name, "Snapshot Test Group");
        assert_eq!(restored_group.epoch, 0);
    }

    #[test]
    fn test_snapshot_with_messages() {
        let storage = MdkMemoryStorage::default();

        // Create and save a group
        let mls_group_id = create_test_group_id();
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Message Snapshot Group".to_string(),
            description: "A group for testing message snapshots".to_string(),
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

        // Save a message
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();
        let event_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let message = Message {
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
            wrapper_event_id: EventId::all_zeros(),
            state: MessageState::Created,
        };
        storage.save_message(message).unwrap();

        // Create a snapshot with the message
        let snapshot = storage.create_snapshot();

        // Add another message
        let event_id_2 =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
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
            wrapper_event_id: EventId::all_zeros(),
            state: MessageState::Created,
        };
        storage.save_message(message_2).unwrap();

        // Verify we have two messages
        let messages = storage.messages(&mls_group_id, None).unwrap();
        assert_eq!(messages.len(), 2);

        // Restore the snapshot
        storage.restore_snapshot(snapshot);

        // Verify we're back to one message
        let messages_after = storage.messages(&mls_group_id, None).unwrap();
        assert_eq!(messages_after.len(), 1);
        assert_eq!(messages_after[0].content, "Original message");
    }

    // ========================================
    // Additional Snapshot/Rollback Tests (Phase 5)
    // ========================================

    #[test]
    fn test_snapshot_with_new_group_rollback() {
        let storage = MdkMemoryStorage::default();

        // Verify group doesn't exist
        let mls_group_id = GroupId::from_slice(&[13, 14, 15, 16]);
        let before = storage.find_group_by_mls_group_id(&mls_group_id).unwrap();
        assert!(before.is_none());

        // Create a snapshot
        let snapshot = storage.create_snapshot();

        // Insert a new group
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "New Group".to_string(),
            description: "A new group".to_string(),
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

        // Verify group exists
        let after_insert = storage.find_group_by_mls_group_id(&mls_group_id).unwrap();
        assert!(after_insert.is_some());

        // Restore snapshot (rollback)
        storage.restore_snapshot(snapshot);

        // Verify group no longer exists
        let after_rollback = storage.find_group_by_mls_group_id(&mls_group_id).unwrap();
        assert!(after_rollback.is_none());
    }

    #[test]
    fn test_snapshot_with_multiple_modifications_rollback() {
        let storage = MdkMemoryStorage::default();

        // Create and save a group
        let mls_group_id = GroupId::from_slice(&[17, 18, 19, 20]);
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Original Name".to_string(),
            description: "A group for testing modification rollback".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 1,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        storage.save_group(group.clone()).unwrap();

        // Verify group exists with original values
        let exists = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(exists.name, "Original Name");
        assert_eq!(exists.epoch, 1);

        // Create snapshot
        let snapshot = storage.create_snapshot();

        // Make multiple modifications
        let modified1 = Group {
            name: "Modified Once".to_string(),
            epoch: 10,
            ..group.clone()
        };
        storage.save_group(modified1).unwrap();

        let modified2 = Group {
            name: "Modified Twice".to_string(),
            epoch: 20,
            ..group.clone()
        };
        storage.save_group(modified2).unwrap();

        // Verify final modification
        let after_mods = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_mods.name, "Modified Twice");
        assert_eq!(after_mods.epoch, 20);

        // Restore snapshot (rollback)
        storage.restore_snapshot(snapshot);

        // Verify original values are restored
        let after_rollback = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_rollback.name, "Original Name");
        assert_eq!(after_rollback.epoch, 1);
    }

    #[test]
    fn test_snapshot_with_relays_rollback() {
        let storage = MdkMemoryStorage::default();

        // Create a group
        let mls_group_id = GroupId::from_slice(&[21, 22, 23, 24]);
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Relay Test Group".to_string(),
            description: "A group for testing relay rollback".to_string(),
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

        // Add initial relay
        let relay1 = RelayUrl::parse("wss://relay1.example.com").unwrap();
        storage
            .replace_group_relays(&mls_group_id, BTreeSet::from([relay1.clone()]))
            .unwrap();

        // Create snapshot
        let snapshot = storage.create_snapshot();

        // Add more relays
        let relay2 = RelayUrl::parse("wss://relay2.example.com").unwrap();
        storage
            .replace_group_relays(&mls_group_id, BTreeSet::from([relay1.clone(), relay2]))
            .unwrap();

        // Verify two relays
        let relays_before = storage.group_relays(&mls_group_id).unwrap();
        assert_eq!(relays_before.len(), 2);

        // Restore snapshot
        storage.restore_snapshot(snapshot);

        // Verify back to one relay
        let relays_after = storage.group_relays(&mls_group_id).unwrap();
        assert_eq!(relays_after.len(), 1);
    }

    #[test]
    fn test_snapshot_with_exporter_secrets_rollback() {
        let storage = MdkMemoryStorage::default();

        // Create a group
        let mls_group_id = GroupId::from_slice(&[25, 26, 27, 28]);
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "Secret Test Group".to_string(),
            description: "A group for testing secret rollback".to_string(),
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

        // Add epoch 0 secret
        let secret_0 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 0,
            secret: Secret::new([1u8; 32]),
        };
        storage
            .save_group_exporter_secret(secret_0.clone())
            .unwrap();

        // Create snapshot
        let snapshot = storage.create_snapshot();

        // Add epoch 1 secret
        let secret_1 = GroupExporterSecret {
            mls_group_id: mls_group_id.clone(),
            epoch: 1,
            secret: Secret::new([2u8; 32]),
        };
        storage
            .save_group_exporter_secret(secret_1.clone())
            .unwrap();

        // Verify epoch 1 secret exists
        let found_1 = storage.get_group_exporter_secret(&mls_group_id, 1).unwrap();
        assert!(found_1.is_some());

        // Restore snapshot
        storage.restore_snapshot(snapshot);

        // Verify epoch 1 secret is gone
        let after_rollback = storage.get_group_exporter_secret(&mls_group_id, 1).unwrap();
        assert!(after_rollback.is_none());

        // Verify epoch 0 secret still exists
        let epoch_0_exists = storage.get_group_exporter_secret(&mls_group_id, 0).unwrap();
        assert!(epoch_0_exists.is_some());
    }

    #[test]
    fn test_snapshot_with_welcomes_rollback() {
        let storage = MdkMemoryStorage::default();

        // Create snapshot before any welcomes
        let snapshot = storage.create_snapshot();

        // Create a welcome
        let event_id = EventId::all_zeros();
        let wrapper_id = EventId::all_zeros();
        let mls_group_id = GroupId::from_slice(&[29, 30, 31, 32]);
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();

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
            group_name: "Welcome Test Group".to_string(),
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
        storage.save_welcome(welcome).unwrap();

        // Verify welcome exists
        let found = storage.find_welcome_by_event_id(&event_id).unwrap();
        assert!(found.is_some());

        // Restore snapshot
        storage.restore_snapshot(snapshot);

        // Verify welcome is gone
        let after_rollback = storage.find_welcome_by_event_id(&event_id).unwrap();
        assert!(after_rollback.is_none());
    }

    #[test]
    fn test_snapshot_multiple_operations_rollback() {
        let storage = MdkMemoryStorage::default();

        // Create initial state with one group
        let mls_group_id_1 = GroupId::from_slice(&[33, 34, 35, 36]);
        let nostr_group_id_1 = generate_random_bytes(32).try_into().unwrap();
        let group1 = Group {
            mls_group_id: mls_group_id_1.clone(),
            nostr_group_id: nostr_group_id_1,
            name: "Group 1".to_string(),
            description: "First group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        storage.save_group(group1).unwrap();

        // Create snapshot
        let snapshot = storage.create_snapshot();

        // Perform multiple operations:
        // 1. Create second group
        let mls_group_id_2 = GroupId::from_slice(&[37, 38, 39, 40]);
        let nostr_group_id_2 = generate_random_bytes(32).try_into().unwrap();
        let group2 = Group {
            mls_group_id: mls_group_id_2.clone(),
            nostr_group_id: nostr_group_id_2,
            name: "Group 2".to_string(),
            description: "Second group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        storage.save_group(group2).unwrap();

        // 2. Add message to first group
        let pubkey =
            PublicKey::from_hex("aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb")
                .unwrap();
        let event_id =
            EventId::from_hex("0000000000000000000000000000000000000000000000000000000000000099")
                .unwrap();
        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::MlsGroupMessage,
            mls_group_id: mls_group_id_1.clone(),
            created_at: Timestamp::now(),
            content: "Test message".to_string(),
            tags: Tags::new(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::MlsGroupMessage,
                Tags::new(),
                "Test message".to_string(),
            ),
            wrapper_event_id: EventId::all_zeros(),
            state: MessageState::Created,
        };
        storage.save_message(message).unwrap();

        // 3. Modify first group
        let modified_group1 = Group {
            mls_group_id: mls_group_id_1.clone(),
            nostr_group_id: nostr_group_id_1,
            name: "Modified Group 1".to_string(),
            description: "First group".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 5,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        storage.save_group(modified_group1).unwrap();

        // Verify all changes
        let groups = storage.all_groups().unwrap();
        assert_eq!(groups.len(), 2);
        let messages = storage.messages(&mls_group_id_1, None).unwrap();
        assert_eq!(messages.len(), 1);
        let g1 = storage
            .find_group_by_mls_group_id(&mls_group_id_1)
            .unwrap()
            .unwrap();
        assert_eq!(g1.name, "Modified Group 1");
        assert_eq!(g1.epoch, 5);

        // Restore snapshot
        storage.restore_snapshot(snapshot);

        // Verify all changes are rolled back
        let groups_after = storage.all_groups().unwrap();
        assert_eq!(groups_after.len(), 1);
        let g2_gone = storage.find_group_by_mls_group_id(&mls_group_id_2).unwrap();
        assert!(g2_gone.is_none());
        let messages_after = storage.messages(&mls_group_id_1, None).unwrap();
        assert_eq!(messages_after.len(), 0);
        let g1_restored = storage
            .find_group_by_mls_group_id(&mls_group_id_1)
            .unwrap()
            .unwrap();
        assert_eq!(g1_restored.name, "Group 1");
        assert_eq!(g1_restored.epoch, 0);
    }

    #[test]
    fn test_snapshot_preserves_snapshot_independence() {
        let storage = MdkMemoryStorage::default();

        // Create a group
        let mls_group_id = GroupId::from_slice(&[41, 42, 43, 44]);
        let nostr_group_id = generate_random_bytes(32).try_into().unwrap();
        let group = Group {
            mls_group_id: mls_group_id.clone(),
            nostr_group_id,
            name: "State A".to_string(),
            description: "Initial state".to_string(),
            admin_pubkeys: BTreeSet::new(),
            last_message_id: None,
            last_message_at: None,
            epoch: 0,
            state: GroupState::Active,
            image_hash: None,
            image_key: None,
            image_nonce: None,
        };
        storage.save_group(group.clone()).unwrap();

        // Take snapshot A
        let snapshot_a = storage.create_snapshot();

        // Modify to state B
        let group_b = Group {
            name: "State B".to_string(),
            epoch: 1,
            ..group.clone()
        };
        storage.save_group(group_b.clone()).unwrap();

        // Take snapshot B
        let snapshot_b = storage.create_snapshot();

        // Modify to state C
        let group_c = Group {
            name: "State C".to_string(),
            epoch: 2,
            ..group.clone()
        };
        storage.save_group(group_c).unwrap();

        // Current state is C
        let current = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(current.name, "State C");

        // Restore to A
        storage.restore_snapshot(snapshot_a.clone());
        let after_a = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_a.name, "State A");

        // Restore to B (from A state)
        storage.restore_snapshot(snapshot_b);
        let after_b = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(after_b.name, "State B");

        // Can still restore to A again
        storage.restore_snapshot(snapshot_a);
        let final_state = storage
            .find_group_by_mls_group_id(&mls_group_id)
            .unwrap()
            .unwrap();
        assert_eq!(final_state.name, "State A");
    }
}
