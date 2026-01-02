//! Groups module
//!
//! This module is responsible for storing and retrieving groups
//! It also handles the parsing of group content
//!
//! The groups are stored in the database and can be retrieved by MLS group ID or Nostr group ID
//!
//! Here we also define the storage traits that are used to store and retrieve groups

use std::collections::BTreeSet;

use crate::GroupId;
use nostr::{PublicKey, RelayUrl};

pub mod error;
pub mod types;

use self::error::GroupError;
use self::types::*;
use crate::messages::types::Message;

/// Default limit for messages queries to prevent unbounded memory usage
pub const DEFAULT_MESSAGE_LIMIT: usize = 1000;

/// Maximum allowed limit for messages queries to prevent resource exhaustion
pub const MAX_MESSAGE_LIMIT: usize = 10000;

/// Maximum allowed offset for messages queries to prevent unreasonable values
pub const MAX_MESSAGE_OFFSET: usize = 1_000_000;

/// Storage traits for the groups module
pub trait GroupStorage {
    /// Get all groups
    fn all_groups(&self) -> Result<Vec<Group>, GroupError>;

    /// Find a group by MLS group ID
    fn find_group_by_mls_group_id(&self, group_id: &GroupId) -> Result<Option<Group>, GroupError>;

    /// Find a group by Nostr group ID
    fn find_group_by_nostr_group_id(
        &self,
        nostr_group_id: &[u8; 32],
    ) -> Result<Option<Group>, GroupError>;

    /// Save a group
    fn save_group(&self, group: Group) -> Result<(), GroupError>;

    /// Get all messages for a group
    ///
    /// **Warning**: This method loads all messages into memory and may cause
    /// memory exhaustion for groups with many messages. Consider using
    /// `messages_paginated()` for better performance and memory safety.
    fn messages(&self, group_id: &GroupId) -> Result<Vec<Message>, GroupError>;

    /// Get messages for a group with pagination
    ///
    /// Returns messages ordered by `created_at DESC` (newest first).
    ///
    /// # Arguments
    /// * `group_id` - The group ID to fetch messages for
    /// * `limit` - Maximum number of messages to return. Must be between 1 and [`MAX_MESSAGE_LIMIT`].
    ///   Values exceeding the maximum will return an error.
    /// * `offset` - Number of messages to skip (for pagination)
    ///
    /// # Returns
    ///
    /// Returns a vector of messages ordered by created_at (descending)
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::InvalidParameters`] if:
    /// - `limit` is 0
    /// - `limit` exceeds [`MAX_MESSAGE_LIMIT`]
    /// - `offset` exceeds [`MAX_MESSAGE_OFFSET`]
    /// - Group with the specified ID does not exist
    ///
    /// # Recommended Usage
    ///
    /// For most use cases, use the default limit via [`messages`](Self::messages).
    /// Only use custom limits when you have specific pagination requirements.
    ///
    /// # Example
    /// ```ignore
    /// // Get first 100 messages
    /// let page1 = storage.messages_paginated(&group_id, 100, 0)?;
    ///
    /// // Get next 100 messages
    /// let page2 = storage.messages_paginated(&group_id, 100, 100)?;
    /// ```
    fn messages_paginated(
        &self,
        group_id: &GroupId,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Message>, GroupError>;

    /// Get all admins for a group
    fn admins(&self, group_id: &GroupId) -> Result<BTreeSet<PublicKey>, GroupError>;

    /// Get all relays for a group
    fn group_relays(&self, group_id: &GroupId) -> Result<BTreeSet<GroupRelay>, GroupError>;

    /// Replace all relays for a group with the provided set
    /// This operation is atomic - either all relays are replaced or none are changed
    fn replace_group_relays(
        &self,
        group_id: &GroupId,
        relays: BTreeSet<RelayUrl>,
    ) -> Result<(), GroupError>;

    /// Get an exporter secret for a group and epoch
    fn get_group_exporter_secret(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<Option<GroupExporterSecret>, GroupError>;

    /// Save an exporter secret for a group and epoch
    fn save_group_exporter_secret(
        &self,
        group_exporter_secret: GroupExporterSecret,
    ) -> Result<(), GroupError>;
}
