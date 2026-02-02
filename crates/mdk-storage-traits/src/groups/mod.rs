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

/// Pagination parameters for querying messages
#[derive(Debug, Clone, Copy)]
pub struct Pagination {
    /// Maximum number of messages to return
    pub limit: Option<usize>,
    /// Number of messages to skip
    pub offset: Option<usize>,
}

impl Pagination {
    /// Create a new Pagination with specified limit and offset
    pub fn new(limit: Option<usize>, offset: Option<usize>) -> Self {
        Self { limit, offset }
    }

    /// Get the limit value, using default if not specified
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_MESSAGE_LIMIT)
    }

    /// Get the offset value, using 0 if not specified
    pub fn offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            limit: Some(DEFAULT_MESSAGE_LIMIT),
            offset: Some(0),
        }
    }
}

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

    /// Get messages for a group with optional pagination
    ///
    /// Returns messages ordered by `created_at DESC, id DESC` (newest first).
    ///
    /// The secondary sort key (`id DESC`) ensures deterministic ordering when
    /// multiple messages have the same `created_at` timestamp (which is common
    /// since Nostr timestamps have second precision). This guarantees that:
    /// - The first message in the result matches `group.last_message_id`
    /// - Message order is consistent across multiple calls
    /// - Messages sent within the same second have a stable order
    ///
    /// # Arguments
    /// * `group_id` - The group ID to fetch messages for
    /// * `pagination` - Optional pagination parameters. If `None`, uses default limit and offset.
    ///
    /// # Returns
    ///
    /// Returns a vector of messages ordered by `created_at DESC, id DESC`
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::InvalidParameters`] if:
    /// - `limit` is 0
    /// - `limit` exceeds [`MAX_MESSAGE_LIMIT`]
    /// - Group with the specified ID does not exist
    ///
    /// # Examples
    /// ```ignore
    /// // Get messages with default pagination
    /// let messages = storage.messages(&group_id, None)?;
    ///
    /// // Get first 100 messages
    /// let messages = storage.messages(&group_id, Some(Pagination::new(Some(100), Some(0))))?;
    ///
    /// // Get next 100 messages
    /// let messages = storage.messages(&group_id, Some(Pagination::new(Some(100), Some(100))))?;
    /// ```
    fn messages(
        &self,
        group_id: &GroupId,
        pagination: Option<Pagination>,
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
