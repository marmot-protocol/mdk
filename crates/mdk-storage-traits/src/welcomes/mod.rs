//! Welcomes module
//!
//! This module is responsible for storing and retrieving welcomes
//! It also handles the parsing of welcome content
//!
//! The welcomes are stored in the database and can be retrieved by event ID
//!
//! Here we also define the storage traits that are used to store and retrieve welcomes

use nostr::EventId;

pub mod error;
pub mod types;

use self::error::WelcomeError;
use self::types::*;

/// Default limit for pending welcomes queries to prevent unbounded memory usage
pub const DEFAULT_PENDING_WELCOMES_LIMIT: usize = 1000;

/// Storage traits for the welcomes module
pub trait WelcomeStorage {
    /// Save a welcome
    fn save_welcome(&self, welcome: Welcome) -> Result<(), WelcomeError>;

    /// Find a welcome by event ID
    fn find_welcome_by_event_id(&self, event_id: &EventId)
    -> Result<Option<Welcome>, WelcomeError>;

    /// Get all pending welcomes
    ///
    /// This method uses a default limit to prevent unbounded memory usage.
    /// For custom pagination, use [`pending_welcomes_paginated`](Self::pending_welcomes_paginated).
    fn pending_welcomes(&self) -> Result<Vec<Welcome>, WelcomeError> {
        self.pending_welcomes_paginated(DEFAULT_PENDING_WELCOMES_LIMIT, 0)
    }

    /// Get pending welcomes with pagination
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of welcomes to return
    /// * `offset` - Number of welcomes to skip
    ///
    /// # Returns
    ///
    /// Returns a vector of pending welcomes ordered by ID (descending)
    fn pending_welcomes_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Welcome>, WelcomeError>;

    /// Save a processed welcome
    fn save_processed_welcome(
        &self,
        processed_welcome: ProcessedWelcome,
    ) -> Result<(), WelcomeError>;

    /// Find a processed welcome by event ID
    fn find_processed_welcome_by_event_id(
        &self,
        event_id: &EventId,
    ) -> Result<Option<ProcessedWelcome>, WelcomeError>;
}
