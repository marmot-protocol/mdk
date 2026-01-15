//! Callback interface for MDK events.
//!
//! This module provides the [`MdkCallback`] trait that applications can implement
//! to receive notifications about important MDK events, such as rollbacks due to
//! commit race resolution.

use std::fmt::Debug;

use mdk_storage_traits::GroupId;
use nostr::EventId;

/// Callback interface for MDK events.
pub trait MdkCallback: Send + Sync + Debug {
    /// Notifies that a rollback occurred due to race resolution.
    ///
    /// This happens when a commit with an earlier timestamp or smaller ID arrives
    /// after we have already applied a commit for the same epoch. MDK rolls back
    /// to the previous state and applies the winner.
    ///
    /// The application should invalidate any state derived from epochs >= `target_epoch`.
    fn on_rollback(&self, group_id: &GroupId, target_epoch: u64, new_head_event: &EventId);
}
