//! Epoch snapshot management for commit race resolution.
//!
//! This module provides the [`EpochSnapshotManager`] which tracks storage snapshots
//! taken before applying commits. When a "better" commit arrives late (per MIP-03
//! ordering rules), the manager can rollback to a previous snapshot and apply the
//! correct winner.
//!
//! See the MIP-03 specification for details on commit ordering:
//! 1. Earliest timestamp wins
//! 2. Lexicographically smallest event ID breaks ties

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use mdk_storage_traits::{GroupId, MdkStorageError, MdkStorageProvider};
use nostr::EventId;

use crate::Error;

/// Metadata about a snapshot taken before applying a commit
#[derive(Debug, Clone)]
pub struct EpochSnapshot {
    /// The group ID
    pub group_id: GroupId,
    /// The epoch *before* the commit was applied (the state captured in the snapshot)
    pub epoch: u64,
    /// The ID of the commit that was applied *after* this snapshot was taken.
    /// This is the "incumbent" winner that we might want to replace.
    pub applied_commit_id: EventId,
    /// The timestamp of the applied commit (for MIP-03 comparison)
    pub applied_commit_ts: u64,
    /// When the snapshot was created
    pub created_at: Instant,
    /// The unique name of the snapshot in storage
    pub snapshot_name: String,
}

#[derive(Debug)]
struct EpochSnapshotManagerInner {
    /// Snapshots per group, ordered by epoch (oldest first)
    snapshots: HashMap<GroupId, VecDeque<EpochSnapshot>>,
}

/// Manages epoch snapshots for rollback support
#[derive(Debug)]
pub struct EpochSnapshotManager {
    inner: Mutex<EpochSnapshotManagerInner>,
    retention_count: usize,
}

impl EpochSnapshotManager {
    /// Create a new snapshot manager
    pub fn new(retention_count: usize) -> Self {
        Self {
            inner: Mutex::new(EpochSnapshotManagerInner {
                snapshots: HashMap::new(),
            }),
            retention_count,
        }
    }

    /// Create a snapshot before applying a commit
    pub fn create_snapshot<S: MdkStorageProvider>(
        &self,
        storage: &S,
        group_id: &GroupId,
        current_epoch: u64,
        commit_id: &EventId,
        commit_ts: u64,
    ) -> Result<String, Error> {
        // Generate a unique snapshot name
        let snapshot_name = format!(
            "snap_{}_{}_{}",
            hex::encode(group_id.as_slice()),
            current_epoch,
            commit_id.to_hex()
        );

        // Create the snapshot in storage
        storage
            .create_named_snapshot(&snapshot_name)
            .map_err(Error::Storage)?;

        // Record metadata
        let snapshot = EpochSnapshot {
            group_id: group_id.clone(),
            epoch: current_epoch,
            applied_commit_id: *commit_id,
            applied_commit_ts: commit_ts,
            created_at: Instant::now(),
            snapshot_name: snapshot_name.clone(),
        };

        let mut inner = self.inner.lock().unwrap();
        let queue = inner.snapshots.entry(group_id.clone()).or_default();
        queue.push_back(snapshot);

        // Prune if needed (deferred slightly, or do it now)
        // We prune strictly greater than retention count.
        // If retention is 5, we keep 5 snapshots.
        while queue.len() > self.retention_count {
            if let Some(old_snap) = queue.pop_front() {
                // Best effort release
                let _ = storage.release_snapshot(&old_snap.snapshot_name);
            }
        }

        Ok(snapshot_name)
    }

    /// Check if a candidate commit is "better" than the one we applied for this epoch.
    /// Returns true if we should rollback.
    pub fn is_better_candidate(
        &self,
        group_id: &GroupId,
        candidate_epoch: u64,
        candidate_ts: u64,
        candidate_id: &EventId,
    ) -> bool {
        let inner = self.inner.lock().unwrap();

        if let Some(queue) = inner.snapshots.get(group_id)
            && let Some(snapshot) = queue.iter().find(|s| s.epoch == candidate_epoch)
        {
            // Compare according to MIP-03
            // 1. Earliest timestamp wins
            if candidate_ts < snapshot.applied_commit_ts {
                return true;
            }
            if candidate_ts > snapshot.applied_commit_ts {
                return false;
            }

            // 2. ID tiebreaker (lexicographically smallest ID wins)
            // If candidate ID is smaller than applied ID, candidate wins
            if candidate_id.to_hex() < snapshot.applied_commit_id.to_hex() {
                return true;
            }
        }

        false
    }

    /// Rollback to the snapshot for the given epoch.
    /// This restores the state to `target_epoch`.
    pub fn rollback_to_epoch<S: MdkStorageProvider>(
        &self,
        storage: &S,
        group_id: &GroupId,
        target_epoch: u64,
    ) -> Result<(), Error> {
        let mut inner = self.inner.lock().unwrap();

        if let Some(queue) = inner.snapshots.get_mut(group_id) {
            // Find the snapshot
            if let Some(index) = queue.iter().position(|s| s.epoch == target_epoch) {
                let snapshot = &queue[index];

                // Perform rollback
                storage
                    .rollback_to_snapshot(&snapshot.snapshot_name)
                    .map_err(Error::Storage)?;

                // Remove and release all snapshots from index onwards (including the used one)
                let removed = queue.split_off(index);
                for snap in removed {
                    let _ = storage.release_snapshot(&snap.snapshot_name);
                }

                return Ok(());
            }
        }

        Err(Error::Storage(MdkStorageError::NotFound(
            "No snapshot found for target epoch".to_string(),
        )))
    }
}
