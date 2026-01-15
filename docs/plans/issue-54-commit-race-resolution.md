# Issue #54: Deterministic Commit Race Resolution

## Problem Statement

When multiple valid MLS Commits are published for the same epoch, MDK currently processes them by **arrival order** instead of the **deterministic ordering required by MIP-03**. This can cause permanent group state divergence across clients.

### Current Behavior

1. First commit arrives → immediately processed
2. Second commit arrives → fails with `ProcessMessageWrongEpoch`
3. Second commit is marked as `Failed` and discarded, even if it should have won per MIP-03

### MIP-03 Requirement

> When receiving multiple Commits for the same epoch, clients MUST apply exactly one using this priority:
> 1. **Timestamp priority**: Choose the Commit with the earliest `created_at` timestamp
> 2. **ID tiebreaker**: If timestamps are identical, choose the Commit with the lexicographically smallest `id`
> 3. **Discard others**: Reject all other competing Commits

### Primary Use Case

**App startup/reconnection** is where commit races are most likely (receiving a batch of events). However, races can occur during active sessions. We need a solution that imposes **zero latency penalty** on the common case (no race) while correctly resolving races when they occur.

## Solution Overview

This implementation uses an **Optimistic Apply** strategy with **Rollback Support**:

1. **Optimistic Apply**: Incoming valid commits are applied **immediately**. There is no artificial delay or buffering window.
2. **Epoch Snapshots**: Before applying *any* commit, a snapshot of the group state is saved.
3. **Conflict Detection**: When a commit arrives for an already-processed epoch (or older), we compare it against the applied commit history.
4. **Rollback & Recovery**: If the late arrival is the "true winner" per MIP-03:
   - We rollback the group state to the snapshot *before* the conflict.
   - We apply the new winner.
   - Subsequent commits from the old branch are effectively invalidated (orphaned).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        process_message()                                 │
│                                                                         │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────────┐   │
│  │ Decrypt &   │───▶│ Conflict Check   │───▶│ Apply Immediately     │   │
│  │ Validate    │    │ (MIP-03 rules)   │    │ (Create Snapshot)     │   │
│  └─────────────┘    └────────┬─────────┘    └───────────────────────┘   │
│                              │                                          │
│                              │ Conflict Detected                        │
│                              │ (New > Old)                              │
│                              ▼                                          │
│                     ┌──────────────────┐                                │
│                     │ Rollback Manager │                                │
│                     │ 1. Restore Snap  │                                │
│                     │ 2. Apply Winner  │                                │
│                     └──────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Configuration Extension

**File**: `mdk-core/src/lib.rs`

```rust
pub struct MdkConfig {
    // ... existing fields ...
    
    /// Number of epoch snapshots to retain for rollback support.
    /// Enables recovery when a better commit arrives late.
    /// Default: 5
    pub epoch_snapshot_retention: usize,
}
```

### 2. Epoch Snapshot Manager

**File**: `mdk-core/src/epoch_snapshots.rs` (new)

Manages storage snapshots for rollback support. Thread safety managed internally.

```rust
pub struct EpochSnapshot {
    pub group_id: GroupId,
    pub epoch: u64, // The epoch *before* the commit was applied
    pub applied_commit_id: EventId, // The ID of the commit that created the *next* epoch
    pub applied_commit_ts: u64,
    pub created_at: Instant,
    pub snapshot_name: String,
}

pub struct EpochSnapshotManager {
    inner: Mutex<EpochSnapshotManagerInner>,
    retention_count: usize,
}

impl EpochSnapshotManager {
    /// Create a snapshot before applying a commit
    pub fn create_snapshot<S: MdkStorageProvider>(
        &self, 
        storage: &S, 
        group_id: &GroupId, 
        current_epoch: u64,
        commit_being_applied: &Event
    ) -> Result<String>;
    
    /// Find a better winner for a specific epoch if one exists in history
    /// Returns true if the candidate is better than what we already applied
    pub fn is_better_candidate(
        &self,
        group_id: &GroupId,
        candidate_epoch: u64,
        candidate_ts: u64,
        candidate_id: &EventId
    ) -> bool;
    
    /// Rollback to the state just before the target epoch
    pub fn rollback_to_epoch<S: MdkStorageProvider>(
        &self, 
        storage: &S, 
        group_id: &GroupId, 
        target_epoch: u64
    ) -> Result<()>;
    
    /// Prune old snapshots
    pub fn prune_snapshots<S: MdkStorageProvider>(
        &self,
        storage: &S,
        group_id: &GroupId
    ) -> Result<()>;
}
```

### 3. Storage Trait Extensions

**File**: `mdk-storage-traits/src/lib.rs`

Add unified snapshot/rollback API to the storage trait.

```rust
pub trait MdkStorageProvider: GroupStorage + MessageStorage + WelcomeStorage + StorageProvider<CURRENT_VERSION> {
    fn backend(&self) -> Backend;
    
    /// Create a named snapshot/savepoint
    fn create_named_snapshot(&self, name: &str) -> Result<(), MdkStorageError>;
    
    /// Rollback to a previously created snapshot
    fn rollback_to_snapshot(&self, name: &str) -> Result<(), MdkStorageError>;
    
    /// Release/commit a snapshot (no longer needed)
    fn release_snapshot(&self, name: &str) -> Result<(), MdkStorageError>;
}
```

### 4. Storage Implementations

**SQLite (`mdk-sqlite-storage`)**:
- Wraps existing `SAVEPOINT` / `ROLLBACK TO` / `RELEASE` commands.

**Memory (`mdk-memory-storage`)**:
- **Critical Update**: Must use `Arc<RwLock<...>>` or `Arc<Mutex<...>>` around internal state to ensure `create_snapshot` and `restore_snapshot` are atomic.
- Previously "Not thread-safe", this requirement is now upgraded to ensure test stability.

### 5. Modified Commit Processing Flow

**File**: `mdk-core/src/messages.rs`

#### Standard Flow (Optimistic)

```
Commit Received (Epoch N)
    ↓
Validate & Decrypt
    ↓
Snapshot Current State (Epoch N-1)
    ↓
Apply Commit
    ↓
Prune Old Snapshots (> 5 epochs)
```

#### Race Condition Flow (Rollback)

```
Late Commit Received (Epoch N)
    ↓
Check History: Did we already apply a commit for Epoch N?
    │
    ├─ No: Proceed to Standard Flow
    │
    └─ Yes: Compare via MIP-03
        │
        ├─ Late Commit is Worse: Reject (Ignore)
        │
        └─ Late Commit is Better:
             ↓
             Rollback to Snapshot (Epoch N-1)
             ↓
             Apply Late Commit (New Epoch N)
             ↓
             Notify App (Rollback occurred)
             ↓
             Note: Commits for N+1, N+2... are now invalid/orphaned
```

### 6. Callback System

**File**: `mdk-core/src/callback.rs`

Callers need to know when the world changes beneath them.

```rust
pub trait MdkCallback: Send + Sync + Debug {
    /// Notifies that a rollback occurred due to race resolution.
    /// The app should discard any state derived from epochs >= `target_epoch`.
    fn on_rollback(&self, group_id: &GroupId, target_epoch: u64, new_head_event: &EventId);
}
```

## Configuration Defaults

| Setting | Default | Description |
|---------|---------|-------------|
| `epoch_snapshot_retention` | 5 | Number of historical epochs to retain for potential rollback |

## Implementation Tasks

### Phase 1: Storage Layer
1. **Thread-Safe Memory Storage**: Refactor `mdk-memory-storage` to use internal locking for atomic snapshots.
2. **Storage Traits**: Add snapshot methods to `MdkStorageProvider`.
3. **SQLite Impl**: Implement snapshot methods.

### Phase 2: Snapshot Manager
4. **Implement `EpochSnapshotManager`**: Logic to track `(epoch -> applied_commit_info)` and manage snapshot lifecycles.
5. **Config**: Add `epoch_snapshot_retention`.

### Phase 3: Core Logic
6. **Integration**: Modify `process_message` to:
   - Check for conflicts before processing.
   - Create snapshots before applying.
   - Trigger rollback if a better candidate is found.
7. **Callback**: Add callback hook for rollbacks.

### Phase 4: Testing
8. **Race Tests**:
   - `test_commit_race_simple`: Apply A, then better B. Verify B is final state.
   - `test_commit_race_worse_late`: Apply A, then worse B. Verify A remains.
   - `test_commit_race_chain`: Apply A -> B -> C. Better A' arrives. Verify rollback to start and apply A'.

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Storage overhead (snapshots) | Limited retention (5 epochs). SQLite savepoints are efficient (COW). Memory storage is for testing/small scale. |
| "Time Travel" confusion | Clear callbacks to the application. Docs explaining that "future" commits are invalidated upon rollback. |
| Performance | Optimistic apply means 0 penalty for normal traffic. Snapshot creation cost is low (transaction start). |
