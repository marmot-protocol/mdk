# Epoch-Aware Message System and Snapshot Consistency

## Problem Statement

PR #152 introduces MIP-03 commit race resolution with snapshot/rollback, but has two critical issues:

1. **Messages lack epoch tracking** - Can't identify which messages belong to which epoch
2. **SQLite/Memory snapshot inconsistency** - Memory includes messages in snapshots, SQLite doesn't
3. **No message cleanup on rollback** - Messages from invalidated epochs persist and may be undecryptable

## Design Decisions

### 1. Add Epoch Field

Add `epoch: Option<u64>` to both `Message` and `ProcessedMessage` structs:
- `Option` for backward compatibility (existing rows get NULL)
- Captures the epoch when the message was decrypted/processed

### 2. New State: `EpochInvalidated` (Both Message and ProcessedMessage)

Add `EpochInvalidated` to **both** `MessageState` and `ProcessedMessageState`:

```rust
pub enum MessageState {
    Created,
    Processed,
    Deleted,
    EpochInvalidated,  // NEW: epoch was rolled back, content may be invalid
}

pub enum ProcessedMessageState {
    Created,
    Processed,
    ProcessedCommit,
    Failed,
    EpochInvalidated,  // NEW: epoch was rolled back, needs reprocessing
}
```

This maintains consistency - when a rollback happens, both the message record and its processing record get the same invalidated state. Applications can then decide whether to display invalidated content with uncertainty indicators or hide it entirely.

### 3. SQLite Snapshot Consistency

Add `messages` and `processed_messages` tables to SQLite snapshots to match memory storage behavior.

### 4. Rollback Message Handling

On rollback to `target_epoch`, mark records as `EpochInvalidated` (don't delete):

| Data | Condition | Action |
|------|-----------|--------|
| Messages | epoch > target_epoch | Mark state = `EpochInvalidated` |
| Messages | epoch <= target_epoch or NULL | KEEP unchanged |
| ProcessedMessage | epoch > target_epoch | Mark state = `EpochInvalidated` |
| ProcessedMessage | epoch <= target_epoch or NULL | KEEP unchanged |

**Rationale**: Keep all records so applications can:
- Show messages with uncertainty indicators ("this message may have changed")
- Allow users to see conversation history even during state transitions
- Re-fetch and reprocess when the correct epoch state is restored

### 5. Enhanced Callback

```rust
pub struct RollbackInfo {
    pub group_id: GroupId,
    pub target_epoch: u64,
    pub new_head_event: EventId,
    pub invalidated_messages: Vec<EventId>,      // Messages marked EpochInvalidated
    pub messages_needing_refetch: Vec<EventId>,  // ProcessedMessages needing refetch
}

pub trait MdkCallback: Send + Sync + Debug {
    fn on_rollback(&self, info: &RollbackInfo);
}
```

### 6. Group-Scope ProcessedMessages

Add `mls_group_id` column to `processed_messages` table to enable group-scoped epoch queries during rollback.

---

## Implementation Plan

### Phase 1: Storage Types (mdk-storage-traits)

**File: `crates/mdk-storage-traits/src/messages/types.rs`**

1. Add `epoch: Option<u64>` to `Message` struct (after `wrapper_event_id`)
2. Add `epoch: Option<u64>` to `ProcessedMessage` struct (after `processed_at`)
3. Add `mls_group_id: Option<GroupId>` to `ProcessedMessage` struct
4. Add `EpochInvalidated` variant to `ProcessedMessageState`
5. Update `as_str()`, `FromStr`, serialization for new state

**File: `crates/mdk-storage-traits/src/messages/mod.rs`**

Add new trait methods:
```rust
/// Mark messages with epoch > target as EpochInvalidated
/// Returns EventIds of invalidated messages
fn invalidate_messages_after_epoch(&self, group_id: &GroupId, epoch: u64)
    -> Result<Vec<EventId>, MessageError>;

/// Mark processed_messages with epoch > target as EpochInvalidated
/// Returns wrapper EventIds of invalidated records
fn invalidate_processed_messages_after_epoch(&self, group_id: &GroupId, epoch: u64)
    -> Result<Vec<EventId>, MessageError>;

/// Find messages in EpochInvalidated state (for UI filtering or reprocessing)
fn find_invalidated_messages(&self, group_id: &GroupId)
    -> Result<Vec<Message>, MessageError>;

/// Find processed_messages in EpochInvalidated state
fn find_invalidated_processed_messages(&self, group_id: &GroupId)
    -> Result<Vec<ProcessedMessage>, MessageError>;
```

### Phase 2: Database Migration (mdk-sqlite-storage)

**New file: `crates/mdk-sqlite-storage/migrations/V002__epoch_awareness.sql`**

```sql
-- Add epoch to messages
ALTER TABLE messages ADD COLUMN epoch INTEGER;

-- Add epoch and group_id to processed_messages
ALTER TABLE processed_messages ADD COLUMN epoch INTEGER;
ALTER TABLE processed_messages ADD COLUMN mls_group_id BLOB;

-- Indexes for rollback queries
CREATE INDEX idx_messages_epoch ON messages(mls_group_id, epoch);
CREATE INDEX idx_processed_messages_epoch ON processed_messages(mls_group_id, epoch);
```

### Phase 3: SQLite Storage Implementation

**File: `crates/mdk-sqlite-storage/src/messages.rs`**

1. Update `save_message()` to include epoch column
2. Update `save_processed_message()` to include epoch and mls_group_id
3. Update row-to-struct conversions to read epoch
4. Implement new trait methods:
   - `invalidate_messages_after_epoch()` - UPDATE state = 'epoch_invalidated' WHERE epoch > target
   - `invalidate_processed_messages_after_epoch()` - same pattern
   - `find_invalidated_messages()` - SELECT WHERE state = 'epoch_invalidated'
   - `find_invalidated_processed_messages()` - same pattern

**File: `crates/mdk-sqlite-storage/src/lib.rs`**

In `snapshot_group_state()` (around line 745), add:
- Section 8: Snapshot `messages` table for this group
- Section 9: Snapshot `processed_messages` table for this group

In `restore_group_from_snapshot()` (around line 815), add:
- Delete current messages/processed_messages for group before restore
- Restore from snapshot table

### Phase 4: Memory Storage Implementation

**File: `crates/mdk-memory-storage/src/messages.rs`**

Implement the three new `MessageStorage` trait methods.

### Phase 5: Callback Enhancement (mdk-core)

**File: `crates/mdk-core/src/callback.rs`**

1. Add `RollbackInfo` struct
2. Update `MdkCallback::on_rollback` to take `&RollbackInfo`

### Phase 6: Core Message Processing (mdk-core)

**File: `crates/mdk-core/src/messages.rs`**

1. **Capture epoch when saving messages** (~line 260):
   ```rust
   let message = Message {
       epoch: Some(mls_group.epoch().as_u64()),
       // ... existing fields
   };
   ```

2. **Capture epoch when saving processed_messages**:
   ```rust
   let processed = ProcessedMessage {
       epoch: Some(group.epoch),
       mls_group_id: Some(group.mls_group_id.clone()),
       // ... existing fields
   };
   ```

3. **Update rollback handler** (~line 1622-1642):
   ```rust
   // After successful rollback_to_epoch()
   let invalidated_msgs = storage.invalidate_messages_after_epoch(&group_id, msg_epoch)?;
   let invalidated_processed = storage.invalidate_processed_messages_after_epoch(&group_id, msg_epoch)?;

   if let Some(cb) = &self.callback {
       cb.on_rollback(&RollbackInfo {
           group_id: group_id.clone(),
           target_epoch: msg_epoch,
           new_head_event: event.id,
           invalidated_messages: invalidated_msgs,
           messages_needing_refetch: invalidated_processed,
       });
   }
   ```

4. **Allow reprocessing of EpochInvalidated** (~line 1941-1956):
   ```rust
   if processed.state == ProcessedMessageState::Failed {
       return Err(...); // Keep existing rejection
   }
   // EpochInvalidated and other states continue processing
   ```

---

## Testing Strategy

### Unit Tests
- Epoch field serialization/deserialization for Message and ProcessedMessage
- EpochInvalidated state for both MessageState and ProcessedMessageState
- Migration with NULL epochs (backward compatibility)

### Integration Tests
- **Rollback with messages**: verify both Message and ProcessedMessage marked EpochInvalidated
- **Reprocessing after rollback**: verify EpochInvalidated messages can be reprocessed
- **Snapshot consistency**: verify SQLite and Memory storage behave identically
- **Callback info**: verify RollbackInfo contains correct invalidated message lists

### Update Existing Tests
- Tests creating Message/ProcessedMessage need epoch field
- Callback tests need RollbackInfo handling
- Commit race tests should verify message invalidation

---

## Verification

1. Run `cargo test -p mdk-storage-traits`
2. Run `cargo test -p mdk-sqlite-storage`
3. Run `cargo test -p mdk-memory-storage`
4. Run `cargo test -p mdk-core`
5. Run full test suite: `cargo test --workspace`
6. Verify commit race tests pass with message cleanup
