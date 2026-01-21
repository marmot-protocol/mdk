# Plan: Storage Adapter Consistency Fixes

**Created:** 2025-01-21
**Branch:** issue-54-commit-race-resolution
**Status:** Ready for implementation

## Overview

During code review of the commit race resolution implementation, several inconsistencies were discovered between the memory storage adapter and the SQLite storage adapter. The SQLite adapter is the source of truth for production behavior; the memory adapter exists for testing and should mimic SQLite's behavior exactly.

---

## Issue 1: Memory Storage Rollback Affects All Groups (CRITICAL)

### Problem

The memory storage's `create_group_snapshot` takes a **full snapshot of ALL data** but the `rollback_group_to_snapshot` restores **ALL data**, not just the target group's data.

**Location:** `crates/mdk-memory-storage/src/lib.rs:570-593`

```rust
fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> Result<(), MdkStorageError> {
    // For simplicity in memory storage, we take a full snapshot.
    // This is acceptable since memory storage is primarily for testing.
    let snapshot = self.create_snapshot();  // <-- Takes FULL snapshot
    self.group_snapshots
        .write()
        .insert((group_id.clone(), name.to_string()), snapshot);
    Ok(())
}

fn rollback_group_to_snapshot(
    &self,
    group_id: &GroupId,
    name: &str,
) -> Result<(), MdkStorageError> {
    let key = (group_id.clone(), name.to_string());
    let snapshot = self
        .group_snapshots
        .write()
        .remove(&key)
        .ok_or_else(|| MdkStorageError::NotFound("Snapshot not found".to_string()))?;
    self.restore_snapshot(snapshot);  // <-- Restores ALL data
    Ok(())
}
```

### Impact

If you have Groups A and B:
1. Create snapshot for Group A at epoch 5
2. Both groups continue processing (Group A → epoch 6, Group B processes messages)
3. Better commit arrives for Group A's epoch 5
4. Rollback to Group A's snapshot
5. **BUG:** Group B's state ALSO gets rolled back to what it was at step 1

### How SQLite Does It

SQLite correctly implements group-scoped snapshots:
- `snapshot_group_state()` only copies rows WHERE `group_id = ?`
- `restore_group_from_snapshot()` only deletes/restores rows for that specific group
- Other groups are completely unaffected

Reference: `crates/mdk-sqlite-storage/src/lib.rs:474-981`

### Fix

Create a new group-scoped snapshot structure and modify the snapshot/restore methods:

1. **Create `GroupScopedSnapshot` struct** that only contains data for one group:

```rust
pub struct GroupScopedSnapshot {
    group_id: GroupId,
    // MLS data (filtered by group_id)
    mls_group_data: HashMap<(Vec<u8>, GroupDataType), Vec<u8>>,
    mls_own_leaf_nodes: Vec<Vec<u8>>,  // Just for this group
    mls_proposals: HashMap<Vec<u8>, Vec<u8>>,  // proposal_ref -> proposal
    mls_epoch_key_pairs: HashMap<(Vec<u8>, u32), Vec<u8>>,  // (epoch_id, leaf_index) -> key_pairs
    // MDK data
    group: Option<Group>,
    group_relays: BTreeSet<GroupRelay>,
    group_exporter_secrets: HashMap<u64, GroupExporterSecret>,  // epoch -> secret
}
```

2. **Implement `create_group_scoped_snapshot()`**:

```rust
fn create_group_scoped_snapshot(&self, group_id: &GroupId) -> GroupScopedSnapshot {
    let inner = self.inner.read();
    let group_id_bytes = group_id.as_slice().to_vec();

    GroupScopedSnapshot {
        group_id: group_id.clone(),
        // Filter MLS data by group_id
        mls_group_data: inner.mls_group_data.data
            .iter()
            .filter(|((gid, _), _)| gid == &group_id_bytes)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        mls_own_leaf_nodes: inner.mls_own_leaf_nodes.data
            .get(&group_id_bytes)
            .cloned()
            .unwrap_or_default(),
        mls_proposals: inner.mls_proposals.data
            .iter()
            .filter(|((gid, _), _)| gid == &group_id_bytes)
            .map(|((_, prop_ref), prop)| (prop_ref.clone(), prop.clone()))
            .collect(),
        mls_epoch_key_pairs: inner.mls_epoch_key_pairs.data
            .iter()
            .filter(|((gid, _, _), _)| gid == &group_id_bytes)
            .map(|((_, epoch_id, leaf_idx), kp)| ((epoch_id.clone(), *leaf_idx), kp.clone()))
            .collect(),
        // MDK data
        group: inner.groups_cache.peek(group_id).cloned(),
        group_relays: inner.group_relays_cache.peek(group_id).cloned().unwrap_or_default(),
        group_exporter_secrets: inner.group_exporter_secrets_cache
            .iter()
            .filter(|((gid, _), _)| gid == group_id)
            .map(|((_, epoch), secret)| (*epoch, secret.clone()))
            .collect(),
    }
}
```

3. **Implement `restore_group_scoped_snapshot()`**:

```rust
fn restore_group_scoped_snapshot(&self, snapshot: GroupScopedSnapshot) {
    let mut inner = self.inner.write();
    let group_id = &snapshot.group_id;
    let group_id_bytes = group_id.as_slice().to_vec();

    // 1. Remove existing data for this group
    inner.mls_group_data.data.retain(|(gid, _), _| gid != &group_id_bytes);
    inner.mls_own_leaf_nodes.data.remove(&group_id_bytes);
    inner.mls_proposals.data.retain(|(gid, _), _| gid != &group_id_bytes);
    inner.mls_epoch_key_pairs.data.retain(|(gid, _, _), _| gid != &group_id_bytes);

    // Remove from MDK caches
    inner.groups_cache.pop(group_id);
    inner.groups_by_nostr_id_cache... // Need to handle this too
    inner.group_relays_cache.pop(group_id);
    // Remove all exporter secrets for this group
    let keys_to_remove: Vec<_> = inner.group_exporter_secrets_cache
        .iter()
        .filter(|((gid, _), _)| gid == group_id)
        .map(|(k, _)| k.clone())
        .collect();
    for key in keys_to_remove {
        inner.group_exporter_secrets_cache.pop(&key);
    }

    // 2. Restore from snapshot
    for (key, value) in snapshot.mls_group_data {
        inner.mls_group_data.data.insert(key, value);
    }
    if !snapshot.mls_own_leaf_nodes.is_empty() {
        inner.mls_own_leaf_nodes.data.insert(group_id_bytes.clone(), snapshot.mls_own_leaf_nodes);
    }
    for (prop_ref, prop) in snapshot.mls_proposals {
        inner.mls_proposals.data.insert((group_id_bytes.clone(), prop_ref), prop);
    }
    for ((epoch_id, leaf_idx), kp) in snapshot.mls_epoch_key_pairs {
        inner.mls_epoch_key_pairs.data.insert((group_id_bytes.clone(), epoch_id, leaf_idx), kp);
    }

    if let Some(group) = snapshot.group {
        let nostr_id = group.nostr_group_id;
        inner.groups_cache.put(group_id.clone(), group.clone());
        inner.groups_by_nostr_id_cache.put(nostr_id, group);
    }
    if !snapshot.group_relays.is_empty() {
        inner.group_relays_cache.put(group_id.clone(), snapshot.group_relays);
    }
    for (epoch, secret) in snapshot.group_exporter_secrets {
        inner.group_exporter_secrets_cache.put((group_id.clone(), epoch), secret);
    }
}
```

4. **Update the `MdkStorageProvider` impl**:

```rust
fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> Result<(), MdkStorageError> {
    let snapshot = self.create_group_scoped_snapshot(group_id);
    self.group_snapshots
        .write()
        .insert((group_id.clone(), name.to_string()), snapshot);
    Ok(())
}

fn rollback_group_to_snapshot(
    &self,
    group_id: &GroupId,
    name: &str,
) -> Result<(), MdkStorageError> {
    let key = (group_id.clone(), name.to_string());
    let snapshot = self
        .group_snapshots
        .write()
        .remove(&key)
        .ok_or_else(|| MdkStorageError::NotFound("Snapshot not found".to_string()))?;
    self.restore_group_scoped_snapshot(snapshot);
    Ok(())
}
```

5. **Change the type of `group_snapshots`**:

```rust
// Before:
group_snapshots: RwLock<HashMap<(GroupId, String), MemoryStorageSnapshot>>,

// After:
group_snapshots: RwLock<HashMap<(GroupId, String), GroupScopedSnapshot>>,
```

6. **Add the isolation test** (copy from SQLite):

```rust
#[test]
fn test_snapshot_isolation_between_groups() {
    let storage = MdkMemoryStorage::new();

    // Create two groups
    let group1 = create_test_group(GroupId::from_slice(&[1; 32]));
    let group2 = create_test_group(GroupId::from_slice(&[2; 32]));
    let group1_id = group1.mls_group_id.clone();
    let group2_id = group2.mls_group_id.clone();

    storage.save_group(group1).unwrap();
    storage.save_group(group2).unwrap();

    // Snapshot group1
    storage.create_group_snapshot(&group1_id, "snap_group1").unwrap();

    // Modify both groups
    let mut mod1 = storage.find_group_by_mls_group_id(&group1_id).unwrap().unwrap();
    let mut mod2 = storage.find_group_by_mls_group_id(&group2_id).unwrap().unwrap();
    mod1.name = "Modified Group 1".to_string();
    mod2.name = "Modified Group 2".to_string();
    storage.save_group(mod1).unwrap();
    storage.save_group(mod2).unwrap();

    // Rollback group1 only
    storage.rollback_group_to_snapshot(&group1_id, "snap_group1").unwrap();

    // Group1 should be rolled back
    let final1 = storage.find_group_by_mls_group_id(&group1_id).unwrap().unwrap();
    assert_eq!(final1.name, "Test Group"); // Original name

    // Group2 should still have modifications
    let final2 = storage.find_group_by_mls_group_id(&group2_id).unwrap().unwrap();
    assert_eq!(final2.name, "Modified Group 2");
}
```

---

## Issue 2: Rollback to Nonexistent Snapshot Behavior Differs

### Problem

| SQLite | Memory |
|--------|--------|
| Succeeds but **deletes** group data (nothing to restore) | Returns `NotFound` error |

### How SQLite Does It

```rust
// SQLite deletes current data, then tries to restore from snapshot
// If snapshot doesn't exist, data is just deleted
conn.execute("DELETE FROM groups WHERE mls_group_id = ?", [group_id_bytes])?;
// ... restore from snapshot (which finds nothing)
```

### Fix

Two options:

**Option A (Recommended):** Make SQLite match memory storage behavior - return an error if snapshot doesn't exist:

```rust
// In SQLite restore_group_from_snapshot, add check at start:
let snapshot_exists: bool = conn.query_row(
    "SELECT EXISTS(SELECT 1 FROM group_state_snapshots WHERE snapshot_name = ? AND group_id = ?)",
    params![name, group_id_bytes],
    |row| row.get(0),
)?;
if !snapshot_exists {
    return Err(Error::Database("Snapshot not found".to_string()));
}
// Then proceed with delete + restore
```

**Option B:** Make memory storage match SQLite - delete data if snapshot doesn't exist (NOT recommended - this is dangerous behavior).

We should ABSOLUTELY do **Option A** because silently deleting data when a snapshot doesn't exist is a dangerous side effect that could cause data loss if the caller makes a typo in the snapshot name.

---

## Issue 3: Snapshot Contents Differ (Messages/Welcomes)

### Problem

**SQLite snapshots these tables:**
- `openmls_group_data`, `openmls_proposals`, `openmls_own_leaf_nodes`, `openmls_epoch_key_pairs`
- `groups`, `group_relays`, `group_exporter_secrets`

**Memory snapshots include additional items:**
- `welcomes`, `processed_welcomes`
- `messages`, `messages_by_group`, `processed_messages`

### Analysis

For **messages**: This is **intentional and correct**. After rollback, `mdk-core` calls `invalidate_messages_after_epoch()` to mark messages as invalid rather than deleting them. This preserves message history while marking affected messages for reprocessing.

For **welcomes**: Welcomes are keyed by EventId, not by GroupId, so they're not really group-specific data. SQLite doesn't snapshot them; memory storage currently does (via full snapshot).

### Fix

With the group-scoped snapshot fix from Issue 1, messages and welcomes will no longer be included in the snapshot (matching SQLite behavior). No additional changes needed - the Issue 1 fix resolves this automatically.

---

## Issue 4: SQLite Groups-by-Nostr-ID Not Snapshotted

### Problem

Memory storage snapshots `groups_by_nostr_id_cache`, but SQLite doesn't have a separate table for this - it's derived from the `groups` table via the `nostr_group_id` column.

### Fix

This is already handled correctly in SQLite (the nostr_group_id is part of the `groups` table which IS snapshotted). The memory storage fix in Issue 1 should ensure `groups_by_nostr_id_cache` is updated when restoring the group. The pseudocode above already handles this.

---

## Implementation Checklist

- [ ] **Issue 1:** Implement group-scoped snapshots in memory storage
  - [ ] Create `GroupScopedSnapshot` struct
  - [ ] Implement `create_group_scoped_snapshot()` method
  - [ ] Implement `restore_group_scoped_snapshot()` method
  - [ ] Update `group_snapshots` field type
  - [ ] Update `create_group_snapshot()` impl
  - [ ] Update `rollback_group_to_snapshot()` impl
  - [ ] Add `test_snapshot_isolation_between_groups` test
  - [ ] Run all existing tests to verify no regressions

- [ ] **Issue 2:** Fix rollback to nonexistent snapshot
  - [ ] Add existence check in SQLite `restore_group_from_snapshot()`
  - [ ] Return error if snapshot doesn't exist
  - [ ] Update `test_rollback_nonexistent_snapshot_behavior` test to expect error

- [ ] **Verification:**
  - [ ] Run `cargo test -p mdk-memory-storage`
  - [ ] Run `cargo test -p mdk-sqlite-storage`
  - [ ] Run `cargo test -p mdk-core`
  - [ ] Verify the race chain tests still pass
  - [ ] Run `just precommit` to ensure all checks pass

---

## Files to Modify

1. `crates/mdk-memory-storage/src/lib.rs` - Main snapshot/rollback implementation
2. `crates/mdk-memory-storage/src/snapshot.rs` - May need new `GroupScopedSnapshot` struct
3. `crates/mdk-sqlite-storage/src/lib.rs` - Add snapshot existence check

---

## Testing Strategy

1. **Unit tests:** Add `test_snapshot_isolation_between_groups` to memory storage
2. **Regression tests:** Ensure all existing snapshot tests pass
3. **Integration tests:** The race chain tests in `mdk-core` exercise the full rollback flow
