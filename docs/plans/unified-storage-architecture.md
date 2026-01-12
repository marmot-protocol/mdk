# Unified Storage Architecture Implementation Plan

## Overview

This plan refactors MDK's storage layer to have a single unified storage implementation that implements both OpenMLS's `StorageProvider<1>` trait and MDK's own storage traits (`GroupStorage`, `MessageStorage`, `WelcomeStorage`). This enables atomic transactions across MLS and MDK state, which is required for proper commit race resolution (Issue #54).

## Background

### Problem Statement

MDK currently uses a dual-connection architecture where:

1. OpenMLS state is stored via `openmls_sqlite_storage` (Connection 1)
2. MDK state (groups, messages, welcomes) is stored via our own code (Connection 2)

Both connections point to the same SQLite database file, but because they are separate connections, we cannot wrap operations across both in a single transaction. This makes it impossible to implement proper rollback for commit race resolution.

### Related Issues

- [Issue #54](https://github.com/marmot-protocol/mdk/issues/54): No Deterministic Commit Race Resolution (LA Audit Finding)
- [Issue #25](https://github.com/marmot-protocol/mdk/issues/25): Handle out of order Commit messages better

### MIP-03 Requirements

The Marmot Protocol specification requires deterministic commit resolution:

1. **Timestamp priority**: Choose the Commit with the earliest `created_at` timestamp
2. **ID tiebreaker**: If timestamps are identical, choose the Commit with the lexicographically smallest event ID
3. **Discard others**: Reject all other competing Commits

To implement this correctly, we need the ability to rollback state if a "better" commit arrives after we've already applied one.

## Current State

### Dependencies

```toml
openmls = "0.7.1"
openmls_traits = "0.4.1"  # Defines StorageProvider<VERSION>
openmls_sqlite_storage = "0.1.1"  # SQLite implementation we'll replace
openmls_memory_storage = "0.4.1"  # Memory implementation we'll replace
```

### Current Architecture

```
MdkSqliteStorage
├── openmls_storage: SqliteStorageProvider<JsonCodec, Connection>  ← Connection 1
└── db_connection: Arc<Mutex<Connection>>                          ← Connection 2

MdkMemoryStorage
├── openmls_storage: MemoryStorage                                 ← OpenMLS data
└── LRU caches for MDK data                                        ← MDK data
```

### Current Tables

**OpenMLS Tables (8 tables, managed by openmls_sqlite_storage):**

- `openmls_group_data` - Polymorphic storage for 11 group data types
- `openmls_proposals` - Queued proposals
- `openmls_key_packages` - Key packages
- `openmls_psks` - Pre-shared keys
- `openmls_signature_keys` - Signature key pairs
- `openmls_encryption_keys` - HPKE encryption key pairs
- `openmls_epoch_keys_pairs` - Epoch HPKE key pairs
- `openmls_own_leaf_nodes` - Own leaf nodes per group

**MDK Tables (7 tables, managed by mdk-sqlite-storage):**

- `groups` - Nostr MLS group metadata
- `group_relays` - Relay URLs per group
- `group_exporter_secrets` - Epoch-keyed exporter secrets
- `messages` - Decrypted messages
- `processed_messages` - Message deduplication tracking
- `welcomes` - Pending welcome invitations
- `processed_welcomes` - Welcome deduplication tracking

## Target State

### New Architecture

```
MdkSqliteStorage
└── connection: Arc<Mutex<Connection>>  ← Single connection
    ├── impl StorageProvider<1>         ← OpenMLS trait (54 methods)
    ├── impl GroupStorage               ← MDK trait
    ├── impl MessageStorage             ← MDK trait
    └── impl WelcomeStorage             ← MDK trait

MdkMemoryStorage
└── unified data structures
    ├── impl StorageProvider<1>         ← OpenMLS trait (54 methods)
    ├── impl GroupStorage               ← MDK trait
    ├── impl MessageStorage             ← MDK trait
    └── impl WelcomeStorage             ← MDK trait
```

### Benefits

1. **Single transaction boundary**: Wrap MLS + MDK operations atomically
2. **Savepoint-based rollback**: `SAVEPOINT` before commit, `ROLLBACK TO` if a better commit arrives
3. **Single migration system**: No more coordinating two sets of migrations
4. **Simpler architecture**: One connection, one storage struct

---

## Implementation Phases

### Phase 1: Update `mdk-storage-traits`

**Goal**: Remove the `openmls_storage()` accessor pattern; make `MdkStorageProvider` require `StorageProvider<1>` directly.

**Changes**:

1. **Update `MdkStorageProvider` trait** (`crates/mdk-storage-traits/src/lib.rs`):

   ```rust
   // Before
   pub trait MdkStorageProvider: GroupStorage + MessageStorage + WelcomeStorage {
       type OpenMlsStorageProvider: StorageProvider<CURRENT_VERSION>;
       fn openmls_storage(&self) -> &Self::OpenMlsStorageProvider;
       fn openmls_storage_mut(&mut self) -> &mut Self::OpenMlsStorageProvider;
   }
   
   // After
   pub trait MdkStorageProvider: 
       GroupStorage + MessageStorage + WelcomeStorage + StorageProvider<CURRENT_VERSION> 
   {
       fn backend(&self) -> Backend;
   }
   ```

**Files Modified**:

- `crates/mdk-storage-traits/src/lib.rs`

---

### Phase 2: Implement `StorageProvider<1>` for `MdkSqliteStorage`

**Goal**: Make `MdkSqliteStorage` directly implement the OpenMLS storage trait.

**Changes**:

1. **Remove `openmls_sqlite_storage` dependency** from `Cargo.toml`

2. **Create new MLS storage module** with adapted implementation:
   - `crates/mdk-sqlite-storage/src/mls_storage/mod.rs` - Main impl
   - `crates/mdk-sqlite-storage/src/mls_storage/group_data.rs` - Polymorphic group data
   - `crates/mdk-sqlite-storage/src/mls_storage/proposals.rs`
   - `crates/mdk-sqlite-storage/src/mls_storage/key_packages.rs`
   - `crates/mdk-sqlite-storage/src/mls_storage/signature_keys.rs`
   - `crates/mdk-sqlite-storage/src/mls_storage/encryption_keys.rs`
   - `crates/mdk-sqlite-storage/src/mls_storage/epoch_key_pairs.rs`
   - `crates/mdk-sqlite-storage/src/mls_storage/own_leaf_nodes.rs`
   - `crates/mdk-sqlite-storage/src/mls_storage/psks.rs`

3. **Update struct definition**:

   ```rust
   // Before
   pub struct MdkSqliteStorage {
       openmls_storage: MlsStorage,
       db_connection: Arc<Mutex<Connection>>,
   }
   
   // After
   pub struct MdkSqliteStorage {
       connection: Arc<Mutex<Connection>>,  // Single unified connection
   }
   ```

4. **Fresh migration system** - Since this is a breaking change, start with new migration numbering:
   - `V001__initial_schema.sql` - Creates all tables (both MLS and MDK) in a single migration

5. **Implement all 54 `StorageProvider<1>` methods**:
   - 17 write methods
   - 17 read methods
   - 18 delete methods
   - Keep JSON serialization (same codec as before)

6. **Add transaction/savepoint support**:

   ```rust
   impl MdkSqliteStorage {
       pub fn savepoint(&self, name: &str) -> Result<(), Error>;
       pub fn release_savepoint(&self, name: &str) -> Result<(), Error>;
       pub fn rollback_to_savepoint(&self, name: &str) -> Result<(), Error>;
   }
   ```

**Files Modified/Created**:

- `crates/mdk-sqlite-storage/Cargo.toml`
- `crates/mdk-sqlite-storage/src/lib.rs`
- `crates/mdk-sqlite-storage/src/mls_storage/` (new module)
- `crates/mdk-sqlite-storage/migrations/V001__initial_schema.sql` (replaces all existing migrations)

---

### Phase 3: Implement `StorageProvider<1>` for `MdkMemoryStorage`

**Goal**: Make `MdkMemoryStorage` directly implement the OpenMLS storage trait.

**Changes**:

1. **Remove `openmls_memory_storage` dependency** from `Cargo.toml`

2. **Add in-memory data structures for MLS state**:

   ```rust
   pub struct MdkMemoryStorage {
       // MLS data (replaces MemoryStorage)
       mls_group_data: RwLock<HashMap<(Vec<u8>, GroupDataType), Vec<u8>>>,
       mls_proposals: RwLock<HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>>,
       mls_key_packages: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
       mls_psks: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
       mls_signature_keys: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
       mls_encryption_keys: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
       mls_epoch_key_pairs: RwLock<HashMap<(Vec<u8>, Vec<u8>, u32), Vec<u8>>>,
       mls_own_leaf_nodes: RwLock<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
       
       // MDK data (existing LRU caches)
       groups_cache: RwLock<LruCache<GroupId, Group>>,
       // ... etc
   }
   ```

3. **Implement all 54 `StorageProvider<1>` methods**

**Files Modified/Created**:

- `crates/mdk-memory-storage/Cargo.toml`
- `crates/mdk-memory-storage/src/lib.rs`
- `crates/mdk-memory-storage/src/mls_storage.rs` (new module)

---

### Phase 4: Update `mdk-core`

**Goal**: Update `MdkProvider` to work with the new trait bounds.

**Changes**:

1. **Update `MdkProvider` impl**:

   ```rust
   // Before
   impl<Storage> OpenMlsProvider for MdkProvider<Storage>
   where
       Storage: MdkStorageProvider,
   {
       type StorageProvider = Storage::OpenMlsStorageProvider;
       fn storage(&self) -> &Self::StorageProvider {
           self.storage.openmls_storage()
       }
   }
   
   // After
   impl<Storage> OpenMlsProvider for MdkProvider<Storage>
   where
       Storage: MdkStorageProvider,
   {
       type StorageProvider = Storage;  // Storage IS the provider now
       fn storage(&self) -> &Self::StorageProvider {
           &self.storage
       }
   }
   ```

**Files Modified**:

- `crates/mdk-core/src/lib.rs`

---

### Phase 5: Testing & Validation

**Goal**: Ensure all existing tests pass and add new tests for unified storage.

**Tests to Add**:

1. Transaction/savepoint tests for SQLite
2. Cross-storage consistency tests (MLS + MDK state atomicity)
3. Migration tests (ensure MLS tables are created correctly)
4. All existing `StorageProvider` behavior tests

**Validation**:

```bash
just test-all
just precommit
```

---

## Detailed File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `crates/mdk-storage-traits/src/lib.rs` | Modify | Update `MdkStorageProvider` trait |
| `crates/mdk-sqlite-storage/Cargo.toml` | Modify | Remove `openmls_sqlite_storage` dep |
| `crates/mdk-sqlite-storage/src/lib.rs` | Modify | Single connection, new struct |
| `crates/mdk-sqlite-storage/src/mls_storage/` | Create | New module with 54 method impls |
| `crates/mdk-sqlite-storage/migrations/` | Replace | Fresh migrations starting at V001 |
| `crates/mdk-memory-storage/Cargo.toml` | Modify | Remove `openmls_memory_storage` dep |
| `crates/mdk-memory-storage/src/lib.rs` | Modify | Add MLS data structures |
| `crates/mdk-memory-storage/src/mls_storage.rs` | Create | New module with 54 method impls |
| `crates/mdk-core/src/lib.rs` | Modify | Update `MdkProvider` impl |
| `Cargo.toml` (workspace) | Modify | Remove unused OpenMLS storage deps |

---

## OpenMLS `StorageProvider<1>` Trait Reference

The trait requires 54 methods plus one associated type:

### Associated Type

- `type Error: Debug + Error`

### Write Methods (17)

| Method | Description |
|--------|-------------|
| `write_mls_join_config` | Store MLS group join configuration |
| `append_own_leaf_node` | Add own leaf node for a group |
| `queue_proposal` | Enqueue a proposal |
| `write_tree` | Write TreeSync tree |
| `write_interim_transcript_hash` | Write interim transcript hash |
| `write_context` | Write group context |
| `write_confirmation_tag` | Write confirmation tag |
| `write_group_state` | Write MLS group state |
| `write_message_secrets` | Write message secrets store |
| `write_resumption_psk_store` | Write resumption PSK store |
| `write_own_leaf_index` | Write own leaf index |
| `write_group_epoch_secrets` | Write group epoch secrets |
| `write_signature_key_pair` | Store signature key pair |
| `write_encryption_key_pair` | Store HPKE encryption key pair |
| `write_encryption_epoch_key_pairs` | Store list of epoch HPKE key pairs |
| `write_key_package` | Store key package |
| `write_psk` | Store PSK |

### Read Methods (17)

| Method | Returns |
|--------|---------|
| `mls_group_join_config` | `Option<MlsGroupJoinConfig>` |
| `own_leaf_nodes` | `Vec<LeafNode>` |
| `queued_proposal_refs` | `Vec<ProposalRef>` |
| `queued_proposals` | `Vec<(ProposalRef, QueuedProposal)>` |
| `tree` | `Option<TreeSync>` |
| `group_context` | `Option<GroupContext>` |
| `interim_transcript_hash` | `Option<InterimTranscriptHash>` |
| `confirmation_tag` | `Option<ConfirmationTag>` |
| `group_state` | `Option<GroupState>` |
| `message_secrets` | `Option<MessageSecrets>` |
| `resumption_psk_store` | `Option<ResumptionPskStore>` |
| `own_leaf_index` | `Option<LeafNodeIndex>` |
| `group_epoch_secrets` | `Option<GroupEpochSecrets>` |
| `signature_key_pair` | `Option<SignatureKeyPair>` |
| `encryption_key_pair` | `Option<HpkeKeyPair>` |
| `encryption_epoch_key_pairs` | `Vec<HpkeKeyPair>` |
| `key_package` | `Option<KeyPackage>` |
| `psk` | `Option<PskBundle>` |

### Delete Methods (18)

| Method | Description |
|--------|-------------|
| `remove_proposal` | Remove a single proposal |
| `delete_own_leaf_nodes` | Delete all own leaf nodes for a group |
| `delete_group_config` | Delete group config |
| `delete_tree` | Delete TreeSync tree |
| `delete_confirmation_tag` | Delete confirmation tag |
| `delete_group_state` | Delete group state |
| `delete_context` | Delete group context |
| `delete_interim_transcript_hash` | Delete transcript hash |
| `delete_message_secrets` | Delete message secrets |
| `delete_all_resumption_psk_secrets` | Delete all resumption PSK secrets |
| `delete_own_leaf_index` | Delete own leaf index |
| `delete_group_epoch_secrets` | Delete epoch secrets |
| `clear_proposal_queue` | Clear all proposals for a group |
| `delete_signature_key_pair` | Delete signature key pair |
| `delete_encryption_key_pair` | Delete encryption key pair |
| `delete_encryption_epoch_key_pairs` | Delete epoch HPKE key pairs |
| `delete_key_package` | Delete key package |
| `delete_psk` | Delete PSK |

---

## Schema Design

We will keep the polymorphic pattern from OpenMLS for group data, using the `openmls_` prefix since these tables are tightly coupled to the OpenMLS `StorageProvider` trait:

```sql
-- Polymorphic group data storage (11 data types in one table)
CREATE TABLE openmls_group_data (
    group_id BLOB NOT NULL,
    data_type TEXT NOT NULL CHECK (data_type IN (
        'join_group_config', 
        'tree', 
        'interim_transcript_hash',
        'context', 
        'confirmation_tag', 
        'group_state', 
        'message_secrets', 
        'resumption_psk_store',
        'own_leaf_index',
        'use_ratchet_tree_extension',
        'group_epoch_secrets'
    )),
    data BLOB NOT NULL,
    PRIMARY KEY (group_id, data_type)
);

CREATE TABLE openmls_proposals (
    group_id BLOB NOT NULL,
    proposal_ref BLOB NOT NULL,
    proposal BLOB NOT NULL,
    PRIMARY KEY (group_id, proposal_ref)
);

CREATE TABLE openmls_own_leaf_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id BLOB NOT NULL,
    leaf_node BLOB NOT NULL
);

CREATE TABLE openmls_key_packages (
    key_package_ref BLOB PRIMARY KEY,
    key_package BLOB NOT NULL
);

CREATE TABLE openmls_psks (
    psk_id BLOB PRIMARY KEY,
    psk_bundle BLOB NOT NULL
);

CREATE TABLE openmls_signature_keys (
    public_key BLOB PRIMARY KEY,
    key_pair BLOB NOT NULL
);

CREATE TABLE openmls_encryption_keys (
    public_key BLOB PRIMARY KEY,
    key_pair BLOB NOT NULL
);

CREATE TABLE openmls_epoch_key_pairs (
    group_id BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    leaf_index INTEGER NOT NULL,
    key_pairs BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch_id, leaf_index)
);
```

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| OpenMLS `StorageProvider` trait changes | Medium | Pin to `openmls_traits = 0.4.1`, test against specific version |
| Serialization compatibility | Low | Keep same JSON codec as `openmls_sqlite_storage` |
| Migration complexity | Low | Fresh start with V001, no data migration needed (breaking change) |
| Test coverage drop | Medium | Port all existing storage tests, add new unified tests |
| Performance regression | Low | Profile before/after; single connection should be faster |

---

## Design Decisions

### Why keep the polymorphic table pattern?

1. **Minimizes divergence from OpenMLS** - easier to understand the mapping
2. **We don't need to query MLS internals** - MDK loads full group state when needed
3. **Can normalize later** - if we find we need queryable fields, we can migrate

### Why keep the `openmls_*` table prefix?

Since these tables are tightly coupled to the OpenMLS `StorageProvider` trait, keeping the `openmls_` prefix makes that relationship clear. The tables store OpenMLS data structures in the format expected by the trait, so the naming reflects this dependency.

### Why start fresh with migration V001?

Since this is a completely breaking change with no migration path from the old dual-connection architecture, we start fresh with `V001__initial_schema.sql`. This creates all tables (both MLS and MDK) in a single clean migration, making the schema easier to understand.

---

## Future Work

Once this unified storage architecture is in place, we can implement:

1. **Commit race resolution** (Issue #54): Use savepoints to snapshot state before applying commits, rollback if a better commit arrives
2. **Pending commit buffering** (Issue #25): Store incoming commits temporarily, apply the winner after a short delay
3. **State snapshots**: For longer-term rollback capability if needed

---

## Changelog

- **2025-01-12**: Initial plan created
