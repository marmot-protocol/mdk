# AGENTS.md - crates/storage-sqlite/src/protocol/storage

Map for Marmot engine-side SQLite tables (the `cgka_traits` storage traits). App projections live under
`src/app/`; see [`../../../AGENTS.md`](../../../AGENTS.md).

## Modules

| Module | Owns |
| --- | --- |
| `mod.rs` | Module wiring and shared helpers. |
| `groups.rs` | `GroupStorage`: group CRUD, listing, cascade delete; delegates route rows to `transport_routes.rs`. `put_group_with_roster` writes a record and its committed roster in one transaction, `put_group_keeping_roster` the record alone; the inherent `put_group` is a `test-support` fixture that writes the record alone. |
| `committed_rosters.rs` | `CommittedRosterStorage`: each group's committed roster, its distinct member account ids, at a revision drawn from one account-wide counter that is never reset, so a group forgotten or deleted and joined again never reuses one (mdk#3273). A read takes the revision and the members from one snapshot. A write changes only the member rows that differ and takes a new revision only when the members change. Each write is its own savepoint, so one refused inside a caller's transaction leaves no rows. Outside every snapshot, so a rewind keeps it; group deletion drops it. |
| `transport_routes.rs` | Durable transport-route index rows (routing id → group id + observing epoch) seeded at session open (mdk#1161). |
| `account_device_history_key.rs` | `AccountDeviceHistoryKeyStorage`: this device's HPKE history key pair (mdk#2628 4.1). |
| `account_device_signer.rs` | Marmot identity to MLS signing-key binding. |
| `device_group_welcome.rs` | `DeviceGroupWelcomeStorage`: the device-group Welcome a confirmed link expects (sender key, deadline). |
| `messages.rs` | `MessageStorage`: message rows (storage format 2 columns), deferred-message metadata, format promotion. |
| `snapshots.rs`, `snapshots/` | Snapshot capture, rollback, listing, release, checkpoints, replay fingerprints; see its local `AGENTS.md`. |
| `outbound.rs` | `OutboundIntentStorage` / `OutboundFanoutStorage`: durable queued outbound intents and fanouts. |
| `welcomes.rs` | Pending Welcome put/list/take. |
| `capabilities.rs` | Feature registry. Members' capabilities are read from the MLS tree, never stored. |
| `member_validation_cache.rs` | `MemberValidationCacheStorage`. |
| `convergence_policy.rs` | Opaque per-group convergence policy bytes. |
| `convergence_passes.rs` | `ConvergencePassStorage`: durable bounded convergence passes. |
| `deferred_peel_generations.rs` | `DeferredPeelGenerationStorage`: deferred-peel generation barriers. |
| `leave_requests.rs`, `disband_requests.rs` | Durable leave and disband requests (plus disband candidates/tombstones). |
| `maintenance.rs` | `MaintenanceStorage`: maintenance and publication-recovery records. |
| `commit_refusals.rs` | The relays that refused this device's confirmed commits (mdk#2333, migration 0207): one record per commit, merged before its fanout is deleted and kept, acknowledged, until then. Session-only inherent methods, not a storage trait. Outside every snapshot; rows go with the group's `cgka_groups` row and outlive an active chat wipe. |
| `welcome_delivery_ledger.rs` | The sender's record of each outbound Welcome's delivery (mdk#1706, migration 0225): one record per Welcome: its invite and its attempt counts, never its state; a pass's counts are saved with its retry record in one transaction (`put_transport_fanout_with_welcome_delivery`), and an invite's new records are inserted together, all of them or none (`insert_missing_welcome_delivery_records`). Session-only inherent methods, not a storage trait. Outside every snapshot; rows go with the group's `cgka_groups` row. |
| `private_key_packages.rs` | `PrivateKeyPackageStorage`: one issuer record per private KeyPackage handed to a sibling (mdk#2628 item 3.4b); the key itself stays in the OpenMLS bundle store. |
| `roster_tag_keys.rs` | `RosterTagKeyStorage`: each tag signature key a device-group roster this device held listed, in a device entry or a `removed` record, by group and slot (mdk#2761). A renewal (mdk#3679) moves a slot's sighting times in one statement and never its order; holding a slot as removed (marmot#520) marks its keys and moves neither. Outside every snapshot, so a rewind keeps them; group deletion drops them. |
| `sibling_adds.rs` | `SiblingAddStorage`: each sibling slot one of this device's own confirmed Commits added to a group, until the app owes it that group's history (mdk#2628 D76). Outside every snapshot, so a rewind keeps them; group deletion drops them. |
| `group_recovery.rs` | Bounded authenticated recovery jobs in `cgka_group_rejoin`, including exact outbound artifacts and retry evidence. |

## Rules

- Keep tests beside the module they exercise.
- Prove that a write joins or owns its transaction by behavior, never by reading source: hold the write lock on a
  second connection (`write_contention::SharedDatabase` in `mod.rs`) or inject a trigger failure, and match the
  injected error's text. `StorageError::Backend(_)` alone also matches the error a nested `BEGIN` raises.
- Message rows follow storage format 2 (`docs/marmot-architecture/storage-format-v2.md`): scalar columns, `payload`,
  and `deferred_peel` are authoritative and `record` is `NULL`; legacy format-1 rows stay readable and promote
  atomically on mutation. Other Marmot records (for example groups) are serialized `record` blobs so trait shapes can
  evolve through Rust migrations.
- `openmls_content` / `openmls_epoch` are derived from `payload` in `put_message_on_connection`, the one write path
  for message rows; never write them anywhere else. Filtered listings may only *leave out* rows they classify, and
  must return pending (`-1`) and unclassified (`4`) rows.
- Select state-filtered message rows by id from a covering index, then read them by id in id order
  (`state_filtered_message_sql`). A plain `ORDER BY insert_order` lets SQLite walk the whole group to skip a sort.
- Preserve insertion order where replay depends on deterministic ordering.
- Group delete must remove group-scoped OpenMLS rows too.
