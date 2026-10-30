# AGENTS.md - crates/storage-sqlite/src/protocol/storage

Map for Marmot engine-side SQLite tables (the `cgka_traits` storage traits). App projections live under
`src/app/`; see [`../../../AGENTS.md`](../../../AGENTS.md).

## Modules

| Module | Owns |
| --- | --- |
| `mod.rs` | Module wiring and shared helpers. |
| `groups.rs` | `GroupStorage`: group CRUD, listing, cascade delete; delegates route rows to `transport_routes.rs`. |
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
| `private_key_packages.rs` | `PrivateKeyPackageStorage`: one issuer record per private KeyPackage handed to a sibling (mdk#2628 item 3.4b); the key itself stays in the OpenMLS bundle store. |
| `announced_key_packages.rs` | `AnnouncedKeyPackageStorage`: each KeyPackage a device-group roster this device held announced, by group and slot (mdk#2628 D31 item 7). Outside every snapshot, so a rewind keeps them; group deletion drops them. |

## Rules

- Keep tests beside the module they exercise.
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
