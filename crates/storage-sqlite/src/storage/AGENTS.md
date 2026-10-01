# AGENTS.md - crates/storage-sqlite/src/storage

Map for Marmot engine-side SQLite tables (the `cgka_traits` storage traits). App projections live in sibling modules
under `src/`; see [`../../AGENTS.md`](../../AGENTS.md).

## Modules

| Module | Owns |
| --- | --- |
| `mod.rs` | Module wiring and shared helpers. |
| `groups.rs` | `GroupStorage`: group CRUD, listing, cascade delete; delegates route rows to `transport_routes.rs`. |
| `transport_routes.rs` | Durable transport-route index rows (routing id → group id + observing epoch) seeded at session open (mdk#1161). |
| `account_device_signer.rs` | Marmot identity to MLS signing-key binding. |
| `messages.rs` | `MessageStorage`: message rows (storage format 2 columns), deferred-message metadata, format promotion. |
| `snapshots.rs`, `snapshots/` | Snapshot capture, rollback, listing, release, checkpoints, replay fingerprints; see its local `AGENTS.md`. |
| `outbound.rs` | `OutboundIntentStorage` / `OutboundFanoutStorage`: durable queued outbound intents and fanouts. |
| `welcomes.rs` | Pending Welcome put/list/take. |
| `capabilities.rs` | Feature registry and per-member capability cache. |
| `member_validation_cache.rs` | `MemberValidationCacheStorage`. |
| `convergence_policy.rs` | Opaque per-group convergence policy bytes. |
| `convergence_passes.rs` | `ConvergencePassStorage`: durable bounded convergence passes. |
| `deferred_peel_generations.rs` | `DeferredPeelGenerationStorage`: deferred-peel generation barriers. |
| `leave_requests.rs`, `disband_requests.rs` | Durable leave and disband requests (plus disband candidates/tombstones). |
| `maintenance.rs` | `MaintenanceStorage`: maintenance and publication-recovery records. |
| `test_support.rs` | Shared storage test fixtures. |

## Rules

- Keep tests beside the module they exercise.
- Message rows follow storage format 2 (`docs/marmot-architecture/storage-format-v2.md`): scalar columns, `payload`,
  and `deferred_peel` are authoritative and `record` is `NULL`; legacy format-1 rows stay readable and promote
  atomically on mutation. Other Marmot records (for example groups) are serialized `record` blobs so trait shapes can
  evolve through Rust migrations.
- Preserve insertion order where replay depends on deterministic ordering.
- Group delete must remove group-scoped OpenMLS rows too.
