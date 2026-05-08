# AGENTS.md - crates/storage-sqlite/src/storage

Map for Marmot-side SQLite tables.

## Modules

| Module | Owns |
| --- | --- |
| `groups.rs` | Group CRUD, group listing, cascade delete. |
| `messages.rs` | Message rows and `MessageStorage` dispatch. |
| `snapshots/` | Snapshot capture, rollback, listing, release. |
| `outbound.rs` | Durable queued outbound intents. |
| `welcomes.rs` | Pending welcome put/list/take. |
| `capabilities.rs` | Feature registry and per-member capability cache. |
| `convergence_policy.rs` | Opaque per-group convergence policy bytes. |
| `test_support.rs` | Shared storage tests fixtures. |

## Rules

- Keep tests beside the module they exercise.
- Store serialized Marmot records in `record` blobs so trait shapes can evolve
  through Rust migrations.
- Preserve insertion order where replay depends on deterministic ordering.
- Group delete must remove group-scoped OpenMLS rows too.
