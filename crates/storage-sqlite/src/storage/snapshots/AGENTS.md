# AGENTS.md - crates/storage-sqlite/src/storage/snapshots

Map for SQLite group snapshots.

## Modules

| Module | Owns |
| --- | --- |
| `capture.rs` | Reads live group state into a serialized snapshot. |
| `restore.rs` | Restores a serialized snapshot into live tables. |
| `lifecycle.rs` | Snapshot listing and release. |
| `rows.rs` | Snapshot serialization rows. |
| `format.rs` | Versioned binary snapshot/checkpoint envelope and legacy JSON decoding. |

## Rules

- Snapshots must include Marmot group metadata, messages, queued outbound intents, member capabilities, convergence
  policy, and group-scoped OpenMLS rows.
- Rollback should restore the captured state and leave unrelated groups alone.
- Snapshot release is idempotent only where the caller explicitly handles `SnapshotMissing`.
- New rollback snapshots and group-state checkpoints use the `MDKS` v2 envelope; untagged legacy JSON remains
  readable, while tagged unknown versions fail closed.
