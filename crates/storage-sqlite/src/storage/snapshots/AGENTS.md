# AGENTS.md - crates/storage-sqlite/src/storage/snapshots

Map for SQLite group snapshots.

## Modules

| Module | Owns |
| --- | --- |
| `capture.rs` | Reads live group state into a serialized snapshot; fingerprints live replay state and retained snapshots/checkpoints in one consistent read. |
| `restore.rs` | Restores a serialized snapshot into live tables. |
| `lifecycle.rs` | Snapshot listing and release. |
| `rows.rs` | Snapshot serialization rows. |
| `format.rs` | Versioned binary snapshot/checkpoint envelope and legacy JSON decoding. |

## Rules

- Full snapshots include Marmot group metadata, messages, queued outbound intents, member capabilities, convergence
  policy, validation state and group-scoped OpenMLS rows. `SnapshotScope::GroupState` deliberately excludes the message
  ledger and outbound queue; restoring that scope must leave those live rows untouched.
- Rollback should restore the captured state and leave unrelated groups alone.
- Replay fingerprints cover live canonical/OpenMLS state and retained snapshot/checkpoint contents, including epochs.
  They exclude live message/outbound/app rows; the engine validates its frozen inputs separately. Fingerprints are
  secret-derived, memory-only validation values: never log or persist them. Keep `mls_write_generation` semantics
  unchanged for loaded MLS objects. Fingerprint regression tests live in the parent `snapshots.rs` test module.
- Snapshot release is idempotent only where the caller explicitly handles `SnapshotMissing`.
- New rollback snapshots and group-state checkpoints use the `MDKS` v2 envelope; untagged legacy JSON remains
  readable, while tagged unknown versions fail closed.
