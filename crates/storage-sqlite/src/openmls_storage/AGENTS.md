# AGENTS.md - crates/storage-sqlite/src/openmls_storage

Map for the custom OpenMLS SQLite storage adapter.

## Modules

| Module | Owns |
| --- | --- |
| `provider.rs` | Direct implementation of OpenMLS's storage trait surface. |
| `value_store.rs` | Generic SQLite row read/write/list/delete helpers. |
| `labels.rs` | Stable labels and key construction helpers. |

## Rules

- Keep the large OpenMLS trait implementation isolated in `provider.rs`.
- Add new labels in `labels.rs`; do not inline ad hoc byte strings in provider
  methods.
- Keep group-scoped values tagged with `group_key` so snapshots and group
  delete can operate by group.
- OpenMLS objects are JSON-encoded in this backend. Schema migrations should
  treat those blobs as opaque unless a deliberate storage-format migration is
  being written.
