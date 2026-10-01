# AGENTS.md - crates/storage-sqlite/src/openmls_storage

Map for the custom OpenMLS SQLite storage adapter.

## Modules

| Module | Owns |
| --- | --- |
| `../openmls_storage.rs` | `SqliteOpenMlsStorage` handle, error type, and module wiring. |
| `provider.rs` | Direct implementation of OpenMLS's storage trait surface. |
| `value_store.rs` | Generic SQLite row read/write/list/delete helpers and value encoding. |
| `labels.rs` | Stable labels, sensitivity classes, and key construction helpers. |

## Rules

- Keep the large OpenMLS trait implementation isolated in `provider.rs`.
- Add new labels in `labels.rs`; do not inline ad hoc byte strings in provider methods.
- Keep group-scoped values tagged with `group_key` so snapshots and group delete can operate by group.
- Value encoding: new writes are MessagePack behind the `VALUE_ENCODING_V2_PREFIX` (`0x00 0x02`); legacy serde_json
  rows keep decoding until their next write replaces them. KeyPackage labels stay serde_json because the engine parses
  their raw bytes (`StoredKeyPackageBundle::value`). Schema migrations treat these blobs as opaque unless a deliberate
  storage-format migration is being written.
