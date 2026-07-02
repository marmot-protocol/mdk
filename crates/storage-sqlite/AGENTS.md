# AGENTS.md - crates/storage-sqlite

Agent-facing map for the SQLCipher-backed storage backend.

## Scope

`SqliteAccountStorage` implements `cgka_traits::StorageProvider` with Marmot metadata and custom OpenMLS storage in one
encrypted SQLite database. One database file belongs to one Marmot account-device identity. `shared.rs`'s
`SqliteSharedStorage` is a deliberate exception: a separate, non-account-scoped database for cross-identity state — do
not "fix" it into the per-account database.

## Key files

| Path | Owns |
| --- | --- |
| `src/connection.rs` | SQLCipher key application, operational PRAGMAs, options, aggregate handle. |
| `src/codec.rs` | JSON serialization helpers and SQLite error mapping. |
| `src/migrations.rs` | Rust migration runner and migration tests. |
| `src/migrations/` | Numbered Rust migration bodies. |
| `src/storage/` | Marmot storage tables by concern. |
| `src/openmls_storage/` | Custom OpenMLS storage adapter. |
| `src/account_projection.rs` | Account-level event projection. |
| `src/chat_list.rs` | Chat-list projection, including avatar URLs. |
| `src/timeline.rs` | Materialized message-timeline aggregation. |
| `src/encrypted_media_secrets.rs` | Per-group encrypted-media secret storage. |
| `src/shared.rs` | `SqliteSharedStorage`: a separate non-account-scoped database for cross-identity state (public-directory cache, relay-telemetry/audit-log settings, telemetry install id). |

## Invariants

- Accept raw SQLCipher keys only. Key derivation and recovery live above this crate.
- Apply privacy/durability defaults unless callers opt out with `SqliteStorageOptions`.
- Keep invalidated message records. Applications decide whether to show them.
- Retained-anchor policy is engine/group policy. SQLite stores snapshots and policy bytes; the engine decides when to
  prune.
- Migration file names use padded numeric prefixes, for example `0001_initial_schema.rs`.

## Verification

```sh
cargo test -p storage-sqlite
cargo clippy -p storage-sqlite --all-targets -- -D warnings
```
