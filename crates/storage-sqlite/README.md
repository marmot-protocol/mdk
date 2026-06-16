# storage-sqlite

SQLite implementation of the `cgka_traits::StorageProvider` aggregate.

This crate owns both Marmot metadata tables and a custom OpenMLS `StorageProvider<CURRENT_VERSION>` implementation
backed by the same SQLite connection. Keeping both sides in one database is intentional: group snapshots and rollback
must be atomic across Marmot records and group-scoped OpenMLS state.

## Layout

The crate is split around storage concerns:

- `connection.rs` owns SQLCipher keying, connection setup, and the aggregate `StorageProvider` handle.
- `storage/` owns Marmot tables by concern: groups, messages, snapshots, outbound intents, welcomes, capabilities, and
  convergence policies. Tests sit beside the concern they exercise.
- `openmls_storage/` owns the custom OpenMLS adapter. `value_store.rs` contains the SQLite row mechanics, `labels.rs`
  contains stable labels and key helpers, and `provider.rs` is the direct implementation of the large OpenMLS storage
  trait.
- `account_projection.rs`, `chat_list.rs`, and `timeline.rs` own the app-facing projections (account event projection,
  chat-list projection including avatar URLs, and the materialized message timeline).
- `encrypted_media_secrets.rs` owns per-group encrypted-media secret storage; `shared.rs` and `codec.rs` own shared
  row/codec helpers and SQLite error mapping.
- `migrations.rs` owns the migration runner and migration tests.

## Migrations

Schema changes go through Rust migrations, not external SQL files. The runner and ordered registry live in
`src/migrations.rs`; migration bodies live in numbered files like `src/migrations/0001_initial_schema.rs`. Each
migration has a monotonically increasing integer version, a matching padded name, and an `apply` function that runs
inside a SQLite transaction. That function can execute DDL, rewrite rows, or perform more complex data-shape changes
when storage semantics evolve.

Applied migrations are recorded in `cgka_schema_migrations`. Opening an encrypted database applies any missing
migrations after SQLCipher keying and before storage handles are exposed.

## Operational boundary

`storage-sqlite` requires callers to provide a non-empty SQLCipher key. The crate applies the key and verifies the
database opens, but it does not derive, rotate, escrow, recover, or prompt for keys. Those policies belong at the
account/session layer above storage.

One SQLite database should belong to exactly one Marmot account-device identity. Keeping account/device pairs in
separate encrypted database files makes deletion and account separation straightforward and avoids cross-identity state
sharing.

The default connection settings are privacy/durability oriented:

- raw SQLCipher key provided by the caller
- `journal_mode=WAL`
- `synchronous=FULL`
- `busy_timeout=5000`
- `foreign_keys=ON`
- `secure_delete=ON`
- `temp_store=MEMORY`
- `trusted_schema=OFF`
- `cipher_memory_security=ON` when supported by the linked SQLCipher build

Use `open_encrypted_with_options` or `in_memory_with_options` to override these runtime settings. The crate does not
expose first-class key rotation for v1; rotate by creating a new encrypted database, migrating data, and replacing the
old file.

Retained-anchor policy is engine/group policy, not a hidden SQLite policy. `max_rewind_commits` defaults to `5` when no
group policy is stored, and the engine persists negotiated policy bytes per group when available. Retained anchor
snapshots are pruned after successful stable canonicalization advances the tip. Invalidated message records are kept as
audit/debug evidence and so applications can decide whether to surface invalidated messages.

OpenMLS proposal queues are also treated as recoverable cached state. If `queued_proposals()` finds a
`ProposalQueueRefs` entry whose `QueuedProposal` entity is missing (a dangling ref) or present but undeserializable
(a truncated/garbled blob from out-of-band corruption, a partial write, or a storage-format skew), the backend clears
the whole proposal queue for that group and returns an empty queue. It deliberately does not load a partial subset of
still-present proposals: after corruption, a later commit must start from the current MLS group state and require
proposals to be re-enqueued rather than silently committing a queue whose history is known incomplete. Only deserialize
failures are treated as recoverable corruption here; operational errors (SQLite/lock failures) still propagate so a
transient backend fault is never mistaken for queue corruption.

Run:

```sh
cargo test -p storage-sqlite
```
