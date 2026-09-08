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
- `encrypted_media_secrets.rs` owns per-group encrypted-media secret storage; `codec.rs` owns shared JSON/codec helpers
  and SQLite error mapping; `shared.rs` owns `SqliteSharedStorage`, a separate (non-account-scoped) database for
  cross-identity state: the public-directory user cache, relay-telemetry settings, audit-log settings, and the telemetry
  install id.
- `migrations.rs` owns the account/session migration runner and migration tests.
- `shared/migrations.rs` owns the independent shared-store runner; `shared/v1.sql` freezes its initial schema,
  `shared/legacy.sql` defines recognized compatibility columns, and `shared/fixtures/` plus the migration and assurance
  tests cover adoption and recovery. `shared/error.rs` owns the privacy-safe error mapper and result extension.

## Migrations

Account/session schema changes go through Rust migrations. The runner and ordered registry live in
`src/migrations.rs`; migration bodies live in numbered files like `src/migrations/0001_initial_schema.rs`. Each
migration has a monotonically increasing integer version, a matching padded name, and an `apply` function that runs
inside a SQLite transaction. That function can execute DDL, rewrite rows, or perform more complex data-shape changes
when storage semantics evolve.

Applied migrations are recorded in `cgka_schema_migrations`. Opening an encrypted database applies any missing
migrations after SQLCipher keying and before storage handles are exposed.

Migration 0066 schedules a one-time historical transport receipt repair for existing account databases.
It creates only repair metadata without scanning retained history on open. After readiness and group
hydration, the app worker inspects at most 256 inventory rows per maintenance pass (also the storage cap).
Transactional keyset cursors and a fixed high water allow restart and bound each pass, including when every
inventory entry is excluded by possession evidence. Retained Nostr fanouts are already keyed by the signed
outer event ID: signing precedes engine persistence and fanout staging, including in the historical version
that introduced fanout storage. An indexed message-ID probe therefore excludes them without an alias table,
a fanout scan or any record decoding. Malformed fanout records retain their exact-ID exclusion without
blocking unrelated inventory repair. Proven corruption, schema and decode failures elsewhere halt the sweep;
lock contention, capacity and unclassified backend failures retry on the next tick. Closed handles stop quietly.

Only retained group-route inventory entries without raw/message, processed-marker, ingress-dedup, Welcome,
or outbound-fanout evidence are selected. Inbox claims, protocol state, projections, retention floors and
reconciliation cursors are preserved. Selected IDs enter the durable release journal and arm epoch backfill;
the active account invalidates its seen index synchronously before checkpoint or redelivery. Counts describe
**uncertain-possession repairs**, since pre-0058 accepted wrappers may lack a processed marker. Normal Nostr
own echoes remain excluded after fanout settlement: the engine stores the already-signed outer ID as `Sent`,
alongside its content-derived marker. The repair never infers possession from author identity or from the
absence of raw data; wrappers without exact outer-ID evidence remain uncertain and redelivery must still
deduplicate canonical messages. Expired epoch keys, retained inventory windows and unavailable
relay history limit recovery; this repair cannot reconstruct missing relay history.
The scan intentionally has no release-date cutoff on event `created_at`: that is the sender's signed authored
time, not the local receipt/deletion time, and account upgrades may occur well after a release. The retained
window and fixed keyset high water define its scope instead. A full 16,384-entry route needs 64 inventory
passes (roughly 16 minutes of active worker time at a 15-second cadence).
The query-work regression checks 256-entry first/last pages against 512 and 16,384 retained entries; it bounds
SQL work, not device latency. Large or multi-route histories can still require many maintenance ticks.

The three current app database categories have independent histories: `session.sqlite` uses
`cgka_schema_migrations`, the per-account `app-cache.sqlite3` uses marmot-app's `app_cache_schema_migrations`, and
installation-wide `shared.sqlite3` uses `shared_schema_migrations`. No runner reads another store's ledger.

Shared version `1 / 0001_shared_store` establishes the five live tables. Each migration body and its ledger row commit
in the same immediate transaction; failure rolls back both. Recorded versions and names must be an exact prefix of
the compiled registry. Future versions return `StorageError::UnsupportedSchemaVersion`. A pending opener rechecks the
prefix under the write lock; an already-current opener validates history using reads only.

Unversioned shared tables must match frozen current or verified historical definitions before adoption. Validation
covers columns, types, nullability, defaults, primary keys, foreign keys, CHECK expressions, collations and indexes.
Conservative DDL comparison can refuse equivalent but unrecognized SQL; incompatible shapes fail with static errors
and no version row. Missing tables are created. Public users, ordered follows, live settings, timestamps, installation
identity and rowids are preserved. Existing unused directory tables remain untouched; their pre-existing orphaned rows do not gate live-store adoption. The recognized nullable
`otlp_endpoint` column (inline or appended) is retained but non-NULL values are cleared transactionally; retained audit `data_mode` columns
(inline or historically appended) remain inert and unchanged by subsequent settings writes. No full-data audit mode
is reintroduced. SQLite errors retain extended result codes and transient BUSY/LOCKED classification without
SQLite's database-controlled message.

The shared store remains unencrypted and owner-only, with WAL, synchronous NORMAL, a 5-second busy timeout,
foreign keys ON, trusted_schema OFF, temp_store MEMORY and terminal close behavior. Its fixture provenance and
assurance limits are documented in [shared/fixtures/README.md](src/shared/fixtures/README.md) and the
[app storage boundaries](../../docs/marmot-architecture/further-context/app-sqlite-storage-boundaries.md).

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
- `cipher_memory_security=ON` process-wide; Android reports a once-per-process
  `platform_limited` diagnostic because its finite `mlock` budget makes memory
  residency best effort while SQLCipher still sanitizes allocations on free

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

See [`AGENTS.md`](AGENTS.md) for module layout and migration rules.

## Deferred recovery preparation benchmark

`MessageStorage::list_deferred_message_metadata` preserves insertion order and exact encoded payload
lengths while omitting normalized payload blobs. The engine uses it for sweep preparation and readiness,
then fetches full records only for selected attempts, retirement, or bounded lifecycle normalization.
Legacy format-1 rows still require their record blob until existing bounded promotion converts them.
The default trait implementation remains compatible with other backends.

Run the opt-in paired benchmark against encrypted temporary files:

```sh
MDK_DEFERRED_PREPARATION_BENCHMARK_OUT=target/deferred-preparation.json \
  CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p storage-sqlite \
  --lib deferred_metadata_file_backed_benchmark -- --ignored --nocapture
```

It generates 0/4,096 processed rows and 0/64/512/2,048 deferred rows with 4 KiB payloads, varies
row epochs over 17 values, includes persisted lifecycle fields, alternates query order, and writes ten warmed samples after two warmups to the requested private JSON file.
Reported blob bytes count full-record values materialized in Rust; they exclude SQLite pages,
metadata values, and filesystem cache effects. This measures storage enumeration, not retained
MLS context construction or scheduler wake pressure. No timing threshold is asserted.

On the September 6, 2026 local run, 4,096 processed plus 2,048 deferred rows took about 29.8 ms
for the full-row query versus 15.1 ms for metadata, avoiding 8 MiB of full payload copies per query.
The query still enumerates all deferred metadata so an unattempted row beyond a previously
attempted prefix remains visible. Candidate-graph cost and repeated zero-attempt wake pacing
remain follow-up work in [#1715](https://github.com/marmot-protocol/mdk/issues/1715).
