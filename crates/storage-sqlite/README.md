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

## Account recovery groundwork

`account_recovery.rs` owns the durable account recovery ledger and retry reservations.
Migration 0092 replaces the overflow and epoch-demand tables while retaining their Rust
storage methods as adapters. The overflow marker task writes loss evidence only; the
account owner imports that evidence transactionally. A NULL imported count means that
an observation has not been imported, including a valid zero-count loss marker.

Attempt reservations fence selected demand and imported loss, survive reopen, and refuse
unknown scope versions. They do not certify coverage. `account_recovery/plan.rs` stores
versioned frozen scopes and accepts owner-validated endpoint/admission checkpoints.
History requires all designated scopes/endpoints; exclusions, EOSE and SDK seen state
are insufficient. Known-event retention and the limited first maintenance boundary use
separate predicates. A stale scope token rejects a multi-scope checkpoint before any
progress is written. Domain updates may share the same `with_transaction` boundary.

Migration 0093 adds the current route-policy snapshot, a unique explicit-history row,
and a receipt-journal flag recording whether inventory invalidation already ran.
It preserves populated obligations, loss evidence, retry state, receipts, maintenance,
inventory and cursors. Repeated serialized callers reuse the row without resetting retry;
a stale detach cannot clear the current caller's urgency. Unexpected duplicate explicit
rows make migration fail atomically; no demand is silently discarded.

`account_recovery/loss.rs` keeps qualified loss completion separate from external plane
acknowledgment. Capture exact token/count watermarks before execution. After qualified
completion, acknowledge the matching live generation and finish its writers before
calling `acknowledge_recovery_loss`. The runtime uses `recovery_loss_snapshot` and
`acknowledge_recovery_loss_snapshot`: a constant-size SHA-256 commitment to the complete
ordered token/count set, streamed under the same connection lock. This avoids copying
unbounded unresolved evidence into active grants without capping or deleting it. Both
acknowledgment forms share the same transaction and revision/qualification checks.
SQL cannot establish the external acknowledgment prerequisite.
New evidence or a persistence failure prevents reclamation; the owner must compensate
the live acknowledgment and call `restore_unacknowledged_recovery_loss` before new work.
Call that restore method when constructing an owner as well. Zero-count loss is evidence.
Legacy clear methods remain caller-directed retirement adapters, not completion proofs;
retained legacy watermarks do not recreate explicitly retired demand.

Inventory expiration, compaction and message release or route/group deletion bump the
account inventory revision in the same transaction; reservations and plan installation
check that revision. Installed proof is invalidated only for overlapping route/window
scopes (and the exact event for known-event predicates). Unrelated or out-of-window
retention churn cannot invalidate bounded completion or loss acknowledgment, including
when a productive admission triggers compaction. Removing the last qualified proof
reopens satisfied demand in the same transaction without forgiving account retry cost;
an alternative known-event copy or independent maintenance boundary remains valid.
Receipt release records scoped invalidation before deleting inventory. Consumption
uses conservative invalidation only if neither inventory bounds nor that durable flag
exist (including journal rows migrated from older schemas). No-op admission never
scans recovery scopes.
Idempotent deletes do not invalidate proof. `retained_recovery_event` checks exact route, event and frozen
window membership after the caller synchronizes release receipts; it does not certify
successful decryption or engine readiness.

**Merge gate:** this storage slice is stacked on #1983 and cannot ship independently.
Runtime integration must replace competing dispatch/clear callers, provide qualified
executor evidence and same-schema conservative handoff, and demonstrate bounded evidence
reclamation under [the recovery design](../../docs/marmot-architecture/further-context/account-recovery-ownership.md).
That integration, runtime cancellation-by-drop, policy/stagnation migration 0094 and
SDK/acquisition changes are outside this slice. Old binaries refuse the upgraded schema;
binary downgrade requires a pre-upgrade backup. Storage tests do not claim that the
current production executor can supply exhaustive coverage. Completed known-event
rows require owner-managed reclamation after no ticket/grant can reference them;
this bounded-lifetime gate must be demonstrated before activation. An unbounded
`since = None` includes older retained input, so its retirement must invalidate proof.
The owner must use finite automatic goals and preserve uncovered older-history debt;
it must not silently clip an explicit full-history request to the retention floor.

## Replay-state validation

`group_replay_state_fingerprint` captures a consistent read of the same live canonical/OpenMLS state as a
state-scoped snapshot, plus all retained snapshot/checkpoint bytes and checkpoint epochs. It excludes live message,
outbound, and app-projection rows; the engine validates its frozen inputs separately. The fingerprint stays in engine
memory and must never be logged or persisted. No schema migration or durable counter is needed.

This lets resumable reconstruction distinguish actual state changes from unrelated writes through another app
connection. The older `mls_write_generation` contract remains unchanged for cached `MlsGroup` objects.

## Conversation opening

`conversation_open` composes a bounded canonical timeline page with retained read state in one read-only snapshot.
It supports first-unread/latest opening and scoped anchor recovery; dirty projections return `ReadStateNotReady`
for the existing owner to refresh. See the [opening contract](../../docs/marmot-architecture/further-context/conversation-opening.md).

`conversation_window` adds explicit context placement around a retained anchor; latest targets always read the tail.
`conversation_account_snapshot` captures that window, system provenance, presentation inputs, draft descriptors and
persisted controls in one deferred read. `StorageProvider::with_read_snapshot` also composes public storage calls
under one deferred transaction, enforcing and restoring SQLite query-only mode even for nested calls.
The engine reuses its existing MLS cache for authority capture. The combined live screen remains C5 M4 work.

Selected composer reads and revision-checked mutations share the existing encrypted draft tables. Migration 0073
tracks legacy writes too; queued/fanout acceptance clears only its submitted revision atomically. See the
[draft contract](../../docs/marmot-architecture/further-context/conversation-drafts.md).

## Avatar storage

The [local avatar storage contract](../../docs/marmot-architecture/further-context/avatar-cache-storage.md) covers account-encrypted bytes, generation-scoped
references, atomic publication, offline local reads, bounded eviction and C7-B durable acquisition intent.
Selected presentation and source demand commit together; native screen integration remains C7-C.

## Migrations

Account/session schema changes go through Rust migrations. The runner and ordered registry live in
`src/migrations.rs`; migration bodies live in numbered files like `src/migrations/0001_initial_schema.rs`. Each
migration has a monotonically increasing integer version, a matching padded name, and an `apply` function that runs
inside a SQLite transaction. That function can execute DDL, rewrite rows, or perform more complex data-shape changes
when storage semantics evolve.

Applied migrations are recorded in `cgka_schema_migrations`. Opening an encrypted database applies any missing
migrations after SQLCipher keying and before storage handles are exposed.

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

Legacy token-only overflow retirement records a per-token retired watermark separately
from import. Clearing one token restores any other joined generations and returns
`false` while loss remains, preserving the runtime's pending flag across reopen.
Late duplicate writers cannot resurrect a retired generation; increased counts can.
The coordinated owner still owns qualified completion and bounded evidence reclamation.
