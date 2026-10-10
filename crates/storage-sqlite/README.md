# storage-sqlite

SQLCipher-backed implementation of the `cgka_traits::StorageProvider` aggregate, plus the app-facing projections and
durable account state that live in the same encrypted account database. Read this if you open, migrate, or reason
about Marmot's on-disk state.

Marmot metadata tables and a custom OpenMLS `StorageProvider<CURRENT_VERSION>` share one SQLite connection on purpose:
group snapshots and rollback must be atomic across Marmot records and group-scoped OpenMLS state.

## Contents

- [Layout](#layout)
- [Operational boundary](#operational-boundary)
- [Migrations](#migrations)
- [Recovery semantics](#recovery-semantics)
- [Conversation reads](#conversation-reads)
- [Chat-list selection](#chat-list-selection)
- [Account recovery ledger](#account-recovery-ledger)
- [Tests and benchmarks](#tests-and-benchmarks)

## Layout

- `connection.rs` — SQLCipher keying, connection setup, options, and the aggregate `SqliteAccountStorage` handle.
- `storage/` — Marmot engine tables by concern (groups, messages, snapshots, outbound intents, Welcomes, capabilities,
  convergence policy and passes, deferred-peel generations, maintenance, transport routes, and more).
- `openmls_storage/` — the custom OpenMLS adapter (`provider.rs`, `value_store.rs`, `labels.rs`).
- App-facing projections and account state: account event projection, chat list (including avatar URLs), the
  materialized timeline and conversation opening, message drafts, attachments, avatar cache, encrypted-media secrets,
  account recovery, delivery spill, transport reconciliation, user blocks, and more.
- `shared.rs` — `SqliteSharedStorage`, a separate, non-account-scoped database for cross-identity state: the
  public-directory user cache and presentation, relay-telemetry, usage-diagnostics and audit-log settings, and the
  telemetry install id.
- `migrations.rs` + `migrations/` — account/session migration runner and numbered bodies; `shared/migrations.rs` —
  the independent shared-store runner.

The complete module map is in [`AGENTS.md`](AGENTS.md).

## Operational boundary

Callers provide a non-empty raw SQLCipher key. The crate applies it and verifies the database opens, but never derives,
rotates, escrows, recovers, or prompts for keys; those policies belong to the account/session layer above.

One database belongs to exactly one Marmot account-device identity. Separate encrypted files per account/device make
deletion and account separation straightforward and avoid cross-identity state sharing.

Default connection settings are privacy/durability oriented:

- raw SQLCipher key provided by the caller
- `journal_mode=WAL`
- `synchronous=FULL`
- `busy_timeout=5000`
- `foreign_keys=ON`
- `secure_delete=ON`
- `temp_store=MEMORY`
- `trusted_schema=OFF`
- `cipher_memory_security=ON` process-wide; Android reports a once-per-process `platform_limited` diagnostic because
  its finite `mlock` budget makes memory residency best effort, while SQLCipher still sanitizes allocations on free

Override with `open_encrypted_with_options` or `in_memory_with_options`. There is no first-class key rotation: create a
new encrypted database, migrate data, and replace the old file.

Long-lived connections are closeable so a host can release file locks before suspending; closing is terminal and
surviving clones return `StorageError::Closed`.

The shared store is unencrypted and owner-only, with WAL, `synchronous=NORMAL`, a 5-second busy timeout, foreign keys
ON, `trusted_schema=OFF`, `temp_store=MEMORY`, and terminal close. See the
[app storage boundaries](../../docs/marmot-architecture/further-context/app-sqlite-storage-boundaries.md).

## Chat-list selection

`chat_list_selection_snapshot(view)` captures all eligible IDs for one of the four native `ChatListView`s in one
read transaction, before display pagination. It uses the view's indexed predicate and ordering and reads no
presentation, profile, roster or history blobs. Pending base-projection work returns `ProjectionNotReady` rather
than a falsely complete result. The runtime must finish its existing bounded base-row preparation before retrying.

The transient snapshot belongs to one connection lifetime and database epoch. Clones of that account store may
use it; a foreign store or reopened connection returns `StaleSelection`, and terminal close preserves
`StorageError::Closed`. Debug output contains only the view and count. The snapshot itself holds no connection
lease and is never persisted.

`chat_list_selection_count` returns the full frozen count; `chat_list_selection_page` returns at most 200 IDs from
an offset in the captured order. New arrivals, activity reordering and window eviction do not expand that intent.
`revalidate_chat_list_selection` returns its still-eligible subset in the original order, never adding new IDs.
Use the returned snapshot for subsequent validation to retain removals. Batch actions must revalidate first and
still enforce their own mutation preconditions: this read is not an atomic authorization for a later write.

Capture and revalidation use O(eligible IDs) work and memory, independently of profile/history size; each page
copies at most 200 IDs. This storage primitive does not implement automatic-folder expressions, binding handles
or host selection UI. Those callers must retain account/view generations, explicit cancellation and progress
while resolving complete intent instead of deriving it from visible rows.

## Migrations

Account/session schema changes are Rust migrations: the ordered registry lives in `src/migrations.rs` and bodies in
numbered files like `src/migrations/0001_initial_schema.rs`. Each has a monotonically increasing version, a matching
padded name, and an `apply` function run inside a SQLite transaction, which can execute DDL, rewrite rows, or perform
larger data-shape changes. Applied migrations are recorded in `cgka_schema_migrations`; opening an encrypted database
applies missing migrations after SQLCipher keying and before storage handles are exposed. Message rows follow
[storage format v2](../../docs/marmot-architecture/storage-format-v2.md).

The three app database categories have independent histories, and no runner reads another store's ledger:

| Database | Ledger |
| --- | --- |
| `session.sqlite` (per account-device) | `cgka_schema_migrations` |
| `app-cache.sqlite3` (per account, owned by `marmot-app`) | `app_cache_schema_migrations` |
| `shared.sqlite3` (per installation) | `shared_schema_migrations` |

**Shared store.** Version `1 / 0001_shared_store` establishes the five original live tables (frozen in
`shared/v1.sql`); later versions add usage diagnostics and directory presentation. Each body and its ledger row commit
in one immediate transaction; failure rolls back both. Recorded versions and names must be an exact prefix of the
compiled registry, and future versions return `StorageError::UnsupportedSchemaVersion`. A pending opener rechecks the
prefix under the write lock; an already-current opener validates history using reads only.

Unversioned shared tables must match frozen current or verified historical definitions (`shared/legacy.sql`) before
adoption. Validation covers columns, types, nullability, defaults, primary and foreign keys, CHECK expressions,
collations, and indexes. Conservative DDL comparison can refuse equivalent but unrecognized SQL; incompatible shapes
fail with static errors and no version row. Missing tables are created. Public users, ordered follows, live settings,
timestamps, installation identity, and rowids are preserved. Existing unused directory tables stay untouched, and
their pre-existing orphaned rows do not gate adoption. The recognized nullable `otlp_endpoint` column (inline or
appended) is retained but non-NULL values are cleared transactionally; retained audit `data_mode` columns stay inert.
No full-data audit mode is reintroduced. SQLite errors keep extended result codes and transient BUSY/LOCKED
classification without SQLite's database-controlled message. Fixture provenance and assurance limits:
[`src/shared/fixtures/README.md`](src/shared/fixtures/README.md).

Account-database compatibility fixtures are described in [`fixtures/README.md`](fixtures/README.md). Old binaries
refuse an upgraded schema; downgrading a binary requires a pre-upgrade backup.

## Recovery semantics

**Retained anchors** are engine/group policy, not hidden SQLite policy. `max_rewind_commits` defaults to `5` when no
group policy is stored, and the engine persists negotiated policy bytes per group. Retained anchor snapshots are pruned
after successful stable canonicalization advances the tip. Invalidated message records are kept as audit/debug
evidence so applications can decide whether to surface them.

**OpenMLS proposal queues** are recoverable cached state. If `queued_proposals()` finds a `ProposalQueueRefs` entry
whose `QueuedProposal` is missing (a dangling ref) or undeserializable (truncation, partial write, format skew), the
backend clears the whole proposal queue for that group and returns it empty. It never loads a partial subset: a later
commit must start from current MLS group state and require proposals to be re-enqueued. Only deserialize failures are
treated as recoverable; SQLite/lock failures propagate so a transient fault is never mistaken for corruption.

**Replay-state validation.** `group_replay_state_fingerprint` takes a consistent read of live canonical/OpenMLS state
(as a state-scoped snapshot) plus all retained snapshot/checkpoint bytes and epochs. It excludes live message,
outbound, and app-projection rows, which the engine validates separately. The fingerprint stays in engine memory and
is never logged or persisted. It lets resumable reconstruction ignore unrelated writes through another app connection;
the `mls_write_generation` contract for cached `MlsGroup` objects is unchanged.

**Deferred recovery preparation.** `MessageStorage::list_deferred_message_metadata` preserves insertion order and exact
encoded payload lengths while omitting payload blobs. The engine uses it for sweep preparation and readiness, then
fetches full records only for selected attempts, retirement, or bounded lifecycle normalization. Legacy format-1 rows
still need their record blob until bounded promotion converts them. The default trait implementation remains
compatible with other backends.

## Conversation reads

`conversation_open` composes a bounded canonical timeline page with retained read state in one read-only snapshot,
supporting first-unread/latest opening and scoped anchor recovery; dirty projections return `ReadStateNotReady` for the
existing owner to refresh. `conversation_window` adds explicit context placement around a retained anchor (latest
targets always read the tail). `conversation_account_snapshot` captures that window, system provenance, presentation
inputs, draft descriptors, and persisted controls in one deferred read. `StorageProvider::with_read_snapshot` composes
public storage calls under one deferred transaction, enforcing and restoring SQLite query-only mode even when nested.
See the [opening contract](../../docs/marmot-architecture/further-context/conversation-opening.md).

Selected composer reads and revision-checked mutations share the encrypted draft tables; migration 0073 tracks legacy
writes too, and queued/fanout acceptance clears only its submitted revision atomically. See the
[draft contract](../../docs/marmot-architecture/further-context/conversation-drafts.md).

The [local avatar storage contract](../../docs/marmot-architecture/further-context/avatar-cache-storage.md) covers
account-encrypted bytes, generation-scoped references, atomic publication, offline local reads, bounded eviction, and
durable acquisition intent; selected presentation and source demand commit together.

## Account recovery ledger

`account_recovery.rs` and `account_recovery/` own the durable account recovery ledger, evidence import, and retry
reservations. The app-side owner supplies validated facts and owns execution policy. Design:
[account recovery](../../docs/marmot-architecture/further-context/account-recovery.md); ownership history: the
[#1946 ownership design](https://github.com/marmot-protocol/mdk/blob/9489bb091/docs/marmot-architecture/further-context/account-recovery-ownership.md).

- **Loss evidence.** The overflow marker task writes loss evidence only; the owner imports it transactionally. A NULL
  imported count means not yet imported, including a valid zero-count loss marker. Zero-count loss is evidence.
- **Reservations.** Attempt reservations fence selected demand and imported loss, survive reopen, and refuse unknown
  scope versions. They do not certify coverage. Repeated serialized callers reuse the explicit-history row without
  resetting retry, and a stale detach cannot clear the current caller's urgency.
- **Frozen scopes (`account_recovery/plan.rs`).** Versioned frozen scopes accept owner-validated endpoint/admission
  checkpoints. History requires all designated scopes/endpoints; exclusions, EOSE, and SDK seen state are insufficient.
  Known-event retention and the limited first maintenance boundary use separate predicates. A stale scope token
  rejects a multi-scope checkpoint before any progress is written. Domain updates may share one `with_transaction`.
- **Loss acknowledgment (`account_recovery/loss.rs`).** Qualified loss completion is separate from external plane
  acknowledgment. Capture exact token/count watermarks before execution; after qualified completion, acknowledge the
  matching live generation and finish its writers before calling `acknowledge_recovery_loss`. The runtime uses
  `recovery_loss_snapshot` / `acknowledge_recovery_loss_snapshot`: a constant-size SHA-256 commitment to the complete
  ordered token/count set, streamed under the connection lock, so unbounded unresolved evidence is never copied into
  active grants, capped, or deleted. Both forms share the same transaction and revision/qualification checks. SQL
  cannot establish the external acknowledgment prerequisite. New evidence or a persistence failure prevents
  reclamation; the owner must compensate the live acknowledgment and call `restore_unacknowledged_recovery_loss`
  before new work, and also when constructing an owner.
- **Legacy adapters.** Legacy clear methods are caller-directed retirement adapters, not completion proofs; retained
  legacy watermarks do not recreate explicitly retired demand. Token-only overflow retirement records a per-token
  retired watermark separately from import: clearing one token restores other joined generations and returns `false`
  while loss remains, preserving the runtime's pending flag across reopen. Late duplicate writers cannot resurrect a
  retired generation; increased counts can.
- **Comparison plans.** Format-1 plans still accept the retired optional `live_since_seconds` field from older
  databases, but recovery ignores it and new writes omit it. A normal settlement rewrites a legacy plan without
  changing its fence, route scopes, retry cost, or uncovered demand. Other unknown fields and malformed legacy values
  remain errors; no schema migration or plan-format change is required.
- **Inventory revision.** Inventory expiration, compaction, message release, and route/group deletion bump the account
  inventory revision in the same transaction; reservations and plan installation check it. Installed proof is
  invalidated only for overlapping route/window scopes (and the exact event for known-event predicates), so unrelated or
  out-of-window retention churn cannot invalidate bounded completion or loss acknowledgment. Removing the last
  qualified proof reopens satisfied demand in the same transaction without forgiving account retry cost; an
  alternative known-event copy or independent maintenance boundary remains valid. Receipt release records scoped
  invalidation before deleting inventory; consumption falls back to conservative invalidation only if neither
  inventory bounds nor that durable flag exist (including journal rows migrated from older schemas). No-op admission
  never scans recovery scopes, and idempotent deletes do not invalidate proof.
- **Retention.** `retained_recovery_event` checks exact route, event, and frozen window membership after the caller
  synchronizes release receipts; it does not certify successful decryption or engine readiness. Completed known-event
  rows need owner-managed reclamation once no ticket or grant can reference them. An unbounded `since = None` includes
  older retained input, so its retirement must invalidate proof. The owner must use finite automatic goals, preserve
  uncovered older-history debt, and never silently clip an explicit full-history request to the retention floor.
- **Migrations.** 0092 replaced the overflow and epoch-demand tables while keeping their Rust storage methods as
  adapters; 0093 added the route-policy snapshot, a unique explicit-history row, and a receipt-journal invalidation
  flag, preserving populated obligations, loss evidence, retry state, receipts, maintenance, inventory, and cursors.
  Unexpected duplicate explicit rows make migration fail atomically; no demand is silently discarded. Later
  migrations add stall observations, recovery comparison, the loss `created_at` bound, and history notices.

## Tests and benchmarks

```sh
cargo test -p storage-sqlite
just bench-storage-upgrade   # ignored file-backed format v1 -> v2 operational benchmark
```

**Deferred recovery preparation benchmark** (opt-in, paired, encrypted temporary files):

```sh
MDK_DEFERRED_PREPARATION_BENCHMARK_OUT=target/deferred-preparation.json \
  CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p storage-sqlite \
  --lib deferred_metadata_file_backed_benchmark -- --ignored --nocapture
```

It generates 0/4,096 processed and 0/64/512/2,048 deferred rows with 4 KiB payloads over 17 epochs, includes
persisted lifecycle fields, alternates query order, and writes ten warmed samples (after two warmups) to the requested
private JSON file. Reported blob bytes count full-record values materialized in Rust, excluding SQLite pages, metadata
values, and filesystem cache. It measures storage enumeration, not retained MLS context construction or scheduler
wake pressure, and asserts no timing threshold. A 2026-09-06 local run with 4,096 processed plus 2,048 deferred rows
took about 29.8 ms for the full-row query versus 15.1 ms for metadata, avoiding 8 MiB of payload copies per query. The
query still enumerates all deferred metadata so an unattempted row beyond a previously attempted prefix stays visible.
