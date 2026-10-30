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

The crate is split by which side owns each table:

- `base/` — SQLCipher keying, connection setup and options, opening an account database, the codec, and the
  account/session migration runner with its numbered bodies (`base/migrations/`).
- `protocol/` — the engine's storage: its handle `SqliteAccountStorage` (`handle.rs`), the `StorageProvider` impls,
  `storage/` (Marmot engine tables by concern: groups, messages, snapshots, outbound intents, Welcomes, capabilities,
  convergence, maintenance, transport routes and more) and `openmls_storage/` (the custom OpenMLS adapter).
- `app/` — app-facing projections and account state: account event projection, chat list, the materialized timeline
  and conversation opening, message drafts, attachments, avatar cache, encrypted-media secrets, account recovery, and
  `media_catalog.rs`, the metadata for the encrypted per-file media store in the
  [`media-store`](../media-store/README.md) crate (the bodies are files that crate owns). `app/transport/` holds the
  transport-specific app storage: delivery spill, NIP-77 reconciliation, user blocks, the moderation outbox, agent
  stream sequences and prepared group-image uploads.
- `SqliteAppStorage` (`app/handle.rs`) — the app side's handle, over the same connection; get it with
  `storage.app_storage()`. Every app and transport method is on it, except the two that also change engine state:
  `delete_local_group_data` and `set_message_draft_commit_observer` stay on `SqliteAccountStorage`, in `cross/`.
- `cross/` — the code that must touch both sides in one transaction, one named function per crossing.
- `shared.rs` + `shared/` — `SqliteSharedStorage`, a separate, non-account-scoped database for cross-identity state
  (public-directory cache and presentation, relay-telemetry, usage-diagnostics and audit-log settings, the telemetry
  install id), with its own migration runner.

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

Account/session schema changes are Rust migrations: the ordered registry lives in `src/base/migrations.rs` and bodies in
numbered files like `src/base/migrations/0001_initial_schema.rs`. Each has a monotonically increasing version, a matching
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

**Group savepoints.** Nested `with_transaction` calls join the outermost transaction and roll back only there.
`StorageProvider::with_group_savepoint` is the nested unit that rolls back on its own: on `Err` or panic a SQLite
`SAVEPOINT` undoes every write the unit made, drops the after-commit wakeups it registered and moves
`mls_write_generation`, and the caller's transaction stays open. Canonical convergence apply uses it in place of a full
group snapshot, so its rollback cost no longer grows with stored history (mdk#2326).
`StorageProvider::rollback_group_state_keeping_live_records`, the rewind onto a retained anchor that a reorg's apply and
the convergence probes use, restores canonical state only, even from a legacy full anchor, and leaves message,
pending-event and queue rows untouched, so it does not grow with stored history either (mdk#2330).

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
- **Native replay.** `SubscriptionReplay` preserves original query floors across source changes and reopen. Its
  `ReplayAdmission` predicate proves only current native input admission, never exhaustive history or loss recovery.
  Request-scoped placement facts preserve qualified, unchanged sources independently of unrelated pending groups.
  Same-group waiting peers still withhold that group's proof. `checkpoint_replay_admission` requires the separate
  `RecoveryReplayPlacement::Placed` account-wide fence before final completion, even when every scoped proof exists.
  Authoritative terminal-group retirement is revision-fenced and preserves unrelated floors. A wanted range with
  no serving source parks as `NeedsDeepRepair` without retry charges or loss evidence; unchanged observations leave
  it parked. A new source generation can rearm the original range. Retirement and source updates reject stale route
  or scope tokens atomically. Public notice dismissal retires the occurrence; it does not mark the range satisfied.
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
- **Coverage ledger (`recovery_coverage.rs`, migration 0123, mdk#2660).** Per route (the inbox or a group's transport
  route) and relay, the inclusive `created_at` ranges proved complete, each with its proof (live boundary, comparison
  certificate, sweep slice, re-check), plus each route's goal floor. `record_recovery_coverage` is the one write entry
  point for a covered `(route, relay, since, until, proof)` slice; it merges overlapping or touching ranges of the same
  route, relay and proof and keeps the oldest proof time. Coverage on a route is what every given relay covers, merged
  across proofs. Debt is the goal floor up to a caller-given time minus that coverage; a route without a goal owes
  nothing. Each delivery or notification loss import, and a legacy clear that re-arms an older generation, un-covers in
  its own transaction what the generations it newly charged lost. A generation recorded through
  `record_account_recovery_loss_routed` with its routes (migration 0128, at most `MAX_LOSS_ROUTES`) un-covers only
  those routes, each from its own bound, and widens their goals; any other generation un-covers every route the ledger
  holds from its floor upward (all of it when a floor is unknown) and widens their goals to it. Imports stay
  count-driven, since the relay plane gives an adopted marker's new drops a fresh token. A worker observation past the
  durable count (`mark_account_delivery_recovery_observed`) merges the relay plane's routes for its generation as a
  marker write would, lowering the generation's floor to the lowest bound they list, and makes the generation
  account-wide when it passes none. Each import stamps every generation it charges with the loss
  revision its join left (`import_revision`, migration 0132). `recovery_loss_reach` reads where one cause's unresolved loss
  may have lost events, by route, and `recovery_loss_reach_after` reads the same for loss imported after a loss
  revision: what a checkpoint captured at that revision has not seen. Acknowledgment deletes the generations it
  reclaims and keeps the highest stamp it deleted (`acknowledged_import_revision`), so below it the read answers
  `None`: where that loss reached is no longer known.
  `uncover_recovery_coverage` does the same for the given routes only. A released receipt (`cross/release.rs`) un-covers its event's second on each route its inventory row
  placed it on. Live boundaries never cover that second again, since the REQ that delivered the event will not
  deliver it again; only a fetch proof (comparison, sweep slice, re-check) covers it, on its own relay, and the hold
  ends when retention pruning passes it. A release with no inventory row leaves
  the ledger to the epoch gap it arms. Every un-cover is also
  appended to the un-cover log (migration 0126) under a new account generation. `recovery_coverage_mark` reads that
  generation before a fetch, and `record_recovery_coverage_since` subtracts from its slices every range un-covered
  on their routes after the mark, or records nothing once the log (an hour, at most 4,096 rows) no longer reaches
  back to it. `prune_recovery_coverage` drops coverage below the retention floor, raises goals to it and ages the log;
  pruning is not an un-cover. First, what each route the caller passes still owes below the floor on any of its
  certifying relays joins the route's parked remainder (migration 0130): one range per route under a park revision,
  never coverage, cleared only by dismissal. The prune then marks every route settled below its floor, and a later
  prune parks only from that mark up, so a goal widened back below it parks nothing twice; loss lowers the mark to its
  floor. A released receipt below the window changes nothing in the ledger (its coverage stays until the prune), so only loss parks debt from below it. The ledger is in
  shadow mode: no obligation, retry, fence or schedule reads it.
- **Retry state and staging (`recovery_units.rs`, `recovery_staging.rs`, migration 0127, mdk#2660).** One row per
  `(route, relay)` unit holds the recovery runner's retry state: active, broken (no progress or refused, with a park
  revision and one probe a newer loss can earn) or retired, plus backoff, slicing, planned relay caps and re-check progress. Relay health (unreachable streak, cooldown, NIP-11 caps), the account's rolling-hour attempt and
  byte budget, each unit's parked and retired spans and the capture ranges it fences (migration 0135) sit beside it. `settle_recovery_unit` applies one quantum's
  outcome in one transaction with policy values the caller passes; a unit's debt is the route goal minus that relay's
  coverage, its retired spans and, unless it holds a probe, its parked spans. Parked and retired spans are never
  coverage. `stage_recovery_slice` writes a proven slice's unseen events and its coverage, through the subtracting
  write, in one transaction, so a crash before settlement refetches nothing; staged rows leave once seen. A re-check
  settles through `settle_recovery_recheck`, which charges its relay and the account budget but never touches the
  unit's retry state, and records its pass's progress only under the revision it began on (migration 0134): every
  request that makes the pass due, a long relay cooldown ending among them, bumps it in the same write.
  `staged_recovery_routes` and `recovery_unit_fences` tell the runner which groups to read, and
  `reclaim_staged_recovery_routes` gives back what a route it no longer lists staged. Nothing schedules on
  this state yet.
- **Upgrade conversion (`account_recovery/convert.rs`, migration 0136, mdk#2660 phase 4).**
  `convert_recovery_obligations` turns the old owner's queue-loss, notification-loss, explicit, incremental and
  native-replay obligations into ledger debt and runner retry state, once, before the runner first starts.
  Epoch-gap, known-event and maintenance obligations stay. The caller passes what storage does not have: every
  current route (the inbox included, so routing is hydrated) with its required relays and standing floor, the
  ledger's spelling of a relay a stored scope names, the retention floor and the time. Each step is one transaction
  that also advances the marker (`recovery_conversion_pending`), so a crash leaves every row intact or converted and
  gone, the next call resumes, and a finished conversion does nothing. In order: phase 2's live-boundary ranges and
  shadow remainders are dropped (comparison, sweep and re-check ranges stay), goals settle at the window floor and
  every current route's standing goal starts; dismissed rows retire their uncertified scopes' windows on the relays
  they recorded, below where live loss reaches that route; live loss un-covers what it reached once, as an import
  charges it (a generation that named its routes reaches only those, from their bounds; any other reaches every route
  from its floor), parks what lies below the window, and counts as imported, generations no import charged yet under
  a new loss revision they are stamped with; parked rows break their routes' required relays that still owe history,
  under one revision per route (one notice), keeping the earliest park time; a pending explicit repair re-arms every
  unit; satisfied rows go. Converted rows are deleted with their scopes, with no third state, and nothing becomes
  coverage. `recovery_conversion_report` keeps the counts by cause and disposition until
  `acknowledge_recovery_conversion_report`, and `recovery_conversion_notices_changed` asks for one announcement of
  the changed "history may be incomplete" notices. Converted loss evidence stays, imported and with no obligation;
  `converted_recovery_loss` lists it by account and cause until the worker has finished the relay plane's overflow
  recovery and calls `reclaim_converted_recovery_loss`, which deletes each generation still at its converted count
  (newer or grown loss stays for the import). Nothing calls the conversion yet.

## Tests and benchmarks

```sh
cargo test -p storage-sqlite
just bench-storage-upgrade   # ignored file-backed format v1 -> v2 operational benchmark
just bench-media-store       # media file format vs the SQLCipher retained-attachment path
```

**Media store benchmark** (`media-store-benchmarks` feature, `examples/media_store_bench.rs`): for 64 KiB, 1 MiB and
100 MiB bodies it times the file format in memory, writing and reading private files, and today's
SQLCipher import (`complete_attachment_acquisition_from_reader`) and `read_retained_attachment`, and prints
`MDK_BENCH media_store ...` lines. `MDK_MEDIA_BENCH_SIZES`, `MDK_MEDIA_BENCH_ITERATIONS` and `MDK_MEDIA_BENCH_DIR`
override the defaults. The example cross-compiles for Android (`adb push`, run from `/data/local/tmp`), and
`media_store_bench::run_media_store_benchmark` can be called from a throwaway iOS app. The format itself lives in
[`media-store`](../media-store/README.md). Results for mdk#2314 step 0
are recorded on the issue.

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


Media upgrades 0104 and 0105 preserve existing payload pages during account open. Retained legacy bodies gain a sentinel length column with validation/accounting on mutation; they retain the legacy byte-array bound, while larger files use the chunk tables. Already-upgraded stores keep their compatible physical layout. Partial upgrades replace only parent metadata: the migration runner suspends connection-local foreign-key enforcement before BEGIN, validates the affected parent/child references before commit, and restores the original setting on success, rollback and unwind. Checkpoint chunks are preserved in place; no migration ledger is relabeled. Optional encrypted-open observation reports fixed phases and schema numbers without paths, SQL, keys or user data.
