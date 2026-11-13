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

Tests can opt out of two defaults, because memory security turns every SQLite allocation into system calls and a full
fsync per commit adds disk waits. Together they made up most of the workspace test lane's run time. Both helpers exist
only in this crate's own tests or with the `test-support` feature, and do nothing until a test calls them:

- `in_memory_for_test()` opens an in-memory store without `cipher_memory_security`, copied from a migrated template
  kept beside the test binary. The first store a build opens replays the migrations and writes the template; where the
  binary's directory takes no files, every store replays them. This crate's own unit tests get it from `in_memory()`;
  dependents call it explicitly.
- After a test process calls `relax_storage_for_test_process()`, every database it opens skips
  `cipher_memory_security` and uses `synchronous=NORMAL`. `marmot-app`'s constructors call it in its unit tests, and
  this crate's own unit tests start that way. The tests that pin the production settings never call it, and here they
  call `use_production_storage_for_test_process()` first.

Long-lived connections are closeable so a host can release file locks before suspending; closing is terminal and
surviving clones return `StorageError::Closed`.

`SqliteAppStorage::notification_policy_snapshot(label, account_id_hex)` returns committed notification settings with
their matching `notification_revision()`. It initializes missing defaults and rejects caller-owned transactions.
The revision is SQL-free and process-local. File-backed account handles opened by this crate share it by canonical
database path, including separate app and engine connections; in-memory handles have private revisions. TEMP
triggers advance it for projected-group, notification-policy, and chat-mute writes, including protocol forget.
Rollbacks may also advance it; repeating an unchanged policy or mute value does not. The snapshot captures its
revision while holding SQLite's write lock, before commit. Pair it with `connection_serial()` when caching across
opens. It is not persisted; writes through unwrapped connections or other processes are not observed.

The shared store is unencrypted and owner-only, with WAL, `synchronous=NORMAL`, a 5-second busy timeout, foreign keys
ON, `trusted_schema=OFF`, `temp_store=MEMORY`, and terminal close. See the
[app storage boundaries](../../docs/marmot-architecture/further-context/app-sqlite-storage-boundaries.md).

## Chat-list selection

A `ChatListViewQuery` is one of the four native `ChatListView`s plus an optional `ChatListFilter` (`All`/`Any`/`Not`
over stored chat facts and group-ID lists). It compiles to SQL appended to the view's condition, with every value
bound as a parameter, and pages, counts and selects through the view's page index; each leaf is a row column or a
keyed per-chat lookup, so cost grows with the view's chats, never with history. Queries are bounded (8 levels, 64
nodes, 500 group IDs, 1024 bytes of search text) and an over-bound query is a typed `ChatListQueryError` before any
read.
Conversation kind (`Direct`, `Group`) reads `chat_list_rows.list_kind`, which triggers keep equal to what the
classifier derives from the row's group name and member count; an Unknown kind matches neither. `Muted` tests the
mute settings against the read's `now_ms`, a bound parameter, so an expired mute needs no write; each read also
evaluates every row's `muted` at that time. A window read whose query tests `Muted` reports the next mute expiry
among the view's chats (`next_mute_expiry_ms`) so a live window can re-read then.
A `Text` leaf matches `chat_list_rows.search_text`, which `store_chat_presentation` writes from the literal title,
group name, description and the direct-chat peer names preparation passes in (`search_peer_names`); localized
fallback titles are not searchable. Fields and query are normalized by `normalize_search_text` (trim, Unicode
lowercase; user directory search uses the same function) and matched as a literal substring of one field with
`instr`, so `%` and `_` are literal. While any chat in the view has pending presentation, a `Text` query is not ready
(`ProjectionNotReady` from the selection calls, `SearchTextNotReady` from a window read);
`chat_list_pending_search_text(view, limit)` lists those chats so a caller can prepare a batch and retry.
A `MessageText` leaf matches chats with a visible chat message or poll question containing the text, by the same rule,
through the `marmot_search_contains` SQL function every account connection registers (timeline `search` uses it too).
It scans each chat's history, so only the selection calls accept it; a window read refuses it with
`ChatListQueryError::MessageTextInWindow`. While the content-report backfill is owed it is not ready.
`ChatListFilter::from_nodes` builds the tree from the bindings' flat node list. A `ChatListView` converts into the
unfiltered query.

Every read is self-contained. `read_chat_list_window`, `chat_list_ids` and `revalidate_chat_list_ids` each run in one
read transaction, and no cursor carries a position into a later read, so filtered and fixed queries behave alike. A
live window keeps its place by re-reading around a stable anchor chat ID; paging grows the window rather than
continuing a stored page.

`chat_list_ids(query, now_ms)` returns every chat ID the query matches, in display order, from one read transaction before
any display paging. It reads no presentation, profile, roster or history blobs. Pending base-row work returns
`ProjectionNotReady` rather than a falsely complete result; the runtime finishes its bounded base-row preparation
before retrying.

`revalidate_chat_list_ids(query, ids, now_ms)` returns the subset of `ids` still matching, in the caller's order with
duplicates dropped. It only removes: chats that matched since are never added. Both calls are stateless;
hosts keep the selection. A bulk action revalidates first, and each per-chat command still enforces its own
preconditions: this read is not an atomic authorization for a later write.

## Migrations

Migration 0204 drops the timeline rows of own sends that failed and were then deleted. Such a send reached no one, so
the projection no longer gives it a row; its source row stays in `app_events`. A deleted send a peer reacted to (or
whose receipt retention kept) was received after all: it is settled as delivered and keeps its placeholder.

Migration 0203 adds a nullable `member_outcomes_json` column to prepared group-image uploads. The app writes a versioned
member-resolution report before canonical creation and keeps it when the upload is consumed. Idempotent retries read
that original report instead of inferring recipient failures from a later roster. Existing rows retain `NULL`; a retry
of an already-created group returns `CreatedGroupMemberReportUnavailable` with its canonical id rather than inventing
an original report.

Migration 0180 records whether a complete removal was valid and its exact target, independently of the sender's
moderation authority. Tag recovery cannot make an invalid decision valid. Validated removals survive retention and tag
damage, including decisions with permitted extra tags. The upgrade classifies existing records only where the original
shape can be proven. For uncertain legacy records, it preserves only target-specific hides already present at upgrade;
uncertain decisions cannot hide newly seen targets. Those preserved hides remain subject to source withdrawal and
invalidation. They do not establish original validity; [verified legacy repair](https://github.com/marmot-protocol/mdk/issues/3017)
is separate, and already-erased content cannot be restored.

Migration0170 adds native local-copy admission metadata and app invitation-decision rows; no existing group is seeded.
It runs for every account database, including builds with device groups disabled, creating two tables and two partial
indexes. Native creation/join writes the local admission association transactionally; it adds no per-message writes.
The admission generation and exact successful local Welcome association are captured in the native join transaction;
founding records a local origin instead. They remain fixed across ordinary epoch changes, are replaced only by a new
successful native admission, and are deleted with local group data. Decision rows are keyed by raw MLS chat id and
generation and retain their winning value, owed publication and pending application/Leave handoff atomically. Unknown
admissions create no membership work; the actual matching native join re-arms them. Full broadcasts enumerate retained
generations, including after a local chat is forgotten. There is no clock-based generation eviction.

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

**Pending publication references.** Migration 0175 seeds an account-device high-water from retained fanouts and group
evolutions once. An undecodable legacy artifact aborts that migration: without an independent bound, skipping it could
reuse a saved recovery handle. Subsequent artifact writes raise the full-width `u64` bound in the same transaction;
deletion and group snapshot restoration never lower it. Engine construction reads only this independent metadata, so
later payload corruption is isolated by per-group hydration. Missing or malformed metadata fails closed. Exhaustion
refuses new native staging before mutation; already saved references can still be restored and settled.

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
`mls_write_generation`, and the caller's transaction stays open. The exception is a transaction SQLite rolls back by
itself (a full disk, an I/O error or out of memory mid-statement, a trigger's `RAISE(ROLLBACK)`): the unit's error comes
back, the rest of the caller's transaction fails instead of committing write by write, and the connection stays usable
for the next one. Canonical convergence apply uses it in place of a full
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

`message_timeline` combines `TimelineMessageQuery`'s literal, Unicode-lowercased substring search with an exact
sender match, an inclusive `since` and exclusive `until` on `timeline_at`, and an attachment type. All filters apply
before the page limit. `TimelineAttachmentType` reads individual `imeta` tags, independently of the decoded media
column: image, video, and audio match case-insensitive MIME prefixes. File matches an attachment without any of
those prefixes, including an unknown MIME type. A message with an image and a separate file matches both filters.
Attachment matches any `imeta` tag; Any leaves attachments unfiltered.
Malformed or non-array tag blobs and non-array tag entries do not match attachment filters.

Group reads use canonical epoch order by default. `search_wall_clock = true` selects wall-clock order instead.
Account-wide searches with that flag order by `(timeline_at, message_id_hex, group_id_hex)` and require
`cursor_group_id` alongside a before or after cursor. The cursor compares the same complete tuple, with
`before_inclusive` including the exact cursor row. Pages remain bounded by `MAX_TIMELINE_LIMIT`, including filtered
searches over longer histories. The default timeline and retention wall-clock query keep their existing cursor
semantics.

`conversation_open` composes a bounded canonical timeline page with retained read state in one read-only snapshot,
supporting first-unread/latest opening and scoped anchor recovery; dirty projections return `ReadStateNotReady` for the
existing owner to refresh. `conversation_window` adds explicit context placement around a retained anchor (latest
targets always read the tail). `conversation_account_snapshot` captures that window, system provenance, presentation
inputs, draft descriptors, and persisted controls in one deferred read. `StorageProvider::with_read_snapshot` composes
public storage calls under one deferred transaction, enforcing and restoring SQLite query-only mode even when nested.
See the [opening contract](../../docs/marmot-architecture/further-context/conversation-opening.md).

A sibling's read position (small state, mdk#2628 item 4.3) advances the read marker as a local read does, but keeps a
manual-unread reminder. It may name a message this device does not hold yet: unread counts compare canonical order
keys, not ids. The position this device sends is the furthest delivered message, other than an edit, at or before its
read marker, so a marker on a synthesized group system row or an undelivered send still has one.

Selected composer reads and revision-checked mutations share the encrypted draft tables; migration 0073 tracks legacy
writes too, and queued/fanout acceptance clears only its submitted revision atomically. See the
[draft contract](../../docs/marmot-architecture/further-context/conversation-drafts.md).

The [local avatar storage contract](../../docs/marmot-architecture/further-context/avatar-cache-storage.md) covers
account-encrypted bytes, generation-scoped references, atomic publication, offline local reads, bounded eviction, and
durable acquisition intent; selected presentation and source demand commit together.

## Account recovery ledger

`account_recovery.rs` and `account_recovery/` keep the old recovery owner's account-private tables for the
account-open conversion and the epoch-gap obligations the recovery runner serves (mdk#2660 phase 4). The app-side
runner supplies validated facts and owns execution policy. Design:
[account recovery](../../docs/marmot-architecture/further-context/account-recovery.md); ownership history: the
[#1946 ownership design](https://github.com/marmot-protocol/mdk/blob/9489bb091/docs/marmot-architecture/further-context/account-recovery-ownership.md).

- **Loss evidence.** The overflow marker task, the notification-lag writer and a discarded spill row write loss
  evidence only; the worker imports it into ledger debt transactionally. A NULL imported count means not yet
  imported, including a valid zero-count loss marker. Zero-count loss is evidence.
- **Frozen scopes (`account_recovery/plan.rs`).** The old owner's versioned scope payloads. Nothing writes a new one;
  conversion reads their checkpoints. Inventory expiration, compaction, message release and route or group deletion
  void the checkpoints of the scopes they overlap (the exact event for known-event scopes) in the same transaction,
  so conversion never counts removed input as coverage. Receipt release records scoped invalidation before deleting
  inventory; consumption falls back to conservative invalidation only if neither inventory bounds nor that durable
  flag exist. No-op admission never scans recovery scopes, and idempotent deletes void nothing.
- **Demand and notices (`account_recovery/demand.rs`, `notice.rs`).** Epoch-gap demand the runner arms and serves,
  and terminal-group retirement, which deletes the group's epoch-gap, maintenance and
  known-event rows atomically with its failure report. A parked occurrence is one "history may be incomplete"
  notice; dismissal retires exactly that revision (`state = 2`, never coverage).
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
  nothing. Each delivery or notification loss import un-covers in its own transaction what the generations it newly
  charged lost. A generation recorded through
  `record_account_recovery_loss_routed` with its routes (migration 0128, at most `MAX_LOSS_ROUTES`) un-covers only
  those routes, each from its own bound, and widens their goals; any other generation un-covers every route the ledger
  holds from its floor upward (all of it when a floor is unknown) and widens their goals to it. Imports stay
  count-driven, since the relay plane gives an adopted marker's new drops a fresh token. A worker observation past the
  durable count records the relay plane's routes for its generation through `record_account_recovery_loss_routed`,
  merged as a marker write's are, and makes the generation account-wide when it passes none. `recovery_loss_reach`
  reads where one cause's unresolved loss may have lost events, by route.
  `uncover_recovery_coverage` does the same for the given routes only, for the `CopyFloorReason` its caller names. A released receipt (`cross/release.rs`) un-covers its event's second on each route its inventory row
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
  floor. A released receipt below the window changes nothing in the ledger (its coverage stays until the prune), so only loss parks debt from below it. The recovery
  runner schedules on it.
- **Epoch-gap return visits (`recovery_epoch_gap.rs`, migration 0150).** An unresolved missing epoch has a durable
  visit count, active-visit marker, exhaustion state and next retry time. Beginning a visit and reopening its
  retained goals commit together. Restart resumes ledger progress; observations and revised tickets at the same
  epoch preserve the budget. A higher missing epoch or explicit repair can start a fresh budget. Exhaustion
  parks the existing EpochGap obligation without claiming coverage or MLS recovery. Storage schedules nothing;
  the account's recovery runner owns these visits.
- **Retry state and staging (`recovery_units.rs`, `recovery_staging.rs`, migration 0127, mdk#2660).** One row per
  `(route, relay)` unit holds the recovery runner's retry state: active, broken (no progress or refused, with a park
  revision and one probe a newer loss can earn) or retired, plus backoff, slicing, planned relay caps and re-check progress. Relay health (unreachable streak, cooldown, NIP-11 caps), the account's rolling-hour attempt and
  byte budget, each unit's parked and retired spans and the capture ranges it fences (migration 0135) sit beside it. `settle_recovery_unit` applies one quantum's
  outcome in one transaction with policy values the caller passes; `settle_recovery_unit_saturated` also records
  the second an answered quantum stopped on because its relay cannot prove it (`saturated_second`, migration 0151),
  which only an answered quantum sets or clears and a change in the relay's recorded caps clears; a unit's debt is the route goal minus that relay's
  coverage, its retired spans and, unless it holds a probe, its parked spans. Parked and retired spans are never
  coverage. `stage_recovery_slice` writes a proven slice's unseen events and its coverage, through the subtracting
  write, in one transaction, so a crash before settlement refetches nothing; staged rows leave once seen. A re-check
  settles through `settle_recovery_recheck`, which charges its relay and the account budget but never touches the
  unit's retry state, and records its pass's progress only under the revision it began on (migration 0134): every
  request that makes the pass due, a long relay cooldown ending among them, bumps it in the same write.
  `staged_recovery_routes` and `recovery_unit_fences` tell the runner which groups to read, and
  `reclaim_staged_recovery_routes` gives back what a route it no longer lists staged. The recovery runner
  schedules on this state.
- **Rejoins (`recovery_copies.rs`, migration 0153, mdk#2660 row 11).** `account_recovery_copies` keeps, per group,
  the install epoch of the local copy the runner last settled, a rejoined copy's floor and the one notice a rejoin
  raises; `account_recovery_copy_routes` records each of the group's routes that floor holds on, with relays or
  without, and `account_recovery_copy_units` each relay of those routes that retired what lay below it. Forgetting a
  group, or deleting a terminal one, drops all three with its engine record. The migration seeds
  every existing group with the copy its engine record holds then (unknown only when the record does not decode), so
  a rejoin from before it raises nothing and one applied after it, even before the runner's first turn, does. `settle_recovery_rejoin`
  settles a copy the app calls a rejoin in one transaction: on each relay of each of the group's routes, what the unit
  owes or parked below the new copy's floor becomes a `BeforeThisCopy` retired span (never coverage; earlier
  retirements keep their reasons), its fences below the floor drop, and it restarts active with a fresh budget; each
  route's remainder below the floor goes; the floor, the routes and those relays are recorded; and the notice is raised under a
  new park revision. It returns false, changing nothing, for a copy already settled. `retire_before_recovery_copy`
  records each carried route and does the same retirement, below the recorded floor, on each carried relay not yet
  recorded (one that joined a route after the rejoin, or returned to one it had left before), once per relay, so loss
  or repair that later reopens it stays reopened. `record_recovery_copy` settles any other copy and clears an earlier
  rejoin's floor, routes, relays and notice; `dismiss_recovery_rejoin_notice` clears the notice at its revision and retires nothing more.
  `recovery_copy_floor` reads the recorded floor. Every write that widens a goal or un-covers coverage names a
  `CopyFloorReason`, and `Clamp` keeps it at or above the highest floor recorded for its route (`copy_floor_tx`: one
  probe of `account_recovery_copy_routes_by_route` and a copy lookup in the same transaction; a route no rejoin
  settled reads no row and is not clamped). So `widen_recovery_coverage_goals`, `uncover_recovery_coverage` and
  `begin_recovery_epoch_gap_retry` stop at the floor, whoever begins the visit, and the retention prune parks nothing
  below it, with relays or without (a route keeps one remainder, which would otherwise join a second owed below the
  floor to debt above it). Only `Loss` (loss
  import and the upgrade conversion) and `Repair` (explicit repair) reach below it, and so does one second the device
  held: a released receipt, or a staged row given back, un-covers its own second, so the re-check fetches it again.
  That second alone is owed: when it lies below the route's goal, the seconds its goal widening opens below the floor
  lay outside the goal, owed nothing, and retire as `BeforeThisCopy` in the same transaction
  (`retire_opened_before_copy_tx`).
  `recovery_copy_debt` is a route's debt on one relay less what a rejoin retired there.
  Retired spans stay in the re-check, loss inside them reopens them and explicit repair re-arms them; a relay that
  leaves the route keeps every span retired below the floor, with its reason, through
  `retire_gone_recovery_units`, so its return owes only from the floor.
- **Upgrade conversion (`account_recovery/convert.rs`, migration 0136, mdk#2660 phase 4).**
  `convert_recovery_obligations` turns the old owner's queue-loss, notification-loss, explicit, incremental and
  native-replay obligations into ledger debt and runner retry state, once, before the runner first starts.
  Epoch-gap, known-event and maintenance obligations stay, except a satisfied epoch gap: the old owner satisfied one
  once its relays answered, never once the engine left the stalled epoch, so the last step reopens it as pending and
  ready at its next revision, with its scopes (mdk#3059). The caller passes what storage does not have: every
  current route (the inbox included, so routing is hydrated) with its required relays and standing floor, the
  ledger's spelling of a relay a stored scope names, the retention floor and the time. Each step is one transaction
  that also advances the marker (`recovery_conversion_pending`), so a crash leaves every row intact or converted and
  gone, the next call resumes, and a finished conversion does nothing. In order: phase 2's live-boundary ranges and
  shadow remainders are dropped (comparison, sweep and re-check ranges stay), goals settle at the window floor and
  every current route's standing goal starts; dismissed rows retire their uncertified scopes' windows on the relays
  they recorded, below where live loss reaches that route; live loss un-covers what it reached once, as an import
  charges it (a generation that named its routes reaches only those, from their bounds; any other reaches every route
  from its floor), parks what lies below the window, and counts as imported; parked rows break their routes' required relays that still owe history,
  under one revision per route (one notice), keeping the earliest park time; a pending explicit repair re-arms every
  unit; satisfied rows go and satisfied epoch gaps reopen. Converted rows are deleted with their scopes, with no third
  state, and nothing becomes coverage. `recovery_conversion_report` keeps the counts by cause and disposition, and the
  reopened epoch gaps (`epoch_gaps_reopened`, migration 0152), until `acknowledge_recovery_conversion_report`, and `recovery_conversion_notices_changed` asks for one announcement of
  the changed "history may be incomplete" notices. Converted loss evidence stays, imported and with no obligation;
  `converted_recovery_loss` lists it by account and cause until the worker has finished the relay plane's overflow
  recovery and calls `reclaim_converted_recovery_loss`, which deletes each generation still at its converted count
  (newer or grown loss stays for the import). After conversion, `import_recovery_loss_to_ledger` imports only
  new or grown evidence into ledger debt, without creating old-owner obligations. It uses the same route and
  retention inputs, un-covers the generations' reach and keeps below-window debt parked, atomically with the
  imported counts and the converted-loss set. Duplicate observations leave subsequent fetch
  proof intact. The existing `converted_recovery_loss` and reclaim handoff also own these later generations.

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

### Delivered sibling-Welcome repair

One row per original Welcome retains its latest successfully published carrier's immutable first actual acceptance
time and a prepared-carrier timestamp high-water. Exact Welcome bytes, private KeyPackage reference, expiry and
originating Add remain engine-owned. Acceptance time commits with the zero-to-positive fanout receipt transition,
before replayable publication output; an already-accepted legacy fanout with no time stays unknown. Duplicate
projection cannot retime a generation, and an older carrier cannot replace the currently prepared carrier. Failed or
unexposed exact retries keep their reservation; a backward wall clock cannot reuse an earlier prepared identity.

Repair reads existing D35 `device_activity` for the current roster entry's slot and `linked_at`. Only a counted
heartbeat at least 600 seconds after that publication time qualifies; first sighting, link activity and arbitrary DG
traffic do not. Unknown publication time never qualifies. The app reuses its bounded 32-row per-Welcome keyset walk;
there is no new timer, source-proof recovery or per-message observation write. Engine participation and delivery
checks still decide whether a qualifying Welcome can be sent. Heartbeat cadence and clock skew make repair best
effort, not a receipt or proof that the target lacks its chat.

Migration 0174 drops the obsolete D90/D91 processed-wrapper observation indexes, per-Welcome activity/deadline indexes
and local ordering-clock table. The permanent processed-wrapper markers remain. Old nullable source-proof/activity
columns and the old group epoch cutoff remain inert to avoid rebuilding the protocol ledger solely to erase them;
no runtime path reads or writes them. Known publication times and carrier high-water values survive the upgrade.

### Backup history provenance and catalog

Migration 0168 keeps existing sibling import slots and permits a checked alternative backup source in
`app_event_imports`. `import_app_events` remains supported for siblings;
`import_app_events_with_provenance` inserts actual device-or-backup provenance atomically with new content, carried
attachment keys and its returned projection. Existing live rows win. The same joined source supplies the additive
`TimelineMessageRecord::history_import_provenance` in incremental, paged and conversation reads. The legacy
`imported_from`/device-label fields remain sibling-only. Backup identity identifies fetched archive bytes, not a
verified writer, historical author or membership grant. Imported rows retain the existing unread, retention and media
key lifecycle.

`backup_restore_catalog` and its indexed chat metadata contain recovery **public** keys and archive availability in
the encrypted account database. An index is never a transcript, group, route or membership. Replacing an archive's
index is atomic, and pruning one completely discovered key's pointer leaves other old keys and imported provenance
alone. The app owns actual current-own-leaf admission and ephemeral secret/job lifecycle; words, entropy, recovery
private keys and archive keys never belong in these tables.

## Reaction artwork sources

Active kind-7 reactions retain their encrypted `imeta` slots in the attachment
index even though reactions are modifiers and have no standalone timeline row.
Migration 0167 backfills these sources from retained events. Normal event
projection maintains them in the same transaction as reaction tallies; unchanged
slots survive timeline rebuilds. Author retractions, convergence withdrawals,
retention and group deletion revoke their sources through the ordinary
acquisition lifecycle. Host applications resolve artwork through
[`reaction_attachment`](../marmot-uniffi/ATTACHMENT-HISTORY.md#reaction-artwork)
and use the returned source slot with existing acquisition and local-read APIs.

### Experimental device-group moves

Migration 0176 adds finite local move records for every account database, including builds with device groups disabled.
A validated expected roster Welcome records Joined inside the native join transaction. The session's present-selected
Made proof then captures old roster facts, switches the one trusted row, retires old App delivery/edit debt and owes the
existing full small-state broadcast/request in one transaction. Taken private-KeyPackage references remain tombstones;
rejections carry slot facts, never rejected KeyPackages. Already admitted native group-pinned work is not recalled.
Detached history results carry their preparation's trust row only in memory and act only while it and their original
owed revision or received delivery remain current. No persistent history journal is introduced.

Custom `DeviceGroupWelcomeStorage` providers retain the default exact expectation consumption but must adopt the
transactional admission hook to provide move bookkeeping; the default does not promise move recovery. Updated
providers must also preserve `Group.device_roster_departures` through group writes and snapshots. Legacy stored groups
decode with an empty field, without inventing past departure causes; Rust struct-literal constructors need the new
field. The hook runs only on an actual validated expected DeviceRoster Welcome. Ordinary message receive adds no move query. The native
Group snapshot adds selected roster-departure metadata only for roster groups; ordinary groups keep the empty default.
