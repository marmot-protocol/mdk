# AGENTS.md - crates/storage-sqlite

Agent map for the SQLCipher-backed storage backend. Human overview, connection defaults, migration ledgers, and
recovery-ledger contracts: [`README.md`](README.md).

## Scope

`SqliteAccountStorage` (`src/protocol/handle.rs`) implements `cgka_traits::StorageProvider` with Marmot metadata and
custom OpenMLS storage in one encrypted SQLite database. One database file belongs to one Marmot account-device
identity. App storage has its own handle, `SqliteAppStorage` (`src/app/handle.rs`): it shares the account's connection,
and `SqliteAccountStorage::app_storage()` (`src/cross/handles.rs`) is the only way to get one. Every app and transport
method is on it. `SqliteAccountStorage` keeps the protocol traits, the open and close lifecycle, and the `cross/` entry
points that span both sides (`delete_local_group_data`, the draft observer's setter). A new app method goes on
`SqliteAppStorage`; one that must also touch protocol state in the same transaction goes in `cross/`. Protocol and base
code never call `app_storage()`, and app code outside `cross/` never names `SqliteAccountStorage` or a trait protocol
code implements for it; the names test treats each as a crossing (tests may hold both handles). `shared.rs`'s
`SqliteSharedStorage` is a deliberate exception: a separate, non-account-scoped database for cross-identity state — do
not "fix" it into the per-account database.

## Layout

The crate is split by which side owns each table.

| Folder | Holds |
| --- | --- |
| `src/base/` | Connection, codec, migration runner and bodies, open progress, test support. Both sides build on it. |
| `src/protocol/` | The engine's storage: its handle (`handle.rs`), the `StorageProvider` impls (`provider.rs`), `storage/` and `openmls_storage/`. |
| `src/app/` | App storage: projections, timeline, chat list, recovery ledger, drafts, attachments, avatars, media catalog. |
| `src/app/transport/` | App storage specific to one transport (NIP-77, NIP-51, relay-plane spill, NIP-59 outbox, QUIC sequences, prepared Blossom uploads), kept together for a later move. |
| `src/cross/` | Code that must touch both sides in one transaction, one named function per crossing; its `README.md` lists them. |
| `src/shared.rs`, `src/shared/` | The separate shared database. |

Put new code on the side that owns its tables. `src/base/boundary_tests.rs` fails on any crossing between the sides
(SQL naming the other side's tables, a `crate::` path or a `self` call into the other side, or a cross-side foreign key
or trigger) that is missing from `src/cross/allow-list.txt`, and on a listed one that no longer occurs. Do not add a
line to make a change pass: code that must touch both sides goes in a named `cross/` function, and a new line needs its
reason in the PR description. A new table needs an owner in `src/base/table_owners.rs`.

## Key files

| Path | Owns |
| --- | --- |
| `src/base/connection.rs` | SQLCipher key application, operational PRAGMAs, options, the shared connection and opening an account database. |
| `src/protocol/handle.rs` | `SqliteAccountStorage`, the engine's handle: open, close and the lifecycle around the shared connection. |
| `src/app/handle.rs` | `SqliteAppStorage`, the app side's handle over the same connection. |
| `src/base/codec.rs` | JSON serialization helpers and SQLite error mapping. |
| `src/base/migrations.rs` | Rust migration runner and migration tests. |
| `src/base/test_support.rs` | Shared storage test fixtures for both sides' tests. |
| `src/cross/migrated_template.rs` | Test support: `in_memory_for_test()` copies a migrated template that a test binary's processes share instead of replaying every migration; a copy draws its own per-database values. |
| `src/base/table_owners.rs`, `src/base/boundary_tests.rs`, `src/cross/allow-list.txt` | The owning side of every table; the boundary tests and the crossings that stay. |
| `src/base/migrations/` | Numbered Rust migration bodies plus upgrade/query-work tests; see its local `AGENTS.md`. |
| `src/protocol/storage/` | Marmot engine storage tables by concern; see its local `AGENTS.md`. |
| `src/protocol/storage/snapshots/` | Snapshot/checkpoint capture, restoration and the consistent replay-state fingerprint; see its local `AGENTS.md`. |
| `src/protocol/openmls_storage/` | Custom OpenMLS storage adapter; see its local `AGENTS.md`. |
| `src/app/account_recovery.rs` | Account-private recovery ledger, evidence import and durable retry reservations; `account_recovery/` holds typed joins, frozen scope checkpoints, loss acknowledgment and reach (where unresolved loss may have lost events, by route: `recovery_loss_reach` for one cause, `recovery_loss_reach_after` for what imports charged after a loss revision, which each import stamps on the generations it charged and which is unknown below the highest stamp an acknowledgment deleted), (`notice.rs`) parked "history may be incomplete" occurrences with their explicit retirement (`state = 2`, never coverage), (`stall.rs`) qualified stall observations, (`comparison.rs`) bounded operational comparison (never a coverage predicate), (`demand.rs`) typed joins for non-legacy callers, and (`observe.rs`) read-only transition facts for the owner's audit rows: a demand write's `RecoveryDemandTransition` read before and after it in the same transaction, and `recovery_obligation_status`. Transition reporting never changes demand. The app owner supplies validated facts and owns execution policy. |
| `src/app/account_recovery/convert.rs` | The one-time upgrade conversion of the old owner's obligations into ledger debt and runner retry state (mdk#2660 phase 4, migration 0136): resumable steps, each one transaction that advances the marker; converted rows deleted with counts by cause and disposition; loss un-covered by its reach, as imports charge it; the durable report and notice flag the worker acknowledges; the converted loss watermarks (`converted_recovery_loss`) until `reclaim_converted_recovery_loss` deletes the generations still at their converted counts. Dormant until the worker calls it. |
| `src/app/recovery_coverage.rs` | The coverage ledger (mdk#2660, shadow mode): proved `created_at` ranges per route, relay and proof, route goal floors, debt, un-covering for loss and released receipts (live boundaries never cover a released second; only a fetch proof covers it, on its own relay), the un-cover log that coverage writes subtract from, and retention pruning, which parks what current routes still owe below its floor before raising goals (no debt vanishes) and settles every route there, so only loss reopens what lies below. Nothing schedules or fences on it yet. |
| `src/app/recovery_units.rs` | The recovery runner's durable retry state (mdk#2660 phase 4, storage only): one row per (route, relay) unit, relay health and caps, the account's rolling-hour budget, parked and retired spans (never coverage), each route's parked remainder (debt the retention prune overtook; only dismissal clears it), each quantum outcome as one settle transaction, the re-arm rules and revision-checked dismissal, route-wide or scoped to the relays a notice shows. The runner owns the policy values. |
| `src/app/recovery_staging.rs` | Fetched history held for oldest-first admission: a proven slice's unseen events and its coverage in one transaction, oldest-first reads, removal once seen, and undecodable rows un-covered for refetch. |
| `src/app/transport/delivery_spill.rs` | Durable overflow tail of the in-memory account delivery queue: bounded spill, seen/released dedup, oldest-first reads and per-row removal after ingest. |
| `src/app/recovery_health.rs` | Durable reports of unsuccessful automatic synchronization recovery. |
| `src/app/transport/transport_reconciliation.rs` | Account-private NIP-77 set-reconciliation inventory. |
| `src/app/pending_welcome_delivery.rs` | Durable pointer to a confirmed create/invite whose Welcome publish failed, for re-delivery (mdk#352). |
| `src/app/device_group_messages.rs` | The kind of each device-group message this device sent or read whose withdrawal a feature acts on (mdk#2628, migration 0161), so the app can hand a withdrawal named only by message id (an own send's transport id, a received message's content id) to its feature. An own send is recorded by app event id before it goes out, and its message id filled in from the drain that publishes it. Rows go after a week, beyond 4,096, and with a local forget of their group. |
| `src/app/history_deliveries.rs` | Sealed history deliveries (mdk#2628 items 4.2b and 4.2c, migrations 0149 and 0166): the histories this device owes its siblings, when each was sent and when one going through Blossom is next uploaded, the chat and receiver of each delivery sent (so a withdrawal owes its history again), and deliveries parked until this device holds their chat or fetched their Blossom blob (at most 1,024). Rows go after a week and with a local forget of their chat. |
| `src/app/device_groups.rs` | The account's device groups this device knows of and how it came to know each (mdk#2628 item 3.1); at most one row claims the account's. Only `trust_device_group` moves a row into a trusted state, writing the compromise warning's first roster in the same transaction; `insert_device_group` and `set_device_group_trust` refuse one. |
| `src/app/device_renames.rs` | Renames this device made in its device group's roster (mdk#2628 item 3.6, D37), one row per device renamed: the label, the rename ids the rename wrote, and the ids the entry held where this device's renames of it were built. |
| `src/app/device_activity.rs` | Heartbeats in the device group (mdk#2628 item 3.6, D35): for each sibling the trusted roster lists, keyed to that entry's `linked_at` so a slot linked again starts afresh, when this device first found it there and the newest time one of its heartbeats counted for; and when, and in which device group, this device last sent its own. |
| `src/app/backup_recovery_key.rs` | The account's backup recovery key as a device that trusts no device group keeps it (mdk#2628 item 4.4a, migration 0163), one row: the public half of words confirmed then, which the roster this device founds carries. `trust_device_group` deletes it in the same transaction. Never the words or the private half. |
| `src/app/sign_ins.rs` | The account's sign-ins this device does not recognize (mdk#2628 item 3.2): one transaction per check, the first taking the baseline of every slot its read returned; this device's answers and rejections the roster does not record yet. |
| `src/app/compromise_warning.rs` | The account's compromise warning (mdk#2628 items 3.7a and 3.7b): every rejection it gathered and every KeyPackage this device found in its own slot that it did not make, seen or not, with per-device seen marks; a device's first trusted roster taken as seen, in the trust write (`trust_device_group`), or for a group trusted before migration 0148 at its first gather; an unseen rejected sign-in neither this device nor the roster holds dropped; a seen found KeyPackage kept for a KeyPackage's lifetime from when it was found, an unseen one until dismissed; rejection times past `i64::MAX` saturate rather than fail; at most 4,096 rows, the oldest going first, seen ones before unseen. |
| `src/app/device_links.rs` | The devices this device added to the account's device group and how each link ended, and the device groups it joined through a link whose first commit has not landed yet (mdk#2628 item 3.3b). |
| `src/app/private_key_packages.rs` | Private KeyPackages siblings handed to this device, keyed by issuer slot, and what this device still wants from each (mdk#2628 item 3.4b). A used one keeps its ref until it expires and is never kept again (D42). |
| `src/app/sibling_welcomes.rs` | Sibling Welcomes this device admitted from its trusted device group and has not joined from yet, keyed by their carrier's message id, at most 64 at once (mdk#2628 item 3.5b, migration 0160). A held row keeps its chat's id; a full stash drops its oldest held row for a new one. |
| `src/app/local_submissions.rs` | Device-local submission identity and durable admission before engine work. |
| `src/app/transport/agent_stream_sequences.rs` | Durable, fail-closed publisher sequence reservations for QUIC previews. |
| `src/app/account_projection.rs` | Account-level event projection. |
| `src/app/chat_list.rs` | Chat-list projection, including avatar URLs; `chat_list/` holds attention, pages, and windows. |
| `src/app/chat_list/small_state.rs` | Small state shared with the account's other devices (mdk#2628 item 4.3, migration 0161): each chat's read position, pin, mute and archive as items. One transaction records local changes (a local state that differs from what this device last observed), merges received items under the app's `SmallStateRule`, and applies winners; archives go back to the caller, which owns the in-memory account state. An item held at the highest version is put back, never changed. Invalid items, and chats whose MLS group id is over 256 bytes, are skipped, never stored. A read marker on a row no position names gives the furthest delivered message before it. Also this device's broadcast schedule: its last broadcast's time and tip, and whether it owes a broadcast request or an answer. |
| `src/app/chat_presentation.rs` | Durable selected-presentation foundation (runtime orchestration owns hydration). |
| `src/app/group_system.rs` | Local presentation of kind-1210 content (not a wire-format change). |
| `src/app/transport/user_blocks.rs` | Account-private NIP-51 block state; never stored in the shared database. |
| `src/app/transport/moderation_reports.rs` | Account-private outbox of signed NIP-59 moderation-report wraps: idempotency and rate-limit metadata, retry state, purge. Never stores the reported key or explanation in the clear. |
| `src/app/message_drafts.rs` | Revisioned encrypted composer drafts (`message_drafts/revisioned.rs`). |
| `src/app/transport/prepared_group_image_upload.rs` | Staged founding-image upload (component data + Blossom upload secret; keep both out of diagnostics). |
| `src/app/attachment_acquisition.rs` | Source-bound durable acquisition jobs, leased attempts, protected retained bytes, bounded worker demand and explicit-removal suppression. Network orchestration stays in marmot-app. |
| `src/app/attachment_acquisition/access.rs` | Read-only source-bound retained-asset lookup and opaque reference encoding; no demand registration. |
| `src/app/attachment_acquisition/controls.rs` | Durable user intent and coalesced transfer metadata in the job store. |
| `src/app/attachment_acquisition/partial.rs` | Attempt-fenced checkpoint rows: identity, recorded length, progress floor and the media store `.wire` file id (the ciphertext lives in that file, mdk#2314). Row operations only; abandoned-partial cleanup. |
| `src/app/attachment_acquisition/outgoing_media.rs` | File-backed outgoing uploads on the media store (mdk#2314 step 3): `reserve_attachment_upload`, `AttachmentUploadStage` (the upload row as the staged file's owner) and `AttachmentUploadPromotion` (the message's slot fences, attaching the file instead of copying bytes). Rows with `file_id` carry no bytes; legacy rows keep `outgoing.rs`'s promotion until they expire. No retained-byte budget. |
| `src/app/attachment_acquisition/legacy_migration.rs` | The database side of moving legacy SQLCipher bodies into the media store (mdk#2314 step 6): completed legacy bodies smallest first, `LegacyBodyReader` (one fenced read transaction per window; flags a body that is malformed as stored), `LegacyBodyPublication` (fenced on the legacy row), the row drops (a migrated drop requires a ready file in the slot; a corrupt drop leaves the slot completed without a body) and the remaining-bytes figure behind `AttachmentMigrationState`. No file I/O here. |
| `src/app/attachment_acquisition/keep_media.rs` | The opt-in "Keep media" setting (mdk#2314 step 10, migration 0116): `attachment_keep_media` (no row is Forever), the bounded sweep that removes retained attachments (and unfinished automatic downloads never explicitly requested) past the window through `storage_usage`'s removal with `RemovalReason::BySetting` (the window is re-read inside the removal transaction), and the automatic-demand gate. Age is the later of `attachment_history.received_at` and `attachment_acquisition.keep_from`, which only explicit requests set. A user's `Remove` relabels a cleaned slot as removed by you; never the reverse. |
| `src/app/storage_compaction.rs` | Returning the account database's free pages to the filesystem (mdk#2314 step 6; new databases are created incremental in `base/connection.rs::finish_account_open`, before WAL mode fixes the header): `DatabaseSpace`, the one-time `compact_database` (`auto_vacuum=INCREMENTAL` plus `VACUUM` between WAL checkpoints, refused inside a transaction) and bounded `reclaim_free_pages`. With `temp_store=MEMORY` a `VACUUM` builds its copy in memory: only the app runtime's gates decide when to call it. The `VACUUM` polls the close latch through a progress handler (`SharedConnection::closing_probe`), so a close (a host about to suspend) that begins while it builds its copy, `begin_close` included, stops it and it rolls back. Its final write-back of the copy (`sqlite3BtreeCopyFile`) cannot be interrupted: a close that lands there waits for it, so only a caller that keeps the live database within a small cap (the app runtime's 64 MiB) may call `compact_database`. WAL truncates never wait on readers and report whether they happened (`wal_checkpoint` signals a blocking reader in its busy column, not as an error); the connection records whether one is still owed (`wal_truncate_pending`, set only with the connection locked by the attempt itself, so no stale result overwrites a newer one), and callers retry with `truncate_wal`. |
| `src/app/attachment_acquisition/checkpoint.rs` | `AttachmentCheckpoint`: a claimed job's checkpoint as the media store's `CheckpointTarget`. The store drives the file and the order of steps; each target call is one transaction under the job's fences. |
| `src/app/media_catalog.rs` | The account database's side of the [`media-store`](../media-store/AGENTS.md) crate: `media_files`/`media_file_refs` rows (migration 0110), the `MediaCatalog` impl, per-use `PublishTarget`s and their one-transaction ready commits. Runs the crate's catalog conformance suite one test per case (`media_catalog_tests.rs`): the cases that restart on an encrypted file, the rest in memory; a guard test fails until a case added to `run_all` is listed there. No media file I/O here. |
| `src/media_store_bench.rs`, `examples/media_store_bench.rs` | `media-store-benchmarks` feature: the `media-store` file format against the SQLCipher retained path, runnable on devices (mdk#2314 step 0). |
| `src/app/attachment_history.rs` | Bounded canonical attachment-slot discovery and per-group revision-fenced cursors; source/visibility triggers maintain the derived index. |
| `src/app/timeline.rs` | Materialized message-timeline aggregation; `timeline/` holds capture, edits, chat history (`chat_history.rs`: the export page in chat order, and the insert-only import marked in `app_event_imports` and never unread, with its attachment keys in `imported_media_file_keys`, and each imported row's source named from the connection's TEMP `device_labels` table that `set_device_labels` fills and nothing stores), opening (`conversation_open` / `conversation_window`), presentation, and reports. |
| `src/app/avatar_cache.rs` | Account-scoped encoded avatar storage, source generations, local reads and eviction; `avatar_cache/acquisition.rs` owns durable demand/retry state, `avatar_cache/access.rs` owns opaque screen targets/local metadata, and `avatar_cache/files.rs` owns `AvatarPublication`, the cache-category `PublishTarget` (mdk#2314 step 9; `avatar_file_refs`, migration 0114) with its acquisition (attempt-fenced, settles the attempt) and migration (moves a database-held image without changing its revision or recency) modes, and the database side of the avatar migration. An image is database-held (`bytes`) or file-backed (`byte_len` plus a reference); `digest` alone says one is present, and clearing it schedules a refetch. |
| `src/app/encrypted_media_secrets.rs` | Per-group encrypted-media secret storage. |
| `src/shared/error.rs` | Shared-store redacting SQLite error mapper and result extension. |
| `src/shared/migrations.rs`, `src/shared/v*.sql`, `src/shared/legacy.sql` | Independent `shared_schema_migrations` runner, frozen per-version schemas, and recognized retired columns. |
| `src/shared/presentation.rs` | Accepted directory profile bytes and local revision under one shared-store transaction. |
| `src/shared/migration_tests.rs`, `src/shared/assurance_tests.rs`, `src/shared/fixtures/` | Shared migration contract, populated historical upgrades and bounded interrupted-transaction recovery. |
| `src/shared.rs` | `SqliteSharedStorage`: a separate non-account-scoped database for cross-identity state (public-directory cache and presentation, relay-telemetry/usage-diagnostics/audit-log settings, telemetry install id). |
| `fixtures/` | Immutable account-database compatibility fixtures; see `fixtures/README.md`. |

## Invariants

- Accept raw SQLCipher keys only. Key derivation and recovery live above this crate.
- Apply privacy/durability defaults unless callers opt out with `SqliteStorageOptions`. The only exceptions are the
  test helpers `in_memory_for_test()` (which this crate's own unit tests get from `in_memory()`) and
  `relax_storage_for_test_process()` (this crate's own unit tests start relaxed; see README). Keep `test-support`
  inert: nothing changes until a test calls a helper. Never call them from non-test code. The tests that pin the
  production settings (`encrypted_connection_applies_operational_defaults`, the `pins_cipher_pragmas_before_keying`
  tests) and the ignored benchmarks of file-backed storage call `use_production_storage_for_test_process()` before
  opening anything; a new one must too.
- Keep invalidated message records. Applications decide whether to show them.
- Prepare every database file with `fs_private::ensure_private_db_files` before `Connection::open`, and never open,
  read or copy a database or `-wal`/`-shm`/`-journal` sidecar through `std::fs` while this process may hold a
  connection to it: closing that descriptor drops the connection's POSIX locks and lets another process take the
  database under it. `connection::tests::reopening_a_live_database_keeps_its_posix_locks` guards this. See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
- Build every long-lived connection on `CloseableConnection` so a host can release the database's file locks at a known
  instant, and give its handle a `closer()` (`DatabaseCloser`, a weak reference) so a host can close it without keeping
  it open. Closing is terminal: surviving clones return `StorageError::Closed`, and nothing reopens implicitly. See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
- The media file lifecycle belongs to the `media-store` crate; this crate holds its metadata and never touches media
  files. Every `PublishTarget::commit_ready`/`commit_existing` is one transaction (fences, presence-checked reuse,
  ready, attach), and the catalog must keep passing the crate's conformance suite. Deleting a `media_files` row is the
  key erase (`secure_delete`); the file is unlinked afterwards by the store. See
  `docs/marmot-architecture/overview/local-artifact-safety.md#encrypted-media-files`.
- Retained-anchor policy is engine/group policy. SQLite stores snapshots and policy bytes; the engine decides when to
  prune.
- Follow `docs/marmot-architecture/storage-format-v2.md`: numbered schema migrations gate database compatibility;
  independently decoded blobs carry artifact-local versions; new `cgka_messages` writes use normalized format 2;
  legacy format-1 rows remain readable and promote atomically on mutation.
- Keep history-wide format promotion out of account open. The app runtime owns bounded post-readiness scheduling;
  storage owns only the atomic, idempotent batch and aggregate progress result.
- Never make `record` and normalized message columns competing authorities. In format 2, scalar columns, `payload`,
  and `deferred_peel` are authoritative and `record` is `NULL`.
- Migration file names use padded numeric prefixes, for example `0001_initial_schema.rs`. Never regenerate a
  version-named fixture with a later writer.
- Recovery-ledger, conversation-read, and replay-fingerprint contracts are stated in README.md; keep code and that text
  in sync. Never log or persist replay fingerprints.

## Verification

```sh
cargo test -p storage-sqlite
cargo clippy -p storage-sqlite --all-targets -- -D warnings
# Ignored file-backed v1 -> v2 operational benchmark:
just bench-storage-upgrade
# Media file format vs SQLCipher retained path (mdk#2314):
just bench-media-store
```
