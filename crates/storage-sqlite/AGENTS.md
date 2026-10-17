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

The crate is split by which side owns each table; see the
[step 4 brief](../../docs/marmot-architecture/review/brief-storage-boundaries.md).

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
| `src/base/table_owners.rs`, `src/base/boundary_tests.rs`, `src/cross/allow-list.txt` | The owning side of every table; the boundary tests and the crossings that stay. |
| `src/base/migrations/` | Numbered Rust migration bodies plus upgrade/query-work tests; see its local `AGENTS.md`. |
| `src/protocol/storage/` | Marmot engine storage tables by concern; see its local `AGENTS.md`. |
| `src/protocol/storage/snapshots/` | Snapshot/checkpoint capture, restoration and the consistent replay-state fingerprint; see its local `AGENTS.md`. |
| `src/protocol/openmls_storage/` | Custom OpenMLS storage adapter; see its local `AGENTS.md`. |
| `src/app/account_recovery.rs` | Account-private recovery ledger, evidence import and durable retry reservations; `account_recovery/` holds typed joins, frozen scope checkpoints, loss acknowledgment and (`notice.rs`) parked "history may be incomplete" occurrences with their explicit retirement (`state = 2`, never coverage), (`stall.rs`) qualified stall observations, (`comparison.rs`) bounded operational comparison (never a coverage predicate), (`demand.rs`) typed joins for non-legacy callers, and (`observe.rs`) read-only transition facts for the owner's audit rows: a demand write's `RecoveryDemandTransition` read before and after it in the same transaction, and `recovery_obligation_status`. Transition reporting never changes demand. The app owner supplies validated facts and owns execution policy. |
| `src/app/transport/delivery_spill.rs` | Durable overflow tail of the in-memory account delivery queue: bounded spill, seen/released dedup, oldest-first reads and per-row removal after ingest. |
| `src/app/recovery_health.rs` | Durable reports of unsuccessful automatic synchronization recovery. |
| `src/app/transport/transport_reconciliation.rs` | Account-private NIP-77 set-reconciliation inventory. |
| `src/app/pending_welcome_delivery.rs` | Durable pointer to a confirmed create/invite whose Welcome publish failed, for re-delivery (mdk#352). |
| `src/app/local_submissions.rs` | Device-local submission identity and durable admission before engine work. |
| `src/app/transport/agent_stream_sequences.rs` | Durable, fail-closed publisher sequence reservations for QUIC previews. |
| `src/app/account_projection.rs` | Account-level event projection. |
| `src/app/chat_list.rs` | Chat-list projection, including avatar URLs; `chat_list/` holds attention, pages, and windows. |
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
| `src/app/attachment_acquisition/checkpoint.rs` | `AttachmentCheckpoint`: a claimed job's checkpoint as the media store's `CheckpointTarget`. The store drives the file and the order of steps; each target call is one transaction under the job's fences. |
| `src/app/media_catalog.rs` | The account database's side of the [`media-store`](../media-store/AGENTS.md) crate: `media_files`/`media_file_refs` rows (migration 0110), the `MediaCatalog` impl, per-use `PublishTarget`s and their one-transaction ready commits, reference release. Runs the crate's catalog conformance suite. No media file I/O here. |
| `src/media_store_bench.rs`, `examples/media_store_bench.rs` | `media-store-benchmarks` feature: the `media-store` file format against the SQLCipher retained path, runnable on devices (mdk#2314 step 0). |
| `src/app/attachment_history.rs` | Bounded canonical attachment-slot discovery and per-group revision-fenced cursors; source/visibility triggers maintain the derived index. |
| `src/app/timeline.rs` | Materialized message-timeline aggregation; `timeline/` holds capture, edits, opening (`conversation_open` / `conversation_window`), presentation, and reports. |
| `src/app/avatar_cache.rs` | Account-scoped encoded avatar storage, source generations, local reads and eviction; `avatar_cache/acquisition.rs` owns durable demand/retry state and `avatar_cache/access.rs` owns opaque screen targets/local metadata. |
| `src/app/encrypted_media_secrets.rs` | Per-group encrypted-media secret storage. |
| `src/shared/error.rs` | Shared-store redacting SQLite error mapper and result extension. |
| `src/shared/migrations.rs`, `src/shared/v*.sql`, `src/shared/legacy.sql` | Independent `shared_schema_migrations` runner, frozen per-version schemas, and recognized retired columns. |
| `src/shared/presentation.rs` | Accepted directory profile bytes and local revision under one shared-store transaction. |
| `src/shared/migration_tests.rs`, `src/shared/assurance_tests.rs`, `src/shared/fixtures/` | Shared migration contract, populated historical upgrades and bounded interrupted-transaction recovery. |
| `src/shared.rs` | `SqliteSharedStorage`: a separate non-account-scoped database for cross-identity state (public-directory cache and presentation, relay-telemetry/usage-diagnostics/audit-log settings, telemetry install id). |
| `fixtures/` | Immutable account-database compatibility fixtures; see `fixtures/README.md`. |

## Invariants

- Accept raw SQLCipher keys only. Key derivation and recovery live above this crate.
- Apply privacy/durability defaults unless callers opt out with `SqliteStorageOptions`.
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
