# AGENTS.md - crates/storage-sqlite

Agent map for the SQLCipher-backed storage backend. Human overview, connection defaults, migration ledgers, and
recovery-ledger contracts: [`README.md`](README.md).

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
| `src/migrations/` | Numbered Rust migration bodies plus upgrade/query-work tests; see its local `AGENTS.md`. |
| `src/storage/` | Marmot engine storage tables by concern; see its local `AGENTS.md`. |
| `src/storage/snapshots/` | Snapshot/checkpoint capture, restoration and the consistent replay-state fingerprint; see its local `AGENTS.md`. |
| `src/openmls_storage/` | Custom OpenMLS storage adapter; see its local `AGENTS.md`. |
| `src/account_recovery.rs` | Account-private recovery ledger, evidence import and durable retry reservations; `account_recovery/` holds typed joins, frozen scope checkpoints, loss acknowledgment and (`notice.rs`) parked "history may be incomplete" occurrences with their explicit retirement (`state = 2`, never coverage), (`stall.rs`) qualified stall observations, (`comparison.rs`) bounded operational comparison (never a coverage predicate), (`demand.rs`) typed joins for non-legacy callers, and (`observe.rs`) read-only transition facts for the owner's audit rows: a demand write's `RecoveryDemandTransition` read before and after it in the same transaction, and `recovery_obligation_status`. Transition reporting never changes demand. The app owner supplies validated facts and owns execution policy. |
| `src/delivery_spill.rs` | Durable overflow tail of the in-memory account delivery queue: bounded spill, seen/released dedup, oldest-first reads and per-row removal after ingest. |
| `src/recovery_health.rs` | Durable reports of unsuccessful automatic synchronization recovery. |
| `src/transport_reconciliation.rs` | Account-private NIP-77 set-reconciliation inventory. |
| `src/pending_welcome_delivery.rs` | Durable pointer to a confirmed create/invite whose Welcome publish failed, for re-delivery (mdk#352). |
| `src/local_submissions.rs` | Device-local submission identity and durable admission before engine work. |
| `src/agent_stream_sequences.rs` | Durable, fail-closed publisher sequence reservations for QUIC previews. |
| `src/account_projection.rs` | Account-level event projection. |
| `src/chat_list.rs` | Chat-list projection, including avatar URLs; `chat_list/` holds attention, pages, and windows. |
| `src/chat_presentation.rs` | Durable selected-presentation foundation (runtime orchestration owns hydration). |
| `src/group_system.rs` | Local presentation of kind-1210 content (not a wire-format change). |
| `src/user_blocks.rs` | Account-private NIP-51 block state; never stored in the shared database. |
| `src/moderation_reports.rs` | Account-private outbox of signed NIP-59 moderation-report wraps: idempotency and rate-limit metadata, retry state, purge. Never stores the reported key or explanation in the clear. |
| `src/message_drafts.rs` | Revisioned encrypted composer drafts (`message_drafts/revisioned.rs`). |
| `src/prepared_group_image_upload.rs` | Staged founding-image upload (component data + Blossom upload secret; keep both out of diagnostics). |
| `src/attachment_acquisition.rs` | Source-bound durable acquisition jobs, leased attempts, protected retained bytes, bounded worker demand and explicit-removal suppression. Network orchestration stays in marmot-app. |
| `src/attachment_acquisition/access.rs` | Read-only source-bound retained-asset lookup and opaque reference encoding; no demand registration. |
| `src/attachment_acquisition/controls.rs` | Durable user intent and coalesced transfer metadata in the job store. |
| `src/attachment_acquisition/partial.rs` | Attempt-fenced SQLCipher ciphertext checkpoints, combined retained/partial byte accounting, bounded writes and abandoned-partial cleanup. |
| `src/attachment_history.rs` | Bounded canonical attachment-slot discovery and per-group revision-fenced cursors; source/visibility triggers maintain the derived index. |
| `src/timeline.rs` | Materialized message-timeline aggregation; `timeline/` holds capture, edits, opening (`conversation_open` / `conversation_window`), presentation, and reports. |
| `src/avatar_cache.rs` | Account-scoped encoded avatar storage, source generations, local reads and eviction; `avatar_cache/acquisition.rs` owns durable demand/retry state and `avatar_cache/access.rs` owns opaque screen targets/local metadata. |
| `src/encrypted_media_secrets.rs` | Per-group encrypted-media secret storage. |
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
- Build every long-lived connection on `CloseableConnection` so a host can release the database's file locks at a known
  instant. Closing is terminal: surviving clones return `StorageError::Closed`, and nothing reopens implicitly. See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
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
```
