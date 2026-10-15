---
title: "Review Map — Durable State Authority"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, system-map, storage]
status: draft
---

# Review Map — Durable State Authority

Part of [Pass 0](00-system-map.md). Baseline `9c95ff2bf`. This page lists every durable store an installation
creates, what each holds, who writes it, and whether it is authoritative or derived. It is descriptive. Observations
at the end are inputs to Pass 1 systems C and D. "(inferred)" marks a claim reasoned from code but not traced. The
existing contract for the three SQLite tiers is
[`app-sqlite-storage-boundaries.md`](../further-context/app-sqlite-storage-boundaries.md).

## 1. Stores

| Store | Path | Encryption | Authority | Writers | Rebuildable? |
| --- | --- | --- | --- | --- | --- |
| Session DB | `accounts/<label>/session.sqlite` (`crates/marmot-app/src/lib.rs:396`) | SQLCipher; HKDF key over the account secret plus a per-DB salt (`crates/marmot-app/src/sqlcipher.rs:568-608`) | Authoritative: protocol state, OpenMLS key material, recovery ledgers, and app projections | Two connections; see §3 | No |
| Per-DB salt and rekey marker | `<db>.salt`, `<db>.salt-migrating` (`sqlcipher.rs:40-42`) | Plaintext, 0600 | Authoritative key input; losing the salt makes the DB unreadable | `sqlcipher.rs:354-406`, `:534-560` | No |
| Directory cache | `accounts/<label>/app-cache.sqlite3` (`lib.rs:393`) | SQLCipher | Derived directory and search data, plus public event previews | `directory/`, `public_event_preview.rs` | Mostly, from relays |
| Shared DB | `<root>/shared.sqlite3` (`lib.rs:394`) | Plaintext, 0600 (`crates/storage-sqlite/src/shared.rs:147-158`) | Mixed: settings, consent and the telemetry installation id are authoritative; public directory rows are derived | Directory mirror, telemetry and audit settings, analytics | Settings no; directory yes |
| Account catalog and journals | `accounts/<label>/account.json`, `.account-setup*.json`, `onboarding*.json`, `key-security.json`, `replaceable-floors.json` (`crates/marmot-account/src/home.rs:21-27`, `:615-810`) | Plaintext; `account.json` and `key-security.json` are written world-readable (`crates/marmot-account/src/io.rs:69-71`) | Authoritative | `AccountHome` | No |
| Signing secret | OS keychain (`crates/marmot-account/src/keyring.rs:79-140`), file store `accounts/<label>/secret.json` (`crates/marmot-account/src/secret_store.rs:80-135`), or a host-provided store (`crates/marmot-uniffi/src/secret_store.rs:30-55`) | Keychain: OS. File store: plaintext hex, 0600 | Authoritative | `AccountHome` | No |
| External-signer DB secret | Secret-store entry `.external-sqlcipher/<label>` (`home.rs:188-202`, `:936-1000`) | Per secret store | Authoritative | `AccountHome` | No |
| Audit logs and cursors | `audit-<engine>-v5.jsonl` in 1 MiB segments, `audit-key-reveal.jsonl`, `audit-upload-checkpoint.json`, `audit-otlp-delivery-v5/` (`crates/marmot-app/src/audit_log.rs:39-49`; `crates/marmot-forensics/src/audit.rs:60-73`) | Plaintext; privacy-safe derived values | Opt-in evidence; cursors are resendable | `marmot-app`, `marmot-forensics` | No |
| Root runtime lease | `<root>/.marmot-runtime.lock` (`crates/marmot-app/src/root_runtime_lease.rs:16`) | n/a | Cross-process ownership lock (`flock` on Unix) | Leased constructor only (`lib.rs:1795-1817`) | n/a |
| Media staging | `accounts/<label>/media-staging/` (`crates/marmot-app/src/client/mod.rs:596`) | Plaintext snapshots and ciphertext temp files | Transient; stale files swept after 24 h | `media/file_transfer.rs` | Yes |
| Legacy imports | `<root>/app-cache.sqlite3`, `accounts/<label>/app.sqlite3`, `<root>/key-packages/` | Mixed | Import-only sources | Import code | n/a |
| CLI and connector files | `wnd.sock`, `wnd.pid`, `wnd.log`, `settings.json` (`crates/cli/src/daemon/lifecycle.rs:71-81`); `wn-agent` sockets, allowlists and idempotency files | Mixed | Mixed | `cli`, `agent-connector` | Mostly |

Migration ledgers: `session.sqlite` has 109 numbered migrations in `cgka_schema_migrations`
(`crates/storage-sqlite/src/migrations.rs:252-910`); `app-cache.sqlite3` has 2 and `shared.sqlite3` has 3. Each
migration body and its ledger row commit in one transaction (`migrations.rs:1119-1160`).

## 2. What `session.sqlite` holds

One database per account-device carries both the protocol authority and the product's projections.

| Domain | Main tables | Authority | Writers |
| --- | --- | --- | --- |
| OpenMLS state | `openmls_values` | Authoritative; secret-bearing | Engine connection, through `SqliteOpenMlsStorage` sharing the engine's connection (`crates/storage-sqlite/src/connection.rs:1160-1162`) |
| Groups, routes, capabilities, convergence | `cgka_groups`, `cgka_transport_group_routes`, `cgka_convergence_passes`, `cgka_deferred_peel_generations`, member capability tables | Authoritative | Engine. The app connection also deletes `cgka_groups` rows for terminal groups (`crates/storage-sqlite/src/account_projection.rs:1545-1565`). |
| Message ledger and transport identity | `cgka_messages`, `cgka_ingress_dedup`, `cgka_processed_transport_ids`, `cgka_released_transport_receipts` | Authoritative; dedup is a cache | Engine |
| Outbound | `cgka_queued_outbound`, `cgka_outbound_fanout`, `cgka_transport_fanout`, `cgka_own_commit_intents` | Authoritative | Engine, through session setters |
| Welcomes | `cgka_welcomes`, `app_pending_welcome_delivery` | Engine table authoritative; app table is a derived index | Engine / app |
| Snapshots and checkpoints | `cgka_group_snapshots`, `cgka_group_state_checkpoints` | Authoritative rollback anchors; full snapshots copy raw OpenMLS rows | Engine |
| Maintenance, leave, disband | `cgka_key_package_lifecycle`, `cgka_maintenance_obligations`, `cgka_group_evolutions`, leave and disband tables | Authoritative; disband tombstones are permanent | Engine |
| Pending application events | `pending_application_events`, `pending_application_authority` | Authoritative outbox from engine to app | Engine writes in the ingest transaction; app acknowledges after its projection commits |
| Timeline | `app_events`, `message_timeline`, `message_modifier_edges`, agent stream rows | Decrypted plaintext; derived from the engine outbox | App connection (`crates/marmot-app/src/lib.rs:6526-6625`) |
| Account projection | `account_state`, `seen_events`, `account_groups`, push and notification tables, group-deletion frontiers | Mixed | App; the engine also writes `seen_events` (`crates/storage-sqlite/src/storage/messages.rs:1079-1086`) |
| Chat list and presentation | `chat_list_rows`, unread and pin tables, `conversation_read_state`, `chat_presentation_*` | Derived, except read state | App, plus triggers |
| Drafts and local submissions | `message_drafts*`, `local_message_submissions` | Authoritative user input | App stages; the engine consumes drafts inside its outbound transaction (`crates/storage-sqlite/src/storage/outbound.rs:50`, `:253`) |
| Moderation and blocks | `content_reports*`, `user_blocks*`, `moderation_report_outbox` | Authoritative | App |
| Recovery ledger and health | `account_recovery_*`, `account_delivery_loss_evidence`, `app_epoch_stall_evidence`, `app_group_recovery_failures` | Authoritative | App, plus the engine through message release and route deletion |
| Delivery spill | `account_delivery_spill` | Authoritative until ingested; 8,192 rows / 16 MiB | App, from relay-plane closures (`lib.rs:4602-4617`) |
| Transport reconciliation | `transport_reconciliation_*` | Inventory derived; floor authoritative | App and engine |
| Attachments | `attachment_acquisition`, `retained_attachment_files`, `retained_attachment_chunks`, `attachment_partial*`, `attachment_retention_usage`, `attachment_history*`, `outgoing_attachment_*` | Bytes re-downloadable (inferred); usage counter and history maintained by triggers | App |
| Avatars | `avatar_assets`, `avatar_access`, `avatar_acquisition*` | Derived cache | App |
| Encrypted media secrets | `encrypted_media_epoch_secrets*` | Cached exporter-derived keys with a retirement barrier | App |

There are 131 `CREATE TRIGGER` statements in non-test `storage-sqlite` source. They maintain derived tables
(notification suppression, attachment history, retained-byte usage, chat-list navigation and presentation queues)
inside whichever transaction performs the write.

## 3. Connections and transactions

**Two connections per account to `session.sqlite`.**

- The **engine connection** is opened by `AccountDeviceSession::open` (`crates/cgka-session/src/lib.rs:336-345`). The
  engine, OpenMLS storage and a maintenance clone share it.
- The **app connection** is cached in `MarmotApp.account_storages` (`crates/marmot-app/src/lib.rs:6480-6511`).
  Projections, recovery, relay-plane spill and loss closures, attachments and drafts all use clones of it.

Each connection is one `rusqlite::Connection` behind a mutex, with an in-process transaction owner
(`connection.rs:181-199`, `:330-345`). There is no pool. `with_transaction` uses `BEGIN IMMEDIATE` with bounded BUSY
retries (`connection.rs:28-44`, `:701-719`) and flattens nested calls without savepoints (`connection.rs:582-588`).
Between the two connections, coordination is SQLite file locking with a 5 s busy timeout (`connection.rs:954`). Cache
invalidation combines an in-process write counter with `PRAGMA data_version`, so the engine notices the app
connection's commits (`connection.rs:1386-1404`).

The session PRAGMAs are WAL, `synchronous=FULL`, `secure_delete=ON`, `foreign_keys=ON` and
`cipher_memory_security=ON` (`connection.rs:950-963`). No `auto_vacuum`, `wal_autocheckpoint` or
`journal_size_limit` is set, and nothing runs `VACUUM` outside tests. Close runs `wal_checkpoint(TRUNCATE)`
(`connection.rs:242-262`).

**The engine-to-projection bridge is an outbox.** The engine persists `MessageReceived` and `GroupJoined` into
`pending_application_events` in the ingest transaction, and the app acknowledges them only after its projection
transaction commits (`crates/marmot-app/src/client/sync.rs:5790-5796`). A crash between the two replays the event, so
projection is at-least-once. Other engine events are memory-only; see
[the engine map](map-engine-contract.md#1-what-engines-holds).

## 4. Where bytes live

| Bytes | Location | Bounds |
| --- | --- | --- |
| Retained attachments | `retained_attachment_chunks` in `session.sqlite`, 64 KiB rows (migration 0106) | Per item: 900 MiB file-backed, 512 MiB legacy (`crates/storage-sqlite/src/attachment_acquisition.rs:14-18`). Per account: 2 GiB by default, with no automatic eviction (`crates/marmot-app/src/config.rs:70-82`). |
| Download partials | `attachment_partial*` | 1 MiB checkpoints, counted with retained usage |
| Outgoing uploads | `outgoing_attachment_upload_files`, sharing the chunk store | Counted in the same usage counter |
| Avatars | `avatar_assets` | 10 MiB each; 128 MiB or 2,048 entries total (`crates/storage-sqlite/src/avatar_cache.rs:18-21`) |
| Event previews | `public_event_previews` in `app-cache.sqlite3` | 256 KiB each; 1,024 rows or 16 MiB total |
| Upload staging | Files under `media-staging/` | Swept after 24 h; the only attachment bytes outside SQLCipher |

## Observations for Pass 1

1. **Each account DB has two writers, and projections never share the engine's transaction.** This is a deliberate
   design held together by the outbox, but the two connections write each other's tables: the engine writes
   `seen_events`, recovery rows, reconciliation state and drafts; the app deletes `cgka_groups` rows.
2. **Triggers are implicit writers.** 131 triggers make derived-table maintenance invisible at call sites and tie
   product projections to the schema of the protocol database.
3. **The protocol database carries the product's bulk data.** Up to 2 GiB of attachments per account share one
   connection mutex, the WAL, `secure_delete` and `synchronous=FULL` with MLS state. With no vacuum, the file never
   shrinks. [#2314](https://github.com/marmot-protocol/mdk/issues/2314) (design decided 2026-10-15) moves retained
   bytes, partials and outgoing copies into per-file encrypted files under `accounts/<label>/media/`, with random
   per-file keys in SQLCipher, no automatic deletion, a free-disk gate with a typed `StorageFull` state, and one
   `VACUUM` plus `auto_vacuum=INCREMENTAL` after migration. Step 0 (PR
   [#2320](https://github.com/marmot-protocol/mdk/pull/2320)) adds the format and benchmark.
4. **The secret-store default is plaintext.** `AccountHome::open` uses the file store (`home.rs:206-212`), which
   `agent-connector` uses (`crates/agent-connector/src/lib.rs:274`). On Windows, `fs-private` mode calls are no-ops.
5. **The CLI runs without the root lease.** `wn` and `wnd` build `MarmotApp` with the unleased constructor
   (`crates/cli/src/lib.rs:1306`), which `lib.rs:1718-1723` documents as "for tests and embeddings that coordinate
   ownership externally". Whether the daemon's own pid and socket ownership substitutes for the lease is a Pass 1
   question.
6. **Some growth is never reclaimed:** audit segments (`crates/marmot-forensics/src/audit.rs:70-72`), delivery-loss
   evidence (deliberately not capped, `crates/storage-sqlite/src/account_recovery.rs:733-736`), disband tombstones,
   per-group processed transport ids, directory rows, and `wnd.log`.
7. **Cross-store writes are not atomic:** directory saves to `shared.sqlite3` and then to every account cache; salt
   files and databases; the legacy projection import. The boundaries doc already says so for the directory.
8. **Docs and comments drift.** The boundaries doc describes `shared.sqlite3` at one version (it has three), and some
   module comments claim single writers or atomicity the code does not provide (for example
   `crates/storage-sqlite/src/pending_welcome_delivery.rs:38-42`).
9. **Every canonical convergence apply copies the group's whole message ledger.** The apply takes a deliberately
   full snapshot (`crates/cgka-engine/src/openmls_projection.rs:2761-2765`), and the full scope copies every
   `cgka_messages` row and queued intent for the group
   (`crates/storage-sqlite/src/storage/snapshots/capture.rs:150-155`).
   Apply cost therefore grows with group history. Measured in
   [#2326](https://github.com/marmot-protocol/mdk/issues/2326): about 570 bytes per message, so 28.5 MB written and
   deleted per apply at 50,000 messages.
10. **Not every transaction goes through `with_transaction`.** Raw `BEGIN` or savepoint sites exist in
    `chat_list.rs:952`, `user_blocks.rs:122`, `account_projection.rs:1463` and `:2271`,
    `transport_reconciliation.rs:145`, `pending_welcome_delivery.rs:47`, `storage/groups.rs:96`,
    `storage/outbound.rs:22` and `agent_stream_sequences.rs:52` (all under `crates/storage-sqlite/src/`). The nesting
    rules are therefore not uniform across the crate.
11. **Engine behaviour depends on app tables.** Message release branches on whether an `account_state` row exists
    (`crates/storage-sqlite/src/storage/messages.rs:283-290`), and the app connection's local-forget wipe deletes
    `openmls_values`, `cgka_welcomes` and tombstones (`account_projection.rs:1564-1581`).
12. **`shared.sqlite3` is plaintext and holds every account's contact and follow graph,** which survives account
    removal. One account's search results are also written into every account's cache
    (`crates/marmot-app/src/directory/search.rs:903-907`).
