---
title: "App SQLite Storage Boundaries"
created: 2026-09-04
updated: 2026-09-06
tags: [marmot, app-core, sqlite, storage, migrations]
status: current-implementation
---

# App SQLite Storage Boundaries

This page records the current MDK app-layer SQLite inventory. These stores have different authority and durability
contracts; sharing a file format does not make them one database or one migration domain.

## Current Layout

For `N` active signing accounts whose stores have been opened, the layout has up to `2N + 1` SQLite files:

| Path | Encryption and scope | Authority and recovery contract |
| --- | --- | --- |
| `accounts/<label>/session.sqlite` | Per-account SQLCipher | Contains authoritative protocol and recovery state plus durable app projections. It is not disposable and uses the numbered `cgka_schema_migrations` history described by [Storage Format V2](../storage-format-v2.md). |
| `accounts/<label>/app-cache.sqlite3` | Per-account SQLCipher | Contains derived account-private Nostr directory and bounded search state. It can be reconstructed from `AccountHome` plus the Nostr network, but ordinary upgrades should preserve and migrate it so offline directory behavior and discovery provenance are not discarded. |
| `shared.sqlite3` | Installation-wide plaintext SQLite, created owner-only | Contains a sanitized public-directory mirror plus durable installation-wide telemetry/audit preferences and the telemetry installation id. The directory rows are reconstructible; the settings and installation id must not be silently discarded with the cache. |

The session database is the only protocol-state authority. The directory stores support app lookup and projection
behavior and must not become an alternate source of MLS truth.

## Directory Mirroring And Reconciliation

Directory writes mirror the public subset into `shared.sqlite3` and the richer record into each active account cache.
Reads reconcile independently timestamped components from both tiers. Those cross-database writes are not one atomic
transaction, so neither directory tier is an authoritative protocol-state boundary.

A read alone does not repair a partial mirror. A later successful save of that directory record reconciles it. Code
that needs stronger cross-store guarantees must introduce an explicit intent/reconciliation mechanism rather than
assuming the two SQLite commits are atomic.

## Legacy Imports

The root-level `app-cache.sqlite3` is a legacy plaintext directory location that is imported and removed. Likewise,
`accounts/<label>/app.sqlite3` is a legacy projection database imported once into `session.sqlite`. Neither is a fourth
current store.

## Migration Domains

All three current database categories have independent numbered migration histories and future-schema refusal:
`session.sqlite` uses `cgka_schema_migrations`, per-account `app-cache.sqlite3` uses `app_cache_schema_migrations`, and
installation-wide `shared.sqlite3` uses `shared_schema_migrations`. Each runner reads and updates only its own ledger.

Cache version 1 creates the six directory/search tables and indexes. Existing unversioned tables are adopted only
after their columns, types, nullability, defaults, primary keys and index columns match the version-1 shape. Missing
tables and indexes are created, but malformed existing tables fail rather than being silently marked migrated.
The legacy `user_directory_records` JSON conversion and removal of its retired table are part of the same migration.

Each migration runs under a write transaction together with its ledger insertion. A failure rolls back that migration's
schema changes, converted records and ledger row; earlier committed migrations remain intact. Reopening a current
cache validates history with reads only and skips applied migrations; a pending migration rechecks history under
the write lock to serialize concurrent openers. SQLite result codes and static history errors remain available without
database-controlled error messages or legacy JSON values. Recorded names must match the compiled ordered history, and any newer recorded version
returns `UnsupportedSchemaVersion` before a migration body runs. This refuses downgrades across a newer schema; it does
not reverse committed migrations. SQLCipher hardening, owner-only files, terminal close behavior, and the legacy
plaintext directory import remain in place.

Shared version `1 / 0001_shared_store` establishes `directory_users`, `directory_user_follows`,
`relay_telemetry_settings`, `audit_log_settings`, and `telemetry_install`. It uses the same body-plus-ledger transaction,
exact-prefix/name validation, read-only current-open path, write-lock recheck and typed future-version refusal contract
within its own storage-sqlite module. Shared-store SQLite errors preserve extended result codes, with BUSY/LOCKED
remaining transient, while omitting database-controlled messages (including trigger payloads).

Before creating missing tables or recording version 1, the shared runner recognizes existing tables against frozen
current and historical definitions. Introspection checks columns, types, nullability, defaults, primary keys, foreign
keys, index columns/collations/order and uniqueness. Conservative DDL comparison also pins CHECK expressions, conflict
policies and table options. Unknown definitions, extra indexes or triggers on live tables, and foreign-key violations
fail closed with stable static errors. Equivalent but unrecognized hand-edited SQL can also be refused. No user data
is deleted to recover an unknown layout.

Adoption preserves public-directory users, follow ordering, telemetry enabled/interval values, audit enabled values,
timestamps and installation identity, including rowids. Recognized retired columns are retained to avoid table rebuilds:
nullable `relay_telemetry_settings.otlp_endpoint` values become NULL within the migration transaction, while audit
`data_mode` (inline or appended by the historical repair) stays inert and unchanged. Subsequent settings writes do not
reactivate either field. Already-current opens do not repeat endpoint writes. Old unused directory tables and their
rows remain untouched; new databases do not create them.

The shared store remains unencrypted and owner-only with its existing 5-second busy timeout, WAL, synchronous NORMAL,
foreign keys ON, trusted_schema OFF, temp_store MEMORY and terminal close semantics. Directory mirroring/reconciliation,
session storage, app-cache migrations, and the retired app-projection import are unchanged.

Each store needs an independent schema identity because its release cadence, rollback behavior, and durability
contract can diverge. A session migration version must never be treated as the version of either cache.

## Upgrade Assurance And Limits

The directory-cache assurance tests use DDL extracted independently from
`9db9dbc092d52eb7b2d5bc6dcfb1f9beb3125464`, where this cache module entered MDK. The structured DDL is unchanged
across the eight master-lineage revisions touching the cache through `7368c737`. This is repository-history evidence,
not a census of deployed app builds or databases.

The encrypted populated-cache test adopts 120,000 rows across all six tables and compares hashes of every typed value
and rowid before and after opening. Nulls, Unicode, unknown metadata and even invalid cached JSON remain untouched:
ordinary structured adoption does not deserialize or rewrite those records.

Legacy conversion tests combine existing structured records with 1,000 JSON records. They check every converted record
and preserve existing rows, force SQLite page-limit exhaustion and retry, and exit a child process without destructors
after conversion/table removal but before the ledger commit. Both rollback-journal and WAL reopen paths recover the
original data, leave the migration unrecorded, retry successfully and pass SQLite integrity checks.

These tests do not establish a numerical field failure rate or guarantee zero risk. Page-limit exhaustion exercises
`SQLITE_FULL`, not every operating-system I/O failure; child-process exit is not a device power-loss test. Production-device
upgrade testing, representative deployed-cache copies and rollout monitoring remain additional evidence. A refused
malformed schema preserves the file but can still make directory operations unavailable until repaired; preserving data
and preserving availability are separate requirements.


Shared-store fixtures independently extract the three master-lineage DDL generations from `9db9dbc0` (original nine
tables), `5464b34e` (five tables with audit data mode), and `fe133b82` (five current tables). All six master-lineage
revisions touching shared.rs through `6b2b041b` fall into these generations. The original revision's tests and additive
repair independently establish the legacy endpoint layout and both audit-column positions. These compatibility tests
are evidence of supported input, not proof of a particular deployed release. See the
[fixture provenance](../../../crates/storage-sqlite/src/shared/fixtures/README.md).

Shared assurance compares every typed value and rowid across 30,003 populated current-shape rows, checks all historical
fixtures (including retained unused tables), and verifies integrity and foreign keys after upgrades. Failure injection
covers migration-body and ledger-insert rollback, including rollback of endpoint neutralization. A bounded child process
exits without destructors after schema and endpoint changes and forced dirty-page spill, before ledger insertion;
rollback-journal and WAL recovery preserve the original rows and allow retry. This proves transaction recovery under
process interruption, not power-loss safety, deployment coverage or every disk-full/I/O failure. Future schemas and
unknown malformed layouts are refused without a migration body; refusal preserves data but can make the shared store
unavailable until a compatible binary or explicit repair is supplied.
