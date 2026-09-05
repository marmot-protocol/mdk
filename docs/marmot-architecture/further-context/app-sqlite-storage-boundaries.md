---
title: "App SQLite Storage Boundaries"
created: 2026-09-04
updated: 2026-09-05
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

Both `session.sqlite` and the per-account `app-cache.sqlite3` have independent numbered migration histories and
future-schema refusal. The directory cache uses `app_cache_schema_migrations`; it never reads or updates
`cgka_schema_migrations`.

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

`shared.sqlite3` still initializes its tables without a numbered ledger or future-schema refusal. Versioning that store
is a separate follow-up; its changes must remain additive and compatible with existing databases in the meantime.
Directory mirroring/reconciliation, session storage, and the retired app-projection import are unchanged.

Each store needs an independent schema identity because its release cadence, rollback behavior, and durability
contract can diverge. A session migration version must never be treated as the version of either cache.
