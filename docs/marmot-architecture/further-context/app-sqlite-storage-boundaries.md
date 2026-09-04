---
title: "App SQLite Storage Boundaries"
created: 2026-09-04
updated: 2026-09-04
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

Only `session.sqlite` currently has a numbered migration ledger and future-schema refusal. The two auxiliary stores
initialize their current tables independently and must receive their own version histories before either schema makes
a non-additive change.

Each store needs an independent schema identity because its release cadence, rollback behavior, and durability
contract can diverge. A session migration version must never be treated as the version of either cache. Until those
ledgers exist, auxiliary-store changes should remain additive and compatible with already-created databases.
