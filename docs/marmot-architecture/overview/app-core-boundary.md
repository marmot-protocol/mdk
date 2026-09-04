---
title: "App Core Boundary"
created: 2026-05-15
updated: 2026-09-04
tags: [marmot, app-core, cli, tui, swift]
status: overview
---

# App Core Boundary

The first app surface is `wn`, but the durable product boundary is the app-core layer underneath it.

`wn` should stay a CLI/TUI-friendly presentation surface. It is useful because it exercises real account setup, relay
lists, KeyPackage publication, directory lookup, group operations, message projection, and sync. It should not become the
place where app policy or protocol state secretly lives.

## Ownership

`crates/cgka-engine` owns MLS and Marmot group state: create, invite, remove, SelfRemove, app messages, group data,
publish-before-apply, convergence, and group events.

`crates/cgka-session` owns one account-device session over encrypted SQLite engine state. It turns engine results into
session effects and keeps engine storage behind a small account-device API.

`crates/marmot-account` owns account home orchestration: account records, signing-key storage, session opening,
transport activation, routing policy, KeyPackage publication, and publish confirmation or rollback.

`crates/marmot-app` owns app-core integration: account projections, account-private and shared directory caches,
relay-list setup and discovery, local development relay support, Nostr SDK relay access, group/message records, and
the long-running `MarmotAppRuntime` used by app surfaces. `AppClient` remains a lower-level compatibility surface, not
the preferred host-owned runtime boundary.

`crates/cli` owns commands and output. Its JSON envelope is intentionally stable enough for a future TUI or harness, but
Swift and other host apps should prefer app-core bindings over shelling out to the CLI.

## Stable App Concepts

The current app-core concepts are:

- **Account home:** a platform user-data directory containing account records, per-account databases, a shared store,
  and local development relay state.
- **Secret store:** platform keychain by default, with a file-backed development store for deterministic tests.
- **Per-account session DB:** one SQLCipher-backed durable database per Marmot account-device identity. It contains
  OpenMLS/Marmot state and the operational app projections needed to preserve groups, messages, delivery state, and
  recovery obligations.
- **Per-account directory cache:** an encrypted account-private directory/search view containing local-account links,
  discovery provenance, profiles, follows, relay lists, KeyPackages, and bounded web-of-trust search state.
- **Shared store:** an installation-wide public-directory mirror stripped of account-private provenance, plus durable
  installation-wide telemetry/audit preferences and the telemetry installation id.
- **App runtime:** the long-running multi-account owner of account workers, relay subscriptions, projections, typed
  event streams, and storage lifecycle.

## Local SQLite Layout

For `N` active signing accounts whose stores have been opened, the current layout has up to `2N + 1` SQLite files: an
authoritative SQLCipher `session.sqlite` and a derived SQLCipher `app-cache.sqlite3` per account, plus the
installation-wide `shared.sqlite3` public-directory and settings store.

Only the session database currently has a numbered migration ledger. The auxiliary stores need independent migration
histories before non-additive schema changes. Their authority, reconciliation, durability, and legacy-import contracts
are detailed in [App SQLite Storage Boundaries](../further-context/app-sqlite-storage-boundaries.md).

## CLI Contract

`wn --json` always returns:

```json
{"ok": true, "result": {}}
```

or:

```json
{"ok": false, "error": {"code": "stable_snake_case", "message": "human readable"}}
```

Error objects may include fields such as `account`, `group_id`, `missing`, `relay_lists`, or `repair` when the caller can
take a concrete next step.

## Archive and Membership

Group membership and local archive state are separate.

When a member is removed from a group, that account keeps its local group projection and message history. The projected
member list should reflect the post-removal group state, but the group is not automatically archived or deleted.

Archiving is a local user decision. An archived group can be hidden from normal lists while remaining available by id for
history, members, and messages.

## Swift and TUI Direction

A Swift app should bind to `marmot-app`/`marmot-account` shaped APIs rather than the CLI text layer:

- open an account home;
- create/import accounts;
- inspect and repair relay-list setup;
- publish/fetch KeyPackages;
- refresh directory entries;
- start and retain an app runtime;
- call group, message, membership, archive, and sync methods;
- render app projection records.

The CLI remains valuable because it is the quickest way to exercise those same APIs and keep the first app surface honest.
