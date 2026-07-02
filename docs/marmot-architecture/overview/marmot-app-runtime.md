---
title: "Marmot App Runtime Shape"
created: 2026-05-19
updated: 2026-06-30
tags: [marmot, overview, app-runtime, daemon, tui]
status: implemented-first-slice
---

# Marmot App Runtime Shape

`marmot-app` should become the runtime boundary for client applications. A daemon, TUI, Flutter app, or desktop app
should create a `MarmotAppRuntime` and send it intents. The runtime owns accounts, shared directory state, relay
subscriptions, projections, and typed event streams.

The lower crates already point in this direction. `cgka-engine` owns convergence and engine state. `cgka-session` owns
one account-device session. `marmot-account` coordinates a session with transport and publish confirmation.
`marmot-app` is the place where those pieces become a product runtime.

## Shape

```text
MarmotAppRuntime
  SharedServices
    account home
    shared directory cache
    Nostr relay plane
    app event hubs
    projection stores
    background maintenance tasks
  AccountManager
    MarmotAccountSession(account A)
    MarmotAccountSession(account B)
    ...
```

`MarmotAccountSession` should wrap the current account-device stack:

- account identity and secret access;
- `AccountDeviceSession`;
- per-account app projection state;
- account-scoped group, message, profile, key-package, and stream operations;
- account inbox subscription state.

`SharedServices` should hold runtime state shared by every account:

- directory/user cache;
- relay-list and KeyPackage lookup state;
- app-wide stream hubs;
- app settings and runtime config;
- the Nostr relay plane.

## Relay Plane And Adapter

`transport-nostr-adapter` remains the reusable transport mechanism. It knows how to express Marmot transport messages as
Nostr events, how to peel inbound Nostr events into transport deliveries, how to publish to endpoint sets, and how to
manage low-level relay client calls behind an injectable boundary.

The Nostr relay plane should live inside `marmot-app` as a module or subsystem. It is the runtime owner for Nostr
subscriptions and relay policy:

- keep discovery and directory subscriptions coalesced across accounts;
- keep account inbox subscriptions for signed-in accounts;
- keep group subscriptions for account/group routes;
- route inbound relay events to the right `MarmotAccountSession`;
- apply reconnect, catch-up, replay-window, and relay-safety policy;
- emit typed runtime events after account sessions ingest deliveries.

The adapter is transport plumbing. The relay plane is app-runtime orchestration.

## Inbound / Convergence Boundary Contracts

The receive/convergence path is governed by **five boundary contracts** (tracking issue #736), each owned locally
rather than by one monolithic pipeline. The engine's live MLS roster/epoch state stays in the engine; these contracts
add the incremental, bounded, non-blocking, single-source properties around it so new code inherits them.

1. **Storage ordering surfaces** (`storage-sqlite`). Two DISTINCT, separately-named orders that MUST NOT be conflated:
   - **Raw-event replay cursor** — `AppEventReplayCursor` = `(recorded_at, message_id_hex, insert_order)` over the
     `app_events` table (queried via `SqliteAccountStorage::app_messages`), with a matching
     `APP_EVENT_REPLAY_ORDER_ASC/_DESC` SQL fragment. `insert_order` is a LOCAL rowid,
     correct here because this cursor is only a per-client lag-recovery cut-point (never cross-client display). The
     third field is load-bearing for unscoped (all-groups) recovery, where the same `message_id_hex` can appear in two
     groups.
   - **Materialized-timeline order** — `TIMELINE_ORDER_BY_ASC/_DESC` = `(timeline_at, message_id_hex)` over
     `message_timeline`/chat-list; the cross-client user-visible display + pagination order (`timeline_at == recorded_at`
     at projection). The replay cursor MUST NOT be applied to timeline pagination.
2. **Runtime recovery** (`marmot-app` runtime). The lag-recovery watermark capture and `recovery_row_is_pre_subscription`
   suppression are the SAME `AppEventReplayCursor` the recovery query orders by, so the suppression boundary can never
   drift from the query order. Lag replay reads a bounded window (broadcast-depth/watermark-keyed), never the full
   history.
3. **Engine convergence scheduling** (`marmot-app` account worker). Pending convergence groups are drained via
   `take_pending_convergence_groups()` → `ScheduledConvergence::schedule_groups` at EVERY worker loop entry, including
   the deferred-startup replay loop, so buffered convergence work is never stranded.
4. **Transport routing** (`cgka-engine` + `transport-nostr-adapter`). Both layers resolve a `transport_group_id` through
   an in-memory index built from authoritative state (engine: at hydration + group create/join; adapter: rebuilt at
   activate/sync_groups/deactivate, with canonicalized relay endpoints cached), so per-event routing is O(1)-ish and no
   unauthenticated peer can force an O(groups) pre-auth scan.
5. **Daemon/connector critical sections** (`agent-connector`; the CLI daemon lock is tracked separately). Relay I/O,
   full resync, and idempotency `fsync` run OFF the per-event/per-command critical path (coalesced resync, `spawn_blocking`
   persistence) so one slow item cannot head-of-line-block unrelated events.

Canonical derived-state owners: timeline display order + raw-event replay cursor = `storage-sqlite` (the two helpers
above); lag watermark/suppression = the subscription runtime, typed on `AppEventReplayCursor`; pending-convergence
scheduling = `ScheduledConvergence`; transport routing = the engine + adapter indexes; message dedup = the engine's
bounded `seen_message_ids` set (borrowed, not re-serialized, per convergence pass). `recorded_at` is cross-client-stable:
the outer transport envelope's `created_at` is bound to the inner app event's `created_at` at wrap time, so a sender and
every receiver record the same value.

The convergence branch-selection model is unchanged; see [`../distributed-convergence.md`](../distributed-convergence.md)
and [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md).

## Daemon Boundary

`dmd` should host one `MarmotAppRuntime`. It should accept socket requests, pass intents into the runtime, and stream
runtime events back to clients.

Daemon responsibilities stay narrow: process lifecycle, socket protocol, request routing, and stream fanout.

## CLI And TUI Boundary

`dm` and the TUI should be thin clients of the daemon/runtime:

- command calls become runtime intents;
- subscription calls attach to runtime broadcast streams;
- initial UI state comes from runtime snapshots;
- live updates come from runtime events;
- `sync` can remain as a diagnostic or repair command, while normal chat and stream flows work without it.

Agent stream previews belong in the same message subscription stream as other message updates. They should appear as
typed updates such as `agent_stream_start`, `agent_stream_delta`, `stream_preview`, and `agent_stream_final`.

## What To Borrow From whitenoise-rs

The useful pattern in `whitenoise-rs` is the app runtime shape:

- one runtime object holds shared services and an account manager;
- each account has a session with scoped operations;
- relay control is a shared runtime service;
- inbound relay events flow through one processing path;
- stream managers use broadcast channels keyed by account, group, or user;
- subscription APIs return an initial snapshot plus a live receiver.

Darkmatter should copy the shape and leave the legacy weight behind. The existing Darkmatter crates give us cleaner
engine/session boundaries and per-account persistence. The runtime work should build on those crates.

## First Vertical Slice

The first slice now proves the architecture without filling in every product surface:

1. `MarmotAppRuntime::open`, `start`, and `shutdown` exist.
2. Local signing accounts are restored into an `AccountManager`.
3. Identity creation publishes relay lists, a profile, and a fresh KeyPackage through runtime-backed setup.
4. Runtime events cover group joins, group-state changes, messages, and typed agent stream start/final messages.
5. Live Nostr receive and ingest run inside `marmot-app` account workers.
6. `dmd` hosts one runtime and forwards command intents into it.
7. `messages subscribe`, `chats subscribe`, and `groups subscribe-state` use runtime snapshots plus live receivers.
8. Agent stream preview state and deltas are owned by a runtime shared stream manager and surfaced through message
   subscriptions.
9. The relay plane applies bounded replay lookback, relay endpoint parsing/deduplication, shared directory discovery
   fetch coalescing, and redacted relay-health reporting.
10. Daemon status reports `last_runtime_activity` instead of modeling the daemon as a background sync loop.
11. The TUI remains a daemon client.

The acceptance test should create Alice and Bob, create a group, receive Bob's group join, send a normal message, start
an agent stream, receive stream deltas, and finish the stream without calling `dm sync` or publishing keys manually.

## Remaining Hardening

The remaining work is narrower than the original refactor, but still real:

- directory, profile, follow-list, and KeyPackage discovery now use a shared relay-plane fetch path with in-flight
  coalescing; the remaining production work is turning hot directory data into long-lived subscription maintenance;
- relay auth, relay scoring, and explicit reconnect/backoff policy are still delegated mostly to `nostr-sdk`;
- stream watch execution still lives in the CLI/daemon adapter, while runtime owns stream state and typed updates and
  the daemon tracks watch worker lifecycle;
- `sync` remains as a diagnostic/repair command and some internal function names still say `sync` for catch-up/replay
  work;
- production apps still need lifecycle hooks for mobile/desktop foregrounding, backgrounding, and shutdown.

## Crate Responsibility After The Refactor

- `crates/traits`: shared transport, engine, app payload, and event types.
- `crates/cgka-engine`: OpenMLS-backed engine and convergence.
- `crates/cgka-session`: one encrypted account-device session.
- `crates/marmot-account`: account/session coordinator for publish-before-apply and transport activation.
- `crates/marmot-app`: multi-account runtime, shared services, relay plane, projections, app events.
- `crates/transport-nostr-adapter`: reusable Nostr transport adapter and SDK bridge.
- `crates/transport-nostr-peeler`: Nostr event peeling and wrapping.
- `crates/transport-quic-stream`: transient agent text stream transport.
- `crates/transport-quic-broker`: memory-only local broker for transient stream records.
- `crates/cli`: daemon host, CLI client, and TUI client.
