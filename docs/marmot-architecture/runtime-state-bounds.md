---
title: "Long-lived runtime state — bounds and reclamation"
created: 2026-07-02
updated: 2026-07-04
tags: [marmot, architecture, runtime, daemon, broker, memory]
---

# Long-lived runtime state — bounds and reclamation

The daemon (`wn-agent`), the QUIC preview broker, and the app runtime are long-lived processes. Every long-lived
collection, handle set, counter, and temp artifact they hold must have a defined lifecycle: creation, accounting,
eviction/expiry, and reclamation, with an enforced bound. Unbounded growth is a contract violation, not a latent leak.
Tracking issue: marmot-protocol/mdk#381.

## The discipline

- **Every insert has a defined remove**, tied to the originating lifecycle event (unsubscribe, deactivate, rotation,
  disconnect), not just one terminal transition (a clean "finish" that may never arrive).
- **Counters cannot drift.** Running totals are adjusted symmetrically with the state they measure on every mutation
  path, including reset/teardown, or are recomputed wholesale from the tracked set.
- **Temp artifacts are reclaimed on actual liveness** (per-artifact last-use), never on a heuristic that races with
  active use.
- **Each structure documents its bound** (max size, TTL, or eviction policy) below and enforces it in code.

## Inventory

### `transport-quic-broker` (`src/state.rs`, `src/server.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `BrokerStateInner.rooms` | `max_rooms` (default 512) | Removed when the last subscriber leaves an empty unfinished room; finished rooms drop after a 60 s TTL; stale unfinished rooms are purged activity-driven on every state-touching op. A publisher reusing a finished key resets the room in place. |
| Per-room `backlog` | `max_backlog` records (default 1024) per room, `max_backlog_bytes` (default 64 MiB) global, `replay_ttl` (default 0 = retain nothing) | Expired entries purged on subscribe/publish/purge; oldest dropped when over depth or byte budget. |
| `total_backlog_bytes` | Derived from room backlogs | Adjusted symmetrically on every backlog mutation, including the finished-room in-place reset (mdk#372); recomputed wholesale by `purge_expired_rooms`. |
| Per-subscriber queue | `per_subscriber_queue` records (default 32) | A lagging subscriber is dropped rather than buffered. |
| Per-publish-stream forwarding | `publish_max_records` (default 65536) records, `publish_max_frame_bytes` (default 64 MiB) cumulative wire frame bytes (ciphertext for encrypted previews — the broker never decrypts) | Forward-role bounds from broker config (never the subscriber-sized receive defaults, mdk#391); on breach the room is finished so subscribers see a clean end. Record reads also carry the shared 120 s quiet-gap deadline, so an alive-but-wedged publisher cannot pin a room via QUIC keepalives. |
| Connections | `max_connections` semaphore (default 256), `max_streams_per_connection` (default 64) | Over-cap connections are refused at accept; permits release on disconnect. TLS handshakes are bounded by `read_timeout`, so a stalling peer cannot pin a connection permit pre-handshake. |

### `agent-connector` / `wn-agent` (`src/lib.rs` and modules)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Control-socket connections | `max_connections` semaphore (default `MAX_CONTROL_CONNECTIONS` = 64, `--max-connections`) | Over-cap connections are closed at accept time (mdk#390); each served connection holds one permit for its whole session, released on disconnect. A zero cap is rejected as unsafe config. |
| `DeliveredInboundCursor` (per `SubscribeInbound` session) | 4096 ids (`DELIVERED_INBOUND_CURSOR_CAPACITY`) | FIFO eviction of oldest ids; dropped with the session. |
| `SendIdempotencyStore` | 1024 entries, persisted | FIFO eviction on insert. |
| Stream compose sessions | Idle timeout 300 s (`STREAM_SESSION_IDLE_TIMEOUT`) | Background sweeper aborts idle sessions every 30 s. |
| Decrypted-media temp dirs (`$TMPDIR/marmot-media/<hash>/`) | TTL 1 h (`MEDIA_TEMP_MAX_AGE`) | Swept every 60 s, keyed on the newest mtime within the per-blob dir so an in-place re-download refreshes liveness (mdk#374); un-inspectable dirs are skipped, never swept blind. |

### `marmot-app` runtime (`src/agent_streams.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `AgentStreamWatchManager.watches` | 256 (`AGENT_STREAM_WATCH_RETAIN_LIMIT`), including `running` watches | Enforced on both start and finish. Finished watches evict oldest-first; when running watches alone exceed the cap (a finish that never arrives), the oldest running watches evict too (mdk#343). |
| `recent_updates` replay ring | 256 (`AGENT_STREAM_UPDATE_REPLAY_LIMIT`) | Oldest popped on publish. |

### `wn-cli` daemon / `wnd` (`src/daemon/`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Daemon connections | `MAX_DAEMON_CONNECTIONS` semaphore (256) | Over-cap connections are closed at accept time; permits release on disconnect. Finished per-connection task handles are reaped every accept iteration. |
| `DaemonEventHub.recent_messages` replay ring | 256 (`DAEMON_EVENT_REPLAY_LIMIT`) | Oldest popped on publish. |
| Per-subscription dedup ids | 256 (`MESSAGE_SUBSCRIPTION_DEDUP_LIMIT`) | FIFO eviction; dropped with the subscription. |
| `StreamWatchWorkers.handles` | Live watches + finished-since-last-start | Finished handles reaped on every watch start and on status; all aborted at shutdown. |

### `transport-nostr-adapter` (`src/lib.rs`, `src/telemetry.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `AdapterState.accounts` + `by_transport_group` index | Live accounts × their group subscriptions | Removed on deactivate; index rebuilt wholesale from `accounts` on every mutation so it cannot drift. |
| `RelaySyncTelemetry.subscriptions` | Live subscription count | Evicted on the `sync_account_groups` remove diff, on deactivate, and on reactivate before the replacement routes are recorded (mdk#342). Subscription ids hash account/group/endpoint-set, so rotations mint new ids and the old ones are forgotten. |
| `RelaySyncTelemetry.first_event` / `eose`, `RelayIndexRegistry` | Distinct relay endpoints ever configured | Aggregate per-relay histograms; intentionally retained (bounded by configuration, not by traffic). |
| `RelayDeliveryTelemetry.pending` | 60 s tracking window (`DEFAULT_TRACKING_WINDOW_MS`) | Entries older than the window are pruned inline on every sighting. |

## Adding a new long-lived structure

When adding a map, task set, counter, or temp artifact to a long-lived process:

1. Name the lifecycle event that removes each entry, and wire the removal to every path that retires the entry — not
   only the clean-completion path.
2. Prefer deriving counters from the tracked set; if a running total is unavoidable, adjust it in the same critical
   section as every mutation, including resets.
3. Give the structure an explicit bound (cap, TTL, or budget) and a test that drives churn and asserts the bound holds.
4. Add a row to the inventory above.
