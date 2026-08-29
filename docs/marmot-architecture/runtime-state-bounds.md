---
title: "Long-lived runtime state — bounds and reclamation"
created: 2026-07-02
updated: 2026-08-28
tags: [marmot, architecture, runtime, daemon, broker, memory, key-package]
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

### `marmot-app` (`src/sqlcipher.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `SQLCIPHER_V2_VERDICTS` probe-verdict cache | 256 entries (`SQLCIPHER_V2_VERDICT_CACHE_CAPACITY`) | Entries are keyed by canonical database path + salt and record only an observed "opens under the v2 key" verdict (mdk#1439). Removed when the database file set is deleted via `remove_sqlite_file_set`; replaced in place when the salt rotates; oldest-first eviction at the cap. Eviction or loss of an entry only ever causes one extra recovery probe, never a wrong-key assumption. The companion `SQLCIPHER_MIGRATION_PROBE_RUNS`/`SKIPS` counters are monotonic process-lifetime aggregates by design (telemetry gauges, not tracked state). |

### `marmot-app` client (`src/client/`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `AppClient.encrypted_media_not_required_epochs` | One `u64` per live projected group (mdk#1380) | Pruned to the live group set at the start of every warm pass; stale entries are evicted when the group epoch advances and an authoritative re-check finds the component required; the whole map is dropped with the client. Entries are only ever inserted after a successful authoritative negative, so map loss or eviction costs at most one `MlsGroup::load` re-check, never a wrong skip. |
| `app_prepared_group_image_upload` SQLCipher rows | 16 active staged/uploaded/failed artifacts and 128 consumed idempotency markers per account | Active artifacts expire after 7 days and consumed markers after 30 days; staging prunes expired rows, consumption evicts the oldest marker at the cap, and consumed rows erase their retained ciphertext/upload-secret copies. The founding MLS component remains authoritative after consumption. |

### `marmot-app` account runtime (`src/runtime/mod.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Runtime-owned sign-out/wipe tasks | 64 concurrently admitted operations (`ACCOUNT_TEARDOWN_TASK_LIMIT`) | Each task holds only an active-count guard; completion drops the guard without retaining a handle or account id. Graceful shutdown closes admission and drains the active count before stopping the relay plane. Terminal `shutdown_and_close` gives the same work one shared bounded grace interval, then closes storage even if a relay operation is still stalled. Over-cap calls fail retryably with `AccountWorkerBusy`. |
| Removed-local KeyPackage tombstones (`key-packages/removed-local-slots-v1/<account>/slots.json`, plus legacy `slot-*.json` / `all.json` during compaction) | One bounded journal per identity: at most 256 exact retired stable-slot ids (`MAX_REMOVED_LOCAL_KEY_PACKAGE_TOMBSTONE_SLOTS`) plus at most one account-wide fallback flag when legacy state cannot prove a stable slot. Growth is driven only by explicit removal of locally signing account devices, never by relay traffic, retries, or cache ingestion. A 257th distinct slot fails closed rather than evicting anti-resurrection proof. | Exact slot identities are never reclaimed. After the journal is durable, leftover per-slot files are compacted with parent-directory fsync. Re-import of the same identity creates a new stable slot; exact old-slot ids continue to win, while an account-wide legacy fallback admits only a different slot proven by the currently active local signing lifecycle. |

### `marmot-account` KeyPackage lifecycle (`src/runtime.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Signed KeyPackage publication liabilities (`current`, signed `pending_replacement`, and `retired_publications_pending_deletion`) | 256 ordinary exact `(event_id, endpoint)` liabilities per account-device (`MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES`), plus a lifecycle-wide reserve of 16 used only to admit one explicitly selected exact deletion atomically (`MAX_KEY_PACKAGE_LIVE_DELETION_OVERFLOW_LIABILITIES`) | Every possible exposure is marked durably before network I/O. Rotation, reauthoring, expiry, consumption, and relay-discovered teardown targets transfer old exact ids into the retired journal; a per-endpoint kind-5 acknowledgement or the adapter's exact recognized target-not-found response removes only that endpoint. Other free-text rejection variants remain retryable. Live-policy endpoints wait for a strictly newer accepted revision before old-id deletion; removed, expired, consumed, or teardown-discovered packages delete immediately. Obligations are never evicted. An explicit event id unknown to current lifecycle projections is conservatively treated as a possible older same-slot revision because that API carries no stable-slot proof. The reserved 16 pairs match the account boundary's maximum relay route and prevent a full ordinary journal from admitting only part of such an exact deletion; while total liabilities remain above 256, every new publication stays blocked until deletion receipts reduce the state to the ordinary bound. Other work never consumes the reserve. When the ordinary cap is full, cleanup is attempted and further discovery liability is blocked fail-closed. In particular, strict upgrade cutover keeps all KeyPackage publication durably interlocked—and can remain unavailable indefinitely—until expiry, consumption, policy prohibition, or a terminal deletion receipt frees enough capacity to admit every newly discovered exact endpoint. One cleanup call attempts at most one endpoint (`KEY_PACKAGE_RETIRED_DELETION_ATTEMPTS_PER_CALL`), bounding a serialized account pass to one relay publish deadline. |
| Consumed KeyPackage reference journal (`consumed_key_package_refs`) | 256 distinct refs awaiting cleanup per account-device (`MAX_CONSUMED_KEY_PACKAGE_REFS_PENDING_CLEANUP`) | Welcome processing appends every locally matched reference atomically with the joined group, including legacy bundles that have no projected lifecycle row. Duplicates replace no state; a 257th distinct ref fails the Welcome transaction closed rather than evicting unswept privacy evidence. The account sweep keeps a consumed current ref until a semantic replacement succeeds, immediately retires a consumed pending ref without exact republication, removes consumed retained material, and clears each journal ref only after handling the matching private/lifecycle artifact. |

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
