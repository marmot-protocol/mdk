---
title: "Long-lived runtime state — bounds and reclamation"
created: 2026-07-02
updated: 2026-09-16
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

### `cgka-engine` candidate reconstruction (`src/openmls_projection/resumable.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `Engine::canonical_replays`, `Engine::peel_replays` | At most one continuation of each kind per pending group. Each owns one input graph; frontier and completed paths are bounded by the existing cumulative replay-probe budget, with path depth limited by the retained graph. Peel output remains capped at eight contexts. This is an input-relative bound, not a fixed account-wide byte cap. | Removed on completion/error, relevant state or policy invalidation, hydration/repair/removal, or engine drop. Exact source identity and replay-state content fingerprint (or strict MLS mutation generation on other tracking backends) are checked before reuse; a new canonical pass discards the old cursor. No transaction, snapshot guard, or durable scratch row survives a slice. |

### `cgka-engine` moderation authority recovery (`src/app_payload.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `Engine::authority_recovery_attempts`, `Engine::authority_recovery_seen` | At most one entry per durable unresolved moderation control encountered in the current or previous cursor pass; input-relative to retained source records, never ordinary chat history. Each maintenance call visits at most 32 requests. Fingerprints identify one named snapshot rather than the whole live group. | Resolved entries are removed immediately; each completed cursor pass removes entries whose requests disappeared. Source-byte pruning and group deletion remove durable requests atomically. Engine drop clears both caches; restart may retry once against unchanged evidence. No secret-derived fingerprint is logged or persisted. |

### `storage-sqlite` durable moderation (`src/timeline/reports.rs`, `src/timeline.rs`)

These are input-relative durable bounds, not fixed account-wide row or byte caps. Moderation evidence must remain
stable under delayed delivery and convergence; ordinary chat expiry must not create a moderation history ledger.

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `content_moderation`, `content_reports` | One summary per reported or removed target; one report per logical `(target, revision, reporter)`. Unreported, unremoved chats have no row. | Recomputed from authenticated controls; invalidation removes withdrawn reports and empty summaries. Target pruning clears both projections; group deletion removes all rows. |
| `content_pruned_controls` and retained control `app_events` | One marker and minimal structural record per retained deletion/report/review/removal control. Input-relative to actual controls, not chat traffic. | Retention and explicit secure erasure scrub report/review explanations and unrelated tags but preserve ids, decision references, authority verdicts and authenticated source-context provenance. Group deletion reclaims the evidence. |
| `content_expired_targets` | At most one marker per erased chat target that had a report/moderation projection or a retained control targeting it. Ordinary expired chats create no marker. | Retained until group deletion so late target/edit/report delivery cannot resurrect moderated content or its scrubbed explanations. Repeated pruning or delivery reuses the same marker. |
| `content_report_backfill` | One cursor row per account database. | Advances through the captured pre-migration prefix in batches of at most 100 events; completion retains only that progress row. |

Explicit secure erasure intentionally retains these minimal moderation identifiers and branch-provenance records;
it does not promise to erase every trace of a moderation decision. Message bodies, report/review explanations and media remain subject to
secure erasure. The moderation replay fence applies only to targets with this retained evidence. Ordinary message
re-delivery and expiry continue through the existing ingress deduplication and retention lifecycle.

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

### Presented chat-list subscriptions (`marmot-app/src/runtime/presented_chat_list.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Initial and current complete snapshots | Existing account-list cardinality; no history retained | Current snapshot is replaced, never appended. UniFFI transfers the initial snapshot once. Dropping the handle releases both and closes the underlying list consumer; shutdown terminates reads. C4 owns future bounded paging. |
| Invalidation receivers | Existing bounded chat-list queue plus the shared 64-entry presentation broadcast | Lag rebuilds current local state. No per-subscriber presentation timer or durable event log. |

### Combined conversation windows (`marmot-app/src/runtime/conversation_window.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Per-subscription actor and snapshots | One account/group; initial, current and latest replacement each contain at most 200 rows plus M3's bounded identity sidecar and one descriptor-only draft. Text byte sizes retain their existing source limits. | Replaced atomically; no accumulated transcript. Subscription drop, account reset/eviction, closed storage or shutdown terminates the actor. A surviving command clone cannot keep it alive. |
| Commands and invalidations | Eight queued commands; existing bounded broadcasts, with at most 1024 queued entries drained per source per capture. | Commands serialize with refresh. Slow receivers coalesce to the latest complete replacement; lag rereads local state. Failed refresh retains one timed retry obligation, not a queue of failed work. |
| Worker/source identity | One pinned worker sender and account-store epoch per open handle. | Never rebound after teardown. Initial opening can be cancelled while live capture is temporarily unavailable. |

### `marmot-app` (`src/sqlcipher.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `SQLCIPHER_V2_VERDICTS` probe-verdict cache | 256 entries (`SQLCIPHER_V2_VERDICT_CACHE_CAPACITY`) | Entries are keyed by canonical database path + salt and record only an observed "opens under the v2 key" verdict (mdk#1439). Removed when the database file set is deleted via `remove_sqlite_file_set`; replaced in place when the salt rotates; oldest-first eviction at the cap. Eviction or loss of an entry only ever causes one extra recovery probe, never a wrong-key assumption. The companion `SQLCIPHER_MIGRATION_PROBE_RUNS`/`SKIPS` counters are monotonic process-lifetime aggregates by design (telemetry gauges, not tracked state). |

### `marmot-app` client (`src/client/`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `AppClient.encrypted_media_not_required_epochs` | One `u64` per live projected group (mdk#1380) | Pruned to the live group set at the start of every warm pass; stale entries are evicted when the group epoch advances and an authoritative re-check finds the component required; the whole map is dropped with the client. Entries are only ever inserted after a successful authoritative negative, so map loss or eviction costs at most one `MlsGroup::load` re-check, never a wrong skip. |
| `app_prepared_group_image_upload` SQLCipher rows | 16 active staged/uploaded/failed artifacts and 128 consumed idempotency markers per account | Active artifacts expire after 7 days and consumed markers after 30 days; staging prunes expired rows, consumption evicts the oldest marker at the cap, and consumed rows erase their retained ciphertext/upload-secret copies. The founding MLS component remains authoritative after consumption. |

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
