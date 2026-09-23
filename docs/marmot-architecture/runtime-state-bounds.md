---
title: "Long-lived runtime state — bounds and reclamation"
created: 2026-07-02
updated: 2026-09-23
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

### `marmot-app` account-worker startup (`src/runtime/worker_startup.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| In-memory startup failures | At most one entry per eligible account, with a saturating failure count and monotonic deadline; no history or error text | Successful readiness, explicit lifecycle reset, ineligibility, account removal/deactivation, or shutdown clears entries. Reconcile prunes absent and ineligible accounts. |
| Pending worker reapers | At most one cleanup task per removed managed worker | Global reconcile joins already-finished workers immediately and checks still-running cleanup without waiting. Targeted worker acquisition and explicit lifecycle operations wait at most twice the worker shutdown grace period for their own account. A timeout during targeted worker acquisition enters per-account retry backoff. An unfinished handle retains only its account's replacement fence. Cancelled callers leave handles tracked for the next transaction or terminal shutdown. |

The retry delay starts at one second, doubles after each actual failure, and caps at 60 seconds.
Suppressed calls do not advance the count or deadline. Expiry permits an attempt on the next
existing trigger; no timer retains an account or holds the transaction through a cooldown.

### `marmot-app` runtime performance observations (`src/app_telemetry/runtime.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Runtime operation aggregates | One fixed array entry per closed `RuntimePerformanceOperation`, with atomic completed-only counters/buckets and a separate mutex for live observations; no account/group/message keys | Runtime telemetry drop reclaims aggregates; snapshots include untouched operations as zeroes |
| Active-operation age slots | At most `TRACKED_STARTS` (64) monotonic starts per operation | RAII completion or cancellation releases a slot; excess starts still increment exact active/outcome counts and appear in `untracked_in_flight` |

Age tracking never drops or delays application work. When slots overflow, the oldest tracked
age is a lower bound; `untracked_in_flight` exposes that limitation. Each observation owns
only telemetry, a closed operation and timing metadata, never a client or storage handle.

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
| `content_reports` | One metadata row per retained valid report event; no target summaries or logical-report grouping. | Recomputed for affected targets; event expiry/invalidation and group deletion remove rows. Target expiry does not erase reports. |
| `content_pruned_controls` and retained control `app_events` | One marker and minimal structural record per retained kind-5 or kind-4891 deletion. | Expiry removes unrelated tags while preserving references, verdicts and source provenance. Group deletion reclaims evidence. Reports and labels use ordinary retention. |
| `content_expired_targets` | At most one marker per erased target with retained deletion evidence. Ordinary expired chats and reports create no marker. | Retained until group deletion so late target/edit delivery cannot restore deleted content. Repeated delivery reuses the marker. |
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
| SQLCipher database-open lock registry (`src/sqlcipher/open_lock.rs`) | One weak entry per concurrently requested database, bounded by peak simultaneous opens. | Each lookup sweeps expired weak entries. Only openers and waiters retain strong references; cached handles do not retain locks. Parent-canonical paths remain stable before/after file creation. |
| `SQLCIPHER_V2_VERDICTS` probe-verdict cache | 256 entries (`SQLCIPHER_V2_VERDICT_CACHE_CAPACITY`) | Entries are keyed by canonical database path + salt and record only an observed "opens under the v2 key" verdict (mdk#1439). Removed when the database file set is deleted via `remove_sqlite_file_set`; replaced in place when the salt rotates; oldest-first eviction at the cap. Eviction or loss of an entry only ever causes one extra recovery probe, never a wrong-key assumption. The companion `SQLCIPHER_MIGRATION_PROBE_RUNS`/`SKIPS` counters are monotonic process-lifetime aggregates by design (telemetry gauges, not tracked state). |

### `marmot-app` client (`src/client/`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| `AppClient.encrypted_media_not_required_epochs` | One `u64` per live projected group (mdk#1380) | Pruned to the live group set at the start of every warm pass; stale entries are evicted when the group epoch advances and an authoritative re-check finds the component required; the whole map is dropped with the client. Entries are only ever inserted after a successful authoritative negative, so map loss or eviction costs at most one `MlsGroup::load` re-check, never a wrong skip. |
| Avatar acquisition | At most 2,048 jobs, each descriptor at most 16 KiB; at most four HTTP/results across foreground media and avatar work, with one permit kept free by background admission | Job rows cascade with asset eviction/removal. Selected source changes replace demand atomically. Interrupted work resumes after worker reconstruction; retry deadlines persist and 16 consecutive transient failures slow to one daily probe. Worker exit cancels active I/O. |
| Native avatar batches | 16 targets/references; at most 16 MiB returned encoded bytes per call | Per-call ownership; budget-deferred images are not copied. Screen updates carry only metadata. |
| Avatar identity demand | 2,048 explicit registrations; 64 inspected per batch after directory version changes | Eviction removes registration; group deletion/account cache clear removes demand. Placeholder registrations remain eligible for later profile updates. No historical-roster crawl. |
| Avatar upgrade ledger | At most one key per chat present at migration 0078 | Consumed in transactions of at most 64 rows; never recreated on restart. |
| `app_prepared_group_image_upload` SQLCipher rows | 16 active staged/uploaded/failed artifacts and 128 consumed idempotency markers per account | Active artifacts expire after 7 days and consumed markers after 30 days; staging prunes expired rows, consumption evicts the oldest marker at the cap, and consumed rows erase their retained ciphertext/upload-secret copies. The founding MLS component remains authoritative after consumption. |

### `storage-sqlite` attachment acquisition (`src/attachment_acquisition.rs`)

| Structure | Bound | Reclamation |
| --- | --- | --- |
| Durable jobs | One per requested retained message slot; source descriptor at most 16 KiB; due/expiry scans at most 64 rows | Raw-source deletion cascades. Canonical source replacement/invalidation reconciles transactionally; matching timeline repair preserves work. Expired leases are reclaimable with a new attempt token; stale completion cannot publish. Eligible demand resumes policy-parked work; explicit-retry failures remain blocked. Worker policy changes must re-admit affected sources. No in-memory history-sized queue. |
| Retained attachment bytes | At most 512 MiB per object; caller-supplied account payload-byte budget checked atomically at publication; local reads at most 1 MiB; publication retains a full plaintext buffer plus SQLite binding cost | No LRU eviction. Budget refusal commits no bytes. Source deletion/expiry, explicit removal and store-generation reset release objects. Separate copies per message slot give independent erasure. Worker admission reserves filesystem/WAL overhead and prunes up to 64 expired jobs per turn. |
| Removal suppression | One tombstone per explicitly removed source slot, owned by the raw app event rather than a rebuildable timeline row | Survives reopen, repair and source revalidation; cleared only by explicit download-again, raw-source deletion or store-generation reset. |

These are attachment-storage bounds, not convergence-input or engine-recovery policy.
C8-C2 schedules complete-body transfers only with explicit Rust opt-in; acquisition
defaults off until native local access/removal and policy controls land. C8-C3 adds protected partial downloads below.

| Worker structure | Bound | Reclamation |
| --- | --- | --- |
| Durable parser demand | One metadata row per eligible retained slot; 32 descriptors per turn, each at most 16 KiB | Generation-fenced acknowledgement after parse/admission; source deletion cascades; rebuild/acceptance regenerates affected demand. No repeated startup history scan. |
| Global automatic transfer permit | One per runtime across all accounts, including completed plaintext awaiting publication | Released on completion or worker exit. FIFO waiter future per active account prevents an account with a large backlog monopolizing capacity. |
| Background transfer body | Default 64 MiB ciphertext, configurable up to the existing 512 MiB ceiling; full-buffer crypto/publication plus SQLite copies | Cancellation discards the uncommitted tail; C8-C3 retains compatible ciphertext checkpoints. The next exclusive worker reclaims abandoned attempts in batches of 64 before scheduling, fencing old completions. |
| Resource admission | Default 2 GiB retained payload per account; 256 MiB disk reserve plus four maximum-size objects for SQLite/WAL | Pause on insufficient/unknown space without eviction or incrementing attempts. Existing 15-second maintenance tick revisits admission; network errors use durable 15-second to one-hour backoff; unavailable secrets defer one candidate for 15 seconds without consuming attempts. |
| Protected partial ciphertext (C8-C3) | One prefix per job, at most the configured transfer ceiling; writes at most 1 MiB; full declared partial size is reserved alongside retained payload in the account budget | Source/attempt/expiry fences on every write; terminal/parked state, success, source removal and explicit removal cascade cleanup. A 24-hour last-progress expiry is reclaimed in batches of 64 by non-frozen maintenance even when acquisition is disabled. Strong ETag, exact locator and ciphertext identity gate Range reuse. |

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

### Local attachment access (`marmot-app/src/runtime/attachment_access.rs`)

| State/resource | Bound | Lifetime / invalidation |
| --- | --- | --- |
| Metadata lookup input/output | At most 64 original source slots per call, each with two fixed-size message IDs and a slot index; output is opaque reference plus byte count | Call-local only; does not enqueue acquisition or retain payloads. Indexed SQL with length-only BLOB metadata. |
| Native local plaintext chunk | Caller-selected 1..=1 MiB per read through incremental SQLite BLOB access | Source visibility/expiry and account/store generation checked for every call. No background worker or network fallback; hosts discard assembled output if a later chunk is unavailable. |

No new long-lived runtime collection or database schema is introduced. These are
local-access bounds, not convergence or recovery policy.
