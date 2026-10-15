---
title: "Review Map — Concurrency"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, system-map, concurrency]
status: draft
---

# Review Map — Concurrency

Part of [Pass 0](00-system-map.md). Baseline `9c95ff2bf`. This page maps how hosts drive the runtime, which tasks
exist, what the per-account worker does inline, and the channels and locks between them. It is descriptive.
Observations at the end are inputs to Pass 1 system B. "(inferred)" marks a claim reasoned from code but not traced;
"(dep)" cites a crate in the cargo registry.

## 1. Topology

```text
 Swift / Kotlin host               C host                         wn / wnd, wn-agent
 async export ─ async_compat ─┐    blocking marmot_* calls        #[tokio::main], multi-thread
 sync export (host thread)    │    one multi-thread runtime        Unix socket accept loop
                              ▼    per client
   one current-thread runtime on the "async-compat/tokio-1" thread (every tokio::spawn lands here)
                              │
   MarmotAppRuntime ── runtime events: broadcast(1024) ──► subscription forwarders ──► host streams
                              │
   AccountManager (worker map, worker_transactions lock)
                              │  mpsc(8) AccountWorkerCommand + oneshot reply (10 s / 2 min / 16 min)
                              ▼
   account worker task, one per account
     owns AppClient → AccountDeviceRuntime → AccountDeviceSession → Engine<SqliteAccountStorage>
     inline: MLS crypto, synchronous SQLCipher, relay publish awaits
     offloaded: recovery comparison job, Welcome relay I/O, media HTTP (≤ 4), file-backed attachment completion
          ▲ per-account delivery mpsc(1025), plus durable spill or loss marker
   relay-plane router task: adapter.receive() → route_account_delivery (try_send only)
          ▲ shared delivery mpsc(1024)
   per-account notification lane: supervisor → consumer → mpsc(4096) → event worker
          ▲ nostr-sdk notifications on the account's own SDK client
```

## 2. How hosts drive the runtime

| Host | Runtime | Notes |
| --- | --- | --- |
| Swift and Kotlin | UniFFI wraps every async export in `async_compat::Compat` (dep `uniffi_macros-0.29.4/src/export/scaffolding.rs:281-283`). With no runtime current, Compat uses one static `new_current_thread()` runtime driven by a single thread (dep `async-compat-0.2.5/src/lib.rs:456-469`). MDK builds no runtime in `marmot-uniffi`. | About 234 async and 102 sync exports. Sync exports read storage on the caller's thread; the README tells hosts to keep them off the UI thread (`crates/marmot-uniffi/README.md:131-133`). |
| C | One `new_multi_thread()` runtime per client (`crates/marmot-c/src/lib.rs:521-542`). Calls go through `block_on`, or `block_in_place` when re-entered from a callback (`:122-139`). | C callbacks run on runtime worker threads (`crates/marmot-c/src/subscriptions.rs:208-236`). |
| `wnd` | `#[tokio::main]` multi-thread (`crates/cli/src/bin/wnd.rs:4`) | Runtime behind an async mutex held across `start()` and `reconcile_accounts()` (`crates/cli/src/daemon/runtime_host.rs:61-68`). Uses `shutdown`, never `shutdown_and_close`. |

Lifecycle entry points are `start`, `shutdown`, `shutdown_and_close`, `notify_connectivity_restored`,
`collect_notifications_after_wake` and `catch_up_accounts`. There are no foreground, background, suspend or resume
hooks; see [the platform map](map-platforms.md#4-lifecycle).

## 3. Tasks

About 54 production `tokio::spawn` sites in `marmot-app`, plus 25 direct `spawn_blocking` calls and about 78
`blocking_app_task` call sites (a `spawn_blocking` wrapper, `crates/marmot-app/src/runtime/mod.rs:8944-8953`).
`marmot-account`, `cgka-session` and `cgka-engine` spawn nothing in production.

| Task | Scope | Owner and cancellation |
| --- | --- | --- |
| Account worker (`runtime/account_worker.rs:967`) | Per account | `AccountManager.workers`; shutdown signal, abort after 5 s |
| Recovery comparison job (`client/sync/comparison_job.rs:356`) | Per job; 2 per process | Aborted on drop; 10 s quantum |
| Media HTTP (`account_worker.rs:3974`) | Per transfer; 4 per account | Detached; lifecycle watch |
| Relay router (`relay_plane/mod.rs:2195`) | Per relay plane | Aborted at relay-plane shutdown |
| Notification supervisor, consumer, event worker (`relay_plane/mod.rs:2654`, `:2667`, `:2834`) | Per account | Aborted on retire or deactivate |
| Subscription forwarders and window actors (`runtime/subscriptions.rs:1052-1810`; `conversation_window.rs:941`; `chat_list_window.rs:249`) | Per host subscription | Detached; end on lifecycle watch or channel close |
| Directory sync, setup, onboarding, catch-up tasks | Per runtime or account | Tracked handles reaped in `AccountManager::shutdown` (`runtime/mod.rs:8707-8760`) |
| Spill writer, loss persistence, moderation retry | On demand | Detached; run to completion |
| Telemetry exporter, analytics worker, audit uploader | Per runtime | Aborted on restart or stop |

## 4. The account worker

The worker owns the account's whole stack and runs a biased `select!` loop (`account_worker.rs:1803`, `:1911-2932`).
Arms in priority order:

1. lifecycle shutdown;
2. explicit shutdown;
3. completions: the recovery job, Welcome recovery and media HTTP;
4. commands, alternating with convergence;
5. an owed local-submission retry;
6. the convergence timer (one group per fire);
7. live delivery receive and ingest;
8. avatar, presentation and attachment maintenance;
9. local-submission wakeups;
10. a recovery yield;
11. the 15 s maintenance tick.

`AccountWorkerCommand` has 89 variants (`account_worker.rs:339-751`):

| Category | Count |
| --- | ---: |
| Group and MLS mutations that publish | 20 |
| Local reads | 15 |
| Key packages and maintenance | 12 |
| Sync, recovery and control | 10 |
| Local-only group state | 7 |
| Media | 7 |
| Messaging | 6 |
| Push registration | 5 |
| Test-only | 5 |
| Audit | 2 |

**Runs inline on the worker task:** engine ingest (one delivery per turn), engine send plus the relay publish await
(20 s per relay), one convergence pass, explicit catch-up, KeyPackage catch-up (up to 15 s), due maintenance, hydration
batches and client restore. Storage is synchronous `rusqlite` behind a `std::sync::Mutex`
(`crates/storage-sqlite/src/connection.rs:182`), and nothing in `storage-sqlite`, `cgka-session` or `cgka-engine` uses
`spawn_blocking`. So SQLCipher I/O and MLS crypto run on the async thread (inferred from those facts).

**Offloaded:** recovery network I/O, Welcome relay I/O, media HTTP, file-backed attachment completion, and
local-submission admission.

**What a command can wait behind:**

| Worker phase | Served immediately | Queued | Rejected |
| --- | --- | --- | --- |
| Startup sync, explicit catch-up | Snapshot reads (members, roster, MLS state) | Sends and other mutations | Conversation capture (`NotReady`); invite accept and rejoin (`AccountWorkerBusy`) |
| Convergence pass, Welcome fanout, full-history repair (`account_worker.rs:4276-4363`) | Snapshot reads | Everything else | Conversation capture |
| Maintenance tick, single ingest, single command | Nothing | Everything | — |
| Reconnect backoff (`account_worker.rs:2490-2560`) | `CatchUp` and `ConnectivityRestored` end the sleep | — | Every other command is dropped (`TransportClosed`) |

Two send paths exist: `send_text` waits for the worker's publish (`crates/marmot-uniffi/src/commands/message.rs:30`),
while `submit_text` returns after durable admission (`crates/marmot-uniffi/src/commands/local_submissions.rs:46`).

## 5. Channels

| Channel | Capacity | When full or lagged |
| --- | --- | --- |
| Worker commands (`runtime/mod.rs:7067`) | mpsc(8) | Sender awaits with no deadline; only the reply wait is bounded (10 s, 2 min or 16 min; `lib.rs:413-423`). The worker drains it into an unbounded `pending` queue during exclusive phases (`account_worker.rs:4286-4363`). |
| Runtime events (`runtime/mod.rs:1537`) | broadcast(1024), shared by all accounts | Forwarders re-read snapshots on lag; `RuntimeEventsSubscription` skips lost events silently (`runtime/subscriptions.rs:888`) |
| Per-account deliveries (`relay_plane/mod.rs:74`) | mpsc(1025) | Router `try_send`; full → durable spill, else drop with a loss marker |
| Shared adapter deliveries (`transport-nostr-adapter/src/lib.rs:110`) | mpsc(1024) | `send().await` back-pressures the notification lane |
| Notification queue (`relay_plane/mod.rs:91`) | mpsc(4096) per account | Full → treated as lag, loss recorded |
| Media admission (`runtime/mod.rs:65`) | Semaphore(8) per account | Callers wait up to 16 min |

## 6. Locks

| Lock | Kind | Held across await or blocking work? |
| --- | --- | --- |
| `worker_transactions` (`runtime/mod.rs:250`) | `tokio::sync::Mutex<()>` | Yes: across worker shutdowns and ready waits of up to 45 s (`:6866-6868`, `:7097-7106`); command lookups can reach it through `reconcile_for_account` (`:7581-7587`) |
| `storage_lifecycle` (`lib.rs:509`) | `std::sync::RwLock<()>` | Read guard held across the synchronous SQLCipher open and migrations (`lib.rs:6346-6355`) |
| SQLite connection (`connection.rs:182`) | `std::sync::Mutex<Option<Connection>>` | Blocking by nature. BUSY retries call `std::thread::sleep` (`connection.rs:94-106`), with up to 6 attempts and a 5 s `busy_timeout` each |
| `directory_subscription_sync` (`relay_plane/mod.rs:112`) | `tokio::sync::Mutex` | Yes, across network I/O |
| `incremental_activation` (`relay_plane/mod.rs:231`) | `tokio::sync::Mutex` | Yes, across EOSE checks and activation |
| Adapter `subscription_lock` (`transport-nostr-adapter/src/lib.rs:1082`) | `tokio::sync::Mutex` | Yes, across relay subscribe and unsubscribe, documented |
| `wnd` `DaemonWorkers` (`crates/cli/src/daemon/mod.rs:85`) | `tokio::sync::Mutex` | Yes, across `start()` and reconcile |

## 7. Transport adapters and notification consumers

There are two `TransportAdapter` implementations, but they are not alternatives. `NostrTransportAdapter`
(`crates/transport-nostr-adapter/src/lib.rs:2262`) is the relay plane's shared internal core.
`MarmotRelayPlaneAccountAdapter` (`crates/marmot-app/src/relay_plane/mod.rs:3994`) is the per-account adapter that
the engine stack uses. It delegates activation, sync, publish accounting and local fanout to the core. Production
notifications flow through the relay plane's per-account supervisor. `spawn_notification_forwarder` in the adapter
crate is public but called only from tests. A shared relay-plane forwarder exists for single-account SDK clients
(`relay_plane/mod.rs:2135-2160`) and does not run in production, because production builds a multi-account client
(inferred).

## Observations for Pass 1

1. **One thread runs everything under UniFFI.** All account workers, the router, notification lanes, timers and the
   terminal-close task share the single `async-compat` thread. Synchronous SQLCipher or MLS work in one worker
   stalls every other account. It can also delay the notification lanes enough that their queues overflow and
   events count as loss, which then triggers recovery work. C and CLI hosts run the same code on multi-thread
   runtimes, so behaviour differs by binding.
2. **Blocking work runs on async threads.** A busy write can retry for about 30 s worst case with `thread::sleep`
   inline on the worker (inferred arithmetic). Account open runs under a std `RwLock`. Account removal deletes files
   inside an async function (`runtime/mod.rs:6588-6611`).
3. **Timeouts are inconsistent.** Reads such as `Members` use a 10 s reply deadline meaning "wedged worker"
   (`lib.rs:413-416`), while inline maintenance catch-up can run for 15 s without serving commands.
4. **The bounded command channel feeds unbounded queues.** During exclusive phases the worker moves commands into an
   unbounded `pending` or `deferred` queue.
5. **Control signals wait behind work.** `ConnectivityRestored` shares the FIFO and is deferred during convergence and
   catch-up. `notify_connectivity_restored` sends to accounts one after another with no deadline
   (`runtime/mod.rs:7272-7278`).
6. **The global reconcile lock is on the command path.** A command lookup can wait behind another account's startup
   for up to 45 s (inferred).
7. **The event broadcast is lossy and shared.** One 1024-slot broadcast carries every account's events, and one
   subscription type drops lagged events silently.
8. **Whether the router starts depends on call order.** `spawn_router` silently does nothing without a current Tokio
   runtime (`relay_plane/mod.rs:2132-2134`). Under UniFFI's synchronous constructor, the router first starts when an
   account adapter is built.
9. **Shutdown does not join detached tasks.** Subscription forwarders, window actors, media HTTP, the spill writer and
   moderation retry drop their handles and end only through the lifecycle watch or a closed channel.
10. **Every command crosses an actor boundary.** 89 command variants, each a request and reply over channels, give
    the worker a very wide interface. Every new product feature adds to it.
