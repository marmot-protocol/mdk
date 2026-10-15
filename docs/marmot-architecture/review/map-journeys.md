---
title: "Review Map — Journeys"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, system-map, journeys]
status: draft
---

# Review Map — Journeys

Part of [Pass 0](00-system-map.md). Baseline `9c95ff2bf`. Six journeys traced through the stack, hop by hop, with the
task that runs each hop, what is persisted and what goes over the network. It is descriptive. Observations are inputs
to Pass 1. "(inferred)" marks a claim not read directly.

Task key: **B** is the binding future (UniFFI export, polled under `async_runtime = "tokio"`); **W** is the per-account
worker task (`crates/marmot-app/src/runtime/account_worker.rs:959`); **RP** is the relay-plane tasks; **S** is a
subscription actor; **BL** is the blocking pool. On Swift and Kotlin hosts, W, RP and S may share one OS thread; see
[the platform map](map-platforms.md#3-async-runtime-per-host).

## Journey 1: send a chat message

| # | Hop | Task | Persisted or sent |
| --- | --- | --- | --- |
| 1 | `Marmot::send_text` (`crates/marmot-uniffi/src/commands/message.rs:21`) → `MarmotAppRuntime::send_message` (`crates/marmot-app/src/runtime/mod.rs:2696`) → `AccountManager` sends `SendMessage` and awaits a oneshot (`runtime/commands.rs:1508`) | B | — |
| 2 | Worker arm → `send_message_on_worker` (`account_worker.rs:6218`). The command runs inline, so the receive and convergence arms wait | W | — |
| 3 | `AppClient::send_with_local_projection` (`client/mod.rs:4184`) builds and encodes the inner event | W | — |
| 4 | Optimistic local echo: `record_account_app_event_at` (`lib.rs:6526`) | W | One app-connection transaction: `app_events`, `message_timeline`, `chat_list_rows`, plus triggers |
| 5 | Down through `marmot-account` (`runtime.rs:2555`), `cgka-session`, the engine (`engine.rs:1076`), `do_send` (`message_processor/mod.rs:866`). Not `Stable`: queued in `cgka_queued_outbound`. Otherwise `create_message`, peeler wrap, sent row (`store.rs:336`) | W | Engine-connection transactions: `openmls_values`, `cgka_messages` |
| 6 | `publish_one` freezes an `OutboundFanout` before any I/O (`marmot-account/src/runtime.rs:4572-4600`) | W | `cgka_outbound_fanout` |
| 7 | `drive_outbound_fanout` (`runtime.rs:4632`) publishes to each relay concurrently through the relay-plane adapter (`relay_plane/mod.rs:4069`), with a 20 s deadline per relay (`ACCOUNT_PUBLISH_WAIT`, `relay_plane/mod.rs:100`), persisting after every result | W | Network: EVENT and OK per group relay |
| 8 | The adapter injects a `local-publish` delivery to every local route, including the sender, whose engine later classifies it as `OwnEcho` (`crates/transport-nostr-adapter/src/lib.rs:2648`) | W | — |
| 9 | Second projection transaction with the source id and read marker; `save_state`; push trigger publish (`client/mod.rs:4713-4763`) | W | App connection; network |
| 10 | Reply, then `schedule_pending_convergence_groups` (`account_worker.rs:2096`) | W | — |
| 11 | Back on B: `publish_chat_list_projection_refresh` (`runtime/mod.rs:2706`) rewrites the chat-list row again and broadcasts | B | App connection |
| 12 | Subscription actors filter the runtime broadcast into the host's stream (`runtime/subscriptions.rs:1151`, `:470`) | S | — |

Failure paths: an engine or transport error retracts the local row as failed (`client/mod.rs:4846`). A partial or
unknown acknowledgement leaves the row pending with the exact bytes in `cgka_outbound_fanout`; later convergence
passes resume the fanout (`marmot-account/src/runtime.rs:3361`).

**Observations**

1. **The worker is held across relay I/O.** A send can wait up to 20 s per relay before quorum, and that account's live
   receive and convergence pause meanwhile.
2. **The chat list is written twice per send,** once on W inside the projection transaction and again on B after the
   reply, each with its own broadcast.
3. **The payload is re-encoded repeatedly.** About 20 type conversions on the outbound path, including a
   bytes-to-String round trip and a full event-JSON round trip through `TransportMessage.payload`
   (`relay_plane/mod.rs:4083`).
4. **`AppClient` reaches the transport directly** (it holds `adapter` and `relay_plane`, `client/mod.rs:822-824`)
   as well as through `marmot-account`.

## Journey 2: receive and converge

| # | Hop | Task | Persisted or sent |
| --- | --- | --- | --- |
| 1 | nostr-sdk deduplicates relay copies; the relay-plane consumer feeds a bounded queue; overflow becomes typed loss (`relay_plane/mod.rs:2819-2895`) | RP | — |
| 2 | `handle_relay_notification` → adapter `deliveries_for` maps kind 445 to a group message and 1059 to a Welcome, and looks up routes in the `transport_group_id` index (`transport-nostr-adapter/src/lib.rs:1913`, `:3785`) | RP | — |
| 3 | Router `route_account_delivery` (`relay_plane/mod.rs:4165`): per-account `try_send`; if full, a durable spill or a persisted loss marker | RP | `account_delivery_spill` or loss evidence |
| 4 | Worker receive arm (`account_worker.rs:2320`) → `AppClient::receive_next_delivery` (`client/sync.rs:2615`), app-level dedup | W | — |
| 5 | `ingest_delivery` → `marmot-account` → session → `Engine::ingest_with_audit_context` (`engine.rs:1014`) → `do_ingest`: three more dedup checks (durable outcome, `seen_message_ids`, `sent_message_ids`) | W | — |
| 6 | Peel and classify (`ingest.rs:398-1230`). Commits at or above the live epoch, and future-epoch messages, are durably admitted into a convergence pass. Other messages apply in one transaction and yield `MessageReceived` | W | Engine connection: `cgka_messages`, `cgka_convergence_passes`, `pending_application_events` |
| 7 | Projection: `project_received_message` (`client/sync.rs:5698`) → `record_account_app_event_at` | W | App connection: timeline, chat list |
| 8 | Checkpoint: `save_state` writes the cursor, `seen_events`, `account_groups` and deletes the acknowledged `pending_application_events` rows in one transaction (`crates/storage-sqlite/src/account_projection.rs:1313`); then marks the account's chat list stale (`lib.rs:5941-5945`) | W | App connection |
| 9 | Broadcast `MessageReceived`, `ProjectionUpdated`, `GroupEvent`; schedule convergence; maybe start a recovery job (`account_worker.rs:2371-2466`) | W | — |
| 10 | Convergence timer arm takes one ready group and runs `advance_convergence` (`marmot-account/src/runtime.rs:2840`): resume fanouts, then the engine pass | W | Engine connection |

Out-of-order and competing commits are handled entirely in the engine: retryable rows, deferred peel generations,
rival commits entering the pass, and superseded own commits re-issued.

**Observations**

1. **Dedup happens in at least six places:** nostr-sdk, the app seen index, the engine's durable outcome,
   `seen_message_ids`, `sent_message_ids`, content dedup, plus the seen set borrowed by convergence.
2. **Every live checkpoint triggers a full chat-list rebuild on the next read.** The stale mark (`lib.rs:5941-5945`)
   makes the next chat-list read call `refresh_chat_list_rows`, which runs `rebuild_all_chat_list_rows_tx` for every
   row (`lib.rs:6084-6087`; `crates/storage-sqlite/src/chat_list.rs:666-674`). This happens even though the projection
   transaction already refreshed the affected row. The cost needs measuring.
3. **The pending-convergence set exists five times:** engine set, `SessionEffects`, `AccountDeviceEffects`,
   `AppClient.pending_convergence_groups` and `ScheduledConvergence`. See
   [the engine map](map-engine-contract.md#5-convergence).
4. **The engine outbox is acknowledged inside the app's transaction.** One table, two owners, two connections.
5. **Doc drift.** [`marmot-app-runtime.md`](../overview/marmot-app-runtime.md) says
   `take_pending_convergence_groups() → ScheduledConvergence::schedule_groups` runs at every loop entry. In code
   `schedule_groups` is `#[cfg(test)]` (`account_worker.rs:6655-6656`). Production schedules after each arm through
   `schedule_pending_convergence_groups` (`:6788`).

## Journey 3: invite and join

**Admin side**

| # | Hop | Task | Persisted or sent |
| --- | --- | --- | --- |
| 1 | `invite_members` (`crates/marmot-uniffi/src/commands/group.rs:752`) pre-checks admin status with a worker `GroupRoster` round trip | B → W → B | — |
| 2 | `InviteMembers` command → `invite_members_with_telemetry` (`client/mod.rs:2780`) | W | — |
| 3 | KeyPackage discovery: relay lists, then outbox relays, then a KeyPackage batch, under one 50 s deadline (`directory/member_key_packages.rs:40`, `:256-823`) | W | Network; directory cache |
| 4 | `refresh_routing` rebuilds all routes (`client/mod.rs:6774`) | W | — |
| 5 | Engine `do_send_invite` (`message_processor/send.rs:159`): stage commit and Welcomes, gift-wrap each Welcome, write projected members before publish (`send.rs:393-398`) | W | Engine connection, not one transaction |
| 6 | `record_welcome_delivery_intents` (`client/mod.rs:6921`) | W | `app_pending_welcome_delivery` |
| 7 | Publish the commit through a frozen fanout; on quorum, `confirm_published_fanout` merges (`crates/cgka-engine/src/publish.rs:50`) | W | Network to group relays; engine connection |
| 8 | Reply, then publish Welcomes to each recipient's inbox relays over the legacy `cgka_transport_fanout` (`marmot-account/src/runtime.rs:3997`) | W | Network |
| 9 | B spawns a catch-up task that sends `CatchUp` back into the worker (`runtime/commands.rs:54`) | B → W | — |

**Recipient side:** the inbox REQ delivers the gift wrap as in Journey 2. The app may peel it itself when the account
has blocked users (`client/sync.rs:3435-3444`). Engine `do_join_welcome` (`group_lifecycle.rs:956`) writes the group,
message, dedup markers, `GroupJoined` outbox row and KeyPackage lifecycle in one transaction. The worker broadcasts
`GroupJoined` and refreshes subscriptions so the group's kind-445 REQ goes out (`account_worker.rs:6908`).

**Observations**

1. **Admin authority is checked three times,** in UniFFI, in `AppClient` (`client/mod.rs:6067`) and in the engine
   (`send.rs:186`).
2. **KeyPackage discovery of up to 50 s runs on the worker** before snapshot reads start serving.
3. **There are three Welcome publication mechanisms:** post-confirmation Welcomes in `marmot-account`, the app's
   `UnpublishedWelcomeDelivery` with `app_pending_welcome_delivery`, and a startup retry task.
4. **Routing logic is duplicated** between `marmot-account`'s `StaticTransportRouting` and `marmot-app`'s
   `AppTransportRouting::publish_target` (`lib.rs:7535`).

## Journey 4: startup and shutdown

| # | Hop | Task | Notes |
| --- | --- | --- | --- |
| 1 | `Marmot::new` → `Marmot::open` (`crates/marmot-uniffi/src/lib.rs:296`, `:471`) → leased `MarmotApp` constructor (`crates/marmot-app/src/lib.rs:1801`): root lease, legacy audit cleanup, relay plane | Host thread | Synchronous; no DB opened |
| 2 | `start()` (`runtime/mod.rs:1682`): `warm_directory_storage` opens the shared store and then every account's directory cache sequentially (`directory/methods.rs:1874-1877`) | BL | One KDF and migration check per cache |
| 3 | `AccountManager::reconcile` spawns one worker per account; ready signals are awaited concurrently, 45 s each (`runtime/mod.rs:7047-7083`) | B | — |
| 4 | Worker open on BL (`lib.rs:1943`): `ensure_account_state` holds the process-wide `account_state_ready` mutex for the whole call (`lib.rs:6019-6045`); first app-connection open with salt probe, KDF and migration ledger (`lib.rs:6408-6505`) | BL | PBKDF2-HMAC-SHA512 at 256k iterations per open |
| 5 | `open_account` (`lib.rs:4467`): `load_state` (up to 16,384 seen ids), loss restore, then `AccountDeviceSession::open` opens a second connection to `session.sqlite` (`crates/cgka-session/src/lib.rs:336`) and seeds groups without loading MLS state (`engine.rs:1424`) | BL | A second KDF and migration check |
| 6 | Client restore on the worker: recovery owner, epoch-stall evidence, sweeps (`lib.rs:1958-2157`) | W | Synchronous SQLCipher on the async thread |
| 7 | Ready (`account_worker.rs:1110-1118`); `start()` returns when every account is ready. This is local readiness | W, B | — |
| 8 | Background hydration in batches of 4 groups, serving up to 8 commands between batches; mutations are deferred (`account_worker.rs:3496-3635`) | W | MLS loads on the worker |
| 9 | Initial sync: activate transport from cursor − 120 s, batched group REQs, and a recovery comparison if one of 2 process-wide credits is free (`client/sync.rs:1712-1804`) | W, RP | Network |
| 10 | Replay deferred commands; enter the steady loop with a 15 s maintenance tick (`account_worker.rs:1647-1803`) | W | — |

**Shutdown.** `shutdown()` stops workers (5 s each, then abort) but closes no databases and keeps the lease.
`shutdown_and_close()` (`runtime/mod.rs:6122`) runs in a runtime-owned task. It closes storage first, then gives
graceful shutdown a 5 s budget. `close_storage` (`lib.rs:6230-6300`) closes every connection in `account_storages`,
`directory_caches` and `shared_storage` with `wal_checkpoint(TRUNCATE)`, then drops the root lease.

**Observations**

1. **`close_storage` does not reach the engine's connection (observed; impact not yet reproduced; filed as
   [#2323](https://github.com/marmot-protocol/mdk/issues/2323)).** The engine's
   `session.sqlite` connection is opened inside `AccountDeviceSession::open` (`cgka-session/src/lib.rs:336-345`) and is
   not in any registry that `close_storage` drains. `storage-sqlite` has no per-path connection sharing. That
   connection is released only when the worker drops `AppClient` during the graceful phase, which runs after the
   lease is already released and is bounded by a timeout that only logs on expiry (`runtime/mod.rs:6165-6175`). The
   method's doc comment says "When this returns, nothing this process owns holds a file lock inside the Marmot root",
   and calls the databases "`Arc`s shared by the engine, the OpenMLS adapter, and app projections"
   (`runtime/mod.rs:6086-6093`); the code opens two separate connections. The suspension tests never start account
   workers (`src/tests.rs:20875-20918`), so they do not cover this connection. This bears directly on iOS
   `0xdead10cc`.
2. **Cold launch pays about five PBKDF2 runs per account:** three for `session.sqlite` (probe, app connection, engine
   connection) and two for the directory cache. The verdict cache that skips the probe is per process
   (`sqlcipher.rs:72`), and open-count reduction is tracked as mdk#1436 (`storage-format-v2.md:356-361`).
3. **Startup serializes where it looks parallel.** Directory caches open sequentially before any worker exists, the
   first account open of every account runs under one process-wide mutex, and `start()` waits for the slowest account.
4. **Heavy synchronous work runs on async threads:** client restore, hydration batches and the read snapshot.
5. **A receive error destroys and rebuilds the whole engine,** with eager re-hydration and most commands dropped during
   the 2-60 s backoff (`account_worker.rs:2486-2610`).

## Journey 5: history-loss detection and recovery

**Loss sources and detection**

- **Router placement** (`relay_plane/mod.rs:511-542`) sends each delivery to the account queue, to the durable spill
  (`relay_plane/delivery_spill.rs`, 8,192 rows / 16 MiB), or omits it with persisted loss evidence
  (`relay_plane/mod.rs:4233-4313`). A spill row that fails eight times is deleted and recorded as loss
  (`client/delivery_spill.rs:183-253`).
- **Notification lag** is charged as loss, and REQs are re-issued after a 30 s settle (`relay_plane/mod.rs:3053-3094`).
- **Epoch stall.** `detect_epoch_stall` (`client/sync.rs:3748-3839`) feeds the in-memory `EpochStallDetector`
  (`client/epoch_stall.rs`). Eight distinct undecryptable messages arm a backfill, a resource refusal arms
  immediately, and the third arm escalates to `EpochStallEscalated`.
- **Other demand:** cold start with no cursor, a bounded comparison at every startup, post-join history, explicit
  repair, and engine-released transport receipts.

**Execution.** One job per account, the same for every cause:

1. `start_pending_recovery_job` (`account_worker.rs:2946`) is tried after every delivery, every convergence and every
   15 s tick, and needs one of 2 process-wide credits.
2. Selection reserves work with 15 s to 5 min backoff (`crates/storage-sqlite/src/account_recovery.rs:585`) and freezes
   a plan: at most 4 routes, 16,384 inventory items per route.
3. The network phase runs in a spawned task (`client/sync/comparison_job.rs:356`): NIP-77 comparison, exact-id
   fetches, and epoch-gap window REQs, under a 10 s deadline.
4. Admission returns to the worker, oldest first, at most 4 events per turn through the normal ingest path
   (`comparison_job.rs:716-738`).
5. Settlement checkpoints, seals the transport cursor for loss, releases the credit and publishes notice changes
   (`client/sync.rs:4623-5105`).

**Obligation state machine** (`account_recovery_obligations`, migrations 0092 and 0098; durable):

| State | Meaning | Leaves by |
| --- | --- | --- |
| Ready / Retry | Due when `not_before` passes | Attempt and checkpoint |
| WaitingCapacity | Admission refused | Retry after the base delay |
| WaitingCapability | Relays unsupported | A route or capability change |
| NeedsDeepRepair (parked) | 3 quiet or 6 unserved passes; shown to the user as a "history may be incomplete" notice | A route change, new evidence, or dismissal |
| Satisfied | Coverage qualified | Inventory invalidation or unacknowledged loss |
| Retired | Dismissed by the user | New demand above the watermark |

Ownership is spread across five places: the relay plane (placement, spill, loss, all recovery network I/O), storage
(the durable machine and fences), `AppClient` (detector, plans, admission, settlement, cursor seal), the worker
(scheduling and the job slot) and the process-wide credit pool.

**Observations**

1. **Important recovery state is memory-only:** the stall detector's arm count, escalation latch, failed-arm buffer and
   loss fence (`epoch_stall.rs:271-310`; `client/sync.rs:3893-3897`).
2. **Some tables have more than one writer despite "single writer" comments:** `app_epoch_stall_evidence` and
   `app_group_recovery_failures` (`account_projection.rs:735-739` vs `account_recovery/stall.rs:121-125`). Epoch-gap
   rows are mutated from about five places.
3. **Selection does real work on every delivery while debt waits.** It imports loss, hashes every route and queries
   eligibility before checking the retry time (`client/recovery.rs:510-525`, `:985-1033`).
4. **Two credits are shared by all accounts.** One slow account can hold a credit through worker-paced admission while
   the others silently defer.
5. **Explicit repair serves only reads while it runs,** with no live-receive arm, for a credit wait plus 60 s
   (`account_worker.rs:4276-4306`).
6. **Incremental history is tracked twice,** as an obligation and in a separate comparison table, kept in step by hand.

## Journey 6: attachment download, re-download and upload

| # | Hop | Task | Persisted or sent |
| --- | --- | --- | --- |
| 1 | A projected message carries `imeta` tags into `message_timeline.media_json`; triggers expand them into `attachment_history` (0081) and `attachment_worker_demand` (0084) | W | App connection, inside the projection transaction |
| 2 | Demand: native automatic (default), host-managed approval, or explicit controls (`runtime/account_worker/attachments.rs:51-86`; `runtime/attachment_controls.rs:70-171`) | W, BL | — |
| 3 | `attachments::schedule` (`attachments.rs:149-414`): per-account permits, one runtime-wide transfer slot (`runtime/mod.rs:370`, `:483`), disk and quota checks, leases of 3 min (automatic) or 20 min (explicit), one transfer per call via `tokio::spawn` | W | `attachment_acquisition` |
| 4 | Fetch through the pinned, redirect-vetted Blossom client with Range and If-Range resume (`media/blossom.rs`; `media/attachment_resume.rs:482-503`). Automatic bodies are buffered in memory; SHA-256 and ChaCha20-Poly1305 run inside the async task (`media/mod.rs:1151-1373`). Large explicit bodies decrypt on BL into a plaintext temp file (`media/file_transfer.rs:405-530`) | Spawned task, BL | Network; 1 MiB partial checkpoints |
| 5 | Retain: memory bodies in one transaction on the worker (`account_worker.rs:4106`); file bodies about 1 MiB per transaction on BL (`attachment_acquisition/file_import.rs:34-156`). Triggers count usage | W, BL | `retained_attachment_chunks` |
| 6 | Host reads up to 1 MiB per FFI call on BL; no file path is handed out (`runtime/attachment_access.rs:62-80`) | BL | — |
| 7 | Upload: snapshot, streaming encryption to a temp file on BL, PUT with fallback, staged bytes promoted after the message commits (`media/file_transfer.rs:532-744`; `attachment_acquisition/outgoing.rs:145-171`) | BL, W | Network; chunk store |

**Acquisition state machine** (`attachment_acquisition.state`, migration 0083; durable):

| State | Leaves to |
| --- | --- |
| Queued | Fetching, RetryScheduled, Blocked, Parked |
| Fetching (lease and nonce) | Ready, RetryScheduled, Blocked; on worker restart back to Queued, Blocked or Parked |
| RetryScheduled (15 s doubling to 1 h) | Fetching, Queued |
| Ready | Only by row deletion: source invalidation, expiry, explicit removal, reset |
| Blocked | Queued on explicit retry, storage readmission or a raised limit |
| Parked | Queued on demand or permission resume |

Hosts see 16 derived states (`attachment_acquisition/controls.rs:843-866`).

**Observations**

1. **A full budget makes progress stop without eviction.** In native mode, every 15 s the scheduler walks candidates,
   and over-budget verified bodies are fetched and then discarded (`attachments.rs:544-546`). Nothing evicts.
   "Re-download" means only after explicit removal or retry.
2. **Hashing and AEAD over bodies of up to 512 MiB run on async threads.**
3. **Plaintext can sit outside SQLCipher:** a decrypted staging file can survive a crash for 24 h or more
   (`file_transfer.rs:196-436`). A large body can exist in up to four copies at peak.
4. **One runtime-wide transfer slot** means an explicit tap can wait behind another account's automatic transfer
   (`attachments.rs:253-258`).
5. **Ownership is spread across** SQL triggers, storage, the worker scheduler, resume and permission code: about 20
   status columns and five physical byte layouts.
6. **Docs drift.** [`attachment-acquisition.md`](../further-context/attachment-acquisition.md) predates migrations
   0103–0109.

[#2314](https://github.com/marmot-protocol/mdk/issues/2314) changes this journey. It replaces the retained-budget
gate with a free-disk gate and a typed `StorageFull` state (observation 1), keeps partials as wire-ciphertext files
and encrypts outgoing sources directly (observation 3, except for explicit handoff leases), and moves bytes out of
`session.sqlite`. It does not yet say which task runs file I/O and AEAD (observation 2), and it leaves the
runtime-wide transfer slot (observation 4) and the spread of ownership (observation 5) as they are.
