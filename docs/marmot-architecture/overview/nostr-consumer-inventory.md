---
title: "Nostr Consumer Inventory and Ownership Map"
created: 2026-11-27
updated: 2026-11-27
tags: [marmot, overview, nostr, transport, ownership]
status: overview
---

# Nostr Consumer Inventory and Ownership Map

This document is the canonical inventory of every Nostr relay consumer in MDK following the `#2897` consolidation onto
the shared Nostr integration (baseline verified against `master` post-`#3835`, commit `f95a40c82`). It records the
factory/auth context, identity validation, request/loss ownership, completion/ACK semantics, and shutdown owner for
each consumer, and distinguishes shared transport guarantees from intentionally domain-specific contracts.

For the bounded acquisition interface see [nostr-bounded-acquisition-interface.md](./nostr-bounded-acquisition-interface.md);
for the account-transport subsystem overview see [nostr-account-transport.md](./nostr-account-transport.md); for
transport-agnosticism boundaries see [transport-agnosticism.md](./transport-agnosticism.md).

## Shared Guarantees vs Domain-Specific Contracts

### Shared across the Nostr integration

- **One client factory and dial/proxy discipline:** Every production `nostr_sdk::Client` is constructed through
  `transport_nostr_adapter::network_proxy::nostr_builder()` (re-exported via `transport_nostr::nostr_builder()`).
  Crate-level `clippy.toml` `disallowed-methods` rules forbid direct `Client::new`, `Client::builder`, and
  `ClientBuilder::new` calls across `transport-nostr-adapter`, `transport-nostr`, `nostr-directory`, `marmot-app`, and
  `marmot-c`.
- **One host-safety chokepoint:** Every relay URL enters through `transport_nostr::RelaySafetyPolicy` (enforcing
  `wss://` for public hosts, loopback behind the explicit dev/test flag, URL canonicalization, and retired-relay
  denylist rejection).
- **One finite-request component:** `transport_nostr_adapter::FiniteRequests` + `DivertTransport` owns every bounded
  one-shot REQ across history sweeps, NIP-77 comparison ID fetches, `KnownEventIds` acquisition, `read_back`, plain and
  strict directory reads, public event fetches, and onboarding/health inspections. Replies are diverted off the
  WebSocket stream by reserved `~f*` subscription IDs before `nostr-sdk`'s reader, admitted against the process-wide
  FIFO `QueueBudget` (`DEFAULT_GLOBAL_QUEUE_BYTES = 192 MiB`) and per-fan-out `SharedBudget`, classified explicitly on
  local backpressure (`FiniteEnd::Busy` -> `LocalBusy`), and retired cleanly via `FiniteRequests::shutdown()`.
- **One recovery scheduler:** `marmot-app`'s `client/history_recovery/` (`#2660`) is the sole owner of recovery
  obligations, scheduling, durable frontiers, and completion fences.
- **Strict transport boundary:** `cgka-engine`, `cgka-traits`, and `storage-sqlite` contain zero `nostr_sdk` types.
  Subscription IDs, relay URLs, NIP-67 EOSE hints, and raw wire frame parsing remain inside `transport-nostr-adapter`
  and `transport-nostr`.

### Intentionally domain-specific (kept separate)

- **NIP-46 remote signer (`marmot-app/src/nip46/transport.rs`, `marmot-c/src/nip46.rs`):** Keeps an independent
  executor, signer session, and request/response RPC matching so signer callbacks cannot deadlock against account
  workers or route signer RPCs through account recovery storage.
- **Device pairing (`marmot-app/src/client/device_pairing/live.rs`):** Keeps ephemeral in-memory session state and a
  bounded `PairingInbox` (`INBOX_CAPACITY = 64`) fed by the account Welcome peeler; restarts end pairing sessions
  rather than forcing ephemeral pairing through durable history recovery.
- **Anonymous group WRITE vs authenticated account contexts:** Group writes use an anonymous publish pool (never
  answering NIP-42 AUTH with account identity), while account/KeyPackage/relay-list publishes and inbox/group receive
  contexts use per-account signer-bound clients. Shared factories never merge sockets that intentionally carry
  different authentication identities.
- **Directory negative proofs:** Strict directory reads (`fetch_directory_events_with_completion`) enforce per-REQ
  `raw_items == received_items`, 3-filter strfry chunking (`mdk#2269`), `RELAY_REPLAY_PAGE_LIMIT` clamp detection, and
  NIP-67 `more`/`auth` withholding checks so dropped or clamped frames never certify deletion/record absence.
- **Publishing ACK semantics:** Publish success is decided strictly by relay `OK` ACK quorum (`required_acks`) and
  durable outbox/fan-out tracking, never by fetch completion.

## Complete Consumer Map

| Consumer | Code Owner | Factory / Auth / Executor Context | Identity & Copy Validation | Request / Coalescing / Loss Ownership | Durable-Success or RPC / ACK Semantics | Shutdown Owner |
| --- | --- | --- | --- | --- | --- | --- |
| **Live group (`kind 445`)** | `transport-nostr-adapter/src/sdk_client.rs`, `transport-nostr/src/lib.rs` | `NostrSdkRelayClient::multi_account()` via `nostr_builder()`; per-account immutable NIP-42 signer context | Per-message `RelayCopy` copy verification + `h`-tag route matching before account delivery | Account-scoped `AccountReceiver` loss watermark + `notification_loss_floor` + durable overflow spill (`delivery_spill.rs`) | Idempotent durable MLS admission in `marmot-session` / `storage-sqlite`; live delivery never certifies completeness | `MarmotRelayPlane::shutdown()` (drains SDK pool, forwarders, spill writers, loss-marker tasks) + `retire_account_session_transport` / `deactivate_account_context` |
| **Inbox / Welcome (`kind 1059`)** | `transport-nostr-adapter/src/sdk_client.rs`, `transport-nostr/src/lib.rs` | Same per-account immutable NIP-42 signer context in `NostrSdkRelayClient::multi_account()` | Per-message `RelayCopy::RawInbox` verification on each relay `RelayMessage::Event` (does not rely on SDK first-seen dedup) | Same per-account `AccountReceiver` loss watermark, `notification_loss_floor`, and durable overflow spill | Idempotent durable Welcome/gift-wrap admission and peeler processing records | `MarmotRelayPlane::shutdown()` and `deactivate_account_context` |
| **Live directory (`kinds 0, 10002, 10050, 30443, 5`; local accounts also `3, 10000`)** | `transport-nostr/src/lib.rs`, `transport-nostr/src/directory.rs`, `nostr-directory/src/sync.rs` | `anonymous_directory_client()` via `nostr_builder()` (anonymous, no account signer) | Per-message `RelayMessage::Event` signature verification + active subscription `(endpoint, subscription_id, author, kind, tags)` filter check + kind-3/30443/5 freshness/deletion guards | `DirectoryRelayPlane` subscription map + `DirectoryRelayPlaneEvent::RecoveryRequired` on lag/overflow | Directory cache SQLite persistence with freshness/deletion watermarks | `MarmotRelayPlane::shutdown()` (shuts down `directory_client` and aborts/joins `directory_notification_forwarder`) |
| **Ordinary & strict directory fetches** | `transport-nostr/src/directory.rs` | Stateless `NostrSdkDirectoryRelayFetcher` creating an isolated anonymous `ScopedDirectoryClient` (`FiniteRequests::install(nostr_builder())`) per read | `FiniteRequests` collector verifies ID, signature, SDK limits, expiry, and filter match; strict reads require `raw_items == received_items`, `!more`, `!auth`, `< limit.min(500)` per REQ | `DirectoryRelayPlane` single-task `coalesce_fetch` with synchronous `CoalescedWaiterGuard` (one cancelled waiter keeps shared work alive; final-waiter loss cancels `CancellationToken`) | Plain reads fail closed on `ByteLimit`/`InvalidMessage`/`Busy`; strict reads return per-endpoint `complete_endpoints` negative proofs | `ScopedDirectoryClient::shutdown()` (joins `finite.shutdown()` + `client.shutdown()`) + `DirectoryRelayPlane::shutdown()` inside `MarmotRelayPlane::shutdown()` |
| **Onboarding & relay-health inspection** | `transport-nostr/src/directory.rs`, `marmot-app/src/client/relay_health/`, `onboarding.rs` | Isolated `ScopedDirectoryClient::from_builder` with optional request-scoped `InspectionAuthenticator` (never mutates shared pools) | `FiniteRequests` per-message verification + `AuthWatch` (`AUTH_CHALLENGE_WAIT`) + `verified_inbox_answer` / `directory_closed_reason` classification | Uncoalesced per-probe request with optional `inspection_budget`; local queue deferral maps to `DirectoryInspectionError::LocalBusy` (not a relay fault) | Structured `DirectoryInspectionError` / `Partial { records, cause }`; `LocalBusy` excluded from relay-health `answered` and retryable in onboarding | `ScopedDirectoryClient` `Drop` / caller cancellation immediately calls `relay.shutdown()` and bounded `finite.shutdown()` + `client.shutdown()` |
| **Previews, stickers, emoji sets** | `transport-nostr/src/directory.rs` (`fetch_public_events`), `nostr-directory/src/previews.rs`, `marmot-app/src/{stickers,emoji_sets}.rs` | Isolated anonymous `ScopedDirectoryClient` (`FiniteRequests::install(nostr_builder())`) per read | `FiniteRequests` per-message ID/signature/filter verification + per-relay `sources` attribution | Bounded `SharedBudget` (`DIRECTORY_REPLY_MAX_BYTES`) across relays + `max_events` cap | Best-effort `PublicEventFetch { events, complete, sources }`; callers re-check domain references | `ScopedDirectoryClient::shutdown()` on exit + `Drop` safety net on cancellation |
| **KeyPackage recovery** | `nostr-directory/src/key_package_recovery.rs` | Delegates all relay reads to `DirectoryRelayPlane` (`fetch_directory_events_with_completion`) | Inherits strict `FiniteRequests` per-REQ absence proofs and scoped `#e`/`#a` deletion verification | Coalesced through `DirectoryRelayPlane`; recovery policy and retry cadence stay in `nostr-directory` | Durable scoped-deletion journal + KeyPackage availability watermarks | Governed by caller cancellation and `DirectoryRelayPlane::shutdown()` |
| **History recovery (`sweep`, `compare`, `KnownEventIds`)** | `marmot-app/src/client/history_recovery/`, `transport-nostr-adapter/src/{sweep,compare,finite_req,sdk_client}.rs` | Runs over the account's `NostrSdkRelayClient` context via `FiniteRequests` (`~f*` diverted REQs) and bounded dry-run NIP-77 compare | `FiniteRequests` collector verifies ID, signature, SDK limits, expiry, database deletion status, admission policy, and filter match | One recovery scheduler (`#2660`); global `QueueBudget` admission (`FiniteEnd::Busy` -> `LocalBusy` -> `Unanswered`); bounded dry-run NEG deadline | Recovery runner durable obligations, cursor/frontier advancement, and idempotent engine/storage admission | Request `CancellationToken` + `NostrSdkRelayClient::shutdown()` (`begin_shutdown()` -> `client.shutdown()` -> `join_shutdown()`) |
| **Device pairing** | `marmot-app/src/client/device_pairing/live.rs`, `transport-nostr-adapter/src/pairing.rs` | Inbound via account inbox `kind 1059` Welcome peeler (`PairingInbox`); outbound via account publish adapter | `read_pairing_rumor` verifies account pubkey and NIP-59 gift-wrap/rumor structure | Ephemeral bounded `PairingInbox` (`INBOX_CAPACITY = 64`), drop-oldest under flood | Ephemeral in-memory SAS/link state machine; confirmed device links persist only after MLS device-group join/commit | In-memory session TTL / explicit cancel / process restart |
| **NIP-46 remote signer** | `marmot-app/src/nip46/transport.rs`, `crates/marmot-c/src/nip46.rs` | Dedicated `nostr_builder(Ok(proxy)).build()` client on independent NIP-46 executor | `validated_payload` verifies NIP-44 decryption, expected remote pubkey, and JSON-RPC request/response ID matching | Request-response RPC matching on dedicated `kind 24133` subscription + readiness EOSE probe | Synchronous RPC ACK/response semantics; never routed through account recovery storage | Dedicated NIP-46 session teardown (`client.shutdown().await` on transport replacement/logout/close) |
| **Publishing & `read_back`** | `transport-nostr/src/lib.rs`, `known_limits.rs`, `read_back.rs`, `transport-nostr-adapter/src/sdk_client.rs` | Unified `NostrSdkRelayClient::from_builder_with_account_signer`: anonymous adapter-owned publish pool for group WRITE & `read_back`; signer-bound cached `ManagedSdkPublishClient` per account for KeyPackages/relay lists | `KnownLimitPublishClient` rejects events exceeding known relay limits before wire send; `read_back` verifies exact event ID + signature via `FiniteRequests` | Publish accounting tracks attempts/successes/failures/cancellations; `read_back` bounded by per-account per-relay hourly cap | Relay `OK` ACK quorum (`required_acks`) + durable outbox/retry; `read_back` reports `Found`/`NotFound` only on exact verified event / EOSE | `PublishClientRegistry` tears down signer-bound clients on eviction, replacement, `deactivate_account_context`, and `MarmotRelayPlane::shutdown()`; adapter-owned anonymous pools tear down on last adapter drop or `deactivate_account_context` |

## Deleted Obsolete Implementations (`#2897`)

- **Dead `reconcile_subscription` stack (`#3789`):** Removed legacy route-level subscription reconciliation and added a
  bounded dry-run NIP-77 comparison deadline (`neg_sync_dry_run`). `NostrAdapterMetrics::reconciliation_*` and the
  exported `relay_reconciliation_attempts` / `relay_reconciliation_order_unproven_passes` telemetry counters are
  retained as always-zero fields for snapshot/telemetry schema stability (see `telemetry.md` and
  `relay-observability.md`) until a future breaking telemetry-schema cleanup removes them.
- **First-seen-only live directory & inbox admission (`#3791`, `#3814`):** Replaced reliance on `nostr-sdk` first-seen
  deduplication with per-message `RelayMessage::Event` verification in live directory forwarding and `RelayCopy::RawInbox`
  in live kind-1059 inbox delivery.
- **Duplicate `DirectoryWireTransport` prefilter wrapper (`#3831`):** Deleted `crates/transport-nostr/src/directory_wire.rs`
  after migrating `strict_fetch_endpoint` onto `FiniteRequests` per-REQ `raw_items == received_items` accounting.
- **Detached directory coalescers, duplicate `ScopedInspectionClient`, and idle standalone directory `Client` (`#3835`):**
  Replaced both detached coalescers with one waiter-counted `DirectoryRelayPlane::coalesce_fetch`, unified per-read
  teardown in `ScopedDirectoryClient`, and made `NostrSdkDirectoryRelayFetcher` zero-sized and stateless.

## Host Synthetic `--release` Measurement Summary (Linux x86_64, In-Process Mock Relays)

Synthetic host-proxy measurements on `master` (`f95a40c82`, post PRs 1–6) using `cargo run --release` against local
in-process `nostr-relay-builder` relays and custom WebSocket relays are recorded on
[mdk#2897](https://github.com/marmot-protocol/mdk/issues/2897):

- **Foreground live latency under burst:** `30/30` live kind-445 events delivered with **p50 `0.97 ms`**, **p95 `27.43 ms`**,
  **p99 `35.64 ms`** while `1,152` background events flowed simultaneously (`KnownEventIds` history fetches sharing the
  account's live sockets via `DivertTransport`, alongside strict directory reads on isolated `ScopedDirectoryClient`
  connections to the same relays). On this host workload, `DivertTransport` isolated live delivery without requiring a
  separate history connection pool.
- **Single-account short-lived burst proxy (1 account × 2 relays, 8-event finite fetch + shutdown):** `4.3 ms` wall,
  `+7.43 MiB` Linux `VmRSS` delta (baseline `3.48 MiB`, process `VmRSS` `20.70 MiB` including 4 in-process mock relays),
  `0` leaked FDs.
- **Multi-account idle, cancellation & churn:** `0.00%` idle CPU over 2 s across 3 accounts × 4 relays; `1.58 ms` full
  teardown of 6 stalled sockets on a 24-waiter cancellation storm; `1.39 ms` p50 (`2.89 ms` max) shutdown latency and
  flat FD count (`24`) across 5 consecutive suspend/resume + NIP-42 AUTH cycles.
- **Concurrent fan-out burst & default budget:** `DEFAULT_GLOBAL_QUEUE_BYTES = 192 MiB` with `SharedBudget` fan-out
  reservation handled 12 concurrent 4-relay directory reads (48 finite requests) in `4.5 ms` with `+3.99 MiB` `VmRSS`
  delta and zero false `LocalBusy`.

### Remaining Device-Side Qualification (Open on `#2897`)

The Linux loopback harness above is a **host proxy only**. It does **not** qualify physical mobile hardware:

- Real iOS Notification Service Extension (NSE) peak dirty memory (`24 MiB` OS ceiling), Android foreground/background
  memory, real OS suspend/resume transitions, and device battery/energy draw remain **outstanding device-side
  verification** on `#2897`.
- Passing narrow per-request `NostrAcquisitionLimits` (e.g. `512 KiB`–`1 MiB`) and avoiding concurrent directory
  fan-outs in an NSE is **unenforced caller guidance** today, not a code-enforced NSE clamp; per-request event-byte
  limits also exclude WebSocket/parser/event-object allocations, and `FiniteRequests` additionally allows up to one
  `5 MiB` frame per active relay (`max_event_bytes + 5 MiB` per unshared request, or `shared_budget + 5 MiB * relays`
  for a sharing group).
