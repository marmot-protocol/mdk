# AGENTS.md - crates/transport-nostr

Agent map for the relay plane crate. Human overview: [`README.md`](README.md).

## Scope

The shared, process-wide relay plane: relay sessions, per-account delivery and overflow, notification forwarding,
guarded native replay facts, publish accounting, relay telemetry, directory fetches and subscriptions, and the relay host-safety
chokepoint. It depends on `transport-nostr-adapter`, `transport-nostr-peeler`, `cgka-traits` and `nostr-sdk`; it must
not depend on `marmot-app` or `storage-sqlite`. The app supplies storage and policy through callbacks and traits
(`AccountDeliverySpillStore`, `AccountDeliveryRecoveryMarker`, `RelayExportGate`). A queue-loss marker carries each
dropped delivery's route (`DeliveryRoute::of`, the same rule `marmot-app` keys reconciliation by) with the earliest
`created_at` dropped there, or no routes once any drop had none or a generation passed `MAX_DELIVERY_LOSS_ROUTES`.
`DeliveryRoute` and the cap live in the adapter, re-exported here, so a REQ's routes and a delivery's are one type.
A lag on an account's own SDK context charges each route's REQ floor too; `notification_loss_routes` hands the
generation's routes to the worker, or none once any of its losses had none (a shared receiver, staged replay).
`delivery_loss_routes` hands the worker a queue-loss generation's drop routes the same way, so its observation past
the durable marker count stays routed.
A generation that adopted a durable marker (a restart, or a failed acknowledgment) takes a fresh token at its first new
drop: storage imports loss by count, so a token's count must cover every drop under it.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | `MarmotRelayPlane`: relay sessions, per-account delivery queues and publish clients, notification forwarding, native replay admission bridge, publish accounting, `nostr_builder()`. |
| `src/delivery_spill.rs` | The plane's side of the durable overflow tail: when a full queue spills and how it reports the disposition. |
| `src/directory.rs` | Directory fetches (plain, strict, public, inspection) and live directory subscriptions. |
| `src/known_limits.rs` | `RelayEventLimits` and the one refusal of relays an event is over the known limit of, shared by the adapter's publish and `KnownLimitPublishClient`, which wraps every account publisher. |
| `src/read_back.rs` | `read_back`, a pending commit's exact-event read (mdk#2332), and its per-account, per-relay hourly cap. |
| `src/safety.rs` | `RelaySafetyPolicy`: the host-safety chokepoint every relay endpoint passes before a connect. |
| `src/telemetry.rs` | Relay telemetry snapshots and the export rollup. |
| `src/test_support.rs` | Publish-accounting fixtures and `ScriptedRelayMessages`, the relay messages a fake relay client sends the plane, shared with `marmot-app`'s tests (`test-support` feature). |

## Rules

- Route every relay endpoint through `RelaySafetyPolicy` and build every relay client with `nostr_builder()`;
  `clippy.toml` rejects direct `nostr_sdk` client constructors. See
  `docs/marmot-architecture/overview/dial-safety.md`.
- Admission sends to each relay under its parsed spelling, but the session matches publish results to its targets
  by equality. `publish` names every receipt and endpoint failure, in a report or an error, as the request spelled
  it (`RequestedSpellings`, mdk#3305); keep any new result path inside that renaming.
- Keep logs privacy-safe: aggregate values only, no account ids, group ids, relay URLs, pubkeys or payloads. The
  tracing target is still `marmot_app::relay_plane`; rename it only in a change of its own.
- Transport consumers enter `transport_nostr_adapter::dispatch_sdk_replay` with the SDK's ordered reader/connection
  metadata. Handle payload variants in its private `dispatch_sdk_notification`; do not add a second dispatcher here.
  Keep metadata through worker queueing and fence receiver loss before resuming. Directory Client input stays separate.
  An injected client's `relay_notification_source` runs under the same supervisor and dispatch as the SDK's stream,
  so a fake relay's EOSE, CLOSED and EVENT reach the plane as a relay's do; give a fake relay client one instead of a
  hook into the adapter.
- `read_back` reads only on the account's anonymous publish pool: no signer answers AUTH there, so it never names the
  account, and its events reach no ingest, sweep cursor or coverage ledger. Only a copy that verifies as the exact
  event is `Found`, and only an EOSE is `NotFound`. It runs when the session asks; it is not history acquisition and
  not a recovery-runner quantum.
- One-shot directory reads (`fetch_directory_events`, `fetch_directory_events_with_completion`, `fetch_public_events`,
  `inspect_directory_events`) send each relay's REQ as one of the adapter's finite requests, on an owned client built
  with `FiniteRequests::install`: each
  relay's reply keeps its own end (EOSE, CLOSED reason, cut, deadline) and exact per-REQ raw-vs-admitted EVENT counts
  (`raw_items == received_items` replaces the retired `DirectoryWireTransport` prefilter counter for strict absence
  proofs), and a relay that requires NIP-42 is asked once
  more after the signer authenticates. A pending signer callback at the inspection deadline is
  `AuthenticationTimedOut`; other deadlines are `TimedOut`. Inspection watches authentication from before the dial with
  `AUTH_CHALLENGE_WAIT` (so a bare `auth-required:` CLOSED with no `AUTH` challenge ends as `AuthenticationRequired`
  instead of waiting out the EOSE window, while an `AUTH` challenge still waits until the deadline), so a refusal on
  connect still decides a later close; a persistent NIP-67 `auth` EOSE hint is `AuthenticationRequired` and `more` is
  `Incomplete` (the inbox probe tolerates `more` and only checks `auth` on external-signer reads). Onboarding's external-signer
  inbox probe asks for one signature per read and distinguishes signer failure (`AuthenticationSignerFailed`) from an
  explicit AUTH event refusal (`AuthenticationRejected`) or rate limit matched to its own signed event. `CLOSED` `rate-limited:` is
  `RateLimited` and bare `error: <other>` is
  `Unreachable`, while permanent prefixes stay `Restricted`; verified kind 10002/10050 records returned before an incomplete or closed
  end are kept in `Partial { records, cause }`. Relay health's `inspect_inbox` sets `verifying_inbox` on its request,
  which onboarding never does: its answer is classified strictly (`inbox_closed_reason`, `verified_inbox_answer`), the
  AUTH reply is matched to the events the read's own authenticator signed, and an answer it cannot verify is
  `AuthenticationUnconfirmed`; the new variants it adds reach no other caller. A dropped inspection client stops its
  relay at once (`Relay::shutdown`). Each query's relays share one byte budget
  (`FiniteRequests::sharing`); directory and public reads set no item cap, since a relay's every EVENT frame would count,
  matching or not. Frames not yet read are bounded per relay request, not per query: a queue of the budget plus one
  frame, and the batch its collector is reading, so up to twice that. A public read past `max_events`, cut, or ending
  on `more` or `auth` is incomplete; a plain directory read cut by its byte budget or stopped at an unreadable frame fails, since
  it cannot say it is partial and a record past the cut would read as absent.
- Recovery debt, retry selection and native input qualification belong to the app's recovery runner.
  Bridge the runner's fence plans and borrowed source guards; never fetch history of the plane's own or schedule quiet-period
  repair here. Import actual loss before cursor authorization and retain placement/spill locking through the owner's
  callback. The cursor seal caps at the oldest frame the adapter's fence holds at or above the restart floor, as it
  does at a queued delivery.
- Test hooks and accessors (`*_for_test`, `test_support`) are `cfg(any(test, feature = "test-support"))`.
  `marmot-app` enables `test-support` only through its dev-dependency; never enable it in app artifacts.
- Widen an item to `pub` only when another crate names it. `marmot-app` re-exports `MarmotRelayPlane` and
  `MarmotRelayPlaneAccountAdapter` to hosts, so methods on them that only the app calls are `#[doc(hidden)] pub`.
- Construct `MarmotRelayPlane` inside a Tokio runtime. `spawn_router` returns early without one, so construction
  succeeds and nothing is routed. Follow-up: take an explicit runtime handle.
- Shutdown tears down the SDK relay pool, directory client, and `publish_clients` (active and retired signer-bound
  publish clients), aborts/joins the router and notification
  forwarders, drains in-flight `delivery_spill.rs` writers (rejecting new spill spawns once shutdown begins and
  transferring any unfinished in-flight/queued spill items into durable queue loss before aborting a timed-out writer),
  and awaits `loss_marker_tasks` and evicted/dropped publish-client shutdowns up to `RELAY_PLANE_SHUTDOWN_WAIT`.
  Adapter-owned `anonymous_publish_clients` stay live across receive-plane `shutdown()` while an adapter is still held
  (so group writes and push triggers survive receive shutdown) and tear down when the last adapter clone drops or when
  `deactivate_account_context` runs (which also tears down that account's cached and retired signer-bound publish
  clients). Unfinished `loss_marker_tasks` are never aborted on
  timeout; bounded shutdown still cannot guarantee marker persistence if storage stays `Retryable` until the host
  closes SQLite (write-ahead cursor fencing for that case is tracked in `#3813`). Directory fetch tasks are not yet
  joined here (tracked for coalesced fetch cancellation). The plane registers nothing in the app's close registry
  (`#2341`).
- Dropping the last plane handle without shutdown aborts the same router and forwarder tasks
  (`Drop for MarmotRelayPlaneInner`). They hold the transport, so without it every short-lived plane (one per `wnd`
  Execute request) stayed alive with its SDK clients. Never give those tasks a `MarmotRelayPlane` clone, or the
  plane can no longer drop. Lock the task slots only through a plane borrow, so none is held when the last handle
  drops; the drop's `try_lock` relies on it.
- The plane owns each account's signer-bound publish client (`account_publish_client`). Order matters: the signer is
  installed before activation, and the client is evicted (`evict_account_publish_client`) before its account reopens
  or its signer is replaced, because a cache hit ignores the signer passed in.

## Verification

```sh
cargo clippy -p transport-nostr --all-targets --all-features --locked -- -D warnings
cargo nextest run -p transport-nostr --all-features
```

Changes that alter what `marmot-app` sees also need its relay tests:
`cargo nextest run -p marmot-app --lib --features test-policy-overrides,otlp-export -E 'test(/^(tests::relay_plane_runtime|relay_telemetry_export)::/)'`.
