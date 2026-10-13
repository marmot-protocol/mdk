# AGENTS.md - crates/transport-nostr-adapter

Agent-facing map for the Nostr transport adapter crate. Read [`README.md`](README.md) for the human overview,
recovery-session contract, and reconciliation budgets.

## Scope

This crate implements the shared `TransportAdapter` boundary for Nostr-shaped traffic:

- account inbox activation,
- group subscription sync,
- stale group subscription cleanup,
- relay-event to account-scoped delivery routing,
- publish target validation and endpoint-level publish reports.

It does not own MLS peeling, CGKA convergence, storage, account key custody, or real relay socket policy by default. The
optional `sdk` feature provides `NostrSdkRelayClient` through the `NostrRelayClient` boundary and relies on `nostr-sdk`
for reconnect/backoff and relay status mechanics.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Adapter implementation, relay-client boundary, routing state, lifecycle metrics. |
| `src/acquisition.rs` | Owned bounded acquisition and receiver-scoped loss evidence types. |
| `src/publish_accounting.rs` | Shared logical publish counters and the cancellation guard used by direct and account publish paths. |
| `src/key_package.rs` | Marmot kind `30443` KeyPackage event building/publishing (`NostrKeyPackagePublication`, `NostrKeyPackagePublisher`). |
| `src/relay_list.rs` | NIP-65 kind `10002` and Marmot inbox kind `10050` relay-list event building. |
| `src/sdk_client.rs` | Optional `nostr-sdk` relay client implementation and SDK planning tests. |
| `src/telemetry.rs` | Relay delivery telemetry: cross-relay arrival spread (phase 1) and subscription sync timing / initial-sync gate (phase 2); local-time, aggregate, privacy-safe. |
| `tests/inbound_routing.rs` | Public behavior tests for group delivery, welcome delivery, group sync, and publish. |
| `tests/acquisition_contract.rs` | Request validation and optional-boundary shape tests. |
| `tests/publish_accounting.rs` | `sdk`-gated direct-adapter publish admission, classification, and cancellation tests. |
| `tests/selective_history_acquisition_tests.rs` | `sdk`-gated bounded history acquisition and reconciliation-cursor tests. |
| `tests/relay_limit_subscriptions.rs` | `sdk`-gated subscription behavior against `tests/support/limit_relay.rs`, a proxy enforcing strfry 1.1.3's per-connection limits (REQ and NEG caps, filter shape, 500 limit clamp). |

## Invariants

- Keep Nostr event DTO conversion delegated to `transport-nostr-peeler`.
- Keep `TransportDeliverySource` metadata diagnostic only; do not feed it into consensus decisions.
- Preserve account-scoped deliveries even when group subscriptions share relay endpoints.
- Keep account-inbox and group subscription ids scoped to the activation attempt that issued them
  (`SubscriptionAttempt`). A relay reports end-of-stored-events by subscription id and nothing else, so a shared id
  would let a superseded attempt's in-flight EOSE satisfy the replay-coverage gate the next activation just reset. Ids
  stay derived from account/group/endpoint state plus the attempt, never from `since`, which is not recorded with the
  routes and so could not be reconstructed at eviction time.
- Keep the attempt ordinal in `AdapterState::activation_attempt_high_water` and never clear it — not on
  `deactivate_account`, not on the failed-activation rollback. Both drop the account's routes without closing the relay
  sockets the superseded attempt's REQs still stream on, so an ordinal recovered from the routes would re-issue ids that
  are still live. `AccountRoutes.attempt` holds only the live copy that `account_subscription_ids` reconstructs from.
- Keep `activate_account`'s opening `unsubscribe_account` unconditional. Attempt-scoped ids removed the relay-side
  REQ-replace backstop, and a rolled-back activation can leave `accounts` empty while the relay client still holds this
  account's subscriptions; an orphaned REQ double-delivers because routing is content-keyed.
- Never leave a REQ live that `account_subscriptions` does not track (#2262):
  - Track a REQ's id before handing it to nostr-sdk, and untrack it only once its CLOSE went out. A failed subscribe
    registered nothing of its own and closes nothing: group syncs reuse their activation's ids, so the id may belong
    to another live REQ. `unsubscribe_account` untracks per id as it closes, so a caller dropped mid-sweep leaves the
    rest tracked.
  - Never abort subscribe tasks. `subscribe_all` drains its siblings after an error and detaches them when dropped.
    Every lifecycle operation takes `lock_subscriptions`, which waits for those stragglers to register before any
    sweep.
  - That wait is bounded so a hung relay client cannot wedge the adapter. When it gives up, it retires the barrier;
    a task that finishes after its barrier was retired closes the REQ it just registered, unless the current routes
    want that id. It releases its barrier guard, then holds the lifecycle lock across that check and the CLOSE, so
    neither can interleave with an activation mid-sweep or a retry re-registering the id.
  - A failed or cancelled group sync closes the REQs its batch installed once its subscribe tasks settle, except ids
    the committed routes still want (`close_abandoned_sync_batch`). Its guard holds the lifecycle lock throughout.
- Never count a replay a relay may have clamped as coverage (#2263):
  - `observe_relay_event` counts each relay's stored events per activation REQ until that relay's EOSE, before
    mapping them. Consumers must pass a relay's copies in order with its EOSE, and report events that fail
    `from_nostr_event` through `observe_unconvertible_relay_event` instead of dropping them.
  - A relay that sent `RELAY_REPLAY_PAGE_LIMIT` or more moves to `RelayReplay::Paging`, which is neither complete nor
    settled. `page_replay` then fetches the window backwards with `acquire_history` until a page comes back short;
    only then does that relay's EOSE count.
  - A failed, unsupported or over-long paging stays incomplete for the next activation and recovery. So does a full page that
    cannot move past its oldest second, because that second may hide more events and everything older.
- Record each REQ's filter `since` in its SDK account context before the REQ goes out, find it by subscription id
  when the REQ closes, and keep a closed REQ's floor for the rest of the context's life: routing is content-keyed,
  and a closed REQ's buffered or in-flight notifications have no deadline, so they can still be lost in a lag. Do
  not add a time-based expiry. Read `notification_loss_floor` at the lag; an unfloored REQ or missing evidence is
  `Unbounded`, never "no loss".
- Recover a lag-lost end-of-stored-events only through `reissue_subscriptions_awaiting_eose`: only REQs issued by the
  lag's `NotificationLagMark`, only on relays that have not reported EOSE to the adapter, all under the subscription
  lifecycle lock. Ask the SDK first: a relay with `Relay::subscription_received_eose` true lost only the notification,
  so record its EOSE and send nothing. Otherwise queue the REQ's CLOSE and the REQ again, unchanged and under its own
  id, in one `Relay::batch_msg`, never as separate sends: a relay must never see a repeated live id, because one that
  answers `CLOSED duplicate:` makes the SDK drop the REQ from the registry that restores it on reconnect, and a lone
  CLOSE would leave it without the REQ. Keep that registry in place; a relay-level unsubscribe and subscribe drops its
  entry when a send fails. The SDK client re-issues only to a connected relay and only while its floor record holds
  the REQ live, and records it with `open` first. Every repair reads the SDK's EOSE record for every relay still
  awaiting EOSE, through `subscription_eose_received` for one already re-issued to, so an answer a later lag lost
  still completes; only the network re-issue is once per relay, so a replay that lags again cannot loop. A relay that
  got nothing has its re-issue released and counted in `EoseReissueSummary::failed_relays` so the caller repairs it
  again later. Never wait for queue room under the lifecycle lock. Never infer EOSE at a lag, change
  a re-issued REQ's filter, or reopen a closed REQ.
- Hand every relay `CLOSED` on a live REQ to `handle_relay_closed` from every notification consumer: this crate's
  `spawn_notification_forwarder` and `marmot-app`'s relay-plane consumer (`handle_relay_notification`). Classify each
  message on its own with `sdk_subscription_refusal` / `NostrSdkRelayClient::subscription_refusal`, which mirrors how
  nostr-sdk settles that REQ (kept for `rate-limited:`, and for `auth-required:` with an authenticator); never read
  the SDK registry when the queued notification is handled, since a later re-send may have changed it. An unknown
  authenticator keeps `auth-required:` pending. The forwarder test pins the table against the SDK registry. Treat a
  staged group-sync REQ as live. A dropped refusal before EOSE settles that relay's replay coverage but never
  completes it: `AccountSubscriptionEose::settled` may end a wait, only `complete` may gate live cursor promotion or
  activation reuse. Ending a drain early on `settled` must leave its checkpoint exactly as the drain's timeout would. EOSE is final; a later `CLOSED` does not undo it. Ignore closes for ids that are not live
  (superseded attempts, one-shot fetches). Keep only the reason's category, never its text, in state, logs,
  telemetry and the audit queue.
- Keep real relay clients behind `NostrRelayClient`.
- Keep the `nostr-sdk` dependency behind the `sdk` feature.
- Relay endpoints are host-safety filtered before any connect at the `RelaySafetyPolicy` chokepoint in `marmot-app`
  (`crates/marmot-app/src/relay_plane/safety.rs`); relay hosts that are non-public IP literals are rejected, and literal
  loopback hosts are rejected too unless the dev loopback flag is set (the flag admits loopback only —
  private/link-local/CGNAT literals stay rejected). A new relay-connect path must go through that chokepoint, not around
  it. See `docs/marmot-architecture/overview/dial-safety.md`.
- Keep per-relay telemetry keyed by the opaque `RelayIndex`. `resolve_relay_labels` (gated behind a
  `RelayExportConsent` token) is the only path that turns an index back into a relay URL, and exists solely for the
  opt-in export boundary. Do not add another reverse mapping or resolve indices outside that boundary.
- Do not log relay URLs, account ids, group ids, message ids, subscription ids, pubkeys, plaintext, ciphertext, or
  payload-derived values.
- Use tracing `target` plus `method` fields so crate/module/method are visible while diagnostic data stays
  aggregate-only.
- Floor history REQs where the caller anchors them: a recovery maintenance session at the `since` it is installed
  with, and a retained route at its `TransportGroupSubscription::retained_since`, never later than the activation's
  `since`. A route with a retained floor is retained wherever it sits; among floorless routes the first per group is
  the current one and a later distinct one is retained and backfilled in full. Reissue a live retained REQ only when
  its floor widens (`AccountRoutes::group_since`): a reissue replaces the live REQ under the same id, so a narrower
  one could cut off history it is still returning.
- Recovery maintenance ids include the owner's durable attempt serial. A duplicate install joins only a live session;
  after failure, cancellation, removal or account reactivation, require a strictly greater serial for that account/group.
  Never clear `maintenance_attempt_high_water` while the adapter lives: CLOSE and route removal cannot recall late EOSE.
  Only recovery installs use the scoped client API; preserve the legacy maintenance subscribe/cleanup path.
- Use Marmot kind `30443` for KeyPackages; never substitute deprecated NIP-104 key package kinds. There is no dedicated
  KeyPackage relay list; KeyPackages go to the NIP-65 kind `10002` relays.

## Verification

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```
