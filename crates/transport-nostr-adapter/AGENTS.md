# AGENTS.md - crates/transport-nostr-adapter

Agent-facing map for the Nostr transport adapter crate.

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
| `src/key_package.rs` | Marmot kind `30443` KeyPackage event building/publishing (`NostrKeyPackagePublication`, `NostrKeyPackagePublisher`). |
| `src/relay_list.rs` | NIP-65 kind `10002` and Marmot inbox kind `10050` relay-list event building. |
| `src/sdk_client.rs` | Optional `nostr-sdk` relay client implementation and SDK planning tests. |
| `src/telemetry.rs` | Relay delivery telemetry: cross-relay arrival spread (phase 1) and subscription sync timing / initial-sync gate (phase 2); local-time, aggregate, privacy-safe. |
| `tests/inbound_routing.rs` | Public behavior tests for group delivery, welcome delivery, group sync, and publish. |

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

## Verification

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```
