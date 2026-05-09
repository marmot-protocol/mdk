# AGENTS.md - crates/transport-nostr-adapter

Agent-facing map for the Nostr transport adapter crate.

## Scope

This crate implements the shared `TransportAdapter` boundary for Nostr-shaped
traffic:

- account inbox activation,
- group subscription sync,
- stale group subscription cleanup,
- relay-event to account-scoped delivery routing,
- publish target validation and endpoint-level publish reports.

It does not own MLS peeling, CGKA convergence, storage, account key custody, or
real relay socket policy by default. The optional `sdk` feature provides
`NostrSdkRelayClient` through the `NostrRelayClient` boundary and relies on
`nostr-sdk` for reconnect/backoff and relay status mechanics.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Adapter implementation, relay-client boundary, routing state, lifecycle metrics. |
| `src/sdk_client.rs` | Optional `nostr-sdk` relay client implementation and SDK planning tests. |
| `tests/inbound_routing.rs` | Public behavior tests for group delivery, welcome delivery, group sync, and publish. |

## Invariants

- Keep Nostr event DTO conversion delegated to `transport-nostr-peeler`.
- Keep `TransportDeliverySource` metadata diagnostic only; do not feed it into
  consensus decisions.
- Preserve account-scoped deliveries even when group subscriptions share relay
  endpoints.
- Keep real relay clients behind `NostrRelayClient`.
- Keep the `nostr-sdk` dependency behind the `sdk` feature.
- Do not log relay URLs, account ids, group ids, message ids, subscription ids,
  pubkeys, plaintext, ciphertext, or payload-derived values.
- Use tracing `target` plus `method` fields so crate/module/method are visible
  while diagnostic data stays aggregate-only.

## Verification

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```
