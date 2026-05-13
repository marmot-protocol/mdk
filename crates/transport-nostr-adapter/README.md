# transport-nostr-adapter

Concrete Nostr transport adapter core for Marmot CGKA transport messages.

This crate implements `cgka_traits::TransportAdapter` for Nostr-shaped relay traffic. It is responsible for
account-aware routing and endpoint management. The default core stays relay-client agnostic; the optional `sdk` feature
adds a `nostr-sdk` backed `NostrSdkRelayClient`.

## What this crate does

- Activates account inbox subscriptions and group subscriptions.
- Refreshes group subscriptions for an active account.
- Converts relay-delivered `NostrTransportEvent` values into account-scoped `TransportDelivery` values.
- Routes kind `445` group messages by endpoint + transport group id.
- Routes signed kind `1059` giftwraps through the account-inbox plane.
- Publishes already-wrapped `TransportMessage`s to target endpoints and returns endpoint-level publish reports.
- Builds and publishes Marmot kind `30443` KeyPackage events through the same relay-client boundary when supplied with
  the MIP-00 metadata.
- Removes stale group subscriptions when an active account's group set changes.
- Exposes adapter-local lifecycle metrics for diagnostics.
- With the `sdk` feature, plans `nostr-sdk` filters/subscription ids, signs unsigned group events with the configured
  SDK signer, publishes to specific relays, forwards SDK notifications into adapter deliveries, and exposes a redacted
  aggregate relay-health snapshot.

## What this crate does not do

- No MLS peeling; that remains in `transport-nostr-peeler`.
- No CGKA convergence; that remains in `cgka-engine`.
- No account key custody. The `sdk` client uses the signer already configured on the supplied `nostr-sdk::Client`.
- No duplicate reconnect/backoff loop. The optional `nostr-sdk` client relies on SDK `RelayOptions` for reconnect, retry
  interval adjustment, jitter, relay sleep/ban/terminate behavior, and connection stats.
- No full production relay-plane orchestration yet. Relay auth, Nostr-backed transport routing policy, full KeyPackage
  metadata derivation, richer telemetry export, and per-platform lifecycle wiring still need hardening.

## Privacy-safe diagnostics

Adapter diagnostics are deliberately aggregate-only. They may include counts, status buckets, method names, and
success/failure totals. They must not include relay URLs, account ids, group ids, message ids, subscription ids,
pubkeys, plaintext, ciphertext, or payload-derived values.

Tracing in this crate uses explicit `target` and `method` fields such as `transport_nostr_adapter::adapter` / `publish`.
Keep future tracing on the same pattern so crate/module/method are visible without leaking routing data.

## Boundary shape

Inbound:

```text
relay client -> NostrRelayEvent -> NostrTransportAdapter -> TransportDelivery
```

Outbound:

```text
TransportPublishRequest -> NostrTransportAdapter -> NostrRelayClient
```

`NostrRelayClient` is intentionally small so tests can use an in-memory client and production can use
`NostrSdkRelayClient` behind the `sdk` feature.

The likely next expansion is to keep Nostr-specific routing here: derive group subscriptions and group-message publish
targets from `marmot.transport.nostr.routing.v1`, derive KeyPackage publish targets from the user's kind `10051`
KeyPackage relay list, and publish KeyPackages as Nostr kind `30443` events through the same relay-client boundary. Kind
`30443` is the Marmot KeyPackage event kind; do not substitute deprecated NIP-104 key package kinds for this path.

## Run tests

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```
