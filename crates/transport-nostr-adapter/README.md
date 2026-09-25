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
- Builds NIP-65 kind `10002` and Marmot inbox kind `10050` account relay-list events. KeyPackages are published to the
  NIP-65 relays; there is no dedicated KeyPackage relay list.
- Removes stale group subscriptions when an active account's group set changes.
- Exposes adapter-local lifecycle metrics for diagnostics.
- With the `sdk` feature, plans `nostr-sdk` filters/subscription ids, signs unsigned group events with the configured
  SDK signer, publishes to specific relays, forwards SDK notifications into adapter deliveries, and exposes a redacted
  aggregate relay-health snapshot.

## Recovery maintenance sessions

`install_group_maintenance_recovery_subscription` accepts the account recovery owner's durable attempt serial and
returns an opaque wire id. A replacement session must use a fresh serial, including after cancellation or reopen.
Reusing a serial joins only a live session without resetting its EOSE. After failure, cancellation or removal, the adapter
requires a strictly greater serial for that account/group, even across account activation. Its lifetime high-water map
retains one scalar per account/group that used this API. Remove the session with
`remove_group_maintenance_recovery_subscription` and its returned id. Failed or cancelled teardown retains retry intent.

`subscription_endpoint_eose` reports EOSE only for the caller-supplied endpoint in that subscription's captured
membership (`None` means unknown subscription or endpoint). EOSE can satisfy a maintenance first-boundary prerequisite;
it does not establish exhaustive historical coverage or durable admission.

Injected `NostrRelayClient` implementations opt in with `supports_scoped_subscriptions` and implement both
`subscribe_scoped` and `unsubscribe_scoped` using the exact supplied wire id. The SDK implementation supports this with
the existing pinned SDK. The default rejects recovery sessions before staging routes or teardown work. Existing
`GroupMaintenance` values and legacy installation/removal APIs retain their shape and ids.

## What this crate does not do

- No MLS peeling; that remains in `transport-nostr-peeler`.
- No CGKA convergence; that remains in `cgka-engine`.
- No account key custody. The `sdk` client uses the signer already configured on the supplied `nostr-sdk::Client`.
- No duplicate reconnect/backoff loop. The optional `nostr-sdk` client relies on SDK `RelayOptions` for reconnect, retry
  interval adjustment, jitter, relay sleep/ban/terminate behavior, and connection stats.
- No full production relay-plane orchestration yet. Relay auth, relay scoring, full KeyPackage metadata derivation, and
  per-platform lifecycle wiring still need hardening. Runtime-level endpoint safety, bounded subscription replay, group
  fanout, and redacted aggregate relay health live in `marmot-app`'s relay plane.

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

The app-runtime layer now projects group subscriptions and group-message publish targets from
`marmot.transport.nostr.routing.v1` and applies relay endpoint parsing/deduplication before subscription or publish.
KeyPackage publish targets are derived from the user's kind `10002` NIP-65 relay list (there is no dedicated KeyPackage
relay list), and directory/profile discovery is coalesced in the shared runtime relay plane. Kind `30443` is the Marmot
KeyPackage event kind; do not substitute deprecated NIP-104 key package kinds for this path.

## Run tests

```sh
cargo test -p transport-nostr-adapter
cargo test -p transport-nostr-adapter --features sdk
```

See [`AGENTS.md`](AGENTS.md) for scope, the `sdk` feature, and privacy-safe telemetry rules.

## Reconciliation progress ownership

`NostrSdkRelayClient::reconcile_subscription` requires a `NostrReconciliationProgress` store for
that account and route. Hosts serialize reconciliation per route and preserve its cursor across
subscription rebuilds. Each selected ID is checkpointed before its exact-ID request, including
when the caller later cancels. An ID left unattempted by the pass budget does not move the cursor.
A failed progress read or write stops replay; it must not silently restart at a refused prefix.
Empty remote sets preserve the cursor: failed relay comparisons can also produce an empty set, and
the next nonempty set wraps around the saved position.

MarmotApp stores the cursor in its encrypted account database alongside existing route inventory
(migration 0061). Route retirement deletes it, and a late replay cannot recreate deleted route
state. The SDK no longer has a shared 256-entry replay cursor cache, so activity on other routes
cannot evict an active route's progress. State adds at most one 32-byte cursor to each existing
route row. The NIP-77 remote-only selection still holds at most 128 IDs from a 16,384-ID
reconciliation set. Each pass now sends at most 16 request-local one-ID acquisitions within the
existing two-second comparison deadline and aggregate 16-received-item / 128-KiB-serialized-event
allowance per endpoint. A byte/item/deadline exit retains partial events but leaves comparison
incomplete. These are SDK received-result bounds, not complete wire or memory ceilings.

Replay position is advisory, separate from admitted event inventory. Failed or cancelled fetches
advance position but acknowledge no delivery. Refused events recur on wrap; only durable app
ingestion removes an event from the missing set. SDK callers must supply this new progress
argument; no FFI signature changes are required.
