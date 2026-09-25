---
title: "#1947 P6 endpoint capability reprobe qualification"
created: 2026-09-24
updated: 2026-09-24
tags: [marmot, nostr, recovery, history]
status: qualification
---

# #1947 P6 endpoint capability reprobe qualification

This slice starts at merged MDK `aae20359d4a669b32ca53a068ac2d3214eefdfcd`
and keeps rust-nostr pinned to `63384e485d55097cb3d9e57a2146f453a5742570`.
It corrects one endpoint-capability lifetime error in the existing NIP-77
comparison path. It does not activate or replace the bounded worker executor.

## Source and contract

`client/recovery.rs` freezes route, endpoint, inventory and revision fences.
`client/sync.rs::reconcile_transport_history` calls the relay plane's SDK
comparison and classifies its aggregate result. The SDK client compares the
durable per-route ID set with each endpoint, then fetches a rotating batch of
missing IDs. The relay plane routes fetched events through ordinary account
admission. The existing recovery executor also rebuilds ordinary subscriptions
and drains them. Its summary has no per-endpoint exhaustiveness certificate,
so the completion path keeps `ServicedUnknown` and endpoint failure incomplete.

Before this change, `NostrSdkRelayClient` cached an affirmative NIP-77
rejection by URL for its entire process lifetime. Later comparisons omitted
that endpoint, including after the SDK had reconnected to a now capable relay
at the same URL. An endpoint rejection is not backend-wide incapability:
`RecoveryComparisonOutcome::Unsupported` would park the comparison slot using
the SDK-presence capability key, which cannot detect a relay upgrade. This
slice keeps rejection as a failed, retryable endpoint outcome and removes the
process-lifetime skip. It adds no timer or automatic attempt. The existing
owner's durable retry pacing still governs app recovery. Lower-level callers
of the public `reconcile_subscription` API choose their own call rate; each
such call can now send one NIP-77 open per requested endpoint.

## Controlled two-relay evidence

`crates/marmot-app/src/runtime/account_worker/tests/selective_history_tests.rs`
places a counting WebSocket proxy in front of each local NIP-77 relay. Both
proxies first reject `NEG-OPEN` with the SDK-recognized unsupported NOTICE.
Two consecutive comparisons report zero successful and two failed endpoints,
with exactly one `NEG-OPEN` per endpoint per comparison. No event payload is
sent. The combined WebSocket text payload for these two zero-new-event calls
was **1,164 bytes**, below the asserted **16 KiB absolute ceiling**. Client
text and relay text are counted separately; the `EVENT` JSON byte count is a
subset of relay text, not an additional total.

The fixture then enables NIP-77 on the left proxy, disconnects and reconnects
the SDK relay at the same URL, and confirms that the SDK's successful-connection
count advanced. The next comparison probes both endpoints again. It reports
one success and one failure and returns the exact event that only the left
relay retained. The proxy observed one event payload of **437 JSON bytes**.
Across three comparisons it counted **six `NEG-OPEN` frames**, exactly one per
endpoint per call. At most one ordinary exact-ID `REQ` was sent to each
endpoint in this fixture. The still-rejecting right endpoint remains an
incomplete result; the app's existing mixed-route regression verifies that a
failed comparison route stays retryable rather than discharging the debt.

The unmodified source failed the new test after the successful reconnect:
the third comparison reported zero successful endpoints because both URLs
remained in the process cache. Removing that cache made the test pass without
changing the summary or storage contract.

## Limits and remaining P6 work

The counter includes outbound and inbound WebSocket **text payloads at the
proxy**, before SDK filtering. It excludes WebSocket framing, binary/control
frames, TCP/TLS, retransmissions, SDK parser and queue allocation, and device
traffic. The fixture measures this direct comparison API, not a concurrent
ordinary live replay. Its returned event is an owned transport object; this
test does not assert SQLCipher admission or decryption. Existing cold-reopen
tests cover durable set reconciliation, but this slice does not compose that
journey with a two-relay large-history byte budget.

The comparison set limit is 16,384 and replay batch is 128 IDs. These are
bounded operations, not proof of exhaustive history above the relay's
retention floor or across truncation. The legacy executor can still issue a
broad ordinary replay alongside selective comparison. Large retained-history,
sparse-gap, no-new-data, unsupported/floored-history fallback, concurrent
ordinary replay byte accounting, account-wide unlocalized loss and device
network/RSS measurements remain P6/P8 work. Neither EOSE nor a successful
set comparison alone certifies durable admission or complete historical
coverage.

Focused commands:

```sh
cargo test -p marmot-app --lib unsupported_endpoint_is_reprobed_after_connection_generation_changes -- --nocapture
cargo test -p marmot-app --lib comparison_runtime_retries_failed_route_without_reissuing_successful_sibling
```
