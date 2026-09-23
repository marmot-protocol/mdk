---
title: "Nostr Bounded Acquisition Interface"
created: 2026-09-23
updated: 2026-09-23
tags: [marmot, nostr, recovery, transport]
status: overview
---

# Nostr bounded acquisition interface

`NostrRelayClient::acquire_history` is an optional operation on the existing
relay-client boundary. It takes an owned `NostrAcquisitionRequest` and a
request-local `NostrAcquisitionCancellation`, and returns owned
`NostrAcquisitionResult` evidence. No account worker, engine, or storage borrow
needs to survive the network wait. Current `NostrSdkRelayClient` uses the
default explicit `Unsupported` result; production traffic is unchanged.

The caller freezes an account, durable attempt serial, existing obligation ID,
scope ID/revision, and current `SubscriptionAttempt` in
`NostrAcquisitionCorrelation`. The backend copies
these identifiers into the result. Each endpoint can also report its observed
connection `session_generation`, when the backend can establish one. These
network generations are separate from durable retry, obligation, route, loss,
and inventory revisions. The recovery owner still checks its existing
`RecoveryRevisionFence` and `RecoveryScopeToken` before any durable checkpoint.
The transport correlation alone is never completion authority.

`NostrAcquisitionScope` selects explicit known IDs or one bounded inbox/group
time window. Explicit IDs can reacquire known inventory; they cannot discover
unknown history. The limits declare the maximum endpoint count, received
items and serialized event JSON bytes **per endpoint**, and one elapsed
deadline for the whole call. Received counts include duplicates and the event
that trips a budget. The result retains partial events, per-endpoint typed
termination, and available counters/high-water values. A backend must return
one result for each requested endpoint. `RequestPolicySatisfied` means only
that the request's exit policy was met. EOSE and request completion prove
neither historical coverage nor durable admission, decryption, or engine
readiness. Endpoint failure never discards useful events from another or the
same endpoint.

Event/serialized-byte budgets are **not** total memory or wire-byte bounds.
They exclude SDK notification queues, WebSocket and parser buffers, temporary
serialization, filter/ID input, event object overhead, in-flight frames, and
other concurrent requests. A later recovery executor must limit concurrent
requests and admission work separately. No pagination cursor or exhaustive
history claim is provided here.

`NostrRelayClient::notification_loss` offers an independent `watch` control
receiver. Its value is a cumulative skipped-notification watermark for the
relay-client lifetime, including replacement receivers. The generation changes
when the receiver changes, but the count never resets. Coalescing therefore
does not erase a gap. The scope stays fixed and is explicitly
`SharedReceiver` or `AccountReceiver`; the production shared SDK receiver
cannot attribute loss to a group or one account. Its current implementation
also returns `Unsupported`. A future per-account client may narrow the scope
only when the underlying receiver is actually account-specific. This control
path must stay observable when event delivery is saturated.
The backend must update the watch value without waiting for room in the
event-delivery queue.

Cancellation signals only the acquisition. The backend must close request
subscriptions on cancellation or dropped work without removing unrelated live
interests. An unsupported backend must reject before issuing a request; it
must not substitute an unbounded subscription. Invalid requests are also
rejected before I/O.

## Implementation handoffs

- The #1358 SDK integration maps the typed #1995 `AcquisitionEnd` variants to
  `NostrAcquisitionEnd`, preserves partial events and per-relay counters,
  validates limits before I/O, and maps receiver `Lagged` updates to cumulative
  `NostrNotificationLoss`. SDK types and error-string parsing stay inside its
  implementation. Any new dial path must pass the existing relay-plane
  `RelaySafetyPolicy` and host-safety checks. It must prove cleanup preserves live subscriptions and
  qualify real SDK behavior separately; the fake tests here do not do that.
- The #1947 recovery consumer captures an owned plan from the #1946 owner,
  dispatches network acquisition outside the serialized account worker,
  requeues events for worker admission, then offers endpoint evidence back to
  the owner. The owner checks durable fences, admission, coverage, retry, and
  completion. Session replacement or receiver loss invalidates the relevant
  network evidence without clearing durable progress. Worker migration and
  scheduling are outside this interface PR.

This slice adds no connection allocator, production SDK acquisition, loss
bridge, recovery executor, retry policy, schema migration, or public binding.
