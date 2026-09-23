---
title: "Nostr Bounded Acquisition Interface"
created: 2026-09-23
updated: 2026-09-24
tags: [marmot, nostr, recovery, transport]
status: overview
---

# Nostr bounded acquisition interface

`NostrRelayClient::acquire_history` is an optional operation on the existing
relay-client boundary. It takes an owned `NostrAcquisitionRequest` and a
request-local `tokio_util::sync::CancellationToken`, and returns owned
`NostrAcquisitionResult` evidence. No account worker, engine, or storage borrow
needs to survive the network wait. The production `NostrSdkRelayClient` now
implements this operation with the qualified rust-nostr fork. Existing account
recovery policy and durable admission remain owned outside the transport.

The request's account ID selects the authentication context and inbox
recipient. The calling executor retains its existing `AttemptGrant`,
`RecoveryRevisionFence`, and `RecoveryScopeToken` across the await and pairs
them with the owned result when handing events to the worker. The transport
does not echo or validate durable recovery identifiers. Each endpoint can
report its observed connection `session_generation`, when available. That
network generation is distinct from durable retry, obligation, route, loss,
and inventory revisions. The recovery owner checks its existing fences after
worker admission; transport evidence alone cannot complete an obligation.

`NostrAcquisitionScope` selects explicit known IDs or one bounded inbox/group
time window. Inbox windows filter kind 1059 by the account's `p` tag; group
windows filter kind 445 by the exact 32-byte `h` tag. Both time bounds are
inclusive. Explicit IDs can reacquire known inventory; they cannot discover
unknown history. The limits declare the maximum endpoint count, requested
ID-filter size, received items and serialized event JSON bytes **per
endpoint**, and one elapsed
deadline for the whole call. Received counts include duplicates and the event
that trips a budget. The result retains partial events, per-endpoint typed
termination, and available counters/high-water values. A backend must return
one result for each requested endpoint. The fixed request exit policy is EOSE
from each endpoint. `RequestPolicySatisfied` means only that this EOSE arrived;
`UnexpectedExitLimit` is incomplete if an SDK exit-count condition fires
despite the fixed policy. EOSE and request completion prove
neither historical coverage nor durable admission, decryption, or engine
readiness. Endpoint failure never discards useful events from another or the
same endpoint.

Event/serialized-byte budgets are **not** total memory or wire-byte bounds.
They exclude SDK notification queues, WebSocket and parser buffers, temporary
serialization, bounded filter/ID input, event object overhead, in-flight frames, and
other concurrent requests. A later recovery executor must limit concurrent
requests and admission work separately. No pagination cursor or exhaustive
history claim is provided here.
Validation rejects zero budgets, oversized or repeated explicit-ID filters,
duplicate endpoints, and reversed time windows; it does not impose upper
ceilings on caller-chosen item, byte, duration, or concurrency budgets.
`received_items` and `serialized_event_bytes` include duplicates and the
over-budget event. Retained high-water values count only distinct retained
events and their serialized JSON bytes. A `ReceiveLoss` endpoint's
`receiver_skipped_notifications` is a per-request count, separate from the
lifetime-cumulative watch below.

`NostrRelayClient::notification_loss` offers an independent `watch` control
receiver. Its value is a cumulative skipped-notification watermark for the
relay-client lifetime, including replacement receivers. The generation changes
when the receiver changes, but the count never resets. Coalescing therefore
does not erase a gap. The scope stays fixed and is explicitly
`SharedReceiver` or `AccountReceiver`. The production SDK now gives each
account its own receiver and cumulative `AccountReceiver` watermark. Its
multi-account root returns `Unsupported` from `notification_loss()`, because
one coalescing watch cannot preserve independent account watermarks. The
smallest contract extension is `notification_loss_for_account(account_id)`,
which returns that account's watch or rejects an unregistered account. The
recovery consumer must subscribe for each activated account and must never
infer a group from a receiver gap. This control path must stay observable
when event delivery is saturated.
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
  validates limits before I/O, uses the fixed EOSE request policy, and maps
  receiver `Lagged` updates to cumulative
  `NostrNotificationLoss`. SDK types and error-string parsing stay inside its
  implementation. The app's `MarmotRelayPlane::acquire_history` validates
  endpoints with the existing `RelaySafetyPolicy` before the backend may
  register a new relay; the recovery consumer must call this guarded method.
  Its production-backend regressions cover bounded partial results, dropped
  request cleanup, live-subscription preservation, and independent account
  loss watches. Platform artifact qualification remains a separate gate.
- The #1947 recovery consumer captures an owned plan from the #1946 owner,
  retains its grant and scope token, dispatches network acquisition outside
  the serialized account worker,
  requeues events for worker admission, then offers endpoint evidence back to
  the owner. The owner checks durable fences, admission, coverage, retry, and
  completion. Session replacement or receiver loss invalidates the relevant
  network evidence without clearing durable progress. Worker migration and
  scheduling are outside this interface PR.

This integration adds the production SDK acquisition and account-scoped loss
bridge. It adds no recovery executor, durable retry policy, schema migration,
or public binding.
