---
title: "Nostr Bounded Acquisition Interface"
created: 2026-09-23
updated: 2026-09-28
tags: [marmot, nostr, recovery, transport]
status: overview
---

# Nostr bounded acquisition interface

This is the contract for two optional operations on the `NostrRelayClient` boundary: bounded history acquisition and
the notification-loss watch. The types live in `crates/transport-nostr-adapter/src/acquisition.rs`. Recovery policy,
durable admission and completion stay outside the transport; see
[account history recovery](../further-context/account-recovery.md). NIP-77 comparison is a separate SDK client
operation; see
[reconciliation progress ownership](../../../crates/transport-nostr-adapter/README.md#reconciliation-progress-ownership).

## Operations

- `NostrRelayClient::acquire_history(request, cancellation)` takes an owned `NostrAcquisitionRequest` and a
  request-local `tokio_util::sync::CancellationToken`, and returns owned `NostrAcquisitionResult` evidence. No account
  worker, engine or storage borrow needs to survive the network wait. The default implementation returns
  `Unsupported`.
- `NostrTransportAdapter::acquire_history` validates the request before dispatch. `MarmotRelayPlane::acquire_history`
  also checks every endpoint against `RelaySafetyPolicy` before the backend may register a new relay. Recovery callers
  must use this guarded method.
- `NostrRelayClient::notification_loss` and `notification_loss_for_account` return a `watch` receiver for the
  cumulative loss watermark described under [Loss scope](#loss-scope).

The production `NostrSdkRelayClient` implements both operations.

## Request

The request's `account_id` selects the authentication context and inbox recipient. `NostrAcquisitionScope` is one of:

- `KnownEventIds`: reacquire explicit event IDs. This cannot discover unknown history.
- `AccountInboxWindow { since, until }`: kind 1059 filtered by the account's `p` tag.
- `GroupWindow { transport_group_id, since, until }`: kind 445 filtered by the exact 32-byte `h` tag.

Both time bounds are inclusive, and a window is never issued as an unfiltered time REQ.

The caller keeps its `AttemptGrant`, `RecoveryRevisionFence` and `RecoveryScopeToken` across the await and pairs them
with the owned result when it hands events to the worker. The transport does not echo or validate durable recovery
identifiers.

## Bounds

`NostrAcquisitionLimits` declares:

| Field | Bound |
| --- | --- |
| `max_endpoints` | Endpoints in one request. |
| `max_requested_event_ids` | IDs in one `KnownEventIds` filter, independent of the item budget. |
| `max_received_items_per_endpoint` | Received events per endpoint. |
| `max_serialized_event_bytes_per_endpoint` | Serialized event JSON bytes per endpoint. |
| `max_duration` | One elapsed deadline for the whole call. |

Validation runs before any I/O. It rejects an empty endpoint list, empty or duplicate endpoints, more endpoints than
`max_endpoints`, zero budgets, empty, repeated or oversized explicit-ID filters, and reversed time windows. It does not
impose upper ceilings on caller-chosen item, byte, duration or concurrency budgets; deployment-wide ceilings belong to
the caller.

`received_items` and `serialized_event_bytes` include duplicates and the event that trips a budget. The retained
high-water values count only distinct retained events and their serialized JSON bytes.

These budgets are not total memory or wire-byte bounds. They exclude SDK notification queues, WebSocket and parser
buffers, temporary serialization, filter and ID input, event object overhead, in-flight frames and other concurrent
requests. Callers bound concurrency and admission work separately. The interface provides no pagination cursor and
makes no exhaustive-history claim.

## Outcomes

`NostrAcquisitionResult` holds exactly one `NostrAcquisitionEndpoint` per requested endpoint, including failed ones.
Each carries the events it retained, a typed `NostrAcquisitionEnd`, `NostrAcquisitionStats`, and the observed
connection `session_generation` when available. Endpoint failure never discards useful events from the same or another
endpoint.

The fixed request exit policy is EOSE from each endpoint, and only `RequestPolicySatisfied` reports that this EOSE
arrived. Every other end means that endpoint did not finish the request:

- `UnexpectedExitLimit`: an SDK exit-count condition fired despite the fixed policy;
- `ItemLimitReached`, `ByteLimitReached` and `Deadline`: a declared budget ran out;
- `Cancelled`: the request-local token fired;
- `Disconnected`, `RelayClosed`, `Rejected`, `AuthenticationFailed` and `SetupFailed`: the relay or request setup
  failed;
- `ReceiveLoss` and `ReceiverClosed`: the SDK receiver lagged or closed. `receiver_skipped_notifications` is this
  request's count, separate from the lifetime watermark under [Loss scope](#loss-scope).

EOSE and request completion prove neither historical coverage nor durable admission, decryption or engine readiness.
`session_generation` is network evidence for rejecting stale observations; it is distinct from durable retry,
obligation, route, loss and inventory revisions. The recovery owner checks its own fences after worker admission.
Transport evidence alone cannot complete an obligation.

`NostrAcquisitionError` is only for refusals before network work: `Unsupported` and `InvalidRequest`. An unsupported
backend must not substitute an unbounded subscription.

## Cancellation

Cancellation signals only this acquisition. On cancellation or a dropped future, the backend closes this request's
subscriptions without removing unrelated live interests.

## Loss scope

The loss watch carries a cumulative skipped-notification watermark for the relay-client lifetime, including
replacement receivers. A replacement advances `receiver_generation` but never resets the count, so coalesced watch
updates cannot erase a gap. The scope is fixed and explicit: `SharedReceiver` or `AccountReceiver { account_id }`.

The production SDK gives each account its own receiver and `AccountReceiver` watermark. Its multi-account root returns
`Unsupported` from `notification_loss`, because one coalescing watch cannot carry independent account watermarks.
`notification_loss_for_account` returns that account's watch or rejects an unregistered account.

Each account context also records the `since` of every REQ it issues, before the REQ goes out. A closed REQ keeps
counting for the rest of the context's life. Routing is by content, so its buffered or in-flight notifications can
still arrive, and nothing bounds when. `notification_loss_floor` (on the root, `notification_loss_floor_for_account`)
returns the lowest of these as a `NostrNotificationLossFloor`: no event whose notification a lag loses at that moment
is older. An unfloored REQ, no REQ at all, or a shared receiver reads as `Unbounded`. The floor only falls over the
context's life, so reading it at the lag gives the tightest bound.

A lag can also lose end-of-stored-events. `reissue_subscription` recovers them: it re-sends a live REQ unchanged, under
its own id, to the connected relays that never answered it. It closes the REQ on each of them first, so no relay sees
the id repeated while it is live there, and sends both as raw frames, which leave the SDK's reconnect registry
untouched. The account context records the REQ again first, with the `since` it was issued with, and never reopens a
closed REQ, so the re-issue leaves the floor where it was.

The recovery consumer subscribes for each activated account and never infers a group from a receiver gap. The backend
must update the watch without waiting for room in the event-delivery queue, so loss stays observable when event
delivery is saturated.
