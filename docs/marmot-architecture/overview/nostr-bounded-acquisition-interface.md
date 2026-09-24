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
other concurrent requests. The controlled P5 worker slice therefore limits
concurrent requests and admission work separately. No pagination cursor or exhaustive
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

The #2009 SDK integration added the production acquisition and account-scoped
loss bridge. It added no recovery executor, durable retry policy, schema
migration, or public binding.

## #1947 P5 controlled worker slice

The account worker now has an inactive, controlled-backend path for one exact
known kind-445 event in one group. It uses the existing recovery owner's
conservative selection and durable attempt reservation, keeping the frozen
scope token, route/loss/inventory fences and exact event ID in the worker.
The relay request runs in a separate task through the endpoint-validated
`MarmotRelayPlane::acquire_history`; its result
returns to the same worker for peeler/engine receipt and storage admission.
Two process-wide credits are reserved before an attempt and held until pending
admission and the guarded checkpoint finish. One account has at most one job.
The worker probes at most once a second and checks the owner's durable retry
deadline before preparing a plan; live deliveries during cooldown do not
re-run the SQLite preparation writes. This slice considers the first known-event
demand, leaving later known-event obligations to the existing owner executor.
The fixture limits each request to two endpoints, one requested ID, 16 retained
events and 128 KiB of serialized event JSON per endpoint, with a five-second
request deadline. The worker admits one event per turn and yields between
completed units. These SDK request budgets do not bound parser buffers, wire
bytes or temporary conversion allocations.

The path never treats EOSE as history coverage. A known event qualifies only
after its exact eligible input has a durable receipt or valid terminal
disposition. The owner fences checkpoint evidence against new loss and route
state. Partial results do not clear unretained demand; saturated responses and
stale fences leave it pending. Unsupported returns without a legacy replay
fallback. Unsupported scope shapes, including a third required relay, are
declined before spending retry authority and retain their full legacy scope.
Installed maintenance subscriptions and their owner observations remain in
place on both a declined and a matched exact-ID selection. Controlled worker
regressions cover a queued send, incoming and other-account
projection, stable live subscriptions, duplicate relay copies, saturation,
partial results, stale loss/route evidence, shutdown before admission and after
a durable prefix with the obligation still pending, storage reopen, and two
already-retained epoch inputs progressing while a
separate request waits.

`RuntimeSharedServices::bounded_group_recovery_enabled` defaults to false and
has no public production setter. The production SDK backend is now available,
but enabling this worker path requires the same integrated two-relay cases
against actual SDK sessions, including cancellation, partial and saturated
results, reopen, stale generation/loss/route evidence, local backlog progress
and measured protocol-byte/duplicate baselines. The legacy
`execute_recovery_grant` path still owns general epoch, overflow, explicit and
unknown-history recovery; it
remains worker-held and can still wait for EOSE. This exact-ID slice does not
establish unknown-history discovery, bandwidth optimality or the original
phone/NSE outcome.

### P5 real-SDK qualification progress

`bounded_real_sdk_two_relays_retain_one_encrypted_known_event` exercises the
production multi-account `NostrSdkRelayClient`, endpoint-validated relay plane,
account worker, MLS receive path, and SQLCipher storage. A real encrypted
kind-445 event is published to two local WebSocket relays while its recipient
is signed out. Their ordinary live subscriptions return EOSE without replaying
history. The exact-ID request retrieves the event from each relay, and the
worker retains the eligible event before clearing its known-event obligation.
The regression asserts one exact-ID REQ per endpoint, one returned EVENT per
endpoint, and per-endpoint fixture ceilings of 6 KiB inbound text, 9 KiB
outbound text, 3 KiB inbound event JSON and 8 KiB outbound event JSON. The
event JSON counters measure normalized JSON after parsing; they are included
in the text counters, not additional bytes. The measurements are WebSocket
text payloads at the local relay boundary, excluding TCP/TLS framing, SDK
allocations, and process memory.

`bounded_real_sdk_missing_eose_keeps_send_and_read_available` withholds one
relay's exact-ID EOSE. During the outstanding SDK request, the acquiring
worker completes an outbound send and a committed snapshot read, and a live
encrypted message from another account reaches its projection. The other
relay supplies the exact event, so durable retention can still satisfy the
known-event obligation. This proves progress for that single case, not general
coverage from partial endpoint evidence.

The activation gate remains closed. These tests do not yet qualify the real
SDK path for SDK-seen but unretained input, both endpoints returning no data,
saturation/oversized results, cancellation on either side of a durable
prefix, stale generation/loss/route fences, restart persistence, or competing
account recovery demands. An exploratory repeat request for the already
retained ID remained pending beyond five seconds after a test-clock advance;
the owner did not satisfy that new obligation within the bound. That needs a
focused owner-scheduling regression before a no-new-data claim. Controlled
backend tests cover several of these policies, but they do not establish
their behavior against production SDK sessions. No public activation or
platform bandwidth/peak-memory claim follows from the P5 regressions.
