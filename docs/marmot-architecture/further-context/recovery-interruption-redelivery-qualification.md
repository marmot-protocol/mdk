---
title: "#1947 P5 interruption and redelivery qualification"
created: 2026-09-24
updated: 2026-09-24
tags: [marmot, nostr, recovery, interruption]
status: qualification
---

# #1947 P5 interruption and redelivery qualification

Baseline: MDK `aae20359d4a669b32ca53a068ac2d3214eefdfcd`; rust-nostr
`63384e485d55097cb3d9e57a2146f453a5742570`. The bounded exact-ID
worker path is enabled only in the fixture. This note does not activate it.

## Current admission shape

`bounded_recovery::prepare` selects one `KnownEvent` demand, one group route,
one exact event ID, and at most two admitted endpoints. `Job::start` acquires
through the relay plane and real SDK off the account worker. The SDK returns
the entire bounded result before `Job::accept` queues events. The worker calls
`ingest_received_delivery` once per admission turn. `Job::finish` checkpoints
the exact ID's durable retention and endpoint outcomes under the owner's
attempt and scope fences. The endpoint evidence is nonexhaustive.

The new `real_sdk_returned_event_rejected_after_receipt_release` fixture
exercises one actual account worker and SQLCipher database. Two controlled
relays store Bob's real encrypted kind-445 message while Alice is signed out.
Their ordinary history subscriptions return an empty EOSE; exact-ID requests
serve the message. The SDK completes an exact-ID acquisition. A test-only
accept-point witness binds the worker account, attempt serial, and requested
ID to a positive matching
returned-item count before admission. Admission is paused; direct SQLCipher
retention remains false. Releasing a distinct seeded receipt through
`release_message_for_replay` advances the inventory revision. The returned
result then fails its admission fence, leaves the target event unretained,
and preserves the exact-ID demand. The fixture asserts one positive result
and one exact request per endpoint, the revision transition, an unchanged
persisted cursor below the missing event's timestamp, no retained-known-event
or admission-complete endpoint checkpoint, and demand survival. The installed
scope may retain nonexhaustive endpoint evidence from the returned result;
that evidence does not satisfy the obligation. The released receipt is
synthetic; it tests
the actual release transaction and fence, not release of the target event.
This witness establishes transport receipt and rejection; it does not assert
MLS decryption or projection for the target.

The test-only result witness proves request-local acquisition of the bytes.
It does not prove insertion into an SDK ordinary-delivery seen registry. The
request-local isolation revision keeps acquisition subscriptions distinct
from ordinary notifications. SDK-seen-but-unretained redelivery at that
ordinary registry boundary remains unproved.

An earlier exploratory single-relay fixture tried to prove a second bounded
acquisition in the same live runtime. A second exact relay query and target
retention occurred, but no second bounded-result witness fired, even while bounded admission was
paused. At timeout, the owner attempt serial had advanced and two demands
remained. Those observations cannot attribute the second retention to bounded
admission. The current worker still calls `run_pending_epoch_backfill` through
maintenance and other legacy seams, and ordinary delivery remains active;
either path may have supplied the bytes. This branch does not change those
paths or claim a bounded redelivery result. A future composed fixture must
identify the ingress and owner that retained the event before treating the
second exact query as proof of bounded reacquisition.

## Structural and lifecycle limits

One exact ID per attempt cannot produce a distinct eligible event suffix in
the same attempt. A two-endpoint result can contain two copies of the same ID;
that is not a distinct suffix. The SDK returns a complete bounded result
before worker admission, so cancellation while the SDK receives an event
cannot preserve a worker-admitted prefix from that same request. Proving the
requested same-attempt retained-prefix and distinct-unretained-suffix case
requires a reviewed admission seam that can carry multiple eligible IDs or
stream owned batches while preserving the existing owner grant, per-ID
retention, and scope-token completion rules. This fixture does not widen the
selector solely for that test.

Existing controlled-result tests cover shutdown after a duplicate-ID durable
prefix and scope replacement after valid retention. Existing real-SDK tests
cover cancellation/reopen before admission and two-endpoint exact-ID
retention. This new fixture stops after first-result rejection, before a
competing owner can change its postconditions. Together these cases do not
establish the distinct same-attempt suffix, same-live-SDK redelivery through
bounded admission, abrupt process-kill durability, device behavior, whole-wire
or RSS bounds, or production activation. EOSE remains endpoint evidence rather than durable
admission. The in-process SQLCipher reopen cases are not crash proof.

## Verification

`cargo test -p marmot-app --lib real_sdk_returned_event_rejected_after_receipt_release`
passed five independent runs without a test retry. `just fast-ci` passed on
the final code diff. No full local CI matrix or device campaign was run.
