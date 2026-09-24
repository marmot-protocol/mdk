---
title: "#1947 P5 resource bounds qualification"
created: 2026-09-24
updated: 2026-09-24
tags: [marmot, nostr, recovery, resources]
status: qualification
---

# #1947 P5 resource bounds qualification

This is a bounded fixture for the inactive exact-known-event worker path, not
a production activation decision. Its source baseline is MDK
`b9ffb8f0aa7214a8e4ca3f3d1415dab53e3b5612` with rust-nostr pinned to
`0efbb4ee20cd2d48ff9ffc19d307ec5a3658d6b9`. This branch pins the
reviewed SDK isolation head `63384e485d55097cb3d9e57a2146f453a5742570`
from merged rust-nostr PR #2.
The focused tests are in
`crates/marmot-app/src/runtime/account_worker/tests/resource_bounds_tests.rs`.

## Source to acceptance map

| Boundary | Current rule | Focused witness |
| --- | --- | --- |
| SDK request | At most two endpoints; each counts every received EVENT, including duplicates and the first rejected item, against item and serialized event JSON budgets. | Two local WebSocket relays send 24 copies each of one signed event. Four accepted notifications plus the fifth boundary item per relay return `ItemLimitReached`; each retains one distinct event. |
| Oversized input | A byte-boundary item is counted but not retained. | One signed event larger than a 1,024-byte request budget is sent by each relay; both return `ByteLimitReached`, one counted item and zero retained items. |
| Empty and partial endpoints | An EOSE is request evidence, while no EOSE is incomplete. | Two empty endpoints return zero input within a 4,096-byte absolute text-payload ceiling. A second fixture returns one event from one endpoint and `Deadline` from the other. |
| Worker ownership | Two process-wide execution credits; one exact ID per job; one admission per worker turn. | A test-only RAII permit exhausts both credits. A counter at the failed `try_acquire` branch witnesses a route-checked candidate reaching the gate; no bounded SDK call occurs, demand persists, a committed snapshot read returns, and shutdown releases credits. A separate controlled-backend worker case durably retains an exact event from a partial endpoint result. |

The credit-refusal counter is after scope/route checks and before owner grant
authorization. It does not prove that all later owner checks would have
approved the attempt. The saturated fixture does not establish resumption of
that same demand after capacity returns. The fresh partial-result fixture is
separate evidence.

The existing conforming-relay worker fixture joins a comparison and thereby
creates an `IncrementalHistory` obligation. Its intermittent comparison timeout
was traced to a test-only window mismatch: the fixture joined an earlier frozen
route with a newer request second, leaving the recorded debt one second short
of the next operational plan. The #2023 fixture correction derives both from
one captured timestamp; its fixed-time storage witness keeps the coverage
guard intact. Six no-retry CI-profile repetitions and #2023's exact-head CI
passed. This resource slice does not establish general comparison fairness.

## Accounting boundaries

The relay fixture counts UTF-8 WebSocket text payloads before SDK filtering.
`sent_event_json` is the JSON object inside an `EVENT` frame and is a subset
of `sent_text`, never an additional byte total. It counts both relay copies.
Received text includes the client's `REQ` and `CLOSE` frames observed before
the result snapshot. Binary frames, WebSocket framing, TCP/TLS, retransmission,
parser allocations, and carrier-billed traffic are excluded. Reconciliation
is not used by these exact-ID requests; its protocol traffic is zero in this
fixture. The SDK's `received_items` and `serialized_event_bytes` are measured
after parsing, before its request-local deduplication. They can be smaller than
the relay's sent counts because the relay may have already queued more frames
when the request stops.

One local run of the six focused tests against the reviewed SDK pin reported:

| Scenario | Client text bytes | Relay text bytes | Relay EVENT JSON bytes | SDK received / retained items |
| --- | ---: | ---: | ---: | ---: |
| Two empty relays | 300 | 148 | 0 | 0 / 0 |
| One event, other endpoint lacks EOSE | 375 | 620 | 470 | 1 / 1 |
| 24 duplicate copies per relay | 300 | 26,208 | 22,560 | 10 / 2 across both relays |
| One oversized event per relay | 300 | 9,176 | 8,876 | 2 / 0 |

The numeric request ceilings are small fixture limits that distinguish a
working budget from a missing one. They are not production latency, memory or
bandwidth targets. For the inactive worker, `MAX_EVENTS_PER_ENDPOINT=16`,
`MAX_BYTES_PER_ENDPOINT=128 KiB`, `MAX_ENDPOINTS=2`, and
`MAX_CONCURRENT_JOBS=2` imply at most 32 returned event objects and 256 KiB
of summed serialized event JSON per job, or 64 objects and 512 KiB across
two simultaneously held results. The worker verifies those endpoint result
limits before moving events to its pending deque. This estimate does not add
the SDK's per-relay one-item activity queue and producer/collector items,
over-budget events, serde serialization while checking the result, event
object/tree overhead, parser/WebSocket buffers, or independent live delivery.
The latter has a 256-item SDK forwarder lane and a 1,024-delivery account
queue plus one reserved overflow-control slot; these are distinct capacities.

As a reproducible process-level smoke measurement on this macOS host, run the
same built `marmot_app` unit-test binary with `RUST_MIN_STACK=4194304` through
`/usr/bin/time -l`, selecting each exact test name. The empty two-relay case
had 27,639,808 bytes maximum resident set size; the 48-copy duplicate case
had 29,245,440 bytes. These include the linked test process and SDK itself.
Their difference is not a per-event allocation estimate or a representative
large-account memory ceiling.

## Remaining boundaries

The baseline pinned SDK emits a first-seen acquisition EVENT to the ordinary
notification path before the request-local item/byte check. That path can
reach the app's live queue and durable admission independently of the bounded
result. The baseline failed the new real SDK/worker/SQLCipher fence assertion
while a second relay withheld EOSE and `bounded_result_ready` was pending.
With the reviewed SDK isolation revision, that assertion and the
stale-new-loss regression passed. All five real-SDK worker cases passed in a
subsequent complete run. A later CI-profile comparison failure was traced to
the stale-window fixture join described above; the earlier timeout had the
same symptom, but its exact cause was not instrumented. No production owner
rejection was observed in the traced failure. The SDK isolation fix
and fixture correction merged separately. This MDK PR's composed CI remains a
gate; activation stays off.

The fixture does not bound shared connection queues, WebSocket/parser
allocation, one oversized in-flight event, all account concurrency, or the
legacy recovery executor. It does not qualify a 36-group/11,000-event account,
optimal selective bandwidth, unknown-history discovery, device Wi-Fi/cellular
traffic, or iOS foreground/NSE memory. Those remain P6/P8 and host gates.

Run `cargo test -p marmot-app --lib resource_bounds_tests -- --nocapture` for
the focused counts, then `just fast-ci` before pushing a candidate. The
default production bounded-recovery activation remains off.
