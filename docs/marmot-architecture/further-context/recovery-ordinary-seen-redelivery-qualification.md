---
title: "#1947 ordinary SDK sighting and bounded redelivery qualification"
created: 2026-09-25
updated: 2026-09-25
tags: [marmot, nostr, recovery, redelivery]
status: qualification
---

# Ordinary SDK sighting and bounded redelivery qualification

Status: focused default-off worker fixture on MDK `2e73c000` and the pinned
rust-nostr revision `63384e485d55097cb3d9e57a2146f453a5742570`. This
does not activate bounded recovery or close the wider P5 acceptance program.

`ordinary_sdk_seen_but_unretained_event_is_admitted_by_bounded_worker` keeps
Alice's actual account worker and account SDK client alive throughout. Bob
publishes a real encrypted kind-445 group message from a separate relay plane,
so local-publish fanout cannot admit it to Alice. A controlled relay sends the
stored signed event on Alice's existing ordinary group subscription. A
default-disabled, exact-account-and-event test hook claims that one worker
delivery and drops it immediately before `ingest_received_delivery`. The hook
records its actual subscription ID, which the fixture matches against the
relay's ordinary live REQ. It leaves every other delivery and overflow path
unchanged. The raw wrapper ID has no engine row, the group's engine-row set is
unchanged, and SQLCipher's reconciliation inventory and Alice's plaintext
projection remain empty for the target at this point.

This is a source-backed ordinary SDK seen witness rather than a direct SDK
registry read. In the pinned SDK, the ordinary `handle_event_msg` path validates
the event and saves its ID to the default `MemoryEventsTracker` before emitting
`ClientNotification::Event`. The transport adapter delivers only that Event
notification; its raw `ClientNotification::Message` path is telemetry only.
The default tracker keeps the ID but returns no bytes from `event_by_id`.
Request-local `acquire_events` skips that shared save and ordinary notification
path. The test's actual ordinary worker delivery therefore crosses the SDK
save/notification boundary, while the account has not durably retained it.

The fixture then records a known-event demand. Two controlled relays serve the
exact ID; their ordinary history REQs return empty EOSE. The existing worker
result witness identifies Alice, the current attempt serial, the exact ID, and
two matching returned items. With bounded admission paused, SQLCipher still
lacks the event and the plaintext. After releasing only that gate, the fixture
waits for a bounded admission prefix and completion, then requires one new
processed MLS content row and the wrapper's reconciliation inventory in
SQLCipher, exactly one decrypted
plaintext message, and discharge of the exact known-event demand. The relay
counts one exact-ID REQ per endpoint. EOSE and the completed transport result
alone are never treated as durable admission.

The relay's empty ordinary backlog and controlled ordinary live sends
are fixture controls, not claims about natural relay loss. This is an
in-process same-client redelivery check, not crash persistence, full historical
coverage, general memory bounds, or device behavior. The test does not imply
that arbitrary ordinary drops are safe; the one-shot hook exists only under
`cfg(test)` to isolate the recovery boundary.
