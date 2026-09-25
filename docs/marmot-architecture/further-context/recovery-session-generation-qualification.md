---
title: "#1948 real SDK account-session replacement qualification"
created: 2026-09-25
updated: 2026-09-25
tags: [marmot, nostr, recovery, lifecycle]
status: qualification
---

# #1948 real SDK account-session replacement qualification

Baseline: MDK `0e2c48241da467abfb83830d5e6f72921a1af248`. The bounded
exact-ID worker path is enabled only by the fixture; production activation
remains off.

## Boundary and fixture

`real_sdk_returned_result_is_dropped_on_account_restart_before_new_session_recovery`
uses one account, the real SDK, two conforming local relays, the managed
account worker and the account SQLCipher store. A signed kind-445 event for
Alice's group is saved once into each relay's database after the initial,
empty comparison has settled. This models a late relay-store import. The query
policy accepts every query and records peer socket addresses. It neither hides
the target from NIP-77 nor emits a synthetic comparison result. The event
timestamp is captured once, inside the 30-day retained-inventory window and
strictly before the ordinary live subscription cutoff. An exact known-ID
request has no `since` bound.

The event has a valid signed Nostr wrapper and a deliberately nondecryptable MLS
payload. Its useful durable outcome is a raw `PeelDeferred` row, not plaintext,
epoch advancement or projection. The fixture checks both the SQLCipher raw row
and the retained transport-inventory entry after recovery.

Alice's first bounded exact-ID attempt returns the event from both relays. The
existing worker witness binds the returned items to her account, attempt serial
and requested event ID. Admission is paused; SQLCipher has no raw row or
retained inventory entry, the frozen scope has no checkpoint, and one bounded
execution credit is held. `restart_account` then removes and reaps the old
worker before opening its replacement. The job drop cancels the old acquisition
and releases the credit. The original demand, scope and cursor remain unchanged
at the teardown snapshot, and the target is still unretained. This lifecycle
boundary removes the old job before its admission or completion methods run.

The source path from `restart_account` awaits the worker reaper; that reaper
calls `MarmotRelayPlane::deactivate_account_context`, which removes and shuts
down the SDK's account client. Reconciliation registers a new account client.
With Alice as the only account, each relay observes a replacement h-tag group
query from a peer socket distinct from the old exact-request peer. The adapter
currently reports `NostrAcquisitionEndpoint.session_generation = None`, so the
fixture records physical connection replacement and source-owned client
replacement rather than claiming an SDK generation token.

The replacement worker's finite NIP-77 comparison covers the imported event's
timestamp. While bounded admission is still paused, that replacement session
settles its comparison and the SQLCipher store gains both the retained event
entry and a `PeelDeferred` raw row. Any replacement exact request is observed
only as transport work; its returned result is not credited with this durable
admission. The test does not depend on a second exact request to prove the new
session's progress.

## Limits

This proves in-process account-session replacement after a real SDK result has
already reached the worker. The earlier cancel/reopen fixture stops before a
result reaches the worker; the owner-attempt replacement fixture keeps one
worker and SDK session. This fixture does not establish process-kill recovery,
ordinary SDK seen-but-unretained redelivery, new-session bounded admission,
unknown-history coverage, MLS decryption, device behavior or full #1948
completion. EOSE and a returned SDK result are transport observations; the
SQLCipher row and inventory are the durable evidence here.

An attempted fixture with an event older than the 30-day comparison window
could not serve as a retention witness: `record_transport_reconciliation_item`
also omits events older than that same configured floor. The final fixture
keeps the target inside that floor and lets the replacement comparison run.

## Verification

The targeted command is:

```sh
cargo test -p marmot-app --lib real_sdk_returned_result_is_dropped_on_account_restart_before_new_session_recovery
```

The targeted test and `just fast-ci` passed on the baseline above. This is
qualification of the inactive path, not production activation or a policy
change.
