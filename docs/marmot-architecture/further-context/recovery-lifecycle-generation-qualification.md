---
title: "#1948 real SDK owner-attempt replacement qualification"
created: 2026-09-25
updated: 2026-09-25
tags: [marmot, nostr, recovery, lifecycle]
status: qualification
---

# #1948 real SDK owner-attempt replacement qualification

Baseline: MDK `73446bc91c7100df4d35866f36b9cf8ccceabbd6`; rust-nostr
`63384e485d55097cb3d9e57a2146f453a5742570`. The bounded exact-ID
worker path is enabled only by the fixture; production activation remains off.

## Boundary and regression

The inactive bounded selector authorizes one `KnownEvent` ID on one group route.
The worker starts a request-local acquisition off-worker, receives the entire
SDK result, then admits at most one returned item per worker turn. A separate
owner scope checkpoint follows admission. This cannot express a distinct
same-attempt durable prefix and unretained suffix without changing the
selector or admission contract.

`real_sdk_result_after_attempt_replacement_retains_bytes_without_old_completion`
uses two controlled relays and a real encrypted kind-445 event sent while Alice
is signed out. Ordinary history returns an empty EOSE; each exact-ID request
serves the event. The test-only worker witness binds the returned result to the
account, old attempt serial, requested ID and a positive matching-item count.
Admission is paused, and SQLCipher confirms that the target is unretained.

The fixture then reserves a newer attempt for the same durable obligation and
installs a new scope token under the unchanged loss, route and inventory
revision fence. This is controlled owner-generation fault injection, not a
second network request or a production scheduling change. Both endpoints
return copies of the same eligible ID. The test releases the old job only
until its first successful bounded ingest, then pauses it before the remaining
copy. At that boundary, SQLCipher retains the ID while the newer scope still
has no checkpoints. The successful-ingest signal is emitted by the exact
resumed bounded worker branch after `Job::admit_one`; it cannot be supplied by
the legacy executor. Empty ordinary history also prevents a live/history read
from supplying the target. Finally, the old attempt's conditional checkpoint
cannot clear the new owner's demand or write into its scope. The test checks
the retained ID, pending demand and current scope token, attempt serial and
empty checkpoint list before and after old completion.

## Ownership and limits

No old execution path is replaced by this assurance test. `Job::start`,
`Job::admit_one` and `Job::finish` remain the inactive bounded executor, and
the owner's conditional checkpoint remains the sole completion authority. The
legacy path remains available for other owner-authorized scopes until its
separate replacement gate; this fixture does not activate or retire it.

Durable retention here is not MLS decryption or projection proof. In-process
SQLCipher checks are not process-kill durability. The test does not prove
same-live SDK ordinary-seen redelivery, unknown-history coverage, device
behavior, full wire/RSS bounds or complete #1948 lifecycle acceptance. EOSE is
endpoint evidence, not durable admission. A newly reserved attempt in this
fixture remains pending; the test does not assert it has made a new network
request or ultimately completed.

## Verification

`cargo test -p marmot-app --lib
real_sdk_result_after_attempt_replacement_retains_bytes_without_old_completion`
passed against the real SDK, worker and SQLCipher. `just fast-ci` passed,
including workspace formatting, default and feature compile checks, and
Clippy. This is a focused qualification, not the full #1948 composed matrix.
