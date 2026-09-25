---
title: "#1947 integrated recovery acceptance qualification"
created: 2026-09-25
updated: 2026-09-25
tags: [marmot, nostr, recovery, history]
status: qualification
---

# Integrated recovery acceptance qualification

The focused `startup_gap_recovers_real_mls_history_and_survives_sqlcipher_reopen`
test starts from merged MDK `3ac6156a` and pinned rust-nostr `63384e48`.
It uses the supported app runtime with two real MLS groups, a local Nostr SDK
relay, and file-backed SQLCipher. Alice joins both groups. Bob receives admin
rights in the target group, then Alice signs out while Bob publishes two real
profile commits and eight encrypted messages after the second commit.

The relay retains every published event. Its test database raises `since` only
for ordinary broad queries on the target route, so Alice receives later
history while the earlier commit is withheld. Exact-ID requests and NIP-77
inventory read the unmodified retained set. This is controlled relay delivery,
not a claim about ordinary relay ordering or a deleted history item. The test
asserts a naturally durable `EpochGap`, absence of a fabricated `KnownEvent`,
and absence of the missing commit from Alice's durable event inventory.

On a cold account reopen, the runtime issued an exact-ID request for the
missing commit. With that relay query handler held, `GroupRecoveryStatus` and
a send on the healthy second group returned. The test does not establish
whether those commands completed before the SDK request's own deadline.
After the handler was released,
Alice durably admitted the commit, reached Bob's MLS epoch, and decrypted all
eight later messages. The plaintext rows and epoch survived
`shutdown_and_close` and a second SQLCipher reopen. The focused feature-on
test passed locally: one test in 10.32 seconds after compilation, then one
repeat in 10.25 seconds. The test-policy-overrides feature shortens the
development retry and settlement intervals to 100 ms.

## Evidence boundary

This demonstrates functioning automatic recovery for one controlled retained
history gap. At the held query, the test-only pending-selection witness was
empty and the gap had no scope snapshot; the account retry serial was 5.
The witness does not observe the direct startup grant path, so the exact
selected cause and owner path are not established by this test.
The relay handler remained active while the status command returned, but the
shared worker credit count was already 2 of 2. A server handler can outlive a
timed-out SDK request, so this result does **not** prove that the request stayed
active through the status response or that a live message was delivered
concurrently with its network wait. A separate healthy-route one-shot publish
returned successfully, but its live receipt did not appear within five
seconds and was removed as an acceptance assertion. The initial credit
assertion expected one available credit and observed two. The first
cancellation assertion expected the server handler to stop immediately and
observed it still active; cancellation and durable debt preservation need a
separate composed test.

The fixture does not count wire bytes, retained-history bandwidth, SDK queue
allocation, whole-process RSS, device traffic, or incomplete/floored relay
histories. Its `since` cutoff hides all earlier target-route events from broad
replay, while the initial group state was already durable on Alice. The
separate selective-history and resource-bound qualifications cover their own
request-local accounting boundaries; this test does not extend those claims.

Focused command:

```sh
cargo test -p marmot-app --features test-policy-overrides --lib startup_gap_recovers_real_mls_history_and_survives_sqlcipher_reopen -- --nocapture
```
