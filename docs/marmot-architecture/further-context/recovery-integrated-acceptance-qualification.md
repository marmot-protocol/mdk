---
title: "#1947 integrated recovery acceptance qualification"
created: 2026-09-25
updated: 2026-09-25
tags: [marmot, nostr, recovery, history]
status: qualification
---

# Integrated recovery acceptance qualification

`startup_gap_recovers_real_mls_history_and_survives_sqlcipher_reopen` uses
the app runtime, two real MLS groups, local Nostr SDK relays, and file-backed
SQLCipher. Bob receives admin rights in the target group. Alice signs out;
Bob publishes two real profile commits and eight encrypted messages after the
second commit. The target relay retains every event. Its test database raises
`since` only for ordinary broad target-route queries, so Alice sees later
history while the first commit is withheld. NIP-77 inventory and exact-ID
lookups read the unmodified retained set. This is controlled delivery
withholding, not a claim about typical relay ordering or deleted history.

On a cold reopen, Alice naturally persists `EpochGap`, with no fabricated
`KnownEvent` demand and the first commit absent from her durable inventory.
The worker's eligible startup comparison grant activates live subscriptions,
then runs its frozen SDK acquisition under one of the shared process credits.
While its network job and adapter reconciliation future remain active, the
test requires a recovery status response within 300 ms, a send on the healthy
group within two seconds, and a decrypted peer message from that group within
two seconds. The healthy group uses an independent relay connection. The
test-only activity witness counts the actual owned job and adapter
reconciliation future, and both counters return to zero after the join. These
are fixture bounds, not production latency promises.

After the held target query is released, Alice durably admits the missing
commit, reaches Bob's MLS epoch, and decrypts all eight later messages. The
plaintext and epoch survive `shutdown_and_close` and a second SQLCipher
reopen. The test also checks that startup snapshot group reads remain ready
and that a status queued behind a coalesced `CatchUp` stays behind that FIFO
barrier until the network work finishes. Its exact selected EpochGap grant
and exhaustive endpoint coverage are not asserted: the startup comparison
may be selected before the later traffic arms the gap, and EOSE alone cannot
certify durable admission.

Two adjacent tests cover the same startup continuation's capacity and
interruption boundaries. With both shared credits held, a comparison stays
pending and the retry serial does not advance while startup still answers a
deferred command. In the cancellation fixture, the owned job and adapter
request are held over a signed Nostr event; `shutdown_and_close` reaps both,
restores the credit, and a fresh SQLCipher open still has the comparison debt
and the same retry serial. That cancellation fixture does not use valid MLS
payloads; valid MLS recovery is established by the main test.

## Baseline and limits

The first valid-MLS fixture passed on merged MDK `3ac6156a` with pinned
rust-nostr `63384e48`: the missing commit, epoch, eight plaintext rows, and
cold reopen recovered through the preexisting startup path. An immediate
status probe on that baseline did not return within 300 ms (302 ms observed),
although a later status reply arrived after the SDK's ten-second comparison
quantum. The original same-relay healthy receipt also timed out. In
`nostr-relay-builder` 0.44.0, a held `QueryPolicy::admit_query` blocks that
WebSocket loop before it polls its live broadcast arm. Bob could publish on a
separate socket, but Alice could not receive the healthy event on that same
held relay connection until release. The independent healthy relay in the
current fixture isolates account-worker progress from this local-relay
head-of-line behavior. It does not prove progress through a physically
blocked connection.

The activity witness covers the adapter reconciliation future, not the
internal lifetime of one exact-ID SDK subrequest. The fixture does not count
wire bytes, retained-history bandwidth, SDK queue allocation, whole-process
RSS, device traffic, or incomplete/floored relay histories. It uses the
`test-policy-overrides` feature to shorten retry and settlement intervals to
100 ms. Separate selective-history and resource-bound qualifications retain
their own request-local accounting boundaries.

Focused commands:

```sh
cargo test -p marmot-app --features test-policy-overrides --lib startup_gap_recovers_real_mls_history_and_survives_sqlcipher_reopen
cargo test -p marmot-app --features test-policy-overrides --lib startup_comparison_waits_for_credit_before_reserving_retry
cargo test -p marmot-app --features test-policy-overrides --lib startup_comparison_shutdown_reaps_owned_request_and_keeps_debt
```
