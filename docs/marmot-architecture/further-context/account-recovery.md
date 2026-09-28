---
title: Account history recovery
updated: 2026-09-28
status: Design (v2), being implemented. Replaces the 22 recovery design, ledger and qualification notes.
---

# Account history recovery

Tracks #1945 (outcome), #1947 (bounded acquisition) and #1948 (assurance). The durable
owner from #1946 stays. This document covers what changes, what is deleted, and how we
will know it worked.

The notes this replaces, including the #1946 ownership design, its integration ledger and
the 13395cc1 checkpoint evidence, remain in git history at
[`9489bb091`](https://github.com/marmot-protocol/mdk/tree/9489bb091/docs/marmot-architecture/further-context).

## Goal and scorecard

Recovery must be correct, responsive, cheap on bandwidth, and it must finish.

The scorecard is the #1945 large-account workload: 36 groups, about 11,000 events, one
51-member group, two relays, one genuinely missing older commit, and live traffic
throughout. It runs under **production policy**, against v0.10.4 (what iOS build 41
shipped) and against the new code.

| Measure | Target |
| --- | --- |
| Status and send latency while recovery runs | under 500 ms |
| A live message becomes visible while recovery runs | within 2 s |
| Queue overflow caused by history we already hold | zero re-download |
| Missing commit that some relay still has | recovered in one paced attempt |
| Steady state once caught up | no full-history download; comparison traffic only |
| Loss obligations | each one completes, or parks visibly after a fixed budget |

The simulator comes first; Jeff validates on a phone.

## Decisions (agreed with Jeff, 2026-09-27; revised 2026-09-28)

1. **Completion is tiered.**
   - Known-event loss completes when that exact event is durably stored, or has a durable
     terminal disposition.
   - Unknown-scope loss completes when every *required* relay finished an untruncated NIP-77
     comparison over the frozen window, and every difference was admitted or terminally
     disposed.
   - That window must cover the obligation's whole goal. A queue-loss goal starts at the
     earliest `created_at` among the deliveries it lost. The router and the spill know each
     delivery's wire `created_at` when they drop or discard it. Step 2 keeps a running
     minimum per loss generation over every delivery charged to it, written in the same
     durable update as the count. That covers the router's marker write and the
     transaction that deletes a spill row and records its loss. A later drop can carry an
     earlier `created_at`, for example an inbox wrap tweaked by NIP-59. The checkpoint is
     not a bound: each subscription keeps the `since` it was built with, which can be far
     older than the current checkpoint. A charge with no known `created_at` clears the
     generation's bound in that same update, so a goal is bounded only when every delivery
     charged to it contributed a timestamp.
   - SDK notification lag loses notifications, not deliveries with known times. It charges
     the lowest `since` among every REQ the account's SDK context issued, live or closed.
     Routing is by content, so a closed REQ's buffered or in-flight notifications still
     arrive, and nothing bounds when: a stalled consumer keeps them buffered, and a relay
     with a deep outbound backlog keeps sending them. An unfloored REQ, such as post-join
     maintenance, makes every later charge on that context unknown. A lag keeps the account route open
     and forces no reconnect. The SDK client has already marked the lost events seen, so
     only comparison and exact-ID acquisition recover them.
   - Loss with no known bound has an unbounded goal. That covers SDK notification lag while
     an unfloored REQ is in scope, an undecodable spill row, count-only rows written before
     step 2, and an epoch gap whose commit time is unknown. So does a goal that reaches below the retained-inventory floor. None of these can be certified by
     comparison, although the comparison still fetches every difference inside the window.
     Such an obligation completes only on its own evidence, for example the missing epoch
     arriving, or it parks for explicit deep repair.
   - Cold-start and incremental history have no lost delivery to bound them. Their goal is
     the retained inventory window, the last 30 days, and a comparison over that window
     certifies them. The earlier rule that an unresolved placeholder had no proven lower
     bound, and so could never certify, is gone.
   - Otherwise, once **every route the obligation still cannot certify has been compared 3
     times in a row without admitting or certifying anything**, the obligation parks. Each
     route counts its own comparisons, so a pass that compares a slice of routes cannot park
     the rest. New evidence, or durable admission on a route, starts that route's count over.
     It shows "history may be incomplete" and offers an explicit deep repair, which can
     still complete it with qualified coverage, or an explicit retirement. There are no
     further automatic retries.
   - Comparisons whose required relays failed or timed out do not count toward the budget. A
     relay that answered but could not hand over a claimed event, an event that was not
     durably admitted, and a backend that cannot compare a route all give a finished answer,
     so they do count.
2. **The queue keeps what it drops.** Overflowed deliveries are stored durably (bytes), within
   a cap.
3. **Required relays are the relays we operate.** `MarmotAppConfig::recovery_operated_relays`
   names them; the default is `wss://relay.eu.whitenoise.chat` and
   `wss://relay.us.whitenoise.chat`, and NIP-77 is a hard requirement for them. A route that
   lists any operated relay requires exactly those. A route that lists none requires all of
   its relays, so its history can still certify. Every other relay is best effort: it is
   still compared and its events are admitted, but its failure, truncation or missing NIP-77
   support never withholds a certificate or schedules a retry. The operated set is part of
   the route policy, so changing it rebuilds every pending scope. An empty required set
   never certifies a scope. A required relay that does not support NIP-77 cannot certify its
   scope, so the scope never completes on the relays that do.
   Acquisition keeps admitting what the supporting relays still hold. The decision 1
   budget applies unchanged: the obligation parks after three completed attempts in a row
   that admit nothing new and certify nothing, and an attempt that admits a batch resets
   that streak. It neither waits indefinitely nor completes vacuously. Nothing
   closes a parked scope without qualified coverage and durable admission. EOSE from an
   unfloored replay is not enough, because the SDK can suppress an event it saw but the
   account never admitted, and an unreachable required relay proves nothing. The only
   other way out is an explicit, user-authorized retirement. It is recorded as a distinct
   outcome ("history may be incomplete"), never as coverage.
4. Both implementation steps land before the next MarmotKit release.

## Design

### 1. Overflow becomes a durable tail, not a loss

Today, when the 1,024-slot account queue is full, the router holds the whole
`TransportDelivery` (ID, payload, route) and keeps only a count. Everything else in the
current design follows from that choice: loss of unknown scope, broad replay, a completion
nobody can certify, and the wait behind the queued backlog.

New behavior, with each tier falling back to the next:

```
router ─► account queue (1,024, memory) ─► worker ingest
   │ full
   ▼
durable spill (encrypted DB, capped: 16 MiB / 8,192 events) ─► worker ingest, alternating with live
   │ full
   ▼
unknown-scope loss (today's behavior) ─► comparison obligation
```

Recording dropped IDs as a middle tier, turning them into known-event obligations for
exact-ID fetch, is deferred. The spill is sized so that tier is rarely reached, and
NIP-77 comparison covers what remains.

- The spill writer extends the already-approved off-worker loss writer. It writes spill rows
  and loss evidence only, never engine or receipt state. The hand-off from the router is a
  bounded in-memory buffer (4 MiB and 4,096 deliveries), so the router never blocks.
- A delivery the account has already seen, and whose receipt was not released for
  redelivery, is discarded before it uses spill capacity. Replaying history the device
  already holds therefore fills neither the spill nor the network.
- A delivery that misses the hand-off or spill limits becomes queue loss, as today: the
  cursor stays fenced until recovery settles that loss, and live input keeps flowing.
- The cursor fence stays up while a hand-off is in flight or queue loss is pending. It
  releases when that hand-off settles as already seen, when its spill write is durable, or
  when recovery settles the pending loss. Deliveries already in hand keep flowing, because
  the fence is on the subscription cursor.
- While spilled rows remain, the worker alternates them with live deliveries, and yields
  between them, so neither a busy live queue nor a large spill starves the other. Order is
  not guaranteed; the engine already handles reordered input (deferral and retained input).
- A row is removed only once its event is in the seen index. A row whose ingest left no
  durable trace is retried with a doubling delay, from one minute up to an hour. After 8
  attempts it is removed and recorded as queue loss in the same transaction, so recovery
  keeps an obligation.
- In the incident, overflow came from replaying history the device already had. Under this
  design those deliveries are discarded before they become spill rows, so the incident
  creates no spill rows and no recovery fetch.

### 2. Recovery never touches live subscriptions

Recovery stops calling `require_fresh_activation`, `activate_transport(since)` and the
group re-subscribe. Live subscriptions follow the cursor and change only on route changes
or reconnects, both owned by the relay plane. Broad unfloored replay is removed from
automatic recovery.

### 3. One execution path for every cause

| Cause | Source of work |
| --- | --- |
| Released receipts | Known event IDs |
| Spill overflow, SDK notification loss, epoch gap, cold-start incremental history, explicit repair | NIP-77 comparison of the affected routes over the retained-inventory window (explicit repair may use a wider window) |

Every cause runs the same job:

1. **Select and freeze** (worker, short turn). The owner picks due obligations and coalesces
   those with compatible routes and window. It freezes the plan (routes, required relays,
   window, revisions) and reserves the retry cost before any I/O. This part exists today.
2. **Acquire** (off the worker, holding one of the two process-wide credits).
   Request-local NIP-77 comparison plus bounded exact-ID fetch, reusing #2031/#2037. The
   task returns an owned batch plus a per-relay outcome: complete, truncated, failed or
   unsupported.
3. **Admit** (worker, bounded turns). A few events per turn go straight into the normal
   ingest path, never through the live queue. The worker yields between turns, so commands
   and live input interleave. A turn admits at most four events.
4. **Settle** (worker, short turn). Checkpoint, then complete, retry or park according to
   the tier rules, using the existing revision checks. Old attempts still cannot clear newer
   demand.

The worker never awaits the network. There is one recovery job per account.

After step 2 the inline executor remains for maintenance boundaries, explicit repair,
known-event demand and routes with more than four relays. It activates transport floored at
the cursor, compares on the worker, and feeds what it fetched back through the live queue.
The startup grant activates the session's first live subscriptions before its off-worker
comparison.

Rules kept from the current design: complete coverage with a still-stuck engine means no
replay; the blocked reason is recorded; the existing one-shot wedge report still escalates
after three distinct local observations and starts no acquisition. That report is separate
from decision 1's budget, which parks an obligation after three completed attempts in a
row that admit nothing new and certify nothing.

NIP-77 cost scales with the difference, not the set size, so comparing the whole retained
window is cheap once we are caught up.

### 4. Parked history is a notice the user can dismiss

Decided with Jeff: parked history is shown to the user as "history may be incomplete",
and the user can dismiss a particular occurrence durably. That dismissal is decision 3's
explicit user-authorized retirement, recorded as its own outcome, never as coverage.

- Every pending obligation parked for deep repair is one notice. Its id encodes the
  obligation and its revision, so new evidence that re-arms the obligation removes the
  notice, and a later parking is a new notice with a new id. The notice carries the cause,
  the group for group-scoped demand, and when it parked.
- A group's own occurrences (today an epoch gap) also show in its recovery status.
  Account-wide ones, such as delivery loss and incremental or explicit history, appear only
  in the account's list. One account event announces any change to the list.
- Dismissal runs on the account worker. In one transaction, and only while that exact
  revision is still parked, it marks the obligation retired and, for loss, gives every
  evidence generation of that cause a retired watermark. Evidence not yet imported is
  newer loss and makes the dismissal stale. Retired evidence bounds no goal and never
  counts as coverage.
- When no loss obligation remains pending, dismissal also releases the cursor fence, with
  the plane's exact-generation guard and without counting a recovery success. A later
  observation of the same retired loss releases it too, rather than raising it again.
- New demand for the same key reopens a retired row as fresh debt: new loss or a count
  above the watermark, a higher missing epoch, a new explicit repair, or a later startup's
  incremental comparison.
- A dismissed incremental-history notice stays dismissed while nothing changes (decided with
  Jeff, 2026-09-28). Dismissal records the routes and required relays it could not certify.
  Each later startup still runs its comparison, which fetches what it finds, but when it
  parks on none but those routes and relays it retires again without a new notice. A route
  stuck on relays the user never dismissed raises a new one. Loss keeps its own notices.

## What gets deleted

Deleted in step 2:

- The per-trigger offload rules in `client/sync/comparison_job.rs`, the online epoch-gap
  job and the test-only bounded exact-ID path. That file is now the one comparison job for
  every automatic cause.
- Activation and broad replay in automatic recovery. Only explicit repair widens.
- Conservative mode (`RecoveryExecutorMode`). It was internal to `marmot-app` and not in the
  bindings.
- The recovery job slots, replaced by one comparison job and one admission loop.
- The 22 recovery notes, replaced by this one. The bounded-acquisition interface contract
  stays in its own document.

Still to delete:

- The inline executor inside `execute_recovery_grant` that the causes above still use: its
  activation, drain-based completion (`DrainVerdict` mapping), `recover_delivery_overflow*`,
  and the `queue_reconciled_event` → `handle_reconciled_event` path back into the live
  queue.
- Most of the 16 real-relay qualification test files. They are replaced by the tests below.

Each PR reports exact before/after line counts. The goal is a large net reduction across
the recovery modules, not a rewrite that adds a second system alongside the current one.

## Kept

- The durable owner, obligations, retry pacing across restarts, and revision checks
  (simplified where they become unnecessary).
- The process credit pool.
- Serialized admission on the worker.
- Per-account SDK clients (#2009) and directory isolation (#2005).
- Worker-startup isolation (#1999).
- Epoch-stall detector facts.
- Post-join maintenance subscriptions. These are unchanged here and revisited later: they
  are also a full-history request.
- The #1946 rule that recovery debt is never evicted. Spill rows are capped; unresolved loss
  is not. Every unresolved loss generation and every parked obligation stays, with no fixed
  row cap, until qualified completion (an explicit deep repair counts only when it achieves
  that coverage) or an explicit user-authorized retirement, which is recorded as "history
  may be incomplete" rather than as coverage.
  [runtime-state-bounds.md](../runtime-state-bounds.md) records the no-cap rule and both
  endings: qualified completion, and the retirement in design section 4. A cap on that
  debt would need its own reviewed retirement rule.

## Storage

- Forward-only migration 0096 adds the spill table: event ID unique, payload, metadata
  blob with a format version, size, retry attempts and retry time.
- Step 2 adds a nullable earliest-`created_at` bound to `account_delivery_loss_evidence`,
  kept as a running minimum with the count. A charge with no known `created_at`, such as an
  undecodable row, sets the generation's bound to unknown for good, so it cannot keep an
  earlier minimum. Count-only rows written before step 2 are unknown too, so their goals
  stay unbounded. A notification-lag row charges its lag's REQ floor the same way, under a
  fresh token per lag.
- Existing pending QueueLoss, notification-loss, epoch-gap, incremental and explicit rows
  run on the new path as unknown-scope comparisons.
- Tables that no code reads any more are dropped in a later migration, once their rows have
  been converted.

## Tests

- **Deterministic:**
  - spill caps and degradation;
  - cursor safety while spill writes are pending;
  - reordered admission, for example a spilled commit followed by live messages;
  - completion tiers and parking;
  - revision checks.
- **Real-relay, a handful:**
  - overflow of known history, which must produce zero network requests;
  - a missing commit fetched through comparison on two relays;
  - status, send and live delivery while a network request is held;
  - restart mid-recovery.
- **Scorecard:** nightly, production policy, measuring the table above. It tracks bytes by
  kind (novel, duplicate, control), attempts, and time to useful progress.
- **CI policy:** no reruns to get green. A flaky test gets a root cause.

## Delivery

| Step | Contents | Status |
| --- | --- | --- |
| 0 | Restore the production-policy nightly (#2064); close #2060; slim the docs to this file; add a scorecard harness with a baseline | Done (#2063, #2064, #2069) |
| 1 | Durable spill of queue overflow, admitted through the live ingest path (#2065) | Merged |
| 2 | One execution path for every cause, removal of activation and broad replay, tier completion, parking and status, deletions | In review (#2068). The fix for the notification-lag issue (#2070) follows in a PR stacked on it. The inline executor for maintenance, explicit repair, known events and routes over four relays remains. |

## Risks and open items

- Spill write latency under a burst, and cursor safety while writes are pending (covered by
  tests).
- Truncated comparisons. The whitenoise relays' own match-set cap is 5,000,000, so the
  adapter's request limit is the binding one. `NostrReconciliationSummary` names each
  failed relay but has no truncation outcome. The adapter therefore
  asks for one item more than the inventory cap (16,385). It reconstructs each endpoint's
  relay-side set size from the SDK sync summary: local items in the window, minus the
  local-only IDs, plus the remote-only IDs. The remote difference alone is not that set.
  An endpoint whose set fills the limit may be truncated, so it counts as failed and cannot
  certify the route. A set of at most 16,384 is complete, including a busy route that sits
  exactly on the cap, and can certify it. A per-relay truncation flag from the fork would
  replace this inference.
- Notification-lag bounds (#2070). Two kinds of REQ still carry no `since`: post-join
  maintenance, and a group's retained prior routes. Once either has been issued, every
  later lag on that account's SDK context has unbounded loss and its goal parks, until the
  context is replaced. A closed REQ's floor keeps counting for the context's life, so the
  floor only falls: every lag compares from the lowest `since` the context ever issued.
  The inbox's two-day NIP-59 widening sets that floor at least two days back on every
  route; per-route floors would need per-scope storage. An EOSE lost in a lag is not
  recovered, so the next activation re-subscribes instead of reusing the live one. Relays
  that ignore `since` are not detected.
- Recovery audit event meanings change. The audit-v5 agents pick this up after step 2.
- NSE behavior needs device validation. The spill makes short extension runs safer, because
  nothing is lost if one ends mid-drain.
