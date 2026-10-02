---
title: Account history recovery
updated: 2026-10-01
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
     with a deep outbound backlog keeps sending them. Post-join maintenance and retained
     routes carry floors (design section 5), so only an unfloored REQ, such as a hidden
     group's route replaced while the group was hidden, makes the charge unknown, and every
     later charge on that context with it. A lag keeps the account route open and forces
     no reconnect. The SDK client has already marked the lost events seen, so only
     comparison and exact-ID acquisition recover them.
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
     A route-policy change (a group created or left, a relay added to one route) is not new
     evidence: it rebuilds the pending scopes, but a route whose own window and required
     relays are unchanged keeps its count and its certificates. Only changed and new routes
     start over, so creating a group does not reset every route's progress (mdk#2110).
     It shows "history may be incomplete" and offers an explicit deep repair, which can
     still complete it with qualified coverage, or an explicit retirement. There are no
     further automatic retries.
   - Comparisons whose required relays failed or timed out do not count toward the quiet
     budget. A request that ran and was answered by at least one of the scope's required
     relays spends a separate budget: after 6 such unserved comparisons for an unchanged
     goal and required relays, the scope counts as exhausted too (mdk#2110). Six is where
     retry pacing reaches its cap. A quiet comparison starts this count over. Offline
     passes, local deadline cuts, unsupported backends and refused admission count nothing.
     A relay that answered but could not hand over a claimed event, or whose events were
     not durably admitted, still answered and can spend the quiet budget.
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
- A delivery that a restart would no longer fetch only because a live ingest promoted the
  cursor goes to the spill even when the queue has room (design section 6).
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
recovery, explicit repair included. Explicit callers reuse the live subscriptions too:
only startup, a frozen wake or a client with no activation yet installs them, and a route
change refreshes them.

### 3. One execution path for every cause

| Cause | Source of work |
| --- | --- |
| Released receipts | Known event IDs |
| Spill overflow, SDK notification loss, epoch gap, cold-start incremental history, explicit repair | NIP-77 comparison of the affected routes over the retained-inventory window. Explicit repair compares every route in one pass |

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

**The epoch waits for known history (mdk#2086).** A pass fetches at most 16 events per
relay, chosen by event id, not time. So a large backlog can deliver every commit before
some older messages. If the group applied those commits, it would move more than the
retained-epoch window (5) past those messages, which could then never be decrypted. Two
steps prevent this:

- Before admitting a pass's batch, the job holds the group's epoch if the route still has
  remote-only events the pass did not return (`unreturned_items`). The hold is a durable
  per-group row that the engine reads at convergence, next to the deferred-peel barrier.
  While it is in place, commits buffer and every send queues, local commits included.
  Such a pass also does not certify the route, even when only a best-effort relay named
  the missing events, so settlement cannot satisfy the obligation while named history is
  still undownloaded. Once a route holds its group, a later pass with any failed relay
  does not certify it either: the silent relay may be the one that named the history.
- The hold ends at the checkpoint of a pass whose comparison certified the route, left no
  remote-only event unreturned, and durably admitted its batch. A relay that failed
  negotiation or truncated its set names nothing, so such a pass keeps the hold. It also ends at any settlement or account open that finds no runnable
  obligation scope still owing the route. That covers recovery giving up on the route,
  which already raises its "history may be incomplete" notice. Releasing reschedules the
  group's convergence.

Passes that fetch something count as progress. So the hold lasts as long as the download
of the backlog, and a stuck download parks after the usual quiet or unserved passes.

The worker loop never awaits the network. There is one recovery job per account, and
every cause and every caller runs it:

- A post-join maintenance grant installs only its own REQ when its job begins, under the
  grant's scope tokens, and completes on that REQ's end of stored events. Its scopes are
  not compared.
- Known-event demand compares its route and completes once that exact event is durably
  retained.
- A startup or explicit-sync comparison request records its routes as incremental-history
  debt, and each comparison pass compares that debt, never the live routing snapshot. A
  selected obligation contributes the scopes its grant installs, which follow the current
  relays and keep their windows, including routes discovered after the request, such as a
  group joined from a Welcome during startup. Otherwise the pass uses the stored scopes. So
  a comparison queries exactly the relays its settlement certifies, and a route, window or
  relay that changed after the request cannot make the plan invalid. Certifying that debt
  settles the request with it.
- A route compares all of its relays in one request, each under its own deadline, however
  many relays it lists.
- A runtime catch-up (host `catch_up_accounts` and the post-mutation catch-ups) only drains
  the live queue, like a delivery. It joins no comparison, takes no credit and runs no job,
  so it crosses a worker-owned job instead of holding sends and conversation opens behind
  it; the owner's paced job serves the debt (mdk#2110).
- `sync()` and a directly owned client's `next_event()` have no worker to run that job.
  They drain the live queue first, so the frozen inventory holds what the live
  subscriptions delivered. With debt a grant could select, they then wait for a credit,
  drain once more and run one job in place, holding the credit through admission and
  checkpoint; without it they take no credit. Startup runs its job only when a credit is
  free. Without a credit nothing is selected, so no reservation is spent.
- Explicit repair runs the job in place too. Its one pass compares every route of the grant
  inside the first 50 seconds of its 60-second budget. At that network deadline a route
  still comparing times out and the routes that finished come back; their events are
  admitted and checkpointed in the last 10 seconds, stopping at a turn boundary if the whole
  budget runs out. That budget starts once the repair holds its credit; the credit wait has
  its own. The verdict prefers the certified window over the clock: cancellation is
  `Cancelled` and admission cut at the whole budget is `Deadline`; otherwise a certified
  window is `BelowRetentionWindow` and closes, an uncertified pass the cutoff cut is
  `Deadline`, and anything else is `CoverageUnproven`. Only cancellation, polled every 50 ms,
  discards a pass in flight; it also stops admission at a turn boundary, keeping the
  admitted prefix. Explicit history has no lower bound, so no window certifies it: a pass whose
  every route's window certified returns `BelowRetentionWindow`, naming the unsearched older
  history, and closes its request (decided with Jeff, 2026-09-28): no explicit-history debt
  remains to park into a notice, and nothing is recorded as coverage. An uncertified,
  cancelled or expired pass keeps the debt open for the owner's ordinary retries. Each
  explicit scope whose window a comparison certified keeps that fact for its goal and is
  never counted as quiet, so the owner's four-route passes accumulate it across slices; the
  checkpoint that finds every scope certified closes the request, whichever pass it is.

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
  notice, and a later parking is a new notice with a new id. A route change is not new
  evidence: it re-checks a parked obligation without changing its revision, so the notice
  leaves while the new routes are compared and returns with the same id if the obligation
  parks again. The notice carries the cause, the group for group-scoped demand, and when
  it parked.
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

### 5. History REQs are floored at their anchors

Decided with Jeff (2026-09-28). The two REQs that asked for full history now carry a
`since`, so their floors bound a notification lag like every other REQ's.

- **Post-join maintenance** is floored at the creation of the Welcome that installed the
  copy (`Group::local_copy_welcome_created_at`, the Welcome rumor's `created_at`, which the
  engine clamps to no later than the join), less the allowance. It is never floored at the
  local join time: a member that was offline processes an old Welcome, and still needs the
  commits made between that Welcome and its join. Anything older belongs to epochs before
  the member's own, which it cannot open.
- **A retained route** is floored at the moment this device saw it replaced as the group's
  current route, less the allowance, and never later than the activation's own `since`.
  The switch time is recorded inside the route JSON (`replaced_at`), so no migration is
  needed. The routing table keeps each group's current route first, which is how the
  adapter tells the two apart. A live REQ is reissued only to widen it, never to narrow it:
  a reissue replaces the live REQ under the same id and could cut off history it is still
  returning.
- **A retained route stored before switch times were kept** (decided with Jeff,
  2026-09-28) is stamped with the time of the first load that finds it after the upgrade,
  and the stamp is written to `prior_nostr_routes_json` straight away, so later loads and
  restarts keep it instead of moving the floor forward with each launch. Its older traffic
  was fetched by the sessions that ran before the upgrade, and the comparison covers the
  rest of the retained window.
- **The allowance** is `HISTORY_FLOOR_CLOCK_SKEW_ALLOWANCE`, fifteen minutes (ledger A14;
  widened from five with Jeff, 2026-09-28). An event carries its sender's clock, while the
  anchor carries the inviter's or this device's. The two directions cost differently. Too
  small an allowance can miss a commit made after the Welcome, and the member's first
  self-update then forks until the epoch gap is acquired. Too large only re-requests
  history the member cannot open or already holds: once per join, and on every activation
  for a retained route. So it leans wide. Fifteen minutes is the future-dated-event limit
  relays commonly enforce, so an inviter whose Add commit a relay accepted cannot run fast
  enough to put the floor after the commits that followed it. It also tolerates committers
  three times further behind than the stack's five-minute sender tolerance (A8). Anything a
  floor still misses inside the retained-inventory window stays within reach of the
  comparison, which covers current and retained routes alike.
- **Still unfloored**: a copy with no Welcome time (created before the field existed), and
  a locally deleted group's routes that no projection has seen replaced: those stored in
  its frontier before this change, and one replaced while the group was hidden. They are
  backfilled in full while the group stays hidden, and stamped at the first account load
  after it is restored. Explicit full-history repair issues no REQ: it compares the
  retained-inventory window (section 3).

### 6. The cursor follows live ingest

A restart re-subscribes 120 seconds below the persisted cursor (the rebuild lookback,
ledger A7, which stays). The cursor used to advance only at a drain checkpoint or when loss
settled, so an account served by live deliveries re-downloaded everything it had received
since its last drain. On the #2069 scorecard that was about 11,474 held-history frames per
relay, and three notification lags during the replay.

A live ingest's own save now promotes the cursor to what the account ingested, when:

- every account subscription reported end-of-stored-events (relays replay newest-first, so
  promoting mid-replay would put the rest of the replay below the new floor);
- no loss or spill hand-off is pending, as for any other checkpoint;
- the cursor advances (not a frozen wake pass) and restarts rebuild from it;
- the account has a settled floor (below). An account that has never persisted a cursor
  waits for its first drain checkpoint, as before. It holds no history a restart would
  re-download, and promoting first would spill every older arrival until that
  checkpoint, such as the whole history of each group it joins.

The rule it keeps: the account queue never holds a delivery that a restart would no longer
fetch only because a live ingest promoted the cursor, or because a cursor commit was saving
when it arrived. A delivery's key is the lowest restart `since` that still fetches it: its
`created_at`, or for an inbox wrap its `created_at` plus the two-day NIP-59 widening the
inbox REQ adds. Two mechanisms keep the rule, and both run under the lock the router
already holds when it places a delivery in the queue, the spill or loss:

- **The seal.** Every cursor commit decides its value there, at one point just before its
  save. It keeps the persisted cursor while loss or a hand-off is pending. Otherwise it is
  capped at the lowest key the persisted cursor still covers of a delivery that is queued,
  or taken and not yet durably ingested, plus the lookback. Nothing it relies on can go
  stale before the decision, which is what broke the first attempt: it read an empty
  queue, then awaited the EOSE read and the save while the router could queue an older
  delivery.
- **The raised floor.** Every seal raises the restart floor before its save. From then on
  the router sends a delivery whose key falls between the settled floor and that floor to
  the durable spill instead of the queue, or to queue loss bounded by its `created_at`
  when the spill cannot take it. The settled floor is what drain checkpoints, settled loss
  and the cursor the account opened with made durable. A drain checkpoint, settled loss or
  retired notice raises it to what it reached once its save succeeds, so it spills only
  what arrives while it saves. A live promotion leaves it, so what only the promotion
  exposed keeps going to the spill. A delivery below the settled floor is exposed exactly
  as before live promotion existed, and one above the raised floor is still fetched.
  Before an account's first settled floor there is nothing below: a restart without a
  cursor relied on its comparison, not the cursor, for everything, so the first raised
  floor spills every older arrival, however old. A delivery queued before that first seal
  caps it like any other.

So a delivery that arrives during the EOSE read caps the promotion, and one that arrives
while any commit saves is spilled. A settled commit raises the settled floor only to what
it reached itself, never to a cursor an earlier live promotion left persisted, so a fenced
drain checkpoint cannot stop the spilling that promotion needs. It stops spilling once its
save is durable: an older delivery that arrives later is queued, as it always was, because
spilling every later arrival below a drain's floor would push the rest of a replay into the
spill, and a repair drain reads only the queue. A failed save of either kind lowers the
floor again. A replaced adapter cannot promote: the queue it drains is not the one the
router tracks.

Taking a delivery from the queue does not end its cap. Its consumer releases it once the
ingest is durable, or when it drops it on purpose (an event the account already holds, or
input the account keeps no trace of by design), and always before the save that follows, so
a committed delivery never holds the cursor back. A failed ingest never releases it. Relays
replay newest-first, so a catch-up drain or startup receive has usually remembered a newer
cursor when an older delivery fails, and the checkpoint that failure runs would otherwise
persist a cursor a restart no longer fetches the failed delivery from, as it did before
live promotion existed. Kept, the key caps that checkpoint and every later commit until a
redelivery of the same event is released or the queue generation ends, so a restart, or the
next generation's subscriptions, start from a cursor no commit moved past it. A resource
refusal releases like any other completed ingest: as before, it holds back only its own
timestamp, and its epoch-stall backfill owns the re-fetch.

One window stays open. A spilled delivery is volatile until its spill write commits, which
is usually right after the save it arrived during, because both use the account database.
No design with a router that never blocks can close it: a delivery can arrive at the
instant a raised cursor commits, and making it durable takes its own write. It is the same
hand-off window the overflow tier has. The fence holds every later commit until the write
settles, and the startup comparison over the retained window still finds what a stop there
would lose.

## What gets deleted

Deleted in step 2:

- The per-trigger offload rules in `client/sync/comparison_job.rs`, the online epoch-gap
  job and the test-only bounded exact-ID path. That file is now the one comparison job for
  every automatic cause.
- Activation and broad replay in automatic recovery. Explicit repair kept its replay until
  the inline executor retired.
- Conservative mode (`RecoveryExecutorMode`). It was internal to `marmot-app` and not in the
  bindings.
- The recovery job slots, replaced by one comparison job and one admission loop.
- The 22 recovery notes, replaced by this one. The bounded-acquisition interface contract
  stays in its own document.

Deleted when the inline executor retired, after step 2:

- The inline executor, `execute_recovery_grant`, with its activation, drain-based
  completion (`DrainVerdict`, the EOSE gate and drain state), `recover_delivery_overflow*`,
  the explicit repair drain and the `queue_reconciled_event` path back into the live queue.
- The drain budgets `EPOCH_BACKFILL_EOSE_WAIT` and `EPOCH_BACKFILL_EXECUTION_QUANTUM`, their
  `dev_epoch_backfill_eose_wait_ms` and `dev_epoch_backfill_execution_quantum_ms`
  overrides, and `MAX_COMPARISON_ENDPOINTS_PER_ROUTE`.
- The inline fallback when no credit is free, the per-cause offload checks, explicit
  catch-up's re-activation, and explicit repair's unfloored replay.

Still to delete:

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
- Post-join maintenance subscriptions, now floored at the Welcome that installed the copy
  less a fifteen-minute clock-skew allowance (design section 5), rather than a
  full-history request. A maintenance grant's job installs them, and they still complete
  on EOSE, not on comparison.
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
- The history floors need no migration. The Welcome time was already on the engine's group
  record, and a retained route's `replaced_at` is an optional field inside the existing
  route JSON (`prior_nostr_routes_json`, also in the local-deletion frontier). The first
  account load after the upgrade stamps each retained route in `account_groups` that has
  none, and persists the stamp in the same step
  (`stamp_unrecorded_prior_route_switches`).
- Migration 0102 adds `cgka_history_acquisition_holds`: one row per held group with the
  route that holds it, removed with the group (mdk#2086).
- Tables that no code reads any more are dropped in a later migration, once their rows have
  been converted.

## Tests

- **Deterministic:**
  - spill caps and degradation;
  - cursor safety while spill writes are pending;
  - reordered admission, for example a spilled commit followed by live messages;
  - completion tiers and parking;
  - revision checks;
  - history floors: maintenance and retained-route REQs carry their anchored floors, a
    retained route stored before switch times were kept is stamped once at its first
    load, a live retained REQ is only ever widened, and a lag while either is live stays
    bounded.
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
| 2 | One execution path for every cause, removal of activation and broad replay, tier completion, parking and status, deletions | Merged (#2068), with the notification-lag fix (#2070, #2074). History floors (#2077, design section 5) and live cursor promotion (#2075, design section 6) merged. |
| 2, follow-up | Retire the inline executor: maintenance boundaries, explicit repair, known events, routes over four relays and explicit callers run the one job | In review (#2079) |

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
- Notification-lag bounds (#2070). Post-join maintenance and retained prior routes now
  carry floors (design section 5). A REQ still without one, listed there, leaves every
  later lag on that account's SDK context unbounded until the context is replaced, and
  its goal parks. A closed REQ's floor keeps counting for the context's life, so the
  floor only falls: every lag compares from the lowest `since` the context ever issued.
  The floors trade a fifteen-minute clock-skew allowance against a missed commit: a sender
  clock off by more than that, a retained route observed long after its switch, or one
  stamped at its first load after the upgrade, can put traffic below a floor, and only the
  comparison, or the epoch gap it causes, recovers it.
  An old Welcome can floor maintenance below the retained-inventory window, and a goal
  there cannot certify. The inbox's two-day NIP-59 widening sets that floor at least two
  days back on every route; per-route floors would need per-scope storage. Relays that
  ignore `since` are not detected.
- End-of-stored-events lost in a notification lag (#2070). A lag cannot tell a lost EOSE
  from one still coming, so it marks none complete. Once the receiver has gone 30 seconds
  without another lag, each REQ issued before the lag that the adapter still sees awaiting
  EOSE on a relay is repaired there. The SDK records each REQ's EOSE in its relay read
  loop, before it sends the notification, so a lag cannot drop it
  (`Relay::subscription_received_eose`). When it has one, the lag lost only the
  notification: the adapter records that EOSE with no network traffic. Every repair reads
  that record for every such relay, including one an earlier repair re-issued the REQ to,
  so a re-issued replay whose fresh EOSE a later lag lost still completes. Otherwise the REQ's CLOSE and the REQ again, unchanged and under its own id, are
  queued in one all-or-nothing batch (`Relay::batch_msg`) to a connected relay. The CLOSE
  goes first, so no relay sees a repeated live id, which a relay could refuse instead of
  replacing the subscription, and the SDK's registry keeps the REQ it restores on
  reconnect. The relay replays from the same `since` and answers with a fresh EOSE, so
  activation reuse returns, live cursor promotion resumes, quiet drains end early again,
  and post-join maintenance observes its boundary. The loss floor does not move. A batch stranded by a disconnect
  goes out once: the SDK's reconnect skips a REQ already queued. Only the network re-issue
  is limited: a relay gets the REQ again at most once, so a replay that keeps lagging
  cannot loop. A relay that got
  nothing, because it was not connected or had no room for both frames, still has the old
  REQ live; its claim is released and the repair runs again after the settle window for
  the same lag, until its EOSE is recorded or the REQ goes out. One known behaviour: an
  EOSE for the old REQ still in flight on the same connection sets the SDK's flag for the
  re-issued one. That is harmless here, because the filters are identical, so it answers
  for the same stored events. What remains: a replay still running 30 seconds after the
  last lag restarts once; a group route removed before its EOSE keeps the activation's
  frozen coverage incomplete; and a relay that stays unreachable is retried once per
  settle window.
- Live cursor promotion (design section 6). A delivery the raised floor sends to the spill
  is volatile until its spill write commits; a stop in that window loses it until the
  startup comparison. Routing is by content, so the router cannot tell an unfloored
  maintenance or prior-route replay from a floored REQ: such a replay's events above the
  settled floor go to the spill too, which costs spill writes (seen events are discarded
  before they use capacity) but loses nothing. EOSE covers the activation's snapshot, not a
  group added since, so a new group's replay may still be arriving when a promotion seals;
  what falls below the floor is spilled, not lost. A drain checkpoint spills only what
  arrives while it saves; an older delivery that arrives after it is queued below its floor,
  exposed to a stop as it always was.
- Explicit repair compares the retained window only. A goal with no lower bound, or one
  below the inventory floor, cannot be certified by it, so explicit repair never reports
  complete, and it no longer fetches history older than the window: the unfloored replay
  it replaced fetched that history but never certified it. A certified window closes the
  request instead of parking it, so history older than the window is simply not searched.
  Each pass also fetches at most 16 missing events per relay. A wider window needs
  acquisition below the inventory floor.
- Explicit catch-up no longer re-subscribes, so a maintenance boundary whose EOSE a lag
  lost waits for the next activation, at reconnect or restart.
- Recovery audit. The owner records its decisions in audit v5 only: need changes, attempt
  start and finish, per-obligation reassessment, and transport-cursor advances
  ([audit-logging.md](../audit-logging.md#account-recovery-owner-rows-v5-only)). The rows sit at
  the comparison job's execution bracket and the owner's storage transitions. Each lag-lost EOSE repair pass (#2076) records its counts as `subscription_eose_repaired`.
- NSE behavior needs device validation. The spill makes short extension runs safer, because
  nothing is lost if one ends mid-drain.
