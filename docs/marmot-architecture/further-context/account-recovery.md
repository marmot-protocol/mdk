---
title: Account history recovery
updated: 2026-10-30
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
     the lowest `since` among every REQ the account's SDK context issued, live or closed,
     and each route those REQs select the lowest `since` among the ones that select it: a
     lost event matched a REQ that selects its route.
     Routing is by content, so a closed REQ's buffered or in-flight notifications still
     arrive, and nothing bounds when: a stalled consumer keeps them buffered, and a relay
     with a deep outbound backlog keeps sending them. Post-join maintenance and retained
     routes carry floors (design section 5), so only an unfloored REQ, such as a hidden
     group's route replaced while the group was hidden, makes the charge unknown, and every
     later charge on that context with it. A lag keeps the account route open and forces
     no reconnect. The SDK client has already marked the lost events seen, so only
     owner-granted original-window capture, comparison and exact-ID acquisition recover them.
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
     not durably admitted, still answered and can spend the quiet budget. An owner capture
     the cutoff cancelled, or one gone stale, is a local deadline cut too: it counts
     nothing toward a native goal's budget, though pacing still backs off.
   - As a safety net, an obligation also parks after 24 reserved attempts in a row without
     progress (mdk#2660), whatever its streaks say. Progress on any of its own scopes, or
     the obligation completing or being retired, starts the count over. A re-arm makes a
     native goal prove its sources' admission again, so only having more of its sources
     admitted at once than it ever has counts as its progress; that bounds the restarts by
     its number of sources. A native goal's re-arm for a new wire generation, a process
     open and a route-policy change keep both the count and a goal this cap parked; new
     loss or epoch evidence gets it one more attempt. Hitting the cap is logged as its own
     `park_capped_recovery` warning.
2. **The queue keeps what it drops.** Overflowed deliveries are stored durably (bytes), within
   a cap.
3. **Required relays are the relays we operate.** `MarmotDeployment::recovery_operated_relays`
   (on `MarmotAppConfig::deployment`) names them; White Noise's deployment
   (`MarmotDeployment::white_noise()`) operates `wss://relay.eu.whitenoise.chat` and
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

### 0. Native replay belongs to the account owner

`SubscriptionReplay` records the original live inbox and group query windows. It is not a loss charge.
Unresolved floors survive cancellation, source replacement and reopen; an unfloored query stays unfloored.
Completed scopes can be pruned when sources change, so they do not force permanent full-history fetches.

The adapter exposes borrowed source facts under its admission guard and a coalescing change watch. The owner
copies those facts and drops the guard before durable recovery writes. It combines a session nonce with the
process-monotonic wire generation to identify the current goal. It freezes source capabilities into the existing
comparison job and uses that job's recovery credit and cancellation.
Native capture and comparison run concurrently under that grant's cutoff. A quiet native REQ cannot consume
the whole pass before comparison starts; both remain owned until cancellation and IO cleanup finish.
A native goal's window has no upper bound, but only input created before the attempt started can reset retry
pacing, so live traffic during an attempt cannot hold the backoff at its floor.
Neither the adapter nor the relay plane selects retries or runs a quiet-period repair timer.

All native group input, including local publication fanout and post-EOSE live tails, uses the owner's ordered admission path rather than
the ordinary queue and its spill tail.
Before activation, durable group spill rows enter the native range as local supplements, including copies
the current relay no longer holds. Every in-deadline peer must finish or settle its finite lease before payload
release; one peer's EOSE cannot release newer ciphertext ahead of another peer's older history. Replacement
REQs establish their own boundaries, including equivalent or narrower repacks. An empty expired peer becomes
dormant without certifying history or inventing loss. After every transport tag's pages finish, a bounded `ReplayBatch` leases
the group's sorted frames. Ordinary ingest borrows each frame until ACK; cancellation returns its
unacknowledged suffix. Native and comparison input share one four-ingest turn and select the oldest known
frame of each group across both sources. An unfinished native range fences comparison only for that group;
independent groups, commands and inbox input still take turns. Each turn also examines at most four native
frames, including receipt skips. Source replacement or restart revokes an unstarted loan before more ciphertext
arrives; its suffix rejoins the complete range. Same-account repacks preserve held live bodies. A frame whose
ingest already committed is acknowledged even if its loan was revoked in the meantime. Retained rows are removed
only after durable admission and successful spill settlement. Backend errors remain visible to explicit callers;
automatic worker retries use the existing 1–60-second backoff and return the failed loan to the fair ready queue.

Native ingests resume the same owner-controlled `Receive` recovery follow-up as ordinary deliveries, including
undecryptable input with no visible summary. Receipt skips and cursor-save-only progress do not request this
follow-up. The receive intent is retained before ACK can suspend; it changes neither capture authority nor credit.

`ReplayAdmission` needs a complete original range placed from at least one issued current-epoch peer for
every scope, with no pending ciphertext or nondurable spill handoff. Empty silence is not notification loss.
The limited `replay_admitted` fact cannot certify retained history, retain a missing known event, satisfy a
maintenance boundary, or acknowledge real queue/notification loss. Those predicates are unchanged.
Scoped source placement is independent of unrelated pending groups, but same-group waiting peers withhold
that group's proof. Final native completion separately requires account-wide placement, including spill handoffs;
persisting a scoped proof does not release that global fence. Local publication cannot supply a relay boundary.

Passive admission spends no network retry credit. Cursor seal consults the owner's cached completion or
explicit retirement while holding the source guard through router placement locking; a changed generation
defers the seal until the owner synchronizes. No source or endpoint identifier enters audit output.
A range already queued to the owner spends no further acquisition attempts while its bytes drain.
That pending observation is not cursor permission: retry eligibility and qualified completion remain separate.

Terminal group removal or disband retires only that group's native scopes under revision checks. A wanted
range with no serving source, including a sole terminally refused REQ or a narrower replacement, parks as
`NeedsDeepRepair` with its original floor. It spends no retry credit and creates no loss evidence. The existing
incremental-history notice exposes it; dismissal records retirement, not completion. A genuinely changed source
generation can rearm the debt without narrowing its original range.

After native ACKs drain the current sources, the owner can save the admitted cursor through the existing live
promotion path. A failed save retains its target for the next admission turn. Replayed durable receipts restore
their validated transport timestamps without emitting duplicate plaintext. Ordinary drain checkpoints still
settle live-promoted floors; native promotion does not add a drain audit row for each message. Future-dated
cursors and explicit full-history policy keep the plane's unfloored query instead of substituting a recent tail.

### 1. Overflow becomes a durable tail, not a loss

Today, when the 1,024-slot account queue is full, the router holds the whole
`TransportDelivery` (ID, payload, route) and keeps only a count. Everything else in the
current design follows from that choice: loss of unknown scope, broad replay, a completion
nobody can certify, and the wait behind the queued backlog.

Native group input uses section 0. Inbox and legacy delivery use these tiers, each falling back to the next:

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
  not guaranteed on this inbox/legacy path. Native group replay never uses this alternation.
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
   unsupported. On an epoch-gap group route, each relay that failed without answering its
   comparison is searched backwards through the same window in 256-event raw pages. Each
   relay gets at most 16,384 raw events and 4 MiB of validated event JSON per pass, with at
   most three seconds within the shared pass deadline. Raw SDK counts and oldest timestamps survive
   filtering. Full pages overlap their oldest second; a short page probes the older prefix
   before admission. An empty probe returns the buffered short page without fetching it
   twice. Only a completed oldest page is admitted; cuts and saturated seconds release no
   newer suffix. Bounded advisory hints resume held spans on later passes. The fetch never
   runs ahead of older comparison backlog, and comparison/window candidates stay ordered
   oldest first. Window events never certify a route, move its replay cursor or withhold
   its certificate. Original comparison stability and SQL fences remain unchanged.
   Inventory revisions invalidate held-span hints, so released input is not skipped on reuse.
   Hints follow every pending epoch-gap ticket, including capacity-waiting tickets
   omitted from another grant's selection.
   Traversing already-held input is not recovery progress: it cannot reset backoff or the
   durable unserved-pass count. Reconstruction or hint eviction may repeat traversal but
   cannot renew that budget. A sufficiently deep prefix may exhaust it and park for explicit
   repair. This paging change does not activate an independent known-event retry tier.
3. **Admit** (worker, bounded turns). A few events per turn go straight into the normal
   ingest path, never through the live queue. The worker yields between turns, so commands
   and live input interleave. A turn admits at most four events. Each successful turn publishes
   its committed message and projection updates; consumers do not wait for the whole batch.
   Published prefixes leave the pending summary, not the pass's accounting or coverage evidence.
4. **Settle** (worker, short turn). Checkpoint, then complete, retry or park according to
   the tier rules, using the existing revision checks. Old attempts still cannot clear newer
   demand.

The worker loop never awaits the network. There is one recovery job per account, and
every cause and every caller runs it:

- A post-join maintenance grant installs only its own REQ when its job begins, under the
  grant's scope tokens, and completes on that REQ's end of stored events. Its scopes are
  not compared. The REQ serves two owners: the PostJoin self-update obligation, which
  waits for the first end of stored events, and the copy's history fetch
  (`GroupMaintenanceState::post_join_history`), which no commit or proposal ends. The
  session stays installed while either is owed, and while the fetch is owed its demand is
  the fetch's own. The fetch ends as `Fetched` once the REQ's
  boundary qualified and native ingress has placed everything the group's replay held,
  however long after the deadline that is, or as `DeadlineExpired` when an installed session
  reaches no end of stored events within the EOSE timeout of its installation. A restart installs an owed fetch again, and a
  replacement Welcome starts a new one (mdk#2626).
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

- the owner's limited native-input goal is completed or explicitly retired for the guarded source generation;
  all original ranges must be placed before admission, including backward pages and newly added group REQs;
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

### 7. Coverage ledger (shadow mode)

mdk#2660 replaces the obligations with a coverage ledger. Phase 2 adds the ledger beside
them without changing behavior. Storage keeps, per route (the inbox or a group's transport
route) and relay, the `created_at` ranges proved complete and how each was proved, plus each
route's goal floor. Debt is the goal minus what every certifying relay covers. The recorder
in `marmot-app` fills it from facts the owner already has:

| Fact | Ledger effect |
| --- | --- |
| A live REQ's endpoint admitted and placed its whole original window, and counted the stored events its relay sent before EOSE | Live boundary on every route the filter carries, from the second after the oldest event counted (never before the REQ's `since`) through the second before the REQ went out (below); a count with no event proves nothing. Written once per generation, while it is healthy (input placed, no loss or spill hand-off pending). A generation that loss may have reached proves nothing. Released seconds stay out (below). The time since the request is a provisional tail, never written (below) |
| A comparison certified a route at settlement | Comparison covers the frozen window on each relay that certifies the route, less every range un-covered after the grant was selected |
| A loss import charged a generation, including a notification lag that charges no count, or a legacy clear restored one | In the import's own transaction, a generation whose every charge named its routes un-covers only those routes, each from its own bound, and widens their goals: for queue loss, every dropped delivery the relay plane placed on a route, from the earliest `created_at` dropped there; for a notification lag on the account's own SDK context, every REQ it issued with a floor and known routes, from the lowest `since` among the REQs that select the route. Any other generation un-covers every route the ledger holds from its floor up (all of it when a floor is unknown) and widens their goals to it; the recorder then widens the other current routes' goals. A generation that touches more than 256 routes counts as one that named none. A worker that observes a generation past its durable count passes the relay plane's routes for it, merged as a marker write's are; if the plane holds none, the generation names none. After a restart the relay plane counts new drops under a fresh token, so new loss always raises a count |
| A receipt was released for replay | In the release's transaction, its event's second is un-covered on each route its inventory row placed it on, and that route's goal widens to it. A second below the retained window is owed nowhere, so that release changes nothing in the ledger: its coverage stays until pruning drops it. The REQ that delivered the event will not deliver it again, so only a comparison on a relay covers that second there again; live boundaries never cover it, until retention pruning passes it. A release with no inventory row changes nothing here; the epoch gap it arms keeps that debt |
| A pending queue or notification loss | Each scope's route goal widens to the scope's floor, restoring a goal the best-effort write lost |
| A startup incremental history request | Every current route's goal widens to its standing floor: the retained window's floor, or for a group route whose copy has a Welcome time, that time less the 15-minute allowance when it is later |
| An explicit history request | Every current route's goal widens to the retained window |
| A pending epoch gap | The group's routes' goals widen to their standing floors |
| Every settlement | Coverage and goals below the retained window are pruned. First, what any certifying relay of a current route still owes below the floor (not covered there and not retired; parked seconds count) joins that route's parked remainder |

**Standing floors.** The Welcome time is a soft signal (`Group::local_copy_welcome_created_at`):
an application message carries its sender's compose time, so one composed offline before the
Welcome and sent after it is openable here yet older than the Welcome. The standing floor
therefore only starts the goals that want history in general. It never retires, un-covers or
drops debt: loss and released receipts keep their own floors, explicit repair wants the whole
window, and goals only widen, so a later Welcome raises nothing.

**Parked remainders.** Debt the moving retention floor overtakes before anything covers it,
and loss whose floor is unknown or older than the window, is parked rather than dropped: each
route keeps one remainder, the earliest and latest such second, under a park revision from the
same counter as unit parks. It is never fetched and never coverage, and only a dismissal clears
it. A route's notice revision is the newest among its broken units' parks and its remainder, so
dismissing the notice clears both. Each prune also settles every route below its floor: a later
prune parks only from there up, because it no longer holds the coverage below. Widening a goal
back below that floor, as the shadow report does each time for pending loss, therefore parks
nothing twice and does not bring back a dismissed remainder; only loss lowers the settled floor
to its own. While the ledger is in shadow mode nothing sweeps, so most routes gather a
remainder; the switch-over drops those.

A count proves only what its relay had stored when it ran the query, so its live boundary ends
the second before the count's request stamp. The adapter takes that stamp before it issues the
REQ; for a REQ the relay pool re-sent on reconnecting, it uses the pool's record of when that
connection was made, and only when the pool's connection count shows the record belongs to a
connection the adapter saw. Either way the stamp is no later than the relay's query. The pool
marks a connection open before it counts it and records its time, so that record can be the
previous connection's, or missing; a stale stamp only ends the proof earlier.

A count also proves nothing at or before the second of the oldest event it holds. A relay may
cut its reply at a limit of its own, and the relay pool drops some frames before the adapter
counts them (expired, deleted or replaced events, bad signatures, frames it cannot parse), so
a count is only a lower bound on what the relay sent and cannot show that a reply was not cut.
The rule assumes relays cut a reply newest first, as NIP-01 asks of a `limit`: every stored
event newer than the oldest one counted was then sent. A relay that cuts any other way breaks
that assumption, and the ledger cannot see it. A count with no event proves nothing, and live
boundaries read no NIP-11 limit. An API that reported the raw frames each REQ received before
EOSE could later add back, on top of this rule, a proof from the REQ's `since` for a reply
under the relay's limit.

Past the request an open REQ vouches only while it lasts, and nothing proves when it stopped
delivering: a connection can die silently, and a frozen process notices nothing. So each
healthy generation's REQ holds a provisional tail in memory (`LiveTails`), never in the ledger.
It starts at the request stamp only when the adapter itself issued the REQ. For a REQ the
relay pool sent again (on a reconnect, or after a `CLOSED` it keeps) it starts at the second
its EOSE was recorded, since when the pool sent it is not reliably known, and the time the REQ
was down stays owed. It starts past the oldest event returned when that is newer (a reply cut
at the relay's limit may have left out what it stored after the request), and past the newest
second released on its route. Debt that drives work reads the ledger only up to the
second before a route's tail on a relay (`LiveTails::owed_until`, refreshed by
`AppClient::live_tails` on every call), and so does the shadow report.

A tail stands only on positive evidence read when it is asked for: the account's relay client
must report the relay connected, on the same connection the generation's serial started on.
The adapter records that connection when it issues the REQ, or when it sees the reconnect
that restarted it. The relay pool names a connection by its relay object and attempt count,
read on both sides of its status, so a read inside a reconnect (the pool marks the new
connection open before it counts it) names the new connection or none. A notification that a
REQ stopped can come late or never: a shutdown can cut short the disconnects it sends, a
removed account context sends none the adapter applies, and a reconnect is seen only once its
boundary is processed. None of these can leave a tail up, because the client's own state no
longer names the generation's connection. A tail lapses silently, so the runner reads tails
at every debt read and never holds them across a wait.

That evidence names a connection, not a REQ, so a tail can outlive its REQ by the time the
adapter takes to process notifications already queued for that relay. Two cases:
- The relay closes the REQ (`CLOSED`) and keeps the connection open.
- The adapter processes a reconnect's boundary after the next connection has opened. The
  restarted serial is then bound to that newer connection until the earlier connection's
  disconnect is processed.

This delay is accepted, and bounded:
- A notification forwarder that falls behind records notification loss, and loss breaks
  the tail (below).
- A tail is never written to the ledger and never marks a second proved. A late lapse only
  delays a sweep.

Closing the delay needs evidence from the end of that ordered path, not one stage of it. The
deferred design is a periodic probe REQ on each connection: its EOSE reaches the adapter after
anything the relay sent before it, so it confirms a tail only up to the second the probe was
sent. Build it with the runner if the runner shows the delay matters.

When the generation ends (the relay closes the REQ or leaves `Connected`, or the client no
longer reports its connection) or breaks, its tail goes, and
the time since its request is owed until a later EOSE or a fetch proves it. A `CLOSED` the
relay pool keeps to send again (AUTH, a rate limit) ends the tail only until the restored
REQ's EOSE, which counts only its own reply and starts a tail there.

A restart or relay rebuild drops every tail, and its new REQs start at the transport cursor
less the rebuild lookback, which a healthy generation keeps raising past its request. The new
generation proves only from its `since` or past the oldest event it counted, whichever is
later, so the seconds from a route's last durable proof to that start stay owed, inside the
retained window startup history already owes, until the runner's sweep proves them. A busy
route's count reaches back near its `since`, so it owes little more than the time between its
last request and that `since`; a quiet route's count holds nothing, so it owes everything from
its last proof through the new request. The REQs do not reach back to the last proof instead:
a quiet route would still prove nothing, a busy filter would return up to the relay's limit
and prove only above its oldest event, and a multi-group filter would reach back to its
stalest route.

The recorder knows a generation loss may have reached by the un-cover log (below): it reads
the log's generation before each look at the adapter's REQs, so a REQ generation one look did
not see began after that look's mark, and any loss imported after it, other than a released
second, breaks every generation it could have reached (all of them while loss is account-wide).
It reads the log again after the look, so loss imported while it looked also ends the tails of
the generations it saw. It also looks at the adapter again after the write, and a generation the
adapter ended meanwhile (a `CLOSED` or reconnect it processed) gets no tail. The first mark is read when the client opens; the relay plane's shared adapter can still report
REQs an earlier session of the account opened, and those never prove for the new session.

Every un-cover is also appended to an un-cover log under a new account-wide generation. A
grant reads that generation when it is selected, before anything is frozen or fetched, and its
certificates leave out every range un-covered on their routes since, so a loss or release that
lands mid-pass keeps its debt while the rest of the window stays proved. The log keeps an hour
and at most 4,096 rows; a pass from before the oldest pruned row records nothing.

At settlement the recorder compares the ledger with every pending obligation's scopes and logs
aggregate counts: scopes owed or proved by both, scopes the obligation still owes that the
ledger proved (ledger ahead), scopes the obligation proved that the ledger has not (ledger
behind), and current routes with ledger debt that no pending scope covers. A scope holds proof
only as completion would count it once loss invalidates by route: its predicate over
checkpoints captured at the account's current route and inventory revisions and the
obligation's own revision. Each loss import stamps the generations it charged with the loss
revision it left, so a checkpoint from before newer loss stops counting only where loss
imported after its revision, retired since or not, may have lost an event on the scope's route
at or before the scope's end. Acknowledgment deletes the evidence that says where loss reached
and keeps only the highest stamp it deleted, so a scope that would hold but has newer loss
acknowledged since is not comparable until a pass captures it again. A loss obligation owes every route, so its scope on a route its loss never reached
at or before the scope's end is not comparable, and the report restores a loss goal only on
the routes the loss reached, from where it reached each. A scope whose
floor is unknown or older than the retained window is owed from that window's floor. On each
required relay the ledger is read only up to that relay's live tail, which vouches for the
rest provisionally, as replay admission does for the obligation; unowed debt is read the same
way. Known-event and maintenance-boundary scopes are
not comparable. On the normal catch-up path (live boundaries,
a bounded loss, a certified pass) the two agree at every step.

Known disagreements, expected until later phases remove their cause:

- **Loss obligations re-owe every route they reached.** The report invalidates checkpoints by
  route and window, but a loss obligation still owes account-wide: newer loss of its own cause
  bumps its revision, so its scopes stop holding proof on every route, and it owes every
  generation it has not acknowledged, including one a pass already recovered. Its scopes on
  routes that older loss reached and the newer loss did not show as ledger ahead until a pass
  captures them again. Phase 4 deletes the global invalidation.
- **Route and inventory revisions.** A route-policy change or a released inventory journal
  bumps an account-wide revision, so pending scopes stop holding proof until the next pass
  captures it again. The ledger keeps per-relay coverage, so a covered window is ledger ahead
  meanwhile.
- **Native goals rewritten per wire generation and process start.** A new generation or session
  nonce writes a fresh `SubscriptionReplay` goal with no proof; the ledger keeps the earlier
  generation's live coverage and any comparison over the same window. Ledger ahead until the
  new generation's boundary is admitted.
- **Unbounded loss goals.** A loss with no known floor never certifies and parks; the ledger
  prunes below the retained window and the comparison owes such a scope, or one whose floor
  is older than the window, from that window's floor, so once the window is covered the
  ledger is ahead.
- **Dismissed loss.** A dismissal retires the obligation without coverage. The ledger keeps the
  debt until a comparison or the next generation's live boundary covers it, counted as unowed
  debt.
- **Tail debt after loss.** Loss breaks every live generation it may have reached, so a
  connected account that recovered from loss owes the time since that generation's request,
  as unowed debt, until a comparison proves it, or its next generation's EOSE does on a
  route busy enough to count an event older than that time.
- **Quiet windows.** A live count with no event proves nothing, so where replay admission
  settles an obligation over a window with no events, the ledger keeps it as unowed debt
  until a comparison proves it.
- **Required relays only.** A certificate is recorded for the route's required relays, and a
  scope is compared on its required relays; a scope with none is not comparable. Live
  boundaries are recorded for every endpoint that admitted one.

### 8. Retry state and staging (storage only)

Phase 4's runner keeps its retry state per (route, relay) unit in the account database, so
backoff, a broken unit's park and the account's rolling-hour budget survive a restart. Whether
a unit is caught up, owed or backing off is not stored: it follows from the unit's debt and
its next attempt time. Each quantum's outcome is one transaction:

| Outcome | Unit | Relay | Account budget |
| --- | --- | --- | --- |
| Advanced | Active, budget and backoff reset, park dropped | Streak and cooldown reset | Charged |
| Nothing owed | Re-armed as for Advanced, except that a broken unit without a probe is unchanged and a retired unit stays retired with its backoff reset | — | Refunded |
| Answered, no progress | Backoff doubles from its base; the budget's last breaks it and parks its debt. A failed probe re-parks under the same revision | Streak and cooldown reset | Charged |
| Unreachable | Retries after the unreachable delay | Streak +1; cools down after the threshold, each cooldown in a spell doubling | Charged |
| Rate-limited | — | Cools down | Charged |
| Refused | Breaks at once and parks its debt | — | Charged |
| Unanswered, local failure | — | — | Refunded |

An attempt is charged when it begins, so a process that dies mid-quantum still counts it.
A runner stopped mid-quantum while storage is open, by a reconnect or a dropped pass, refunds
the attempt as unanswered instead, unless the quantum's own settle came in time. A full
shutdown (`shutdown_and_close`) refunds the same way if storage is still open as the runner
stops, and otherwise keeps the charge until it leaves the hour. A crash keeps the charge too,
which caps a reply that crashes the process.
Newer loss over a parked span earns one probe under the same park. Newer loss inside a
retired span reopens that part whatever the unit's state: an active unit owes it as ordinary
debt, a broken one adds it to its park with one probe, and a retired one parks it under a new
revision with one probe. A failed probe re-parks under the same revision and keeps every parked
second the relay still does not cover. A relay added
to a route and a known caps read that differs from what a broken unit was planned with re-arm
it and drop its park; explicit repair re-arms every unit and drops retired spans too, so they
are owed again. An unknown caps read is never evidence. Dismissing a route's
notice checks its newest park revision and retires its broken units' parked spans, which are
never coverage; the units then serve anything else they owe with a fresh budget. Any
coverage write on a unit's relay trims its parked and retired spans; once
its last parked part is proved, a broken unit re-arms and its notice ends. The retention prune
trims parked and retired spans at its floor, as it does coverage and goals, so no span reaches
below its route's goal and a re-arm owes exactly what the window still holds.

A proven slice's unseen events go to staging, keyed by event id, in the transaction that
records its coverage through the subtracting write. A crash after that loses nothing and
refetches nothing: the events are durable and the ledger-derived cursor is past the slice.
Staging is not admission; a row leaves once its event is in the seen index, or, if it no
longer decodes, by un-covering its second so it is fetched again.

### 9. The recovery runner (behind its gate)

`client/recovery_runner.rs` is phase 4's runner: one task per account that schedules history
fetches over the ledger and the retry state above. It runs only behind the internal
`runner_owns_debt` gate, off until the switch-over turns it on, so the comparison job keeps
every behavior until then. With the gate on (`recovery_runner/host.rs`), the account worker
spawns the runner with itself, serves its turns between its other work and stops it on every
exit, a quantum in flight included. A directly owned client runs one pass in place from
`sync()` and from `next_event()` when it meets delivery loss. Sweeps go over the account's own
relay pool and dial nothing. The places that change debt or routes wake it: loss import, goal
widening, route replacement, a released receipt, a dismissal and a group lifecycle change. A
wake only makes it read the ledger again. A unit is one (route,
required relay) of a group route or the inbox; a best-effort relay gets one uncharged attempt per new debt.
One step picks a unit in a worker turn and waits off the worker for one of the process's two
recovery credits. It then begins: it reads the relay's NIP-11 caps, records known ones, reads
the live tails again, plans the unit's owed ranges from its ledger cursor, reads the un-cover
mark and charges the attempt. It sweeps those ranges oldest first under one 10 s deadline,
stages each proven slice with its coverage through that mark, and applies the outcome table
above. Progress is newly covered seconds on the unit's own relay, so live traffic, other routes
and reconnects reset nothing. Every event byte a required relay sends counts toward the
account's rolling-hour budget, including replies a budget cut short and replies a halving
discards. A quantum cut by its deadline, shutdown or a pass's budget interrupts its request in
flight instead of dropping it: the relay cancels the request, which still reports the bytes it
read, and is dropped only if it has not ended within a 1 s grace. So the reply being read when
the quantum was cut counts too, and a pass or shutdown can run up to that grace past its
deadline.

Debt subtracts the healthy live tails. They are a process-local query that every debt turn
asks again and nothing keeps across an await, since a tail can lapse with no event when its
relay disconnects. The runner reads them through the live boundary's own query
(`AppClient::live_tails`).
Units are served by class: held groups, then open conversation windows and the inbox, then the
rest, then best-effort relays. Within a class each eligible unit runs once per round, smallest
route debt first, so a large group is served every round. The runner sleeps until a bump, a
hint change, a relay reconnect or its earliest retry time. An explicit pass runs each due unit
once in place within a budget, as a directly owned client's `sync()` does behind the gate.
Its starting values are convergence-ledger decision A19.

The runner's inputs come from the account itself. A group with a conversation window open is
in the window class while the window holds its capture. A reconnect is a relay whose
connection generation in the account's relay pool moved since the runner last looked: it ends
that relay's cooldown, its caps are read again, and the survey that follows reads fresh tails.
The runner's first look only records the generations, so a connection made before it ends
nothing. A reconnect that a lag of the pool's notifications skipped still moves the
generation, and a relay that leaves the pool leaves the feed. An Unrecoverable group's routes are suspended: their debt keeps accruing, but their
units and re-checks are not scheduled, charged, broken or noticed, since a fetch would only
fill the frozen copy's deferred input. For the same reason admission gives back what the group
had staged, owed again, so it holds no staging bound, frontier or fence. With the gate on, the comparison owner also leaves their
epoch-gap obligations out of its grant, so they stay ready and are never fetched. A retained
route owes nothing past its switch plus the clock-skew allowance: members that had not applied
the switch by then still send there, and its live subscription carries that. A relay a route
replacement drops is retired as gone at the runner's next debt turn, once the routes still do
not carry it and its group is terminal or still has a route: what it owed, parked or retired
becomes a gone span that loss never reopens. A group left with no route may only be waiting to
hydrate, so that drop is forgotten. A gone relay that the routes carry again owes its whole
goal again; nothing else re-arms a unit when a route gains a relay. Pending drops are not kept
across a restart, which leaves their debt inert. The account breaker reports each pause once:
a warning, a process count, and a v5 `recovery_runner_paused` audit row with the cap, the
hour's usage and the process totals of pauses and late findings.

A unit compares instead of sweeping when its relay's recorded caps show NIP-77 and the device
already holds events in the owed range: its retained inventory and anything staged. With
nothing held a sweep is cheaper, since every id the relay names would be fetched anyway. The
comparison fetches the difference by id, oldest first, in windows that keep the relay's set
under its 16,384-item limit, and certifies a window once every id the relay holds there is
fetched or held. A quantum cut short certifies the prefix below its oldest unfetched
difference and stages the rest uncovered, so the next quantum holds it and resumes: a large
difference finishes over several quanta and nothing is fetched twice. A relay that turns out
not to support NIP-77, or refuses a comparison, is swept until it reconnects. Progress is still
newly covered seconds: a single second whose difference is larger than one quantum may fetch is
taken in parts that certify nothing until the last, so a second holding more than six quanta of
missing events (about 12,000 typical group messages) breaks its unit and parks behind the
notice, as a sweep's saturated second does. What those parts fetched stays staged.

Re-checks look for late input on history already covered or retired. Each group (route,
relay) on a required relay with NIP-77 has one resumable pass over its covered and retired
ranges inside the route's complete reconciliation inventory: the retention window, raised past
whatever the inventory compacted beyond its 16,384 ids. That is the window inside which
automatic late-publication repair is guaranteed; below it the held set is incomplete, so
nothing is re-checked there, and an epoch gap's bound below it is raised to it. Best-effort relays get none, and a relay that can only
prove by count is never re-checked. A pass falls due 6 h after the last full pass, and at once
after an epoch gap (that group, from the gap's bound), explicit repair, or a cooldown of its
relay longer than an hour. Storage makes them due in the write that ends the cooldown, and each
such request bumps the pass's revision; a quantum records its pass's progress only under the
revision it began on, so a request that arrives while one runs is never swallowed. Re-checks run
only while no debt unit is eligible. A window that
finds nothing records a re-check proof; what one finds inside a covered range is staged as
late input and counted, and a retired span it proves becomes coverage. A failed or truncated
pass un-covers nothing and resumes from its position after the unit backoff's doubling. A
re-check charges the account budget and the relay's streak like any quantum, never the unit's
own retry state. These values are decision A20.

Each step first admits from staging. A group's staged events, across its current and retained
routes, go to the recovered-ingest path oldest first by `(created_at, id)`, below the group's
admission frontier: the first second, after the live tail, that its furthest-behind required
relay still owes. A relay leaves the frontier after an answer without progress or an
unreachable or refused end, and while it cools down or is broken or retired; what it staged
ahead of the others then goes in as late input. An admission turn ingests four events, one
worker command each, so commands and live input go between them. An event the engine keeps no
trace of stays staged, and its group waits behind it on the local-failure backoff while other
groups go on. A relay that holds a group's staging bound (2,048 events or 8 MiB), or any relay
once the account holds 64 MiB, is not eligible while another relay holds that group's frontier.
A debt unit at the frontier is never held back, so the runner never waits on itself; a
re-check, which never moves the frontier, waits at the bound like any other. Nothing is fetched
for a group admission cannot drain: one held behind an event the engine kept no trace of, or
every group while admission waits after local failures. The bounds hold while admission can
drain the group; a stalled group is not swept, and the runner idles until the hold or the wait
ends. A stalled group's fence stays where it is meanwhile, since the capture debt that would
drop it is not swept. What a route the runner no longer lists staged is given back, its seconds owed again on
that route, so it never holds the account's bound.

Only capture debt fences live frames: the part `[since, oldest seen]` of a live REQ's range
that its relay's non-empty count left unproven. An empty count's range is cold-start debt,
owed and swept but never fencing, and loss, re-check and epoch-gap debt never fence either. A
group's held frames may go below the first second its fencing relays still owe in their
capture (`live_fences`), and a relay off the frontier fences nothing. Each unit keeps every
capture range it still owes (migration 0135), up to 8, so the hold survives a restart, which
forgets the counts. Past 8 the newest are joined into one, which can only fence more.
Once a capture is covered its fence drops, even while its staged events wait behind another
relay's cold-start debt; those events then follow the released frames. Fenced groups are the
runner's first class. Until the switch-over the adapter's hold keeps owner capture, and PR 5
maps the recorder's live counts into the runner's own input.

The adapter's hold (PR 5c) holds one group, and nothing enables it before the switch-over. A
count becomes a fact only once its boundary is admitted, and a boundary is admitted only once
its group's frames have left the adapter, so a fence read from facts alone would come too late.
The adapter therefore arms a provisional hold, from the REQ's `since`, at the EOSE of every
non-empty count it did not clamp, until the runner answers with a plan whose ticket saw that
count. A clamped count is paged by the adapter itself. The plan releases each group's frames
below its fence and keeps the rest held, with their claims. A hold lasts at most one replay
deadline (30 s); then its frames go in as late input, the range stays owed, and plans hold the
group no more until a new count arms it. A hold covers only what is still in the adapter's
buffer: frames already handed on, to native ingress or a draining batch, go in as late input in
the same way, and the range stays owed. Held frames count neither in the account's pending
admission nor against other groups' placement, so other groups' boundaries, tails and ingest go
on. The recorder writes no live boundary on a held route until its frames are released; its
tail still stands. Held frames stay under the replay buffer bounds, so overflow is loss, and the
relay plane's cursor seal stops at the oldest one its restart floor does not cover, since no
queue holds it yet.

The inbox (PR 5e) is a route of its own: its units compare the account's gift wraps and are
never swept, admission takes its events as a group of their own and never fences them, and
re-checks visit it as they do a group route. A relay that will not compare the inbox refuses
its unit, which breaks and parks behind a notice, and keeps comparing groups. Explicit repair,
behind the gate, is one request the account's runner owns. The runner takes it between its own
steps, with no quantum in flight, and in one turn widens every current route's goal to the
retention floor and re-arms every unit. Passes then run within the repair's 60 s while the
caller serves their turns. Cancelling, or the budget running out, stops the request: a quantum
in flight is interrupted and settles, so what it read is charged. Its verdicts are today's,
never success. `BelowRetentionWindow` once every current route has nothing staged and its
required relays' units are still active, owe nothing up to their live tails, and, on each that
compares, were re-checked since the re-arm. `Cancelled` or `Deadline` when the caller or the
budget ends it. Otherwise `CoverageUnproven` after a pass that served nothing. A route the ledger parks is one
"history may be incomplete" notice with the cause `UnprovenHistory`, whose id is a hash of the
route with its park revision; a group route's also shows in that group's status. A remainder
is a notice only once the runner has surveyed and catches up nothing on its route. A suspended
(Unrecoverable) group's routes give no notice. Each survey
publishes the required units still catching up; the account's recovery status reads that, and
a change in it or in the notices is one `RecoveryStatusChanged`. With the gate off none of this
shows.

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
- Lost end-of-stored-events (#2070, #2375, #2381). Ordered receiver gaps fence the source;
  they never infer completion from an out-of-band SDK EOSE flag or re-issue its live REQ.
  The account owner preserves original query windows and grants bounded private capture
  under its existing retry policy and process credit. Captures and delivery draining
  survive notification-worker cancellation; owner cancellation retains credit through IO
  cleanup. Empty expiry creates no loss. Actual discarded ciphertext and real notification
  gaps retain separate loss evidence. A capture cut by its comparison deadline, or failed,
  discards what its source held without new loss, including copies the live REQ delivered
  before the capture: the source stays unadmitted, the pending obligation still owes that
  window, and a new loss would wipe that obligation's scope certificates so it could never
  finish. That loss is deferred on the source, not dropped: a finished capture clears it,
  and a reconnect, refusal, removal or execution failure records it, since the source can
  then be admitted or retired without the capture. A parked obligation, or one whose notice
  the user dismissed, schedules no capture, so the debt stays deferred until one of those
  happens: until then the history the cut discarded is reported only by that notice, as
  possibly incomplete, not as new loss. Native clamp paging is not an owner capture; its
  cut records loss at once. See design section 0 for the limited native predicate.
- Live cursor promotion (design section 6). A delivery the raised floor sends to the spill
  is volatile until its spill write commits; a stop in that window loses it until the
  startup comparison. Routing is by content, so the router cannot tell an unfloored
  maintenance or prior-route replay from a floored REQ: such a replay's events above the
  settled floor go to the spill too, which costs spill writes (seen events are discarded
  before they use capacity) but loses nothing. Source generations include newly issued
  group REQs; native admission fences their original ranges, not just the activation snapshot.
  A drain checkpoint spills only what
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
  the comparison job's execution bracket and the owner's storage transitions. Native replay uses the same owner
  rows with cause `subscription_replay`; `subscription_eose_repaired` remains historical decoding only.
- NSE behavior needs device validation. The spill makes short extension runs safer, because
  nothing is lost if one ends mid-drain.
