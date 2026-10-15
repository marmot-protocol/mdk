---
title: "Review Pass 1 — B: Runtime Concurrency"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, pass-1, concurrency]
status: draft for discussion
---

# Review Pass 1 — B: Runtime Concurrency

System B of the [review](README.md): how the app runtime schedules work, and whether that design can keep the
groups a user cares about current and responsive at the [scale targets](README.md#scale-targets). Baseline
`9c95ff2bf`. It builds on the [concurrency map](map-concurrency.md) and the [journey map](map-journeys.md).
"(inferred)" marks claims reasoned from code but not traced at runtime.

## Summary

- **The safety rule is per group, and the engine already enforces most of it per group.** Every engine gate on outbound
  work is per group and built from durable state. Sends to a group that is not settled are queued durably (§2).
- **The account-wide worker mostly duplicates those gates, and the part only it covers, it covers loosely.** The one
  fact the engine cannot know is whether relays still hold commits this device has not fetched. The worker covers it
  with account-wide holds, but sends still run during the startup comparison and replay after a failed catch-up, and
  the startup drain ends on quiet rather than on complete EOSE (§2.3).
- **The cost is high and visible.** About 40 PRs in four months worked around the single worker. Production numbers
  include a 25 s p95 conversation read and a 45% invite-accept failure rate. On Swift and Kotlin hosts the whole
  runtime appears to share one thread (§3).
- **The open conversation gets no priority.** Opening a window changes no scheduling decision, and its live capture
  waits in the same queue as everything else (§3.4).
- **Recommendation: split the worker by role, not by group** (option B in §5). One writer lane per account that runs
  short, prioritized units of work; a read path that never waits on it; I/O lanes that never hold it; and an explicit
  per-group readiness state that replaces the account-wide holds. This keeps SQLite's single writer and the engine's
  invariants. The migration in §6 starts with low-risk substrate steps.

## 1. The rule to protect

The product owner's statement of intent: never publish messages or commits into a group before this device is caught
up and converged for that group. Stated precisely:

- **R1, commit safety.** Stage a commit for group G only when:
  - (a) the local view of G is settled: `EpochState::Stable`, own publication resolved, no gating convergence pass, no
    unresolved inputs within the rewind window, no deferred-peel generation, and canonical application messages
    drained;
  - (b) there is no reason to believe relays hold commits for G that this device has not fetched.
- **R2, message durability.** Send an application message for G only when both (a) and (b) hold; otherwise accept it,
  queue it durably, and encrypt it when the queue drains. A message sent on what turns out to be a losing branch is
  invalidated: the 2026-10-12 stale-commit incident invalidated 133 messages. Decided 2026-10-15 (§8): application
  messages wait for catch-up just as commits do.
- **R3, ordering.** Outbound intents for one group leave in the order they were accepted.

None of R1–R3 requires ordering between different groups.

## 2. How the rule is enforced today

### 2.1 Engine, per group, durable

| Gate | Where | Effect |
| --- | --- | --- |
| Hydrate on demand; quarantine on failure | `crates/cgka-engine/src/message_processor/mod.rs:947-952`; `engine.rs:2701-2750` | Hydrated inline, or rejected |
| Terminal and lifecycle checks (`validate_send_acceptance`) | `mod.rs:953-1033` | Rejected; re-checked when the queue drains (`send.rs:41-87`) |
| `ResolvingLocalPublish` | `mod.rs:1289-1315` | Application messages queued durably; other intents rejected |
| `ConvergencePending`: a gating pass, unresolved inputs, a deferred-peel generation, pending disband, undrained canonical applications | `mod.rs:1316-1339`, `:1626-1812` | Queued durably |
| `ForegroundBudgetExhausted` (250 ms or 4 rows of deferred peel) | `mod.rs:283-286`, `:1340-1342` | Queued durably |
| Queue cap of 256 per group | `mod.rs:213`, `:3690-3694` | Rejected |
| Drain only when `Stable`; one group evolution per drain; admin fairness | `mod.rs:1086-1250` | Stays queued |

A send runs its own group's convergence inline under the foreground budget before deciding. This layer covers R1(a)
and R2(a) completely, for one group at a time.

### 2.2 Account and app layers, per group

| Gate | Where | Effect |
| --- | --- | --- |
| Older fanout below quorum blocks the group's queued drain | `crates/marmot-account/src/runtime.rs:2840-2870`, `:3012-3027` | Held, durable |
| `GroupCatchingUp`: an open epoch-gap obligation at or above the local epoch. **Group changes only**; application messages and leave are not gated (`crates/marmot-app/src/client/mod.rs:6066`) | `client/mod.rs:6067-6100` | Rejected until cleared or acknowledged |
| `GroupCommitUndelivered`: the last commit is owed to a relay for more than 2 minutes | `client/mod.rs:115`, `:6071-6110` | Rejected unless acknowledged |
| Post-join phases: catch-up, then EOSE or 5 minutes, then grace, quiet and jitter, before the post-join self-update | `marmot-account/src/runtime.rs:1470-1545` | Deferred, durable |

Both acknowledgements live only in memory (`client/mod.rs:6025-6035`), so a worker restart forgets them. The
post-join phases are the only per-group model of "transport caught up" in the codebase, and they gate only one
self-update.

### 2.3 Worker, account-wide

| Hold | Where | Effect |
| --- | --- | --- |
| Startup hydration | `crates/marmot-app/src/runtime/account_worker.rs:3686-3830` | Mutations for every group join a deferred FIFO |
| Startup sync | `account_worker.rs:823-917` | Mutations deferred; capture returns `NotReady`; invite accept returns `AccountWorkerBusy` |
| Explicit catch-up | `account_worker.rs:3123-3262` | Same |
| Convergence pass, Welcome fanout, full-history repair | `account_worker.rs:4268-4363` | Every mutation for every group waits |
| Reconnect backoff | `account_worker.rs:2502-2560` | Commands dropped |

This is the only layer that stands in for R1(b), and it does so loosely:

- `SendMessage` and local submissions run live during the startup comparison whenever the deferred queue is empty
  (`account_worker.rs:1462-1490`).
- Deferred commands replay even when catch-up failed (`account_worker.rs:1606-1700`).
- Steady-state recovery jobs block nothing except full-history repair (`account_worker.rs:758-760`).
- The startup drain ends after 750 ms, then 250 ms, of quiet, or when EOSE is "settled", not "complete"
  (`client/sync.rs:2983-2997`).
- The pre-send subscription sync re-registers routes but does not wait for EOSE. The code itself says it "cannot
  prove the device caught up" (`client/mod.rs:6042-6043`).
- EOSE is tracked per batched REQ and exported only as per-account counts
  (`crates/transport-nostr-adapter/src/lib.rs:1465-1497`), so no per-group transport state exists for live traffic.

Meanwhile the holds serialize unrelated groups. A convergence pass for group X, including fanout retries with 20 s
per-relay waits, holds a send to group Y, though nothing in R1–R3 links the two (inferred).

### 2.4 R3, ordering

`do_send` queues only when a queue reason applies, and otherwise sends at once (`mod.rs:866-904`). It does not check
whether older intents are already queued for the group (`has_queued_outbound_intents`, `mod.rs:1983-1988`, is not
consulted). Whether a fresh application message can overtake older queued ones once convergence settles depends on
the drain inside the foreground advance (`mod.rs:1690-1693`). This is unverified and needs a test.

## 3. What the serialization costs

### 3.1 Field evidence

- UI stalls on iOS and Android; fewer on macOS, which uses the same binding on a faster CPU. Not yet compared on the
  Linux desktop app, which runs the multi-thread C ABI runtime
  ([platform map](map-platforms.md#observations-for-pass-1)).
- #1803: conversation snapshot read p95 of 25 s, because snapshot serving switched off once anything was deferred.
- #1812: invite accept failed 45% of the time with a 10 s deadline (p95 13.6 s).
- #1809: 12% of downloads failed when a fifth transfer was refused admission.
- #2098: workers hung up to the 45 s ready wait roughly every 64 s.
- #1711: recovery held the worker 11 s past a 10 s query deadline.
- #2114: "starting a DM takes tens of seconds".

### 3.2 Workarounds

Roughly 40 PRs from 2026-06-15 to 2026-10-15 exist mainly to work around the single worker or thread. Examples:

- snapshot reads during exclusive phases (#1457, #1719, #1819);
- command and convergence alternation (#1815, #2196);
- the startup deferred FIFO and pending queue (#1158, #2045, #2058);
- durable `submit_*` admission next to the waiting `send_*` (#1943, #2026);
- media slot gating (#1447, #1824, #1879);
- `NotReady`, the 50 ms authority wait and local-first window opening (#1853, #1873, #1878);
- `AccountWorkerBusy` and the 10 s / 2 min / 16 min reply timeouts (#1444, #1830);
- the startup hydration pipeline, which cut account-ready from 1,862 ms to 241 ms (#1308);
- recovery work moved off the worker behind two process-wide credits (#2045–#2114);
- shorter command tails (#1316, #1457, #1500, #1821, #1823).

Issue #1814, a backlog drawn from 30 days of production timings, lists 12 items. At least five are worker
head-of-line costs.

### 3.3 Reads

- **19 host reads round-trip through the worker.** About 15 of them could be served from durable rows alone: members,
  roster, recovery status, commit delivery, app components, maintenance status. `HistoryNotices` already reads only
  the app connection but still goes through the worker (`client/history_notices.rs:17-25`). The in-memory facts the
  rest need are small: `EpochState` lifecycle, the quarantine set, the hydration set, the in-flight upload set and a
  maintenance pause flag.
- **About 22 direct reads of `session.sqlite` run on the host thread** (`chat_list`, `timeline_messages`, reactions and
  others). They share the app connection's mutex and per-thread transaction ownership with the worker's projection and
  checkpoint writes (`crates/storage-sqlite/src/connection.rs:330-345`, `:550-572`), so they wait while one of those
  transactions is open (inferred).
- **Snapshot serving costs O(groups) per convergence fire.** Each scheduled convergence pass first captures a snapshot
  of every group, including an `MlsGroup::load` per group (`client/mod.rs:2642-2717`), so that reads can be answered
  while the pass runs (inferred cost; not measured).

### 3.4 The open conversation

`open_conversation_window` reads the local projection, then sends `CaptureConversation` through the ordinary worker
queue (`crates/marmot-app/src/runtime/conversation_window.rs:607-640`). Capture never forces hydration, and it returns
`NotReady` in every exclusive phase. No scheduler reads open-window state. Deliveries are FIFO; convergence is earliest
deadline first, with ties broken by group-id bytes; local submissions publish in one account-wide sequence; recovery
orders obligations by id, and a stored `urgency` field is never read (`storage-sqlite/src/account_recovery/demand.rs`).
The only group-level priorities are on-demand hydration for a few group reads, and the inline convergence a send
triggers for its own group.

### 3.5 History

Workers once ran off the shared executor. `2e712ac8d` (2026-05-23, "run app account workers off the async executor")
gave each worker its own current-thread runtime inside `spawn_blocking`. Four days later, `65f56af60` ("Harden app
runtime shutdown") moved them back to `tokio::spawn`, so shutdown could abort and join workers through a `JoinSet`.
The commit gives no reason. A blocking task cannot be aborted, which is the likely cause (inferred). Any move off the
shared thread must keep cancellable shutdown, and must tie into the close registry that
[#2323](https://github.com/marmot-protocol/mdk/issues/2323) needs.

## 4. Requirements for a replacement

1. Keep R1–R3, and fix R1(b), which is enforced loosely today.
2. Focus on concurrency within one account. One account per device is by far the most common case.
3. Keep the open group responsive under load, with work for groups untouched for weeks done on a budget.
4. Keep per-group work bounded by a window, not by history or membership. Targets are groups of thousands and years of
   history.
5. Respect SQLite: one writer per database file. The goal is short write units in a good order, not parallel writes.
6. Keep reads off the write path entirely.
7. Keep network, crypto and file I/O out of any unit that blocks the writer.
8. Keep mobile suspension safe: terminal close in bounded time, long operations interruptible, every handle closed
   before the lease drops.
9. Keep crash safety: durable intents, at-least-once projection, no torn writes
   ([multi-step state changes](../overview/multi-step-state-changes.md)).
10. Behave the same on every binding. Today the UniFFI hosts run single-threaded and the C ABI and CLI hosts run
    multi-threaded.

## 5. Options

### A. Keep the actor, fix the substrate

Give `marmot-uniffi` its own multi-thread runtime. Move synchronous engine and SQLCipher calls off async threads.
Take relay waits and KeyPackage discovery out of worker commands, and serve durable reads from read-only connections.

- **For:** incremental and low-risk; most steps are local; it removes cross-account and relay-plane starvation.
- **Against:** still one lane per account, so the open group still waits behind another group's convergence pass, and
  the account-wide holds remain. It does not meet requirements 1 or 3.

### B. Split the worker by role (recommended)

Per account:

1. **One writer lane.** It owns the engine and the write connection, and it runs short units: ingest one delivery,
   advance one group's convergence slice, stage one intent, confirm one publication, project one batch. The engine's
   budgets and continuations already have this shape.
2. **A read path.** Read-only WAL connections, plus a small published view of the writer's in-memory facts (lifecycle,
   quarantine, hydration), updated after each unit. Host reads never enter the writer's queue.
3. **I/O lanes.** Publish fanout, catch-up and comparison fetches, KeyPackage discovery and media transfers run outside
   the writer and hand results back as units. The writer never awaits a relay.
4. **Per-group readiness**, owned by one component, as an explicit state per group: `CatchingUp` (transport evidence
   incomplete), `Converging` (engine not settled), `Ready`, and `Stalled` (epoch gap or undelivered commit). Sends to a
   group that is not `Ready` are accepted and queued durably, using the engine queue that already exists, and drain
   when it becomes `Ready`. This replaces the account-wide startup and catch-up holds.
5. **A priority scheduler** for writer units and I/O, with three tiers (§8): the open window, then groups with recent
   activity, then everything else. Budgets keep background groups from starving: they catch up within minutes of the
   app opening or a notification wake.

- **For:** matches the stated intent; keeps the single writer and every engine invariant; fixes R1(b) per group; and
  retires most workarounds in §3.2 (see §6).
- **Against:** a large change. It needs real per-group transport evidence, which today exists only for post-join. The
  writer lane still serializes groups, but in short prioritized units rather than whole commands.

### C. Per-group actors or engine shards

Give each group its own lane and engine shard.

- **For:** maximum isolation between groups.
- **Against:** the engine is one struct with about 20 per-group maps over one connection; SQLite still serializes
  commits; and account-wide state (KeyPackages, inbox and Welcomes, dedup, recovery, identity) needs cross-shard
  coordination. It means rewriting the engine for little gain over B under SQLite.

Not recommended.

## 6. Migration path

Each step ships on its own and can be judged by measurement.

| Step | Change | Retires |
| --- | --- | --- |
| 0. Measure | Thread-name trace of MarmotKit on iOS and Android. Command latency while a convergence pass runs. Snapshot-capture cost. The same flows on the Linux desktop app. | — |
| 1. Substrate | `marmot-uniffi` owns a multi-thread runtime, documented per binding. Synchronous engine and storage work runs on a per-account blocking executor that stays cancellable, learning from `65f56af60`, and is registered with the close registry from #2323. Acceptance criteria are below. | Cross-account and relay-plane starvation; most of the 79 `blocking_app_task` sites over time |
| 2. Read path | Read-only connections per account. The 15 durable-servable worker reads, and `HistoryNotices`, move off the worker. The writer publishes its small in-memory view after each unit. | Snapshot serving and its O(groups) capture per pass; `NotReady`; the 50 ms authority wait; read timeouts |
| 3. I/O out of the writer | Fanout waits, KeyPackage discovery and catch-up network run in I/O lanes; the writer only stages and confirms. | The send path's 20 s per-relay hold; media slot parking; long command tails |
| 4. Per-group readiness | Per-group transport evidence: EOSE per group out of batched REQs, or a per-group comparison. One readiness owner. Durable acknowledgements. A decision on whether application messages respect epoch-gap evidence. | The startup deferred FIFO; the account-wide catch-up holds; `AccountWorkerBusy` for reads |
| 5. Priority scheduling | The open window and visibility feed a priority class for writer units, I/O, recovery and attachments, with background budgets. | Ad-hoc alternation (`yield_to_convergence`) |
| 6. Clean up | Remove each workaround once its replacement is measured. | — |

### Step 1 acceptance criteria

**Runtime handoff.**

- Every async export runs its body on the runtime that `marmot-uniffi` owns, never on async-compat's fallback. One way
  is to spawn the export's future onto the owned runtime and await the `JoinHandle`, which any executor can poll.
- Synchronous constructors and `start` enter the owned runtime, so code that looks up the current runtime finds it.
  `spawn_router`, for example, silently does nothing without one (`crates/marmot-app/src/relay_plane/mod.rs:2132-2134`).
- There is no silent fallback. If the owned runtime cannot be built, construction fails with a typed error rather than
  running on async-compat's thread.
- A test checks thread names: account workers, the relay plane and subscription tasks run on the owned runtime's
  threads, and none run on `async-compat/tokio-1`.

**Cancellation and bounded close.**

- An SQLCipher statement or MLS operation that has started is not interrupted midway. The cancellation boundary is
  between units: the per-account executor checks a stop flag before each unit, and once stopped it starts no new one.
- A long SQLite statement that unit size cannot bound, such as the `VACUUM` planned in #2314, must be interruptible
  through SQLite's interrupt mechanism, so close can stop it.
- Blocking work that cannot be aborted fails fast. After `close_storage`, every later database call returns
  `StorageError::Closed`, and close waits only for a statement that has already started
  (`crates/marmot-app/src/runtime/mod.rs:6105-6121`). Such work therefore stops at its next statement.
- Writer units meet the engine's existing budgets as a p99 target: 250 ms in the foreground and 500 ms in the
  background (`crates/cgka-engine/src/message_processor/mod.rs:273`, `:283`), measured on a mid-range Android device in
  Step 0. These are targets, not guarantees. The same trace reports the maximum unit duration and counts every unit
  over its budget, so outliers stay visible. On long histories, meeting the target depends on
  [#2326](https://github.com/marmot-protocol/mdk/issues/2326).
- `shutdown_and_close` returns within its current graceful budget of 5 s (`crates/marmot-app/src/lib.rs:427`) while a
  convergence pass and a hydration batch are in flight. When it returns, no connection to any database in the root is
  open ([#2323](https://github.com/marmot-protocol/mdk/issues/2323)).

These stay under any design: the engine's foreground and background budgets and sliced replay, the writer-side FIFO
for mutations within a group, typed busy and unknown-completion errors for mutations, and the diagnostics.

## 7. Possible defects found in this pass

| # | Candidate | Evidence | Status |
| --- | --- | --- | --- |
| B-1 | A fresh application message may overtake older queued intents for the same group | §2.4 | Unverified; write a test, then file if it reproduces |
| B-2 | `GroupCatchingUp` and `GroupCommitUndelivered` acknowledgements are lost on worker restart | `client/mod.rs:6025-6035`, `:6170-6172` | Observed; possibly intended, needs a product decision |
| B-3 | Sends run during the startup comparison, and deferred commands replay after a failed catch-up | §2.3 | Observed; it is either the intended "best effort" or a gap in R1(b), so it needs a product decision |

## 8. Decisions (product owner, 2026-10-15)

1. **Outgoing application messages wait for catch-up, like commits.** The aim is reasonable certainty that catch-up is
   done before anything is sent. Epoch-gap evidence and transport catch-up are two sides of one question: gap evidence
   (undecryptable traffic at a later epoch) shows that commits were missed, and completed catch-up rules that out. Both
   feed the per-group readiness state in option B.
   - **The wait must be bounded.** Gap evidence is undecryptable traffic that anyone can mint
     (`crates/marmot-app/src/client/mod.rs:6043-6044`). An unbounded gate would let anyone who can publish to a group's
     relays block it from sending. Gap evidence should start an immediate targeted fetch, and sends should wait only
     until that fetch completes or a short bound expires. The existing acknowledgement escape stays.
   - **Sends are accepted immediately and queued durably.** The host shows them as sending, and they publish when the
     group is ready. The UI never blocks on readiness.
   - Incoming traffic is unaffected. Received messages are processed as they arrive, and those that need an unseen
     commit are buffered until it arrives.
2. **Three priority tiers:**
   - the open window;
   - groups with any recent activity;
   - everything else.

   "Recent" needs a concrete window. Proposed default: any message sent or received, or the group opened, in the last
   7 days.
3. **Background groups catch up within minutes**, not hours and not only when opened. Opening the app and a
   notification wake both start catch-up, processed tier by tier with budgets. With 50 to 100 groups, 5 to 10 are
   typically active and one is open.
4. **Swift and Kotlin hosts can run a multi-thread runtime.** iOS and Android run native threads normally, and
   MarmotKit already uses several: host threads calling sync exports, the async-compat thread, and Tokio's blocking
   pool, which serves about 100 `spawn_blocking` call sites. Only async tasks are confined to one thread, and that
   comes from UniFFI's fallback, not from any platform limit. `marmot-uniffi` can own a multi-thread runtime the way
   `marmot-c` already does (`crates/marmot-c/src/lib.rs:521-542`), so the same core already runs multi-threaded in
   production on the Linux desktop app.

   Conditions:
   - keep the worker-thread count small on mobile;
   - host callbacks already have to be thread-safe (`crates/marmot-uniffi/README.md:131-133`);
   - most tests use single-threaded `#[tokio::test]`, so add multi-thread test runs to expose hidden ordering
     assumptions.
