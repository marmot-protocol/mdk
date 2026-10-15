---
title: "Review Map — Engine State and Contract"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review, system-map, cgka-engine]
status: draft
---

# Review Map — Engine State and Contract

Part of [Pass 0](00-system-map.md). Baseline `9c95ff2bf`. This page describes what `cgka-engine` holds, how its
per-group state machine is persisted, and the API that `cgka-session`, `marmot-account` and `marmot-app` use. It is
descriptive. Observations at the end are inputs to Pass 1 system A, not conclusions. "(inferred)" marks a claim
reasoned from code but not traced end to end.

## 1. What `Engine<S>` holds

`Engine<S>` (`crates/cgka-engine/src/engine.rs:120-343`) has 59 fields, three of them test-only. The builder
(`engine.rs:518-673`) fills every field.

| Class | Count | Examples |
| --- | ---: | --- |
| Config or injected dependency | 25 | `storage`, `crypto`, `identity`, `peeler`, `wall_clock`, `convergence_policy`, `convergence_clock`, `recorder`, deferred-peel limits |
| Cache of persisted state, rebuilt at hydration | 13 | `epoch_manager`, `mls_group_cache`, `pending_origin_commits`, `seen_message_ids`, `quarantined_groups`, `unhydrated_groups`, `transport_group_id_index` |
| In-memory only | 15 | `authority_recovery_{cursor,attempts,seen}`, `scheduled_self_remove_auto_commits`, `queued_intent_by_{message,pending}`, `deferred_peel`, `canonical_replays`, `peel_replays`, metrics and audit context |
| Buffer or queue | 6 | `events_buf`, `auto_publish_buf`, `auto_proposal_buf`, `valid_proposal_groups`, `pending_convergence_groups`, `pending_confirmation_replays` |

What survives a crash or restart:

| State | On restart |
| --- | --- |
| `events_buf` | Partly durable. Only `MessageReceived` and `GroupJoined` are persisted (`crates/traits/src/storage.rs:344-352`), in the transaction that marks their input processed (`message_processor/ingest.rs:1549-1553`, `distributed_convergence.rs:1587-1592`). The builder re-seeds them (`engine.rs:563-616`), and `marmot-app` acknowledges them only after its projection commits (`crates/marmot-app/src/client/sync.rs:5790-5796`). The other 15 `GroupEvent` variants are lost. Derived-state reconcilers, `GroupUnrecoverable` re-emission at hydration (`engine.rs:2179`) and `PendingCommitRecovered` (`engine.rs:2046`) repair the effects. |
| `auto_publish_buf` | Lost. The staged commit survives in OpenMLS storage. Hydration restores `PendingPublish` from a durable `OutboundFanout` (`engine.rs:1919-1968`), re-queues an `AutoPublish` from a `DurableGroupEvolution` in phase `Prepared` or `Attempting` (`engine.rs:2217-2320`), or clears the pending commit unless it removes a member (`engine.rs:1974-2048`). |
| `auto_proposal_buf` | Lost. `last_proposed_epoch` is persisted with the sent row before the proposal is buffered (`message_processor/send.rs:833-845`), and re-proposal is skipped while that epoch is unchanged (`send.rs:829-831`). A crash before publish therefore suppresses the leave proposal until the next epoch (inferred). |
| `pending_convergence_groups` | Rebuilt at hydration from durable conditions: queued intents, unresolved inputs, canonical apps, deferred peels, self-remove schedules, pending disband (`engine.rs:2080-2207`). |
| `queued_intent_by_*` | Lost. The durable queued-intent row remains, so the next drain regenerates the artifact (inferred). |
| `deferred_peel`, `canonical_replays`, `peel_replays` | Discarded by design. They hold secret-bearing peel contexts that are never persisted (`message_processor/mod.rs:312-383`). The durable `DeferredPeelGeneration` is the correctness barrier. |

## 2. The per-group state machine

There is an explicit enum, `EpochState` (`crates/traits/src/engine_state.rs:220-241`): `Stable`, `PendingPublish`,
`Merging`, `Recovering`, `Unrecoverable`, `Disbanded`. Its fields are private, so only transition methods can produce
a non-`Stable` value. `EpochManager` (`crates/cgka-engine/src/epoch_manager.rs:48-52`) owns the per-group state map
and the pending-publish table.

| Transition | Durable write, and how it relates to the memory change |
| --- | --- |
| `set_stable` | No write of its own. It mirrors `Group.epoch`, which the apply transaction already wrote (`distributed_convergence.rs:1543-1597`). Memory changes after commit. |
| `begin_pending` (Stable to PendingPublish) | Preceded by several separate writes with no single transaction: OpenMLS pending commit, sent row, projected record, caches (`send.rs:278-394`). A drop guard compensates in process (`pending_commit_guard.rs`), and hydration compensates after a crash. |
| `confirm_publish` (PendingPublish to Stable) | Runs after one transaction (`publish.rs:133-288`). A crash in between is recovered because the record already holds the new epoch. |
| `rollback_publish` | Runs after the clear-pending transaction (`publish.rs:473-525`). |
| `mark_unrecoverable` | Preceded by one `put_group(unrecoverable=true)` outside any transaction (`distributed_convergence.rs:1025`, `:1451`). |
| `mark_disbanded` | Follows the terminal deletion transaction; restored from the tombstone. |

No transition shares a unit of work with storage. The pattern is always durable write first, then memory, with
hydration as the reconciler.

The enum is not the whole story. The effective per-group state is the combination of at least eight facets:
`EpochState`; the durable `Group` flags `removed` and `unrecoverable` and the disband tombstone
(`crates/traits/src/group.rs:64,75,80`); leave and disband requests; `quarantined_groups` and `unhydrated_groups`;
`DurableConvergencePass.phase` (`Collecting`, `Frozen`, `Resolving`, `Completed`;
`crates/traits/src/convergence_pass.rs:12-16`); `DeferredPeelGeneration`; `FanoutMlsState`
(`crates/traits/src/transport_adapter.rs:228-233`); and `GroupEvolutionPhase`
(`crates/traits/src/maintenance.rs:148-154`). `validate_send_acceptance` re-checks most of them separately
(`message_processor/mod.rs:944-1035`).

## 3. The API the layers above use

The call chain is strict: `marmot-app` calls `AccountDeviceRuntime` (`marmot-account`), which calls
`AccountDeviceSession` (`cgka-session`), which calls `Engine`. The session exposes no engine accessor
(`crates/cgka-session/src/lib.rs:193-197`).

| Surface | Size |
| --- | ---: |
| Inherent `pub fn` on `Engine` | 123 (113 production) |
| `CgkaEngine` trait methods (`crates/traits/src/engine.rs:823-1157`) | 30 |
| Distinct engine methods called by `cgka-session` | 119 |
| `AccountDeviceSession` public methods | 119 |
| Session methods used by `marmot-account` / directly by `marmot-app` | 88 / 34 |
| `AccountDeviceRuntime` public methods / used by `marmot-app` | 95 / 75 |

Session-to-engine calls by purpose: ingest (3), send and intent (6), publish lifecycle (18), convergence scheduling
(8), queries (27), maintenance, retention and KeyPackages (25), recovery (12), hydration (7), draining (5), audit (8).

Outputs: `GroupEvent` (17 variants, `crates/traits/src/engine.rs:568-789`), `SendResult` (8), `IngestOutcome` (8,
`crates/traits/src/ingest.rs:12-63`), `AutoPublish` (`engine.rs:372-375`) and `PendingStateRef`
(`engine_state.rs:65`). Draining happens in one place: `cgka-session` `collect_effects`
(`crates/cgka-session/src/lib.rs:1482-1578`) runs after every session call and returns
`SessionEffects { events, publish, queued, pending_convergence }`.

## 4. Publish-before-apply

| Step | Where | Durable after the step |
| --- | --- | --- |
| 1. Intent, queued when convergence is unsettled or the group is not `Stable` | `message_processor/mod.rs:866-904`, `:3642` | Queued-intent row |
| 2. Stage the commit | `do_send_ready` (`send.rs:27`), invite example `send.rs:278-430`. SelfUpdate writes a `DurableGroupEvolution` before the MLS mutation (`self_update.rs:144`, `:221-225`). | OpenMLS pending commit, signed sent row, projected record, own-commit intent. Not one transaction. |
| 3. Freeze the obligation | `marmot-account` persists an `OutboundFanout` in `Pending(ref)` (`crates/marmot-account/src/runtime.rs:4572-4600`); earlier failures call `publish_failed` (`:4616-4630`) | Exact request bytes, targets, pending ref |
| 4. Attempt | Attempt start and each relay receipt are persisted (`runtime.rs:4685-4688`, `:4811`) | Per-target receipts |
| 5a. Confirm (at least one relay accepted) | One transaction merges, mirrors the record, refreshes caches, checkpoints, marks the fanout `Confirmed` and deletes the intent (`publish.rs:133-288`). Then the memory transition and `EpochChanged` (`:300`, `:371`). | All of the above, atomically |
| 5b. Fail (none accepted, fanout complete) | One transaction clears the pending commit, deletes the intent and marks the fanout `RolledBack` (`publish.rs:473-525`) | Same, atomically |

Inbound commits are never merged on the direct ingest path (`ingest.rs:1653-1666`). Only convergence merges them
(`openmls_projection.rs:4263`).

| Crash point | Recovery |
| --- | --- |
| After staging, before the fanout is persisted | Hydration clears the pending commit unless it removes a member (`engine.rs:1974-2048`) |
| After the fanout is persisted | `restore_pending` (`engine.rs:2131`); `resume_outbound_fanouts` re-sends the exact bytes (`marmot-account/src/runtime.rs:3295-3418`) |
| Accepted, before confirm | Resume confirms first (`runtime.rs:4653-4658`) |
| After the confirm transaction, before the memory transition | Record is at the new epoch; hydration calls `set_stable` (`engine.rs:2148`) |
| After confirm, before the app sees `EpochChanged` | Event lost (memory only); reconcilers repair |

## 5. Convergence

- **Entry.** `commit_should_enter_convergence` (`ingest.rs:1171-1201`) routes every commit at or above the live
  epoch to convergence, plus past-epoch commits within `max_rewind_commits` (5, `convergence.rs:14`) when a pass or
  anchor is active. Admission is durable and shares a transaction with pass admission
  (`distributed_convergence.rs:541-553`).
- **The pass** (`distributed_convergence.rs:1096-1760`). Quiescence deadline is open + 1,000 ms and the absolute
  deadline open + 5,000 ms (`:808-811`, `canonicalization.rs:23-25`). While `Collecting` and before cutoff the pass
  returns "waiting", so an inbound commit applies on a later wake. It then freezes, resolves, canonicalizes (sliced,
  with a continuation in `canonical_replays`, or full), and applies in one transaction (`:1543-1597`).
  `MissingRetainedAnchor` makes the group `Unrecoverable` (`:1440-1487`).
- **Cost bounds.** Replay budget is commits × (rewind + 1) × slack + floor (`openmls_projection.rs:221-227`). Per
  advance: 16 reprocessing passes (`message_processor/mod.rs:116`), 64 rows or 500 ms of background allowance
  (`:219`, `:273`), 32 probes per slice (`:277`), 8 branch peel contexts (`:307`). Deferred peel: 2,048 rows and
  16 MiB per group, 64 MiB per account (`:153-171`). 256 queued intents per group (`:213`).
- **Scheduling.** The engine runs no timers. A convergence hint passes through four in-memory hops: engine set, then
  `SessionEffects.pending_convergence` (`cgka-session/src/lib.rs:1487`), then `AccountDeviceEffects`
  (`marmot-account/src/runtime.rs:4933-4939`), then `AppClient.pending_convergence_groups`
  (`marmot-app/src/client/mod.rs:900`), then the worker's `ScheduledConvergence`
  (`marmot-app/src/runtime/account_worker.rs:6575-6582`). The worker sets its timer from the engine's `*_delay_ms`
  queries (`client/sync.rs:765-830`).
- **Time** enters through an injectable `ConvergenceClock` (`convergence_clock.rs:17-19`), `WallClock`, explicit
  `now_ms` entry points, and about 20 direct `Instant::now()` reads for work budgets.

## 6. `StorageProvider`

- **Shape.** 16 supertraits plus 7 own items (`crates/traits/src/storage.rs:955-973`), and `MaintenanceStorage`
  reached through an accessor (`:1035`). About 119 methods in total.
- **Implementations.** One production backend, `SqliteAccountStorage` (`crates/storage-sqlite/src/connection.rs:1380`),
  plus `SqliteOpenMlsStorage` for OpenMLS. "In-memory" means SQLite in-memory mode (`connection.rs:1023`). Test
  doubles wrap SQLite. The simulator also uses `Engine<SqliteAccountStorage>`.
- **Atomicity.** One closure API, `with_transaction` (`storage.rs:1039-1058`). Its default implementation is not
  transactional: it just calls the closure. SQLite overrides it with `BEGIN IMMEDIATE` on one shared connection and
  flattens nested calls into the outer transaction without savepoints (`connection.rs:575-638`). There are 39
  production call sites in 17 engine files.
- **Writes outside one unit:** send staging; the auto-commit `put_group` (`ingest.rs:2021-2050`); application ingest,
  split into two transactions (`ingest.rs:1237-1255`, then `:1549-1553`); `retire_raw_wrapper`, by design
  (`store.rs:1118-1122`); the pre-confirm anchor (`publish.rs:118`); the unrecoverable marker
  (`distributed_convergence.rs:1451`).

## 7. `MlsGroupCache`

Up to 32 loaded `MlsGroup`s; the whole map clears when the cap is hit (`mls_group_cache.rs:40`, `:78-80`). An entry
is valid while the connection's write generation is unchanged, so any write evicts every entry
(`mls_group_cache.rs:24-26`, `connection.rs:1387-1404`). About 40 call sites bypass the cache and call
`MlsGroup::load` directly, including publish, hydration, convergence and lifecycle code.

## 8. What the session and account layers add

- **`cgka-session`** is a thin wrapper, concrete over SQLite (`lib.rs:193-197`). It opens SQLCipher, builds the
  engine, retires stale KeyPackages, runs eager or deferred hydration (`lib.rs:313-428`), collates effects, provides
  budgeted background hydration (`:737-771`), and passes about 119 methods through. It has no queues, timers or
  durable records of its own.
- **`marmot-account`** (`AccountDeviceRuntime`, `runtime.rs:427-457`) owns the frozen-fanout publish pipeline, the
  legacy `DurableTransportFanout` path (`:5022-5310`), due maintenance (`:1550-2140`), KeyPackage rotation
  (`:845-1125`), supersession reconcilers (`:3580-3748`), Welcome redelivery, relay backoff and a per-group ordering
  barrier for fanouts (`:3387-3395`).

## 9. Existing verification

27 engine test targets, including `crash_recovery_sqlite.rs`, `record_write_atomicity.rs` and
`two_phase_hydration.rs`; the conformance simulator (42 test files, 29 vectors); the Tamarin model
`formal/tamarin/distributed_convergence_v0.spthy` (78 lemmas); test-only crash hooks (`test_crash_hooks.rs`).

## Observations for Pass 1

1. **The real lifecycle is implicit.** `EpochState` is explicit, but `Merging` is never observable
   (`engine_state.rs:225-229`), `Recovering` exists only as a transient step inside disband, and the state that
   gates behaviour is spread over eight facets checked separately.
2. **Per-group sidecars are cleaned up by hand.** About 20 maps are keyed by `GroupId`, and each teardown path lists
   them itself (`engine.rs:3085-3130`, `disband.rs:556-571`, `engine.rs:2594-2617`).
3. **Only 2 of 17 events are durable.** The rest rely on reconcilers to repair what a lost event would have done.
4. **There are six outbound durability rails:** `OutboundFanout`, legacy `DurableTransportFanout`,
   `DurableGroupEvolution`, `OwnCommitIntent`, queued intents and sent rows. In-memory maps join them
   (`pending_origin_commits`, `queued_intent_by_*`).
5. **Convergence scheduling is memory-only across four hops.** Only the engine end is rebuilt at hydration.
6. **A memory-bounded set feeds selection.** The 100k-entry `seen_message_ids` FIFO (`bounded_id_set.rs:34`) is an
   input to canonicalization dedup (`distributed_convergence.rs:313-331`). A restart empties it. Whether a warm and
   a restarted engine can reach different outcomes is unverified.
7. **Some queries have side effects.** `prepare_convergence_cutoff_delay_ms` can open a durable pass
   (`distributed_convergence.rs:206`); `marmot-app` notes that it is "a command, not a query"
   (`client/sync.rs:761-762`). Many `&mut` entry points hydrate implicitly.
8. **The storage genericity is unused and its default is unsafe.** One backend, a session hard-coded to SQLite, and
   a default `with_transaction` that silently drops atomicity for any second backend.
9. **The API is broad and mostly pass-through.** 153 engine methods and 119 near one-to-one session pass-throughs.
   The `CgkaEngine` trait is not the contract the layers above actually use; 8 of its methods, including
   `join_welcome` and `upgrade_group_capabilities`, are not called by the session.
10. **Possible crash windows (inferred, not traced):** application ingest commits the ratchet advance and the
    `Processed` mark in separate transactions; a removal-bearing staged commit with no fanout is kept at hydration
    while the record may already be projected to the next epoch (`ingest.rs:2022`, `engine.rs:2148`).
11. **Some reads rescan everything.** Full hydration reads every message row for the group (`engine.rs:2059`);
    `outstanding_sent_welcomes` decodes all rows of all groups (`engine.rs:3247-3300`). Every convergence pass seeds
    its inputs from all messages in the rewind horizon, `Processed` application messages included
    (`distributed_convergence.rs:877-885`). Together with the full apply snapshot, this is measured in
    [#2326](https://github.com/marmot-protocol/mdk/issues/2326).
12. **Docs lag the source.** `crates/cgka-engine/AGENTS.md:286-291` still names direct ingest as an epoch writer, and
    the publish-before-apply steps in [`target-architecture.md`](../overview/target-architecture.md) omit the frozen
    fanout.
