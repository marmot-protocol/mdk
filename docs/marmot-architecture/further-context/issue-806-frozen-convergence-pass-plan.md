---
title: "Issue #806 — Durable Frozen Convergence Pass Implementation Plan"
created: 2026-07-25
updated: 2026-07-25
tags: [marmot, mdk, convergence, canonicalization, storage, recovery, implementation-plan]
status: implemented-awaiting-review
related:
  - https://github.com/marmot-protocol/mdk/issues/806
  - https://github.com/marmot-protocol/mdk/pull/1107
  - https://github.com/marmot-protocol/mdk/pull/1103
  - https://github.com/marmot-protocol/marmot/pull/408
---

# Issue #806 — Durable Frozen Convergence Pass Implementation Plan

> **Implementation record.**
>
> Implementation began on `codex/issue-806-frozen-convergence` from settled post-prerequisite
> `origin/master` at `e40fa5fc677a26f680f786c6f9bde88c64e5f6cd`, after both prerequisite pull requests merged:
>
> - [MDK PR #1107 — pin convergence policy to the adopted v1 baseline](https://github.com/marmot-protocol/mdk/pull/1107)
> - [MDK PR #1103 — durable KeyPackage and self-update maintenance](https://github.com/marmot-protocol/mdk/pull/1103)
>
> The branch confirmed migration `0035` was next, retained the merged maintenance/evolution architecture, and
> implemented the durable frozen-pass design described below. The detailed checklist remains as review context; where
> it offered multiple design alternatives, the architecture documents describe the selected implementation.

## 1. Purpose

[Issue #806](https://github.com/marmot-protocol/mdk/issues/806) closes a protocol-significant convergence gap.
The existing convergence scheduler can extend its collection timer when additional input arrives. Under continuous
traffic, this can prevent selection indefinitely and allow clients to resolve different moving input sets.

The adopted Marmot v1 behavior requires one convergence pass to have:

- a normal cutoff after 1000 milliseconds without selection-relevant input;
- an absolute collection cap exactly 5000 milliseconds after its first eligible input;
- an immutable input and selection snapshot at cutoff;
- no admission of post-cutoff input into the current pass;
- restart recovery that preserves the original cutoff terms and frozen batch;
- bounded, fair processing across groups; and
- protocol-facing outcomes that match the adopted taxonomy.

This is not merely an application timer correction. The collection boundary must be owned by the engine and durable
storage because it controls which state transition becomes canonical.

## 2. Normative and implementation context

### 2.1 Normative source

The implementation must be checked against the adopted specification rather than this plan:

- [`protocol-core/convergence.md`](https://github.com/marmot-protocol/marmot/blob/master/protocol-core/convergence.md)
- [`protocol-core/inbound-processing.md`](https://github.com/marmot-protocol/marmot/blob/master/protocol-core/inbound-processing.md)
- [`protocol-core/publish-lifecycle.md`](https://github.com/marmot-protocol/marmot/blob/master/protocol-core/publish-lifecycle.md)
- [Marmot PR #408](https://github.com/marmot-protocol/marmot/pull/408)

This document describes how MDK should implement those rules. It does not replace or restate the protocol
specification authoritatively.

### 2.2 Related MDK work

- [Issue #707](https://github.com/marmot-protocol/mdk/issues/707)
- [Issue #970](https://github.com/marmot-protocol/mdk/issues/970)
- [Issue #1027](https://github.com/marmot-protocol/mdk/issues/1027)
- [PR #1107](https://github.com/marmot-protocol/mdk/pull/1107)
- [PR #1103](https://github.com/marmot-protocol/mdk/pull/1103)

PR #1107 should resolve the production policy-divergence prerequisite from #970. PR #1103 introduces durable group
evolutions, maintenance obligations, exact transport fanout, and shared deterministic clock seams. Issue #806 must
extend those foundations without creating a competing state-management layer.

### 2.3 Snapshot of the prerequisite pull requests

At the time this plan was last updated:

| Pull request | Current state | Relevant revision | Relevant effect |
| --- | --- | --- | --- |
| #1107 | Merged 2026-07-25 | merge `e40fa5fc677a26f680f786c6f9bde88c64e5f6cd` | Pins the adopted convergence policy in release builds while preserving validated debug/test overrides |
| #1103 | Merged 2026-07-25 | merge `b34fa9a0a6f7c421c959d5d3378b9bd66e0f0f63` | Adds durable KeyPackage/self-update maintenance, semantic group evolution, exact fanout, and wall/monotonic clock seams |

Both pull requests were based on the same pre-merge master and overlapped in:

- `crates/cgka-engine/src/engine.rs`
- `crates/cgka-session/src/lib.rs`
- `crates/marmot-app/src/lib.rs`
- `crates/marmot-app/src/runtime/account_worker.rs`

The final merged form of those files—not either reviewed branch in isolation—is the implementation baseline. Current
master contains migration `0034_maintenance_publication`; #806 is therefore expected to use `0035`, subject to a final
branch-time confirmation after #1107 and any intervening master changes.

## 3. Goals

The implementation must:

1. Close each pass at the earlier of 1000 milliseconds of selection-relevant quiescence or its immutable 5000
   millisecond absolute cap.
2. Make cutoff membership deterministic at the before/exactly-at/after boundary.
3. Persist enough immutable state to reconstruct the same pass after restart.
4. Prevent mutable storage, new network input, or local group mutations from changing a frozen result.
5. Preserve the existing selector ordering, witness scoring, rollback horizon, and publish lifecycle unless the adopted
   specification explicitly requires a change.
6. Allow multiple busy groups to make bounded progress.
7. Integrate safely with durable self-update, maintenance, queued outbound intent, and exact fanout.
8. Fail closed without discarding evidence when durable pass state is inconsistent.
9. Produce the same adopted outcome classes through direct and wrapped ingest seams.
10. Keep transport-specific concerns outside `cgka-engine`, `traits`, and storage.

## 4. Non-goals

This work should not:

- redesign branch selection or witness scoring;
- add a host-configurable convergence policy in release builds;
- turn the application runtime timer into the source of truth;
- create a second general-purpose maintenance or group-evolution framework;
- persist transport envelopes inside replayable MLS group-state snapshots;
- rewind, delete, or duplicate externally visible publication intent during candidate replay;
- introduce a broad new public outcome stream unless final-master consumers require it;
- use a production feature flag that permits clients to retain the old moving-window behavior;
- solve unrelated transport reliability, KeyPackage, or self-update issues; or
- assume migration `0035` without confirming that it is still next on the final implementation branch.

## 5. Required invariants

These invariants should be written down in code comments at the owning state transitions and covered by tests.

### 5.1 Policy invariants

- Adopted v1 pins `settlement_quiescence_ms = 1000`.
- Adopted v1 pins `max_convergence_pass_ms = 5000`.
- Release builds reject convergence policy values that differ from the adopted v1 baseline.
- Debug and test overrides remain available only through the validated seam established by PR #1107.
- The application-message past-epoch window remains aligned with the engine's configured maximum past epochs.

### 5.2 Collection invariants

- The first **eligible engine admission** opens pass generation `N`.
- Its absolute deadline is calculated once as `opened_at + 5000 ms`.
- Its quiescence deadline is initially `opened_at + 1000 ms`.
- Newly admitted selection-relevant input before cutoff restarts only the quiescence deadline:
  `last_selection_relevant_admission + 1000 ms`.
- Later input never moves the absolute deadline.
- Duplicate, invalid, stale, already-dominated, already-fully-counted witness, and ordinary application input that
  cannot affect selection do not restart quiescence.
- The effective cutoff is:

  ```text
  freeze_at = min(
      last_selection_relevant_admission + settlement_quiescence_ms,
      opened_at + max_convergence_pass_ms
  )
  ```

- Admission before the effective cutoff may join generation `N`.
- Admission exactly at or after the effective cutoff does not join generation `N`.
- Transport observation time is not authoritative; the engine admission transaction assigns membership.
- Once frozen, pass membership cannot change.

### 5.3 Resolution invariants

For a frozen generation `N`, the result must be a deterministic function of:

```text
result(N) = resolve(
    pinned_policy,
    pinned_base_state,
    frozen_authenticated_inputs,
    pinned_candidate_parent_and_dependency_state
)
```

Resolution must not consult newly arrived input, mutable candidate membership, a later group state, or newly fetched
dependencies.

- Candidate probing has no externally visible side effect.
- Canonical group state changes only in the final successful transition.
- No partial winner or loser disposition becomes visible before the final transaction.
- Missing parents or dependencies are deferred to a later pass.
- Post-cutoff arrival order cannot affect the current result.

### 5.4 Mutation ownership invariants

At most one subsystem may own a pending MLS group mutation:

- an active convergence pass;
- a prepared/attempting/publishing durable group evolution; or
- an authorized local outbound group-state intent being prepared.

These states must be mutually exclusive. Inputs may be retained while another owner is active, but they must not open a
pass against an unstable base state.

### 5.5 Persistence invariants

- Restart never grants a fresh quiescence or 5000 millisecond window to an existing pass.
- Restart reconstructs the same last selection-relevant admission, absolute deadline, effective cutoff, or frozen
  manifest.
- In-process scheduling uses monotonic time.
- Durable recovery uses a persisted millisecond wall deadline.
- If restart-time continuity cannot be trusted, the implementation freezes immediately rather than extending the
  collection window.
- A corrupt or incomplete frozen record blocks group evolution and preserves evidence.
- Storage cleanup occurs only after completion is durably recorded.

### 5.6 Side-effect isolation invariants

Replayable convergence snapshots contain MLS group state, not unrelated durable workflow state.

Candidate replay must not rewind or clone:

- maintenance obligations;
- KeyPackage publication state;
- durable group evolutions;
- exact signed transport fanout;
- queued outbound intents;
- convergence pass rows; or
- records describing external side effects.

## 6. Time model

### 6.1 Reuse the shared clock seam

PR #1103 adds shared wall and monotonic clock abstractions with deterministic test injection. Issue #806 should reuse and
extend this seam rather than introduce convergence-only clock traits.

The existing `WallClock::now() -> Timestamp` is seconds-quantized. `Timestamp` is already a seconds-domain transport and
maintenance type and must not be widened for convergence.

The final design must either:

- add a required millisecond method to the shared clock contract and update every implementation explicitly; or
- add a separate required millisecond wall-clock trait beside the existing seconds clock.

There must be no default `now_ms()` derived from `Timestamp`: it would silently quantize existing and test
implementations to whole seconds and make exact millisecond boundary tests vacuous.

### 6.2 Live process

When a process opens a pass:

1. Sample the injected monotonic clock for scheduling.
2. Sample the injected wall clock in milliseconds for persistence.
3. Persist the opening time, last selection-relevant admission, quiescence deadline, and absolute wall deadline in the
   same transaction that creates the pass and admits its first input.
4. Record the corresponding in-memory monotonic cutoff for efficient wakeup.

The monotonic effective cutoff governs the live process. Selection-relevant admission may move the quiescence term but
must not move the absolute term. Wall-clock changes must not move either live monotonic term.

### 6.3 Restart

After restart:

1. Read the original durable opening time, last selection-relevant admission, quiescence deadline, and absolute
   deadline.
2. Compare it with the current wall time through the injected clock seam.
3. If either reconstructed cutoff term has elapsed, freeze immediately.
4. If the effective cutoff is plausibly in the future, schedule only the remaining duration.
5. If continuity is untrustworthy because of detected backward movement, invalid timestamps, overflow, or inconsistent
   records, freeze immediately.

The failure policy favors a shorter collection window over a silently extended moving window.

### 6.4 Exact cutoff

The storage-backed engine admission operation evaluates both terms:

```text
effective_cutoff = min(quiescence_deadline, absolute_deadline)

admission_time < effective_cutoff  => current generation
admission_time >= effective_cutoff => freeze current generation first,
                                      then retain input for a later generation
```

The timestamp and membership decision must occur inside one serialized storage operation. An application-level timer
wakeup cannot decide membership retroactively.

## 7. Durable pass model

The exact Rust and SQL types should be designed after final master settles. Conceptually, storage needs the following
records.

This is a greenfield scheduling-persistence layer. Current master retains messages durably, but
`last_convergence_relevant_input_ms` and the scheduler's group/timer state are process-local. Restart currently loses
the timing state and can grant retained input a fresh quiescence window. Phase 2 therefore adds new pass tables and
trait operations; it is not a data migration from an existing convergence-schedule row.

### 7.1 Pass header

A pass header should contain:

- opaque pass identifier;
- opaque group identifier;
- monotonically increasing group-local generation;
- phase;
- policy version or digest;
- opening wall time in milliseconds;
- last selection-relevant admission time in milliseconds;
- quiescence deadline in milliseconds;
- absolute wall deadline in milliseconds;
- base epoch;
- pinned base-state reference and digest;
- frozen-at time, when applicable;
- completion or failure metadata;
- aggregate bounded-work counters needed for safety limits.

Candidate phases are:

```text
Collecting -> Frozen -> Resolving -> Completed
```

Do not introduce a third fail-closed group state named `RecoveryRequired`. The existing precedence remains:

1. a durable protocol `Unrecoverable` halt blocks all group mutation;
2. hydration/storage quarantine blocks processing until explicit repair; and
3. only then may an active pass run.

Missing required retained state enters the existing protocol `Unrecoverable` path. Structurally corrupt pass storage
uses a quarantine-shaped explicit repair path that preserves the pass and its inputs. Whether this reuses the exact
hydration quarantine record or a pass-specific blocked reason must be decided in the storage review, but it must share
the same operator-facing repair model rather than create a fourth recovery mechanism.

### 7.2 Frozen membership

Each frozen member should contain the minimum data needed to prove and reproduce its admission:

- canonical engine input identifier;
- digest of the canonical peeled MLS bytes;
- authenticated sender and epoch metadata required by selection;
- candidate-parent reference;
- dependency references;
- relevant validation result or version;
- deterministic ordering key; and
- storage reference to the immutable input material.

The digest must cover canonical peeled MLS input, not incidental Nostr event or transport framing bytes. Exact signed
events used for relay fanout remain in the publication/fanout subsystem introduced by the merged master.

### 7.3 Snapshot references

The frozen manifest should pin:

- the current base MLS state;
- retained candidate-parent states;
- dependency state used by selection; and
- the policy under which selection runs.

Prefer pass-owned references and pruning pins over duplicating complete group snapshots where the existing snapshot
model already provides immutable, digestible state. If a dedicated snapshot is necessary, it must be explicitly
state-only and must exclude queue, maintenance, publication, fanout, and pass records.

### 7.4 Storage constraints

The final schema should enforce, where possible:

- one group-local generation number per group;
- no more than one current collecting/frozen/resolving pass for a group;
- immutable frozen membership;
- unique membership of an input in a pass generation;
- valid phase transitions;
- referential integrity between a pass and its frozen members;
- retained snapshot pins while a pass is active; and
- transactional finalization.

SQLite constraints supplement engine validation; neither layer should assume the other is sufficient.

## 8. Transaction boundaries

### 8.1 Open and first admission

One transaction must:

1. Verify there is no conflicting local group mutation.
2. Classify the input as convergence-eligible.
3. Allocate the next generation.
4. Capture the base-state reference.
5. Persist opening time, initial quiescence deadline, and immutable absolute deadline.
6. Admit the first input.

Failure leaves neither an empty pass nor a half-admitted input.

### 8.2 Later pre-cutoff admission

One transaction must:

1. Load and validate the collecting pass.
2. Sample admission time.
3. Calculate the current effective cutoff.
4. If the cutoff has already been reached, freeze the current pass before retaining this input for a later generation.
5. Otherwise insert the input membership.
6. If and only if the input is selection-relevant, persist its admission as the new quiescence anchor without changing
   the absolute deadline.

Duplicate membership is classified before convergence or handled idempotently without altering the pass.

### 8.3 Cutoff and freeze

One transaction must:

1. Serialize against admission.
2. Verify that selection-relevant quiescence, the absolute maximum, or a fail-closed recovery condition requires
   cutoff.
3. Capture the complete eligible membership.
4. Pin base, candidate-parent, and dependency state.
5. Persist the frozen manifest and its aggregate digest.
6. Persist the cutoff cause: `Quiescence`, `MaxPassDeadline`, or `FailClosed`.
7. Transition the phase from `Collecting` to `Frozen`.

Nothing may join the pass after this transaction commits.

### 8.4 Post-cutoff arrival

An input admitted while generation `N` is frozen or resolving is retained for generation `N+1`. It must not:

- mutate `N`;
- cause `N` to consult new dependencies;
- change `N`'s winner;
- start `N+1` against an unstable base state; or
- become stale merely because it arrived during resolution.

The implementation may store it as unassigned retained input until the next pass is allowed to open.

### 8.5 Final application

One logical transaction must:

1. Revalidate the frozen pass header and base-state identity.
2. Apply the selected canonical transition.
3. Record accepted, deferred, stale, or invalidated dispositions.
4. Emit the appropriate internal group-state invalidation/evolution events.
5. Mark the pass complete.
6. Release pass-owned snapshot pins only when they are no longer needed.
7. Make the next-generation retained inputs eligible for scheduling.

If the storage provider cannot express the entire transition in one database transaction, the design must use the
repository's intent-first and compensation discipline. It must never confirm a transition that reached no durable
state.

## 9. Engine state machine

### 9.1 Pre-convergence classification

The engine should classify these conditions before attempting pass admission:

- `duplicate`;
- `own_echo`;
- `wrong_recipient`; and
- `unknown_group`.

They are not stale convergence candidates. Direct ingest and wrapped/session ingest must call the same classifier.

### 9.2 Admission gate

An otherwise eligible input can open or join a pass only when:

- the group base state is stable;
- there is no prepared or publishing local group evolution;
- there is no conflicting local mutation authority;
- the durable pass record is internally consistent; and
- required authenticated metadata is already available.

If the group is temporarily unstable, retain the input durably. Do not discard it and do not open a pass whose base
state may change underneath it.

### 9.3 Frozen resolution

Resolution must receive an immutable value representing the frozen manifest. It should not receive a storage query
capability that can enumerate newly arrived convergence input.

Existing selection behavior should first be extracted behind a single-shot immutable interface resembling:

```rust
resolve_frozen_pass(
    pinned_policy,
    pinned_base,
    frozen_inputs,
    pinned_candidate_state,
    work_budget,
) -> Result<FrozenPassResolution, FrozenPassError>
```

This is illustrative, not a prescribed public API.

The error must distinguish at least total safety-limit exhaustion, missing frozen dependency, snapshot/digest mismatch,
and unrecoverable local consistency failure.

### 9.4 Start single-shot; add slicing only if fairness requires it

The durable source of truth is the immutable pass, not an evolving serialized search cursor.

The first implementation should preserve the existing bounded replay budget and 16-pass drain cap while resolving one
immutable frozen pass in a single scheduler turn. The multi-group fairness test must measure the worst-case effect of
that turn.

If the acceptance test demonstrates that one bounded single-shot pass can still starve another ready group, then split
resolution into deterministic in-memory slices. Between slices, canonical state remains unchanged, the scheduler gives
another group a turn, the frozen manifest remains durable, and newly arrived input remains assigned to a later
generation.

In either design, a crash restarts resolution deterministically from the frozen manifest. A durable internal cursor
should be introduced only if profiling proves reconstruction unacceptably expensive and a separately reviewed design
can preserve determinism and torn-write safety.

### 9.5 Failure behavior

Failures must not silently reopen collection or fall back to mutable live replay.

- A transient runtime interruption leaves the pass restartable.
- If optional slicing is required, slice exhaustion yields to the scheduler without changing canonical state.
- A total safety-limit exhaustion places the pass in a safe blocked/recovery state.
- A snapshot digest mismatch blocks mutation and preserves the frozen evidence.
- A missing dependency that was not frozen is deferred to a later pass.
- A storage invariant violation does not delete the pass or its inputs.

## 10. Integration with durable self-update and maintenance

PR #1103 introduces a durable semantic group-evolution lifecycle independently from exact transport fanout. Issue #806
must preserve that separation.

### 10.1 Prepared local evolution blocks pass opening

If a self-update or other local group evolution is `Prepared`, `Attempting`, or awaiting publication resolution:

- the group base state is not available for a new convergence pass;
- incoming convergence input is retained durably;
- no pass collection clock begins until the local evolution resolves; and
- restart recovery continues the existing exact-event publication lifecycle.

This follows the issue's "first eligible input" language: retained input becomes eligible only when the group has a
stable base state.

### 10.2 Active convergence blocks maintenance mutation

While a pass is collecting, frozen, or resolving:

- automatic self-update remains an obligation but cannot stage an MLS mutation;
- manual self-update receives the existing queued/retryable disposition appropriate to final master;
- maintenance may perform unrelated non-group-mutating work if it cannot delay the convergence cutoff;
- exact transport fanout retries for already-confirmed state remain governed by their own durable lifecycle; and
- no maintenance code may bypass the engine's mutation-ownership gate.

The final-master audit must replace any broad `has_pending_convergence_inputs` check with the precise active-pass and
retained-input semantics introduced here without weakening send-path preflight. That predicate is used by engine,
session, account, app-runtime, maintenance, and simulator paths; several call sites gate whether a send may proceed.
The refactor must preserve the behavior covered by
`bob_send_after_quiescence_replays_deferred_post_promote_messages` in
`issue_494_admin_promote_delivery.rs`.

### 10.3 Superseded self-update reconciliation

If convergence invalidates a branch containing a previously confirmed self-update:

- preserve the merged `GroupStateInvalidated` event flow;
- preserve `SupersededByConvergence` reconciliation;
- determine whether the selected branch already rotated the local leaf;
- complete or re-arm the maintenance obligation accordingly; and
- never resend or reconstruct an exact signed event from candidate replay.

### 10.4 Local-intent fairness

After convergence settlement, the adopted fairness rule gives one already-queued, admin-authorized user group-state
intent an opportunity before an inbound-only next pass.

Automatic maintenance self-update is not that user-authorized fairness intent. It must not consume the slot or jump
ahead of it.

The ordering is:

1. Complete and commit the current frozen pass.
2. Reconcile invalidated local evolution and maintenance state.
3. Give one eligible queued authorized user group-state intent its preparation opportunity.
4. If no such intent runs, allow the next retained inbound generation to open.
5. Run automatic self-update only after convergence and user-intent fairness permit it.

## 11. Account-runtime scheduling

### 11.1 Authority

The application runtime schedules wakeups; it does not decide collection membership or cutoff. Durable engine state is
authoritative.

### 11.2 Earliest cutoff

Current `ScheduledConvergence` is one global timer plus a set of groups. Input for any group resets that timer and a
wakeup drains every pending group. Issue #806 requires replacing it with per-group cutoff state and a ready queue, not
tuning the existing shared delay.

The replacement should:

- query or receive each active group's effective cutoff;
- arm one monotonic runtime wakeup for the earliest effective cutoff;
- update only the affected group's quiescence term when selection-relevant input arrives;
- never let group B move group A's cutoff;
- reconstruct it from durable state after restart;
- process all expired groups fairly; and
- re-arm after every bounded unit of work.

Freeze must also be driven by the next engine admission if the runtime wakes late: the admission transaction checks the
durable cutoff before deciding membership. Retry or unsettled backoff may delay another resolution attempt, but it may
not extend collection membership or postpone the durable freeze decision by up to the current 60-second retry ceiling.

The existing 100 millisecond settlement margin must not become part of cutoff semantics. The new scheduler should arm
from the exact remaining duration and safely re-arm if it wakes early; no margin may extend the absolute cap or admit
post-cutoff input.

### 11.3 Fair bounded work

A ready queue should initially give each group one bounded single-shot frozen resolution before rotating. The existing
replay budget and drain cap provide the initial bound.

If the multi-group acceptance test shows that this bound is still too large, introduce deterministic in-memory slices
measured in replay/selection operations rather than elapsed wall time.

Optional slice fairness does not replace the total replay/work safety bound: slicing prevents one group from starving
another, while the total bound prevents adversarial input from creating unbounded computation.

### 11.4 Maintenance ordering

The maintenance interval introduced by PR #1103 must not become the convergence clock.

When convergence and maintenance are both ready:

- an expired convergence cutoff is processed first;
- one bounded convergence turn runs;
- the scheduler may rotate among other ready convergence groups;
- maintenance runs only where it cannot stage a conflicting group mutation; and
- long maintenance work is itself bounded so it cannot delay convergence wakeups.

The final merged `biased` worker selection and sync behavior must be audited for this property.

## 12. Outcome taxonomy

The protocol-facing taxonomy should be corrected with the smallest coherent API change.

Current master exposes one serialized `cgka_traits::ingest::StaleReason` enum that mixes pre-convergence routing/dedupe
conditions with canonical local states. It is also mapped into the forensic JSONL schema. Phase 6 is therefore a typed
API and forensic-schema migration, not a label-only cleanup.

### 12.1 Pre-convergence categories

- duplicate;
- own echo;
- wrong recipient;
- unknown group.

These outcomes never become convergence members and are not reported as stale convergence candidates.

### 12.2 Convergence dispositions

Frozen-pass work is classified as:

- accepted;
- deferred;
- stale; or
- invalidated.

Exact names should follow the adopted specification and existing final-master type conventions.

### 12.3 Local canonical state

`SelfEvicted` is behavioral today: authenticated local eviction triggers "realizing removal", emits the self-removed
notification, and marks the local group copy removed. That behavior must be preserved as a local canonical transition
even though `SelfEvicted` must not remain a protocol convergence disposition.

The convergence reorg path must preserve its existing coupling to the removed marker so a later input cannot re-emit
the departure notification.

### 12.4 API scope

Prefer:

- one shared classifier used by direct and wrapped ingest;
- narrow changes to existing result types;
- exhaustive conversion tests; and
- explicit internal-to-protocol mapping;
- an explicit compatibility/version decision for the Marmot forensics JSONL schema; and
- preservation of the realizing-removal side effect independently from the protocol outcome.

Do not add a repository-wide public outcome stream or binding expansion unless the final-master call graph demonstrates
a concrete consumer requirement.

## 13. Observability and diagnostics

Diagnostics must follow the repository privacy contract.

Safe aggregate fields include:

- pass phase;
- number of frozen inputs;
- number of deferred post-cutoff inputs;
- resolution turn count and, if optional slicing is enabled, slice count;
- aggregate candidate count;
- cutoff cause: quiescence, maximum pass deadline, or fail-closed recovery;
- recovery/rebuild count;
- work-budget exhaustion; and
- aggregate scheduling delay.

Do not log:

- account identifiers;
- group identifiers;
- input or message identifiers;
- relay URLs;
- public keys;
- payloads;
- ciphertext or plaintext;
- snapshot bytes; or
- key material.

Metrics and traces are diagnostic only. They must never become correctness inputs.

## 14. Implementation phases

### Phase 0 — final-master rebaseline

1. Confirm merged PR #1103 is present and wait for PR #1107 to rebase and merge.
2. Fetch the settled `origin/master`.
3. Record the two merge commits and any follow-up conflict-resolution commits.
4. Create a clean isolated worktree and branch from that exact master.
5. Re-read the adopted spec and issue acceptance criteria.
6. Reinspect the four overlapping prerequisite files.
7. Inventory final policy, clock, maintenance, fanout, queue, snapshot, and storage APIs.
8. Confirm that `0035` is still the next migration number on final master.
9. Run a clean baseline test suite.
10. Update this plan if the merged architecture differs from the assumptions above.

No #806 implementation starts until this phase is complete.

### Phase 1 — policy and clock contract

1. Add the named adopted `max_convergence_pass_ms = 5000` constant to the policy established by #1107.
2. Extend release-mode pinned-policy assertions.
3. Add a required millisecond wall-clock method or trait and update every implementation explicitly; do not provide a
   seconds-derived default.
4. Add deterministic cutoff and restart-continuity unit tests.
5. Document and test the two-term quiescence/absolute cutoff comparison.

### Phase 2 — storage model and migration

1. Add pass header, membership, and snapshot-pin storage types.
2. Add transactional trait operations rather than exposing table-shaped CRUD to the engine.
3. Implement the greenfield SQLite scheduling schema and constraints, expected as migration `0035`.
4. Add atomic open, admit, freeze, retain-next-generation, finalize, and recovery operations.
5. Add migration, reopen, corruption, and torn-write tests.
6. Verify that snapshot serialization excludes workflow and external-side-effect records.

### Phase 3 — engine collection boundary

1. Route all convergence-eligible admission through the durable pass API.
2. Perform pre-convergence classification before admission.
3. Open immutable absolute and restartable quiescence terms on the first eligible input.
4. Restart only quiescence for newly admitted selection-relevant input.
5. Freeze atomically at the earlier normal cutoff or a fail-closed recovery cutoff.
6. Assign post-cutoff input to retained next-generation work.
7. Hydrate collecting and frozen passes on restart.
8. Remove mutable live-batch enumeration from the resolution path.

### Phase 4 — frozen resolution and fairness

1. Adapt existing selector/replay behavior to accept only a frozen manifest.
2. Add state-only snapshot pinning and digest validation.
3. Land bounded single-shot frozen resolution using the existing replay budget and drain cap.
4. Replace global `ScheduledConvergence` timing with per-group cutoffs and a ready queue.
5. Preserve the existing total replay safety budget.
6. Commit only the final selected transition and dispositions.
7. Add crash-and-rebuild coverage for every phase.
8. Add deterministic in-memory slicing only if the multi-group fairness acceptance test fails.

### Phase 5 — maintenance and local-intent integration

1. Add one mutation-ownership gate shared by convergence and durable local evolution.
2. Retain inbound input without opening a pass during pending publication.
3. Prevent maintenance from staging self-update during an active pass.
4. Preserve exact fanout and maintenance reconciliation.
5. Implement user-authorized local-intent fairness before the next inbound generation.
6. Preserve send-path preflight gating while splitting active-pass from retained-input predicates.
7. Audit the final account-worker selection order and maintenance tick.

### Phase 6 — outcome normalization

1. Introduce the smallest shared classification types required by final master.
2. Remove pre-convergence conditions from stale convergence reporting.
3. Separate `SelfEvicted` realizing-removal behavior from protocol-facing convergence outcomes.
4. Update or version the Marmot forensics JSONL mapping explicitly.
5. Test direct, engine, session, account, app-runtime, forensic, and binding conversions as applicable.

### Phase 7 — conformance, formal model, and documentation

1. Add deterministic-clock acceptance tests.
2. Add storage restart and failure-injection tests.
3. Extend multi-client simulator/vector scenarios.
4. Update the matching Tamarin scenario or model if the frozen boundary changes a modeled transition.
5. Update engine architecture/current-state docs.
6. Run targeted suites, `just fast-ci`, and the full `just ci` matrix where practical before review.

## 15. Test plan

### 15.1 Clock and cutoff

- First eligible input opens one quiescence deadline and one immutable absolute deadline.
- A quiet single-input pass freezes after 1000 milliseconds rather than waiting 5000 milliseconds.
- Selection-relevant input one millisecond before quiescence restarts quiescence.
- Non-selection-relevant input does not restart quiescence.
- Continuous selection-relevant arrivals restart quiescence but never extend the 5000 millisecond absolute deadline.
- Input admitted one millisecond before either effective cutoff joins the current pass.
- Input admitted exactly at either effective cutoff joins the next generation.
- Input admitted one millisecond after either effective cutoff joins the next generation.
- A wall-clock change during a live process does not move the monotonic cutoff terms.
- Restart with time remaining schedules only the remainder.
- Restart after expiry freezes immediately.
- Backward wall movement fails closed without granting extra time.
- Invalid or overflowing persisted time fails closed.
- A deliberately seconds-quantized test clock cannot satisfy the millisecond clock contract.

### 15.2 Frozen membership and determinism

- Frozen membership is immutable.
- Post-cutoff arrival permutations do not affect the current winner or dispositions.
- Canonical peeled input digest is stable across transport-envelope differences.
- Manifest digest mismatch blocks mutation.
- Candidate-parent state cannot be pruned while pinned.
- Newly fetched or late dependency state is not admitted into the frozen pass.
- A missing frozen dependency fails safely or is deferred according to the adopted rule.

### 15.3 Restart and torn writes

- Restart during `Collecting` preserves both cutoff terms and membership.
- Restart after either effective cutoff freezes the original membership.
- Restart during `Frozen` reproduces the same result.
- Restart during resolution rebuilds from the same manifest, including between slices if optional slicing is enabled.
- Restart during final application produces one canonical result.
- Failure injection at each storage write boundary leaves a valid prior or next state, never an unowned intermediate
  mutation.
- Completed-pass cleanup cannot delete retained next-generation input.

### 15.4 Multi-group fairness

- A large pass for group A cannot prevent an expired pass for group B from receiving work.
- Sustained selection-relevant traffic in group B cannot move group A's quiescence or absolute cutoff.
- A runtime wakeup arriving late freezes the original batch before resolving or admitting later input.
- Retry backoff cannot delay the durable cutoff or add membership after it.
- Every ready group receives a bounded turn under sustained load.
- Total adversarial replay limits still apply.
- An unrecoverable or quarantined group does not block unrelated groups.
- Scheduling delay is bounded independently of the maintenance interval.

### 15.5 Maintenance and publication

- A prepared self-update prevents pass opening.
- Inputs arriving during pending publication are retained.
- Publication completion makes retained input eligible without changing its stored arrival identity.
- An active convergence pass prevents automatic self-update preparation.
- A manual self-update receives the correct queued/retryable disposition.
- Candidate replay does not alter durable fanout records.
- Candidate replay does not alter maintenance obligations.
- Convergence invalidation preserves `SupersededByConvergence` reconciliation.
- A selected branch that already rotated the local leaf completes the appropriate obligation.
- Automatic maintenance cannot consume the authorized user-intent fairness slot.

### 15.6 Outcome taxonomy

- Duplicate is rejected before convergence.
- Own echo is rejected before convergence.
- Wrong recipient is rejected before convergence.
- Unknown group is rejected before convergence.
- Accepted, deferred, stale, and invalidated map consistently through all owning seams.
- `SelfEvicted` is absent from protocol-facing convergence outcomes.
- Authenticated self-eviction still performs realizing removal exactly once.
- The forensic schema change is versioned or proven backward-compatible.
- Direct and wrapped ingest produce equivalent outcome classes.

### 15.7 Regression and conformance

- Existing selector-ordering tests remain unchanged and green.
- Existing witness-scoring tests remain unchanged and green.
- Existing rollback-horizon tests remain unchanged and green.
- Existing pending-publication and exact-fanout tests remain green.
- Existing maintenance restart tests remain green.
- `bob_send_after_quiescence_replays_deferred_post_promote_messages` remains green.
- Simulator scenarios converge under arrival permutations and restart.
- Release builds reject a non-v1 `max_convergence_pass_ms`.

## 16. Validation commands

Exact targeted commands should be confirmed after final master settles. The expected validation shape is:

```sh
just fast-ci
cargo test -p cgka-engine
cargo test -p cgka-session
cargo test -p storage-sqlite
cargo test -p marmot-account
cargo test -p marmot-app
cargo test -p cgka-conformance-simulator
cargo test -p marmot-forensics
```

For formal-model changes:

```sh
just tamarin
```

Full local CI parity:

```sh
just ci
```

After #1107 merges, run its concrete release-mode pin target:

```sh
just test-convergence-policy-pin
```

This executes `crates/cgka-engine/tests/convergence_policy_pin.rs` with debug assertions disabled.

## 17. Suggested commit boundaries

Keep the implementation reviewable and bisectable. These are intended as independently mergeable PR-sized units, not
necessarily single commits:

1. **Policy and time contract**
   - v1 maximum pass constant;
   - release assertion;
   - millisecond clock seam;
   - deterministic time tests.
   - Independently mergeable before the storage work.

2. **Durable pass storage**
   - shared storage types and transactional trait;
   - SQLite migration and implementation;
   - migration/restart/failure tests.
   - Independently mergeable with no production callers before engine cutover.

3. **Engine collection boundary**
   - durable admission;
   - quiescence and immutable absolute cutoff terms;
   - atomic freeze;
   - next-generation retention.

4. **Frozen resolution and scheduler**
   - immutable resolution input;
   - bounded single-shot resolution;
   - per-group fairness;
   - restart reconstruction.
   - Optional slicing only if acceptance evidence requires it.

5. **Maintenance and local-intent integration**
   - mutation ownership;
   - self-update gating;
   - invalidation reconciliation;
   - fairness ordering.

6. **Outcome taxonomy**
   - pre-convergence classification;
   - protocol disposition mapping;
   - seam compatibility tests.

7. **Conformance and documentation**
   - simulator/vector/formal coverage;
   - architecture docs;
   - final regression evidence.

A commit boundary may move if the final-master APIs make an intermediate commit uncompilable, but each commit should
still leave the repository in a coherent, testable state.

## 18. Risk register

| Risk | Failure mode | Mitigation |
| --- | --- | --- |
| 5000 ms cap replaces quiescence | Every quiet group adds roughly four seconds of avoidable latency | Freeze at the earlier of quiescence or absolute cap; test both boundaries |
| Millisecond clock defaults from seconds | Exact boundary tests pass vacuously and production cutoffs are quantized | Require every millisecond clock implementation explicitly |
| Moving deadline survives below the app scheduler | Clients collect different batches | Make engine/storage admission authoritative; test continuous arrival |
| Global app timer remains | Traffic in group B postpones group A | Replace it with per-group cutoffs plus an earliest-deadline ready queue |
| Retry backoff delays cutoff | Runtime can arrive up to 60 seconds late | Freeze on admission and preserve the durable cutoff independently from retry |
| Frozen pass stores only input IDs | Candidate-parent or validation state changes during resolution | Pin complete authenticated selection inputs and state references |
| Restart grants a new window | Busy clients diverge after process interruption | Persist original cutoff terms; hybrid monotonic/wall recovery; fail closed |
| Resolution mutates state incrementally | Crash exposes a half-selected branch | Probe from isolated state; commit only the final result |
| Durable cursor becomes another workflow engine | Torn writes and incompatible recovery paths | Keep resolution cursor rebuildable and in memory initially |
| Snapshot captures maintenance/fanout state | Replay duplicates or erases external effects | Use state-only snapshots and explicit exclusion tests |
| Convergence races self-update | Two owners mutate one MLS group | Enforce one durable mutation owner and mutual exclusion |
| Maintenance steals fairness slot | User-authorized intent starves behind automatic rotation | Distinguish user intent from maintenance obligation |
| One group monopolizes resolution | Other groups miss progress/deadlines | Test bounded single-shot behavior first; add deterministic slicing only if required |
| Outcome refactor expands across bindings or silently changes forensic JSONL | High-risk API/schema churn | Implement the narrowest shared classifier and make schema compatibility explicit |
| `SelfEvicted` label removal drops behavior | Realizing removal is no longer emitted or persisted | Preserve the local transition and exactly-once side effect outside protocol dispositions |
| Corrupt pass is silently discarded | Inputs are recollected under a different base | Reuse quarantine/unrecoverable repair discipline and preserve evidence |
| Release configuration remains tunable | Honest clients permanently fork | Extend PR #1107's pinned release-policy assertions |
| Migration assumes current numbering | Merge collision or invalid upgrade path | Expect `0035`, but confirm it remains next on the implementation branch |

## 19. Review gates

Implementation should not proceed past each gate without evidence.

### Gate A — baseline

- PR #1103 is confirmed on master and PR #1107 is rebased and merged.
- Settled master is green.
- The merged architecture matches or updates this plan.
- The normative spec has been reread.

### Gate B — storage design

- Transaction boundaries and constraints are reviewed.
- Snapshot inclusion/exclusion is explicit.
- Restart and corrupt-state behavior is agreed.
- Migration works from the immediately preceding production schema.

### Gate C — engine behavior

- Exact quiescence and absolute-cap semantics are demonstrated with deterministic millisecond tests.
- Resolution cannot enumerate mutable live input.
- No external-side-effect record participates in replay.
- Existing branch selection behavior remains stable.

### Gate D — scheduler and maintenance

- Multi-group fairness is measured.
- The global convergence timer has been replaced by per-group cutoff state.
- Convergence deadlines are independent of maintenance polling.
- Mutation ownership and self-update reconciliation are demonstrated.
- The authorized user-intent fairness slot is preserved.

### Gate E — release readiness

- Targeted and full validation are green.
- Release-policy assertions include the new 5000 millisecond invariant.
- Simulator/restart/failure scenarios pass.
- Architecture and operational diagnostics are current.

## 20. Questions for reviewers

Reviewers should focus especially on these decisions:

1. Is persisting immutable pass state while rebuilding the resolution cursor after restart sufficient, or is there a
   demonstrated need for a durable resolution checkpoint?
2. Does the final self-update lifecycle have any state in which inbound convergence may safely collect before
   publication resolution, or should all such input remain unassigned?
3. Are the proposed state-only snapshot references sufficient to reproduce candidate-parent authorization and
   dependency state without copying unrelated workflow records?
4. What should the operator-visible recovery path be for a digest mismatch or structurally corrupt frozen pass?
5. Is the authorized local-intent fairness ordering correctly separated from automatic maintenance?
6. Does the existing replay budget and 16-pass drain cap pass the multi-group fairness test? If not, what deterministic
   unit of work best bounds a resolution slice without making results platform-dependent?
7. Can the final storage transaction atomically apply canonical state, dispositions, pass completion, and snapshot-pin
   release, or is an intent/compensation record required?
8. Which outcome types are already public through UniFFI, the daemon, or agent control after PR #1103, and what is the
   smallest compatible taxonomy correction?
9. Should the required millisecond clock be a new trait or an explicit required method beside
   `WallClock::now() -> Timestamp`?
10. Which Tamarin property or trace should explicitly model frozen membership and post-cutoff deferral?

## 21. Definition of done

Issue #806 is complete only when:

- the first eligible input creates one restartable quiescence term and one immutable 5000 millisecond absolute cap;
- a quiet pass freezes after 1000 milliseconds without selection-relevant input;
- continuous selection-relevant arrivals can restart quiescence but cannot extend the absolute cap;
- exact cutoff membership is deterministic;
- the complete resolution snapshot is frozen durably;
- restart preserves both cutoff terms and the frozen result;
- post-cutoff input is retained for a later pass;
- branch resolution uses no mutable live input;
- no candidate replay can rewind or duplicate maintenance/publication state;
- self-update and convergence cannot concurrently own group mutation;
- multiple busy groups make bounded progress;
- traffic in one group cannot move another group's cutoff;
- direct and wrapped ingest expose the adopted outcome classes;
- realizing removal remains correct when `SelfEvicted` is removed from protocol-facing dispositions;
- release builds enforce the adopted v1 constant;
- all required engine, storage, runtime, simulator, formal, and CI validation passes; and
- the implementation and architecture documentation describe the same behavior.

The intended result is one small, durable authority boundary around the existing convergence engine—not a second
general orchestration framework alongside durable maintenance.
