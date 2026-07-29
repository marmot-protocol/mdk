# Convergence settling remediation plan

Status: DRAFT v2 for review — 2026-07-29
Supersedes: v1 of this document (which proposed deleting the fairness reservation and
softening integrity failure; both reversed after review — see "Decision history" at the end).

Audience: the implementing agent. This document specifies current behavior, target behavior,
exact code sites, edge cases, and required tests for each PR. Read
`crates/cgka-engine/AGENTS.md` and
`docs/marmot-architecture/further-context/issue-806-frozen-convergence-pass-plan.md` first.

---

## 1. Background and root cause

Convergence settling latency regressed after two changes:

- **PR #1110** (2026-07-25, closes mdk#806): durable frozen convergence passes, including a
  persisted post-completion reservation (`fairness_slot_available`) that holds the next pass
  open for one queued local intent.
- **PR #1158** (2026-07-28): app messages sent while transport is inactive are now durably
  queued (`queue_app_message`), making queued outbound intents a routine steady state.

### 1.1 The defect

The spec rule behind the reservation
([convergence.md](https://github.com/marmot-protocol/marmot/blob/master/protocol-core/convergence.md#L97-L103),
adopted to close [marmot#375](https://github.com/marmot-protocol/marmot/issues/375)) is
scoped to **one already-queued, admin-authorized local group-state intent**. The MDK
implementation over-broadened it: `load_or_open_convergence_pass`
(`crates/cgka-engine/src/distributed_convergence.rs`, first branch) parks the previous
`Completed` pass whenever `fairness_slot_available && !queued.is_empty()` — where `queued` is
**all** queued outbound intents, including ordinary app messages. While parked:

- newly arrived commits are only *retained* (`admit_stored_message_to_convergence_pass`
  returns `Retained` because the pass phase is not `Collecting`) — no pass opens, no
  quiescence clock starts;
- `converge_stored_openmls_messages` short-circuits at the
  `pass.phase == Completed → settled_empty_result` branch, reporting `Settled` while retained
  work sits unprocessed.

The park is released only by a drain consuming the reservation. Combined with #1158's
routine queuing, an inbound commit arriving while any app message is queued needs multiple
scheduler cycles to apply.

**Hypothesized magnitudes** (to be confirmed by the paused-time test in PR A, not asserted as
fact): ~3 cycles (~3.3 s) to apply the commit and ~4 (~4.4 s) to flush the send, versus
~1.1 s before #1110. If drains fail (flaky transport), inbound convergence waits behind the
queue on retry backoff up to 60 s.

### 1.2 The scheduler defect (independent of the above)

`ScheduledConvergence` in `crates/marmot-app/src/runtime/account_worker.rs`:

- `schedule_after_pass` / `schedule_unsettled_groups` re-arm at the full
  `quiescence + margin` (~1.1 s) regardless of the pass's actual remaining cutoff. A tick
  that lands mid-window (normal whenever a selection-relevant admission moved the pass
  deadline) burns a full extra cycle.
- Every such in-window tick increments `unsettled_rearm_attempts`; after
  `CONVERGENCE_UNSETTLED_MAX_REARMS` (10) the group is demoted to exponential error backoff
  (1 s → 60 s) even though nothing is wrong.
- The client wrappers swallow errors:
  `has_pending_convergence_inputs(...)` → `unwrap_or(false)` and
  `prepare_convergence_cutoff_delay_ms(...)` → `.ok().flatten()`
  (`crates/marmot-app/src/client/sync.rs:25-45`). A storage error therefore reads as "no
  pending work" and `note_success` cancels future wakeups — a liveness bug.

## 2. Scope decision

**Keep, unchanged** (spec-adopted, working):

- Durable pass lifecycle (Collecting → Frozen → Resolving → Completed), quiescence (1000 ms),
  absolute deadline (5000 ms), immutable frozen membership, restart rebasing, atomic
  admit-with-row, ingest outcome taxonomy, #1158's durable outbound queue.
- The **one-attempt admin reservation itself.** marmot#375 is a self-preservation attack: the
  member being removed floods no-authorization self-update commits (~1/sec) to keep the group
  perpetually unsettled; since Remove preparation requires `Stable`, they block their own
  removal and the group goes read-only. The absolute deadline bounds each pass; the
  generation-boundary reservation guarantees the admin's Remove one preparation attempt per
  generation. Removing the rule would require a replacement answer to #375. **No spec change.**
- The `Unrecoverable` posture on frozen-member integrity failure. Rows are content-addressed;
  a digest mismatch means storage corruption or tampering. Weakening the response (v1's
  "abandon and terminalize" idea) mutates the batch after cutoff, which the issue-806 risk
  register explicitly warns against. Withdrawn.

**Fix:**

- Scope the reservation to admin-authorized group-state intents (the spec's actual rule).
- App messages must never delay pass admission.
- Open the next pass immediately after the reservation attempt (spec: "the scheduler
  proceeds"), not one scheduler cycle later.
- Scheduler: schedule against real cutoffs, stop penalizing in-window ticks, propagate errors.

**Defer:** drain-loop refactor (PR B), frozen-snapshot completeness (PR C).

---

## 3. PR A — settling fix (urgent, ships alone)

### 3.1 Engine: scope the reservation

**Classifier.** `is_admin_group_state_fairness_intent`
(`crates/cgka-engine/src/message_processor/mod.rs:1348`) already matches exactly the
admin-authorized group-state evolutions
(`Invite | RemoveMembers | UpdateAppComponents | UpdateGroupData | EnableDisbanding |
Disband`). Rename to `is_admin_group_state_intent`, make it `pub(crate)`, and move it where
`distributed_convergence.rs` can call it (e.g. re-export from `message_processor`). It is the
single classification chokepoint — do not duplicate the match arms anywhere.

**`load_or_open_convergence_pass`** (`distributed_convergence.rs`, first branch). Current:

```text
if previous is Completed && fairness_slot_available:
    queued = list_queued_outbound_intents(group)
    if !queued.is_empty(): return the Completed pass   # parks admission
    else: persist fairness_slot_available = false      # dormant-slot consumption
```

Target:

```text
if previous is Completed && fairness_slot_available:
    queued = list_queued_outbound_intents(group)
    if queued.any(is_admin_group_state_intent): return the Completed pass
    else: persist fairness_slot_available = false
```

Consequences to preserve/verify:

- With only app messages queued, the dormant reservation is consumed on the next
  load-or-open and a new pass opens normally from retained trigger input. App messages can
  no longer park admission — this is the regression fix.
- With an admin intent queued, semantics are exactly today's: admission parks until the
  drain grants the one attempt. That park is now rare (admin intents only).

**Drain (`converge_and_drain_queued_outbound_intents`, `message_processor/mod.rs`).** Keep
the existing structure in this PR (the cleanup is PR B). Required behavioral changes only:

1. The fairness branch inside the record loop
   (`if fairness_slot_available && !is_admin_group_state_intent(...) { continue; }`) and the
   consume-on-error / consume-after-attempt logic stay as-is — they already implement
   "one attempt, consumed win or lose", matching the spec's "proceeds rather than waiting
   indefinitely".
2. After the reservation is consumed (any of the three consumption sites in this function),
   call `self.schedule_pending_convergence_group(group_id)` so the next inbound generation is
   scheduled *immediately* rather than discovered a cycle later. The app worker drains
   `take_pending_convergence_groups()` after every command/event and computes the real cutoff
   via `prepare_convergence_cutoff_delay_ms`, so this closes the generation-handoff gap.
3. `advance_convergence_inputs_until_settled`: keep the fairness early-return
   (`fairness_slot_available → Ok(true)`) — with the scoped park it is reachable only when an
   admin intent is actually queued, which is the intended reservation flow.

**No changes** to `DurableConvergencePass` (field name, serde layout, storage schema all stay;
records remain serde_json blobs so nothing to migrate).

### 3.2 App runtime: honest scheduling with error propagation

**New structured state.** Add to `AppClient` (in `crates/marmot-app/src/client/sync.rs`,
replacing the two swallowing wrappers at lines 25-45):

```rust
pub(crate) enum ConvergenceScheduleState {
    /// No active pass, no pending inputs. Cancel wakeups.
    Idle,
    /// A pass is collecting; wake when its cutoff elapses.
    Collecting { remaining_ms: u64 },
    /// A pass is frozen/resolving (or cutoff already elapsed); run now.
    Ready,
    /// Pending inputs exist but no pass can open yet (epoch not Stable,
    /// admin reservation parked, missing trigger). Re-check on fallback delay.
    PendingUnopenable,
}

pub(crate) fn convergence_schedule_state(
    &mut self, group_id: &GroupId,
) -> Result<ConvergenceScheduleState, AppError>
```

Implementation: call `prepare_convergence_cutoff_delay_ms` (which may legitimately open a
pass — it is a command); map `Some(0)` → `Ready`, `Some(d)` → `Collecting { d }`, `None` →
consult `has_pending_convergence_inputs` for `PendingUnopenable` vs `Idle`. **Propagate every
error.** Delete the `unwrap_or(false)` / `.ok().flatten()` wrappers; update the two other
call sites (`account_worker.rs:650`, `client/mod.rs:2696`) accordingly.

**Worker changes** (`account_worker.rs`):

- `ScheduledConvergence::schedule_after_pass(&mut self, group_id, state: &ConvergenceScheduleState)`:
  - `Idle` → `note_success`.
  - `Collecting { remaining_ms }` → arm at
    `remaining_ms + CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS`; **do not** touch
    `unsettled_rearm_attempts` (an in-window wake is on time, not a failure).
  - `Ready` → arm at `MIN_CONVERGENCE_SETTLEMENT_DELAY`.
  - `PendingUnopenable` → arm at `normal_delay()` and increment
    `unsettled_rearm_attempts` (this is the only state that counts toward
    `CONVERGENCE_UNSETTLED_MAX_REARMS` → error backoff).
- If `convergence_schedule_state` itself returns `Err`: `schedule_retry_groups([group])` +
  `publish_app_runtime_account_error`. Never `note_success` on an error path.
- `schedule_pending_convergence_groups` (line 2003): same treatment — an `Err` from the
  per-group delay computation schedules a retry, not the silent fallback.
- `schedule_unsettled_groups` shrinks to the `PendingUnopenable` arm; fold it in or keep it
  private to `schedule_after_pass`.
- `arm_no_later` semantics (never postpone an existing earlier deadline) are load-bearing —
  keep, and keep the existing tests for them.

### 3.3 Tests (PR A) — as built

Engine (`crates/cgka-engine/tests/distributed_convergence.rs`, deterministic engine clock,
default pinned v1 policy — timing is driven by explicit `now_ms`, so no policy override is
needed):

1. `pass_opens_while_app_message_intents_are_queued` — completed pass with reservation set,
   app-message intent queued, inbound commit buffered: a generation-1 `Collecting` pass
   exists immediately (admission not parked) and settles at its cutoff.
2. `admin_group_state_intent_gets_one_attempt_before_next_inbound_generation` — a queued
   `UpdateGroupData` intent holds the boundary (pass stays generation-0 `Completed`), the
   drain grants exactly one `GroupEvolution` attempt, and after `publish_failed` rollback the
   retained inbound proceeds into generation 1.
3. `admin_attempt_failure_consumes_reservation_and_inbound_proceeds` — an Invite with
   unparseable KeyPackage bytes fails preparation: reservation consumed, intent stays
   queued, inbound proceeds.
4. `continuous_inbound_cannot_starve_admin_attempt` — six commits admitted at 800 ms
   intervals keep restarting quiescence; the pass freezes with
   `ConvergenceCutoffCause::AbsoluteDeadline`, applies all six, and the queued admin intent
   gets its boundary attempt while the flood continues (the marmot#375 property).
5. `restart_preserves_admin_reservation` — engine rebuilt on the same storage +
   `hydrate_stable_groups_from_storage`: the durable reservation survives and the attempt is
   still granted.
6. `restart_with_only_app_messages_opens_pass_without_delay` — restart with only app intents
   queued: dormant reservation consumed, generation 1 opens on the first buffered commit.
7. `reservation_consumption_schedules_next_generation_immediately` — after the attempt,
   `drain_pending_convergence_groups()` contains the group.

App runtime:

8. `convergence_settles_across_generations_with_mid_window_queued_sends`
   (`tests/relay_runtime.rs`, real MockRelay + full worker loop): three successive rename
   commits, each with a member send fired inside the convergence window; every rename and
   every message must land within the harness's 5 s event deadlines. **Deviation from the
   draft plan:** the draft called for a paused-tokio-time "within one quiescence + margin"
   assertion; the runtime harness is real-time (in-proc MockRelay, real relay I/O), so the
   wall-clock latency-class assertion lives in the engine tests (pass-state assertions in
   tests 1–7), and this test pins the liveness class (no parking, no spurious backoff)
   through the real scheduling path.
9. The draft's `app_message_transport_failure_does_not_delay_pass_admission` is covered
   compositionally: engine test 1 proves admission is independent of the outbound queue
   (publish failures only affect the drain, which cannot park admission after this change),
   and the scheduler unit tests cover drain-error retry arming. No end-to-end variant: the
   runtime harness has no deterministic public seam to fail exactly one publish.
10. Scheduler unit tests (`account_worker.rs mod tests`):
    `collecting_tick_does_not_increment_rearm_counter`,
    `post_cutoff_retained_input_arms_from_remaining_cutoff`, the rewritten
    `schedule_after_pass_*` pair (now over `ConvergenceScheduleState`), plus the retained
    multi-group independence tests
    (`scheduling_one_group_never_postpones_an_earlier_group_cutoff`,
    `rescheduling_same_group_never_postpones_its_frozen_cutoff`).

The pre-existing #1110 reservation test
(`engine_keeps_child_commit_pending_until_parent_arrives`) already asserts the scoped
behavior (its queued intent is `UpdateGroupData`, an admin group-state evolution) and passes
unchanged.

### 3.4 Telemetry (small, ships with PR A)

Post-settle reorg rate does not observe scheduling latency. Add to
`crates/cgka-engine/src/engine_metrics.rs` (aggregate values only — no group ids, per the
observability invariant): pass-open → apply latency, completed-generation → next-generation-open
gap, cutoff-overdue duration at freeze, and admin-reservation counters (per-drain hold
observations / prepared / failed-consumed). These four directly validate this fix in production.
Queue-age-by-category and backoff-transition metrics are optional follow-ups.

### 3.5 Docs / changelog

- `issue-806-frozen-convergence-pass-plan.md` §10.4: append a dated note — reservation
  retained, activation scoped to admin group-state intents, app messages never park
  admission; link this document.
- CHANGELOG (Unreleased): "Fix convergence settling regression: queued app messages no
  longer delay convergence passes; scheduler wakes on actual pass cutoffs and no longer
  backs off on healthy busy groups."
- Optional spec PR (not a blocker): one clarifying sentence in `protocol-core/convergence.md`
  that a queued application payload MUST NOT delay opening a convergence pass — the current
  text already implies it via the admin-intent scoping.

### 3.6 Acceptance

- All tests in §3.3 pass; full suite: `just fast-ci` &&
  `cargo test -p cgka-engine -p marmot-app -p storage-sqlite -p cgka-conformance-simulator`.
- Conformance harness expectations updated where they encoded the over-broad park.
- No `DurableConvergencePass` schema/serde change (verify by round-tripping a pre-fix record
  fixture).

---

## 4. PR B — drain/maintenance cleanup (semantics-preserving, after PR A)

Goal: reduce the risk surface of `converge_and_drain_queued_outbound_intents` without
changing behavior. PR A's tests pin the semantics first; PR B must not change any test
expectation (test-diff-neutral except for added unit tests).

1. Extract the thrice-repeated maintenance block (stage due SelfRemove auto-commit →
   re-propose leave → leave-gate check) into one helper returning an enum
   (`MaintenanceGate::{Clear, StagedCommit, LeaveGated}`); replace all three call sites.
2. Extract the reservation lifecycle into a small helper owning the
   check/grant/consume transitions, so `fairness_slot_available` reads/writes stop being
   scattered across the loop.
3. Replace the string-keyed reason dispatch in
   `realize_group_unrecoverable_for_convergence_pass` (`error_kind == "base_epoch_mismatch"`)
   with an enum carrying the audit strings.
4. Add a local `fn storage_err(e) -> OpenMlsProjectionError` /
   `EngineError` mapping helper in `distributed_convergence.rs` and use it at the ~30
   `format!("{e:?}")` sites in that file.
5. Optional, same theme in marmot-app: deduplicate the notification-trigger block that #1158
   copied into both `client/mod.rs` and `client/sync.rs`.

Acceptance: `git diff` shows no behavioral branches added/removed (reviewer checklist), full
suite green, no changes to PR A's tests.

---

## 5. PR C — frozen-snapshot completeness (design first, replaces v1's "PR 2")

v1 of this plan proposed softening integrity failure (abandon pass, terminalize row,
continue). **Withdrawn**: it mutates the frozen batch after cutoff — exactly the
"corrupt pass silently discarded → inputs recollected under a different base" risk the
issue-806 plan warns against. The `Unrecoverable` posture stays until the pass owns a
complete immutable snapshot.

The actual gap: `ConvergencePassMember` pins id/digest/role/source-epoch, but frozen
*resolution* still consults mutable state the digest does not cover — message-record states,
`seen_message_ids`, retained anchor snapshots, disband-candidate rows, the stored policy.
The pass freezes membership, not resolution input.

Scope for PR C (start with a short design addendum to the issue-806 plan doc, agree, then
implement):

1. Enumerate every input `canonicalize_stored_openmls_messages_with_profile_policy` and
   `apply_openmls_canonicalization_result_with_profile_policy` read beyond pinned payloads.
2. Extend the pass record with an aggregate manifest digest over: ordered member digests,
   `base_epoch`, policy hash, retained-anchor reference, and the enumerated auxiliary state
   references. serde-additive (`#[serde(default)]`), no migration.
3. Verify the manifest (one hash compare) at each converge call on a Frozen/Resolving pass —
   this is what eventually makes it safe to drop the current per-call full-member re-hash,
   as a perf win that *follows* completeness rather than preceding it.
4. Define the verified-repair path for a manifest mismatch (aligned with the existing
   quarantine-repair flow), keeping `Unrecoverable` as the interim response.

Not scheduled until PR A has shipped and its telemetry confirms settling is fixed.

---

## 6. Sequencing, rollout, revert levers

- PR A ships first and alone; it is the user-facing fix. PR B after, trivially revertable.
  PR C is gated on a design review.
- Post-release, watch (a) the new §3.4 latency metrics — pass-open → apply should sit at
  ~quiescence + margin, generation gaps near zero; (b) post-settle reorg rate (existing
  `engine_metrics`) — near-zero confirms 1 s quiescence remains adequate; a rise argues for
  quiescence tuning, not for widening the reservation.
- Revert levers: PR A is one revert; the reservation scoping and the scheduler rework touch
  disjoint crates (engine vs marmot-app) and can be reverted independently if needed.

## Decision history

- **v1 → v2: fairness-slot removal reversed.** v1 claimed the rule was implementation-local;
  review located the normative text (convergence.md L97-103, added to close marmot#375 —
  commit "Bound convergence recovery passes"). #375 is a member-flooding self-preservation
  attack, not an organic-traffic scenario; the reservation is the adopted mitigation. The
  regression came from MDK activating the park for *any* queued intent instead of the spec's
  admin-scoped rule. Fix is scoping, not removal. No spec change.
- **v1 → v2: integrity softening withdrawn.** Post-cutoff batch mutation is unsafe per the
  issue-806 risk register; digest mismatches on content-addressed rows are near-zero
  frequency, so the strict posture costs nothing in practice. Replaced by PR C
  (snapshot completeness first; verification-cadence relaxation only after).
- **v1 → v2: split enlarged.** The urgent fix (PR A) no longer includes the drain-loop
  rewrite (now PR B) so the behavioral diff stays reviewable; scheduler error propagation
  added to PR A after review flagged `unwrap_or(false)` → `note_success` as a liveness bug.
