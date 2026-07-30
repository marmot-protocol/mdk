---
title: "Convergence Reliability And Simulation Plan"
created: 2026-07-30
updated: 2026-07-30
tags: [marmot, cgka, convergence, simulation, verification, reliability]
status: working-plan
---

# Convergence Reliability And Simulation Plan

This is the tracking plan for making Marmot convergence predictable, testable, diagnosable, and durable from the
standalone CGKA engine through full application and multi-process deployments.

The plan has two related goals:

1. establish a precise assurance case for the convergence protocol and its constants; and
2. build one versioned scenario corpus that can run against increasingly production-shaped subjects without changing
   what the scenario means.

This document owns sequencing, work-item status, exit gates, and verification evidence. Detailed protocol behavior
continues to live in
[`cgka-engine-canonicalization-contract.md`](./cgka-engine-canonicalization-contract.md),
[`distributed-convergence.md`](./distributed-convergence.md), and the adopted Marmot
[`protocol-core/convergence.md`](https://github.com/marmot-protocol/marmot/blob/master/protocol-core/convergence.md).
Implementation-specific relay measurement remains in
[`relay-delivery-telemetry.md`](./relay-delivery-telemetry.md).

## Target Assurance Statement

The program is successful when the following statement is justified by specification, executable tests, formal or
bounded models, and repeatable campaign evidence:

> Under explicit delivery, input-closure, policy-version, participant, and resource assumptions, every nonfaulty client
> either reaches exactly equivalent cryptographic and application state within a measured bound or reaches the same
> explicit, deterministic, diagnosable, and replayable terminal outcome.

This statement deliberately does not promise prompt convergence under permanent message suppression, an unbounded
stream of valid competing commits, or exhausted resources. Those cases require an explicit availability or fairness
policy; timers and retries cannot manufacture the missing assumptions.

## Status And Tracking Conventions

Work-item states:

- `not-started`: scoped below but no implementation has landed;
- `in-progress`: implementation or design work is active;
- `blocked`: a named dependency or protocol decision prevents progress;
- `complete`: implementation and every listed verification step have evidence;
- `deferred`: deliberately outside the current delivery horizon, with rationale recorded.

Every completed work item records:

- the issue or design decision, when one exists;
- the implementing PR or commit;
- exact verification commands;
- saved report, model-check, or campaign artifacts where applicable;
- any guarantee, constant, scenario, or adapter capability changed by the work.

Checkboxes represent repository state, not intention. A checked item must have evidence in the progress log.

## Current Baseline

The repository already provides:

- a real `Engine<SqliteAccountStorage>` harness with OpenMLS and the Nostr peeler;
- scripted `ScenarioSpec` v1 cases and portable vectors;
- seeded delivery schedules, generated chaos families, reports, and conservative failure minimization;
- symbolic selector/canonicalization properties and engine integration tests;
- encrypted file-backed restart coverage;
- incident archetype synthesis from forensic audit exports;
- a Tamarin model for bounded selector, lifecycle, and output-safety scenarios.

The baseline is useful scaffolding, but it is not yet the target reliability lab:

- portable `ClientsConverged` checks epoch/member count rather than exact member and state equivalence;
- normal scenarios can use a harness with engine/storage access;
- a partition drops messages instead of retaining relay history for reconnect;
- queue emptiness does not prove all client, pass, publication, retry, deferred, or projection work is quiescent;
- generated storms are structural tests rather than sustained rate/volume campaigns;
- scenario seeds do not reproduce randomized MLS bytes;
- the executable policy model used by several tests is production code, not an independent oracle;
- Tamarin abstracts clocks, crash/restart, durable generations, resource bounds, fairness, and sustained self-updates.

## Program Principles

1. **Correctness before scale.** Do not build a large process fleet around an oracle that can accept the wrong state.
2. **One scenario meaning.** Human authoring compiles to one canonical Scenario IR consumed by every adapter.
3. **Public boundary by default.** Normal conformance scenarios use public subject behavior. White-box fault injection is
   explicit and separately classified.
4. **Retained history, not healed packet loss.** Offline/reconnect scenarios query durable per-relay histories and
   observe EOSE/backfill behavior.
5. **Independent expected behavior.** Production selector/canonicalization code cannot be the only source of expected
   outcomes.
6. **Timers do not define truth.** Operational scheduling may affect latency and intermediate passes, but must not
   silently change the correct final result after input closure.
7. **Resource failure is explicit.** A budget or cap may fail closed, defer, or report an unresolved state; it must not
   select from partial evidence.
8. **Logical and byte replay are distinct.** Seeds reproduce logical actions and schedules. Captured wire artifacts
   reproduce randomized MLS bytes.
9. **Failures become assets.** Every useful failure is minimized, captured, classified, and considered for promotion
   into the permanent regression corpus.
10. **Privacy-safe evidence.** Committed fixtures are synthetic. Reports and telemetry follow the repository
    observability rules and never emit identifiers, relay URLs, payloads, ciphertext, plaintext, or key material into
    production tracing.

## Milestone Summary

| Milestone | Outcome | Status | Exit gate |
| --- | --- | --- | --- |
| 0. Assurance foundation | Guarantees, assumptions, constants, and formal gate are explicit | complete | Every constant is classified; formal warnings fail CI; protocol decisions are named |
| 1. Trustworthy engine black box | Exact oracle, public subject boundary, full quiescence, replay capsules | not-started | Known semantic mutations fail and captured failures replay |
| 2. Scenario IR and retained relays | One adapter-neutral DSL/IR plus realistic offline/history sync | not-started | One compiled case runs against reference, engine, and retained-relay adapters |
| 3. Adversarial campaigns | Sustained real-world workloads, resource sweeps, incident import | not-started | Headline workload families produce bounded, diagnosable results |
| 4. Independent verification | Reference model, liveness model, mutation adequacy, protocol decision gate | not-started | Model and tests detect seeded policy/lifecycle defects |
| 5. App and process simulation | Real projections and lifecycle in one or many isolated runtimes | not-started | The same case agrees in-process and across N processes |
| 6. Distributed campaigns | Container/VM/network/disk/version hardening and campaign operations | not-started | Repeatable soak and release campaigns retain actionable artifacts |

## Milestone 0: Assurance Foundation

### 0.1 Guarantee And Assumption Contract

Status: `complete`

The initial assurance matrix is below. “Required verification” names the minimum evidence before a claim can become
`established`.

| ID | Claim | Required assumptions | Required verification | Status |
| --- | --- | --- | --- | --- |
| S1 | Same retained anchor, authenticated input closure, policy version, and engine version produce the same canonical branch and exact state | Finite relevant input set; every compared client possesses the same validated dependency closure | Independent reference comparison; schedule/restart metamorphic tests; bounded model | specified |
| S2 | Application output after settlement is exactly the payload/state-change projection of the selected branch | MLS and Marmot payload authentication succeeds; invalidations reach projection | Exact logical ledger; losing-branch and superseded-state scenarios; Tamarin output lemmas | partially-covered |
| S3 | Missing retained state, invalid policy, corrupt frozen input, and exhausted replay budget never apply a partial candidate result | Storage reports failures accurately; fail-closed errors are durable or retryable by contract | Engine tests, crash matrix, resource campaigns, seeded mutations | partially-covered |
| S4 | Publish-before-apply and convergence lifecycle changes are torn-write-free | Storage transaction contract holds; external publication results are accurately reported | Storage/engine lifecycle tests; kill/restart at each durable transition | partially-covered |
| S5 | Operational scheduler timing does not change the eventual canonical result after authenticated input closure | All pending passes are eventually revisited; required retained state remains available | Virtual-time metamorphic tests across scheduler margin, retry, and re-arm values | unverified |
| L1 | After relevant input closes and all required history is locally available, convergence reaches `Settled` or a named terminal failure | Client continues executing; resource policy admits the workload | Bounded state-machine liveness model; engine and retained-relay scenarios | unverified |
| L2 | Outbound work blocked by convergence is eventually released, regenerated, or terminated with an explicit outcome | L1 assumptions; publication path eventually returns a result | Scheduler/outbound ledger assertions; crash/restart scenarios | partially-covered |
| L3 | Marmot does not guarantee that a privileged administrative transition becomes canonical while valid selection-relevant input, including ordinary self-updates, continues without bound | The bounded post-settlement preparation opportunity remains enforced; stronger progress requires eventual relevant-input closure | Adversarial model and sustained simulator family; bounded preparation-opportunity tests | specified |
| S6 | Clients are exactly equivalent only when the canonical conformance projection, including its domain-separated exporter commitment, matches | Synthetic/local conformance execution; raw exporter secret never leaves the test process | M1.1 exact snapshot comparison; mismatched-member, component, disposition, output, and commitment sentinels | specified |
| R1 | Crash/reopen from any durable convergence phase is equivalent to uninterrupted execution | Database and required WAL/sidecars remain intact; no storage corruption unless scenario declares it | File-backed crash matrix and process-kill replay | partially-covered |
| R2 | Clients with unequal relay histories converge after the histories reconcile | Relevant events remain retained and are eventually fetched; same policy/version | Retained multi-relay scenarios with EOSE, backfill, and set equality | unverified |
| D1 | Every failure is attributable to a stable action, policy, state transition, or resource bound and can be replayed | Failure artifact completes successfully; sensitive evidence remains local | Failure-capsule self-replay and schema tests | unverified |

#### Assurance verification ownership

This table assigns every claim a current evidence owner and the work item that owns the remaining gap. A named existing
test is evidence for only the behavior in its name; it does not establish the larger claim by itself.

| ID | Normative/architecture source | Current evidence | Missing evidence owner |
| --- | --- | --- | --- |
| S1 | Protocol `convergence.md` branch selection; local canonicalization contract “Determinism and convergence” | Tamarin `same_input_set_converges`; `prop_candidate_graph_selection_is_order_invariant`; `prop_stored_convergence_restart_equivalence` | M1.1 exact-state oracle; M4.1 independent reference model; M4.2 arbitrary schedule/lifecycle model |
| S2 | Protocol `convergence.md` “Applying the selected branch”; local canonicalization output contract | Tamarin application-output/invalidation lemmas; `engine_emits_only_canonical_branch_app_messages_after_convergence`; `rebuilt_engine_emits_losing_branch_app_invalidation_after_convergence` | M1.1 exact logical ledger and projection equivalence; M5.1 app projection adapter |
| S3 | Protocol retained-anchor error rules; local canonicalization errors and fail-closed replay contract | Tamarin missing/beyond-anchor lemmas; `frozen_pass_member_tampering_fails_closed_to_unrecoverable`; `missing_frozen_pass_member_fails_closed_to_unrecoverable`; replay-budget unit tests | M3.1 end-to-end resource exhaustion; M4.3 mutations |
| S4 | Protocol publish lifecycle and bounded-pass persistence; local multi-step-state-change rules | `convergence_pass_round_trips_updates_and_cascades`; `collecting_pass_restart_preserves_remaining_window_and_backward_clock_fails_closed`; `reopen_after_crash_during_publish_recovers_stranded_pending_commit`; crash-recovery SQLite tests | M3.1 complete durable-transition kill matrix; M5.1 runtime crash matrix |
| S5 | Protocol bounded collection window; relay telemetry claim that quiescence is not a correctness boundary | `prop_quiescence_gate_controls_settlement`; cutoff and scheduler unit tests | M3.2 cross-value metamorphic campaign; M4.2 scheduler model |
| L1 | Protocol pass freeze and completion rules; group convergence status | Individual settle/fail-closed integration tests | M4.2 TLA+/TLC liveness specification; M2.3 retained-relay scenarios |
| L2 | Protocol outbound gating; local queued-intent lifecycle | Tamarin queued-outbound lemmas; `engine_queues_app_send_until_convergence_is_settled`; `trait_advance_convergence_drains_queued_outbound_intent`; scheduler tests | M1.3 complete quiescence; M3.1 crash/failure workload |
| L3 | Protocol same-epoch priority and depth rules; no sustained-progress guarantee currently stated | `convergence_privileged_remove_beats_grinding_ordinary_self_update`; `continuous_inbound_cannot_starve_admin_attempt` | M3.1 sustained self-update family; M4.2 fairness model; protocol decision PDR-2 below |
| S6 | Protocol `foundation/conformance.md`, adopted by [marmot#410](https://github.com/marmot-protocol/marmot/pull/410) | Domain separation and 33-byte commitment prefix checked in the protocol PR | M1.1 public snapshot API and exact-equivalence sentinels |
| R1 | Protocol durable pass wall/monotonic deadline rules; local storage/restart contract | `collecting_pass_restart_preserves_remaining_window_and_backward_clock_fails_closed`; `h5_kill_before_historical_apply_commit_preserves_live_inputs`; `h6_kill_after_retained_anchor_rewind_recovers_live_snapshot` | M3.1 every-phase crash matrix; M5.3 process kill/reopen |
| R2 | Relay telemetry EOSE/backfill/reconciliation architecture; protocol requires equalized relevant history for equivalent selection | `stalled_epoch_backfill_recovers_below_floor_backlog_when_armed`; `next_event_returns_when_a_live_delivery_arms_the_epoch_backfill` | M2.3 retained multi-relay model; M3.1 unequal-history family |
| D1 | Local forensic audit/report contracts and privacy rules | Generated reports, oracle coverage, conservative minimizer, incident archetype synthesis | M1.4 failure capsule and self-replay; M3.3 exact incident import |

Milestone 0 work:

- [x] Record the initial assurance statement, assumptions, and claim matrix in this plan.
- [x] Review each claim against the adopted protocol text and record missing implementation-neutral assumptions or
  outcomes.
- [x] Open protocol PR [marmot#410](https://github.com/marmot-protocol/marmot/pull/410) for the missing
  implementation-neutral assumptions and outcomes recorded below.
- [x] Assign each claim an owning Rust test, formal lemma/model property, and simulator family or future work item.
- [x] Add an explicit claim for cryptographic state equivalence using the protocol PR's test-only exporter commitment.
- [x] Resolve L3 as an explicit non-guarantee under unbounded valid input; retain the bounded preparation opportunity.
Follow-on rule: a claim is marked `established` only after all required evidence is linked in the progress log.

#### Protocol gaps and decision register

The adopted convergence specification defines policy constants, candidate validity, pass collection/freeze, branch
selection, dispositions, and retained-history behavior. The following broader assurance statements are not yet explicit
protocol guarantees:

| ID | Required decision or protocol clarification | Status | Blocking work |
| --- | --- | --- | --- |
| PDR-1 | State the input-closure and execution assumptions under which eventual convergence is promised: equivalent authenticated dependency closure, same policy/version, continued client execution, and retained state availability | adopted-protocol-pr-410 | S1, L1, R2 establishment |
| PDR-2 | Decide whether privileged administrative progress is guaranteed during an unbounded stream of valid ordinary self-updates; if not, state the eventual-quiet limitation | adopted-no-guarantee-pr-410 | M3.1/M4.2 verify the bounded opportunity and characterize adversarial behavior |
| PDR-3 | State the interoperable outcome when local resource policy drops, defers, or refuses otherwise valid input; distinguish fail-closed local availability from canonical branch selection | adopted-protocol-pr-410; MDK-aligned | M3.1 resource campaigns |
| PDR-4 | Define the portable notion of exact cryptographic/application state equivalence without exposing secrets | adopted-protocol-pr-410 | M1.1 exporter commitment and cross-implementation vectors |
| PDR-5 | Keep quiescence/pass cutoffs explicitly outside final-state correctness after input closure, or revise the guarantee if metamorphic tests find a counterexample | adopted-protocol-pr-410; evidence-required | S5 and P4/P5 verification |

This MDK branch records and tests the implementation implications. The implementation-neutral wording is adopted in
`marmot-protocol/marmot` through [marmot#410](https://github.com/marmot-protocol/marmot/pull/410).

### 0.2 Convergence Constant Ledger

Status: `complete`

Categories:

- `semantic`: changes the versioned branch-selection or eligibility result;
- `security-retention`: trades delayed processing/recovery against secret or state retention;
- `resource`: bounds CPU, memory, durable rows, or work per pass;
- `scheduler`: controls when equivalent work is attempted;
- `input-recovery`: controls when or how relay history is reacquired;
- `sentinel`: implementation mechanics that must not affect externally visible behavior.

“Final-state influence” records the intended contract, not a conclusion already proved.

#### Versioned convergence policy

| ID | Constant | Value | Category | Intended effect | Too low / too high | Final-state influence | Required evidence |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| P1 | `V1_MAX_REWIND_COMMITS` | 5 commits | semantic, security-retention | Bounds eligible fork depth and retained anchors | Too low rejects recoverable late history; too high increases reorg, storage, replay, and secret-retention exposure | yes, by policy version | Eligibility boundaries, delayed-history sweep, retention/security review |
| P2 | `V1_APP_MESSAGE_PAST_EPOCH_LIMIT` | 5 epochs | semantic, security-retention | Bounds delayed app delivery and witness eligibility | Too low expires realistic offline traffic; too high retains old message secrets and increases work | yes, by policy version | Multi-commit offline flood, exact app ledger, six-advance boundary |
| P3 | `DEFAULT_MAX_PAST_EPOCHS` | 5 epochs | security-retention | Configures OpenMLS decryptable history; must equal P2 | Drift causes messages to be policy-eligible but cryptographically undecryptable, or retains unusable secrets | must be identical to P2 | Pin/alignment tests and delayed decryption sweep |
| P4 | `V1_SETTLEMENT_QUIESCENCE_MS` | 1,000 ms | semantic scheduling policy | Closes a live-input window after delivery jitter | Too low raises post-settle reorgs; too high stalls outbound work | intended no after input closure; may change intermediate passes | Virtual-time sweep, post-settle reorg metrics, retained-relay spread |
| P5 | `V1_MAX_CONVERGENCE_PASS_MS` | 5,000 ms | semantic scheduling policy | Guarantees a collecting pass freezes under sustained relevant input | Too low fragments ordinary bursts; too high lets a flood hold the group collecting | intended no after all follow-up passes; may change pass membership | Sustained-flood test, cutoff restart matrix, eventual fixed-point comparison |
| P6 | `V1_WITNESS_QUORUM_SENDERS_PER_EPOCH` | 2 senders | semantic | Defines per-epoch corroboration | Too low lets one identity dominate; too high makes evidence unavailable in small/offline groups | yes, by policy version | Group-size/device-topology sweep and Sybil/account dedupe model |
| P7 | `V1_WITNESS_QUORUM_EPOCHS` | 1 epoch | semantic | Defines how many branch epochs require quorum | Too low gives brief activity more weight; too high suppresses witnesses on short branches | yes, by policy version | Branch-length and traffic-duration sweep |
| P8 | `V1_MAX_WITNESS_OVERRIDE_DEPTH` | 1 commit | semantic | Caps witness-derived effective-depth boost | Too low makes witnesses irrelevant; too high lets traffic outrank much longer commit history | yes, by policy version | Bound proof, depth-difference matrix, adversarial witness flood |

#### Engine resource and retry bounds

| ID | Constant | Value | Category | Intended effect | Failure behavior to verify | Final-state influence | Required evidence |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| E1 | `MAX_CONVERGENCE_REPROCESSING_PASSES` | 16 passes | resource | Bounds recursive/in-call drain work | Remaining work stays durable/retryable and no partial result is called settled | intended no | End-to-end exhaustion and later-progress test |
| E2 | `MAX_DEFERRED_PEEL_ATTEMPTS` | 32 changed contexts | resource | Releases repeatedly undecryptable retained rows as `resource_refused_retry_budget` | Same transport id remains refetch-eligible; the limit makes no validity or permanent-unreadability claim | may affect locally available input until refetch | Changed-context exhaustion, exact-ID redelivery, and missing-commit recovery |
| E3 | `MAX_PEEL_DEFERRED_ROWS_PER_GROUP` | 256 rows | resource | Bounds attacker-mintable undecryptable durable backlog | Over-cap input returns typed `ResourceRefused`, remains exact-ID eligible, and immediately arms history backfill | may affect locally available input until refetch | Flood, bounded-storage assertion, exact-ID recovery after drain, app backfill signal |
| E4 | `MAX_DEFERRED_ROWS_PER_SWEEP` | 64 rows | resource, scheduler | Prevents old deferred history monopolizing a pass | Fair cursor progress eventually visits every row | intended no | Backlog fairness and restart tests |
| E5 | `CANDIDATE_REPLAY_BUDGET_SLACK` | 4× | resource | Scales replay budget over linear commit/rewind estimate | `ReplayBudgetExceeded` fails closed without partial selection | intended no | Branch-explosion campaign and recovery policy test |
| E6 | `CANDIDATE_REPLAY_BUDGET_FLOOR` | 32 probes | resource | Gives small passes minimum replay headroom | Same as E5 | intended no | Small/large boundary matrix |
| E7 | self-remove auto-commit jitter | 10 ms + [0, 40) ms | scheduler | Reduces synchronized automatic self-remove commits | Jitter changes ordering only, not admissible final behavior after closure | intended no | Seeded schedule invariance and collision tests |

#### App scheduler and input-recovery bounds

| ID | Constant | Value | Category | Intended effect | Failure behavior to verify | Final-state influence | Required evidence |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| A1 | `CONVERGENCE_SETTLEMENT_SCHEDULE_MARGIN_MS` | 100 ms | scheduler | Avoids firing just before an engine cutoff | Early/late wake affects latency only | intended no | Paused-time boundary tests |
| A2 | `MIN_CONVERGENCE_SETTLEMENT_DELAY` | 10 ms | scheduler | Prevents zero-delay spin | Work remains scheduled | intended no | Timer-spin and progress tests |
| A3 | convergence retry base/max | 1 s / 60 s | scheduler | Bounds exponential retry wakeups | Persistent error stays visible and periodically retried | intended no | Backoff sequence and eventual recovery |
| A4 | `CONVERGENCE_UNSETTLED_MAX_REARMS` | 10 rearms | scheduler, resource | Moves persistently unopenable work to error-style backoff | Does not strand a healthy collecting pass or pending outbound work | intended no | Pending-unopenable and recovery tests |
| A5 | `IDLE_CONVERGENCE_TIMER_DELAY` | 365 days | sentinel | Parks an empty timer | Earliest real deadline always replaces sentinel | none | Scheduler unit test |
| A6 | `EPOCH_STALL_BACKFILL_THRESHOLD` | 8 distinct messages | input-recovery | Detects likely missed commits from undecryptable traffic | Too low causes redundant history reads; too high delays repair | can affect time/input equality, not branch choice given equality | Multi-cohort replay, relay scenario sweep, production evidence |
| A7 | `APP_RUNTIME_RELAY_REBUILD_LOOKBACK` | 120 s | input-recovery | Rewinds relay query floor during runtime rebuild | Too low misses delayed events; too high increases replay volume | can affect acquired input set | Since-floor and long-offline retained-history tests |
| A8 | `TRANSPORT_CURSOR_MAX_FUTURE_SKEW` | 5 min | input-recovery | Prevents sender timestamps from moving the cursor arbitrarily forward | Clamp must preserve benign skew without suppressing history | can affect acquired input set | Malicious timestamp, clock-skew, and cursor-reset tests |

#### Constant verification ownership

The completeness scope is constants that directly affect convergence policy, retained convergence input, convergence
engine work bounds, dedicated convergence scheduling, or dedicated history reacquisition. Generic HTTP, relay SDK,
account-open, and UI timeouts remain owned by their subsystem runtime policy and are not convergence constants merely
because they can delay a process.

The machine-readable
[`convergence-constant-inventory.txt`](./convergence-constant-inventory.txt) maps every ledger ID to its current Rust
declaration. `just convergence-ledger-gate` verifies those declarations, requires every P/E/A ID below, and scans the
named source families for newly introduced constants that have not been reviewed into this ledger.

| IDs | Current source/test owner | Remaining verification owner |
| --- | --- | --- |
| P1 | `convergence.rs`; Tamarin anchor/stale lemmas; `engine_replays_late_same_epoch_commit_from_retained_anchor`; `engine_prunes_retained_anchor_snapshots_to_rewind_horizon` | M3.1 delayed-history depth sweep; M4.1 reference model |
| P2, P3 | `canonicalization.rs` and `wire_format.rs`; `app_message_window_must_match_engine_max_past_epochs`; `app_message_expired_is_relative_to_the_passed_reference_tip`; `send_preflight_terminally_retires_deferred_app_message_outside_past_epoch_window` | M3.1 multi-commit offline flood; M1.1 exact message ledger |
| P4 | `canonicalization.rs`; `prop_quiescence_gate_controls_settlement`; `engine_duplicate_convergence_input_does_not_reset_quiescence`; `app_witness_beside_competing_commits_resets_convergence_quiescence` | M3.2 quiescence sweep; relay-spread/reorg telemetry |
| P5 | `canonicalization.rs`; `convergence_pass_freezes_at_absolute_cap_under_continuous_selection_input`; `input_at_effective_cutoff_is_retained_for_the_next_generation`; collecting-pass restart test | M3.1 sustained flood; M3.2 eventual fixed-point comparison |
| P6, P7, P8 | `convergence.rs`; generated policy cases; Tamarin score/bound lemmas; multi-device witness-deduplication replay probe | M3.1 group-size/device/Sybil sweeps; M4.1 independent reference |
| E1 | `message_processor/mod.rs`; existing multi-pass integration flows | M3.1 force exhaustion, verify durable continuation and no partial settle |
| E2, E3, E4 | `message_processor/mod.rs`; `deferred_peel_retry_budget_refuses_without_terminal_dedup`; `peel_deferred_rows_capped_per_group_under_flood`; `resource_refusal_signals_immediately_once_per_epoch`; deferred retry/context tests | M3.1 fairness/restart/redelivery campaign |
| E5, E6 | `openmls_projection.rs`; `for_pass_scales_with_commits_and_rewind_and_keeps_a_floor`; `for_pass_saturates_instead_of_overflowing`; `consume_fails_closed_when_exhausted` | M3.1 branch-explosion end-to-end recovery; M4.3 mutation |
| E7 | `message_processor/mod.rs`; `reopen_preserves_deferred_selfremove_auto_commit` | M3.1 deterministic jitter/collision schedules |
| A1, A2, A4, A5 | `account_worker.rs`; clamp, re-arm, collecting, pending-outbound, cutoff-order, and backoff scheduler tests | M3.2 virtual-time scheduler invariance; M4.2 lifecycle model |
| A3 | `account_worker.rs`; `retry_delay_for_attempt_backs_off_and_caps` | M3.1 persistent-error recovery and visibility |
| A6 | `epoch_stall.rs`; threshold/debounce/reset tests; next-event and audit backfill tests | M3.1 retained-relay threshold sweep; additional production cohorts |
| A7 | `marmot-app/lib.rs`; `cold_restart_since_floor_permanently_drops_backlog_below_it`; `stalled_epoch_backfill_recovers_below_floor_backlog_when_armed` | M2.3 long-offline retained-relay matrix |
| A8 | `marmot-app/lib.rs`; since-floor malicious/future timestamp coverage | M3.1 explicit skew/cursor-reset Scenario IR family |

Ledger work:

- [x] Record the first code-backed classification of versioned policy, engine bounds, scheduler bounds, and
  input-recovery heuristics.
- [x] Mechanically audit convergence engine, storage, app scheduler, and relay-sync paths for missing constants within
  the completeness scope above.
- [x] Add a test or generated inventory that detects unreviewed convergence constants where practical.
- [x] Assign every ledger row at least one named scenario/test and one current or future owner.
Follow-on work in Milestones 3 and 4 verifies the “final-state influence” assertion for every non-semantic constant
through metamorphic testing and records the production telemetry needed to justify future policy revisions.

### 0.3 Formal Verification Gate

Status: `complete`

- [x] Identify that the noninteractive Make target runs `--prove` without `--quit-on-warning`.
- [x] Make noninteractive proof runs fail on warnings and use an explicit derivation-check timeout.
- [x] Document the strict command and override mechanism.
- [x] Run the complete model and save the summary in the progress log.
- [x] Add `SameInputSet` and same-policy premises to convergence lemmas where the model currently relies on
  closed-world initializer construction.
- [x] Classify each Tamarin lemma as safety, executability, lifecycle, delivery, or bounded-case coverage.
- [x] Select a separate bounded state-machine tool for clock, restart, fairness, resource, and liveness properties.

#### State-machine model decision

TLA+/TLC is the primary independent model for Milestone 4.2:

- TLA+ expresses the state machine separately from Rust production code, reducing shared-assumption risk.
- TLC directly checks temporal liveness properties and weak/strong fairness assumptions and produces counterexample
  behaviors.
- The first model remains deliberately small: bounded clients, branches, messages, pass generations, crashes, and
  resources.

Stateright remains a later implementation-bridge option because it can model Rust actor systems and produce executable
paths, but it is not the primary independent oracle. Apalache may be added if bounded safety checks encounter TLC state
explosion; it is not required for the first liveness model.

Primary references:

- [TLA+ tools](https://lamport.org/tla/tools.html)
- [TLC current tool behavior](https://github.com/tlaplus/tlaplus/blob/master/general/docs/current-tools.md)
- [Stateright model checker](https://docs.rs/stateright/latest/stateright/)

### Milestone 0 Exit Gate

- [x] Every convergence-affecting constant in the declared Milestone 0 scope is in the ledger, classified, and guarded.
- [x] Every assurance claim names its assumptions, observable outcome, and verification owner.
- [x] The canonical protocol states the required liveness/fairness assumptions
  ([marmot#410](https://github.com/marmot-protocol/marmot/pull/410)).
- [x] `just tamarin` fails on warnings/timeouts and passes the current complete proof.
- [x] No known resource or scheduler bound can silently select from partial evidence.
- [x] The self-update administrative-progress decision is resolved as an explicit non-guarantee under unbounded valid
  input.

The implementation exits now fail visibly. E1 returns unsettled after its in-call pass limit, and E5/E6 return
`ReplayBudgetExceeded` rather than selecting a partial candidate graph. E2 releases a retry-budget-exhausted transport
row without terminal deduplication, while E3 returns typed `ResourceRefused`; exact-ID regression coverage proves both
remain eligible, and the app runtime immediately arms history backfill for resource refusal. The normative availability
and liveness wording is adopted through
[marmot#410](https://github.com/marmot-protocol/marmot/pull/410). With that dependency merged, Milestone 0 is complete;
the exact state/message oracle is the first Milestone 1 slice.

Milestone 0 verification:

```sh
rg -n \
  "TODO|TBD|open question|future SQLite|production storage|retry-deferred|AlreadyAtEpoch.*Peel" \
  docs \
  --glob '!AGENTS.md' \
  --glob '!docs/marmot-architecture/convergence-reliability-plan.md'

cargo test -p cgka-engine --test convergence_policy_pin
cargo test -p cgka-engine --features test-policy-overrides --test distributed_convergence
just convergence-ledger-gate
just tamarin
just fast-ci
git diff --check
```

## Milestone 1: Trustworthy Engine Black Box

### 1.1 Exact state and logical-message oracle

- [ ] Add exact sorted member identities to portable observations.
- [ ] Include epoch, selected branch, admin policy, application profile, required capabilities, and group state.
- [ ] Record a logical message ledger: sent, accepted, delivered, deduplicated, expired, invalidated, and pending.
- [ ] Add a test-only privacy-safe cryptographic state commitment based on MLS exporter state.
- [ ] Prove bidirectional decryptability after apparent convergence.
- [ ] Add `ClientsExactlyEquivalent`, `LogicalMessageLedger`, and `NoPendingWork` expectations.
- [ ] Make strict oracle behavior the default for reliability campaigns.

Verification:

- same member count but different member identities fails;
- same public metadata but different exporter commitment fails;
- duplicate delivery appears once in the logical ledger;
- losing-branch payload/state output is absent or explicitly invalidated.

### 1.2 Public subject boundary

- [ ] Define a simulator-owned `ConvergenceSubject` interface using public engine behavior.
- [ ] Implement create/mutate, ingest, virtual-time advance, public event/outbound polling, crash/reopen, and sanitized
  observation.
- [ ] Split normal black-box execution from explicitly named white-box storage/fault capabilities.
- [ ] Reject scenarios that require unsupported subject capabilities before execution.

### 1.3 Full-system quiescence

- [ ] Include deliverable input, inbox, delayed messages, pass phase, deferred replay, outbound publication, retry
  timers, and durable transitions in a progress snapshot.
- [ ] Require two stable virtual-time observations with no state or ledger progress.
- [ ] Report which subsystem prevents quiescence.
- [ ] Bound quiescence waiting by scenario policy and emit a terminal timeout artifact.

### 1.4 Deterministic failure capsules

- [ ] Define a versioned capsule schema.
- [ ] Save original scenario, canonical IR, seeds, expanded schedule, policy/constant snapshot, adapter/binary versions,
  captured wire bytes, virtual time, logical ledger, state commitments, and resource measurements.
- [ ] Replay a capsule without regenerating MLS bytes.
- [ ] Keep real incident artifacts local and restrictive-by-construction.
- [ ] Promote minimized synthetic failures into portable vectors when they define durable behavior.

### Milestone 1 Exit Gate

- [ ] A wrong exact state cannot pass as converged.
- [ ] A normal scenario cannot access engine/storage internals.
- [ ] Hidden pending work prevents quiescence.
- [ ] A captured byte-level failure replays with the same outcome.
- [ ] Targeted semantic mutations are detected.

## Milestone 2: Scenario IR And Retained Relays

### 2.1 Scenario IR v2 and authoring DSL

- [ ] Define adapter-neutral, versioned JSON IR and JSON Schema.
- [ ] Add human YAML authoring that compiles to canonical JSON; execute only canonical JSON.
- [ ] Model accounts, devices, processes, roles, groups, relays, and policy/binary versions explicitly.
- [ ] Add `repeat`, `parallel`, `rate`, `burst`, barriers, and virtual time.
- [ ] Add create, invite, remove, leave, self-update, group/admin state update, and application send.
- [ ] Add offline/reconnect, delay, duplicate, omit, withhold/release, crash/restart, and declared storage faults.
- [ ] Replace queue indices with semantic action/message selectors.
- [ ] Add `exactly`, `eventually`, `within`, `never`, and resource assertions.
- [ ] Compile `ScenarioSpec` v1 into v2 so existing vectors retain meaning.

### 2.2 Adapter contract

- [ ] Define capability discovery and compile-time rejection for unsupported operations.
- [ ] Produce stable action ids and a deterministic expanded schedule.
- [ ] Implement initial reference-model and engine adapters.
- [ ] Require all adapters to emit the same observation/capsule schema.

### 2.3 Retained multi-relay model

- [ ] Maintain a durable event history per relay.
- [ ] Model publish fanout, subscriptions, query filters, EOSE, reconnect, since floors, and full backfill.
- [ ] Model relay-specific duplicate/order/visibility/omission behavior.
- [ ] Model unequal client relay sets and later history reconciliation.
- [ ] Keep the existing in-memory packet bus as a fast unit-test adapter, not offline-sync evidence.

### Milestone 2 Exit Gate

- [ ] One compiled scenario runs unchanged against the reference, engine, and retained-relay adapters.
- [ ] Offline participants recover from relay history rather than healed packet loss.
- [ ] Relay disagreement followed by equalized history reaches exact state equivalence.
- [ ] Unsupported adapter behavior fails before a partial run.

## Milestone 3: Adversarial Workload Campaigns

### 3.1 Required workload families

- [ ] Offline retained-history flood with application traffic spanning many membership/state commits.
- [ ] Sustained application traffic interspersed with proposals and commits.
- [ ] Sequential self-update adversary racing privileged administrative changes.
- [ ] Unequal relay histories followed by reconciliation.
- [ ] Crash/restart at every durable convergence transition.
- [ ] Multi-group noisy-neighbor and per-group fairness.
- [ ] Candidate graph/replay budget/resource exhaustion.
- [ ] Multi-device account identity and witness deduplication.
- [ ] Mixed binary and policy versions.
- [ ] Clock movement, scheduler delay, and timestamp/cursor attacks.

Each family varies schedule, storage mode, participant count, rates, restart placement, relay topology, and applicable
test-only constants while preserving a stable semantic oracle.

### 3.2 Resource and sensitivity measurements

- [ ] Record convergence latency and blocked-send duration.
- [ ] Record pass count, reorg count/depth/lateness, and unresolved outcomes.
- [ ] Record logical delivery/expiry/invalidation results.
- [ ] Record CPU time, peak memory, database size/writes, queue depth, and replay probes.
- [ ] Sweep constants around the pinned value in explicit test-policy builds.
- [ ] Produce curves and boundary failures; never auto-tune production policy from simulator output.

### 3.3 Incident replay

- [ ] Preserve normalized archetype synthesis for incomplete forensic evidence.
- [ ] Add exact-history IR import when evidence is sufficient.
- [ ] Carry evidence confidence and unavailable fields into the scenario artifact.
- [ ] Keep sensitive exports and generated exact capsules out of version control.

### Milestone 3 Exit Gate

- [ ] The three headline workloads run both as small regressions and sustained campaigns.
- [ ] Every resource exhaustion reaches a named fail-closed or retryable outcome.
- [ ] Campaign reports identify the first failing action and limiting resource.
- [ ] Selected incident histories reproduce or clearly state why exact replay is impossible.

## Milestone 4: Independent Verification And Adequacy

### 4.1 Independent reference model

- [ ] Implement symbolic authenticated candidates, authorization, dependency closure, witness scoring, selection, and
  dispositions without calling production selector/canonicalization code.
- [ ] Differentially compare reference model, production selector, and full engine.
- [ ] Keep model inputs small and shrinkable.

### 4.2 Liveness and lifecycle model

- [ ] Prototype the self-update/admin-progress case in TLA+/TLC and Stateright, then record the tool decision.
- [ ] Model unequal histories, eventual input closure, pass freeze/settle, crash/restart, fairness, and resource failure.
- [ ] Produce minimal counterexample traces consumable by Scenario IR where practical.
- [ ] Keep Tamarin focused on symbolic safety/security and executable bounded policy cases.

### 4.3 Mutation adequacy

- [ ] Mutate selector comparison order.
- [ ] Mutate witness sender/epoch deduplication.
- [ ] Mutate cutoff admission and frozen-member persistence.
- [ ] Mutate scheduler deadlines and re-arm classification.
- [ ] Mutate output invalidation and publication acknowledgement.
- [ ] Mutate retained-history and expiration boundaries.
- [ ] Maintain a matrix showing which verification layer kills each mutation.

### 4.4 Protocol decision gate

- [ ] Prove bounded administrative progress under stated assumptions, add explicit fairness/admission policy, or
  document the non-guarantee.
- [ ] Confirm which constants are truly semantic and version them through protocol capabilities.
- [ ] Confirm scheduler/resource constants cannot silently change a settled result after input closure.

### Milestone 4 Exit Gate

- [ ] The independent model and production engine agree over the bounded corpus.
- [ ] Every targeted semantic mutation is killed or becomes a tracked verification gap.
- [ ] Liveness counterexamples name the violated assumption.
- [ ] The self-update/adversarial-progress decision is part of the protocol contract.

## Milestone 5: Application And Multi-Process Simulation

### 5.1 `MarmotAppRuntime` adapter

- [ ] Give every participant a unique restrictive root and SQLCipher database.
- [ ] Drive only public app-runtime operations.
- [ ] Exercise real account/device lifecycle, projections, outbound publication, relay sync/backfill, and retries.
- [ ] Compare engine state commitments and user-visible chat/member/admin/message projections.
- [ ] Crash/reopen the complete runtime.

### 5.2 Simulator node process

- [ ] Add a small test binary wrapping `MarmotAppRuntime`.
- [ ] Define a versioned JSONL control and observation protocol.
- [ ] Keep engine/storage internals unavailable through the process protocol.
- [ ] Emit privacy-safe structured diagnostics and failure capsules.

### 5.3 Process orchestrator

- [ ] Allocate one isolated root per participant.
- [ ] Launch and barrier N participant processes.
- [ ] Kill, pause, resume, and restart individual participants.
- [ ] Connect all participants to controlled local relay topologies.
- [ ] Preserve the canonical Scenario IR action schedule and observation schema.

### Milestone 5 Exit Gate

- [ ] The same scenario reaches equivalent results through engine, app-runtime, and process adapters.
- [ ] Application projections contain no losing/superseded output after settlement.
- [ ] Process kill/restart agrees with uninterrupted execution.
- [ ] Failure capsules identify participant, action, layer, and replay instructions without sensitive production logs.

## Milestone 6: Distributed Campaigns And Operations

### 6.1 Container and VM execution

- [ ] Add containers before VMs.
- [ ] Add network partition, latency, bandwidth, and loss controls.
- [ ] Add relay and participant host restarts.
- [ ] Add slow/full disk and database contention.
- [ ] Add mixed-build rolling upgrades.
- [ ] Use VMs only for kernel, filesystem, network, or host-isolation behavior containers cannot represent.

### 6.2 Execution lanes

- [ ] PR lane: strict formal gate, fixed vectors, small engine/reference/relay cases.
- [ ] Nightly lane: seed matrices, file-backed storage, crash matrix, retained relays, mutation subset.
- [ ] Weekly/manual lane: process/container soak, resource and constant sweeps.
- [ ] Release-hardening lane: mixed-version and incident-derived corpus.
- [ ] Define wall-clock, CPU, memory, disk, artifact-retention, and flake budgets for every lane.

### 6.3 Failure corpus lifecycle

- [ ] Automatically save failing seeds/capsules.
- [ ] Minimize semantically, not only by generic step removal.
- [ ] Classify product defect, protocol ambiguity, environment failure, or expected resource refusal.
- [ ] Promote stable synthetic regressions into vectors.
- [ ] Track recurrence and time-to-diagnosis.

### Milestone 6 Exit Gate

- [ ] Campaigns are repeatable from saved configuration and artifact manifests.
- [ ] A failing process/container run can be reduced into a smaller adapter when the defect is not layer-specific.
- [ ] Resource and flake budgets prevent silent campaign degradation.
- [ ] Release hardening produces a reviewed convergence evidence bundle.

## Cross-Milestone Verification Matrix

| Verification layer | Primary purpose | PR | Nightly | Weekly/manual |
| --- | --- | --- | --- | --- |
| Engine unit/integration | Local state, persistence, fail-closed outcomes | yes | yes | yes |
| Portable vectors | Cross-implementation semantic contracts | yes | yes | yes |
| Property/metamorphic tests | Schedule, restart, and constant invariance | bounded | expanded | expanded |
| Independent reference model | Detect shared implementation assumptions | bounded | expanded | expanded |
| Tamarin | Symbolic safety/security and bounded executable cases | yes | yes | yes |
| State-machine model | Liveness, fairness, clock, crash, resource counterexamples | bounded | expanded | on protocol changes |
| Retained-relay simulator | Input-set equality, offline sync, EOSE/backfill | smoke | expanded | sustained |
| App-runtime adapter | Projections and orchestration | smoke after M5 | expanded | sustained |
| Multi-process/container | OS/runtime/network failures | no by default | selected | sustained |
| Mutation campaign | Test adequacy | small sentinel set | targeted set | full targeted set |

## Standard Scenario Artifact

Every adapter eventually emits the same logical envelope:

```text
scenario source
canonical Scenario IR
expanded action schedule
adapter capabilities and versions
policy and constant snapshot
captured transport artifacts
virtual and wall-clock timeline
logical input/output/disposition ledger
exact state commitments
resource observations
assertion failures
quiescence or terminal-state explanation
minimized reproducer
```

The artifact schema must distinguish synthetic shareable data from sensitive incident evidence. Local sensitive
artifacts use restrictive creation helpers and are never committed.

## Immediate Implementation Sequence

The first implementation series is deliberately ordered:

1. strict Tamarin warning/derivation gate;
2. assurance contract and constant-ledger review against the canonical protocol;
3. exact state/message oracle;
4. public subject boundary and complete quiescence;
5. failure capsule;
6. Scenario IR v2;
7. retained multi-relay model;
8. required workload families;
9. independent/liveness models and mutation campaign;
10. app-runtime, process, and distributed adapters.

Large-scale process or VM work does not begin before Milestone 1 establishes that the simulator can recognize an
incorrect result.

## Progress Log

| Date | Work item | Result | Evidence |
| --- | --- | --- | --- |
| 2026-07-30 | 0.1 initial assurance contract | Recorded target statement, assumptions, and first safety/liveness/restart/diagnostic claims | This document |
| 2026-07-30 | 0.2 initial constant ledger | Classified current versioned policy, engine resource bounds, app scheduler values, and input-recovery heuristics | This document and linked source constants |
| 2026-07-30 | 0.3 strict formal gate | Added `--quit-on-warning` and a configurable 60-second derivation-check timeout; the strengthened full model passed with all 76 lemmas verified in 45.17 seconds | `just tamarin` |
| 2026-07-30 | Milestone 0 baseline verification | Default policy pin passed 5 tests; distributed convergence passed 75 tests with explicit test-policy overrides; formatting, diff whitespace, and 48 local documentation links passed | Commands in “Milestone 0 verification” plus local link check |
| 2026-07-30 | 0.1 assurance evidence ownership | Mapped every assurance claim to protocol/architecture text, current named evidence, and its remaining milestone owner; recorded five protocol decisions/gaps | Assurance verification ownership and protocol decision register |
| 2026-07-30 | 0.2 constant audit ownership | Completed the scoped code audit and mapped every ledger row to named current tests plus remaining campaign/model ownership | Constant verification ownership |
| 2026-07-30 | 0.3 proof scope and model decision | Added explicit input-set/run-policy premises to agreement lemmas, classified all 76 lemmas, and selected TLA+/TLC as the independent liveness/fairness model | Tamarin model/README and state-machine decision |
| 2026-07-30 | 0.2 constant ledger drift gate | Added a 23-ID/25-declaration inventory and a fast-CI source audit for newly unreviewed convergence constants | `just convergence-ledger-gate` |
| 2026-07-30 | 0.1 protocol assurance contract | Merged the protocol contract defining conditional liveness, pass-partition invariance, the unbounded-self-update non-guarantee, exact conformance state, and transport-deferred/resource-refused availability | [marmot#410](https://github.com/marmot-protocol/marmot/pull/410), merge `4ad4ae2` |
| 2026-07-30 | 0.1 typed deferred/resource outcomes | Replaced ambiguous `Stale(PeelFailed)` results with typed transport availability, protocol rejection, and stale-disposition categories; retry-budget release no longer terminally deduplicates exact-ID redelivery | `cargo test -p cgka-engine --features test-policy-overrides --test deferred_peel_lifecycle`; `--test ingest`; `--test fork_detection` |
| 2026-07-30 | 0.1 resource-refusal recovery signal | Resource refusal immediately arms one account-wide history backfill per group epoch; ordinary transport deferral retains the existing evidence threshold | `cargo test -p marmot-app client::epoch_stall --lib` |
| 2026-07-30 | Milestone 0 completion verification | Rebased onto MDK `master` at `1b949655`; fast CI, the full feature-enabled engine suite, full simulator suite, session suite, focused app deferral/backfill coverage, and all 76 strict Tamarin lemmas passed | `just fast-ci`; `cargo test -p cgka-engine --features test-policy-overrides`; `cargo test -p cgka-conformance-simulator`; `cargo test -p cgka-session --features test-policy-overrides`; focused `marmot-app` tests; `just tamarin` |
