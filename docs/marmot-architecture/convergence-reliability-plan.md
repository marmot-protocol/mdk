---
title: "Convergence Reliability And Simulation Plan"
created: 2026-07-30
updated: 2026-08-03
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
> either reaches exactly equivalent cryptographic and application state within the scenario's declared observation
> budget, with convergence latency characterized separately, or reaches the same explicit, deterministic, diagnosable,
> replayable, and durably recoverable non-progress outcome.

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
- scripted `ScenarioSpec` v2 cases and portable vectors;
- seeded delivery schedules, generated chaos families, reports, and conservative failure minimization;
- symbolic selector/canonicalization properties and engine integration tests;
- encrypted file-backed restart coverage;
- incident archetype synthesis from forensic audit exports;
- a Tamarin model for bounded selector, lifecycle, and output-safety scenarios.

The baseline is useful scaffolding, but it is not yet the target reliability lab:

- legacy portable `ClientsConverged` remains an epoch/member-count check, although strict reliability scenarios now use
  exact canonical state, ledgers, pending-work sentinels, and active decryptability;
- the engine, independent reference, and retained-relay subjects share one compiled scenario contract, but app-runtime
  and process adapters do not exist yet;
- the retained-relay adapter covers deterministic offline/history behavior, but sustained relay campaigns and
  production runtime synchronization are future milestones;
- queue emptiness does not prove all client, pass, publication, retry, deferred, or projection work is quiescent;
- generated storms are structural tests rather than sustained rate/volume campaigns;
- scenario seeds do not reproduce randomized MLS bytes;
- the independent selector/canonicalization model covers bounded authenticated input, dependency, witness, selection,
  and disposition behavior, while production persistence remains exercised by engine and retained-relay subjects;
- TLA+/TLC and Stateright now cover a bounded lifecycle/fairness state space, while real process/VM scheduling and
  production app-runtime lifecycle behavior remain future milestones;
- Tamarin remains focused on symbolic safety/security and executable bounded policy cases rather than wall-clock or
  process scheduling.

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
11. **Clocks are dependencies.** Engine campaigns inject advancing monotonic and wall clocks. Process adapters define
    their own observable quiescence contract rather than pretending an in-process progress snapshot is universal.
12. **Equivalence is layered.** Shared protocol state, scenario-input/application-output dispositions, and local
    operational/resource diagnostics are compared separately. Local diagnostic differences cannot silently weaken
    shared-state or output equality.

## Milestone Summary

| Milestone | Outcome | Status | Exit gate |
| --- | --- | --- | --- |
| 0. Assurance foundation | Guarantees, assumptions, constants, and formal gate are explicit | complete | Every constant is classified; formal warnings fail CI; protocol decisions are named |
| 1. Trustworthy engine black box | Exact oracle, public subject boundary, full quiescence, replay capsules | complete | Known semantic mutations fail and captured failures replay |
| 2. Scenario IR and retained relays | One adapter-neutral DSL/IR plus realistic offline/history sync | complete | One compiled case runs against reference, engine, and retained-relay adapters |
| 3. Adversarial campaigns | Sustained real-world workloads, resource sweeps, incident import | complete | Headline workload families produce bounded, diagnosable results |
| 4. Independent verification | Reference model, liveness model, mutation adequacy, protocol decision gate | complete | Model and tests detect seeded policy/lifecycle defects |
| 5. App and process simulation | Real projections and lifecycle in one or many isolated runtimes | not-started | The same case agrees in-process and across N processes |
| 6. Distributed campaigns | Container/VM/network/disk/version hardening and campaign operations | not-started | Repeatable soak and release campaigns retain actionable artifacts |

## Milestone 0: Assurance Foundation

### 0.1 Guarantee And Assumption Contract

Status: `complete`

The initial assurance matrix is below. “Required verification” names the minimum evidence before a claim can become
`established`.

| ID | Claim | Required assumptions | Required verification | Status |
| --- | --- | --- | --- | --- |
| S1 | Same retained anchor, authenticated input closure, policy version, and engine version produce the same canonical branch and exact state | Finite relevant input set; every compared client possesses the same validated dependency closure | Independent reference comparison; schedule/restart metamorphic tests; bounded model | partially-covered |
| S2 | Application output after settlement is exactly the payload/state-change projection of the selected branch | MLS and Marmot payload authentication succeeds; invalidations reach projection | Exact scenario-input/output ledger; losing-branch and superseded-state scenarios; Tamarin output lemmas | partially-covered |
| S3 | Missing retained state, invalid policy, corrupt frozen input, and exhausted replay budget never apply a partial candidate result | Storage reports failures accurately; fail-closed errors are durable or retryable by contract | Engine tests, crash matrix, resource campaigns, seeded mutations | partially-covered |
| S4 | Publish-before-apply and convergence lifecycle changes are torn-write-free | Storage transaction contract holds; external publication results are accurately reported | Storage/engine lifecycle tests; kill/restart at each durable transition | partially-covered |
| S5 | For one retained authenticated input set and fixed horizon eligibility, changing delivery partitioning across convergence passes or scheduler timing does not change the eventual canonical result | All pending passes are eventually revisited; required retained state remains available; no compared run crosses a semantic retention/eligibility boundary | Controlled pass-partition and virtual-time metamorphic tests; separately classified horizon-assumption violations | partially-covered |
| L1 | After relevant input closes and all required history is locally available, convergence reaches `Settled` or a named durable fail-closed/non-progress state with an explicit repair path | Client continues executing; resource policy admits the workload | Bounded state-machine liveness model; engine and retained-relay scenarios; repair-path tests | partially-covered |
| L2 | Outbound work blocked by convergence is eventually released, regenerated, or terminated with an explicit outcome | L1 assumptions; publication path eventually returns a result | Scheduler/outbound ledger assertions; crash/restart scenarios | partially-covered |
| L3 | Marmot does not guarantee that a privileged administrative transition becomes canonical while valid selection-relevant input, including ordinary self-updates, continues without bound | The bounded post-settlement preparation opportunity remains enforced; stronger progress requires eventual relevant-input closure | Adversarial model and sustained simulator family; bounded preparation-opportunity tests | specified |
| S6 | Clients are exactly equivalent only when the canonical conformance projection, including its domain-separated exporter commitment, matches | Synthetic/local conformance execution; raw exporter secret never leaves the test process | M1.1 exact snapshot comparison; mismatched-member, component, disposition, output, and commitment sentinels | specified |
| S7 | Shared protocol state, exact scenario-input/application-output dispositions, and local operational diagnostics remain distinct comparison layers | Every scenario input has a stable action id; adapters declare observable capabilities | M1.1 disposition ledger; M2 adapter schema; M5 projection comparison | partially-covered |
| R1 | Crash/reopen from any durable convergence phase is equivalent to uninterrupted execution | Database and required WAL/sidecars remain intact; no storage corruption unless scenario declares it | File-backed crash matrix and process-kill replay | partially-covered |
| R2 | Clients with unequal relay histories converge after the histories reconcile | Relevant events remain retained and are eventually fetched; same policy/version | Retained multi-relay scenarios with EOSE, backfill, and set equality | partially-covered |
| R3 | A runtime can determine the completeness claim it is making for acquired relay history and can invoke a stronger reconciliation path when incremental cursors are insufficient | Relay EOSE and query completion are observable; at least one full-history/set-reconciliation mechanism is available | Since-floor/EOSE matrix; full-history backstop tests; retained-relay adapter | partially-covered |
| D1 | Every observed failure is attributable to a stable action, policy, state transition, or resource bound and can be replayed; silent input absence requires the separate R3 completeness signal | Failure manifests in an observable layer; failure artifact completes successfully; sensitive evidence remains local | Failure-capsule self-replay and schema tests; R3 absence detection | partially-covered |

#### Assurance verification ownership

This table assigns every claim a current evidence owner and the work item that owns the remaining gap. A named existing
test is evidence for only the behavior in its name; it does not establish the larger claim by itself.

| ID | Normative/architecture source | Current evidence | Missing evidence owner |
| --- | --- | --- | --- |
| S1 | Protocol `convergence.md` branch selection; local canonicalization contract “Determinism and convergence” | Tamarin `same_input_set_converges`; `prop_candidate_graph_selection_is_order_invariant`; `prop_stored_convergence_restart_equivalence` | M1.1 exact-state oracle; M4.1 independent reference model; M4.2 arbitrary schedule/lifecycle model |
| S2 | Protocol `convergence.md` “Applying the selected branch”; local canonicalization output contract | Tamarin application-output/invalidation lemmas; `engine_emits_only_canonical_branch_app_messages_after_convergence`; `rebuilt_engine_emits_losing_branch_app_invalidation_after_convergence` | M1.1 exact scenario-input/output ledger; M5.1 app projection adapter |
| S3 | Protocol retained-anchor error rules; local canonicalization errors and fail-closed replay contract | Tamarin missing/beyond-anchor lemmas; `frozen_pass_member_tampering_fails_closed_to_unrecoverable`; `missing_frozen_pass_member_fails_closed_to_unrecoverable`; replay-budget unit tests | M3.1 end-to-end resource exhaustion; M4.3 mutations |
| S4 | Protocol publish lifecycle and bounded-pass persistence; local multi-step-state-change rules | `convergence_pass_round_trips_updates_and_cascades`; `collecting_pass_restart_preserves_remaining_window_and_backward_clock_fails_closed`; `reopen_after_crash_during_publish_recovers_stranded_pending_commit`; crash-recovery SQLite tests; transaction-boundary contention tests from [MDK #1191](https://github.com/marmot-protocol/mdk/pull/1191) | [MDK #1184](https://github.com/marmot-protocol/mdk/pull/1184) inbound commit mirror atomicity; M3.1 complete durable-transition kill matrix; M5.1 runtime crash matrix |
| S5 | Protocol pass-partition invariance and bounded collection window; relay telemetry claim that quiescence is not a correctness boundary | `prop_quiescence_gate_controls_settlement`; cutoff and scheduler unit tests | M1.3 controlled partition metamorphic test; M3.2 cross-value campaign; M4.2 scheduler model |
| L1 | Protocol pass freeze and completion rules; group convergence status | Individual settle/fail-closed integration tests; stale collecting/frozen pass compensation at the current tip from [MDK #1182](https://github.com/marmot-protocol/mdk/pull/1182) | M4.2 TLA+/TLC liveness specification; M2.3 retained-relay scenarios; named repair tests for every durable non-progress state |
| L2 | Protocol outbound gating; local queued-intent lifecycle | Tamarin queued-outbound lemmas; `engine_queues_app_send_until_convergence_is_settled`; `trait_advance_convergence_drains_queued_outbound_intent`; scheduler tests | M1.3 complete quiescence; M3.1 crash/failure workload |
| L3 | Protocol same-epoch priority and depth rules; no sustained-progress guarantee currently stated | `convergence_privileged_remove_beats_grinding_ordinary_self_update`; `continuous_inbound_cannot_starve_admin_attempt` | M3.1 sustained self-update family; M4.2 fairness model; protocol decision PDR-2 below |
| S6 | Protocol `foundation/conformance.md`, adopted by [marmot#410](https://github.com/marmot-protocol/marmot/pull/410) | Domain separation and 33-byte commitment prefix checked in the protocol PR | M1.1 public snapshot API and exact-equivalence sentinels |
| S7 | Protocol conformance projection and input-disposition requirements | M1.1 exact canonical snapshot plus commit/proposal/application disposition ledger; M2.2 common adapter observation schema | M5.1 app projection layer |
| R1 | Protocol durable pass wall/monotonic deadline rules; local storage/restart contract | Injectable paired convergence clocks from [MDK #1195](https://github.com/marmot-protocol/mdk/pull/1195); `collecting_pass_restart_preserves_remaining_window_and_backward_clock_fails_closed`; `h5_kill_before_historical_apply_commit_preserves_live_inputs`; `h6_kill_after_retained_anchor_rewind_recovers_live_snapshot` | M3.1 every-phase crash matrix; M5.3 process kill/reopen |
| R2 | Relay telemetry EOSE/backfill/reconciliation architecture; protocol requires equalized relevant history for equivalent selection | `stalled_epoch_backfill_recovers_below_floor_backlog_when_armed`; `next_event_returns_when_a_live_delivery_arms_the_epoch_backfill`; retained-relay unequal-history reconciliation | M3.1 sustained unequal-history family |
| R3 | Relay sync/backfill architecture; incremental cursors do not establish full offline history | Since-floor regressions plus retained-relay EOSE, quiet-history, full-backfill, and set-reconciliation scenarios | M5.1 production runtime adapter |
| D1 | Local forensic audit/report contracts and privacy rules | Failure-capsule self-replay, generated reports, oracle coverage, conservative minimizer, incident synthesis, and explicit relay-completeness observations | M3.3 exact incident import; production R3 absence detection |

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
| PDR-6 | Distinguish deterministic processing of one frozen batch from invariance under different pass partitions of the same retained input; classify runs that cross anchor/app-retention eligibility as assumption violations, not scheduler counterexamples | test-method-required | M1.3 controlled metamorphic harness; M3.2 witness-expiry/deferred-commit/anchor-pruning matrix; M4.2 model |
| PDR-7 | Define the supported repair outcome for a joiner/invite/device-add that lands only on a losing branch | protocol-decision-required | M3.1 workload; M4.2 lifecycle model; M5.1 user-visible repair projection |
| PDR-8 | Define what relay-history completeness claim implementations make after EOSE, cursor rebuild, and long offline intervals, including the full-history or set-reconciliation backstop | architecture/protocol-decision-required | R2/R3; M2.3 retained relay; M5.1 runtime |

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
| P4 | `V1_SETTLEMENT_QUIESCENCE_MS` | 1,000 ms | semantic, scheduler | Closes a live-input window after delivery jitter | Too low raises post-settle reorgs; too high stalls outbound work | intended no after input closure; may change intermediate passes | Virtual-time sweep, post-settle reorg metrics, retained-relay spread |
| P5 | `V1_MAX_CONVERGENCE_PASS_MS` | 5,000 ms | semantic, scheduler | Guarantees a collecting pass freezes under sustained relevant input | Too low fragments ordinary bursts; too high lets a flood hold the group collecting | intended no after all follow-up passes; may change pass membership | Sustained-flood test, cutoff restart matrix, controlled pass-partition fixed-point comparison |
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
| E7 | self-remove auto-commit jitter | 10 ms + [0, 40] ms (10–50 ms inclusive) | scheduler | Reduces synchronized automatic self-remove commits | Jitter changes ordering only, not admissible final behavior after closure | intended no | Seeded schedule invariance and collision tests |
| E8 | `MAX_DEFERRED_PEEL_RESIDENCE_MS` | 30 days | resource, scheduler | Durably bounds opaque local transport residence across stable contexts and restart | Release is `resource_refused`, exact-ID redelivery remains eligible, and backwards wall movement cannot expire early | may affect locally available input until refetch | First-join opaque reproducer, restart/backwards-clock test, redelivery, and app backfill signal |

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
named source families for newly introduced constants that have not been reviewed into this ledger. It currently checks
declaration presence and coverage, not literal values; production-value drift remains guarded by policy pin tests, and a
future inventory revision should encode machine-checked expected values where the Rust expression is stable enough.

| IDs | Current source/test owner | Remaining verification owner |
| --- | --- | --- |
| P1 | `convergence.rs`; Tamarin anchor/stale lemmas; `engine_replays_late_same_epoch_commit_from_retained_anchor`; `engine_prunes_retained_anchor_snapshots_to_rewind_horizon` | M3.1 delayed-history depth sweep; M4.1 reference model |
| P2, P3 | `canonicalization.rs` and `wire_format.rs`; `app_message_window_must_match_engine_max_past_epochs`; `app_message_expired_is_relative_to_the_passed_reference_tip`; `send_preflight_terminally_retires_deferred_app_message_outside_past_epoch_window` | M3.1 multi-commit offline flood; M1.1 exact message ledger |
| P4 | `canonicalization.rs`; `prop_quiescence_gate_controls_settlement`; `engine_duplicate_convergence_input_does_not_reset_quiescence`; `app_witness_beside_competing_commits_resets_convergence_quiescence` | M3.2 quiescence sweep; relay-spread/reorg telemetry |
| P5 | `canonicalization.rs`; `convergence_pass_freezes_at_absolute_cap_under_continuous_selection_input`; `input_at_effective_cutoff_is_retained_for_the_next_generation`; collecting-pass restart test | M3.1 sustained flood; M3.2 eventual fixed-point comparison |
| P6, P7, P8 | `convergence.rs`; generated policy cases; Tamarin score/bound lemmas; multi-device witness-deduplication replay probe | M3.1 group-size/device/Sybil sweeps; M4.1 independent reference |
| E1 | `message_processor/mod.rs`; existing multi-pass integration flows | M3.1 force exhaustion, verify durable continuation and no partial settle |
| E2, E3, E4, E8 | `message_processor/mod.rs`; `deferred_peel_retry_budget_refuses_without_terminal_dedup`; `deferred_peel_residence_survives_restart_and_backward_clock`; `peel_deferred_rows_capped_per_group_under_flood`; `resource_refusal_signals_immediately_once_per_epoch`; strict first-join chaos case; deferred retry/context tests | M3.1 fairness/restart/redelivery campaign |
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
the exact state/scenario-input oracle is the first Milestone 1 slice.

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

### 1.1 Exact state and scenario-input oracle

Status: `complete`

- [x] Add exact sorted member identities to strict observations, while also preserving nonblank leaves in MLS leaf-index
  order.
- [x] Include epoch, selected branch commitment, admin policy, application profile, required capabilities, exact
  app-component state, and group lifecycle/convergence state.
- [x] Record a generalized scenario-input disposition ledger for commits, proposals, and application messages, keyed by
  stable scenario action id and distinguishing sent, accepted, delivered, deduplicated, expired, invalidated, rejected,
  resource-refused, rolled-back, and pending outcomes.
- [x] Add a test-only privacy-safe cryptographic state commitment based on MLS exporter state.
- [x] Prove bidirectional decryptability after apparent convergence.
- [x] Add strict expectations for `ClientsExactlyEquivalent`, `ScenarioInputLedger`, `NoPendingWork`, and
  `ClientsBidirectionallyDecryptable`.
- [x] Project terminal disband tombstones into exact canonical state without device-local authorship metadata.
- [x] Make strict oracle behavior the default for reliability campaigns, with an explicit exploratory opt-out.

Verification:

- same member count but different member identities fails;
- same public metadata but different exporter commitment fails;
- duplicate application delivery appears once in the scenario-input ledger;
- commit, proposal, and application actions retain stable scenario ids and exact current dispositions;
- losing-branch payload/state output is absent or explicitly invalidated;
- queued, delayed, unread, unconfirmed-publish, and retained transport-deferred work addressed to the observed client
  fail `NoPendingWork`; a deliberately dropped object does not masquerade as local pending work, and its missing
  recipient delivery fails an independent ledger/output assertion;
- every directed application-message edge succeeds after settled convergence; a deliberately missed commit produces a
  visible one-way decryptability failure while the reverse past-epoch edge succeeds;
- terminal disband state survives restart and compares independently of device-local committer-leaf metadata;
- generated reliability cases finish with a global drain, exact observation, and `NoPendingWork`; report runs fail on
  weak-oracle coverage unless explicitly invoked with `--allow-weak-oracle`.

The exact-state interface is feature-gated to the simulator. Legacy observations remain unchanged for existing vectors;
strict scenarios opt in with `observe_client_exact` / `observe_exact`, `ClientsExactlyEquivalent`, and
`ScenarioInputLedger`. The ledger names every commit, proposal, and application action independently of randomized
transport/MLS ids, correlates aliases through the feature-gated durable conformance view, and uses the deterministic
inner application event only for delivery correlation. It preserves the protocol distinction between authenticated
acceptance and pre-admission `TransportDeferred`. `NoPendingWork` adds an instantaneous, client-scoped local-progress
snapshot across group-scoped engine state, client-addressed bus state, and the client's scenario-input ledger. It is not
an end-to-end delivery assertion for objects removed by an explicit transport fault; required delivery is checked
through recipient ledger/output expectations. It deliberately does not replace Milestone 1.3's structural virtual-time
quiescence test. The active
decryptability probe sends one exact logical event per client, correlates every directed delivery by logical event id,
and retains the recipient ledger disposition for failed edges. Exact canonical state is a tagged live-or-disbanded
projection; the terminal form is derived from the durable authenticated tombstone and excludes
`local_was_committer_leaf`, which is device-local rather than a shared protocol fact.

This Milestone 1.1 slice supplies exact engine observations and sentinels; it does not close the cross-layer Scenario IR
operational-semantics and adapter-refinement acceptance criteria tracked in
[#1189](https://github.com/marmot-protocol/mdk/issues/1189). Those remain owned by Milestones 2.1 and 2.2 before
campaign/process expansion relies on equivalence across adapters.

The strict campaign migration deliberately exposed three pre-existing reliability failures that the legacy observation
point hid. Two are resolved without weakening the oracle:

- [MDK #1196](https://github.com/marmot-protocol/mdk/pull/1196) made simulator `FailPending` mean definite
  non-publication: it atomically retracts every matching undelivered commit/Welcome before local rollback and refuses
  the operation after any artifact reaches a recipient mailbox.
- [MDK #1192](https://github.com/marmot-protocol/mdk/pull/1192) terminally retires proposal rows and proposal-arrival
  schedule signals consumed by a confirmed or converged commit, including across restart.

The remaining engine-state failure was closed by durably bounding opaque local transport residence: after controlled
virtual time, the pre-join object is released as `resource_refused`, exact-ID redelivery remains eligible, and the
strict scenario-input/pending-work boundary settles without claiming a protocol stale reason. Report campaigns run the
complete strict expectations by default. The mixed large storm now retains its application phase through the
interleaved commit storm and pins each observed recipient's ordered payload set, so commit convergence cannot hide
dropped or duplicated application traffic.

### 1.2 Public subject boundary

Status: `complete`

Completion here means the explicit engine-subject contract and its capability boundary are implemented. The
publication-control slice of Scenario IR v2 is also complete: every built-in runner uses exact outbound polling and
typed acknowledgement, and the temporary auto-confirming compatibility lifecycle has been removed. Broader workload,
rate, topology, assertion, and schema work remains owned by Milestone 2.1.

- [x] Define a simulator-owned `ConvergenceSubject` interface that keeps scenario semantics in the runner and exposes
  semantic engine operations through declared adapter capabilities.
- [x] Implement the first engine-adapter vertical slice: create/mutate, publication confirmation/failure, application
  send, transport delivery/ingest, event/exact/admin observation, active decryptability probing, and crash/reopen.
- [x] Add a capability-gated, serializable virtual-time advance backed by one shared paired clock; keep time advancement
  separate from `Tick`, which selects the participant runtimes that wake and observe elapsed deadlines.
- [x] Add explicit public outbound polling/acknowledgement so later adapters can model publication progress without
  exposing harness queues.
- [x] Cut ScenarioSpec and all repository-owned vectors/generators over to v2 `acknowledge_outbound` operations; remove
  direct pending confirmation/failure from the subject contract and delete the compatibility constructor and client
  lifecycle branches ([MDK #1207](https://github.com/marmot-protocol/mdk/issues/1207)).
- [x] Split normal black-box execution from the explicitly named `ConvergenceFaultSubject` queue/partition mutation
  capability; reserve a named white-box storage-fault capability for a future adapter.
- [x] Reject scenarios that require unsupported subject capabilities before execution.
- [x] Refresh the local canonicalization contract against the adopted protocol before freezing the public observation
  schema; keep normative behavior in the protocol repo and implementation/diagnostic detail here.

### 1.3 Full-system quiescence

Status: `complete`

- [x] Add an injectable paired monotonic/wall convergence clock and use it for pass deadlines, cutoff decisions, restart
  rebasing, and deterministic engine/harness tests.
- [x] Expose that clock through the subject-level `virtual_time` capability and portable `advance_time` scenario step;
  route subject `Tick` through the same clock so global time can advance while participant runtimes remain paused.

- [x] Expose a sanitized structural progress token, runnable work, earliest next wake-up, deferred/retry work, outbound
  work awaiting acknowledgement, and terminal blockers; include inbox, delayed messages, pass phase, and durable
  transitions.
- [x] Drive subject operations and scheduled wakes from the shared advancing monotonic/controlled wall clock; do not
  infer time progress from repeated calls at one synthetic timestamp or wait on real wall time.
- [x] Compute a bounded virtual-time fixed point from structural work and the earliest next wake-up. Treat step, time,
  and work limits only as watchdog/performance evidence, not as the definition of quiescence.
- [x] Report which subsystem prevents quiescence.
- [x] Bound quiescence waiting by scenario policy and emit a terminal timeout artifact.
- [x] Add controlled metamorphic runs that preserve retained input and horizon eligibility while varying delivery across
  one frozen batch versus multiple convergence passes; report retention/anchor assumption violations separately.

### 1.4 Deterministic failure capsules

Status: `complete`

- [x] Define a versioned capsule schema.
- [x] Save the report's single authoritative scenario, seeds, expanded schedule, policy/constant snapshot,
  adapter/binary versions, a bounded tail of captured wire bytes, virtual time, scenario-input/output ledger, state
  commitments, and resource measurements.
- [x] Replay a capsule without regenerating MLS bytes.
- [x] Keep real incident artifacts local and restrictive-by-construction.
- [x] Promote minimized synthetic failures into portable vectors when they define durable behavior.

Capsule v1 is the local `failure_capsule.rs` data contract plus
`schemas/failure-capsule.v1.schema.json`. Report campaigns automatically emit a portable logical capsule for failed
steps, oracle violations, weak-oracle failures, and quiescence failures. A capsule records the complete report (including exact state,
input ledgers, and output observations), generated seed metadata, a virtual-time-expanded action schedule, exact
quiescence policies, the engine constant snapshot, adapter/binary versions, and bounded resource counters. Failure
evidence retains at most the newest 256 transport objects and 1 MiB of serialized transport data while recording
observed, retained, and dropped object/byte counts. A warning-only strict-oracle capsule retains no wire bytes or key
material. Byte replay uses the same delivery limits and a 16 MiB checkpoint ceiling; an oversized selected tick is
skipped. Stable full fingerprints combine a normalized terminal classification, first failing action, failure kind,
and observed-state digest. The reducer instead preserves semantic failure identity (classification, action type, and
failure kind), so removing irrelevant steps is not defeated by shifted action indices or a changed trace digest.

The optional engine byte-replay payload is deliberately separate from logical scenario replay. Sensitive capture is
off by default and requires `--capture-sensitive-replay`. The engine adapter then exports at most one checkpoint, for
the final planned recipient tick, rather than serializing every client database before every tick. Its pre-input
SQLite/OpenMLS checkpoint includes any active durable convergence pass, the exact mailbox `TransportMessage` objects,
and the resulting typed engine fingerprint. The report runner keeps the logical capsule `synthetic_shareable` and
writes the checkpoint to a separately named `sensitive_local` sibling; if execution stops before the selected tick, no
replay sibling is emitted. Replay therefore never asks OpenMLS to regenerate a commit. Ordinary epoch rollback
snapshots intentionally do not rewind pass scheduling; only this replay envelope carries that additional state. The
checkpoint contains key material, and the writer creates directories/files with owner-only modes. The report CLI
accepts `--replay-capsule FILE` and verifies the captured engine fingerprint. `promote_failure_capsule_to_vector` accepts only
`synthetic_shareable` capsules, preserves the intended exact or semantic expectation rather than the buggy observed
trace, and uses the fingerprint-preserving minimized scenario when present. It refuses capsules without a portable
expectation.

### Milestone 1 Exit Gate

- [x] A wrong exact state cannot pass as converged.
- [x] A normal scenario cannot access engine/storage internals.
- [x] Hidden pending work prevents quiescence.
- [x] A captured byte-level failure replays with the same outcome.
- [x] Targeted semantic mutations are detected.
- [x] Every durable fail-closed/non-progress state names a tested repair or terminal user-visible outcome.

The Milestone 1 mutation sentinels deliberately alter member identity
(`exact_equivalence_rejects_same_count_with_different_member_identities`), exporter commitment
(`exact_equivalence_rejects_different_exporter_commitments`), input-ledger disposition
(`scenario_input_ledger_expectation_is_exact`), pending-work state
(`no_pending_work_requires_an_empty_exact_progress_snapshot`), a directed decryptability edge
(`bidirectional_decryptability_requires_every_directed_edge`), and the captured byte delivery set
(`exact_captured_commit_replays_from_sensitive_checkpoint`). The campaign producer and CLI path are pinned by
`failed_campaign_capsule_contains_a_replayable_tick_witness`. This is the minimum oracle-adequacy gate; Milestone 4.3
still owns a broad implementation mutation campaign.

Durable non-progress/fail-closed outcome inventory:

| Durable state/disposition | Named recovery or terminal outcome | Current test evidence |
| --- | --- | --- |
| `PendingPublish` / unresolved outbound | Transport acknowledgement commits it; `ReachedNoEndpoint` atomically retracts artifacts and rolls back; a crash reopens stranded pending state | `definite_publish_failure_retracts_commit_before_local_rollback`; `reopen_after_crash_during_publish_recovers_stranded_pending_commit` |
| `Merging` / `Recovering` / active pass | Scheduled convergence drains runnable work; inherited stale passes are discarded and reseeded at the current tip | `stale_pass_base_epoch_reopens_at_the_current_tip_instead_of_halting`; `frozen_stale_pass_base_epoch_reopens_at_the_current_tip_instead_of_halting` |
| `Retryable` message | Dependency arrival or rollback replays it; an invalid replay retires terminally | `future_epoch_app_message_stays_deferred_until_commit_arrives`; `buffered_retryable_peer_message_is_retired_terminal_after_replay` |
| `PeelDeferred` transport | Changed peel context retries it; capacity/retry/residence exhaustion emits typed `resource_refused`, releases the row, and preserves exact-ID redelivery | `deferred_peel_retries_after_epoch_advance`; `deferred_peel_retry_budget_refuses_without_terminal_dedup`; `deferred_peel_residence_survives_restart_and_backward_clock`; `peel_deferred_rows_capped_per_group_under_flood` |
| `ConvergenceDeferred` input | Later dependency/evidence makes it eligible; falling below retained history terminally expires/invalidates it; it does not itself hold the scheduler open | `commit_with_missing_parent_is_deferred`; `deferred_commit_ages_out_when_it_falls_below_retained_anchor`; `future_epoch_app_message_stays_deferred_until_commit_arrives` |
| Durable queued outbound intent | The scheduler regenerates and drains it; restart re-arms it; group removal terminally discards it | `trait_advance_convergence_drains_queued_outbound_intent`; `restart_schedules_groups_with_durable_queued_intents`; `drain_on_removed_copy_discards_queued_intents_without_error` |
| Hydration quarantine | Access/send/convergence are visibly refused; verified retry or authenticated rejoin repairs and replays retained input | `quarantined_group_rejects_valid_inbound_commit_on_do_ingest`; `retry_recovers_a_transiently_quarantined_group`; `rejoin_welcome_replays_and_retires_quarantine_retained_input` |
| `Unrecoverable` | Structural progress exposes a terminal blocker and the engine emits `GroupUnrecoverable`; verified replacement Welcome repairs it | `unrecoverable_halt_survives_engine_restart_until_verified_repair`; quiescence terminal-blocker tests |
| `Disbanded`, removed/self-evicted, `Failed`, or `EpochInvalidated` | Terminal state/disposition is explicit and cannot masquerade as pending work; disband retains an authenticated shared tombstone | `exact_oracle_projects_terminal_disband_tombstone_across_restart`; `deferred_peel_self_evicted_row_stays_failed_not_swept_processed`; losing-branch invalidation tests |

Typed operation failures such as `ReplayBudgetExceeded`, invalid policy, serialization, and storage failure remain
fail-closed and cannot return a partial candidate. They do not add another durable lifecycle/disposition: the capsule
records the failed step and the durable state already covered by this inventory. Milestone 3.1 still owns end-to-end
resource-exhaustion and recovery campaigns for those error sources.

## Milestone 2: Scenario IR And Retained Relays

Status: `complete`

### 2.1 Scenario IR v2 and authoring DSL

- [x] Land a minimal vertical slice first: versioned action/assertion IR, deterministic executor, stable action ids, and
  one engine-adapter scenario that round-trips through JSON.
- [x] Define the complete adapter-neutral JSON IR and JSON Schema.
- [x] Specify deterministic expansion and rate semantics (`repeat`, `parallel`, `rate`, `burst`, barriers, and virtual
  time) before adding authoring sugar.
- [x] Add human YAML authoring only after the canonical JSON IR/executor is stable; execute only canonical JSON.
- [x] Model accounts, devices, processes, roles, groups, relays, and policy/binary versions explicitly.
- [x] Add `repeat`, `parallel`, `rate`, `burst`, barriers, and virtual time with a recorded expanded schedule.
- [x] Add create, invite, remove, leave, self-update, group/admin state update, and application send.
- [x] Add executable offline/reconnect, delay, duplicate, omit, and withhold/release behavior.
- [x] Declare adapter-neutral process crash/restart and storage-fault steps for later process/storage adapters. No
  Milestone 2 adapter advertises those capabilities; whole-schedule preflight rejects them before action zero.
- [x] Replace queue indices with semantic action/message selectors.
- [x] Add `exactly`, `eventually`, `within`, `never`, and resource assertions.
- [x] Make a repository-owned clean cutover from `ScenarioSpec` v1 to v2 rather than retaining a runtime compatibility
  compiler; migrate fixed vectors, generated families, tests, and incident-replay synthesis together.
- [x] Add portable outbound poll/acknowledgement operations, migrate built-in runners to the explicit lifecycle, and
  remove the legacy-compatible constructor and dual client lifecycle
  ([MDK #1207](https://github.com/marmot-protocol/mdk/issues/1207)).

### 2.2 Adapter contract

- [x] Define capability discovery and compile-time rejection for unsupported operations.
- [x] Produce stable action ids and a deterministic expanded schedule.
- [x] Implement initial reference-model and engine adapters.
- [x] Require all adapters to emit the same observation/capsule schema.

### 2.3 Retained multi-relay model

- [x] Maintain a durable event history per relay.
- [x] Model publish fanout, subscriptions, query filters, EOSE, reconnect, since floors, and full backfill.
- [x] Make query completion explicit: distinguish relay EOSE from proven relevant-history completeness and record the
  completeness claim in every run.
- [x] Model relay-specific duplicate/order/visibility/omission behavior.
- [x] Model unequal client relay sets and later history reconciliation.
- [x] Add a set/full-history reconciliation backstop for the case where no qualifying live event arms the existing
  epoch-stall recovery path; evaluate NIP-77-like set reconciliation without making it a prerequisite.
- [x] Make quiet-group diagnosis explicit: a lack of new traffic must not be mistaken for complete history or healthy
  convergence, and reports must identify which reconciliation path was or was not attempted.
- [x] Keep the existing in-memory packet bus as a fast unit-test adapter, not offline-sync evidence.

### Milestone 2 Exit Gate

- [x] One compiled scenario runs unchanged against the reference, engine, and retained-relay adapters.
- [x] Offline participants recover from relay history rather than healed packet loss.
- [x] Relay disagreement followed by equalized history reaches exact state equivalence.
- [x] Unsupported adapter behavior fails before a partial run.

## Milestone 3: Adversarial Workload Campaigns

### 3.1 Required workload families

- [x] Offline retained-history flood with application traffic spanning many membership/state commits.
- [x] Sustained application traffic interspersed with proposals and commits.
- [x] Sequential self-update adversary racing privileged administrative changes.
- [x] Losing-branch joiner/invite/device-add, including an explicit successful repair, re-invite, or named unrecoverable
  user-visible outcome.
- [x] Unequal relay histories followed by reconciliation.
- [x] Crash/restart at every durable convergence transition.
- [x] Multi-group noisy-neighbor and per-group fairness.
- [x] Candidate graph/replay budget/resource exhaustion.
- [x] Multi-device account identity and witness deduplication.
- [x] App-message witness value: compare selection with/without witnesses, include proposal expiry and multi-parent
  commit cases, and decide whether the speculative mechanism earns its complexity.
- [x] Mixed binary and policy versions as controlled negative/compatibility tests. Do not require a production policy
  stamp before Scenario IR v2 can carry explicit policy versions.
- [x] Clock movement, scheduler delay, and timestamp/cursor attacks.

Each family varies schedule, storage mode, participant count, rates, restart placement, relay topology, and applicable
test-only constants while preserving a stable semantic oracle.

Policy compatibility decision: v1 does not add a policy-version wire field or app component. Scenario preflight rejects
mixed convergence policies but permits mixed binary versions when their policy and capabilities are equivalent. A
future incompatible policy revision must introduce an authenticated required capability or GroupContext application
component atomically with the new behavior; a diagnostic binary version is never protocol evidence.

The losing-branch invite campaign records a current protocol limit: the devices admitted by competing commits remain
non-equivalent after the canonical members settle. Reusing either already-consumed device signature key is not a valid
repair (`DuplicateSignatureKey`), so the named outcome requires an explicit local reset/rejoin with fresh device
state; v1 does not claim automatic repair for the stranded device.

### 3.2 Resource and sensitivity measurements

- [x] Record convergence latency and blocked-send duration.
- [x] Record pass count, reorg count/depth/lateness, and unresolved outcomes.
- [x] Record commit/proposal/application dispositions and logical delivery/expiry/invalidation results.
- [x] Record CPU time, peak memory, database size/writes, queue depth, and replay probes.
- [x] Sweep constants around the pinned value in explicit test-policy builds.
- [x] For P4/P5, preserve one retained input set and fixed eligibility horizons while varying pass partitioning; keep
  witness expiry, deferred commits, and anchor pruning as explicit boundary cases rather than accidental confounders.
- [x] Produce curves and boundary failures; never auto-tune production policy from simulator output.

`CampaignMeasurementsV1` is embedded in every scenario report. In-process reports record the wall time of the final
successful fixed-point convergence attempt when a scenario requests one (and mark it unavailable otherwise), true
queued-acceptance-to-publication/refusal wall time, decisions,
restart-preserved reorg histograms, dispositions, logical outcomes, unresolved work, maximum sampled transport depth,
exact completed OpenMLS replay probes, and file-backed SQLite/WAL/SHM size. The child-process campaign runner adds
per-case CPU time and peak RSS where the host exposes them, Linux OS-accounted write blocks, an explicit unavailable
field list elsewhere, and worker exit/signal/timeout failure. OS write blocks may be zero under caching and are not
presented as SQLite logical writes; every worker has a configurable hard deadline and is killed and reaped if it
exceeds it.

The feature-gated policy sweep holds retained input, tip, anchor, time, eligibility horizons, and all other constants
fixed, emits explicit rejected boundary points, and sets `production_auto_tuning_permitted` to false. P4/P5
pass-partition invariance continues to use `fixed_point_is_invariant_to_same_horizon_batch_partitioning`; expiry,
deferred-commit retirement, and retained-anchor pruning are covered by separately named boundary tests so a semantic
eligibility change cannot masquerade as a scheduler result.

### 3.3 Incident replay

- [x] Preserve normalized archetype synthesis for incomplete forensic evidence.
- [x] Add producer-attested normalized-history IR import when evidence is sufficient.
- [x] Carry evidence confidence and unavailable fields into the scenario artifact.
- [x] Keep sensitive exports and generated exact capsules out of version control.

`IncidentScenarioArtifactV1` makes replay fidelity and trust boundaries explicit. Existing Goggles audit exports
continue through the proven fork/convergence archetype synthesizers and are labeled
`outcome_equivalent_archetype` with derived confidence; the artifact names unavailable action history, participant
delivery order, transport bytes, and MLS state. Normalized import is `producer_attested_normalized_history`: it checks
coverage and bounds of the producer's step-to-source mapping, validates the Scenario IR, and requires the declared
outcomes to reproduce, but it does not independently prove semantic correspondence between arbitrary source events
and declared actions. Imported free-form labels and application payloads remain
`confidential_unredacted_scenario`, and the artifact records `unverified` until simulator reproduction changes it to
`reproduced`. Raw MLS bytes plus an engine checkpoint remain a separate opt-in sensitive local failure capsule.

The CLI writes the vector and evidence envelope owner-only and never copies the source export or checkpoint. These
files are not shareable without separate redaction and review. Real
exports belong under ignored `incident-exports/`; local generated output belongs under `target/` or ignored
`incident-replay-output/`; sensitive replay-capsule filenames are ignored repository-wide.

### Milestone 3 Exit Gate

- [x] The three headline workloads run both as small regressions and sustained campaigns.
- [x] Every resource exhaustion reaches a named fail-closed or retryable outcome with a tested repair path.
- [x] Campaign reports identify the first failing action and limiting resource.
- [x] Selected incident histories reproduce or clearly state why exact replay is impossible.

Offline retained-history catch-up, mixed application/commit traffic, and the self-update/admin adversary each have a
small default regression and a separately ignored sustained campaign. Replay-probe exhaustion fails closed while
retaining the frozen durable inputs, then succeeds after the test-only ceiling is removed; opaque transport limits use
the separately tested resource-refused/redelivery repair contract. Report measurement tests pin the first failing
action and resource-category limiting cause. Incident tests cover both a reproducing producer-attested history and the
ordinary legacy-export archetype whose evidence envelope explicitly names why exact action and byte replay are
unavailable.

Milestone 3 also closes a production amplification loophole: application-bearing candidate re-materialization now
draws from the same finite per-pass replay budget as the preceding candidate search instead of creating an unlimited
fallback budget. The v1 numeric constants and branch-selection policy are unchanged, but the fail-closed boundary is
observable: a near-ceiling pass can now return `ReplayBudgetExceeded` where the old path continued without a limit.
The shared-budget regression retains the frozen inputs and proves the same durable work succeeds when capacity is
restored.

Final integration verification also pins the topology compatibility boundary: resolving a legacy client-only
scenario may add explicit deployment records to its report, but does not change its historical client-derived member
identities. Explicitly authored account/device topology alone opts into account-derived credentials, including shared
credentials for two modeled devices of one account. The complete 41-case canonical scenario suite passes with this
boundary, including exact fixtures, bidirectional decryptability, generated chaos/delivery families, and strict
pre-join resource retirement.

The `just milestone3-ci` gate executes every catalog family (including the feature-gated witness and replay-budget
campaigns), all three sustained headline workloads, policy sweeps, and a file-backed isolated worker with a hard
timeout. GitHub's simulator job runs this gate in addition to the ordinary simulator and vector suites; the exit gate
is not based on compile-only catalog coverage.

## Milestone 4: Independent Verification And Adequacy

### 4.1 Independent reference model

- [x] Implement symbolic authenticated candidates, authorization, dependency closure, witness scoring, selection, and
  dispositions without calling production selector/canonicalization code.
- [x] Include proposal expiry and multi-parent commit sentinels, and keep an app-message-witness-free reference variant
  so the witness mechanism's marginal effect is measurable.
- [x] Differentially compare reference model, production selector, and full engine.
- [x] Keep model inputs small and shrinkable.

`reference_convergence` is deliberately type-independent of `cgka-engine`; a source guard rejects production selector
or canonicalizer imports. It models authenticated/authorized candidates and inputs, iterative parent closure,
multi-proposal commit dependencies, candidate-relative witness retention, selection, and keyed dispositions. The
committed Tamarin policy corpus and 256-case shrinkable proptest corpus compare its winner to the production selector;
named dependency/proposal sentinels compare dispositions to the production canonicalizer; and the bounded common
Scenario IR lifecycle comparison continues through the real OpenMLS engine subject. Authentication/authorization
negative cases remain reference-only because the engine canonicalizer's public comparison boundary is post-peeling.
The witness-free variant is an explicit model dimension, not a locally modified convergence policy.

### 4.2 Liveness and lifecycle model

- [x] Prototype the self-update/admin-progress case in TLA+/TLC and Stateright, then record the tool decision.
- [x] Model unequal histories, eventual input closure, pass freeze/settle, crash/restart, fairness, and resource failure.
- [x] Model joiner/invite/device-add state that becomes stranded on a losing branch and its permitted repair transitions.
- [x] Emit model traces that preserve enough action identity to compile into Scenario IR regression cases.
- [x] Produce minimal counterexample traces consumable by Scenario IR where practical.
- [x] Keep Tamarin focused on symbolic safety/security and executable bounded policy cases.

TLA+/TLC is the temporal-liveness authority; Stateright is retained as the executable Rust trace bridge. The fair TLC
model exhausts 684 distinct states (1,785 generated) and checks settlement after closure, administrative progress,
stranded-joiner repair, frozen-revision durability, and settled-history equality. Its assumptions are explicit:
input closure plus strong fairness for delivery, restart, resource recovery, freeze, settle, and permitted repair.
Crash and resource failure are temporary bounded events in the finite model. The unfair configuration is an
expected-failure gate and produces a temporal counterexample when those scheduling assumptions are absent.

The Stateright mirror checks the same bounded lifecycle while carrying stable identities such as
`model-step-0:self_update`. Its minimized two-action starvation witness names
`eventual_input_closure_or_fair_admin_scheduling` as the violated assumption. The committed canonical Scenario IR
counterexample compiles to stable action ids and preserves the self-update/admin-change prefix. Losing-branch joiners
may become stranded; their only modeled repair is reset/rejoin with fresh state. Tamarin's scope is unchanged.

### 4.3 Mutation adequacy

- [x] Mutate selector comparison order.
- [x] Mutate witness sender/epoch deduplication.
- [x] Mutate app-message witness admission/removal to determine which scenarios actually depend on it.
- [x] Mutate cutoff admission and frozen-member persistence.
- [x] Mutate scheduler deadlines and re-arm classification.
- [x] Mutate output invalidation and publication acknowledgement.
- [x] Mutate retained-history and expiration boundaries.
- [x] Maintain a matrix showing which verification layer kills each mutation.

`SemanticMutation::ALL` contains nine one-rule simulator mutants with minimal deterministic witnesses. The campaign
requires every mutant to change the adopted observation; none is a production compile feature. It kills raw-depth-first
selection, non-deduplicated witnesses, witness removal, exclusive cutoff, crash-lost frozen state, suppressed
post-settlement re-arm, retained losing output, uncleared accepted publication, and inclusive expiration. The
machine-checked [`MUTATION_MATRIX.md`](../../crates/cgka-conformance-simulator/MUTATION_MATRIX.md) has exactly one row
per executable mutant and maps each to its primary independent layer plus a production-shaped regression. There are
no surviving targeted mutations or tracked adequacy gaps at this checkpoint.

### 4.4 Protocol decision gate

- [x] Prove bounded administrative progress under stated assumptions, add explicit fairness/admission policy, or
  document the non-guarantee.
- [x] Confirm which constants are truly semantic and version them through protocol capabilities.
- [x] Confirm scheduler/resource constants cannot silently change a settled result after input closure.

The live canonical Marmot `master` was reverified at adopted commit
`4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` (marmot#410). It already states the bounded post-settlement admin
preparation opportunity, the non-guarantee under unbounded valid self-updates, the closed-input liveness assumptions,
pass-partition invariance, the mandatory implicit v1 values, and the rule that any future behavior-changing policy
ships as a new required app component/capability. No additional protocol PR is needed for Milestone 4.

`policy_contract::CONSTANT_DECISIONS` classifies every P/E/A ledger id exactly once. P1/P2/P6/P7/P8 directly affect
selected state; P4/P5 affect the bounded-pass lifecycle; P3 is coupled security-retention implementation of P2. All
remain mandatory implicit v1 and any change requires the future required component. No component is allocated merely
to re-encode the only valid v1 choice. E/A constants remain local only under operational non-interference: exhaustion
is visible and fail-closed, retained work can retry, and equal closed input reaches the same settled result.

The protocol decision gate pins all eight P values, checks the 24-id ledger/classification bijection, enforces the
future-component decision, and varies batch width, wake delay, and a temporary resource refusal over one closed
witness-sensitive input set. Intermediate pass histories differ while the settled winner remains equal; the resource
failure never produces a partial settled result. Production coverage remains the same-horizon pass-partition
metamorphic test and replay-budget fail-closed/repair campaign.

### Milestone 4 Exit Gate

- [x] The independent model and production engine agree over the bounded corpus.
- [x] Every targeted semantic mutation is killed or becomes a tracked verification gap.
- [x] Liveness counterexamples name the violated assumption.
- [x] The self-update/adversarial-progress decision is part of the protocol contract.

Milestone 4 is complete. The independent reference and production implementations agree over the committed policy
corpus, proposal/dependency sentinels, common engine lifecycle case, and 256 generated shrinkable cases. TLC exhausts
the fair bounded lifecycle and the expected-failure unfair run emits a counterexample tied to a named closure/fairness
assumption. All nine targeted semantic mutants are killed, and the protocol decision gate covers every P/E/A constant
while pinning the adopted self-update non-guarantee and future policy-component rule.

## Milestone 5: Application And Multi-Process Simulation

### 5.1 `MarmotAppRuntime` adapter

Recent runtime/storage hardening constrains this adapter without completing it:

- [MDK #1186](https://github.com/marmot-protocol/mdk/pull/1186) fixed group-state updates applied inside an outbound
  send reaching durable projections without waking app subscriptions. The adapter must therefore assert stored
  projection state and notification/event delivery independently rather than treating either as evidence for the other.
- [MDK #1200](https://github.com/marmot-protocol/mdk/pull/1200) enforces one live `AppClient`/engine session per account
  inside a `MarmotApp`. The adapter must allocate one account-device identity per participant and classify
  `AccountSessionBusy` as an explicit local operational outcome rather than opening a second session over the same
  database.
- [MDK #1201](https://github.com/marmot-protocol/mdk/pull/1201) makes projection pruning and secure deletion durable
  and exposes `erasure_pending`. App/process comparison must keep that local maintenance outcome separate from shared
  protocol-state and application-projection equivalence.
- [MDK #1199](https://github.com/marmot-protocol/mdk/pull/1199) is a non-normative multi-device exploration, not an
  adopted identity model. Scenario IR and process adapters must identify account-device instances explicitly and must
  not assume that same-account device admission, synchronization, or repair semantics already exist.

- [ ] Give every participant a unique restrictive root and SQLCipher database.
- [ ] Drive only public app-runtime operations.
- [ ] Exercise real account/device lifecycle, projections, outbound publication, relay sync/backfill, and retries.
- [ ] Compare engine state commitments and user-visible chat/member/admin/message projections.
- [ ] Compare the three equivalence layers independently: shared protocol state, scenario-input/application projection,
  and local operational diagnostics.
- [ ] Crash/reopen the complete runtime.
- [ ] Exercise long-offline sync where no live message arms epoch-stall backfill, and prove the selected EOSE/full-history
  completeness policy closes the gap.

### 5.2 Simulator node process

- [ ] Add a small test binary wrapping `MarmotAppRuntime`.
- [ ] Define a versioned JSONL control and observation protocol.
- [ ] Keep engine/storage internals unavailable through the process protocol.
- [ ] Emit privacy-safe structured diagnostics and failure capsules.
- [ ] Define process-adapter quiescence from observable inbox/outbox, relay-query completion, retry timers, projection
  checkpoints, and stable state commitments; do not reuse engine-private counters as the contract.

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
scenario-input/application-output disposition ledger
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
3. exact state/scenario-input oracle;
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
| 2026-07-30 | 1.1 exact live-group state oracle | Added a conformance-only canonical snapshot and strict equivalence expectation; exact member and exporter semantic mutations now fail while two independently joined clients match | [MDK #1190](https://github.com/marmot-protocol/mdk/pull/1190), merge `f4464902`; `cargo test -p cgka-conformance-simulator`; `cargo test -p cgka-engine --features "test-conformance-snapshot test-policy-overrides"` |
| 2026-07-30 | 1.1 generalized scenario-input disposition ledger | Added strict per-client commit, proposal, and application dispositions keyed by stable scenario action ids and joined to outer transport/content aliases; duplicate application delivery is one delivery plus one dedup, and unpeeled input remains visibly transport-pending | `cargo test -p cgka-conformance-simulator exact_observation_ledgers_commit_proposal_and_application_dispositions`; full simulator suite |
| 2026-07-30 | 1.1 instantaneous pending-work oracle | Added client-scoped `NoPendingWork` over group-scoped engine, client-addressed bus, and per-client scenario-input-ledger progress; queued, delayed, unread, unconfirmed-publish, and transport-deferred sentinels fail, while a dropped-object sentinel proves delivery remains an independent recipient assertion | `cargo test -p cgka-conformance-simulator` |
| 2026-07-30 | 1.1 bidirectional decryptability probe | Added an active exact-ID application-message matrix; settled members pass every directed edge, a missed commit exposes future-epoch deferral in only one direction, and a named nonmember cannot pass | `cargo test -p cgka-conformance-simulator bidirectional_decryptability` |
| 2026-07-30 | 1.1 terminal disband projection | Added a shared-fact-only canonical tombstone projection; terminal state passes exact/no-pending observation across restart, while device-local authorship and roster ordering cannot split equality | `cargo test -p cgka-conformance-simulator exact_oracle_projects_terminal_disband_tombstone_across_restart`; `cargo test -p cgka-engine --features test-conformance-snapshot disband_projection_excludes_device_local_authorship_and_canonicalizes_roster` |
| 2026-07-30 | 1.1 strict reliability campaigns | Made report oracle coverage strict by default, added `--allow-weak-oracle`, and appended final global drain/exact/no-pending checks to send-leave and chaos cases. The stronger boundary exposed rollback divergence, pre-join deferred work, unretired leave proposal work, and an unasserted mixed-storm application phase rather than masking them | `strict_chaos_boundary_retains_known_reliability_failures`; focused generator/report tests; generated JSON reports |
| 2026-07-30 | 1.1 durable opaque-input retirement | Persisted deferred-peel residence/context budgets, rebased deadlines conservatively across restart and backwards wall movement, scheduled stable-context expiry, preserved exact-ID redelivery, armed history recovery, and repaired strict chaos seed 123 case 4 | `deferred_peel_residence_survives_restart_and_backward_clock`; `strict_chaos_boundary_retires_pre_join_opaque_resource_work`; focused app scheduler/backfill tests |
| 2026-07-30 | L1 stale-pass repair path | Reclassified inherited convergence-pass base/tip disagreement as recoverable local scheduling drift: collecting and frozen stale passes are discarded, audited, and reseeded at the current tip while frozen-member integrity failures remain fail-closed | [MDK #1182](https://github.com/marmot-protocol/mdk/pull/1182), merge `66c7162c`; behind-tip, ahead-tip, and frozen-phase compensation regressions |
| 2026-07-30 | 1.2a public convergence subject | Extracted scenario execution behind a capability-declared `ConvergenceSubject`, added the in-process engine adapter, separated queue/partition mutation behind `ConvergenceFaultSubject`, rejected unsupported scenarios before actions, and recorded adapter identity/capabilities in reports | [MDK #1194](https://github.com/marmot-protocol/mdk/pull/1194), merge `2cee3f94`; subject preflight/fault-classification tests; default-versus-explicit engine subject trace equivalence; report metadata test |
| 2026-07-30 | S4 SQLite transaction-boundary contention | Made transient `COMMIT`/`ROLLBACK` busy conditions retry in place without rerunning application closures; persistent contention remains a typed retryable error and releases a clean connection | [MDK #1191](https://github.com/marmot-protocol/mdk/pull/1191), merge `cff57a5d`; 300 storage tests; `just fast-ci` |
| 2026-07-30 | 1.3a injectable convergence dual clock | Routed convergence deadlines, pass timestamps, cutoff decisions, and restart rebasing through paired monotonic/wall-clock samples; clock-sensitive engine and harness tests advance deterministically without sleeping | [MDK #1195](https://github.com/marmot-protocol/mdk/pull/1195), merge `5db10d68`; feature-enabled engine and simulator suites; `just fast-ci` |
| 2026-07-30 | 1.1 consumed self-remove work retirement | Made confirmed and converged commits terminally retire exact consumed proposal rows and epoch-scoped proposal schedule signals; strict send/leave scenarios and restart now reach no-pending-work without an exception | [MDK #1192](https://github.com/marmot-protocol/mdk/pull/1192), merge `1a611eec`; feature-enabled engine suite; strict send/leave family; `just fast-ci` |
| 2026-07-30 | 1.1 definite publish-failure semantics | Minimized the transported-commit rollback split to nine steps; made definite simulator publication failure retract the complete undelivered commit/Welcome artifact set and reject artifacts that already reached any recipient, restoring strict exact equivalence without changing production lifecycle behavior | [MDK #1196](https://github.com/marmot-protocol/mdk/pull/1196), merge `1985d9a8`; `definite_publish_failure_retracts_commit_before_local_rollback`; `definite_publish_failure_retracts_commit_and_welcome`; `publication_failure_rejects_artifact_that_already_reached_a_recipient`; full simulator suite |
| 2026-07-30 | 1.2b adopted canonicalization contract refresh | Reconciled the executable selector, dispositions, durable message state, simulator ledger, local architecture docs, and Tamarin model with adopted Marmot convergence commit `4ad4ae2`: removed the redundant raw-depth selector step; made missing-parent, future-epoch, and eligible losing-branch outcomes explicitly deferred; added `ConvergenceDeferred` so retained inputs can be reconsidered without immediately reopening an unchanged completed pass; and terminally retires deferred commits only after they age below the retained horizon | [MDK #1198](https://github.com/marmot-protocol/mdk/pull/1198), merge `562c5d5f`; `just fast-ci`; full engine/simulator/storage/traits suites; relay runtime and simulator/vector CI; all 78 strict Tamarin lemmas |
| 2026-07-30 | M5 projection/event-delivery prerequisite | Fixed state changes folded into outbound sends reaching stored projections without waking runtime subscriptions; established that process-level simulation must observe projection state and notification delivery as separate surfaces | [MDK #1186](https://github.com/marmot-protocol/mdk/pull/1186), merge `1b949655`; focused interleaved-send subscription regression; `just fast-ci` |
| 2026-07-30 | M5 app-runtime ownership prerequisite | Enforced one live account session per account within a `MarmotApp`, surfaced typed contention through UniFFI, and made worker reconnect release the failed client before replacement | [MDK #1200](https://github.com/marmot-protocol/mdk/pull/1200), merge `8dc7c12b`; ownership, worker-lifecycle, FFI, and focused runtime tests |
| 2026-07-30 | M5 projection-maintenance prerequisite | Made large-set projection pruning bounded, preserved draft-owning groups, and made secure-delete checkpoint completion durable and explicitly observable as `erasure_pending` | [MDK #1201](https://github.com/marmot-protocol/mdk/pull/1201), merge `eec70bd9`; 307 storage tests; focused app/UniFFI retention tests; `just fast-ci` |
| 2026-07-30 | M5 account-device modeling input | Documented a non-normative multi-device design space while deliberately leaving admission, synchronization, and repair choices unresolved; future scenarios must model account-device instances without assuming those candidate semantics | [MDK #1199](https://github.com/marmot-protocol/mdk/pull/1199), merge `aac777f3`; documentation-only |
| 2026-07-30 | 1.2c / 1.3b subject virtual time | Added a capability-gated `advance_time` scenario operation backed by one shared paired clock across the engine subject; time advancement is a separate failure-free operation and `Tick` selects which participant runtimes observe it, while standalone clients without an injected clock preserve the legacy far-future shortcut | [MDK #1202](https://github.com/marmot-protocol/mdk/pull/1202), merge `1ccc4065`; focused serialization/preflight/dispatch test; two real disband passes remain live at a 999 ms tick, Alice alone settles at 1,000 ms, and Bob settles on a later tick without another time advance; full simulator suite |
| 2026-08-01 | 1.2d public outbound lifecycle and Scenario IR v2 cutover | Added non-destructive polling of exact transport-ready subject artifacts and typed accepted/no-endpoint acknowledgement; client-scoped pending identities, state-bearing commits, independent Welcomes, definite rollback, regenerated queued intents, scheduled evolution work, duplicate acknowledgement, and exposure refusal retain their distinct semantics without exposing mutable bus queues. Migrated every repository-owned scenario producer to v2 `acknowledge_outbound` operations and removed the compatibility constructor, direct subject pending controls, client lifecycle flag, and silent auto-confirm branches ([MDK #1207](https://github.com/marmot-protocol/mdk/issues/1207)) | Focused subject/runner contract tests; fixed vectors; generated families; incident replay; full simulator suite; `just fast-ci` |
| 2026-08-01 | 1.3 full-system quiescence | Added privacy-safe structural progress with runnable work, exact virtual deadlines, pass phase/generation, retry/deferred/publication/transport work, and terminal blockers; added runner-owned bounded fixed-point settling with explicit healthy-path publication/delivery policy and serializable blocked/timeout artifacts; added same-horizon batch-partition metamorphic coverage | [MDK #1216](https://github.com/marmot-protocol/mdk/pull/1216); focused real-engine deadline, lost-ack, withheld-transport, watchdog, serialization/privacy, and metamorphic tests; full simulator suite; `just fast-ci` |
| 2026-08-02 | 1.4 deterministic failure capsules and Milestone 1 exit | Added versioned restrictive failure capsules, semantic-identity minimization, typed protocol/resource/environment failure provenance, bounded transport evidence with truncation accounting, campaign-produced recipient checkpoints, exact recipient-state plus captured-transport and CLI replay, portable checkpoint-free vector promotion, failed-step report retention, a constant snapshot, and mixed-storm application assertions; completed the named mutation-sentinel and durable-outcome inventories | `failure_capsules`; `report_runner`; `failed_campaign_capsule_contains_a_replayable_tick_witness`; `failing_generated_case_records_a_minimized_reproducer`; `subject_step_failure_is_a_report_artifact_and_a_spec_run_error`; `convergence_chaos_family_generates_specs_with_semantic_expectations`; storage snapshot round-trip; full simulator/storage suites; `just fast-ci` |
| 2026-08-02 | 2.1 canonical Scenario IR v2 and authoring | Added deterministic repeat/parallel/rate/burst/barrier expansion, explicit topology and lifecycle actions, executable temporal/resource assertions, a repository-owned JSON Schema, YAML-to-canonical-JSON authoring, and a clean semantic-selector-only transport fault contract. Queue positions now remain private to low-level bus tests; fixed vectors, generated families, and incident synthesis select by action, publication, sender, protocol class, and occurrence | `schema_declares_every_executable_step_kind`; `every_repository_vector_compiles_to_stable_actions`; `semantic_transport_selectors_survive_queue_shape_changes`; generated delivery and chaos families; incident-replay witness acceptance |
| 2026-08-02 | 2.2 initial independent reference adapter | Added a capability-limited symbolic-memory subject that executes the common group/publication/application lifecycle without production selector or canonicalizer calls; one compiled scenario now runs unchanged on reference and engine adapters with equal semantic observations, exact-only predicates add their true preflight capability, and assertion sampling no longer consumes later report evidence | `one_compiled_scenario_runs_unchanged_on_reference_and_engine_adapters`; `unsupported_exact_assertion_fails_before_reference_model_executes`; scenario IR suite |
| 2026-08-02 | 2.3 retained multi-relay model and exit scenarios | Added real-engine delivery through durable per-relay histories with topology fanout/subscriptions, cursor/since/full/set queries, EOSE-versus-completeness observations, offline reconnect, visibility omission, duplicate/order policy, history equalization, and quiet-query diagnosis; the same compiled scenario runs on all three initial adapters, offline delivery comes from history, and unequal histories reach exact state equality only after reconciliation | `one_compiled_scenario_runs_unchanged_on_all_initial_adapters`; `offline_client_recovers_from_retained_history`; `unequal_relay_histories_converge_after_set_equalization`; `eose_does_not_heal_hidden_cursor_history_but_full_backfill_does`; `relay_reverse_order_and_duplicates_are_explicit_and_deduplicated` |
| 2026-08-02 | Milestone 2 completion verification | Completed every 2.1-2.3 work item and exit scenario; the canonical IR no longer exposes mutable queue positions, all repository vectors compile, and retained-history behavior is distinct from healed packet loss | [MDK #1233](https://github.com/marmot-protocol/mdk/pull/1233); `cargo test -p cgka-conformance-simulator`; `cargo test -p incident-replay`; `just fast-ci` |
| 2026-08-02 | 3.1 adversarial workload campaigns | Added the twelve-family workload catalog, small and sustained headline campaigns, real durable-phase process kills, resource-exhaustion/repair, multi-group and shared-account-device topologies, retained-relay disagreement, clock/cursor attacks, witness-enabled/disabled full-engine comparison, and mixed binary/policy preflight. Recorded the current losing-branch device repair limit and the future authenticated policy-capability boundary | `milestone3_campaigns`; `kill_at_every_durable_convergence_phase_reopens_and_finishes`; explicit sustained campaign; proposal-expiry and multi-parent replay tests |
| 2026-08-02 | 3.2 campaign measurements and policy sweeps | Embedded stable latency/blocking, pass/reorg, disposition/outcome, queue/replay/database measurements in scenario reports; added an isolated child-process runner for CPU/RSS/write accounting; and added fixed-input test-policy curves with named boundary failures and no production auto-tuning | `offline_retained_history_flood_runs_as_a_small_regression`; `policy_sweeps`; child-process smoke campaign; default and feature-enabled compile gates |
| 2026-08-02 | 3.3 attested/derived incident replay evidence | Preserved accepted fork/convergence archetypes while labeling them outcome-equivalent and naming unavailable evidence; added fail-closed producer-attested normalized Scenario IR import with per-step and contested-incident source mappings, explicit trust/sensitivity status, semantic reproduction, and owner-only vector/evidence output | Full `incident-replay` suite; `producer_attested_history_imports_and_reproduces`; replayable synthetic membership-fork CLI smoke and `0600` mode check |
| 2026-08-02 | Milestone 3 exit scenarios | Split the three headline workloads into small default regressions and explicit sustained campaigns; pinned replay-budget fail-closed repair, report first-failure/resource attribution, and exact-versus-unavailable incident outcomes | Three `small_regression` tests; explicit offline, mixed-traffic, and self-update sustained runs; `replay_budget_exhaustion_fails_closed_then_repairs_with_same_durable_inputs`; campaign metric and incident artifact tests |
| 2026-08-02 | Milestone 3 integration verification | Preserved legacy client identities while limiting account-scoped credential sharing to explicitly authored topology; all canonical semantic oracles and active decryptability probes remain compatible with the new deployment model | `implicit_topology_preserves_legacy_client_identity_seeds`; `explicit_topology_shares_account_identity_across_devices`; `cargo test -p cgka-conformance-simulator --test canonical_scenarios` (41 passed) |
| 2026-08-03 | 4.1 independent reference model | Added a type-independent authenticated candidate/dependency/proposal/witness selector and disposition model, including witness-free comparison; differentially checked the adopted corpus, production canonicalizer sentinels, common full-engine lifecycle, and 256 shrinkable generated cases | `independent_reference_model` (7 tests); source-coupling guard; `one_compiled_scenario_runs_unchanged_on_reference_and_engine_adapters` |
| 2026-08-03 | 4.2 bounded liveness and lifecycle model | Selected TLA+/TLC as temporal authority and Stateright as the Rust trace bridge; checked input closure, strong fairness, freeze/settle, crash/restart, temporary resource failure, unequal histories, and stranded-joiner repair; retained an expected unfair counterexample with stable Scenario IR action identity | `lifecycle_model` (4 tests); `just tla-liveness` (684 distinct states, 1,785 generated, depth 14); `just tla-liveness-counterexample` |
| 2026-08-03 | 4.3 semantic mutation adequacy | Added nine simulator-only one-rule mutants spanning selection, witness handling, cutoff/frozen state, scheduling, output, publication, and retention; every mutant is killed and the checked matrix maps it to independent and production-shaped evidence | `mutation_adequacy` (2 tests); [`MUTATION_MATRIX.md`](../../crates/cgka-conformance-simulator/MUTATION_MATRIX.md) |
| 2026-08-03 | 4.4 protocol decision gate | Reverified adopted Marmot convergence commit `4ad4ae2`, classified every P/E/A ledger id, pinned all v1 policy values and the future required-component rule, and demonstrated operational non-interference across batch, wake-delay, and temporary-resource variants | `protocol_decision_gate` (5 tests); [`PROTOCOL_DECISIONS.md`](../../crates/cgka-conformance-simulator/PROTOCOL_DECISIONS.md); `just convergence-ledger-gate` |
| 2026-08-03 | Milestone 4 completion verification | Completed every 4.1-4.4 item and exit condition without changing production convergence-engine behavior; the bounded independent, lifecycle, mutation, and protocol gates all pass alongside the full simulator, strict symbolic model, and repository-wide compile/lint gate | `just milestone4-ci`; `cargo test -p cgka-conformance-simulator --locked`; `just tamarin` (78 lemmas); `just fast-ci` |
