---
title: "Convergence Reliability And Simulation Plan"
created: 2026-07-30
updated: 2026-08-11
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

The baseline is now a functioning reliability lab, but it does not yet justify the complete target assurance statement:

- legacy portable `ClientsConverged` remains an epoch/member-count check, although strict reliability scenarios now use
  exact canonical state, ledgers, pending-work sentinels, and active decryptability;
- the engine, independent reference, retained-relay, app-runtime, and process adapters exist, but only a bounded shared
  scenario subset has been checked across all of them; a portable fixture is not automatically cross-adapter evidence;
- deterministic retained-relay behavior, sustained relay workloads, and the production runtime's explicit full-history
  repair seam exist, while systematic container/VM evidence for those paths remains open;
- the engine and process adapters have distinct complete quiescence contracts, but every new adapter and scenario still
  has to prove that its observable contract detects all unfinished work it can own;
- every built-in generated family now carries strict-oracle coverage, and the reviewed seeds `1`, `42`, and `1337`
  pass without weak-oracle warnings, including all twelve adversarial workload arms; this establishes that those runs
  ask and observe meaningful questions, not that the engine is universally correct or the current constants are
  optimal;
- small and sustained generated storms exist, but the reviewed run volume, constant-boundary coverage, and accumulated
  evidence are not yet sufficient to characterize the current constants across realistic operating envelopes;
- scenario seeds do not reproduce randomized MLS bytes;
- the independent selector/canonicalization model covers bounded authenticated input, dependency, witness, selection,
  and disposition behavior, while production persistence remains exercised by engine and retained-relay subjects;
- TLA+/TLC and Stateright cover a bounded lifecycle/fairness state space, and production-shaped app/process lifecycle
  tests exist; systematic container/VM scheduling and host-failure evidence remains open;
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
| 5. App and process simulation | Real projections and lifecycle in one or many isolated runtimes | complete | The same case agrees in-process and across N processes |
| 6. Route assurance and distributed campaigns | Decision-route equivalence plus container/VM/network/disk/version hardening and campaign operations | in-progress | Repeatable route-equivalence, soak, and release campaigns retain actionable artifacts |

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
| P9 | `DEFAULT_OUT_OF_ORDER_TOLERANCE` | 100 messages | semantic, security-retention | Retains within-epoch application-message keys across realistic relay reordering and offline floods | Too low drops otherwise valid application messages and potential branch witnesses; too high retains more within-epoch secrets | yes, by policy version | OpenMLS-default regression seeds, exact value pin, persisted-group migration/restart |
| P10 | `DEFAULT_MAXIMUM_FORWARD_DISTANCE` | 1,000 messages | semantic, resource | Bounds how far a receiver advances a sender ratchet across missing application messages | Too low rejects realistic loss/offline gaps; too high increases one-message catch-up work and admits a larger application/witness gap | yes, by policy version | Exact value pin, forward-gap boundary and resource campaign |

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
| E9 | `MAX_QUEUED_OUTBOUND_INTENTS_PER_GROUP` | 256 intents | resource | Bounds the durable retention queue of locally originated outbound intents per group, including a group holding an unresolvable local publication | Over-cap send is refused with typed `QueuedOutboundAtCapacity`, deliberately not transient so no automatic retry loop forms, nothing is persisted, and already-retained intents still drain at the post-resolution epoch | intended no | Fill to cap under an unresolved publication, typed non-transient refusal, retained-row integrity, and full drain plus capacity reclaim after resolution |

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
| A9 | `EPOCH_STALL_ESCALATION_ARM_THRESHOLD` | 3 arms per unrecovered run | input-recovery | Reports a group that repeated full-history replay is not returning to the tip, naming the stronger repair the app owns | Too low reports groups a further replay would have healed; too high leaves an unrecoverable group silently retrying, the 2026-07-29 field failure | none — it reports, it does not change recovery or branch choice | Field-cohort arm-run replay, escalation/reset/latch tests, additional production cohorts |

#### Constant verification ownership

The completeness scope is constants that directly affect convergence policy, retained convergence input, convergence
engine work bounds, dedicated convergence scheduling, or dedicated history reacquisition. Generic HTTP, relay SDK,
account-open, and UI timeouts remain owned by their subsystem runtime policy and are not convergence constants merely
because they can delay a process. Simulator/campaign execution budgets and evidence-artifact transaction timeouts are
likewise tooling policy: they may make a test or evidence write fail closed, but they do not alter engine inputs,
branch selection, application projection, or production scheduling and therefore stay outside this ledger.

The machine-readable
[`convergence-constant-inventory.txt`](./convergence-constant-inventory.txt) maps every ledger ID to its current Rust
declaration. `just convergence-ledger-gate` verifies those declarations, requires every P/E/A ID below, and scans the
named source families for newly introduced constants that have not been reviewed into this ledger. It currently checks
declaration presence and coverage, not literal values; production-value drift remains guarded by policy pin tests, and a
future inventory revision should encode machine-checked expected values where the Rust expression is stable enough.

| IDs | Current source/test owner | Remaining verification owner |
| --- | --- | --- |
| P1 | `convergence.rs`; Tamarin anchor/stale lemmas; `engine_replays_late_same_epoch_commit_from_retained_anchor`; `engine_prunes_retained_anchor_snapshots_to_rewind_horizon`; [MDK #1377](https://github.com/marmot-protocol/mdk/pull/1377) normal-build terminal-stale regression beyond the pinned horizon | M3.1 delayed-history depth sweep; M4.1 reference model |
| P2, P3 | `canonicalization.rs` and `wire_format.rs`; `app_message_window_must_match_engine_max_past_epochs`; `app_message_expired_is_relative_to_the_passed_reference_tip`; `send_preflight_terminally_retires_deferred_app_message_outside_past_epoch_window` | M3.1 multi-commit offline flood; M1.1 exact message ledger |
| P4 | `canonicalization.rs`; `prop_quiescence_gate_controls_settlement`; `engine_duplicate_convergence_input_does_not_reset_quiescence`; `app_witness_beside_competing_commits_resets_convergence_quiescence` | M3.2 quiescence sweep; relay-spread/reorg telemetry |
| P5 | `canonicalization.rs`; `convergence_pass_freezes_at_absolute_cap_under_continuous_selection_input`; `input_at_effective_cutoff_is_retained_for_the_next_generation`; collecting-pass restart test | M3.1 sustained flood; M3.2 eventual fixed-point comparison |
| P6, P7, P8 | `convergence.rs`; generated policy cases; Tamarin score/bound lemmas; multi-device witness-deduplication replay probe | M3.1 group-size/device/Sybil sweeps; M4.1 independent reference |
| P9, P10 | `wire_format.rs`; seed-2001 rollback-flood regression; encrypted-SQLite hydration migration/restart | Sustained within-epoch reorder/loss sweeps and resource measurements |
| E1 | `message_processor/mod.rs`; existing multi-pass integration flows | M3.1 force exhaustion, verify durable continuation and no partial settle |
| E2, E3, E4, E8 | `message_processor/mod.rs`; `deferred_peel_retry_budget_refuses_without_terminal_dedup`; `deferred_peel_residence_survives_restart_and_backward_clock`; `peel_deferred_rows_capped_per_group_under_flood`; `resource_refusal_signals_immediately_once_per_epoch`; strict first-join chaos case; deferred retry/context tests | M3.1 fairness/restart/redelivery campaign |
| E5, E6 | `openmls_projection.rs`; `for_pass_scales_with_commits_and_rewind_and_keeps_a_floor`; `for_pass_saturates_instead_of_overflowing`; `consume_fails_closed_when_exhausted` | M3.1 branch-explosion end-to-end recovery; M4.3 mutation |
| E7 | `message_processor/mod.rs`; `reopen_preserves_deferred_selfremove_auto_commit` | M3.1 deterministic jitter/collision schedules |
| E9 | `message_processor/mod.rs`; `queued_outbound_intents_are_capped_per_group_while_a_publish_stays_unresolved` | M3.1 stalled-publication backlog campaign: cap behavior across restart and the drain/reclaim path |
| A1, A2, A4, A5 | `account_worker.rs`; clamp, re-arm, collecting, pending-outbound, cutoff-order, and backoff scheduler tests | M3.2 virtual-time scheduler invariance; M4.2 lifecycle model |
| A3 | `account_worker.rs`; `retry_delay_for_attempt_backs_off_and_caps` | M3.1 persistent-error recovery and visibility |
| A6 | `epoch_stall.rs`; threshold/debounce/reset tests; next-event and audit backfill tests | M3.1 retained-relay threshold sweep; additional production cohorts |
| A7 | `marmot-app/lib.rs`; `cold_restart_since_floor_permanently_drops_backlog_below_it`; `stalled_epoch_backfill_recovers_below_floor_backlog_when_armed` | M2.3 long-offline retained-relay matrix |
| A8 | `marmot-app/lib.rs`; since-floor malicious/future timestamp coverage | M3.1 explicit skew/cursor-reset Scenario IR family |
| A9 | `epoch_stall.rs`; `escalates_when_arms_repeat_without_passing_cleanly_through_an_epoch`; `an_epoch_the_device_passes_through_cleanly_ends_the_arm_run`; `an_escalated_run_reports_once_however_long_it_keeps_arming`; `storm_collapse_suppression_is_not_an_arm`; `repeated_arming_without_recovery_escalates_exactly_once`; `an_epoch_passed_cleanly_between_arms_never_escalates`; `an_escalation_recorded_before_a_failing_sync_is_reported_by_the_next_sync`; `an_escalation_recorded_during_a_received_delivery_rides_that_seam` | M3.1 retained-relay arm-run sweep; production cohorts confirming the run length that warrants the stronger repair |

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
trace, and may use a semantic-identity-preserving minimized scenario only through this explicit reviewed-promotion
path. That is not a full-fingerprint or terminal-state-digest attestation: the reviewer must rerun the promoted
candidate and validate that its portable expectation still expresses the intended regression. Automatic generated
fixture candidates do not take this exception. Promotion refuses capsules without a portable expectation.

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
model exhausts 720 distinct states (1,821 generated) and checks settlement after closure, administrative progress,
stranded-joiner repair, frozen-revision durability, and settled-history equality. Its assumptions are explicit:
input closure plus strong fairness for delivery, restart, resource recovery, freeze, settle, and permitted repair.
Crash and resource failure are temporary bounded events in the finite model. The unfair configuration is an
expected-failure gate and produces a temporal counterexample when those scheduling assumptions are absent.

The Stateright mirror checks the same bounded lifecycle, including the durable/volatile frozen-revision split, while
carrying stable identities such as `model-step-0:self_update`. Its minimized two-action starvation witness names
`eventual_input_closure_or_fair_admin_scheduling` as the violated assumption. The committed canonical Scenario IR
counterexample compiles to stable action ids; a drift test derives its self-update/barrier action kinds from the model
trace instead of pinning magic schedule indices. Losing-branch joiners may become stranded; their only modeled repair
is reset/rejoin with fresh state. Tamarin's scope is unchanged.

### 4.3 Mutation adequacy

- [x] Mutate selector comparison order.
- [x] Mutate witness sender/epoch deduplication.
- [x] Mutate app-message witness admission/removal to determine which scenarios actually depend on it.
- [x] Mutate cutoff admission and frozen-member persistence.
- [x] Mutate scheduler deadlines and re-arm classification.
- [x] Mutate output invalidation and publication acknowledgement.
- [x] Mutate retained-history and expiration boundaries.
- [x] Mutate group-profile projection and pairwise-loser terminalization.
- [x] Maintain a matrix showing which verification layer kills each mutation.

The macro-generated `SemanticMutation::ALL` catalog contains eleven one-rule simulator mutants with minimal deterministic
witnesses. The campaign requires every mutant to change the adopted observation; none is a production compile feature.
It kills raw-depth-first selection, non-deduplicated witnesses, witness removal, exclusive cutoff, crash-lost durable
frozen state, suppressed post-settlement re-arm, retained losing output, uncleared accepted publication, and inclusive
expiration, as well as stale group-profile projection and terminalized pairwise losers. Frozen-state, scheduler, and
frozen-state and scheduler mutants execute alternate transitions through the shared independent Rust lifecycle model.
The route-choice mutant is a bounded sibling-model witness only; it distinguishes the adopted abstract rule from a
terminal-loser rule but is not production route-equivalence evidence. The publication mutant drives a real
`ReferenceModelSubject` and compares structural pending work before and after acknowledgement. The
machine-checked
[`MUTATION_MATRIX.md`](../../crates/cgka-conformance-simulator/MUTATION_MATRIX.md) has exactly one row per executable
mutant and maps each to its primary independent layer plus a production-shaped regression. There are no surviving
targeted mutations or tracked adequacy gaps at this checkpoint.

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

`policy_contract::CONSTANT_DECISIONS` classifies every P/E/A ledger id exactly once. P1/P2/P6/P7/P8/P9/P10 directly
affect selected state; P4/P5 affect the bounded-pass lifecycle; P3 is coupled security-retention implementation of P2. All
remain mandatory implicit v1 and any change requires the future required component. No component is allocated merely
to re-encode the only valid v1 choice. E/A constants remain local only under operational non-interference: exhaustion
is visible and fail-closed, retained work can retry, and equal closed input reaches the same settled result.

The protocol decision gate pins all ten P values, checks the 28-id ledger/classification bijection, enforces the
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

- [x] Give every participant a unique restrictive root and SQLCipher database.
- [x] Drive only public app-runtime operations.
- [x] Exercise real account/device lifecycle, projections, outbound publication, relay sync/backfill, and retries.
- [x] Compare engine state commitments and user-visible chat/member/admin/message projections.
- [x] Compare the three equivalence layers independently: shared protocol state, scenario-input/application projection,
  and local operational diagnostics.
- [x] Crash/reopen the complete runtime.
- [x] Exercise long-offline sync where no live message arms epoch-stall backfill, and prove the selected EOSE/full-history
  completeness policy closes the gap.

The app-runtime adapter owns a real loopback relay but treats every account-device as a separate application: a
private root, account identity, runtime worker set, SQLCipher projection database, event subscription, and lifecycle.
Its versioned observation keeps three independent layers. The shared layer hashes only public protocol facts (epoch,
roster, admin set, and signed profile); the application layer records visible chat output, invalidated rows, invite
projection state, and runtime notifications; the local layer records encrypted-database posture, catch-up/reopen
counts, and privacy-safe failure classes. It never opens an `AppClient`, engine session, engine storage, or the
test-only canonical snapshot.

The quiet-offline test exposed the expected blind spot in purely incremental restart: a participant could recover an
older message and commit yet remain one epoch behind forever when no post-reconnect object existed to arm the
undecryptable-message detector. `MarmotAppRuntime::repair_full_history` is therefore the explicit public repair seam.
It performs one account-wide, unfloored relay query through the ordinary ingest/convergence/projection pipeline; normal
startup remains cursor-based. Scenario IR `FullHistory` and set-reconciliation sync modes select that operation.

### 5.2 Simulator node process

- [x] Add a small test binary wrapping `MarmotAppRuntime`.
- [x] Define a versioned JSONL control and observation protocol.
- [x] Keep engine/storage internals unavailable through the process protocol.
- [x] Emit privacy-safe structured diagnostics and failure capsules.
- [x] Define process-adapter quiescence from observable inbox/outbox, relay-query completion, retry timers, projection
  checkpoints, and stable state commitments; do not reuse engine-private counters as the contract.

`cgka-conformance-node` owns exactly one `MarmotAppRuntime` and speaks
`marmot-convergence-node-v1` JSONL over stdin/stdout. Commands cover initialization, peer aliases, group selection,
the public group/message/admin lifecycle, incremental and full-history catch-up, observation, barriers, and graceful
shutdown. The response schema exposes only normalized errors and public projection/aggregate relay facts. Account ids
appear only in ephemeral orchestration responses and peer-addressing commands; shareable observations normalize them
to scenario labels (or a one-way opaque fallback), and failure capsules exclude them entirely.

Process quiescence requires two identical projection checkpoints plus an empty observable command/outbox boundary, no
relay query or directory fetch in flight, and no retry timer armed. Relay delivery/publish counters and the stable
protocol/application commitments remain diagnostic evidence, but engine work queues and storage rows are not part of
the process contract.

### 5.3 Process orchestrator

- [x] Allocate one isolated root per participant.
- [x] Launch and barrier N participant processes.
- [x] Kill, pause, resume, and restart individual participants.
- [x] Connect all participants to controlled local relay topologies.
- [x] Preserve the canonical Scenario IR action schedule and observation schema.

`ProcessOrchestrator` compiles the same Scenario IR used by the engine subject, owns one or more local retained relays,
and launches one `cgka-conformance-node` process for each account-device participant. Participant labels are hashed
before they become filesystem components; each process gets a private root, private stderr file, and a stable durable
identity across restart. On Unix each child is its own process-group leader, so crash actions kill and reap the entire
owned group while offline/reconnect actions use real process suspension and resumption. The parent re-establishes peer
aliases and scenario-group selections after a restart before continuing the canonical schedule.

The process report retains the compiler's expanded action schedule, records an outcome for every executed action, and
uses the node's versioned layered observation schema. Explicit topology relay labels become parent-owned local relay
instances; a process may connect to any declared subset, while client-only legacy scenarios resolve to one shared
relay. The process adapter defines settlement only from public projection commitments and observable node progress.
It does not query engine queues or child databases.

### Milestone 5 Exit Gate

- [x] The same scenario reaches equivalent results through engine, app-runtime, and process adapters.
- [x] Application projections contain no losing/superseded output after settlement.
- [x] Process kill/restart agrees with uninterrupted execution.
- [x] Failure capsules identify participant, action, layer, and replay instructions without sensitive production logs.

Milestone 5 is complete. `process_orchestrator` drives one canonical scenario through the engine,
`MarmotAppRuntime`, and a real child process and compares epoch, roster size, signed group profile, and the normalized
public app/process commitment. A two-participant, two-relay scenario proves stable convergence and visible-message
projection with no invalidated output. Its lifecycle variant performs real pause, resume, process-group kill, durable
restart, full-history repair, and settlement, then compares the final protocol and application projections with the
uninterrupted run. The failure path writes an owner-only shareable capsule containing the scenario participant label,
stable action id, `app_process` layer, normalized error classification, and replay instructions; a controlled marker
test proves producer error text is not copied into it.

Milestone 5 verification:

```sh
cargo test -p cgka-conformance-simulator \
  --test app_runtime_adapter \
  --test node_protocol \
  --test process_orchestrator
cargo clippy -p cgka-conformance-simulator --all-targets -- -D warnings
just fast-ci
```

## Milestone 6: Route Assurance And Distributed Campaigns

Milestone 6 strengthens and quantifies the assurance case; it does not claim an exhaustive proof that every possible
production execution is correct. Completion means that the declared decision routes, adapters, failure dimensions,
and bounded state spaces have evidence, and that residual assumptions and untested surfaces are explicit. Formal
models prove the rules represented in those models, while campaigns test the implementation routes actually placed
under observation. Neither substitutes for checking that every production decision route is represented.

The investigation in closed [MDK #1236](https://github.com/marmot-protocol/mdk/pull/1236) demonstrated the missing
dimension this milestone must close: the same-epoch conflict could be routed through pairwise fork recovery on a
committing member and distributed convergence on an observing member, with the two seams applying different winner
rules. A real-relay, four-VM soak found equal terminal epochs on incompatible cryptographic lineages. The existing
bounded reference model represented one canonical selector but did not represent that route asymmetry.

[MDK #1285](https://github.com/marmot-protocol/mdk/pull/1285) replaced the unmerged #1236 implementation with immutable,
commit-addressed checkpoints for locally authored branches and reconsiderable same-epoch losers. That supplies the
merged engine recovery primitive and an engine-level regression, but it does not by itself prove route equivalence
through app-runtime, process, retained-history, or distributed execution. Milestone 6 therefore treats decision-route
equivalence and cryptographic interoperability as first-class campaign properties rather than assuming that either the
engine repair or scaling the existing corpus is sufficient.

### 6.1 Decision-route assurance closure

- [x] Inventory every production path that selects, rejects, defers, invalidates, replays, or applies a competing
  commit, and map each site to the adopted canonical rule, reference-model transition, mutation sentinel, and campaign
  family that exercises it.
- [ ] Define and test route equivalence: for the same authenticated dependency-closed input set, the final canonical
  result does not depend on whether input first passes through pairwise fork recovery, ordinary ingest, stored
  convergence, retained-history replay, or crash/restart recovery.
- [ ] Promote the same-source-epoch cross-route topology exposed during #1236 and repaired at engine level by #1285
  into a permanent synthetic regression family with at least four participants, simultaneous same-source-epoch
  committers, committer-versus-observer routing, ordering-key-versus-depth disagreement, branch growth, application
  traffic, delivery permutations, and restarts around every durable transition.
  - [x] Promote the core four-party engine topology as `cross-route-own-commit-recovery/v1`: pairwise displacement,
    deeper-branch reconsideration, commit-addressed recovery after encrypted-SQLite restart, exact canonical equality,
    durable selected/invalidated commit dispositions, no pending work, and twelve-direction active decryptability.
  - [x] Reproduce the topology as `cross-route-retained-history-recovery/v1` using retained relay visibility,
    incremental cursor advancement, full-history recovery, and encrypted-SQLite restart; require exact equality,
    commit dispositions, no pending work, twelve-direction decryptability, and evidence that every final history query
    injected retained objects.
  - [x] Establish the portable public-projection seam in
    [MDK #1372](https://github.com/marmot-protocol/mdk/pull/1372): run one profile/message/restart journey unchanged
    through the engine, app-runtime, and isolated-process adapters, plus an app/process offline/full-history journey,
    while preserving typed accepted-publication and rollback-refusal behavior.
  - [ ] Expand the core vector into app-runtime, process, container, and VM executions, with delivery permutations and
    restarts around each durable transition rather than the single post-displacement restart. The #1372 journeys are
    capability-overlap evidence, not execution of the four-party adversarial vector or a substitute for its exact
    cryptographic, disposition, pending-work, and active-decryptability assertions. The first controlled app-runtime
    execution now exists as `cross-route-app-runtime-recovery/v1`, but it is counterexample evidence: repeated runs
    either leave Zeta one epoch behind, lose Alpha's non-invalidated post-settlement probe at Zeta despite public
    protocol agreement, or strand Alpha/Observer on the competing root/baseline while Yankee/Zeta reach the reference
    branch and probe sets split along those boundaries. Keep this item open until that falsification is resolved and
    the process/container/VM adapters gain equivalent retained-event staging.
- [x] Add a bounded abstract route-choice lifecycle and mutation sentinel for reconsiderable versus terminal loser
  disposition, volatile routing history, and restart; record that exhaustive shared-model and production-route
  comparison remains part of the open route-equivalence work above.
- [ ] Require exact cryptographic-state commitment equality and active bidirectional decryptability after settlement
  in every adapter that can expose them. Epoch, roster, profile, and visible projection equality are insufficient on
  their own.
- [ ] Require a durable disposition for every scenario application input: canonical projection, explicit invalidation,
  retry/resend eligibility, or a named fail-closed outcome. Include sender-visible handling for application messages
  invalidated by fork recovery.
- [ ] Record which assurance claims each route-equivalence campaign covers and reopen a claim when a field, soak, or
  mutation result falsifies one of its premises.

The remaining 6.1 work is assurance closure, not another speculative engine rewrite. #1285 is the implementation now
on `master`; the next test must reproduce the cross-route topology against that design and either confirm equivalent
results or produce a new minimized counterexample.

[MDK #1329](https://github.com/marmot-protocol/mdk/pull/1329) has now merged the fail-closed missing-anchor behavior and
Welcome-repair retirement. Its formerly stacked [MDK #1293](https://github.com/marmot-protocol/mdk/pull/1293) remains
open and is not part of the oracle. The route inventory, assurance claims, and campaign inputs remain independently
reviewable and runnable against current `master`; a production PR may change the implementation under test, but not
silently redefine the expected result.

### 6.2 Container and VM execution

- [x] Add containers before VMs.
- [x] Add network partition, latency, bandwidth, and loss controls.
- [x] Add relay and participant host restarts.
- [x] Add full-disk pressure and database contention, with slow block-device latency delegated to VMs.
- [x] Validate per-participant mixed build/image assignments.
- [ ] Execute and retain reviewed rolling-upgrade evidence with at least two real builds.
- [x] Use VMs only for kernel, filesystem, network, or host-isolation behavior containers cannot represent.

The checked items above mean that [MDK #1270](https://github.com/marmot-protocol/mdk/pull/1270) provides a validated,
transactional command plan and capability-gated backend boundary. They do not mean that every fault has accumulated a
reviewed soak result. Real container/VM execution evidence remains part of the Milestone 6 exit gate.

Scenario-corpus consolidation is active alongside the runner. The external multi-VM harness remains the provisioning
and VM-execution layer; MDK owns canonical scenario meaning and assertions:

- [x] Merge the transcript, forward/removal-secrecy, and incremental-growth vectors from
  [MDK #1292](https://github.com/marmot-protocol/mdk/pull/1292).
- [x] Merge the multi-group isolation, pairwise-thread, admin-handover, and reconnect-catch-up vectors from the stacked
  [MDK #1294](https://github.com/marmot-protocol/mdk/pull/1294).
- [x] Port the remaining seeded churn family without introducing a second scenario language in
  [MDK #1295](https://github.com/marmot-protocol/mdk/pull/1295).
- [ ] Run every suitable imported scenario through its declared engine, app-runtime, process, container, and VM adapter
  matrix; fixture portability alone is not evidence that every adapter executed it.

### 6.3 Execution lanes

- [x] Define and wire a PR lane for the strict formal gate, fixed vectors, and small engine/reference/relay cases.
- [x] Define and wire a nightly lane for seed matrices, file-backed storage, crash matrix, retained relays, and a
  mutation subset.
- [x] Define and wire a weekly/manual lane for process/container soak plus resource and constant sweeps.
- [x] Define and wire a release-hardening lane that requires an explicit mixed-build manifest.
- [x] Define wall-clock, CPU, memory, disk, artifact-retention, and flake budgets for every lane.
- [ ] Collect aggregate workflow-owned observations and invoke the reviewed budget evaluator in every scheduled lane.
- [ ] Execute a reviewed incident-derived corpus before setting any lane's `incident_corpus` capability to true.
- [ ] Produce and review a byte-verified release evidence bundle from an actual release-hardening run.

Four versioned lane manifests are the single reviewed policy source for intended contents and limits. The nightly and
weekly entry points run only existing named targets, and selected-container filtering fails instead of silently passing
when it matches no test. Scheduled runs inherit the source revision's mandatory PR formal gate instead of rerunning the
same symbolic proof. The failure-corpus lifecycle validation recipe is now an explicit PR and scheduled-lane
dependency, but it does not execute an incident corpus; `incident_corpus` therefore remains false in every current
lane. The conservative minimum case counts are liveness floors preventing empty evidence, not attestations that every
declared capability ran.

The typed evaluator rejects zero-case observations, inconsistent flaky-case counts, work below the lane minimum, and
wall-clock, CPU, RSS, disk, artifact-size, retry, or flake-rate overages. It is not yet fed by a workflow-owned
observation collector, so workflow enforcement and the resource/flake exit gate remain open. Evidence
bundles require a nonempty artifact set; `check-evidence` recomputes the budget result from its observation and the
reviewed lane policy, resolves each relative artifact path beside the bundle, and verifies its SHA-256 bytes. A policy
test also pins each workflow artifact-retention setting to the corresponding lane manifest. The remaining
route/model/adapter/mutation/boundary/assumption fields are still producer-supplied scoped evidence rather than an
automatic correctness attestation.

### 6.4 Failure corpus lifecycle

- [x] Automatically save failing seeds/capsules.
- [x] Minimize semantically, not only by generic step removal.
- [x] Classify product defect, protocol ambiguity, environment failure, or expected resource refusal.
- [x] Promote stable synthetic regressions into vectors.
- [x] Track recurrence and time-to-diagnosis.

Simulator failures write portable and optional sensitive replay capsules; process-node capsules and distributed-run
failures can be added to the same private versioned corpus. The index retains seeds, adapters, build matrices,
recurrence, minimum diagnosis time, reduction candidates, and digest-pinned promoted-vector provenance without
copying raw error text.
[MDK #1140](https://github.com/marmot-protocol/mdk/pull/1140) now also fails closed when a manifest-less or corrupt
NDJSON stream is presented to incident replay, preventing an incomplete stream remnant from being silently adopted as
an empty healthy document. This hardens corpus admission; it does not constitute execution of an incident-derived
corpus in the scheduled lanes.
The reducer now treats paired transport, partition, lifecycle, and storage actions as dependency units before removing
independent noise. Non-layer-specific failures receive a canonical Scenario IR candidate for the next smaller adapter;
the semantic identity must reproduce there before concluding that the larger layer is uninvolved. Promotion remains
restricted to synthetic shareable capsules with portable expectations. Semantic minimization may change the terminal
state digest, so automatic generated fixture candidates retain the original executed scenario. Two intentional corpus
consumers use the smaller case under a narrower contract: corpus indexing records it as a semantic-identity reduction
candidate, and explicit human-reviewed vector promotion may select it only after rerunning and validating the portable
expectation. Neither path labels the reduced case as full-fingerprint-equivalent to the original execution.

### 6.5 Stateful canonical journeys

- [x] Generate product-shaped legal action histories as canonical Scenario IR rather than through a second executor.
- [x] Track membership, administrator authority, connectivity, epoch, full group profile, and application delivery in a
  symbolic model, and turn that model state into expected-value terminal oracles.
- [x] Cover late invites, removals, application sends, group-profile and admin changes, self-updates, restarts, offline
  windows, full-history catch-up, exact state, and active decryptability across a deterministic seed/case corpus.
- [x] Keep late-membership and retained-history profiles distinct: valid pre-admission retry rows are not a global
  no-pending defect, while founding-member offline journeys must reach full quiescence and no pending work.
- [x] Persist an owner-only, versioned generated-case input before action zero, including the selected subject adapter
  and semantic expectations, so a crash cannot erase or change the reproducer.
- [ ] Expose these saved journeys as first-class selectable app-runtime, process, container, and VM campaign inputs.
  Every wider adapter must select the canonical Scenario IR embedded in the saved generated-input envelope, preserve
  its generator/profile provenance and semantic expectations, and record the selected IR digest in distributed
  manifests. An adapter that deterministically lowers the selected history must also record the executed IR digest;
  this remains a cross-layer usability slice rather than being hidden inside the generator.

[MDK #1313](https://github.com/marmot-protocol/mdk/pull/1313) added selection plumbing that resolves raw Scenario IR
and saved generated inputs through one parser, records source, selected-IR, and (after adapter lowering) executed-IR
digests, preserves generator provenance and expectations in app/process/container reports, and hands VM drivers a
privately materialized canonical file. This item remains open until representative stateful journeys pass the
capability and oracle contracts of every listed adapter; an adapter merely rejecting an engine-only observation during
preflight is useful evidence, not completion.

### 6.6 Shared legality model and workload profiles (planned follow-up)

The current generated families are useful coverage slices, but they should not mature into independent mini-simulators
with separate and drifting definitions of legal product behavior. Consolidate product-action legality into one shared
symbolic model that emits canonical Scenario IR. Keep workload families as thin profiles over that model: a profile may
weight actions, require a named interaction, select compatible subject capabilities, and attach the appropriate
oracles and resource budgets, but it should not privately reimplement common action semantics. Simulator-only faults
remain a separate catalog that profiles can compose with product actions; they are not user operations.

The coverage target applies to a campaign corpus, not to every individual scenario. Requiring every scenario to contain
every legal operation would produce long, unrealistic, difficult-to-minimize failures. Instead, every supported legal
operation must be reachable through the shared model, and reviewed execution lanes must prove that their required
operations and cross-operation interactions actually occurred.

- [ ] Inventory every generated product action, its legality preconditions and state transition, and identify duplicate
  implementations across `family.rs`, `stateful_generator.rs`, incident synthesis, and adapter-specific producers.
- [ ] Extract one shared legality-aware product model covering membership, administrator authority, profile state,
  application traffic, connectivity, restart, retained-history synchronization, and future canonical IR operations.
- [ ] Define workload profiles declaratively in terms of action weights, required motifs, compatible subjects,
  assertions, and execution budgets; require an explicit reason for any shared legal action a compatible profile
  excludes.
- [ ] Keep transport, process, storage, clock, and resource faults in a separately typed fault catalog that can be
  composed with generated product histories without weakening product-action legality.
- [ ] Emit aggregate operation and interaction coverage in campaign evidence, including zero-hit gaps, and let lane
  policy require named coverage rather than treating a nonzero case count as evidence that a capability ran.
- [ ] Add explicit workload-size controls for dimensions such as actions, participants, message volume, commit/proposal
  frequency, and offline backlog. Do not overload `--cases` or `--seed`: cases remains the number of independently
  generated scenarios, while the seed selects reproducible choices within each case.
- [ ] Preserve reproducibility as `(family/profile version, seed, case index)`: increasing `--cases` must preserve the
  existing case prefix, saved inputs must replay independently, and output-changing generator work must bump the
  generator/profile version rather than silently changing an existing corpus.

Verification for this follow-up must include:

- a reachability test proving every registered product operation appears in a bounded generated corpus or has a named
  capability restriction;
- an interaction-coverage test for required pairs/sequences such as offline plus profile update, application flood plus
  membership commit, self-update plus administrator commit, restart plus pending convergence, and delayed application
  input plus branch replacement;
- a sentinel test showing that removing a required operation or interaction makes the corresponding lane evidence fail;
- deterministic prefix tests showing that the first `N` cases are unchanged when a larger case count is requested;
- cross-subject execution of emitted canonical IR wherever adapter capabilities overlap; and
- unchanged fixed regression vectors, with explicit version migration for generated corpora whose construction changes.

This is a post-Milestone 6 architecture improvement and is intentionally not added to the current Milestone 6 exit
gate. It should begin after the remaining cross-adapter route-assurance item is either closed or recorded as a scoped
residual gap.

### Current Milestone 6 execution order

1. [x] Establish a short local operator smoke path that visibly runs a canonical scenario, writes a strict file-backed
   report, and exercises the existing app/process boundary without relying on Docker or VMs. The saved-input selection
   boundary landed in #1313; bounded local engine, retained-relay, and adversarial discovery runs are now the baseline
   evidence source. [MDK #1347](https://github.com/marmot-protocol/mdk/pull/1347) restored the container smoke preflight
   by keeping its observation step within that adapter's declared capabilities; it did not substitute for container
   soak evidence.
2. [x] Finish scenario-catalog consolidation. #1292 and #1294 imported the portable scenario catalog, and
   [MDK #1295](https://github.com/marmot-protocol/mdk/pull/1295) added the simulator-only seeded admin-churn family
   without introducing a second scenario language.
3. [x] Close the known strict-oracle coverage gaps in every built-in generated family. [MDK #1349](https://github.com/marmot-protocol/mdk/pull/1349)
   gave `convergence-e2e-delivery/v1` an exact/decryptable settle tail, added deterministic delivery and accepted-publish
   expectations across `adversarial-reliability/v1`, and taught the oracle to recognize a passing exact-equivalence
   expectation over a subset even when other observed clients intentionally diverge. The reviewed all-family seeds
   `1`, `42`, and `1337` are strict-green; this removes known oracle false positives but is not an engine-correctness
   claim.
4. [x] Generalize the isolated child-process campaign runner from the adversarial catalog to every built-in generated
   family, persist the exact generated input before each worker starts, run the worker through the strict report path,
   and retain its report, fixture candidate, and failure capsule. Then execute a reviewed file-backed seed/case matrix
   and classify every failure as a product defect, protocol ambiguity, environment failure, or expected resource
   refusal. Verification must include one smoke case from every family, exact saved-input replay, deadline kill/reap,
   nonzero exit propagation, and artifact-path integrity. [MDK #1357](https://github.com/marmot-protocol/mdk/pull/1357)
   completed the runner. The reviewed campaign executed 60 isolated campaigns and 1,170 file-backed cases across all
   six generated families with zero failures, timeouts, signals, integrity errors, missing artifacts, or failure
   capsules. It tested commit `7b0480604a84b8f5728289c18018dd71d8d33e77` on base
   `5e90b22e`, so it is retained evidence for that snapshot rather than evidence for later production changes.
5. [ ] Complete the #1285 cross-route regression across every capable adapter. The `CgkaEngine` checkpoint is now permanent
   as `cross-route-own-commit-recovery/v1` and pins exact cryptographic, decryptability, commit-disposition, pending-work,
   and projection agreement after restart. `cross-route-retained-history-recovery/v1` now establishes the same contract
   through retained relay histories; full app-runtime, process, container, and VM evidence remains.
   [MDK #1372](https://github.com/marmot-protocol/mdk/pull/1372) completed the first capability-overlap slice: one
   profile/message/restart journey runs unchanged through the `CgkaEngine` harness and the full
   app-runtime/separate-process adapters, crossing the production-shaped `CgkaEngine`, `TransportPeeler`, and
   `TransportAdapter` seams in the latter two. A companion offline/full-history journey runs through the app-runtime
   and process adapters that implement participant connectivity. It compares their public protocol and application
   projections without weakening the four-party vector or claiming exact cryptographic/disposition evidence from
   adapters that cannot expose it. The actual four-party adversarial vector and its durable-transition permutations
   remain open. The next app-runtime slice now uses action-addressed shared-relay event staging, rather than timing a
   live relay, to reproduce the actual four-party branch split. Its strict retained-engine reference passes, and the
   app runtime has three exactly characterized counterexample surfaces after repeated full-history repair: Zeta one
   epoch behind; public protocol agreement with Alpha's post-settlement application probe absent and non-invalidated at
   Zeta; or Alpha/Observer stranded on the competing root/baseline while Yankee/Zeta reach the reference branch and the
   probe sets split along those boundaries. Any fourth shape or complete equivalence now fails the characterization.
   Those counterexamples reopen route equivalence, active decryptability, and complete application disposition;
   process/container/VM execution still needs equivalent controlled retained-event staging. The decision-route
   inventory is machine checked; keep the remaining assurance artifacts independent of #1293.
6. [x] Land and execute a focused current-`master` regression gate for the production convergence changes that landed
   after the reviewed 1,170-case snapshot. Cover #1329 missing-anchor halt and authenticated Welcome repair, #1360
   atomic self-removal persistence across injected write failures and restart, #1365 armed full-history backfill after
   catch-up, and #1377's pinned rewind-horizon policy boundary. `just focused-convergence-regressions` runs each exact
   named engine/app test through an independent Nextest selector, so a renamed or deleted test fails closed with no
   tests to run. The simulator CI job owns a separately named step for this gate. Close this item after that step passes
   on the squash-merge commit; the retained CI run and commit are the durable evidence, not machine-local timings,
   paths, logs, or digests. This is a small targeted matrix, not a requirement to repeat the entire historical campaign.
   [MDK #1383](https://github.com/marmot-protocol/mdk/pull/1383) merged the gate at `fc3cae3e`.
7. [ ] Feed real workflow observations into the lane budgets and produce a reviewed evidence bundle.
8. [ ] Accumulate container soak evidence, then use the external VM driver only for the remaining
   host/kernel/block-device dimensions.

The local smoke path is a usability and integration checkpoint, not an assurance exit gate. A visually successful run
does not substitute for the cross-route campaign or the reviewed distributed evidence above.

The reviewed all-family campaign's per-process reports identify the slowest case as `convergence-chaos/v1`, seed `7`,
case `9`, at 211.849220 seconds under the 300-second limit. The aggregate summary reported 205.307222 seconds because
its slowest-case rollup considered only the soak subset; future evidence generation must derive this field from every
included campaign. The case artifacts and directories were owner-only, while the three top-level hand-authored summary
files were mode `0644`; future bundles should create aggregate manifests through the same private-file boundary.

Because #1329, #1360, and #1365 changed production behavior after the historical campaign snapshot, item 6 gives those
paths a continuously executed regression owner without carrying the historical 1,170-case result forward to newer
code. The successful named CI step on each commit binds the source revision and retains readable logs. A full matrix
rerun remains useful release evidence and must still identify its own exact source snapshot.

### Milestone 6 Exit Gate

- [ ] Every inventoried convergence decision route has a named model/test/campaign owner, and no unexplained
  route-dependent outcome remains.
- [ ] The #1285 same-source-epoch cross-route regression passes across engine, app-runtime, process, and distributed
  adapters with exact cryptographic agreement, active decryptability, and complete application-input dispositions.
- [ ] Campaigns are repeatable from saved configuration and artifact manifests.
- [ ] A failing process/container run can be reduced into a smaller adapter when the defect is not layer-specific.
- [ ] Resource and flake budgets prevent silent campaign degradation.
- [ ] Release hardening produces a reviewed convergence evidence bundle that lists covered decision routes, models,
  adapters, mutation results, workload/constant boundaries, unresolved counterexamples, residual assumptions, and
  untested surfaces. The bundle makes a scoped assurance claim rather than asserting universal implementation
  correctness or universally optimal constants.

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
| 2026-07-30 | L1 epoch-stall backfill escalation | Closed the open self-heal loop for repeated epoch-gap backfills: three arms in one unrecovered run now report a typed `EpochStallEscalated` runtime event plus a durable `epoch_stall_backfill_escalated` audit row naming the app-owned stronger repair, latched once per run and reset when the device passes cleanly through an epoch (ledger A9) | `cargo test -p marmot-app client::epoch_stall --lib`; `cargo test -p marmot-app --test epoch_stall_backfill_audit`; `cargo test -p marmot-forensics`; `just convergence-ledger-gate` |
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
| 2026-08-02 | 3.1 adversarial workload campaigns | Added the twelve-family workload catalog, small and sustained headline campaigns, real durable-phase process kills, resource-exhaustion/repair, multi-group and shared-account-device topologies, retained-relay disagreement, clock/cursor attacks, witness-enabled/disabled full-engine comparison, and mixed binary/policy preflight. Recorded the current losing-branch device repair limit and the future authenticated policy-capability boundary | `adversarial_reliability_campaigns`; `kill_at_every_durable_convergence_phase_reopens_and_finishes`; explicit sustained campaign; proposal-expiry and multi-parent replay tests |
| 2026-08-02 | 3.2 campaign measurements and policy sweeps | Embedded stable latency/blocking, pass/reorg, disposition/outcome, queue/replay/database measurements in scenario reports; added an isolated child-process runner for CPU/RSS/write accounting; and added fixed-input test-policy curves with named boundary failures and no production auto-tuning | `offline_retained_history_flood_runs_as_a_small_regression`; `policy_sweeps`; child-process smoke campaign; default and feature-enabled compile gates |
| 2026-08-02 | 3.3 attested/derived incident replay evidence | Preserved accepted fork/convergence archetypes while labeling them outcome-equivalent and naming unavailable evidence; added fail-closed producer-attested normalized Scenario IR import with per-step and contested-incident source mappings, explicit trust/sensitivity status, semantic reproduction, and owner-only vector/evidence output | Full `incident-replay` suite; `producer_attested_history_imports_and_reproduces`; replayable synthetic membership-fork CLI smoke and `0600` mode check |
| 2026-08-02 | Milestone 3 exit scenarios | Split the three headline workloads into small default regressions and explicit sustained campaigns; pinned replay-budget fail-closed repair, report first-failure/resource attribution, and exact-versus-unavailable incident outcomes | Three `small_regression` tests; explicit offline, mixed-traffic, and self-update sustained runs; `replay_budget_exhaustion_fails_closed_then_repairs_with_same_durable_inputs`; campaign metric and incident artifact tests |
| 2026-08-02 | Milestone 3 integration verification | Preserved legacy client identities while limiting account-scoped credential sharing to explicitly authored topology; all canonical semantic oracles and active decryptability probes remain compatible with the new deployment model | `implicit_topology_preserves_legacy_client_identity_seeds`; `explicit_topology_shares_account_identity_across_devices`; `cargo test -p cgka-conformance-simulator --test canonical_scenarios` (41 passed) |
| 2026-08-03 | 4.1 independent reference model | Added a type-independent authenticated candidate/dependency/proposal/witness selector and disposition model, including witness-free comparison; differentially checked the adopted corpus, production canonicalizer sentinels, common full-engine lifecycle, and 256 shrinkable generated cases | `independent_reference_model` (8 tests); source-coupling guard; `one_compiled_scenario_runs_unchanged_on_reference_and_engine_adapters` |
| 2026-08-03 | 4.2 bounded liveness and lifecycle model | Selected TLA+/TLC as temporal authority and Stateright as the Rust trace bridge; checked input closure, strong fairness, freeze/settle, durable/volatile crash recovery, temporary resource failure, unequal histories, and stranded-joiner repair; retained an expected unfair counterexample with drift-checked Scenario IR action kinds | `lifecycle_model` (5 tests); `just tla-liveness` (720 distinct states, 1,821 generated, depth 14); `just tla-liveness-counterexample` |
| 2026-08-03 | 4.3 semantic mutation adequacy | Added nine simulator-only one-rule mutants spanning selection, witness handling, cutoff/frozen state, scheduling, output, publication, and retention; every mutant is killed and the checked matrix maps it to independent and production-shaped evidence | `mutation_adequacy` (3 tests); [`MUTATION_MATRIX.md`](../../crates/cgka-conformance-simulator/MUTATION_MATRIX.md) |
| 2026-08-03 | 4.4 protocol decision gate | Reverified adopted Marmot convergence commit `4ad4ae2`, classified every P/E/A ledger id, pinned all v1 policy values and the future required-component rule, and demonstrated operational non-interference across batch, wake-delay, and temporary-resource variants | `protocol_decision_gate` (5 tests); [`PROTOCOL_DECISIONS.md`](../../crates/cgka-conformance-simulator/PROTOCOL_DECISIONS.md); `just convergence-ledger-gate` |
| 2026-08-03 | Milestone 4 completion verification | Completed every 4.1-4.4 item and exit condition without changing production convergence-engine behavior; the bounded independent, lifecycle, mutation, and protocol gates all pass alongside the full simulator, strict symbolic model, and repository-wide compile/lint gate | `just convergence-verification-ci`; `cargo test -p cgka-conformance-simulator --locked`; `just tamarin` (78 lemmas); `just fast-ci` |
| 2026-08-04 | Milestone 5 app/process simulation | Added a production-shaped app-runtime adapter, versioned child-node protocol, multi-process orchestrator, projection/event observation, retained-relay repair, real pause/resume/kill/restart, cross-adapter comparison, and privacy-safe failure capsules; then replaced milestone-scoped module/test names with durable capability names | Commits `a3296b16` through `19d0d5f8`; `app_runtime_adapter`; `node_protocol`; `process_orchestrator`; `just fast-ci` |
| 2026-08-04 | Milestone 6 assurance scope correction | Used the cross-seam divergence found during the now-closed [MDK #1236](https://github.com/marmot-protocol/mdk/pull/1236) investigation to add decision-route inventory/equivalence, a permanent four-participant regression family, cryptographic interoperability, application disposition, model/mutation expansion, and scoped evidence requirements before distributed scale work can be called complete | Milestone 6.1 and strengthened exit gate in this document |
| 2026-08-05 | 6.2 container and VM execution | Split the container-first distributed runner, barrier-bound faults, mixed-image participants, real OCI smoke coverage, and capability-gated external VM-driver boundary out of the larger assurance branch without carrying production convergence changes or assuming the unmerged #1236 implementation | [MDK #1270](https://github.com/marmot-protocol/mdk/pull/1270); `distributed_runner`; ignored `container_runtime`; [`distributed-convergence-campaigns.md`](./distributed-convergence-campaigns.md) |
| 2026-08-06 | 6.1 commit-addressed own-branch recovery | Replaced the unmerged #1236 recovery design with immutable wire-digest-addressed checkpoints, reconsiderable same-epoch losers, fail-closed missing-checkpoint handling, and an engine restart regression; retained cross-adapter route-equivalence as open assurance work | [MDK #1285](https://github.com/marmot-protocol/mdk/pull/1285); feature-enabled engine suite; storage and snapshot tests; `just fast-ci` |
| 2026-08-05 | E9 outbound retention bound | Bounded the per-group durable outbound-intent retention queue at its single insertion point, covering every path that retains — the locally staged publication path, the pre-existing stable-but-unsettled path, and the offline outbox — the over-cap send is refused with a typed non-transient `EngineError` surfaced as a distinct FFI variant, and already-retained intents still drain and reclaim capacity once a publish is accepted | `cargo test -p cgka-engine --features test-policy-overrides --test publish_lifecycle`; `cargo test -p cgka-traits`; `cargo test -p cgka-conformance-simulator --test protocol_decision_gate`; `cargo test -p marmot-uniffi`; `just convergence-ledger-gate` |
| 2026-08-06 | 6.3 lane policy and evidence foundations | Added single-source PR, nightly, weekly/manual, and release-hardening policy manifests; fail-closed standalone wall/CPU/RSS/disk/artifact/retention/flake evaluation; nonempty byte-verified evidence artifacts; and scheduled entry points without claiming workflow-owned measurement or incident-corpus execution yet | [MDK #1271](https://github.com/marmot-protocol/mdk/pull/1271); `lane_policy`; `convergence-lane-policy`; `simulator-nightly.yml`; `convergence-hardening.yml` |
| 2026-08-07 | 6.4 failure corpus lifecycle | Unified simulator/process/distributed failure indexing with the four reviewed classifications, semantic dependency-aware reduction, cross-adapter reduction candidates, safe vector promotion, recurrence counts, and time-to-diagnosis as a separate layer over the campaign runner | [MDK #1272](https://github.com/marmot-protocol/mdk/pull/1272); `failure_corpus`; `semantic_reduction`; `convergence-failure-corpus` |
| 2026-08-07 | Capability naming cleanup | Renamed long-lived simulator/process artifacts around their owned capability and added a fast-CI gate rejecting any tracked filename whose basename contains `milestone`, case-insensitively | [MDK #1273](https://github.com/marmot-protocol/mdk/pull/1273); `just naming-gate`; required GitHub CI |
| 2026-08-07 | 6.5 stateful canonical journeys | Added deterministic legality-aware Scenario IR v3 journeys with modeled membership, admin, profile, connectivity, epoch, and delivery outcomes; separated late-membership from founding-member offline history so pre-admission retry state is not mislabeled; and saved owner-only, subject-preserving inputs before execution | [MDK #1302](https://github.com/marmot-protocol/mdk/pull/1302); `stateful_generator`; `chat-journey/v1`; strict eight-case/two-profile rotation plus retained-input replay |
| 2026-08-07 | Planned shared legality model and workload profiles | Recorded the follow-up architecture: one canonical product-action legality model, separately typed composable faults, thin workload profiles, explicit size controls, and corpus-level operation/interaction coverage rather than independent family semantics or overloaded case counts | Section 6.6; planned verification and migration gates |
| 2026-08-09 | Sender-ratchet reorder policy restoration | Restored the historical 100-message out-of-order tolerance and 1,000-message maximum forward distance for new/joined groups, normalized persisted groups during hydration before new traffic, and pinned the seed-2001 rollback-flood regressions that exposed OpenMLS's inherited five-message default; already-pruned secrets remain unrecoverable | `wire_format`; encrypted-SQLite hydration migration/restart; convergence-chaos cases 2 and 13 |
| 2026-08-09 | 6.1 decision-route inventory, abstract model, and claim lifecycle | Registered every current production decision route with specific source markers, adopted rule, evidence owner, mutation sentinel, campaign owner, and explicit partial/gap limitations; modeled route choice and restart as a bounded abstract witness without treating it as production route-equivalence proof; added a pairwise-loser terminalization mutant and stable assurance claims whose recurring falsifications reopen cleanly and require explicit reviewed resolution | `route_assurance`; `pairwise_losing_branch_terminalization`; [`CONVERGENCE_ROUTE_MATRIX.md`](../../crates/cgka-conformance-simulator/CONVERGENCE_ROUTE_MATRIX.md); focused source-drift, abstract lifecycle, mutation, matrix, serialization, and claim-lifecycle tests |
| 2026-08-09 | Campaign follow-up: strict clock oracle and fixture fidelity | Accepted exact no-pending evidence as temporal closure after an explicit virtual-time advance, while retaining fixed-point quiescence as the stronger option; kept semantic minimizers diagnostic and made fixture candidates preserve the original executed scenario so broad failure identity cannot silently replace a five-of-six delivery failure with a zero-delivery case | Oracle coverage unit tests; fixture-candidate fidelity unit test; strict seed-2001 convergence-chaos replay |
| 2026-08-09 | 6.1 four-party engine cross-route checkpoint | Promoted the #1285 topology into a portable vector with two simultaneous source-epoch committers, pairwise committer displacement, observer-side stored convergence, ordering-key-versus-depth disagreement, branch growth by a third member, encrypted-SQLite restart of the displaced own-commit author, exact cryptographic equality, durable selected/invalidated commit dispositions, no pending work, and active application decryptability in all twelve directions; retained external-adapter and transition-permutation work explicitly open | `cross-route-own-commit-recovery/v1`; strict file-backed report; focused canonical-scenario regression; [`CONVERGENCE_ROUTE_MATRIX.md`](../../crates/cgka-conformance-simulator/CONVERGENCE_ROUTE_MATRIX.md) |
| 2026-08-10 | 6.1 retained-history cross-route checkpoint | Replayed the four-party #1285 topology through explicit retained relay history rather than semantic packet-bus withholding: participant-specific visibility advances incremental cursors past hidden roots/children, restart reopens encrypted SQLite after pairwise displacement, and full-history queries restore the complete set before exact settlement. Also normalized active-probe evidence from authenticated account identities to stable scenario labels after logical-id correlation. App-runtime and distributed permutations remain open. | `cross-route-retained-history-recovery/v1`; strict file-backed regression; retained-object injection assertions; [`CONVERGENCE_ROUTE_MATRIX.md`](../../crates/cgka-conformance-simulator/CONVERGENCE_ROUTE_MATRIX.md) |
| 2026-08-10 | Strict generated-family oracle closure | Closed the known strict-oracle false positives across every built-in generated family without changing production convergence behavior: subset exact-equivalence now counts as observed evidence when its executable expectation passes, convergence delivery has an exact/decryptable settle tail, and adversarial arms pin accepted publication plus deterministic delivery claims. Generator versions changed where scenario meaning changed. | [MDK #1349](https://github.com/marmot-protocol/mdk/pull/1349); all 28 vectors; all six families at seeds `1`, `42`, and `1337`; full simulator suite; `test-policy-overrides` campaign gate; `just fast-ci` |
| 2026-08-11 | All-family isolated campaign evidence | Generalized the isolated worker runner to all six generated families, then reviewed 60 file-backed campaigns and 1,170 cases with exact inputs, reports, fixture candidates, process accounting, deadlines, and failure-capsule paths preserved per case. No case failed, timed out, signaled, lost artifact integrity, or emitted a failure capsule. Recorded the exact tested snapshot and corrected the aggregate slowest-case bookkeeping limitation rather than carrying the result forward to newer production code. | [MDK #1357](https://github.com/marmot-protocol/mdk/pull/1357); tested commit `7b0480604a84b8f5728289c18018dd71d8d33e77` on base `5e90b22e`; 1,170/1,170 cases passed |
| 2026-08-11 | Post-campaign convergence deltas | Merged fail-closed missing-anchor handling and Welcome-repair retirement, atomic self-removal persistence, and armed backfill after catch-up. These changes postdate the reviewed all-family matrix and therefore require focused current-`master` delta evidence rather than being covered by the older green result. | [MDK #1329](https://github.com/marmot-protocol/mdk/pull/1329); [MDK #1360](https://github.com/marmot-protocol/mdk/pull/1360); [MDK #1365](https://github.com/marmot-protocol/mdk/pull/1365) |
| 2026-08-11 | 6.1 cross-adapter public projection checkpoint | Made accepted publication checkpoints portable across the `CgkaEngine` harness's staged transport and the app runtime's already-published command surface, then ran a three-participant profile/message/restart IR unchanged through the `CgkaEngine` harness, full app-runtime adapter, and isolated app processes. The production-shaped adapters cross the `CgkaEngine`, `TransportPeeler`, and `TransportAdapter` seams. A companion app/process permutation takes one member offline across the commit and message, restarts another member, performs full-history repair, and requires equivalent duplicate-free public projections. Exact MLS state, active decryptability, the four-party adversarial topology, containers, and VMs remain open. | [MDK #1372](https://github.com/marmot-protocol/mdk/pull/1372); `engine_app_runtime_and_process_adapters_reach_equivalent_public_state`; `app_runtime_and_process_adapters_recover_the_same_offline_projection`; simulator-only adapter seam and focused process/app tests |
| 2026-08-11 | Failure-input and pinned-policy boundary hardening | Rejected manifest-less or corrupt NDJSON stream remnants instead of silently classifying them as empty healthy incident exports, and restored normal-build coverage proving that a commit beyond the pinned five-commit rewind horizon is terminal stale without weakening the production policy guard. These strengthen failure-corpus admission and the P1 boundary sentinel; they do not replace incident-corpus lane execution or a delayed-history campaign. | [MDK #1140](https://github.com/marmot-protocol/mdk/pull/1140); [MDK #1377](https://github.com/marmot-protocol/mdk/pull/1377); incident-replay regressions; `stale_commit_outside_rewind_horizon_is_not_treated_as_recoverable_fork` |
| 2026-08-11 | Focused post-campaign production-delta gate | Added a fail-closed named CI gate for the missing-anchor halt, verified Welcome repair, three-write atomic self-removal rollback/restart, armed post-catch-up backfill, and pinned rewind-horizon regressions. Every exact Nextest selector runs independently, so moving or removing one test cannot silently become a zero-test success. The squash-merge commit's successful named CI step will be the durable current-`master` evidence. This is targeted regression coverage, not a rerun of the historical generated matrix or distributed cross-route evidence. | `just focused-convergence-regressions`; `Run focused convergence regressions` CI step; five exact named engine/app tests |
| 2026-08-11 | 6.1 app-runtime cross-route falsification | Added action-addressed event staging to the app-runtime harness's real retained Nostr relay so offline recipients cannot race the intended four-party branch topology. The strict retained-engine reference still reaches exact state, durable commit dispositions, no pending work, and twelve active decryptability edges; repeated app-runtime executions have three exact counterexample surfaces: Zeta one epoch behind, public agreement with Alpha's probe missing at Zeta, or an Alpha/Observer versus Yankee/Zeta protocol-and-probe split. A fourth shape or complete equivalence now fails the characterization. This is retained counterexample evidence, not passing route-equivalence evidence; no production convergence behavior changed. | `cross-route-app-runtime-recovery/v1`; `four_party_cross_route_recovery_records_app_runtime_equivalence_falsification`; route-assurance claims reopened |

## Capability Naming Cleanup

Status: `complete`. This naming-only work was completed early in #1273 because it was mechanically separable from the
remaining assurance work and reduced further naming drift without changing scenario meaning or campaign history.

- [x] Inventory every tracked file whose basename contains `milestone`, case-insensitively.
- [x] Rename long-lived files after the capability or behavior they own, update module declarations, test targets,
  `Justfile` recipes, CI, documentation links, and replay instructions, and preserve history with ordinary Git moves.
- [x] Rename the adversarial campaign test target to `adversarial_reliability_campaigns`.
- [x] Delete obsolete milestone-only scaffolding and generated artifacts after confirming that no fixture, replay capsule,
  CI lane, or documentation reference still depends on them.
- [x] Review milestone-numbered commands, scenario-family ids, test names, and output directories. Preserve versioned
  external identifiers when compatibility requires it; otherwise give long-lived interfaces capability-based names.
- [x] Run the affected simulator, app-runtime, process, distributed, formal, and repository CI gates after
  the renames.
- [x] Require this tracked-filename check to return no output and exit successfully:

```sh
test -z "$(git ls-files | awk -F/ 'tolower($NF) ~ /milestone/ { print }')"
```

Cleanup exit gate: no tracked file basename contains `milestone`, every retained long-lived artifact has a
capability-based name, and all references plus verification lanes pass after the rename/delete sweep.
