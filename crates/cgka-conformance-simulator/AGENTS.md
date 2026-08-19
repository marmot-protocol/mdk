# AGENTS.md — cgka-conformance-simulator

Read [`README.md`](README.md) for the human framing, [`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md) for exact operator
commands and artifact handling, [`SCALING_CAMPAIGNS.md`](SCALING_CAMPAIGNS.md) for large matrices and family design,
[`SCENARIO_IR.md`](SCENARIO_IR.md) for canonical and authoring semantics, [`SCENARIOS.md`](SCENARIOS.md) for the
scenario registry, and [`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) for the property-test registry. This file is the
agent-facing code model.

## Agent operating workflow

When asked to run, extend, diagnose, or report on convergence campaigns:

1. Identify the claim before choosing the execution layer. Use an engine-capable subject for exact MLS-private state,
   durable input dispositions, pending work, and active decryptability. Use app/process/container projections only for
   public facts they can actually expose.
2. Start with a strict, file-backed canary. Do not use `--allow-weak-oracle` to make an assurance run green.
3. For broad discovery, use `cgka-conformance-campaign`: it persists the exact input before action zero, isolates each
   case in a child, enforces a deadline, and verifies artifacts. Build once and shard distinct seeds when scaling.
4. Reproduce from the saved `*-generated-input.json`, not from a remembered command alone. Record family version,
   seed, case index, selected/executed IR digests, adapter, storage mode, source revision, and output path.
5. Move a failure down to the smallest compatible adapter before debugging it. Move representative cases outward to
   process/container/VM only when that layer answers a named hypothesis.
6. Preserve reports and capsules before changing code. Sensitive replay capsules contain key material: keep them
   owner-only, never commit them, and never quote their contents into issues or logs.
7. Classify a failure before fixing it: product defect, protocol ambiguity, environment failure, or expected resource
   refusal. A timeout, unsupported capability, weak oracle, and semantic mismatch are not interchangeable.
8. After a fix, rerun the minimized input, original input, family canary, relevant focused test, and widest adapter
   needed by the claim. Report local gates, remote CI, and retained evidence separately.

Use a new output directory for every run; overwrite refusal is an evidence-integrity feature. Direct binary execution
requires `RUST_MIN_STACK=4194304`; Cargo-launched commands inherit the repository configuration. Keep `--locked` on
CI-like Cargo commands.

Do not infer that more `--cases` means more complex scenarios. Cases are independent indices and seed selects their
deterministic choices. The stable identity is `(family_name, generator_version, seed, case_index)`, plus an
independently versioned workload profile when applicable. The CLI has no case-start offset, so shard large campaigns
by distinct seeds rather than overlapping prefixes of the same seed. Generated inputs/reports do not embed the tested
Git commit; require a clean build and retain the exact source revision plus command matrix beside durable evidence.

## Pieces

- **Module:** `src/bus.rs`
  - **Role:** `TransportBus`, the in-memory bus. Owns delivery policy, the queue, partition state, and the address book
    that maps `MemberId` to `ClientId` for welcome routing.

- **Module:** `cgka_engine::canonicalization`
  - **Role:** Executable model of the CGKA canonicalization contract, re-exported by this crate for tests. Uses symbolic
    peeled messages plus optional materialized candidate metadata, then calls the convergence selector to produce
    deterministic message dispositions.

- **Module:** `src/client.rs`
  - **Role:** `HarnessClient` + `ClientBuilder`. Wraps an `Engine<SqliteAccountStorage>`, a real `NostrMlsPeeler`, and the bus
    handle. It uses in-memory SQLite by default and can run on temp file-backed SQLite via the report CLI's
    `--storage file`, `MDK_CONFORMANCE_SQLITE_STORAGE=file`, or `ClientBuilder::storage_mode`. Explicit CLI selection
    overrides the environment. File-backed `restart()` drops all engine/storage handles, reopens the encrypted database,
    and hydrates it. `tick().await` drains pending inbound for one client. `confirm(pending).await` finishes a
    `GroupEvolution`.

- **Module:** `src/cross_route_scenario.rs`
  - **Role:** One canonical four-party route-assurance scenario plus its strict public process-report oracle. The
    engine-capable form adds exact state and active decryptability; app-runtime, process, container, and VM adapters
    reuse the public form and must not privately reconstruct its action schedule or terminal assertions.

- **Module:** `src/scenario_input_ledger.rs`
  - **Role:** Simulator-owned per-client commit, proposal, and application-input accounting. Joins stable scenario
    action ids to outer transport and peeled MLS content ids; application entries also retain the inner Marmot event id.
    It records send/queue/publication, ingest/defer/resource outcomes, delivery/deduplication/expiry/invalidation, and
    pending state without adding production engine hooks.

- **Module:** `src/pending_work.rs`
  - **Role:** Instantaneous strict local-progress observation plus the adapter-neutral structural progress schema. The
    structural form adds an opaque token, runnable work, earliest wake, deferred/retry and acknowledgement work,
    transport state, pass phase/generation, and terminal blockers without serializing protocol identifiers.

- **Module:** `src/quiescence.rs`
  - **Role:** Bounded virtual-time fixed-point driver. Runner-owned policy decides whether outbound work is accepted and
    transport is delivered; the driver activates controlled time, runs immediate work, advances exactly to the earliest
    wake, and records quiescent, blocked, or watchdog-timeout evidence. Limits never define success.

- **Module:** `src/failure_capsule.rs`
  - **Role:** Versioned failure fingerprints and capsules, restrictive artifact I/O, synthetic-vector promotion, and
    exact engine byte replay from a sensitive recipient SQLite/OpenMLS checkpoint. Never put a checkpoint into a
    `synthetic_shareable` capsule; it contains key material. The wire/schema contract is
    `schemas/failure-capsule.v1.schema.json`.

- **Module:** `src/decryptability.rs`
  - **Role:** Serializable active application-message probe results. A
    `ProbeBidirectionalDecryptability` scenario step sends one logical event per named client, drains every attached
    client, and records each directed sender-to-recipient edge by exact logical event id and recipient ledger
    disposition. This is a mutating probe, not a passive observation.

- **Module:** `cgka_engine::convergence`
  - **Role:** Candidate-state graph scoring rules for the distributed convergence design, re-exported by this crate for
    tests. These tests pin selector policy independently from OpenMLS replay.

- **Module:** `src/family.rs`
  - **Role:** Deterministic generated scenario families. `generate_send_leave_family`,
    `generate_convergence_e2e_delivery_family`, `generate_convergence_chaos_family`,
    `generate_admin_churn_family`, and `generate_bounded_convergence_pressure_family` record family name, generator
    version, seed, case index, runnable `ScenarioSpec`, and optional semantic expectations. `run_generated_case_report`
    adds generated metadata to report artifacts. Reliability families append a final global drain, exact canonical
    observation, and pending-work assertion; do not remove a red strict result merely because an earlier legacy
    observation passed. Positive `PayloadCount` asserts are strict-oracle `AppMessage` coverage.

- **Module:** `src/large_group_family.rs`
  - **Role:** Replay-stable 10–200 member pressure catalog. Keeps group size, administrator population, active
    committer width, traffic balance, formation, and disruption explicit in versioned workload metadata. Size blocks
    are ordered by execution cost because campaign selection is prefix-only; race arms must retain at least two active
    committers, and bounded decryptability probes must preserve late-join/re-add and roster-tail representatives.

- **Module:** `src/stateful_generator.rs`
  - **Role:** Legality-aware product journey generation into canonical Scenario IR v3. Tracks membership, admins,
    connectivity, profile, epoch, and application delivery; alternates late-membership engine cases with founding-member
    retained-history cases so pre-admission retry state is not mislabeled as a quiescence defect. Add new product actions
    to the symbolic model and terminal oracle together.

- **Module:** `src/oracle.rs`
  - **Role:** Scenario oracle and coverage evidence. Computes scenario stimuli, expected behavior classes, observed
    behavior classes, weak-oracle warnings, and coverage matrix rows. Executable `PayloadCount` asserts with a
    positive count cover `AppMessage` without inventing a cross-sender payload order. Declared asserts are
    expected coverage; only passing assertion observations count as observed evidence.

- **Module:** `cgka_engine::openmls_projection`
  - **Role:** Bytes-first OpenMLS projection and candidate materialization helpers, re-exported by this crate for tests.
    Parses MLS bytes, replays candidate paths against a snapshot, observes proposal refs / staged commits / app
    decryptions, rolls storage back, and can run the canonicalizer with OpenMLS-derived pending proposal/app-message
    evidence.

- **Module:** `src/proptest_support.rs`
  - **Role:** `intent_seq(n_clients, range)` proptest strategy. Generates `HarnessIntent::Send` and
    `HarnessIntent::Leave`; `delivery_profile()` covers FIFO, reverse, and seeded-random delivery. Other properties in
    `tests/proptest_invariants.rs` generate symbolic canonicalization, capability, lifecycle, and restart cases locally.

- **Module:** `src/scenario.rs`
  - **Role:** Serializable `ScenarioSpec` v2/v3 plus `run_scenario_spec` / `run_scenario_report` /
    `run_vector_fixture_report`. Drives ordered client operations from JSON-shaped scenario data and returns either a
    `ScenarioTrace` or a serializable report with the executed scenario, metadata, step log, flattened epoch changes,
    app invalidations, recoveries, expectation failures, and invariant failures. `ObserveExact` opts a portable scenario
    into the canonical snapshot and scenario-input ledger while legacy `Observe` remains stable for existing fixtures.
    `ProbeBidirectionalDecryptability` actively exercises send, transport peel, MLS decrypt, and application delivery.
    Membership operations include invite, admin removal, leave, and leaf self-update through the same subject contract.

- **Module:** `src/scenario_ir.rs`
  - **Role:** Canonical ScenarioSpec v2/v3 compiler. It validates input, assigns stable action ids, records the deterministic
  virtual-time schedule, derives per-action adapter capabilities, and preflights the complete schedule before the
    selected subject executes anything. V2 remains replayable; v3 adds full group-profile updates. The JSON contracts
    are `schemas/scenario-ir.v2.schema.json` and `schemas/scenario-ir.v3.schema.json`.

- **Module:** `src/topology.rs`
  - **Role:** Adapter-neutral accounts, devices, processes, groups, relays, roles, and binary/policy versions. The
    compiler validates all cross-references and resolves old client-only vectors to an explicit deterministic topology.

- **Module:** `src/scenario_authoring.rs`
  - **Role:** Authoring-only repeat, deterministic parallel, rate, burst, and barrier expansion. It lowers into canonical
    ScenarioSpec v2 before execution; adapters never interpret authoring control flow. The contract and exact timing
    rules are in `SCENARIO_IR.md` and `schemas/scenario-authoring.v1.schema.json`.

- **Modules:** `src/scenario_faults.rs`, `src/scenario_assertions.rs`
  - **Role:** Semantic message selectors plus declared offline/process/storage faults, and executable exactly/eventually/
    within/never/resource assertions. Assertions sample through the subject boundary and are recorded in reports and
    failure capsules; unsupported lifecycle/fault capabilities fail whole-schedule preflight.

- **Module:** `src/subject.rs`
  - **Role:** Simulator-owned `ConvergenceSubject` boundary and the built-in `EngineHarnessSubject` adapter. The
    scenario runner owns step semantics and stable action ids; subjects implement semantic group, publication,
    application, delivery, observation, and restart operations. Every adapter declares a versioned capability set that
    is checked before execution. The engine adapter installs one shared manual paired clock; `AdvanceTime` moves both
    clock domains without waking a runtime, activates virtual-time ticks for that subject, and `Tick` selects which
    participants run convergence against that time. Scenarios that never call `AdvanceTime` and standalone clients
    retain the legacy far-future `Tick` shortcut. The explicit engine subject also captures an append-only emission
    stream separate from the mutable bus queue: `poll_outbound` returns unresolved transport-ready artifacts
    non-destructively, and `acknowledge_outbound` applies accepted/no-endpoint outcomes to staged commits, independent
    Welcomes, and regenerated queued intents. ScenarioSpec v2 uses the same poll/acknowledgement contract; there is no
    auto-confirming compatibility lifecycle. The `structural_progress` capability exposes privacy-safe aggregate work,
    deadlines, pass phase/generation, and terminal state; scenario-owned `await_quiescence` composes it with the existing
    clock/delivery/publication operations. Queue/partition mutation is available only through the separately named
    `ConvergenceFaultSubject` white-box interface.

- **Module:** `src/reference_subject.rs`
  - **Role:** Independent symbolic-memory `ConvergenceSubject` for the common logical group, publication, delivery, and
    application lifecycle. It does not call the production selector/canonicalizer and deliberately omits exact MLS and
    adversarial transport capabilities. Use whole-schedule capability preflight to keep unsupported reference scenarios
    from partially executing.

- **Module:** `src/retained_relay.rs`
  - **Role:** Real-engine subject with deterministic per-relay durable histories. It captures and removes packet-bus
    emissions, models fanout/subscription/query/EOSE/cursors/full backfill/set reconciliation plus relay-local
    visibility/order/duplicates, and records an explicit completeness claim for every query. Offline recovery tests
    must use this adapter rather than clearing a packet-bus partition.

- **Module:** `src/vector.rs`
  - **Role:** `ScenarioTrace`, observations, and semantic `TraceExpectation` checks. Records final epoch/member/payload
    facts plus member additions/removals, client convergence, epoch changes, app invalidations, exact canonical state,
    commit/proposal/application input dispositions, pending-work blockers, active decryptability matrices, and
    settled `ConvergenceDecisionObservation` entries captured from the forensic recorder.

- **Module:** `src/policy_cases.rs`
  - **Role:** Serializable `PolicyCase` DTOs plus selection-reasoning helpers (`parse_policy_cases`, `reason_against`,
    `digest_rank`) for the bounded convergence-policy cases shared with the Tamarin model.

- **Module:** `src/report.rs`
  - **Role:** Report command parsing and run-summary types (`ReportArgs`, `ReportCommand`, `ReportRunSummary`,
    `ScenarioReportSummary`, `ReportFailureSummary`) used by the report CLI. Failed reports retain subject-step errors
    and emit restrictive failure capsules with captured transport artifacts.

- **Module:** `src/campaign_metrics.rs`
  - **Role:** Stable report-native campaign measurements: scenario/convergence wall-time envelope, actual queued-send
    blocking time, convergence decisions, engine reorg histograms, input dispositions, logical outcomes, unresolved
    work, queue depth, replay probes, and database footprint. Fields that require an OS process boundary are explicitly
    unavailable in an in-process report.

- **Module:** `src/route_assurance.rs`
  - **Role:** Machine-readable ownership for every current production convergence decision route plus stable,
    reopenable assurance-claim records. Source-marker and Markdown-matrix drift tests force review when a production
    route changes. This module records evidence only and never participates in engine selection.

- **Module:** `src/policy_sweep.rs`
  - **Role:** Feature-gated, one-variable-at-a-time sweeps over a fixed canonicalization input and fixed eligibility
    horizons. Curves record rejected boundary values and explicitly prohibit production auto-tuning.

- **Module:** `src/bin/cgka-conformance-simulator-report.rs`
  - **Role:** Report writer CLI. Runs generated families or vector fixture files/directories, writes one JSON
    `ScenarioReport` per scenario plus fixture candidates and failure capsules, replays checkpoint-bearing capsules,
    prints a pass/fail summary, and exits non-zero on expectation failures.

- **Module:** `src/bin/cgka-conformance-campaign.rs`
  - **Role:** Parent/worker campaign runner. Executes each generated case in an isolated child process and combines the
    durable scenario report with `wait4` wall/CPU/peak-RSS/write measurements. The parent persists the exact generated
    input before spawning each worker, verifies report provenance and artifact integrity afterward, and refuses to
    overwrite an earlier campaign. Workers emit the report CLI's fixture and failure-capsule artifacts. Every generated
    family exposes direct case-index generation so a large isolated campaign does not regenerate the complete earlier
    prefix for each worker. This is the engine campaign boundary for real process isolation; the app-runtime and
    child-process adapters are separate production-shaped boundaries.

- **Module:** `src/bin/cgka-policy-casegen.rs`
  - **Role:** Policy-case generator CLI; reads `formal/tamarin/policy_cases.json` and parses/reasons over the bounded
    convergence-policy cases shared with Tamarin.

- **Module:** `vectors/`
  - **Role:** External JSON `VectorFixture` files. Each fixture carries input `scenario` plus either exact
    `expected_trace` or semantic `expected_outcomes`.

## Bus model

The bus is **synchronous and deterministic**. Calling `client.send_app(...)` enqueues; calling `bus.deliver_all()` (or
`bus.step(n)`) flushes; calling `client.tick().await` ingests on the receiver side. There is no actual async runtime
cooperation; sending is `&mut self`, the engine is awaited inline.

Delivery policies (`DeliveryPolicy`):

- `ordered`: FIFO (`Ordered { broadcast_welcomes }`). Default for all canonical scenarios + the proptest.
- `reverse`: pop from the back. Useful for ingesting commits before their proposals.
- `seeded_random`: deterministic shuffle from a fixed `u64` seed.

Partitioning is orthogonal to the delivery policy, not a fourth policy: `set_partition(Some(allowed))` restricts
delivery to the allowed client set (messages to clients outside it are dropped) and `set_partition(None)` heals.

The bus knows about welcomes vs. group messages so welcomes can be routed to a specific recipient without requiring it
to be a group member yet.

`ScenarioSpec` transport faults are explicit adapter-neutral steps. They select messages by stable scenario meaning
(action id, publication, sender, protocol class, and occurrence): `omit_message`, `duplicate_message`,
`withhold_message`, `release_withheld`, and `reorder_messages`. Queue positions remain an internal bus-test detail.
`set_partition` and `clear_partition` remain the partition/heal operations.

`reached_no_endpoint` means definite non-publication. Before invoking the engine rollback, the harness retracts every matching
undelivered commit and Welcome from the queue and delayed sets. It returns a scenario error instead of rolling back if
any matching artifact has already reached a recipient mailbox; model that case as ambiguous exposure at an adapter-aware
boundary rather than as definite failure.

Use `clear_events` after setup when a scenario wants the final trace to describe only the behavior under test. The
convergence E2E scenario does this after the initial welcome joins so its trace focuses on the peeler-ingest epoch
change and selected branch outputs. Delayed past-epoch app messages are covered via retained epoch contexts.
Future-epoch branch messages are stored as raw transport bytes, retried after canonical branch selection advances the
MLS context, and only emitted if they decrypt on the selected branch.

The `convergence-e2e-delivery/v1` generated family reuses that E2E shape and varies queue delivery with duplicate,
delay/release, and reorder steps before observer ticks. Use it when checking the peeler-ingest to `GroupEvent` bridge
under transport schedule noise.

The `convergence-chaos/v1` generated family rotates through adversarial convergence shapes: invite fork recovery,
group-data fork recovery, rollback plus delayed duplicate app delivery, partition/heal/leave, delayed past-epoch app
delivery, stable duplicate/delay/reorder queue faults, 20+ client message storms, partitioned large-group delivery
storms, multi-committer group-data storms, mixed large message/commit storms, and restart plus duplicate delivery
faults. These cases carry semantic `expected_outcomes`, so report failures point at the broken convergence invariant
instead of only writing an observation dump. Generator version `6` draws the delivery schedule of the rollback and storm
shapes (arms 2, 6, 7, 8, 9) from the seed, so distinct seeds exercise distinct adversarial orderings; the
schedule-invariant convergence, rollback, and payload-set expectations stay fixed, so coverage grows with the seed
without re-pinning vectors.

The `bounded-convergence-pressure/v1` generated family is the finite-pressure acceptance campaign for the unified
fork-resolution route: a same-epoch commit race, application sends issued inside the quiescence window, a committer
restart taken mid-resolution, and a bounded self-update/profile/admin tail. It activates controlled virtual time before
the race, so every later settle must be `AwaitQuiescence`; the driver's watchdog budget is the bounded-time assertion.
The campaign is finite by construction and claims nothing about progress under unbounded self-updates.

## How to add a new scripted scenario

1. Prefer a `ScenarioSpec` when the case should become portable or reportable.
2. For narrow engine-harness behavior, add a test fn in `tests/canonical_scenarios.rs`.
3. Build N clients with `ClientBuilder::new(pad32(b"alice")).registry(registry()).attach(&bus)` only when the test needs
   lower-level harness control. The label bytes seed deterministic Nostr keys; use `client.member_id()` when a scenario
   needs the actual engine member id.
4. Drive manual scenarios with `client.send_*` / `bus.deliver_all()` / `client.tick().await`.
5. Assert on `client.epoch()`, `client.members()`, `observe_client(...)`, or `run_scenario_report(...)` depending on the
   test surface.
6. Update [`SCENARIOS.md`](SCENARIOS.md) with the setup, fault shape, and expected outcome.

Look at `three_client_happy_path_via_harness` for the canonical shape.

## How to add or update a vector fixture

1. Encode the runnable input as `ScenarioSpec` JSON in `vectors/*.json`.
2. Include `scenario_name`, `vector_version`, `conformance_version`, `seed`, `scenario`, and either `expected_trace` or
   `expected_outcomes`.
3. Keep `ScenarioTrace` free of MLS bytes and Rust-only internals.
4. Make fork-resolution behavior observable through a settled `convergence_decision` expectation, not just final membership.
5. Run `cargo test -p cgka-conformance-simulator canonical_vector_fixtures_match_generated_traces`.

## OpenMLS replay probes

`openmls_projection` is intentionally bytes-first. Probe tests should capture `TransportMessage` values from the
harness, replay their MLS payload bytes against a `SqliteAccountStorage` group snapshot, collect observations such as
`ProposalRef`s from `StagedCommit::queued_proposals()`, then rely on the helper to roll storage back. Candidate
materialization should turn those replay observations into `MaterializedCandidate` values, then call
`canonicalize_with_materialized_candidates` so commit ids, consumed proposal ids, and losing-branch dispositions are
handled by the canonicalizer. Do not store OpenMLS protocol objects in conformance fixtures; they are consumed by
OpenMLS APIs. For a full replay-to-canonicalization pass, use `canonicalize_openmls_batch`: it maps OpenMLS
`ProposalRef`s back to canonical message ids and turns successful application-message replays into branch witnesses plus
stored payload refs. Candidate paths should carry commits; the batch's `pending_messages` supplies proposals and app
messages for replay probing. Use `canonicalize_stored_openmls_messages` when the test should prove that durable
`MessageRecord` rows can reconstruct the same batch after restart or relay sync.

## How to run reports

Run a generated family:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family convergence-chaos/v1 \
  --seed 42 \
  --cases 10 \
  --out target/cgka-conformance-simulator-reports
```

Generated-family runs first write owner-only `*-generated-input.json` artifacts containing the full generated case,
including its subject adapter and expectations. Replay one through the same report path with `--generated-input FILE`.
Runs then write owner-only `*-case-N.json` reports and `*-case-N-fixture.v1.json` candidates that can be promoted into
`vectors/` after review. Oracle coverage is strict by default; use `--allow-weak-oracle` only for an explicitly
exploratory run.

Run portable vector fixtures:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --out target/cgka-conformance-simulator-reports
```

## How to add a new proptest invariant

1. New `proptest!` block in `tests/proptest_invariants.rs`.
2. If you need new intent kinds, extend `HarnessIntent` in `src/proptest_support.rs` and the matching strategy fn.
3. Encode the invariant with `prop_assert(actual, expected, msg)` when comparing model values; the helper panics with
   useful context so shrinking keeps the original failure visible.
4. Use one config per `proptest!` block. Harness-heavy properties default to smaller case counts; pure
   selector/canonicalization properties can run more cases. The `conformance-slow` feature should raise counts according
   to test cost, rather than forcing every property to the same number.
5. Update [`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) with generated inputs, the rule being checked, and the case counts.

## Coverage gaps

Keep these aligned with [`README.md`](README.md), [`SCENARIOS.md`](SCENARIOS.md), and
[`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) when filling a gap.

- **`HarnessIntent` does not generate Invite / UpgradeCapabilities / UpdateGroupProfile.** It remains the small
  shrinkable send/leave strategy. `chat-journey/v1` now generates legal invites and profile changes as canonical IR and
  relies on saved-input semantic reduction; upgrade lifecycle remains separate.
- **Partition policy is scripted, not strategy-driven.** The bus supports partitions; proptest currently drives FIFO /
  Reverse / SeededRandom.
- **Generated family coverage is broad but not exhaustive.** `chat-journey/v1` covers legal product-shaped membership,
  admin, profile, application, offline, reconnect, self-update, and restart histories. `send-leave/v1` records lifecycle
  metadata, `convergence-e2e-delivery/v1` mutates the convergence E2E bridge with duplicate/delay/reorder delivery, and
  `convergence-chaos/v1` covers invite races, group-data races, publish rollback, partitions, leaves, delayed past-epoch
  app delivery, queue faults, 20+ client message storms, partitioned large-group storms, multi-committer group-data
  storms, mixed message/commit storms, and restart plus duplicate delivery. `admin-churn/v1` covers seeded admin-set
  churn, competing same-epoch admin-policy commits, restart between publish and delivery, and latecomer joins under
  commit pressure. Storage-loss families are still future work. A welcome-joined member retains its own join commit as
  a permanently deferred transport input; latecomer arms scope their strict pending-work oracle to the founders and
  pin the joiner to exactly that retained artifact (`no_pending_work_except_retained_join_commit`) until that is
  resolved.
- **Stateful chat journeys serialize commits by construction.** Each commit is acknowledged and delivered before the
  next state-changing action, and restart is a terminal checkpoint. Mutation-after-reopen plus concurrent and racing
  commit coverage remains owned by `convergence-chaos/v1`.
- **Admin-gated scripted steps need admin setup.** When a scenario has an invitee later send `InviteMembers` or
  `UpdateGroupData`, the runner promotes that invitee to an initial admin for the group. Direct harness tests should
  use `create_group_with_admins` explicitly for competing admin commits.
- **Deadline-pinning virtual-time scenarios cannot become portable vectors yet.** A scenario whose contract is *which*
  tick settles a pass (see `open_convergence_pass_survives_restart_and_walks_the_backlog_to_the_tip`) has to tick
  manually: `await_quiescence` advances virtual time until the subject stops changing, so it settles a pass whenever it
  comes due and erases the evidence that a specific deadline fired. That costs nothing at the oracle —
  `VirtualTimeAdvance` recommends `QuiescenceState` *or* `NoPendingWorkObserved` and coverage is any-of, so a
  `NoPendingWork` expectation discharges the stimulus under `--strict-oracle`. The multi-process subject is the actual
  block: `process_subject_descriptor` deliberately does not advertise `SubjectCapability::VirtualTime`, so preflight
  rejects `AdvanceTime` as `unsupported_subject_capability` and the orchestrator's `tokio::time::sleep` arm never
  runs — and `node_protocol` has no clock surface, so there is no subject clock to move even if it did. Node deadlines
  would run on real elapsed time: fine for a step that only needs settling slack, wrong for one that must land on a
  boundary.
  Such scenarios stay in `tests/canonical_scenarios.rs` until the node protocol grows a virtual clock the process
  subject can honestly advertise.
- **Failure minimization is intentionally conservative.** Generated reports populate `minimized_case` with a greedy
  step-removal reducer when removable app/delivery noise can be dropped without changing the semantic failure identity
  (classification, action type, and failure kind). Complete state-digest fingerprints remain diagnostic evidence. There is no
  domain-specific shrinker yet.

## Conventions

- **Client labels seed deterministic Nostr keys.** The ergonomic `pad32(b"name")` helper remains fine for stable test
  labels, but the engine identity attached to the bus is the derived public key. Use `HarnessClient::member_id()` for
  admin lists or other policy inputs.
- **Tracing audit is repo-wide.** `tests/tracing_audit.rs` scans production Rust source for `tracing::*` calls. New
  tracing must include explicit `target` and `method` fields and must not include account ids, group ids, message ids,
  relay URLs, pubkeys, payloads, ciphertext, plaintext, or key material.
- **The harness peeler is real; the relay is not.** `TransportBus` stays in memory, but group messages and welcomes go
  through `transport-nostr-peeler`.
- **`HarnessClient` exposes only what tests need.** If you need the inner `Engine<S>`, that's a smell — extend the
  harness API instead and keep tests at one abstraction level.
