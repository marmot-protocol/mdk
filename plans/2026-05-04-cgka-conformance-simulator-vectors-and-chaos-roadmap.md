# CGKA Conformance, Vectors, and Chaos Roadmap

## Objective

Build `cgka-conformance-simulator` into conformance machinery for CGKA implementations.
Any implementation should be able to consume the same scenario inputs, run the
same logical events, and produce the same trace outputs.

The target is deterministic final state plus deterministic recovery trace. A
client that reaches the same member set by taking a different fork-recovery
path should fail the relevant vector.

This plan covers conformance and vector direction. It does not cover Nostr
transport work, Docker or system-level simulation, SQLite storage, or a
production deployment runner.

## Current State

The harness in `crates/cgka-conformance-simulator` is an in-process simulator.
It uses `Engine<MemoryStorage>` instances, the real `NostrMlsPeeler` over an
in-memory bus, and deterministic `TransportBus` delivery controls. Engine-local
tests still use pass-through mock peelers when the question under test does not
cross the transport-peeling boundary.

Current bus capabilities:

- Ordered delivery.
- Reverse delivery.
- Seeded-random delivery.
- Scripted partitions via `TransportBus::set_partition`.
- Queue-level drop, duplicate, delay/release, and reorder scenario steps.
- Direct message injection via `TransportBus::inject` for replay tests.

Current scenario coverage:

- Three-client create and message exchange.
- Welcome-before-commit classification.
- SelfRemove proposal plus auto-commit.
- Same-epoch invite fork with deterministic recovery.

Current property coverage:

- Same-message replay produces one process and one `AlreadySeen`.
- Live clients converge after generated `Send` and `Leave` sequences.
- Convergence holds under ordered, reverse, and seeded-random delivery.
- Publish confirm advances; publish fail rolls back and leaves the group usable.
- Candidate graph selection is order-invariant.
- Canonicalization proposal/app dispositions are order-invariant.
- Canonicalization replay is idempotent for already-seen message ids.
- Quiescence gates outbound work until the stability window closes.
- Capability negotiation matches generated requirement/support matrices.
- Stored convergence input gives the same result after an engine rebuild.
- Group-data update publish confirm/fail preserves or rolls back projected
  metadata and leaves the group reusable.

Current trace surface:

- `ScenarioTrace` is the output contract for early vectors.
- `ClientObservation` records client label, epoch, member count, received
  payloads, removals, and recoveries.
- `ForkRecoveryObservation` records source epoch, recovered epoch, winner
  ordering key, and invalidated ordering key.
- `VectorFixture` may carry exact `expected_trace` or semantic
  `expected_outcomes`.

Current fixture coverage:

- External JSON fixtures live in `crates/cgka-conformance-simulator/vectors/`.
- Each fixture includes a runnable `ScenarioSpec` input and either exact
  `ScenarioTrace` output or semantic expected outcomes.
- `ScenarioSpec` includes fixture-visible queue faults for drop, duplicate,
  delay/release, reorder, partition/heal, and client restart.
- `generate_send_leave_family` emits deterministic generated cases with
  family name, generator version, seed, case index, and runnable
  `ScenarioSpec`.
- `generate_convergence_chaos_family` emits deterministic adversarial
  convergence cases with runnable `ScenarioSpec`s and semantic expectations,
  including large 20+ client message storms, partitioned large-group storms,
  multi-committer group-data storms, mixed message/commit storms, and restart
  plus duplicate delivery.
- `run_scenario_report` emits serializable metadata, expected trace, observed
  trace, executed scenario input, oracle coverage evidence, step log, recovery
  observations, expectation failures, and invariant failures.
- `run_generated_case_report` adds generated-family metadata and records a
  minimized case when conservative greedy step removal can reproduce the same
  failure kinds.
- `cgka-conformance-simulator-report` writes generated family reports or vector
  fixture reports as JSON artifacts, writes generated fixture candidates, and
  prints a pass/fail summary.
- `three-client-message-exchange/v1` is captured as a fixture.
- Portable scenario fixtures now cover message exchange, create rollback,
  invite success, invite rollback, group-data update, queue drop,
  duplicate/delay/reorder queue faults, partition heal with leave, delayed
  past-epoch app delivery, restart plus delayed duplicate delivery, group-data
  fork recovery, and concurrent-invite fork recovery.
- Fixture-loading tests regenerate portable fixture traces and compare either
  exact traces or semantic expected outcomes.

Current gaps after the generated-delivery slice:

- Generated family coverage includes send/leave, convergence E2E delivery
  variants, and `convergence-chaos/v1` for invite races, group-data races,
  publish rollback, partition/heal/leave, delayed past-epoch app delivery,
  queue faults, large-group message storms, partitioned large-group storms,
  multi-committer storms, mixed message/commit storms, and restart plus
  duplicate delivery. Storage-loss families remain open.
- Generated failures now run a conservative greedy minimizer. It is useful for
  dropping removable app/delivery noise, but it is not yet a domain-specific
  shrinker for joins, commits, or client topology.
- Fixture reports now expose semantic expectation mismatches and oracle coverage
  evidence directly; the next reporting gap is richer grouping by scenario
  family and failure kind.

## Ideas Borrowed From FIPS Chaos

Jonathan's FIPS chaos harness is system-level and Docker-based. The CGKA
harness should borrow its testing discipline, not its machinery.

Useful ideas:

- Seeded scenario configs so any run can be reproduced.
- Explicit topologies for hand-authored cases and generated topologies for
  broader search.
- Separate stressor modules for delivery mutation, partitions, node churn,
  peer churn, and load.
- Connectivity protection as a scenario option.
- A run lifecycle with warmup, run, teardown, and post-run analysis.
- Output artifacts that include metadata, traces, logs, and an analysis
  summary.
- CLI overrides for seed, duration, scenario selection, and case count.

CGKA-specific interpretation:

- "Topology" means clients, group membership, bus visibility, and delivery
  rules. It does not require network interfaces.
- "Node churn" means client restart, storage loss/preservation choices, or
  delayed participation.
- "Peer churn" means group membership changes, invite races, leaves, and
  future multi-device topology changes.
- "Traffic" means application messages and group operations, with optional
  generated load.
- "Analysis" means trace comparison, invariant checks, and minimized failure
  reproduction.

## Roadmap

### Phase 1 - Externalize Canonical Vectors

Create `crates/cgka-conformance-simulator/vectors/`.

Add JSON fixtures for:

- `three-client-message-exchange/v1`

Each fixture should include:

- Scenario name.
- Vector version.
- Conformance crate version.
- Seed when applicable.
- Exact expected `ScenarioTrace`, or semantic expected outcomes for scenarios
  with randomized cryptographic bytes.

Add a Rust test that regenerates each fixture from the current conformance runner and
compares the trace or semantic outcomes. Failure output must include the fixture
name and the observed trace.

Status: complete for the portable initial fixtures and the first semantic
fork-recovery fixture.

### Phase 2 - Add a Minimal ScenarioSpec

Add a serializable input contract for deterministic scripted scenarios.

The v1 shape should cover only what the current conformance runner already does:

- Client labels.
- Initial group creation.
- Invite members.
- Confirm or fail pending operations.
- Send application messages.
- Leave.
- Deliver all queued messages.
- Tick selected clients.
- Observe selected clients.
- Optional partition allowlist and clear-partition actions.

Keep `ScenarioTrace` as the v1 output contract.

Status: complete for the current canonical fixture surface.

### Phase 3 - Add Scheduled Delivery Faults

Move beyond one-shot bus policies by adding a deterministic delivery schedule.

Faults to support first:

- Drop selected messages.
- Duplicate selected messages.
- Delay selected messages until a later step.
- Reorder queued messages.
- Partition clients.
- Heal partitions.

Every fault must be step-indexed and fixture-visible. No hidden randomness in
fixture execution.

Status: complete for first-pass queue-level scheduled faults.

### Phase 4 - Add Seeded Scenario Families

Add generated scenario families that record their seed and generator version.

Start with small families:

- Send and leave under varied delivery.
- Invite races with deterministic winner checks.
- Update group data interleaved with application traffic.
- Publish confirm/fail sequences.
- Restart/reopen delivery cases.

Generated failures should be convertible into fixed fixtures.

Status: initial `send-leave/v1` family complete.
`convergence-e2e-delivery/v1` is also complete for duplicate/delay/reorder
delivery variants around the real-peeler convergence bridge.
`convergence-chaos/v1` is complete for first-pass adversarial convergence
cases with semantic expectations, fixture-candidate output, 20+ client message
storms, partitioned large-group storms, multi-committer group-data storms, and
mixed message/commit storms, and restart plus duplicate delivery.

### Phase 4A - Use Semantic Scenario Expectations

Do not carry a test-only KAT profile through the engine. It adds provider,
identity, transport, and scenario-runner code for little conformance value.
Whole CGKA histories should be portable when their group-state outcomes match.
Exact randomized MLS envelopes are outside the scenario contract.

The semantic expectation layer should support:

- pending publish confirmations and rollbacks;
- final client epoch and member count;
- client convergence on epoch and member count;
- delivered payload observations;
- epoch changes;
- app invalidations;
- fork-recovery counts and epochs;
- future selected-branch payload checks for invite races.

Status: complete for the first conformance pass. `group-data-fork-recovery/v1`,
`concurrent-invite-fork-recovery/v1`, and `convergence-chaos/v1` use semantic
outcomes instead of exact commit digest bytes, and fixture reports include
`expectation_failures` with expected and actual JSON values.

### Phase 5 - Add Analysis and Failure Minimization

Add a conformance report that writes:

- Scenario metadata.
- Expected trace.
- Expected outcomes.
- Observed trace.
- Step log.
- Recovery observations.
- Invariant failures.

For generated scenarios, store the seed, generator parameters, and minimized
case if shrinking found one.

Status: report artifacts and first-pass greedy minimization are complete.
Domain-aware shrinking remains future work.

### Phase 6 - System-Level Chaos Runner Later

After real transports exist, consider a separate runner inspired by FIPS:

- Multi-process clients.
- Real adapter instances.
- Transport-specific faults.
- Longer duration runs.
- Artifact collection from each process.

This phase should consume the same scenario and trace ideas where possible, so
the in-process conformance runner remains the reference conformance layer.

## Interface Decisions

- `ScenarioTrace` remains the v1 output contract.
- JSON is the fixture format for v1.
- `ScenarioSpec` is the v1 input contract.
- Seeded chaos must be replayable from fixture metadata.
- Quick CI runs fixed fixtures and small generated suites.
- Slow CI runs larger generated suites behind an explicit feature or command.
- Docker and netem-style testing are later system-runner concerns.

## Acceptance Criteria

The roadmap is complete when:

- A fresh checkout can run every canonical vector fixture.
- Repeated vector runs either match exact traces or satisfy semantic expected
  outcomes.
- Fork recovery fixtures include `ForkRecoveryObservation` along with final
  membership.
- Failures name the scenario, seed, step index, client, expected outcomes, and
  observed trace.
- Slow or stochastic suites are separated from quick CI.
- A non-Rust implementation can read the fixture format without depending on
  Rust-only types or OpenMLS internals.

## Suggested First Implementation Slice

1. Add `crates/cgka-conformance-simulator/vectors/`.
2. Add JSON fixtures for the message-exchange and fork-recovery scenarios.
3. Add a fixture-loading test that regenerates each `ScenarioTrace`.
4. Add fixture metadata fields: scenario name, vector version, conformance version,
   and seed.
5. Document how another implementation should consume fixtures and compare
   observations.

## Sources

- FIPS chaos harness: <https://github.com/jmcorgan/fips/tree/master/testing/chaos>
- FIPS scenario model: <https://raw.githubusercontent.com/jmcorgan/fips/master/testing/chaos/sim/scenario.py>
- FIPS runner lifecycle: <https://raw.githubusercontent.com/jmcorgan/fips/master/testing/chaos/sim/runner.py>
- FIPS churn example: <https://raw.githubusercontent.com/jmcorgan/fips/master/testing/chaos/scenarios/churn-mixed.yaml>
- Local harness map: `crates/cgka-conformance-simulator/AGENTS.md`
- Current production refactor plan: `plans/2026-04-22-cgka-engine-production-refactor-v1.md`
