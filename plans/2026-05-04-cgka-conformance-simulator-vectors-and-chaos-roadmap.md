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

The harness in `crates/cgka-conformance-simulator` is an in-process simulator. It uses
`Engine<MemoryStorage>` instances, a pass-through `MockPeeler`, and a
deterministic `TransportBus`.

Current bus capabilities:

- Ordered delivery.
- Reverse delivery.
- Seeded-random delivery.
- Scripted partitions via `TransportBus::set_partition`.
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

Current trace surface:

- `ScenarioTrace` is the output contract for early vectors.
- `ClientObservation` records client label, epoch, member count, received
  payloads, removals, and recoveries.
- `ForkRecoveryObservation` records source epoch, recovered epoch, winner
  ordering key, and invalidated ordering key.

Current fixture coverage:

- External JSON fixtures live in `crates/cgka-conformance-simulator/vectors/`.
- Each fixture includes a runnable `ScenarioSpec` input and expected
  `ScenarioTrace` output.
- `ScenarioSpec` includes fixture-visible queue faults for drop, duplicate,
  delay/release, reorder, partition, and heal.
- `generate_send_leave_family` emits deterministic generated cases with
  family name, generator version, seed, case index, and runnable
  `ScenarioSpec`.
- `run_scenario_report` emits serializable metadata, expected trace, observed
  trace, step log, recovery observations, and invariant failures.
- `run_generated_case_report` adds generated-family metadata and a future
  `minimized_case` field.
- `cgka-conformance-simulator-report` writes generated `send-leave/v1` scenario reports as JSON
  artifacts from seed and case-count CLI arguments.
- `three-client-message-exchange/v1` is captured as a fixture.
- `deliberate-fork-recovery/v1` is captured as a fixture and includes
  `ForkRecoveryObservation`.
- Fixture-loading tests regenerate both traces and compare them exactly.

Current gaps after Phase 5 initial slice:

- Queue faults are fixed-script operations, not generated delivery profiles.
- Generated family coverage is limited to send/leave traffic.
- Generated failures do not yet run a shrinker to populate minimized cases.

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
- `deliberate-fork-recovery/v1`

Each fixture should include:

- Scenario name.
- Vector version.
- Conformance crate version.
- Seed when applicable.
- Expected `ScenarioTrace`.

Add a Rust test that regenerates each fixture from the current conformance runner and
compares the trace exactly. Failure output must include the fixture name and
the observed trace.

Status: complete for the initial two fixtures.

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
- Restart-like storage rollback cases once restart support exists.

Generated failures should be convertible into fixed fixtures.

Status: initial `send-leave/v1` family complete.

### Phase 5 - Add Analysis and Failure Minimization

Add a conformance report that writes:

- Scenario metadata.
- Expected trace.
- Observed trace.
- Step log.
- Recovery observations.
- Invariant failures.

For generated scenarios, store the seed, generator parameters, and minimized
case if shrinking found one.

Status: report artifacts complete; shrinking/minimization algorithm remains
future work.

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
- Repeated vector runs produce byte-stable JSON output.
- Fork recovery fixtures compare `ForkRecoveryObservation`, not only final
  membership.
- Failures name the scenario, seed, step index, client, expected trace, and
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
