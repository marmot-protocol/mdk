# cgka-conformance-simulator

In-process multi-client simulator for the CGKA engine.

The engine crate proves local engine rules. This crate asks the bigger question: if several clients run that engine and
the network behaves badly, do they still end up with the same group state?

The simulator does not use real relays. It runs `Engine<MemoryStorage>` clients against a deterministic in-memory
`TransportBus`. Transport wrapping still goes through the real Nostr peeler, so group messages use the Marmot kind-445
envelope and welcomes use NIP-59 gift wraps before the bus delivers them.

## What this crate gives you

- `TransportBus` — an in-memory message bus with seeded scheduling, partition support, broadcast and addressed
  delivery for welcomes, and replay hooks.
- `HarnessClient` — wraps `Engine<MemoryStorage>` and the real Nostr transport peeler while keeping delivery in
  memory.
- `ScenarioSpec` — a serializable v1 input contract for deterministic scripted scenarios, including explicit queue
  faults and partitions.
- `VectorFixture` — portable JSON fixtures pairing runnable scenario input with exact traces or semantic expected
  outcomes.
- `ScenarioReport` — serializable run artifacts with metadata, expected and observed traces, oracle coverage evidence,
  step logs, recoveries, and expectation failures.
- `cgka-conformance-simulator-report` — a small CLI that runs generated scenario families, writes JSON reports, and
  emits fixture candidates for generated cases.
- `proptest_support` — strategies that generate arbitrary typed `SendIntent` sequences for property-based tests.

## Testing layers

- **Layer:** Scenario registry
  - **Files:** [`SCENARIOS.md`](SCENARIOS.md)
  - **What it catches:** Human-readable setup, fault shape, and expected outcome for each scenario family.

- **Layer:** Scripted scenarios
  - **Files:** [`tests/canonical_scenarios.rs`](tests/canonical_scenarios.rs)
  - **What it catches:** Known multi-client flows and named regressions.

- **Layer:** Vector fixtures
  - **Files:** [`vectors/`](vectors/)
  - **What it catches:** Portable conformance cases that other implementations can run.

- **Layer:** Generated families
  - **Files:** [`src/family.rs`](src/family.rs), report CLI
  - **What it catches:** Seeded adversarial cases, report artifacts, and fixture candidates.

- **Layer:** Oracle coverage
  - **Files:** [`src/oracle.rs`](src/oracle.rs), report CLI
  - **What it catches:** Which stimuli were run, which behaviors were expected, and which behaviors were observed.

- **Layer:** Property tests
  - **Files:** [`PROPERTY_TESTS.md`](PROPERTY_TESTS.md), [`tests/proptest_invariants.rs`](tests/proptest_invariants.rs)
  - **What it catches:** Broad invariant checks over many generated inputs.

- **Layer:** Replay probes
  - **Files:** [`tests/openmls_replay_probe.rs`](tests/openmls_replay_probe.rs)
  - **What it catches:** Byte-first replay behavior and fixture materialization probes.

## Run the tests

```sh
# Default: scripted scenarios plus normal property-test case counts.
cargo test -p cgka-conformance-simulator

# Slower validation: raises property-test case counts according to test cost.
cargo test -p cgka-conformance-simulator --features conformance-slow
```

To run every portable vector fixture and write a report for each one:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --out target/cgka-conformance-simulator-reports
```

The normal `cargo test -p cgka-conformance-simulator` run already validates the top-level vector fixtures and checks the
vector manifest / byte-fixture files. Use the report command when you want saved JSON reports and a human-readable
pass/fail summary outside the test harness.

The report command exits non-zero when any fixture expectation fails. Each report includes the exact scenario input,
observed trace, flattened recovery and epoch observations, and the mismatched expected/actual JSON.

## Property tests

Property tests live in [`tests/proptest_invariants.rs`](tests/proptest_invariants.rs). See
[`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) for the human-readable registry. They generate many small inputs and assert
rules that should hold for every generated shape: candidate selection order-invariance, canonicalization disposition
order-invariance, canonicalization replay idempotence, quiescence gating, capability negotiation, send/leave
convergence, varied delivery convergence, same-message replay, restart equivalence for stored convergence input, upgrade
publish confirm/fail, and group-data update publish confirm/fail.

Cheap symbolic properties run more cases. Harness-heavy properties use smaller default counts and larger
`conformance-slow` counts.

## Canonical vector fixtures

Canonical conformance fixtures live in [`vectors/`](vectors/). Each file is a JSON `VectorFixture` envelope:

- `scenario_name` — stable logical scenario id, currently including `/v1`.
- `vector_version` — fixture schema version, currently `"1"`.
- `conformance_version` — `cgka-conformance-simulator` crate version that produced the fixture.
- `seed` — `null` for hand-authored deterministic scenarios.
- `scenario` — the input-side `ScenarioSpec` to execute.
- `expected_trace` — an exact `ScenarioTrace` for cases whose output is stable by construction.
- `expected_outcomes` — semantic checks for cases where randomized MLS bytes make exact trace comparison too brittle.

Non-Rust implementations should read the JSON file, run the named scenario from `scenario`, serialize their observed
trace into the same shape, and compare it with either `expected_trace` or `expected_outcomes`. The trace intentionally
avoids OpenMLS internals.

The current vector work is tracked in the engine quality plan:
`docs/marmot-architecture/overview/cgka-engine-quality-and-vectors.md`.
The crate now has [`vectors/manifest.v1.json`](vectors/manifest.v1.json),
[`vectors/byte-fixtures/schema.v1.json`](vectors/byte-fixtures/schema.v1.json), first app-component byte fixtures, and
portable scenario vectors for message exchange, pending rollback, invites, group-data updates, queue faults, partition
repair, leave, delayed past-epoch app delivery, restart plus delayed duplicate delivery, and fork recovery. It does not
yet have a full byte-level wire-event suite.

For a human-readable list of each fixed scenario, generated family, and Rust-only harness case, read
[`SCENARIOS.md`](SCENARIOS.md).

`convergence-e2e-group-events/v1` is kept as an in-tree bridge scenario rather than a portable JSON fixture. Raw harness
messages enter through the Nostr peeler and `ingest`, the convergence engine selects one same-epoch branch, and the
observed trace records the selected epoch/member additions plus the canonical branch application payload. Delayed
past-epoch application messages are also covered: the receiver advances, then peels the late transport message from a
retained epoch context and emits the payload once. Future-epoch branch messages are stored as raw transport bytes when
the outer peeler cannot unwrap them yet. After canonical branch selection advances the MLS context, the engine retries
those raw records and emits only the payloads that decrypt on the selected branch.

### Semantic fork-recovery vector

`CommitOrderingKey` is now content-derived (`SHA-256(mls_bytes)` of the serialized MLS commit). This makes the engine
fully transport-agnostic for fork-recovery decisions. Portable scenario fixtures do not assert exact winner digest
bytes, because those bytes come from randomized MLS envelopes.

The first fork-recovery fixture is
[`vectors/group-data-fork-recovery.v1.json`](vectors/group-data-fork-recovery.v1.json). It models a same-epoch
group-data update race and asserts the semantic outcome: both clients reach epoch 2 with two members, one client
observes recovery from epoch 1 to epoch 2, and the winner and invalidated ordering keys are distinct.

`concurrent-invite-fork-recovery/v1` uses the same semantic recovery style for an invite race. It checks convergence and
recovery without pinning which invite branch wins.

`ScenarioSpec` v1 contains ordered client labels and ordered steps. Supported steps are:

- `create_group`
- `invite_members`
- `update_group_data`
- `confirm_pending`
- `fail_pending`
- `send_app_message`
- `leave`
- `deliver_all`
- `tick`
- `observe`
- `clear_events`
- `drop_queued`
- `duplicate_queued`
- `delay_queued`
- `release_delayed`
- `reorder_queued`
- `set_partition`
- `clear_partition`
- `restart_client`

Pending operations are referenced by string labels chosen inside the scenario. Client labels are stable logical names;
the Rust harness maps them to deterministic Nostr keys so welcome routing and NIP-59 decryption exercise the same
identity shape as production. Queue fault steps select messages by the current zero-based queue index at that step.
`reorder_queued.order` is a full permutation of current queue indices; each entry names which old queue slot moves into
the next position. `delay_queued` stores selected messages under a string label, and `release_delayed` returns that
label's messages to the end of the queue.

## Generated scenario families

`generate_send_leave_family(seed, cases)` produces deterministic `GeneratedScenarioCase` values. Each case records:

- `family_name`
- `generator_version`
- `seed`
- `case_index`
- `scenario`
- `expected_outcomes`

The generated `scenario` is a normal `ScenarioSpec`, so a selected generated case can be serialized into a fixed fixture
without inventing a separate execution path. We promote a case only when it should become a stable named contract, such
as a regression fixture or the smallest readable example of a semantic edge.

`generate_convergence_e2e_delivery_family(seed, cases)` produces deterministic variants of
`convergence-e2e-group-events/v1`. Each variant keeps the logical branch race stable but mutates queued delivery with
duplicate, delay/release, and reorder steps before observer clients tick. Under the real Nostr peeler the stable
expectation is that observers agree on one canonical branch, which may be Bob's single-commit branch at epoch 2 or
Alice's deeper branch at epoch 3 depending on which messages are available before the stability gate. In both cases the
trace includes exactly the selected branch application payload.

`generate_convergence_chaos_family(seed, cases)` produces deterministic adversarial convergence cases with built-in
semantic expectations. The first generator version rotates through invite forks, group-data forks, publish rollback plus
delayed duplicates, partition/heal/leave, delayed past-epoch app delivery, stable duplicate/delay/reorder queue faults,
20+ client message storms, partitioned large-group delivery storms, multi-committer group-data storms, mixed large
message/commit storms, and restart plus duplicate delivery faults. These cases are ordinary `ScenarioSpec`s, so the same
runner and report path can turn selected generated cases into fixed vectors when that makes the conformance contract
clearer.

## Report artifacts

`run_scenario_report(spec, expected_trace)` executes a scenario and returns a serializable `ScenarioReport` with:

- `metadata` — scenario name, spec version, step count, and optional generated case or fixture metadata.
- `scenario` — the exact scenario input that was executed.
- `expected_trace` — the trace being checked, when supplied.
- `expected_outcomes` — semantic fixture expectations, when supplied.
- `observed_trace` — the trace produced by the scenario runner.
- `oracle` — scenario stimuli, expected behavior classes, observed behavior classes, evidence counts, and weak-oracle
  warnings.
- `step_log` — one entry per completed scenario step.
- `pending_resolution_observations` — flattened publish confirmations and rollbacks.
- `recovery_observations` — flattened fork-recovery events from all client observations.
- `epoch_change_observations` — flattened `EpochChanged` events from all client observations.
- `app_invalidation_observations` — flattened app invalidation dispositions from all client observations.
- `expectation_failures` — exact-trace or semantic expectation mismatches with expected and actual JSON.
- `invariant_failures` — compatibility field mirroring expectation failures by kind and message.

`run_generated_case_report(case, expected_trace)` adds generated-family metadata: family name, generator version, seed,
case index, and an optional `minimized_case` field. Failing generated cases run a conservative greedy minimizer that
removes removable delivery/app steps only when the same failure kinds still reproduce. Generated report runs also write
a sibling `*-fixture.v1.json` candidate. Cases with semantic expectations keep those expectations; cases without them
use the observed trace as an exact expected trace in the candidate. When a failing generated case has a minimized
reproducer, the fixture candidate uses that minimized scenario.

To run the current generated family and write JSON reports:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family send-leave/v1 \
  --seed 42 \
  --cases 10 \
  --out target/cgka-conformance-simulator-reports
```

To shake the convergence E2E bridge instead:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family convergence-e2e-delivery/v1 \
  --seed 42 \
  --cases 10 \
  --out target/cgka-conformance-simulator-reports
```

To run the broader adversarial convergence chaos family:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family convergence-chaos/v1 \
  --seed 42 \
  --cases 10 \
  --out target/cgka-conformance-simulator-reports
```

Reports are written as one file per case, for example
`target/cgka-conformance-simulator-reports/send-leave-v1-seed-42-case-0.json`. Generated family runs also write fixture
candidates such as `target/cgka-conformance-simulator-reports/convergence-chaos-v1-seed-42-case-0-fixture.v1.json`.

## When to use the harness vs. integration tests

- **Question:** "Does this single engine method behave correctly?"
  - **Where to put the test:** `cgka-engine/tests/*.rs`

- **Question:** "Do N engines converge under FIFO delivery?"
  - **Where to put the test:** `cgka-conformance-simulator/tests/canonical_scenarios.rs`

- **Question:** "Does this hold for _any_ sequence of N intents?"
  - **Where to put the test:** `cgka-conformance-simulator/tests/proptest_invariants.rs`

- **Question:** "What happens under reorder / partition / replay?"
  - **Where to put the test:** New scripted scenario; consider extending the proptest strategies once the case is
    concrete

- **Question:** "Can another implementation reproduce this behavior?"
  - **Where to put the test:** Add or update a JSON fixture in `vectors/`

- **Question:** "Do generated scenarios produce useful artifacts?"
  - **Where to put the test:** Run `cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report --
    ...`

See [`AGENTS.md`](AGENTS.md) for the agent-facing map (bus model, scheduler policies, how to add a scenario).
