# test-harness

In-process multi-client simulator for the CGKA engine. Lets us replay scripted scenarios and run property-based invariants against `Engine<MemoryStorage>` without going anywhere near a network or real crypto.

## What this crate gives you

- `TransportBus` — an in-memory message bus with seeded scheduling, partition support, broadcast and addressed delivery (for welcomes), and replay hooks.
- `HarnessClient` — wraps `Engine<MemoryStorage>` + a `MockPeeler` (skips encryption so tests can assert on inner payloads directly).
- `ScenarioSpec` — a serializable v1 input contract for deterministic scripted scenarios, including explicit queue faults and partitions.
- `VectorFixture` — portable JSON fixtures pairing runnable scenario input with expected `ScenarioTrace` output.
- `ScenarioReport` — serializable run artifacts with metadata, expected/observed traces, step logs, recoveries, and invariant failures.
- `harness-report` — a small CLI that runs generated `send-leave/v1` cases and writes JSON reports.
- `proptest_support` — strategies that generate arbitrary typed `SendIntent` sequences for property-based tests.
- `MockPeeler` — a deliberately trivial `TransportPeeler` impl. Distinguishes the group-message vs welcome paths but performs no encryption.

## Run the tests

```sh
# Default: scripted scenarios + proptest with 24 cases (~1 s).
cargo test -p test-harness

# Pre-release validation: 1000 proptest cases per property.
cargo test -p test-harness --features harness-slow
```

## Canonical vector fixtures

Canonical conformance fixtures live in [`vectors/`](vectors/). Each file is a
JSON `VectorFixture` envelope:

- `scenario_name` — stable logical scenario id, currently including `/v1`.
- `vector_version` — fixture schema version, currently `"1"`.
- `harness_version` — `test-harness` crate version that produced the fixture.
- `seed` — `null` for hand-authored deterministic scenarios.
- `scenario` — the input-side `ScenarioSpec` to execute.
- `expected_trace` — the `ScenarioTrace` a conforming implementation must
  produce.

Non-Rust implementations should read the JSON file, run the named scenario
from `scenario`, serialize their observed trace into the same shape, and
compare `expected_trace` by value. The trace intentionally avoids OpenMLS
internals, but it does include `ForkRecoveryObservation` entries so an
implementation that reaches the same final membership through a different
recovery path fails the vector.

`ScenarioSpec` v1 contains ordered client labels and ordered steps. Supported
steps are:

- `create_group`
- `invite_members`
- `confirm_pending`
- `fail_pending`
- `send_app_message`
- `leave`
- `deliver_all`
- `tick`
- `observe`
- `drop_queued`
- `duplicate_queued`
- `delay_queued`
- `release_delayed`
- `reorder_queued`
- `set_partition`
- `clear_partition`

Pending operations are referenced by string labels chosen inside the scenario.
Client labels are stable logical names; the Rust harness maps them to padded
32-byte test identities. Queue fault steps select messages by the current
zero-based queue index at that step. `reorder_queued.order` is a full
permutation of current queue indices; each entry names which old queue slot
moves into the next position. `delay_queued` stores selected messages under a
string label, and `release_delayed` returns that label's messages to the end
of the queue.

## Generated scenario families

`generate_send_leave_family(seed, cases)` produces deterministic
`GeneratedScenarioCase` values. Each case records:

- `family_name`
- `generator_version`
- `seed`
- `case_index`
- `scenario`

The generated `scenario` is a normal `ScenarioSpec`, so a failing generated
case can be serialized and promoted into a fixed fixture without inventing a
separate execution path.

## Report artifacts

`run_scenario_report(spec, expected_trace)` executes a scenario and returns a
serializable `ScenarioReport` with:

- `metadata` — scenario name, spec version, step count, and optional generated
  case metadata.
- `expected_trace` — the trace being checked, when supplied.
- `observed_trace` — the trace produced by the scenario runner.
- `step_log` — one entry per completed scenario step.
- `recovery_observations` — flattened fork-recovery events from all client
  observations.
- `invariant_failures` — currently records `trace_mismatch` when expected and
  observed traces differ.

`run_generated_case_report(case, expected_trace)` adds generated-family
metadata: family name, generator version, seed, case index, and an optional
`minimized_case` field for future shrink results.

To run the current generated family and write JSON reports:

```sh
cargo run -p test-harness --bin harness-report -- \
  --family send-leave/v1 \
  --seed 42 \
  --cases 10 \
  --out target/harness-reports
```

Reports are written as one file per case, for example
`target/harness-reports/send-leave-v1-seed-42-case-0.json`.

## When to use the harness vs. integration tests

| Question | Where to put the test |
|---|---|
| "Does this single engine method behave correctly?" | `cgka-engine/tests/*.rs` |
| "Do N engines converge under FIFO delivery?" | `test-harness/tests/canonical_scenarios.rs` |
| "Does this hold for *any* sequence of N intents?" | `test-harness/tests/proptest_invariants.rs` |
| "What happens under reorder / partition / replay?" | New scripted scenario; consider extending the proptest strategies once the case is concrete |
| "Can another implementation reproduce this behavior?" | Add or update a JSON fixture in `vectors/` |
| "Do generated scenarios produce useful artifacts?" | Run `cargo run -p test-harness --bin harness-report -- ...` |

See [`AGENTS.md`](AGENTS.md) for the agent-facing map (bus model, scheduler policies, how to add a scenario).
