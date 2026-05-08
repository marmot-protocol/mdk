# AGENTS.md — cgka-conformance-simulator

Read [`README.md`](README.md) for the human framing. This file is the agent-facing model.

## Pieces

| Module | Role |
|---|---|
| `src/bus.rs` | `TransportBus` — in-memory bus. Owns delivery policy, the queue, partition state, and the address book that maps `MemberId → ClientId` (for welcome routing). |
| `src/canonicalization.rs` | Executable model of the CGKA canonicalization contract. Uses symbolic peeled messages plus optional materialized candidate metadata, then calls the convergence selector to produce deterministic message dispositions. |
| `src/client.rs` | `HarnessClient` + `ClientBuilder`. Wraps an `Engine<MemoryStorage>` and the bus handle. `tick().await` drains pending inbound for one client. `confirm(pending).await` finishes a `GroupEvolution`. |
| `src/convergence.rs` | Model-level candidate-state graph scoring rules for the distributed convergence design. These tests do not drive OpenMLS yet; they pin policy before the engine canonicalizer lands. |
| `src/family.rs` | Deterministic generated scenario families. `generate_send_leave_family` and `generate_convergence_e2e_delivery_family` record family name, generator version, seed, case index, and a runnable `ScenarioSpec`. `run_generated_case_report` adds generated metadata to report artifacts. |
| `src/openmls_projection.rs` | Bytes-first OpenMLS projection and candidate materialization helpers. Parses MLS bytes, replays candidate paths against a snapshot, observes proposal refs / staged commits / app decryptions, rolls storage back, and can run the canonicalizer with OpenMLS-derived pending proposal/app-message evidence. |
| `src/peeler.rs` | `MockPeeler` — pass-through. Group messages and welcomes go through distinct methods, matching the production `TransportPeeler` four-method shape, but the body is just length-prefixed framing with no encryption. Transport ids/timestamps are deterministic per client so vector traces stay stable despite OpenMLS randomness. |
| `src/proptest_support.rs` | `intent_seq(n_clients, range)` proptest strategy. Generates `HarnessIntent::Send` and `HarnessIntent::Leave`; `delivery_profile()` covers FIFO, reverse, and seeded-random delivery. |
| `src/scenario.rs` | Serializable `ScenarioSpec` v1 plus `run_scenario_spec` / `run_scenario_report`. Drives ordered client operations from JSON-shaped scenario data and returns either a `ScenarioTrace` or a serializable report with metadata, step log, flattened epoch changes, app invalidations, recoveries, and invariant failures. |
| `src/vector.rs` | `ScenarioTrace` and observations. Records final epoch/member/payload facts plus member additions/removals, epoch changes, app invalidations, and `ForkRecoveryObservation` entries from `GroupEvent::ForkRecovered`. |
| `src/bin/cgka-conformance-simulator-report.rs` | Tiny report writer CLI. Runs `send-leave/v1` cases with `--seed`, `--cases`, and `--out`, then writes one JSON `ScenarioReport` per generated case. |
| `vectors/` | External JSON `VectorFixture` files. Each fixture carries both input `scenario` and output `expected_trace`. |

## Bus model

The bus is **synchronous and deterministic**. Calling `client.send_app(...)` enqueues; calling `bus.deliver_all()` (or `bus.step(n)`) flushes; calling `client.tick().await` ingests on the receiver side. There is no actual async runtime cooperation — sending is `&mut self`, the engine is awaited inline.

Delivery policies (`DeliveryPolicy`):

- `ordered` — FIFO. Default for all canonical scenarios + the proptest.
- `reverse` — pop from the back. Useful for ingesting commits before their proposals.
- `seeded_random` — deterministic shuffle from a fixed `u64` seed.
- `partition` — drop messages whose recipient is in the partition set.

The bus knows about welcomes vs. group messages so welcomes can be routed to a specific recipient without requiring it to be a group member yet.

`ScenarioSpec` queue faults are explicit steps. They mutate the bus queue
before delivery by zero-based queue index: `drop_queued`, `duplicate_queued`,
`delay_queued`, `release_delayed`, and `reorder_queued`. `set_partition` and
`clear_partition` remain the partition/heal operations.

Use `clear_events` after setup when a scenario wants the final trace to describe
only the behavior under test. The convergence E2E vector does this after the
initial welcome joins so its trace contains only canonical branch application,
app invalidation, epoch change, and member addition events.

The `convergence-e2e-delivery/v1` generated family reuses that E2E shape and
varies queue delivery with duplicate, delay/release, and reorder steps before
observer ticks. Use it when checking the peeler-ingest to `GroupEvent` bridge
under transport schedule noise.

## How to add a new scripted scenario

1. Prefer a `ScenarioSpec` when the case should become portable or reportable.
2. For narrow engine-harness behavior, add a test fn in `tests/canonical_scenarios.rs`.
3. Build N clients with `ClientBuilder::new(pad32(b"alice")).registry(registry()).attach(&bus)` only when the test needs lower-level harness control.
4. Drive manual scenarios with `client.send_*` / `bus.deliver_all()` / `client.tick().await`.
5. Assert on `client.epoch()`, `client.members()`, `observe_client(...)`, or `run_scenario_report(...)` depending on the test surface.

Look at `three_client_happy_path_via_harness` for the canonical shape.

## How to add or update a vector fixture

1. Encode the runnable input as `ScenarioSpec` JSON in `vectors/*.json`.
2. Include `scenario_name`, `vector_version`, `conformance_version`, `seed`, `scenario`, and `expected_trace`.
3. Keep `ScenarioTrace` free of MLS bytes and Rust-only internals.
4. Make recovery behavior observable through `ForkRecoveryObservation`, not just final membership.
5. Run `cargo test -p cgka-conformance-simulator canonical_vector_fixtures_match_generated_traces`.

## OpenMLS replay probes

`openmls_projection` is intentionally bytes-first. Probe tests should capture
`TransportMessage` values from the harness, replay their MLS payload bytes
against a `MemoryStorage` group snapshot, collect observations such as
`ProposalRef`s from `StagedCommit::queued_proposals()`, then rely on the helper
to roll storage back. Candidate materialization should turn those replay
observations into `MaterializedCandidate` values, then call
`canonicalize_with_materialized_candidates` so commit ids, consumed proposal
ids, and losing-branch dispositions are handled by the canonicalizer. Do not
store OpenMLS protocol objects in conformance fixtures; they are consumed by
OpenMLS APIs. For a full replay-to-canonicalization pass, use
`canonicalize_openmls_batch`: it maps OpenMLS `ProposalRef`s back to canonical
message ids and turns successful application-message replays into branch
witnesses plus stored payload refs. Candidate paths should carry commits; the
batch's `pending_messages` supplies proposals and app messages for replay
probing. Use `canonicalize_stored_openmls_messages` when the test should prove
that durable `MessageRecord` rows can reconstruct the same batch after restart
or relay sync.

## How to run generated reports

Use the CLI when you want JSON artifacts:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family send-leave/v1 \
  --seed 42 \
  --cases 10 \
  --out target/cgka-conformance-simulator-reports
```

## How to add a new proptest invariant

1. New `proptest!` block in `tests/proptest_invariants.rs`.
2. If you need new intent kinds, extend `HarnessIntent` in `src/proptest_support.rs` and the matching strategy fn.
3. Encode the invariant with `prop_assert(actual, expected, msg)` when comparing model values; the helper panics with useful context so shrinking keeps the original failure visible.
4. Use one config per `proptest!` block. Harness-heavy properties default to smaller case counts; pure selector/canonicalization properties can run more cases. The `conformance-slow` feature should lift release-check properties to 1000 cases.

## Coverage gaps

These are tracked in [`../../plans/2026-05-04-cgka-conformance-simulator-vectors-and-chaos-roadmap.md`](../../plans/2026-05-04-cgka-conformance-simulator-vectors-and-chaos-roadmap.md). If you're filling one of these in, update the plan's status row in the same change.

- **`HarnessIntent` does not generate Invite / UpgradeCapabilities / UpdateGroupData.** Invite needs client minting inside a strategy; the scripted tests cover it today.
- **Partition policy is scripted, not strategy-driven.** The bus supports partitions; proptest currently drives FIFO / Reverse / SeededRandom.
- **Only two generated families exist.** `send-leave/v1` records lifecycle metadata, and `convergence-e2e-delivery/v1` mutates the convergence E2E bridge with duplicate/delay/reorder delivery. Invite races, group-data updates, publish confirm/fail families, and broader failure minimization are still future work.
- **Failure minimization is represented but not implemented.** Reports expose `minimized_case`, but there is no shrinker yet.

## Conventions

- **Identities are `pad32(b"name")`.** MIP-01 requires 32-byte x-only pubkeys; the engine strict-fails on non-32-byte. Don't shortcut.
- **`MockPeeler` does not panic on garbage.** It returns a structured `PeelerError`. Tests can assert on `StaleReason::PeelFailed` if needed.
- **`HarnessClient` exposes only what tests need.** If you need the inner `Engine<S>`, that's a smell — extend the harness API instead and keep tests at one abstraction level.
