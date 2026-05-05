# AGENTS.md — cgka-conformance

Read [`README.md`](README.md) for the human framing. This file is the agent-facing model.

## Pieces

| Module | Role |
|---|---|
| `src/bus.rs` | `TransportBus` — in-memory bus. Owns delivery policy, the queue, partition state, and the address book that maps `MemberId → ClientId` (for welcome routing). |
| `src/client.rs` | `HarnessClient` + `ClientBuilder`. Wraps an `Engine<MemoryStorage>` and the bus handle. `tick().await` drains pending inbound for one client. `confirm(pending).await` finishes a `GroupEvolution`. |
| `src/family.rs` | Deterministic generated scenario families. `generate_send_leave_family` records family name, generator version, seed, case index, and a runnable `ScenarioSpec`. `run_generated_case_report` adds generated metadata to report artifacts. |
| `src/peeler.rs` | `MockPeeler` — pass-through. Group messages and welcomes go through distinct methods (matches the real `TransportPeeler` four-method shape from spike-findings §1.3) but the body is just length-prefixed framing, no encryption. Transport ids/timestamps are deterministic per client so vector traces stay stable despite OpenMLS randomness. |
| `src/proptest_support.rs` | `intent_seq(n_clients, range)` proptest strategy. Generates `HarnessIntent::Send` and `HarnessIntent::Leave`; `delivery_profile()` covers FIFO, reverse, and seeded-random delivery. |
| `src/scenario.rs` | Serializable `ScenarioSpec` v1 plus `run_scenario_spec` / `run_scenario_report`. Drives ordered client operations from JSON-shaped scenario data and returns either a `ScenarioTrace` or a serializable report with metadata, step log, recoveries, and invariant failures. |
| `src/vector.rs` | `ScenarioTrace` and observations. Records final epoch/member/payload facts plus `ForkRecoveryObservation` entries from `GroupEvent::ForkRecovered`. |
| `src/bin/cgka-conformance-report.rs` | Tiny report writer CLI. Runs `send-leave/v1` cases with `--seed`, `--cases`, and `--out`, then writes one JSON `ScenarioReport` per generated case. |
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
5. Run `cargo test -p cgka-conformance canonical_vector_fixtures_match_generated_traces`.

## How to run generated reports

Use the CLI when you want JSON artifacts:

```sh
cargo run -p cgka-conformance --bin cgka-conformance-report -- \
  --family send-leave/v1 \
  --seed 42 \
  --cases 10 \
  --out target/cgka-conformance-reports
```

## How to add a new proptest invariant

1. New `proptest!` block in `tests/proptest_invariants.rs`.
2. If you need new intent kinds, extend `HarnessIntent` in `src/proptest_support.rs` and the matching strategy fn.
3. Encode the invariant as `prop_assert_unique(actual, expected, msg)` — the helper panics on mismatch so shrinking works.
4. Default `cases` is 24; the `conformance-slow` feature lifts it to 1000. Don't hand-tune per-test counts.

## Coverage gaps

These are tracked in [`../../plans/2026-05-04-cgka-conformance-vectors-and-chaos-roadmap.md`](../../plans/2026-05-04-cgka-conformance-vectors-and-chaos-roadmap.md). If you're filling one of these in, update the plan's status row in the same change.

- **`HarnessIntent` does not generate Invite / UpgradeCapabilities / UpdateGroupData.** Invite needs client minting inside a strategy; the scripted tests cover it today.
- **Partition policy is scripted, not strategy-driven.** The bus supports partitions; proptest currently drives FIFO / Reverse / SeededRandom.
- **Only one generated family exists.** `send-leave/v1` records replay metadata; invite races, group-data updates, and publish confirm/fail families are still future work.
- **Failure minimization is represented but not implemented.** Reports expose `minimized_case`, but there is no shrinker yet.

## Conventions

- **Identities are `pad32(b"name")`.** MIP-01 requires 32-byte x-only pubkeys; the engine strict-fails on non-32-byte. Don't shortcut.
- **`MockPeeler` does not panic on garbage.** It returns a structured `PeelerError`. Tests can assert on `StaleReason::PeelFailed` if needed.
- **`HarnessClient` exposes only what tests need.** If you need the inner `Engine<S>`, that's a smell — extend the harness API instead and keep tests at one abstraction level.
