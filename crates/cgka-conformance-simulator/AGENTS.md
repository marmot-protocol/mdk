# AGENTS.md — cgka-conformance-simulator

Read [`README.md`](README.md) for the human framing, [`SCENARIOS.md`](SCENARIOS.md) for the scenario registry, and
[`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) for the property-test registry. This file is the agent-facing model.

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
    handle. It uses in-memory SQLite by default and can run on temp file-backed SQLite via
    `DARKMATTER_CONFORMANCE_SQLITE_STORAGE=file` or `ClientBuilder::storage_mode`. `tick().await` drains pending inbound
    for one client. `confirm(pending).await` finishes a `GroupEvolution`.

- **Module:** `cgka_engine::convergence`
  - **Role:** Candidate-state graph scoring rules for the distributed convergence design, re-exported by this crate for
    tests. These tests pin selector policy independently from OpenMLS replay.

- **Module:** `src/family.rs`
  - **Role:** Deterministic generated scenario families. `generate_send_leave_family`,
    `generate_convergence_e2e_delivery_family`, and `generate_convergence_chaos_family` record family name, generator
    version, seed, case index, runnable `ScenarioSpec`, and optional semantic expectations. `run_generated_case_report`
    adds generated metadata to report artifacts.

- **Module:** `src/oracle.rs`
  - **Role:** Scenario oracle and coverage evidence. Computes scenario stimuli, expected behavior classes, observed
    behavior classes, weak-oracle warnings, and coverage matrix rows.

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
  - **Role:** Serializable `ScenarioSpec` v1 plus `run_scenario_spec` / `run_scenario_report` /
    `run_vector_fixture_report`. Drives ordered client operations from JSON-shaped scenario data and returns either a
    `ScenarioTrace` or a serializable report with the executed scenario, metadata, step log, flattened epoch changes,
    app invalidations, recoveries, expectation failures, and invariant failures.

- **Module:** `src/vector.rs`
  - **Role:** `ScenarioTrace`, observations, and semantic `TraceExpectation` checks. Records final epoch/member/payload
    facts plus member additions/removals, client convergence, epoch changes, app invalidations, and
    `ForkRecoveryObservation` entries from `GroupEvent::ForkRecovered`.

- **Module:** `src/policy_cases.rs`
  - **Role:** Serializable `PolicyCase` DTOs plus selection-reasoning helpers (`parse_policy_cases`, `reason_against`,
    `digest_rank`) for the bounded convergence-policy cases shared with the Tamarin model.

- **Module:** `src/report.rs`
  - **Role:** Report command parsing and run-summary types (`ReportArgs`, `ReportCommand`, `ReportRunSummary`,
    `ScenarioReportSummary`, `ReportFailureSummary`) used by the report CLI.

- **Module:** `src/bin/cgka-conformance-simulator-report.rs`
  - **Role:** Report writer CLI. Runs generated families or vector fixture files/directories, writes one JSON
    `ScenarioReport` per scenario plus fixture candidates for generated cases, prints a pass/fail summary, and exits
    non-zero on expectation failures.

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

- `ordered`: FIFO. Default for all canonical scenarios + the proptest.
- `reverse`: pop from the back. Useful for ingesting commits before their proposals.
- `seeded_random`: deterministic shuffle from a fixed `u64` seed.
- `partition`: drop messages whose recipient is in the partition set.

The bus knows about welcomes vs. group messages so welcomes can be routed to a specific recipient without requiring it
to be a group member yet.

`ScenarioSpec` queue faults are explicit steps. They mutate the bus queue before delivery by zero-based queue index:
`drop_queued`, `duplicate_queued`, `delay_queued`, `release_delayed`, and `reorder_queued`. `set_partition` and
`clear_partition` remain the partition/heal operations.

Use `clear_events` after setup when a scenario wants the final trace to describe only the behavior under test. The
convergence E2E scenario does this after the initial welcome joins so its trace focuses on the peeler-ingest epoch
change and selected branch outputs. Delayed past-epoch app messages are covered via retained epoch contexts.
Future-epoch branch messages are stored as raw transport bytes, retried after canonical branch selection advances the
MLS context, and only emitted if they decrypt on the selected branch.

The `convergence-e2e-delivery/v1` generated family reuses that E2E shape and varies queue delivery with duplicate,
delay/release, and reorder steps before observer ticks. Use it when checking the peeler-ingest to `GroupEvent` bridge
under transport schedule noise.

The `convergence-chaos/v1` generated family rotates through adversarial convergence shapes: invite fork recovery,
group-data fork recovery, rollback plus delayed duplicate delivery, partition/heal/leave, delayed past-epoch app
delivery, stable duplicate/delay/reorder queue faults, 20+ client message storms, partitioned large-group delivery
storms, multi-committer group-data storms, mixed large message/commit storms, and restart plus duplicate delivery
faults. These cases carry semantic `expected_outcomes`, so report failures point at the broken convergence invariant
instead of only writing an observation dump.

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
4. Make recovery behavior observable through `ForkRecoveryObservation`, not just final membership.
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

Generated-family runs write both `*-case-N.json` reports and `*-case-N-fixture.v1.json` candidates that can be promoted
into `vectors/` after review.

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

- **`HarnessIntent` does not generate Invite / UpgradeCapabilities / UpdateGroupData.** Invite needs client minting
  inside a strategy; the scripted tests cover it today. Upgrade and group-data update lifecycle are covered by separate
  generated properties.
- **Partition policy is scripted, not strategy-driven.** The bus supports partitions; proptest currently drives FIFO /
  Reverse / SeededRandom.
- **Generated family coverage is now convergence-focused but not exhaustive.** `send-leave/v1` records lifecycle
  metadata, `convergence-e2e-delivery/v1` mutates the convergence E2E bridge with duplicate/delay/reorder delivery, and
  `convergence-chaos/v1` covers invite races, group-data races, publish rollback, partitions, leaves, delayed past-epoch
  app delivery, queue faults, 20+ client message storms, partitioned large-group storms, multi-committer group-data
  storms, mixed message/commit storms, and restart plus duplicate delivery. Storage-loss families are still future work.
- **Admin-gated scripted steps need admin setup.** When a scenario has an invitee later send `InviteMembers` or
  `UpdateGroupData`, the runner promotes that invitee to an initial admin for the group. Direct harness tests should
  use `create_group_with_admins` explicitly for competing admin commits.
- **Failure minimization is intentionally conservative.** Generated reports populate `minimized_case` with a greedy
  step-removal reducer when removable app/delivery noise can be dropped without changing the failure kinds. There is no
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
