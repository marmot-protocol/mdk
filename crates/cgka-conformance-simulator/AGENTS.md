# AGENTS.md — cgka-conformance-simulator

Agent-facing code model. Read [`README.md`](README.md) for how convergence is tested (adapters, Scenario IR, oracles,
families, reports), [`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md) for exact operator commands and artifact handling,
[`SCALING_CAMPAIGNS.md`](SCALING_CAMPAIGNS.md) for large matrices and family design, [`SCENARIO_IR.md`](SCENARIO_IR.md)
for canonical and authoring semantics, [`SCENARIOS.md`](SCENARIOS.md) for the scenario registry, and
[`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) for the property-test registry. Local maps: [`src/AGENTS.md`](src/AGENTS.md),
[`tests/AGENTS.md`](tests/AGENTS.md), [`vectors/AGENTS.md`](vectors/AGENTS.md).

## Agent operating workflow

When asked to run, extend, diagnose, or report on convergence campaigns:

1. Identify the claim before choosing the execution layer. Use an engine-capable subject for exact MLS-private state,
   durable input dispositions, pending work, and active decryptability. Use app/process/container projections only for
   public facts they can actually expose.
2. Start with a strict, file-backed canary. Do not use `--allow-weak-oracle` to make an assurance run green.
3. For broad discovery, use `cgka-conformance-campaign`: it persists the exact input before action zero, isolates each
   case in a child, enforces a deadline, and verifies artifacts. Build once and shard distinct seeds or disjoint
   `--case-index` selections when scaling.
4. Reproduce from the saved `*-generated-input.json`, not from a remembered command alone. Record family version,
   seed, case index, selected/executed IR digests, adapter, storage mode, source revision, and output path.
5. Move a failure down to the smallest compatible adapter before debugging it. Move representative cases outward to
   process/container/VM only when that layer answers a named hypothesis.
6. Preserve reports and capsules before changing code. Sensitive replay capsules contain key material: keep them
   owner-only, never commit them, and never quote their contents into issues or logs.
7. Classify a failure before fixing it: product defect, protocol ambiguity, environment failure, or expected resource
   refusal. A timeout, unsupported capability, weak oracle, and semantic mismatch are not interchangeable. Suspect the
   harness too: the exact restart catalog's first red run was a simulator false positive (MDK #1465).
8. After a fix, rerun the minimized input, original input, family canary, relevant focused test, and widest adapter
   needed by the claim. Report local gates, remote CI, and retained evidence separately.

Use a new output directory for every campaign run; overwrite refusal is an evidence-integrity feature. Direct binary
execution requires `RUST_MIN_STACK=4194304`; Cargo-launched commands inherit it from `.cargo/config.toml`. Keep
`--locked` on CI-like Cargo commands.

Do not infer that more `--cases` means more complex scenarios. Cases are independent indices and seed selects their
deterministic choices. The stable identity is `(family_name, generator_version, seed, case_index)`, plus an
independently versioned workload profile when applicable. Shard large campaigns by disjoint repeatable `--case-index N`
selections with fresh output roots, or by distinct seeds, rather than overlapping prefixes of the same seed. Generated
inputs/reports do not embed the tested Git commit; require a clean build and retain the exact source revision plus
command matrix beside durable evidence.

## Code map

### Scenario language

- **`src/scenario.rs`** — Serializable `ScenarioSpec` v2/v3 plus `run_scenario_spec` / `run_scenario_report` /
  `run_vector_fixture_report`. Owns step semantics: ordered client operations, the step log, flattened epoch changes,
  app invalidations, recoveries, and expectation/invariant failures. `ObserveExact` opts a portable scenario into the
  canonical snapshot and scenario-input ledger while legacy `Observe` stays stable for existing fixtures.
  `ProbeBidirectionalDecryptability` actively exercises send, peel, MLS decrypt, and delivery. V3's `expect_tick_error`
  records a normalized expected transport refusal and continues.
- **`src/scenario_ir.rs`** — Canonical v2/v3 compiler: validates input, assigns stable action ids, records the
  virtual-time schedule, derives per-action capabilities, and preflights the whole schedule before the subject runs
  anything. `SCENARIO_IR_V3_ONLY_STEP_KINDS` lists post-v2 actions; v2 documents that use them fail to compile. JSON
  contracts: `schemas/scenario-ir.v2.schema.json`, `schemas/scenario-ir.v3.schema.json`.
- **`src/scenario_authoring.rs`** — Authoring-only repeat, deterministic parallel, rate, burst, and barrier expansion,
  lowered to canonical IR before execution. Adapters never interpret authoring control flow. Contract:
  `SCENARIO_IR.md`, `schemas/scenario-authoring.v1.schema.json`.
- **`src/topology.rs`** — Adapter-neutral accounts, devices, processes, groups, relays, roles, and binary/policy
  versions. Resolves old client-only vectors to an explicit deterministic topology.
- **`src/scenario_faults.rs`, `src/scenario_assertions.rs`** — Semantic message selectors and declared
  offline/process/storage faults; executable exactly/eventually/within/never/resource assertions sampled through the
  subject boundary and recorded in reports and capsules. Unsupported capabilities fail whole-schedule preflight.
- **`src/assertion_wait.rs`** — Shared real-app eventual-assertion pacing (see `src/AGENTS.md`).
- **`src/scenario_input.rs`** — Resolves raw canonical IR or a saved `GeneratedScenarioInputV1` into one scenario plus
  source-byte and canonical-IR digests. Wider adapters must consume this boundary.
- **`src/scenario_stimuli.rs`** — Typed, replayable real-runtime stimuli (`interrupt_relay`, racing edits) and their
  execution evidence.

### Subjects and transport

- **`src/subject.rs`** — `ConvergenceSubject` boundary and the built-in `EngineHarnessSubject`. Every adapter declares a
  versioned capability set checked before execution. The engine adapter installs one shared manual paired clock:
  `AdvanceTime` moves both clock domains without waking a runtime and activates virtual-time ticks; `Tick` selects
  which participants run. It captures an append-only emission stream separate from the mutable bus queue:
  `poll_outbound` is non-destructive and `acknowledge_outbound` applies accepted/no-endpoint outcomes to staged commits,
  independent Welcomes, and regenerated queued intents. There is no auto-confirming compatibility lifecycle. Pending and
  outbound bookkeeping is scoped per client incarnation; never compare process-local pending handles across restarts.
  `structural_progress` exposes privacy-safe aggregate work, deadlines, pass phase/generation, and terminal state.
  Queue/partition mutation is only on the separately named `ConvergenceFaultSubject` white-box interface.
- **`src/retained_relay.rs`** — Real-engine subject with deterministic per-relay durable histories: fanout,
  subscriptions, incremental/since/full/set queries, EOSE, cursors, relay-local visibility/order/duplicates, and an
  explicit completeness claim per query. Quiet EOSE is never proof of complete history. Offline recovery tests must use
  this adapter rather than clearing a packet-bus partition.
- **`src/reference_subject.rs`** — Independent symbolic-memory `ConvergenceSubject`. Does not call the production
  selector/canonicalizer and omits exact-MLS and adversarial-transport capabilities; rely on preflight to keep
  unsupported scenarios from partially executing.
- **`src/bus.rs`** — `TransportBus`: delivery policy, queue, partition state, and the `MemberId` → `ClientId` address
  book for Welcome routing.
- **`src/client.rs`** — `HarnessClient` + `ClientBuilder`. Wraps `Engine<SqliteAccountStorage>`, a real
  `NostrMlsPeeler`, and the bus handle. Storage mode comes from `ClientBuilder::storage_mode`, the report CLI's
  `--storage`, or `MDK_CONFORMANCE_SQLITE_STORAGE` (CLI wins). File-backed `restart()` drops all engine/storage
  handles, reopens the encrypted database, and hydrates. `tick().await` drains pending inbound for one client;
  `confirm(pending).await` finishes a `GroupEvolution`. The per-tick no-progress guard counts durable deferred-row
  context attempts; an unchanged backlog count alone does not mean a bounded sweep stalled, but identical durable
  state still fails the guard.
- **`src/relay_control.rs`** — Simulator-owned retained-relay recording and reversible query visibility, outside
  production transport code.
- **`src/relay_fault_proxy.rs`** — Real socket interruption in front of the harness-owned loopback relay; every
  advertised relay URL goes through it, and it taps aggregate frame counts.
- **`src/audit_capture.rs`** — In-memory forensic capture so decisions the engine never surfaces as a `GroupEvent`
  (notably `convergence_decision`) are observable.

### App runtime and processes

- **`src/app_runtime.rs`, `src/app_runtime/`** — Public app scenario actions and assertions over separate participant
  processes with private SQLCipher roots and a separate real local relay. `process_backend.rs` bridges public app
  calls; `process_io.rs` owns bounded RPC, build-policy matching, and child cleanup; `process_relay.rs` owns
  relay/history/fault commands; `process_server.rs` dispatches node service modes; `strfry_process_scale.rs` is the
  manual real-strfry scale probe. `new_in_process_stress` is a diagnostic control. Gates and journeys:
  [`APP_SCENARIO_INVENTORY.md`](APP_SCENARIO_INVENTORY.md).
- **`src/process_orchestrator.rs`** — Multi-process executor for canonical IR (`cgka-conformance-process`). Shares the
  relay child while keeping its own capability-declared participant protocol.
- **`src/node_protocol.rs`** — Versioned JSONL control protocol for one app-runtime participant
  (`cgka-conformance-node`). Application-level only. It has no clock surface, so the process subject does not advertise
  `VirtualTime`.
- **`src/cross_route_scenario.rs`** — The canonical four-party route-assurance scenario plus its strict public
  process-report oracle. The engine-capable form adds exact state and active decryptability; app-runtime, process,
  container, and VM adapters reuse the public form and must not privately reconstruct its action schedule or terminal
  assertions. The branch-witness boundary uses a bounded `Eventually(ClientState)` assertion; preserve its
  process-report evidence and publication correlation checks instead of relying on relay drain timing. Restart
  permutations name relay-visibility boundaries by publication (`zeta-root`, `alpha-root`) and resolve them to action
  ids only after inserting the restart; non-publication boundaries match the complete semantic sequence that ends them.
  A table-driven test pins every inserted restart's exact step and client.

### Oracles and evidence

- **`src/oracle.rs`** — Stimuli, expected/observed behavior classes, weak-oracle warnings, and coverage matrix rows.
  Declared asserts are expected coverage; only passing assertion observations count as observed. Positive
  `PayloadCount` asserts cover `AppMessage` without inventing a cross-sender payload order.
- **`src/vector.rs`** — `ScenarioTrace`, observations, and semantic `TraceExpectation` checks: epoch/member/payload
  facts, member additions/removals, client convergence, epoch changes, app invalidations, exact canonical state,
  input dispositions, pending-work blockers, decryptability matrices, and settled `ConvergenceDecisionObservation`
  entries from the forensic recorder.
- **`src/scenario_input_ledger.rs`** — Per-client commit/proposal/application input accounting joined to transport,
  MLS content, and inner Marmot event ids, without production engine hooks.
- **`src/pending_work.rs`** — Strict instantaneous local-progress observation and the adapter-neutral structural
  progress schema (opaque token, runnable work, earliest wake, deferred/retry and acknowledgement work, transport
  state, pass phase/generation, terminal blockers) without protocol identifiers.
- **`src/quiescence.rs`** — Bounded virtual-time fixed-point driver. Runner policy decides whether outbound is accepted
  and transport delivered; limits never define success.
- **`src/decryptability.rs`** — Active probe results. A queued send counts as published only when the authenticated
  sender ledger proves publication; up to eight transport rounds deliver messages released during convergence.
  Unpublished or undelivered probes still fail. This is a mutating probe.
- **`src/campaign_metrics.rs`** — Report-native `campaign_measurements`. OS-only fields are explicitly unavailable
  in-process.

### Generated families

- **`src/family.rs`** — `GeneratedScenarioCase`, the `generate_family_case` registry (the single dispatch for every
  family name), the engine families (`send-leave`, `convergence-e2e-delivery`, `convergence-chaos`, `admin-churn`,
  `adversarial-reliability`, `bounded-convergence-pressure`, both cross-route restart catalogs), report wrappers, and
  the semantic minimizer. Reliability families append a final global drain, exact canonical observation, and
  pending-work assertion; do not remove a red strict result because an earlier legacy observation passed. The
  minimizer removes only app/transport-fault/partition steps and keeps fault–recovery pairs together
  (`semantic_reduction_units`).
- **`src/large_group_family.rs`** — Replay-stable 10–200 member pressure catalog with group size, admin population,
  committer width, traffic, formation, and disruption in versioned workload metadata. Size blocks are cost-ordered.
  Race arms must keep at least two active committers; bounded decryptability probes must keep late-join/re-add and
  roster-tail representatives.
- **`src/membership_reentry_family.rs`** — Single/repeated remove/re-add cycles, restart boundaries, self-update and
  self-leave interactions, fresh post-rejoin traffic, exact terminal equivalence, and the stale-original-Welcome
  incident archetype.
- **`src/offline_catchup_family.rs`** — Retained-relay backlog catalog; requires exact payload multiplicity, canonical
  equality, input closure, and post-recovery decryptability.
- **`src/stateful_generator.rs`** — Legality-aware journeys into canonical IR v3 (`chat-journey/v1`) and the
  `public-app-*` families. Add new product actions to the symbolic model and terminal oracle together.

### Independent verification

- **`src/reference_convergence.rs`** — Production-independent selector/canonicalizer oracle; no production engine
  imports.
- **`src/lifecycle_model.rs`** — Stateright mirror of `formal/liveness/ConvergenceLifecycle.tla`; transitions carry
  stable action ids projectable into Scenario IR.
- **`src/mutation_adequacy.rs`** — Single-rule semantic mutants, simulator-only. Production code is never compiled with
  a mutation feature. `tests/mutation_adequacy.rs` drift-checks `MUTATION_MATRIX.md`.
- **`src/route_assurance.rs`** — Ownership for every production convergence decision route plus reopenable claim
  records. Source-marker and `CONVERGENCE_ROUTE_MATRIX.md` drift tests force review when a route changes. Records
  evidence only; never participates in selection.
- **`src/policy_contract.rs`** — Machine-readable convergence-policy classification (conformance metadata, not wire
  format). `tests/protocol_decision_gate.rs` pins it against `PROTOCOL_DECISIONS.md`.
- **`src/policy_cases.rs`** — `PolicyCase` DTOs and selection-reasoning helpers for the cases shared with Tamarin.
- **`src/policy_sweep.rs`** — Feature-gated one-variable sweeps; prohibit production auto-tuning.
- **Re-exports** — `cgka_engine::{canonicalization, convergence, openmls_projection}` are re-exported for tests: the
  executable canonicalization contract, candidate-graph scoring rules, and bytes-first OpenMLS projection helpers.

### Reports and binaries

- **`src/report.rs`** — Report CLI parsing (`ReportArgs`, `ReportCommand`) and run summaries. Failed reports retain
  subject-step errors and emit restrictive failure capsules with captured transport artifacts.
- **`src/failure_capsule.rs`** — Failure fingerprints and capsules, restrictive artifact I/O, synthetic-vector
  promotion, and exact byte replay from a sensitive recipient checkpoint. Never put a checkpoint into a
  `synthetic_shareable` capsule; it contains key material. Schema: `schemas/failure-capsule.v1.schema.json`.
- **`src/bin/cgka-conformance-simulator-report.rs`** — In-process report writer: families, vectors, saved inputs,
  capsule replay.
- **`src/bin/cgka-conformance-campaign.rs`** — Parent/worker isolated campaign runner with `wait4`
  wall/CPU/peak-RSS/write measurements, provenance and artifact-integrity verification, and overwrite refusal. Every
  family exposes direct case-index generation so workers never regenerate the earlier prefix.
- **`src/bin/cgka-conformance-process.rs`, `src/bin/cgka-conformance-node.rs`** — Process orchestrator and participant
  child.
- **`src/bin/cgka-conformance-app-inventory.rs`** — Enumerates existing generated cases for `--adapter app-runtime`
  replay without rewriting actions or assertions.
- **`src/bin/cgka-policy-casegen.rs`** — Reads `formal/tamarin/policy_cases.json`; `just policy-casegen`.

## Bus model

The bus is **synchronous and deterministic**. `client.send_app(...)` enqueues; `bus.deliver_all()` (or `bus.step(n)`)
flushes; `client.tick().await` ingests on the receiver. There is no async runtime cooperation; sending is `&mut self`
and the engine is awaited inline.

Delivery policies (`DeliveryPolicy`):

- `ordered`: FIFO (`Ordered { broadcast_welcomes }`). Default for all canonical scenarios and the proptest.
- `reverse`: pop from the back. Useful for ingesting commits before their proposals.
- `seeded_random`: deterministic shuffle from a fixed `u64` seed.

Partitioning is orthogonal to delivery policy: `set_partition(Some(allowed))` restricts delivery to the allowed client
set (messages to clients outside it are dropped) and `set_partition(None)` heals. The bus distinguishes Welcomes from
group messages so a Welcome can reach a recipient that is not yet a member.

`ScenarioSpec` transport faults select by stable meaning (action id, publication, sender, protocol class, occurrence);
queue positions are an internal bus-test detail. `reached_no_endpoint` means definite non-publication: before engine
rollback the harness retracts every matching undelivered commit and Welcome from the queue and delayed sets, and
returns a scenario error instead of rolling back if any matching artifact already reached a recipient mailbox.

Use `clear_events` after setup when the final trace should describe only the behavior under test (the convergence E2E
scenario does this after the initial Welcome joins).

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
   `expected_outcomes`. Do not bump `conformance_version` outside a release.
3. Keep `ScenarioTrace` free of MLS bytes and Rust-only internals.
4. Make fork-resolution behavior observable through a settled `convergence_decision` expectation, not just final
   membership.
5. Update `vectors/manifest.v1.json` and `SCENARIOS.md`, then run
   `cargo test -p cgka-conformance-simulator canonical_vector_fixtures_match_generated_traces`.

More rules: [`vectors/AGENTS.md`](vectors/AGENTS.md).

## How to add a new proptest invariant

1. New `proptest!` block in `tests/proptest_invariants.rs`.
2. If you need new intent kinds, extend `HarnessIntent` in `src/proptest_support.rs` and the matching strategy fn.
3. Encode the invariant with `prop_assert(actual, expected, msg)` when comparing model values; the helper panics with
   useful context so shrinking keeps the original failure visible.
4. Use one config per `proptest!` block. Harness-heavy properties default to smaller case counts; pure
   selector/canonicalization properties can run more. `conformance-slow` raises counts according to test cost rather
   than forcing every property to the same number.
5. Update [`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) with generated inputs, the rule being checked, and the case counts.

## OpenMLS replay probes

`openmls_projection` is bytes-first. Probe tests capture `TransportMessage` values from the harness, replay their MLS
payload bytes against a `SqliteAccountStorage` group snapshot, collect observations such as `ProposalRef`s from
`StagedCommit::queued_proposals()`, and rely on the helper to roll storage back. Candidate materialization turns those
observations into `MaterializedCandidate` values, then calls `canonicalize_with_materialized_candidates` so commit ids,
consumed proposal ids, and losing-branch dispositions are handled by the canonicalizer. Do not store OpenMLS protocol
objects in conformance fixtures. For a full replay-to-canonicalization pass use `canonicalize_openmls_batch`: it maps
`ProposalRef`s back to canonical message ids and turns successful application replays into branch witnesses plus stored
payload refs. Candidate paths carry commits; the batch's `pending_messages` supplies proposals and app messages. Use
`canonicalize_stored_openmls_messages` to prove durable `MessageRecord` rows reconstruct the same batch after restart or
relay sync.

## Coverage gaps

Keep these aligned with [`README.md`](README.md), [`SCENARIOS.md`](SCENARIOS.md), and
[`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) when filling a gap.

- **`HarnessIntent` does not generate Invite / UpgradeCapabilities / UpdateGroupProfile.** It stays the small
  shrinkable send/leave strategy. `chat-journey/v1` generates legal invites and profile changes as canonical IR and
  relies on saved-input semantic reduction; upgrade lifecycle remains separate.
- **Partition policy is scripted, not strategy-driven.** Proptest drives FIFO / Reverse / SeededRandom only.
- **Storage-loss families are future work.** Generated coverage is broad but not exhaustive.
- **Welcome-joined members retain their own join commit** as a permanently deferred transport input. Latecomer arms
  scope their strict pending-work oracle to the founders and pin the joiner to exactly that retained artifact
  (`no_pending_work_except_retained_join_commit`) until that is resolved.
- **Stateful chat journeys serialize commits by construction.** Each commit is acknowledged and delivered before the
  next state-changing action, and restart is a terminal checkpoint. Mutation-after-reopen and concurrent/racing commit
  coverage remains owned by `convergence-chaos/v1`.
- **Admin-gated scripted steps need admin setup.** When an invitee later sends `InviteMembers` or `UpdateGroupData`,
  the runner promotes that invitee to an initial admin. Direct harness tests should use `create_group_with_admins`
  explicitly for competing admin commits.
- **Deadline-pinning virtual-time scenarios cannot become portable vectors yet.** A scenario whose contract is *which*
  tick settles a pass (see `open_convergence_pass_survives_restart_and_walks_the_backlog_to_the_tip`) must tick
  manually: `await_quiescence` settles a pass whenever it comes due and erases the evidence that a specific deadline
  fired. The oracle is not the blocker — `VirtualTimeAdvance` recommends `QuiescenceState` *or*
  `NoPendingWorkObserved` and coverage is any-of, so a `NoPendingWork` expectation discharges the stimulus under
  `--strict-oracle`. The multi-process subject is: `process_subject_descriptor` does not advertise
  `SubjectCapability::VirtualTime`, so preflight rejects `AdvanceTime` as `unsupported_subject_capability`, and
  `node_protocol` has no clock surface to move. Node deadlines would run on real elapsed time — fine for settling slack,
  wrong for landing on a boundary. Keep such scenarios in `tests/canonical_scenarios.rs` until the node protocol grows
  a virtual clock the process subject can honestly advertise.
- **Failure minimization is conservative.** No domain-specific shrinker yet; complete state-digest fingerprints remain
  diagnostic evidence.

## Conventions

- **Client labels seed deterministic Nostr keys.** `pad32(b"name")` is fine for stable test labels, but the engine
  identity attached to the bus is the derived public key. Use `HarnessClient::member_id()` for admin lists or other
  policy inputs.
- **Tracing audit is repo-wide.** `tests/tracing_audit.rs` scans production Rust source for `tracing::*` calls. New
  tracing must include explicit `target` and `method` fields and must not include account ids, group ids, message ids,
  relay URLs, pubkeys, payloads, ciphertext, plaintext, or key material.
- **The harness peeler is real; the relay is not.** `TransportBus` stays in memory, but group messages and Welcomes go
  through `transport-nostr-peeler`.
- **`HarnessClient` exposes only what tests need.** Needing the inner `Engine<S>` is a smell — extend the harness API
  instead and keep tests at one abstraction level.
- **App-runtime maintenance runs on real time unless the build says otherwise.** Own-leaf rotations wait out a
  60-second quiet window plus up to 30 seconds of jitter. `AppRuntimeHarness::new_with_immediate_maintenance` zeroes
  those windows through `MarmotAppConfig::with_dev_maintenance_timing`, honored only when this crate is built with
  `test-policy-overrides` (which also enables `marmot-app/test-policy-overrides`). Gate any journey that depends on it
  with `cfg_attr(not(feature = "test-policy-overrides"), ignore)` and check
  `AppRuntimeHarness::honors_maintenance_timing_override()` rather than assuming the knob took effect. That build also
  switches `AppRuntimeHarness::new()` to marmot-app's instant-settlement test default, so journeys that claim
  production settlement must use `new_with_pinned_settlement` or `new_with_immediate_maintenance` (both pin the
  1,000 ms window), and a recipe that enables the feature must select its tests explicitly rather than run the crate.

## Verification

```sh
cargo test -p cgka-conformance-simulator            # or: just conformance
just simulator-smoke                                # PR-lane selection
```

Add the narrowest gate that covers the change:

- Verification layers (reference model, lifecycle, mutation, route assurance, protocol decisions):
  `just convergence-verification-ci`.
- Adversarial catalog, policy sweeps, or `test-policy-overrides` behavior: `just adversarial-reliability-ci`.
- Family generators: the family's test file plus a strict file-backed report or campaign canary on a fresh `--out`.
- Policy cases: `cargo test -p cgka-conformance-simulator --test generated_policy_cases --test policy_case_tamarin_drift`.
- Convergence policy/resource/scheduler constants: `just convergence-ledger-gate`.
- Process/app adapters: the explicit ignored tests and commands named in [`tests/AGENTS.md`](tests/AGENTS.md).
