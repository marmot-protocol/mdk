# cgka-conformance-simulator

In-process multi-client simulator for the CGKA engine.

The engine crate proves local engine rules. This crate asks the bigger question: if several clients run that engine and
the network behaves badly, do they still end up with the same group state?

The simulator does not open real relay connections. Its fast engine adapter runs `Engine<SqliteAccountStorage>` clients
against a deterministic in-memory `TransportBus`; its retained-relay adapter persists independent per-relay histories
and drives engine mailboxes through explicit queries, cursors, EOSE, full backfill, and set reconciliation. In-memory
SQLite remains the default. Report runs select storage explicitly with
`--storage memory|file`; the flag overrides `MDK_CONFORMANCE_SQLITE_STORAGE` when both are present. File mode uses
temporary encrypted SQLite databases and a restart fully closes and reopens each client database before hydration.
Transport wrapping still goes through the real Nostr peeler, so group messages use the Marmot kind-445 envelope and
welcomes use NIP-59 gift wraps before the bus delivers them.

## What this crate gives you

- `TransportBus` — an in-memory message bus with seeded scheduling, partition support, broadcast and addressed
  delivery for welcomes, and replay hooks.
- `HarnessClient` — wraps `Engine<SqliteAccountStorage>` and the real Nostr transport peeler while keeping delivery in memory.
- `ConvergenceSubject` — a capability-declared semantic boundary between scenario execution and the implementation
  under test. `EngineHarnessSubject` is the in-process OpenMLS adapter. `ReferenceModelSubject` is an independent,
  symbolic-memory adapter for the common logical group/publication/application lifecycle; it deliberately does not
  advertise exact MLS projection or adversarial transport capabilities. Queue and partition mutation live on a separate,
  explicitly white-box fault interface. Its `virtual_time` capability advances one shared paired convergence clock;
  subsequent `tick` steps select which participant runtimes wake and observe the elapsed deadline. Its
  `outbound_publication` capability returns exact transport-ready artifacts through non-destructive polling and accepts
  typed `accepted` / `reached_no_endpoint` outcomes through opaque adapter-owned acknowledgement handles.
- `ScenarioSpec` — the canonical JSON v2 input contract for deterministic scripted scenarios, including explicit
  outbound acknowledgement, queue faults, and partitions. The runner compiles the whole document into a stable action
  schedule and preflights every required adapter capability before executing the first action; the schema is
  `schemas/scenario-ir.v2.schema.json`. New scenarios can declare accounts, devices, processes, groups, relays, roles,
  and binary/policy versions explicitly; old vectors receive a visible deterministic topology projection in reports.
- `ScenarioAuthoringSpec` — a non-executable authoring contract with deterministic repeat, logical parallel, rate,
  burst, and barrier lowering. See [`SCENARIO_IR.md`](SCENARIO_IR.md) for the exact schedule semantics.
- Semantic fault and assertion actions — select transport by stable meaning instead of queue position, declare
  offline/process/storage failures, and record bounded exactly/eventually/within/never/resource samples. Predicate
  sampling is passive and does not consume the event window retained for later report observations.
- `SubjectProgressSnapshot` and `await_quiescence` — a sanitized structural work/deadline contract plus a bounded
  virtual-time fixed-point driver. It accepts and delivers healthy-path transport according to explicit policy, advances
  exactly to the earliest subject wake, and records quiescent, blocked, or watchdog-timeout artifacts.
- `VectorFixture` — portable JSON fixtures pairing runnable scenario input with exact traces or semantic expected
  outcomes.
- `ScenarioReport` — serializable run artifacts with metadata, expected and observed traces, oracle coverage evidence,
  step logs, recoveries, and expectation failures.
- `FailureCapsuleV1` — a versioned failure artifact containing the scenario, expanded declared-time schedule, exact
  policy/constants, report/ledgers/state commitments, a bounded transport-evidence tail with truncation counters, and a
  stable failure fingerprint. Explicitly requested byte-exact replay is written to a separately named sensitive sibling
  capsule so the logical campaign capsule remains portable.
- `RetainedRelaySubject` — wraps the real engine subject but removes captured emissions from the packet bus and stores
  them per configured relay. It models publish fanout, unequal subscriptions, incremental/since/full/set queries, EOSE,
  reconnect, visibility omission, deterministic duplicate/order policy, and explicit history equalization. Every query
  records its completeness claim; quiet EOSE is never reported as proof of complete relevant history.
- `ConformanceGroupSnapshot` — a feature-gated synthetic-test projection of exact canonical group state: leaf identities
  and capabilities, required/application state, lifecycle/profile/admin state, a GroupContext hash, and the adopted
  domain-separated exporter commitment. Raw exporter material is never serialized.
- `cgka-conformance-simulator-report` — a small CLI that runs generated scenario families, writes JSON reports and
  failure capsules, emits fixture candidates for generated cases, and replays capsules that contain byte checkpoints.
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

# Milestone 3 catalog and small headline regressions.
cargo test -p cgka-conformance-simulator --test milestone3_campaigns

# Deliberately slow offline, mixed-traffic, and self-update campaigns.
cargo test -p cgka-conformance-simulator --test milestone3_campaigns \
  -- --ignored --nocapture

# Full generated adversarial catalog with durable report artifacts.
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family milestone3-adversarial/v1 --seed 7 --cases 12 \
  --out target/cgka-milestone3-reports --storage file --strict-oracle

# Run each adversarial case in its own process and add OS resource measurements.
cargo run -p cgka-conformance-simulator --bin cgka-conformance-campaign -- \
  --seed 7 --cases 12 --case-timeout-secs 300 \
  --out target/cgka-milestone3-process-campaign --storage file

# Test-only one-variable policy curves around fixed retained inputs/horizons.
cargo test -p cgka-conformance-simulator --features test-policy-overrides \
  --test policy_sweeps
```

Every `ScenarioReport` embeds `campaign_measurements` v1. Its convergence latency is the measured wall time of the
final successful `await_quiescence` action, or explicitly unavailable when the scenario does not request one;
queued-send blocking time starts only when an engine accepts a send as queued and ends at publication or terminal
refusal/rollback. Passes count observed convergence decisions across clients. Reorg count,
rewind depth, and lateness use the engine's diagnostic counters/histograms and survive harness restarts. Input
dispositions and logical delivery/expiry/invalidation come from the final per-client scenario ledger; queue depth is
the maximum sampled after scenario actions; replay probes are exact completed OpenMLS replay probes; database size is
the aggregate SQLite, WAL, and SHM footprint for file-backed subjects.

CPU time, peak RSS, and filesystem write blocks require process isolation and are therefore listed as unavailable in
an in-process report. `cgka-conformance-campaign` adds the fields the host exposes with one deadline-bounded worker
process per case and explicitly lists unavailable fields. `filesystem_block_write_lower_bound_bytes` is child
`rusage` block-write accounting across all files. It is explicitly a page-cache-sensitive lower bound and can remain
zero when writes are satisfied through cache; Darwin reports the field as unavailable. It is not a SQLite
logical-write counter. Generated artifacts are private-by-construction and belong under `target/` or another
ignored private location.

Policy sweeps are experiments, not configuration. They clone one retained symbolic input, hold current tip, anchor,
time, and every non-selected policy value fixed, then vary one constant and emit a curve plus named rejected boundary
values. The runner never writes a production policy. Pass-partition invariance is tested separately with the same
retained horizon; witness expiry, deferred-commit retirement, and retained-anchor pruning remain separately named
eligibility-boundary tests rather than being mixed into the scheduler comparison.

To run every portable vector fixture and write a report for each one:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --out target/cgka-conformance-simulator-reports \
  --storage file
```

The normal `cargo test -p cgka-conformance-simulator` run already validates the top-level vector fixtures and checks the
vector manifest / byte-fixture files through the default in-memory backend. CI additionally runs every portable vector
through encrypted file-backed storage. Use the report command when you want saved JSON reports and a human-readable
pass/fail summary outside the test harness.

The report command exits non-zero when any fixture expectation fails. Each report includes the exact scenario input,
selected subject adapter, declared capabilities, storage backend, observed trace, flattened recovery and epoch
observations, and the mismatched expected/actual JSON. A subject that lacks any capability required by a scenario is
rejected before the first scenario action executes.

Failed report runs also write a portable `*-failure-capsule.v1.json`. The capsule writer uses owner-only directories and
files. Sensitive SQLite/OpenMLS checkpoint capture is off by default because it contains key material and incurs a
checkpoint export. Pass `--capture-sensitive-replay` to capture only the final planned recipient tick and write a
separate `*-sensitive-replay-capsule.v1.json`; the portable logical capsule remains eligible for vector promotion.
Replay the sensitive sibling without regenerating MLS bytes with:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --replay-capsule /private/path/failure-capsule.v1.json
```

The replay succeeds only when the exact stored recipient state plus captured transport objects reproduce the recorded
engine fingerprint. Capsule v1's JSON Schema is `schemas/failure-capsule.v1.schema.json`.

## Exact state oracle

Legacy `observe_client` traces retain the portable epoch/member-count/group-name observation used by existing vectors.
Reliability scenarios call `observe_client_exact` (or use the serializable `observe_exact` step) and assert
`ClientsExactlyEquivalent` plus `ScenarioInputLedger`. The canonical-state expectation compares a tagged
`ConformanceCanonicalStateSnapshot`: either the complete live-group `ConformanceGroupSnapshot` or the authenticated
terminal disband tombstone. Equal member counts cannot hide different member identities, equal public metadata cannot
hide different exporter state, and device-local `local_was_committer_leaf` metadata cannot split otherwise equivalent
terminal clients. The engine interface is enabled only for this simulator through `test-conformance-snapshot`; it
exposes the commitment, never the raw exporter secret.

The scenario-input ledger gives every commit, proposal, and application action a stable scenario id, then joins it to
the outer transport id and content-derived MLS id; application entries also retain the inner Marmot event id for
delivery correlation. Per client it distinguishes send attempt/acceptance/queue/publication, protocol acceptance,
convergence deferral, transport deferral, application delivery, deduplication, expiry, invalidation, resource refusal,
rejection, and pending work. A convergence-deferred input has a current non-terminal protocol disposition and is not
counted as active work until later evidence opens another pass. In particular,
`TransportDeferred` remains pending but is not mislabeled as application acceptance: until peeling succeeds, the engine
cannot make a logical validity or branch claim about that object.

`NoPendingWork` is the strict instantaneous local-progress assertion. An `observe_exact` step captures group-scoped
engine work (publish lifecycle, convergence pass/input, queued outbound, deferred/retryable storage, and scheduling
buffers), bus queue/delayed/mailbox work addressed to that client, and that client's pending scenario-input ledger
entries. The expectation fails with the blocking subsystem names. It is deliberately not an end-to-end delivery claim
for an application object that a transport fault dropped; scenarios that require delivery must assert the recipient's
ledger or output separately. The serializable `advance_time` step advances the shared convergence clock without
sleeping or waking a participant; a later `tick` selects the awake runtimes and uses that same clock. Every engine
subject carries the deterministic manual clock, but only a scenario that executes `advance_time` switches `tick` to
that clock. Existing scenarios and standalone `HarnessClient` tests that never opt into virtual time retain the
historical far-future `tick` shortcut.

`EngineHarnessSubject::new` uses the only outbound lifecycle. Polling never removes work, identical repeated
acknowledgements are idempotent, and a contradictory acknowledgement fails. An accepted state-bearing commit confirms
the engine's pending state; a `reached_no_endpoint` result rolls back only while the complete publication remains
unexposed. Welcome outcomes remain independent after a live commit is accepted, and regenerated queued intents are
retired or re-armed from the same acknowledgement. A state transition with no transport artifacts is confirmed as a
no-op publication rather than inventing a synthetic artifact. ScenarioSpec v2 drives the same contract through
`acknowledge_outbound`: the runner polls opaque artifacts, optionally selects a stable scenario publication label and
artifact role, and applies the declared transport outcome. Engine-generated work has no publication label and can be
acknowledged as the client's current unresolved outbound set. There is no compatibility constructor, silent
auto-confirmation mode, or second subject publication capability. `ProtocolProfile::Legacy` is separate from that
removed lifecycle: it selects the engine's legacy application-profile compatibility through
`legacy_compatibility_profile()`, but it uses the same explicit outbound contract as `ProtocolProfile::Current`.
ScenarioSpec v1 is intentionally unsupported after the repository-owned v2 cutover and is rejected before any subject
action runs. `await_quiescence` composes structural-progress, virtual-time, and delivery capabilities. It additionally
requires outbound-publication capability when `policy.outbound` is `accept_all`; manual-publication scenarios retain
that work as a named blocker without requiring the capability. Its progress token is diagnostic only: success requires
no runnable work, future wake, deferred/retry work, publication acknowledgement, transport backlog, scenario-input
work, or terminal engine blocker. Explicit virtual-time activation prevents the legacy far-future harness tick from
bypassing virtual deadlines. Iteration, virtual-time, and work budgets produce serializable timeout evidence and never
redefine unfinished work as quiescent.

`probe_bidirectional_decryptability` is the active cryptographic-reachability check. Each named client sends one
uniquely identified application event through the normal engine and transport path; the runner delivers the resulting
objects, ticks every attached client, and records every directed sender-to-recipient edge. The
`ClientsBidirectionallyDecryptable` expectation requires every edge to reach application delivery and preserves queued,
failed, deferred, rejected, expired, and invalidated ledger evidence when it does not. The probe mutates the scenario by
sending application messages, so place it after the state whose decryptability is being tested.

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
portable scenario vectors for message exchange, pending rollback, invites, group-data updates, admin-policy
promotion/demotion (`vectors/admin-policy-update.v1.json`), queue faults, partition repair, leave, delayed past-epoch
app delivery, restart plus delayed duplicate delivery, and fork recovery. It does not yet have a full byte-level
wire-event suite.

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

`CommitOrderingKey` is derived from authenticated commit metadata first (source epoch, priority, committer) and uses
`SHA-256(mls_bytes)` only as the same-committer fallback. This keeps fork-recovery decisions transport-agnostic without
letting commit-byte grinding decide cross-member races. Portable scenario fixtures do not assert exact digest bytes,
because those bytes come from randomized MLS envelopes.

The first fork-recovery fixture is
[`vectors/group-data-fork-recovery.v1.json`](vectors/group-data-fork-recovery.v1.json). It models a same-epoch
group-data update race and asserts the semantic outcome: both clients reach epoch 2 with two members, one client
observes recovery from epoch 1 to epoch 2, and the winner and invalidated ordering keys are distinct.

`concurrent-invite-fork-recovery/v1` uses the same semantic recovery style for an invite race. It checks convergence and
recovery without pinning which invite branch wins.

`ScenarioSpec` v2 contains ordered client labels and ordered steps. Supported steps are:

- `create_group`
- `invite_members`
- `remove_members`
- `self_update`
- `update_group_data`
- `update_admin_policy`
- `expect_update_admin_policy_error`
- `observe_admin_policy`
- `acknowledge_outbound`
- `send_app_message`
- `leave`
- `deliver_all`
- `tick`
- `advance_time`
- `await_quiescence`
- `observe`
- `observe_exact`
- `probe_bidirectional_decryptability`
- `clear_events`
- `omit_message`
- `duplicate_message`
- `withhold_message`
- `release_withheld`
- `reorder_messages`
- `set_partition`
- `clear_partition`
- `restart_client`
- `set_client_offline`
- `reconnect_client`
- `sync_relay_history`
- `configure_relay`
- `set_relay_event_visibility`
- `reconcile_relay_histories`
- `crash_process`
- `restart_process`
- `inject_storage_fault`
- `clear_storage_fault`
- `barrier`
- `assert`

Staged publications are referenced by string labels chosen inside the scenario. `acknowledge_outbound.publication`
selects artifacts emitted by that operation; omitting it selects all currently unresolved artifacts for the client.
The optional `selection` further restricts the set to `all`, `state_confirmation`, `welcome`, `group_message`, or
`regenerated_queued_intent`. `outcome` is either `accepted` or `reached_no_endpoint`. A labelled acknowledgement fails
when no unresolved artifact matches, while an unlabelled acknowledgement is an idempotent drain and may match nothing.
`group_message` includes both application messages and proposals because both use the group-message transport envelope.
Proposal artifacts are engine-generated and have no scenario publication label, so scenarios select them with an
unlabelled `group_message` acknowledgement unless a future proposal action introduces labels. Client labels are stable
logical names;
the Rust harness maps them to deterministic Nostr keys so welcome routing and NIP-59 decryption exercise the same
identity shape as production. `reached_no_endpoint` represents a definite publication failure: it retracts all matching
undelivered commit/Welcome artifacts before local rollback and fails the scenario if any matching artifact has already
reached a recipient mailbox. Transport fault steps use conjunctive semantic selectors over stable action id,
publication label, sender, protocol class, and occurrence. `reorder_messages.order` selects every current message in
the desired order. `withhold_message` stores one selected message under a label, and `release_withheld` returns that
label's messages to the end of the transport schedule.

## Generated scenario families

`generate_send_leave_family(seed, cases)` produces deterministic `GeneratedScenarioCase` values (generator version
`2`). Each case records:

- `family_name`
- `generator_version`
- `seed`
- `case_index`
- `scenario`
- `expected_outcomes`

The generated `scenario` is a normal `ScenarioSpec`, so a selected generated case can be serialized into a fixed fixture
without inventing a separate execution path. We promote a case only when it should become a stable named contract, such
as a regression fixture or the smallest readable example of a semantic edge.

Send/leave and convergence-chaos reliability cases finish with a global transport/mailbox drain, an exact observation,
and a per-client `NoPendingWork` expectation. Multi-client settled claims also require `ClientsExactlyEquivalent`, and
delivery-sensitive cases assert recipient ledgers or outputs. These checks are intentionally capable of making a
generated campaign red even when its earlier legacy observation passed; that is how hidden unread input, branch
divergence, and retained work become visible.

`generate_convergence_e2e_delivery_family(seed, cases)` produces deterministic variants of
`convergence-e2e-group-events/v1`. Each variant keeps the logical branch race stable but mutates queued delivery with
duplicate, delay/release, and reorder steps before observer clients tick. Under the real Nostr peeler the settled
expectation is that observers agree on one canonical branch, which may be Bob's single-commit branch at epoch 2 or
Alice's deeper branch at epoch 3 depending on which messages are available before the settlement gate. In both cases the
trace includes exactly the selected branch application payload.

`generate_convergence_chaos_family(seed, cases)` produces deterministic adversarial convergence cases with built-in
semantic expectations. The generator rotates through invite forks, group-data forks, publish rollback plus delayed app
duplicates, partition/heal/leave, delayed past-epoch app delivery, stable duplicate/delay/reorder queue faults, 20+
client message storms, partitioned large-group delivery storms, multi-committer group-data storms, mixed large
message/commit storms, and restart plus duplicate delivery faults. Generator version `6` draws the delivery schedule of
the rollback and storm shapes from the seed, so distinct seeds exercise distinct adversarial orderings while the
schedule-invariant convergence, rollback, and payload-set expectations stay fixed. These cases are ordinary
`ScenarioSpec`s, so the same runner and report path can turn selected generated cases into fixed vectors when that makes
the conformance contract clearer.

## Report artifacts

`run_scenario_report(spec, expected_trace)` executes a scenario and returns a serializable `ScenarioReport` with:

- `metadata` — scenario name, spec version, step count, and optional generated case or fixture metadata.
- `scenario` — the exact scenario input that was executed.
- `expected_trace` — the trace being checked, when supplied.
- `expected_outcomes` — semantic fixture expectations, when supplied.
- `observed_trace` — the trace produced by the scenario runner.
- `oracle` — scenario stimuli, expected behavior classes, observed behavior classes, evidence counts, and weak-oracle
  warnings.
- `step_log` — one entry per attempted scenario step, including the first typed failure; later planned steps remain
  visible in a failure capsule's expanded schedule with no status.
- `pending_resolution_observations` — flattened publish confirmations and rollbacks.
- `recovery_observations` — flattened fork-recovery events from all client observations.
- `epoch_change_observations` — flattened `EpochChanged` events from all client observations.
- `app_invalidation_observations` — flattened app invalidation dispositions from all client observations.
- `expectation_failures` — exact-trace or semantic expectation mismatches with expected and actual JSON.
- `invariant_failures` — compatibility field mirroring expectation failures by kind and message.

`run_generated_case_report(case, expected_trace)` adds generated-family metadata: family name, generator version, seed,
case index, and an optional `minimized_case` field. Failing generated cases run a conservative greedy minimizer that
removes removable delivery/app steps only when the semantic failure identity (classification, action type, and failure
kind) still reproduces. The complete fingerprint, including the state digest, remains in the capsule for diagnosis.
Generated report runs also write
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
Report runs are strict by default: oracle coverage problems (`weak_oracle_warnings` or
`missing_observed_behaviors`) count as failures. `--strict-oracle` remains accepted for explicit scripts. Use
`--allow-weak-oracle` only for exploratory legacy or diagnostic runs where advisory coverage is intentional.

File-backed restart tests and the engine subprocess-kill tests cover durability when the encrypted database and WAL are
intact: handles are closed or the process is killed, the database is reopened, and hydration reconciles interrupted
convergence state. Recovery when required local records are genuinely missing or corrupted remains future work.

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
