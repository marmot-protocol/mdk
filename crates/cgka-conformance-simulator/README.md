# cgka-conformance-simulator

Multi-client conformance and convergence testing for the Marmot CGKA engine and the public Marmot app stack. The engine
crate proves local engine rules; this crate asks the bigger question: if several clients run that engine and the
network, processes, and storage behave badly, do they still end up with the same group state?

Read this if you change convergence behavior, add a regression scenario, want the portable vectors for another
implementation, or need to run or interpret a convergence campaign.

## Contents

- [How convergence is tested](#how-convergence-is-tested)
- [Testing layers](#testing-layers)
- [Execution adapters](#execution-adapters)
- [Run the tests](#run-the-tests)
- [Scenarios (Scenario IR)](#scenarios-scenario-ir)
- [Exact state and progress oracles](#exact-state-and-progress-oracles)
- [Vector fixtures](#vector-fixtures)
- [Generated scenario families](#generated-scenario-families)
- [Property tests](#property-tests)
- [Reports and failure artifacts](#reports-and-failure-artifacts)
- [Campaign measurements and policy sweeps](#campaign-measurements-and-policy-sweeps)
- [Library components](#library-components)
- [Where to put a new test](#where-to-put-a-new-test)
- [Known limits](#known-limits)
- [Further reading](#further-reading)

## How convergence is tested

Every convergence check follows the same path, whatever produced the input:

```text
 inputs                          compile                     execute                   judge
 ------                          -------                     -------                   -----
 scripted Rust scenarios ─┐
 portable JSON vectors   ─┼─> Scenario IR v2/v3 ──────> subject adapter ──────> trace, exact state, input
 seeded generated families┘   stable action ids,       engine / retained       ledger, pending work,
                              virtual-time schedule,   relay / app runtime /   decryptability probes
                              capability preflight     process / container           │
                                                                                     v
                                                     report, fixture candidate <── oracle + semantic
                                                     and failure capsule           expectations
```

- **Inputs.** Hand-written scenarios pin named regressions, portable [vector fixtures](#vector-fixtures) let other
  implementations run the same cases, and seeded [generated families](#generated-scenario-families) supply deterministic
  chaos: forks, partitions, storms, restarts, offline backlogs, and membership churn. [Property
  tests](#property-tests) drive the harness directly with many small generated inputs.
- **Compile.** Every scenario is canonical Scenario IR. The compiler assigns stable action ids, records the
  deterministic virtual-time schedule, and preflights every capability the scenario needs, so an adapter that cannot
  perform an action is rejected before action zero.
- **Execute.** The same IR runs on the cheapest adapter that can answer the question, from the in-memory engine bus up
  to separate processes, containers, and VMs.
- **Judge.** Reports compare observations against exact traces or semantic expectations and record oracle coverage.
  Runs are strict by default: a weak oracle fails the run. Failures leave a portable failure capsule and, for generated
  cases, a minimized reproducer.

Independent checks verify the verifiers: a production-independent reference model, a bounded lifecycle model mirrored
from TLA+, single-rule mutation adequacy, and a route-assurance inventory. The Tamarin model in
[`formal/tamarin`](../../formal/tamarin/) proves the abstract selector and lifecycle rules these tests exercise.

## Testing layers

| Layer | Files | What it catches |
| --- | --- | --- |
| Scenario registry | [`SCENARIOS.md`](SCENARIOS.md) | Human-readable setup, fault shape, and expected outcome for each scenario |
| Scripted scenarios | [`tests/canonical_scenarios.rs`](tests/canonical_scenarios.rs) | Known multi-client flows and named regressions |
| Vector fixtures | [`vectors/`](vectors/) | Portable conformance cases that other implementations can run |
| Generated families | [`src/family.rs`](src/family.rs) and sibling `*_family.rs`, report CLI | Seeded adversarial cases, report artifacts, fixture candidates |
| Oracle coverage | [`src/oracle.rs`](src/oracle.rs), report CLI | Which stimuli ran, which behaviors were expected, which were observed |
| Property tests | [`tests/proptest_invariants.rs`](tests/proptest_invariants.rs), [`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) | Invariants over many generated inputs |
| Replay probes | [`tests/openmls_replay_probe.rs`](tests/openmls_replay_probe.rs) | Byte-first OpenMLS replay and fixture materialization |
| Independent reference model | [`src/reference_convergence.rs`](src/reference_convergence.rs), [`tests/independent_reference_model.rs`](tests/independent_reference_model.rs) | Drift in authentication/authorization filtering, dependency closure, branch scoring, dispositions, and selector order |
| Lifecycle model checking | [`formal/liveness`](../../formal/liveness/), [`src/lifecycle_model.rs`](src/lifecycle_model.rs), [`tests/lifecycle_model.rs`](tests/lifecycle_model.rs) | Missing input-closure/fairness assumptions, frozen-pass loss across restart, unequal-history settlement, unrepaired resource failure, losing-branch joiner recovery |
| Mutation adequacy | [`src/mutation_adequacy.rs`](src/mutation_adequacy.rs), [`MUTATION_MATRIX.md`](MUTATION_MATRIX.md) | Verification layers that agree with production only because both omit or share the same faulty rule |
| Route assurance | [`src/route_assurance.rs`](src/route_assurance.rs), [`CONVERGENCE_ROUTE_MATRIX.md`](CONVERGENCE_ROUTE_MATRIX.md) | Production decision routes without independent model, mutation, or campaign ownership |
| Public app catalog | [`APP_SCENARIO_INVENTORY.md`](APP_SCENARIO_INVENTORY.md), [`APP_PATH_COVERAGE.md`](APP_PATH_COVERAGE.md) | Behavior visible only through the production app runtime, real relay, and encrypted roots |

## Execution adapters

An adapter (a `ConvergenceSubject`) declares a versioned capability set; the runner owns step semantics and stable
action ids. Use the smallest adapter whose capabilities can establish the claim;
[`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md#what-each-execution-layer-proves) lists what each layer does and does not
prove.

| Adapter | Selected by | What it is |
| --- | --- | --- |
| Engine (`EngineHarnessSubject`) | default; `--adapter engine` | `Engine<SqliteAccountStorage>` clients on a deterministic in-memory `TransportBus`. No sockets, but wrapping goes through the real Nostr peeler: group messages use the Marmot kind-445 envelope and Welcomes use NIP-59 gift wraps. Exposes exact MLS state, input ledgers, pending work, and active decryptability. |
| Retained relay (`RetainedRelaySubject`) | `--adapter retained-relay` | The real engine subject with independent per-relay durable histories instead of a packet bus. Mailboxes are driven by explicit queries, cursors, EOSE, full backfill, and set reconciliation. Offline recovery belongs here, not in a cleared packet-bus partition. |
| Reference model (`ReferenceModelSubject`) | Rust tests | Independent symbolic-memory adapter for the common logical group/publication/application lifecycle. It does not advertise exact MLS projection or adversarial transport capabilities. |
| App runtime (`app_runtime`) | `--adapter app-runtime` | Production app operations with one child process and encrypted database root per participant and a separate real local Nostr relay process. Processes share the host's CPU and memory. Public facts only. |
| Process orchestrator | `cgka-conformance-process` + `cgka-conformance-node` | One account-device per child process over the versioned JSONL node protocol, with private SQLCipher roots and restart. |
| Containers and VMs | [`convergence-campaign-runner`](../convergence-campaign-runner/) | Real sockets, network namespaces, network faults, mixed builds, and external VM drivers. |

Public app, process, and container projections cannot establish exact MLS-private state, durable input dispositions,
or active decryptability. Pair them with an engine-capable exact control when a claim needs those facts.

**Storage.** Engine clients use in-memory SQLite by default. Select storage with `--storage memory|file`; the flag
overrides `MDK_CONFORMANCE_SQLITE_STORAGE` when both are present. File mode uses temporary encrypted SQLite databases,
and a restart fully closes and reopens each client database before hydration.

## Run the tests

```sh
# Default: scripted scenarios plus normal property-test case counts.
cargo test -p cgka-conformance-simulator

# Slower validation: raises property-test case counts according to test cost.
cargo test -p cgka-conformance-simulator --features conformance-slow

# Adversarial reliability catalog and small headline regressions.
cargo test -p cgka-conformance-simulator --test adversarial_reliability_campaigns

# Deliberately slow offline, mixed-traffic, and self-update campaigns.
cargo test -p cgka-conformance-simulator --test adversarial_reliability_campaigns \
  -- --ignored --nocapture

# Test-only one-variable policy curves around fixed retained inputs/horizons.
cargo test -p cgka-conformance-simulator --features test-policy-overrides \
  --test policy_sweeps
```

`test-policy-overrides` also switches the app harness's default constructor to an instant-settlement test default, so
select tests explicitly under that feature rather than running the whole crate.

The `Justfile` wraps the CI lanes:

| Recipe | What it runs |
| --- | --- |
| `just conformance` / `just conformance-slow` | The whole crate under nextest, default or slow property-test counts |
| `just simulator-smoke` | PR-lane coverage without dedicated verification binaries or multi-minute generated batches |
| `just simulator-full` | Nightly generic coverage with `conformance-slow` |
| `just adversarial-reliability-ci` | Adversarial catalog, test-policy A/B, resource sweeps, and one isolated process-campaign case |
| `just convergence-verification-ci` | Route assurance, independent reference model, lifecycle model, mutation adequacy, protocol-decision gate, and TLA+ liveness |
| `just convergence-nightly-lane` / `just convergence-weekly-lane` | Scheduled lanes; weekly adds a four-case isolated campaign |
| `just cross-route-restart-campaign` / `just cross-route-exact-restart-campaign` | The twelve-case restart catalogs (seed, cases, and output root are arguments) |
| `just app-stack-campaign <out>` | Production-policy public app catalog, including explicitly ignored journeys |
| `just tracing-audit` | Repository-wide production tracing privacy audit |

### Report and campaign CLIs

```sh
# Full generated adversarial catalog with durable report artifacts.
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family adversarial-reliability/v1 --seed 7 --cases 12 \
  --out target/cgka-adversarial-reliability-reports --storage file --strict-oracle

# Run every portable vector fixture and write one report per fixture.
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --out target/cgka-conformance-simulator-reports --storage file

# Isolate any generated family case-by-case in deadline-bounded worker processes.
cargo run -p cgka-conformance-simulator --bin cgka-conformance-campaign -- \
  --family convergence-chaos/v1 --seed 42 --cases 22 --case-timeout-secs 300 \
  --out target/cgka-convergence-chaos-process-campaign --storage file
```

`cgka-conformance-simulator-report` runs in process. It defaults to `send-leave/v1`, seed 0, one case, and
`target/cgka-conformance-simulator-reports`, and exits non-zero when any expectation fails.

`cgka-conformance-campaign` defaults to `adversarial-reliability/v1`. The parent writes each exact generated input
before spawning its worker; workers write the same reports, fixture candidates, and portable failure capsules as the
report CLI, and the parent adds OS resource measurements. Repeat `--case-index N` to run selected cases only. The
campaign runner refuses to overwrite a prior summary, generated input, report, fixture, or failure capsule, so use a new
output directory for each run. The committed `adversarial-reliability-ci` and `convergence-weekly-lane` recipes remove
their fixed output directories first, so they stay rerunnable. Its summary records family, seed, storage mode, timeout,
sensitive-capture setting, per-case process measurements, and every artifact path. A normally exiting worker must leave
a parseable report whose generated metadata and source digest match the saved input, plus its fixture candidate;
otherwise `artifact_integrity_errors` fails the campaign. Cases are generated directly by index, so increasing
`--cases` keeps generation work linear.

The normal `cargo test` run already validates the top-level vector fixtures, the vector manifest, and byte-fixture files
through the in-memory backend; CI additionally runs every portable vector through encrypted file-backed storage. Use the
report command when you want saved JSON reports and a pass/fail summary outside the test harness.

[`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md) is the full operator manual.

## Scenarios (Scenario IR)

`ScenarioSpec` is the canonical JSON input contract for deterministic scripted scenarios. The schemas are
[`schemas/scenario-ir.v2.schema.json`](schemas/scenario-ir.v2.schema.json) and
[`schemas/scenario-ir.v3.schema.json`](schemas/scenario-ir.v3.schema.json); [`SCENARIO_IR.md`](SCENARIO_IR.md) holds the
exact semantics.

- **Versions.** V2 remains stable and replayable. V3 adds the actions listed below. ScenarioSpec v1 is unsupported
  after the repository-owned v2 cutover and is rejected before any subject action runs.
- **Topology.** New scenarios can declare accounts, devices, processes, groups, relays, roles, and binary/policy
  versions. Older client-only vectors receive a visible deterministic topology projection in reports.
- **Authoring.** `ScenarioAuthoringSpec` is a non-executable authoring layer with deterministic repeat, logical
  parallel, rate, burst, and barrier lowering into canonical IR
  ([`schemas/scenario-authoring.v1.schema.json`](schemas/scenario-authoring.v1.schema.json)). Adapters never interpret
  authoring control flow.
- **Client labels** are stable logical names. The Rust harness maps them to deterministic Nostr keys, so Welcome
  routing and NIP-59 decryption exercise the same identity shape as production.

### Actions

Both v2 and v3 support these actions (an `in_group` wrapper scopes a group action to a named scenario group):

| Purpose | Actions |
| --- | --- |
| Group operations | `create_group`, `invite_members`, `remove_members`, `self_update`, `update_group_data`, `update_admin_policy`, `expect_update_admin_policy_error`, `leave` |
| Publication and messaging | `acknowledge_outbound`, `send_app_message` |
| Delivery and time | `deliver_all`, `tick`, `advance_time`, `await_quiescence`, `barrier` |
| Observation and probes | `observe`, `observe_exact`, `observe_admin_policy`, `probe_bidirectional_decryptability`, `clear_events`, `assert` |
| Transport faults | `omit_message`, `duplicate_message`, `withhold_message`, `release_withheld`, `reorder_messages`, `set_partition`, `clear_partition` |
| Clients and relays | `restart_client`, `set_client_offline`, `reconnect_client`, `sync_relay_history`, `configure_relay`, `set_relay_event_visibility`, `reconcile_relay_histories` |
| Process and storage faults | `crash_process`, `restart_process`, `inject_storage_fault`, `clear_storage_fault` |

V3 adds:

- `update_group_profile` — optional `name` and `description`; omitted values are preserved and explicitly empty values
  clear. At least one field is required. Expectations can use `group_profile`; `clients_converged` also compares both
  profile fields.
- `expect_tick_error` — records a normalized, expected transport refusal and continues, so the same input can be
  replayed after a later prerequisite state transition.
- Real app-runtime stimuli: `interrupt_relay` (cuts live relay sockets for a real wall-time outage),
  `race_group_profiles` (2–8 clients release concurrent profile edits from a shared barrier), and `race_invite_profile`
  (an invite racing a rename, with an explicit rejoin offer). Adapters without the required capability refuse them
  before action zero.
- The `public_payload_multiset` assertion predicate, which compares one participant's complete visible public history,
  including multiplicity.

`assert` records bounded `exactly` / `eventually` / `within` / `never` / resource samples. Predicate sampling is passive
and does not consume the event window retained for later report observations.

### Transport faults and partitions

Transport fault steps select messages by stable meaning, not queue position: conjunctive selectors over stable action
id, publication label, sender, protocol class, and occurrence. `reorder_messages.order` selects every current message in
the desired order. `withhold_message` stores one selected message under a label, and `release_withheld` returns that
label's messages to the end of the transport schedule. Queue positions remain an internal bus-test detail.
`set_partition` restricts delivery to an allowed client set and `clear_partition` heals.

### Publication acknowledgement

Staged publications are referenced by string labels chosen inside the scenario.

- `acknowledge_outbound.publication` selects artifacts emitted by that operation. On an auto-publishing app adapter,
  the same label identifies the completed mutation whose command already returned successfully. Omitting the label
  selects all currently unresolved artifacts for adapters that expose them.
- The optional `selection` restricts an exposed artifact set to `all`, `state_confirmation`, `welcome`,
  `group_message`, or `regenerated_queued_intent`. `group_message` includes both application messages and proposals
  because both use the group-message envelope. Proposal artifacts are engine-generated and unlabelled, so scenarios
  select them with an unlabelled `group_message` acknowledgement.
- `outcome` is `accepted` or `reached_no_endpoint`. A labelled acknowledgement fails when neither an unresolved artifact
  nor an already-accepted named app mutation matches; an unlabelled acknowledgement is an idempotent drain and may
  match nothing.
- `reached_no_endpoint` is a definite publication failure. It retracts every matching undelivered commit and Welcome
  from the queue and delayed sets before local rollback, and fails the scenario if any matching artifact already
  reached a recipient mailbox. Model that case as ambiguous exposure at an adapter-aware boundary instead.

The engine subject has exactly one outbound lifecycle; there is no compatibility constructor or silent
auto-confirmation mode. Polling never removes work, identical repeated acknowledgements are idempotent, and a
contradictory acknowledgement fails. An accepted state-bearing commit confirms the engine's pending state; a
`reached_no_endpoint` result rolls back only while the complete publication remains unexposed. Welcome outcomes remain
independent after a live commit is accepted, and regenerated queued intents are retired or re-armed from the same
acknowledgement. A state transition with no transport artifacts is confirmed as a no-op publication rather than
inventing a synthetic artifact. Engine-generated work has no publication label and can be acknowledged as the client's
current unresolved outbound set.

Production-shaped app adapters publish inside their command surface instead of exposing transport artifacts. After a
successful named mutation they report its publication as already accepted, so the same accepted checkpoint can remain
in canonical IR, and they reject a later `reached_no_endpoint` because an accepted publication cannot be rolled back.

`ProtocolProfile::Legacy` is separate from that lifecycle: it selects the engine's legacy application-profile
compatibility through `legacy_compatibility_profile()` but uses the same explicit outbound contract as
`ProtocolProfile::Current`.

## Exact state and progress oracles

### Exact canonical state

Legacy `observe` traces keep the portable epoch/member-count/group-name observation used by existing vectors.
Reliability scenarios use `observe_exact` (or `observe_client_exact` in Rust) and assert `ClientsExactlyEquivalent` plus
the scenario-input ledger. The expectation compares a tagged `ConformanceCanonicalStateSnapshot`: either the complete
live-group `ConformanceGroupSnapshot` or the authenticated terminal disband tombstone. Equal member counts cannot hide
different member identities, equal public metadata cannot hide different exporter state, and device-local
`local_was_committer_leaf` metadata cannot split otherwise equivalent terminal clients. The engine interface is enabled
only for this simulator through the `test-conformance-snapshot` feature; it exposes a domain-separated exporter
commitment, never the raw exporter secret.

### Scenario-input ledger

The ledger gives every commit, proposal, and application action a stable scenario id, then joins it to the outer
transport id and the content-derived MLS id; application entries also keep the inner Marmot event id for delivery
correlation. Per client it distinguishes send attempt, acceptance, queue, and publication; protocol acceptance;
convergence deferral; transport deferral; application delivery; deduplication; expiry; invalidation; resource refusal;
rejection; and pending work. A convergence-deferred input has a current non-terminal protocol disposition and is not
counted as active work until later evidence opens another pass. `TransportDeferred` remains pending but is never
mislabeled as application acceptance: until peeling succeeds, the engine cannot make a validity or branch claim about
that object.

### Pending work and quiescence

`NoPendingWork` is the strict instantaneous local-progress assertion. An `observe_exact` step captures group-scoped
engine work (publish lifecycle, convergence pass/input, queued outbound, deferred/retryable storage, and scheduling
buffers), bus queue/delayed/mailbox work addressed to that client, and that client's pending ledger entries. A failure
names the blocking subsystems. It is deliberately not an end-to-end delivery claim for an application object that a
transport fault dropped; scenarios that require delivery must assert the recipient's ledger or output separately.

`advance_time` advances the shared paired convergence clock without sleeping or waking a participant; a later `tick`
selects the awake runtimes and uses that same clock. Every engine subject carries the deterministic manual clock, but
only a scenario that executes `advance_time` switches `tick` to it. Scenarios and standalone `HarnessClient` tests that
never opt into virtual time keep the historical far-future `tick` shortcut.

`await_quiescence` is a bounded virtual-time fixed-point driver. It composes the structural-progress, virtual-time, and
delivery capabilities, and also requires outbound publication when `policy.outbound` is `accept_all`; manual-publication
scenarios keep that work as a named blocker. It delivers healthy-path transport according to explicit policy and
advances exactly to the earliest subject wake. Success requires no runnable work, future wake, deferred/retry work,
publication acknowledgement, transport backlog, scenario-input work, or terminal engine blocker; its progress token is
diagnostic only. Iteration, virtual-time, and work budgets produce serializable quiescent, blocked, or watchdog-timeout
evidence and never redefine unfinished work as quiescent.

### Active decryptability

`probe_bidirectional_decryptability` is the active cryptographic-reachability check. Each named client sends one uniquely
identified application event through the normal engine and transport path; the runner delivers the resulting objects,
ticks every attached client, and records every directed sender-to-recipient edge. `ClientsBidirectionallyDecryptable`
requires every edge to reach application delivery and preserves queued, failed, deferred, rejected, expired, and
invalidated ledger evidence when one does not. The probe sends application messages, so place it after the state whose
decryptability is being tested.

## Vector fixtures

Portable fixtures live in [`vectors/`](vectors/), indexed by [`vectors/manifest.v1.json`](vectors/manifest.v1.json) and
described one by one in [`SCENARIOS.md`](SCENARIOS.md). Each file is a JSON `VectorFixture` envelope:

- `scenario_name` — stable logical scenario id, currently including `/v1`.
- `vector_version` — fixture schema version, currently `"1"`.
- `conformance_version` — `cgka-conformance-simulator` crate version that produced the fixture.
- `seed` — `null` for hand-authored deterministic scenarios.
- `scenario` — the input-side `ScenarioSpec` to execute.
- `expected_trace` — an exact `ScenarioTrace` for cases whose output is stable by construction.
- `expected_outcomes` — semantic checks for cases where randomized MLS bytes make exact trace comparison too brittle.

**For other implementations:** read the JSON file, run `scenario`, serialize the observed trace into the same shape, and
compare it with `expected_trace` or `expected_outcomes`. The trace intentionally avoids OpenMLS internals.

The portable set covers message exchange, pending rollback, invites, group-data and full group-profile updates,
admin-policy changes and handover, queue faults, partition repair, leave, delayed past-epoch delivery, restart with
delayed duplicates, fork recovery, convergence-decision selection, forward secrecy for latecomers and leavers,
multi-group isolation, and late Welcome backfill. Other directories:

- [`vectors/byte-fixtures/`](vectors/byte-fixtures/) — first app-component byte fixtures, following
  [`schema.v1.json`](vectors/byte-fixtures/schema.v1.json). There is not yet a full byte-level wire-event suite.
- [`vectors/incidents/`](vectors/incidents/) — vectors synthesized from Goggles forensic exports by
  [`incident-replay`](../incident-replay/) and verified against the simulator before commit.
- [`vectors/generated-inputs/`](vectors/generated-inputs/) — subject-pinned saved generated inputs, outside the manifest
  and `VectorFixture` discovery (see [saved generated inputs](#saved-generated-inputs-and-adapter-overrides)).

Vector-quality planning lives in
[`docs/marmot-architecture/overview/cgka-engine-quality-and-vectors.md`](../../docs/marmot-architecture/overview/cgka-engine-quality-and-vectors.md).

### Semantic fork-recovery vectors

`CommitOrderingKey` is derived from authenticated commit metadata first (source epoch, priority, committer) and uses
`SHA-256(mls_bytes)` only as the same-committer fallback. This keeps fork-recovery decisions transport-agnostic without
letting commit-byte grinding decide cross-member races. Portable fixtures do not assert exact digest bytes, because
those come from randomized MLS envelopes.

[`vectors/group-data-fork-recovery.v1.json`](vectors/group-data-fork-recovery.v1.json) models a same-epoch group-data
race and asserts the semantic outcome: both clients reach epoch 2 with two members, one client observes recovery from
epoch 1 to epoch 2, and the winner and invalidated ordering keys are distinct. `concurrent-invite-fork-recovery/v1` uses
the same style for an invite race and checks convergence without pinning which branch wins.

### The convergence E2E bridge

`convergence-e2e-group-events/v1` stays an in-tree bridge scenario rather than a portable fixture. Raw harness messages
enter through the Nostr peeler and `ingest`, the convergence engine selects one same-epoch branch, and the trace records
the selected epoch/member additions plus the canonical branch application payload. Delayed past-epoch application
messages are peeled from a retained epoch context and emitted once. Future-epoch branch messages that the outer peeler
cannot unwrap yet are stored as raw transport bytes; after canonical branch selection advances the MLS context, the
engine retries them and emits only the payloads that decrypt on the selected branch.

## Generated scenario families

A generated family turns `(seed, case_index)` into an ordinary `ScenarioSpec` plus semantic expectations. A case's
stable identity is `(family_name, generator_version, seed, case_index)`. `--cases` is a count of independent indices,
not a complexity dial: increasing it never changes an existing case, and `--seed` changes the deterministic choices
within each case. Because a generated case is a normal `ScenarioSpec`, a selected case can become a fixed fixture
without a separate execution path; promote one only when it should be a stable named contract, such as a regression or
the smallest readable example of a semantic edge.

| Family | What it varies |
| --- | --- |
| `send-leave/v1` | Small membership/application lifecycle (generator version 2) |
| `convergence-e2e-delivery/v1` | Duplicate, delay/release, and reorder noise over the convergence E2E bridge |
| `convergence-chaos/v1` | Eleven adversarial arms: forks, rollback, partitions, storms, restarts, delayed messages |
| `admin-churn/v1` | Sequential churn, competing admin-policy commits, restart between publish and delivery, latecomers under commit pressure |
| `adversarial-reliability/v1` | Named real-world and resource-pressure workload catalog |
| `bounded-convergence-pressure/v1` | Finite pressure on the unified fork-resolution route under a bounded quiescence contract |
| `large-group-pressure/v1` | 10–200 members with explicit admin population, committer width, traffic, formation, and disruption |
| `offline-catchup-pressure/v1` | A founding member returns only after a retained 24–1,024-message backlog plus commit pressure |
| `membership-reentry/v1` | Single/repeated removal and fresh-Welcome re-entry with restart, self-update, self-leave, and stale Welcomes |
| `chat-journey/v1` | Legality-aware product journeys over membership, admins, profile, traffic, offline repair, and restart |
| `cross-route-restart-permutations/v1` | Twelve public app-runtime restart boundaries in the four-party cross-route scenario |
| `cross-route-exact-restart-permutations/v1` | Exact/private engine companion to the public restart catalog |
| `public-app-*/v1` | Public app-runtime families; see [`APP_SCENARIO_INVENTORY.md`](APP_SCENARIO_INVENTORY.md#generated-families) |

[`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md#choosing-a-generated-family) explains how to choose one and how
`large-group-pressure/v1` size blocks map to case indices. [`SCENARIOS.md`](SCENARIOS.md#generated-scenario-families)
describes each arm.

Run any family through the report CLI:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --family chat-journey/v1 --seed 42 --cases 10 \
  --out target/chat-journey-reports --storage file --strict-oracle
```

### Strict terminal oracles

Send/leave and convergence-chaos reliability cases finish with a global transport/mailbox drain, an exact observation,
and a per-client `NoPendingWork` expectation. Multi-client settled claims also require `ClientsExactlyEquivalent`, and
delivery-sensitive cases assert recipient ledgers or outputs. These checks can turn a generated campaign red even when
an earlier legacy observation passed; that is how hidden unread input, branch divergence, and retained work become
visible.

### Family notes

- **`convergence-e2e-delivery/v1`** keeps the logical branch race of `convergence-e2e-group-events/v1` stable but
  mutates queued delivery before observer clients tick. Observers must agree on one canonical branch — Bob's
  single-commit branch at epoch 2 or Alice's deeper branch at epoch 3, depending on which messages arrive before the
  settlement gate — and the trace includes exactly the selected branch's application payload.
- **`convergence-chaos/v1`** rotates through invite forks, group-data forks, publish rollback plus delayed app
  duplicates, partition/heal/leave, delayed past-epoch app delivery, stable duplicate/delay/reorder queue faults, 20+
  client message storms, partitioned large-group storms, multi-committer group-data storms, mixed message/commit storms,
  and restart plus duplicate delivery. Generator version 6 draws the delivery schedule of the rollback and storm arms
  (2 and 6–9) from the seed, so distinct seeds exercise distinct orderings while the schedule-invariant convergence,
  rollback, and payload-set expectations stay fixed.
- **`bounded-convergence-pressure/v1`** is the finite-pressure acceptance campaign for the unified fork-resolution
  route: a same-epoch commit race, application sends inside the quiescence window, a committer restart mid-resolution,
  and a bounded self-update/profile/admin tail. Controlled virtual time starts before the race, so every later settle is
  `await_quiescence` and the watchdog budget is the bounded-time assertion. It claims nothing about progress under
  unbounded self-updates.
- **`chat-journey/v1`** tracks membership, administrators, connectivity, epoch, group profile, and per-client delivery
  in a symbolic model. Adjacent indices alternate between late-membership journeys on the engine subject and
  retained-history offline journeys whose offline participants were members from epoch 1. The split is deliberate: a
  late joiner querying full history sees valid pre-admission objects it was never entitled to decrypt, so combining the
  shapes would make a global no-pending assertion a false protocol guarantee. Every case covers application traffic and
  a profile update; the corpus also rotates invites, removals, admin changes, self-updates, restarts, and reconnect
  repair. Terminal expectations pin epoch, roster size, profile, admin set, per-client delivery, exact state, and active
  decryptability. Membership cases scope `NoPendingWork` to founding members; retained-history cases require it for
  every surviving member plus global quiescence.
- **`offline-catchup-pressure/v1`** reproduces the production symptom where a founding member is offline for nearly the
  whole scenario and then processes a large retained history. Cost-ordered blocks contain 24, 96, 384, and 1,024
  application messages interleaved with epoch commits. Six arms vary natural versus reverse history, reverse
  three-copy replay, natural two-copy incremental plus full repair, reverse two-copy restart before backlog processing,
  and reverse three-copy competing commit waves. Terminal expectations require Bob's exact payload multiset, exact
  canonical equality, no pending work, and a post-recovery decryptability probe. Capacity-refused retained objects remain
  a subject-owned redelivery obligation: later assertion ticks re-query complete history after engine progress frees
  capacity, while a truly full/no-progress loop ends with a typed resource failure.

### Cross-route restart catalogs

The fixed `cross-route-retained-history-recovery/v1` saved input pins the retained-relay adapter and the semantic oracle
for the four-party cross-route regression:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --generated-input \
  crates/cgka-conformance-simulator/vectors/generated-inputs/cross-route-retained-history-recovery.generated-input.json \
  --out target/cross-route-retained-history --storage file --strict-oracle
```

That command enforces the saved input's portable state, recovery, profile, pending-work, and decryptability outcomes.
The `cross_route_recovery_uses_retained_history_after_restart` Rust regression additionally owns the
accepted/invalidated/accepted commit-disposition subset and exact retained-sync injection observations, which have no
portable expectation.

`cross-route-restart-permutations/v1` applies the same four-party topology to a twelve-case restart catalog. It reopens
the durable author/consumer after accepted create, admin-policy, and competing profile transitions; after the branch
witness and branch ingestion; and each participant after retained-history repair. Twelve consecutive indices cover the
catalog exactly once; the seed rotates the order for deterministic sharding. Each case runs through the full
app-runtime adapter with a strict public epoch/roster/profile/admin-policy oracle and an order-insensitive exact payload
multiset. The exact retained-engine form is a separate family so a panic-shaped private-state failure cannot stop later
cases:

```sh
just cross-route-restart-campaign 0 12 target/cross-route-restart-seed-0
just cross-route-exact-restart-campaign 0 12 target/cross-route-exact-restart-seed-0

# Isolated-process adapter catalog.
cargo test -p cgka-conformance-simulator --test process_orchestrator --locked -- \
  --ignored four_party_cross_route_process_restart_permutations_match_unified_route
```

The builder names relay-visibility boundaries by publication (`zeta-root` and `alpha-root`) and resolves them to stable
action ids only after inserting a restart, so a shifted schedule cannot silently retarget or disable the branch
topology. Public and exact artifacts carry distinct scenario-name prefixes so every result stays attributable to the
subject and oracle that produced it.

### Saved generated inputs and adapter overrides

For every generated family the report runner writes an owner-only, versioned `*-generated-input.json` before executing
the case. It preserves the full case, including its selected subject adapter and semantic expectations, so a crash or
panic cannot erase the exact executable input. Replay one with `--generated-input FILE`.

Add `--adapter engine|retained-relay|app-runtime` to run the embedded canonical IR through a different in-process
adapter; capability preflight still rejects unsupported operations before action zero. Reports keep the producer's
family name, generator version, seed, case index, and subject provenance plus separate SHA-256 digests of the envelope
bytes and of the canonical IR inside it. An override adds the executing adapter to report and capsule filenames so A/B
runs cannot overwrite one another, and it never mints a promotable vector candidate: only the generator-recorded subject
supplies that adapter-neutral fixture.

The process adapter accepts the same saved input in place of a raw Scenario IR file:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-process -- \
  target/cgka-conformance-simulator-reports/chat-journey-v1-seed-42-case-0-generated-input.json \
  target/debug/cgka-conformance-node \
  target/chat-journey-process-report.json
```

Its report keeps the same provenance and the semantic expectations for downstream oracle tooling, but the process
executor does not evaluate them itself; it records the digest of the IR it compiled.
`cgka-conformance-process --validate-cross-route <input.json> <report.json>` checks saved process evidence against the
strict cross-route oracle without executing a workload. Container and VM manifests in
[`convergence-campaign-runner`](../convergence-campaign-runner/) use the same envelope: containers resolve it in memory
and may apply deterministic manifest-declared host-crash lowering; VM runs privately materialize the selected canonical
IR before launching the external driver.

## Property tests

Property tests live in [`tests/proptest_invariants.rs`](tests/proptest_invariants.rs);
[`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) is the human registry. They generate many small inputs and assert rules that
must hold for every shape: candidate selection order-invariance, canonicalization disposition order-invariance,
canonicalization replay idempotence, quiescence gating, capability negotiation, send/leave convergence, varied delivery
convergence, same-message replay, restart equivalence for stored convergence input, upgrade publish confirm/fail, and
group-data update publish confirm/fail.

Cheap symbolic properties run more cases. Harness-heavy properties use smaller default counts and larger
`conformance-slow` counts.

## Reports and failure artifacts

### Scenario reports

`run_scenario_report(spec, expected_trace)` returns a serializable `ScenarioReport`:

- `metadata` — scenario name, spec version, step count, and optional generated-case or fixture metadata.
- `scenario` — the exact scenario input that was executed.
- `expected_trace` / `expected_outcomes` — the exact trace or semantic expectations being checked, when supplied.
- `observed_trace` — the trace produced by the runner.
- `oracle` — scenario stimuli, expected and observed behavior classes, evidence counts, and weak-oracle warnings.
- `step_log` — one entry per attempted step, including the first typed failure; later planned steps stay visible in a
  failure capsule's expanded schedule with no status.
- `pending_resolution_observations`, `recovery_observations`, `epoch_change_observations`,
  `app_invalidation_observations` — flattened publish confirmations/rollbacks, fork recoveries, `EpochChanged` events,
  and app invalidation dispositions from all clients.
- `expectation_failures` — exact-trace or semantic mismatches with expected and actual JSON.
- `invariant_failures` — compatibility field mirroring expectation failures by kind and message.
- `campaign_measurements` — see [campaign measurements](#campaign-measurements-and-policy-sweeps).

Reports also record the selected subject adapter, declared capabilities, and storage backend. A subject that lacks a
capability required by a scenario is rejected before the first action executes.

Report runs are strict by default: oracle coverage problems (`weak_oracle_warnings` or `missing_observed_behaviors`)
count as failures. `--strict-oracle` remains accepted for explicit scripts. Use `--allow-weak-oracle` only for
exploratory legacy or diagnostic runs where advisory coverage is intentional.

Reports are written one file per case, for example
`target/cgka-conformance-simulator-reports/send-leave-v1-seed-42-case-0.json`.

### Fixture candidates and minimization

Generated report runs on the generator-recorded subject also write a sibling `*-fixture.v1.json` candidate, for example
`convergence-chaos-v1-seed-42-case-0-fixture.v1.json`. Cases with semantic expectations keep them; cases without them
use the observed trace as an exact expected trace. Candidates always preserve the original executed scenario and need
review before promotion into `vectors/`.

`run_generated_case_report(case, expected_trace)` adds family name, generator version, seed, case index, minimization
status, and an optional `minimized_case`. A failing generated case runs a conservative greedy reducer that removes
application-message, transport-fault, and partition steps — keeping each fault paired with its recovery step — only
while the semantic failure identity (classification, action type, and failure kind) still reproduces. The reducer may
change the terminal state digest, so `minimized_case` is diagnostic evidence, not a faithful fixture for the original
observation; the complete fingerprint stays in the capsule. There is no domain-specific shrinker.

Reports, fixture candidates, and capsules are written before reduction starts; completed minimization metadata replaces
them atomically, so interruption leaves a complete original artifact. The process campaign removes replacement
temporaries owned by a reaped worker and records cleanup failures as artifact-integrity errors. Status is `complete`,
`budget_exhausted`, `not_reproducible`, or `skipped`; a durable `pending` status identifies a worker interrupted during
reduction. Reduction defaults to a 30-second wall-clock budget, 256 reproduction trials, and five seconds per trial;
override with `--minimization-wall-time-secs`, `--minimization-max-trials`, and `--minimization-trial-timeout-secs`.
Budget exhaustion never changes the original failure classification.

### Failure capsules

Failed report runs write a portable `*-failure-capsule.v1.json` (`FailureCapsuleV1`, schema
[`schemas/failure-capsule.v1.schema.json`](schemas/failure-capsule.v1.schema.json)). It contains the scenario, the
expanded declared-time schedule, exact policy/constants, report/ledgers/state commitments, a bounded transport-evidence
tail with truncation counters, and a stable failure fingerprint. The writer uses owner-only directories and files.

Sensitive SQLite/OpenMLS checkpoint capture is off by default because it contains key material and costs a checkpoint
export. `--capture-sensitive-replay` captures only the final planned recipient tick and writes a separate
`*-sensitive-replay-capsule.v1.json`; the portable logical capsule stays eligible for vector promotion. Keep sensitive
capsules private and never commit them. Replay one without regenerating MLS bytes:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --replay-capsule /private/path/failure-capsule.v1.json
```

Replay succeeds only when the stored recipient state plus captured transport objects reproduce the recorded engine
fingerprint.

## Campaign measurements and policy sweeps

Every `ScenarioReport` embeds `campaign_measurements` v1:

- **Convergence latency** is the wall time of the final successful `await_quiescence` action, or explicitly unavailable
  when the scenario requests none.
- **Queued-send blocking time** starts when an engine accepts a send as queued and ends at publication or terminal
  refusal/rollback.
- **Passes** count observed convergence decisions across clients. Reorg count, rewind depth, and lateness use the
  engine's diagnostic counters/histograms and survive harness restarts.
- **Policy pressure** — deferred-peel sweeps, row/group-byte/account-byte capacity refusals, and row/byte high-water
  marks — is aggregate, carries no identifiers or payloads, and survives harness restarts.
- **Input dispositions** and logical delivery/expiry/invalidation come from the final per-client ledger; queue depth is
  the maximum sampled after scenario actions; replay probes are completed OpenMLS replay probes; database size is the
  aggregate SQLite, WAL, and SHM footprint for file-backed subjects.

CPU time, peak RSS, and filesystem write blocks require process isolation and are listed as unavailable in an
in-process report; `cgka-conformance-campaign` fills in the fields the host exposes and lists the rest as unavailable.
`filesystem_block_write_lower_bound_bytes` is child `rusage` block-write accounting across all files: a
page-cache-sensitive lower bound that can stay zero when writes hit cache, unavailable on Darwin, and not a SQLite
logical-write counter. Generated artifacts are private-by-construction and belong under `target/` or another ignored
private location.

Policy sweeps (`--features test-policy-overrides --test policy_sweeps`) are experiments, not configuration. They clone
one retained symbolic input, hold current tip, anchor, time, and every non-selected policy value fixed, then vary one
constant and emit a curve plus named rejected boundary values. The runner never writes a production policy.
Pass-partition invariance is tested separately with the same retained horizon; witness expiry, deferred-commit
retirement, and retained-anchor pruning stay separately named eligibility-boundary tests.

## Library components

The main public types, for writing tests against the crate:

- `TransportBus` — in-memory bus with seeded scheduling, partitions, broadcast and addressed Welcome delivery, and replay
  hooks.
- `HarnessClient` — wraps `Engine<SqliteAccountStorage>` and the real Nostr transport peeler while keeping delivery in
  memory.
- `ConvergenceSubject` — the capability-declared boundary between scenario execution and the implementation under
  test; `EngineHarnessSubject`, `RetainedRelaySubject`, and `ReferenceModelSubject` implement it. Queue and partition
  mutation live on the separate, explicitly white-box `ConvergenceFaultSubject`. The `virtual_time` capability advances
  one shared paired clock; the `outbound_publication` capability returns transport-ready artifacts through
  non-destructive polling and accepts typed `accepted` / `reached_no_endpoint` outcomes through opaque adapter-owned
  handles.
- `ScenarioSpec`, `ScenarioAuthoringSpec`, `VectorFixture`, `ScenarioReport`, `FailureCapsuleV1` — the input, fixture,
  report, and failure contracts described above.
- `SubjectProgressSnapshot` and `await_quiescence` — sanitized structural work/deadline contract and the bounded
  fixed-point driver.
- `ConformanceGroupSnapshot` — feature-gated synthetic-test projection of exact canonical group state: leaf identities
  and capabilities, required/application state, lifecycle/profile/admin state, a GroupContext hash, and the adopted
  domain-separated exporter commitment. Raw exporter material is never serialized.
- `proptest_support` — strategies for arbitrary typed `SendIntent` sequences.
- `reference_convergence` — a small serializable convergence oracle with its own policy, candidate, score, dependency,
  authorization, and disposition types and no production engine imports. Bounded corpus and proptest adapters compare
  it to the production selector/canonicalizer; the Scenario IR lifecycle comparison reaches the full OpenMLS engine
  subject. `WitnessMode::Disabled` measures the app-witness rule's marginal effect without rewriting policy constants.
- `lifecycle_model` — the bounded Rust/Stateright mirror of the authoritative TLA+ lifecycle specification. It keeps
  model action identities, separates durable frozen revision from crash-lost volatile staged revision, exercises unequal
  histories, freeze/settle, crash/restart, temporary resource failure, administrative progress, and losing-branch joiner
  repair, and emits a minimal assumption-labeled starvation trace whose action kinds are drift-checked against committed
  Scenario IR.
- `mutation_adequacy` — eleven simulator-only single-rule mutants with minimal deterministic witnesses, covering
  selector order, witness dedup/admission, cutoff, frozen state, scheduler re-arm, invalidation, publication ack,
  retention boundary, group-profile projection, and provisional-winner terminalization, without compiling mutation
  switches into production. Lifecycle mutants run through the shared Rust transition model; publication
  acknowledgement runs through an independent reference subject; the profile mutant runs the production-shaped engine
  vector and changes only its app-facing projection.
- `route_assurance` — machine-readable inventory of every production decision route and its independent model,
  mutation, and campaign ownership. Partial coverage and gaps stay explicit, and a green campaign cannot silently close
  a recorded counterexample. The human mirror is [`CONVERGENCE_ROUTE_MATRIX.md`](CONVERGENCE_ROUTE_MATRIX.md).

Binaries: `cgka-conformance-simulator-report` (in-process reports, vectors, capsule replay), `cgka-conformance-campaign`
(isolated per-case workers), `cgka-conformance-process` and `cgka-conformance-node` (multi-process orchestrator and
participant), `cgka-conformance-app-inventory` (enumerate existing generated cases for `--adapter app-runtime` replay),
and `cgka-policy-casegen` (bounded policy cases shared with Tamarin; `just policy-casegen`).

## Where to put a new test

| Question | Where |
| --- | --- |
| Does this single engine method behave correctly? | `crates/cgka-engine/tests/*.rs` |
| Do N engines converge under FIFO delivery? | [`tests/canonical_scenarios.rs`](tests/canonical_scenarios.rs) |
| Does this hold for _any_ sequence of N intents? | [`tests/proptest_invariants.rs`](tests/proptest_invariants.rs) |
| What happens under reorder, partition, or replay? | A new scripted scenario; extend the proptest strategies once the case is concrete |
| Can another implementation reproduce this behavior? | A JSON fixture in [`vectors/`](vectors/) |
| Does it hold through the real app runtime and relay? | The public app journeys and families in [`APP_SCENARIO_INVENTORY.md`](APP_SCENARIO_INVENTORY.md) |
| Do generated scenarios produce useful artifacts? | Run `cgka-conformance-simulator-report --family ...` |

[`AGENTS.md`](AGENTS.md) has the code map and step-by-step instructions for adding scenarios, vectors, and properties.

## Known limits

- File-backed restart tests and the engine subprocess-kill tests cover durability when the encrypted database and WAL
  are intact: handles are closed or the process is killed, the database is reopened, and hydration reconciles
  interrupted convergence state. Recovery when required local records are genuinely missing or corrupted is future
  work.
- Scenarios whose contract is *which* tick settles a pass cannot become portable vectors yet: the multi-process subject
  has no virtual clock. They stay in `tests/canonical_scenarios.rs`.
- **Public runtime history-repair observations.** The app/process adapter records a repair that stops only because
  exhaustive coverage is unproven, or that searched only the retained window, in
  `local.history_repairs_without_coverage`; the standalone node adapter uses the same classifier and records
  `progress.history_repairs_without_coverage`. The scenario action can then continue to its independent delivery,
  membership, and public-state assertions. The counter never certifies history or clears runtime debt, and the private
  process RPC preserves the typed outcome. Delivery loss, cancellation, deadline, and other failures remain scenario
  failures. The retained-relay model differs: it can provide its own explicit completeness evidence for a finite query.

## Further reading

- [`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md) — operator manual: vectors, generated cases, saved-input replay,
  app/process adapters, containers, VMs, artifacts, and failure handling.
- [`SCALING_CAMPAIGNS.md`](SCALING_CAMPAIGNS.md) — sharding thousands of cases, choosing execution layers, retaining
  evidence, and adding high-value workload families.
- [`SCENARIO_IR.md`](SCENARIO_IR.md) — canonical scenario and authoring contracts.
- [`SCENARIOS.md`](SCENARIOS.md) — fixed and generated scenario registry.
- [`PROPERTY_TESTS.md`](PROPERTY_TESTS.md) — property-test registry.
- [`APP_SCENARIO_INVENTORY.md`](APP_SCENARIO_INVENTORY.md) — public app families, fixed journeys, process layout, slow
  gates, and recorded validation boundaries.
- [`APP_PATH_COVERAGE.md`](APP_PATH_COVERAGE.md) — basic public-runtime acceptance tests and the large offline catch-up
  gate.
- [`MUTATION_MATRIX.md`](MUTATION_MATRIX.md), [`CONVERGENCE_ROUTE_MATRIX.md`](CONVERGENCE_ROUTE_MATRIX.md),
  [`PROTOCOL_DECISIONS.md`](PROTOCOL_DECISIONS.md) — verification matrices and adopted protocol decisions.
- [`docs/marmot-architecture/convergence-reliability-plan.md`](../../docs/marmot-architecture/convergence-reliability-plan.md)
  — the convergence reliability plan these tools serve.
