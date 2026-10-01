# AGENTS.md - crates/cgka-conformance-simulator/tests

Map for simulator tests.

Read `../RUNNING_CAMPAIGNS.md` for the supported operator entrypoints and `../SCALING_CAMPAIGNS.md` for the required
determinism, reachability, interaction-coverage, and promotion checks when adding generated coverage.

## Files

- **File:** `app_history_repair_diagnostic.rs`
  - **Owns:** Explicit saved-input prefix diagnosis through large-app action 254, aggregate drain verdicts,
    exact saved app recovery capture with optional post-failure probes, and retained private fixtures.
    Prefix success or successful diagnostic capture is not full-family acceptance; inspect the saved report verdict.

- **File:** `app_large_group.rs`
  - **Owns:** Public 10/20/50-member bulk/staged family contracts, whole-history assertion validation,
    exclusion-delivery-before-reinvitation regression, and explicit production-policy scale canaries.

- **File:** `support/offline_catchup.rs`
  - **Owns:** Compact reconstruction of the exact checkpoint 368/1,024-message inputs. Pinned SHA-256 values
    cover serialized metadata, actions and expected outcomes; compare against checkpoint `9282a643` before
    intentionally changing these workloads. Shared by engine regressions and public app journeys.

- **File:** `public_app_families.rs`
  - **Owns:** Seeded public send/leave, membership re-entry, admin handoff and small offline recovery family contracts,
    capability preflight, interaction coverage, and explicit real-socket strict oracle canaries.

- **File:** `app_runtime_journeys.rs`
  - **Owns:** Basic public app acceptance journeys and the explicit slow 1,024-message public catch-up gates,
    including the extra-epoch released-object replay regression (#1721),
    also selected by the dedicated required public recovery CI job with production policy.
    Real local relay, SQLCipher roots, exact public payload/state checks, post-change messaging, and restart
    persistence. See `../APP_PATH_COVERAGE.md` for replay and evidence commands.
    `support/recovery_scorecard.rs` holds the report-only large-account recovery scorecard: it asserts
    recovery correctness only and records latency, per-relay traffic and idle downloads in `scorecard.json`.

- **File:** `app_runtime_interaction_journeys.rs`
  - **Owns:** Public app interaction journeys that the serialized generated families do not reach: two groups on
    one device with a removal and reopen, two admins editing different profile fields at the same instant, a
    concurrent invite plus rename, a member removed while its device is closed, a voluntary leave with three
    remaining auto-committers, and the explicit slow manual self-update. Same harness and evidence layout as `app_runtime_journeys.rs`; see `../APP_PATH_COVERAGE.md`.

- **File:** `adversarial_reliability_campaigns.rs`
  - **Owns:** `adversarial-reliability/v1` catalog coverage, small headline regressions, and the ignored sustained,
    offline-flood, and self-update campaigns run by `just adversarial-reliability-ci`.

- **File:** `app_generated_variance.rs`
  - **Owns:** Public app family seed diversity, measured after removing labels, actors, and payload text.

- **File:** `app_recovery_expansion.rs`
  - **Owns:** Cheap contracts for the opt-in process-backed recovery workloads (`../APP_RECOVERY_EXPANSION.md`):
    replay/prefix/diversity/reachability, unexercised-race rejection, and relay-configuration preflight.

- **File:** `app_runtime_adapter.rs`
  - **Owns:** Long-lived black-box app-runtime adapter coverage, including owner-death child cleanup.

- **File:** `agent_text_stream_vectors.rs`
  - **Owns:** Byte-level conformance vectors for the agent text stream QUIC feature: `AgentTextStreamKeyContextV1`
    encoding, HKDF-SHA256 record key / nonce derivation, record AEAD AAD, transcript hashes, and the
    `QuicBrokerControlEnvelopeV1` envelope.

- **File:** `candidate_state_graph.rs`
  - **Owns:** Selector/candidate graph policy tests.

- **File:** `canonical_scenarios.rs`
  - **Owns:** Scripted scenarios, vector fixtures, generated family checks, reports.

- **File:** `canonicalization_contract.rs`
  - **Owns:** Executable canonicalization contract behavior, including sync-state edge cases.

- **File:** `failure_capsules.rs`
  - **Owns:** Capsule round trip (schedule, policy, resources) and exact commit replay from a sensitive checkpoint.

- **File:** `generated_policy_cases.rs`
  - **Owns:** Rust consumer for bounded policy cases shared with Tamarin generation.

- **File:** `issue_494_admin_promote_delivery.rs`
  - **Owns:** mdk#494 regression: a promoted peer receives the promoter's later messages without sending first.

- **File:** `independent_reference_model.rs`
  - **Owns:** Production-independent symbolic selector/canonicalizer differential tests, including small shrinkable
    selector inputs, authentication/authorization, dependency closure, proposal expiry, and witness-free comparison.

- **File:** `lifecycle_model.rs`
  - **Owns:** Stateright lifecycle mirror, fair bounded progress, crash/resource recovery, stranded-joiner repair, and
    stable-action-id counterexample-to-Scenario-IR validation.

- **File:** `large_group_family.rs`
  - **Owns:** Deterministic large-group size/admin/traffic profiles, replay metadata, strict whole-group terminal
    oracles, exact retained-join pending-work classification, sampled delivery/decryptability coverage, and the normal
    mid-size application and incremental-join executable canaries.

- **File:** `membership_reentry_family.rs`
  - **Owns:** Deterministic single/repeated departure and fresh-Welcome re-entry, restart/self-update/self-leave
    interactions, stale-Welcome recovery, strict terminal state/input/decryptability oracles, and family registration
    and prefix stability.

- **File:** `offline_catchup_family.rs`
  - **Owns:** Deterministic offline-backlog volume/recovery profiles, retained-relay enforcement, terminal-only
    reconnect, exact backlog multiplicity, strict pending-work/equivalence/decryptability oracles, and file-backed
    executable canaries.

- **File:** `offline_catchup_regression.rs`
  - **Owns:** The reduced `offline-catchup-pressure/v1` seed 17001 case 19 regression (16 commit rounds, first 368
    messages) with full payload multiplicity, exact state, and decryptability.

- **File:** `node_protocol.rs`
  - **Owns:** Versioned convergence-node JSONL protocol: observable quiescence, identifier-free errors, oversized-frame
    handling.

- **File:** `mutation_adequacy.rs`
  - **Owns:** Exact executable mutation catalog coverage, kill assertions, and drift-checking
    `../MUTATION_MATRIX.md`.

- **File:** `protocol_decision_gate.rs`
  - **Owns:** `../PROTOCOL_DECISIONS.md` and convergence-constant inventory pins, adopted protocol commit/value pin, exhaustive constant versioning classification, future required
    component rule, and closed-input scheduler/resource non-interference.

- **File:** `policy_case_tamarin_drift.rs`
  - **Owns:** Generated Tamarin seed rules and lemmas from `formal/tamarin/policy_cases.json` match the committed model.

- **File:** `policy_sweeps.rs`
  - **Owns:** `test-policy-overrides` one-variable policy curves and named boundary failures.

- **File:** `openmls_replay_probe.rs`
  - **Owns:** OpenMLS replay and candidate materialization probes.

- **File:** `proptest_invariants.rs`
  - **Owns:** Property tests for selector order, canonicalization, capability matrices, lifecycle/restart behavior,
    generated send/leave histories, and delivery-profile convergence.

- **File:** `process_orchestrator.rs`
  - **Owns:** Multi-process orchestrator: isolated process roots, engine/app-runtime/process public-state equivalence,
    four-party cross-route checkpoints and ignored soaks/restart permutations, kill/reconnect/restart agreement,
    saved-input execution, capability and relay-map preflight, and private reports/capsules. Selected tests run in
    `just simulator-smoke`; the whole binary runs in the nightly lane.

- **File:** `process_campaign_runner.rs`
  - **Owns:** Real child-process campaign execution, exact saved-input/report provenance, fixture/capsule artifacts, and
    refusal to overwrite prior campaign evidence.

- **File:** `report_runner.rs`
  - **Owns:** Report artifact runner, oracle evidence, and coverage matrix coverage.

- **File:** `route_assurance.rs`
  - **Owns:** Route inventory liveness against source markers, `../CONVERGENCE_ROUTE_MATRIX.md` drift, and
    counterexample claims that a green run cannot silently close.

- **File:** `scenario_ir.rs`
  - **Owns:** Schema/compiler contract: every executable step kind declared, v3-only actions rejected in v2, authoring
    schema references, group-scoping and preflight failures.

- **File:** `semantic_reduction.rs`
  - **Owns:** Dependency-aware reduction units that keep each fault paired with its recovery step.

- **File:** `sqlite_storage_modes.rs`
  - **Owns:** Harness storage-mode coverage over encrypted file-backed SQLite, including full close/reopen hydration,
    production WAL defaults, encrypted headers, and busy-writer retry behavior.

- **File:** `stateful_generator.rs`
  - **Owns:** `chat-journey/v1` determinism, legality, canonical IR, and report execution of both journey profiles.

- **File:** `tracing_audit.rs`
  - **Owns:** Repo-wide production tracing privacy audit.

- **File:** `vector_artifacts.rs`
  - **Owns:** Vector manifest and byte-fixture well-formedness checks.

## Rules

- Use a fixed seed for generated test families.
- Promote a generated failure into a vector when it becomes a regression case.
- Update `../SCENARIOS.md` or `../PROPERTY_TESTS.md` when adding a scenario, generated family, or property-test
  invariant.
- Keep harness tests at the `HarnessClient`/`TransportBus` level. Extend the harness API instead of reaching into engine
  internals.
- Keep default property-test counts fast. Use `conformance-slow` for the wider pass, with case counts chosen by test
  cost.
- A generated-family test must not rely only on successful execution. Pin deterministic replay/prefix behavior and
  prove that the strict oracle observes the operation or interaction the family claims to cover.
- Keep real process/container/VM tests explicit or ignored when their cost or external dependencies make them
  unsuitable for the ordinary crate test. Document the exact manual command and artifact path.

## Verification

```sh
cargo test -p cgka-conformance-simulator
cargo test -p cgka-conformance-simulator --features conformance-slow
```
