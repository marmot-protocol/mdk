# AGENTS.md - crates/cgka-conformance-simulator/tests

Map for simulator tests.

Read `../RUNNING_CAMPAIGNS.md` for the supported operator entrypoints and `../SCALING_CAMPAIGNS.md` for the required
determinism, reachability, interaction-coverage, and promotion checks when adding generated coverage.

## Files

- **File:** `support/offline_catchup.rs`
  - **Owns:** Compact reconstruction of the exact checkpoint 368/1,024-message inputs. Pinned SHA-256 values
    cover serialized metadata, actions and expected outcomes; compare against checkpoint `9282a643` before
    intentionally changing these workloads. Shared by engine regressions and public app journeys.

- **File:** `public_app_families.rs`
  - **Owns:** Seeded public send/leave, membership re-entry and small offline recovery family contracts,
    capability preflight, interaction coverage, and explicit real-socket strict oracle canaries.

- **File:** `app_runtime_journeys.rs`
  - **Owns:** Basic public app acceptance journeys and the explicit slow 1,024-message public catch-up gate,
    also selected by the dedicated required public recovery CI job with production policy.
    Real local relay, SQLCipher roots, exact public payload/state checks, post-change messaging, and restart
    persistence. See `../APP_PATH_COVERAGE.md` for replay and evidence commands.

- **File:** `app_runtime_interaction_journeys.rs`
  - **Owns:** Public app interaction journeys that the serialized generated families do not reach: two groups on
    one device with a removal and reopen, two admins editing different profile fields at the same instant, a
    concurrent invite plus rename, a member removed while its device is closed, a voluntary leave with three
    remaining auto-committers, and the explicit slow manual self-update. Same harness and evidence layout as `app_runtime_journeys.rs`; see `../APP_PATH_COVERAGE.md`.

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

- **File:** `generated_policy_cases.rs`
  - **Owns:** Rust consumer for bounded policy cases shared with Tamarin generation.

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

- **File:** `mutation_adequacy.rs`
  - **Owns:** Exact executable mutation catalog coverage, kill assertions, and drift-checking the human-readable
    verification-layer matrix.

- **File:** `protocol_decision_gate.rs`
  - **Owns:** Adopted protocol commit/value pin, exhaustive constant versioning classification, future required
    component rule, and closed-input scheduler/resource non-interference.

- **File:** `openmls_replay_probe.rs`
  - **Owns:** OpenMLS replay and candidate materialization probes.

- **File:** `proptest_invariants.rs`
  - **Owns:** Property tests for selector order, canonicalization, capability matrices, lifecycle/restart behavior,
    generated send/leave histories, and delivery-profile convergence.

- **File:** `process_campaign_runner.rs`
  - **Owns:** Real child-process campaign execution, exact saved-input/report provenance, fixture/capsule artifacts, and
    refusal to overwrite prior campaign evidence.

- **File:** `report_runner.rs`
  - **Owns:** Report artifact runner, oracle evidence, and coverage matrix coverage.

- **File:** `sqlite_storage_modes.rs`
  - **Owns:** Harness storage-mode coverage over encrypted file-backed SQLite, including full close/reopen hydration,
    production WAL defaults, encrypted headers, and busy-writer retry behavior.

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
