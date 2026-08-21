# AGENTS.md - crates/cgka-conformance-simulator/tests

Map for simulator tests.

Read `../RUNNING_CAMPAIGNS.md` for the supported operator entrypoints and `../SCALING_CAMPAIGNS.md` for the required
determinism, reachability, interaction-coverage, and promotion checks when adding generated coverage.

## Files

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
