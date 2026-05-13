# AGENTS.md - crates/cgka-conformance-simulator/tests

Map for simulator tests.

## Files

- **File:** `candidate_state_graph.rs`
  - **Owns:** Selector/candidate graph policy tests.

- **File:** `canonical_scenarios.rs`
  - **Owns:** Scripted scenarios, vector fixtures, generated family checks, reports.

- **File:** `canonicalization_contract.rs`
  - **Owns:** Executable canonicalization contract behavior, including sync-state edge cases.

- **File:** `generated_policy_cases.rs`
  - **Owns:** Rust consumer for bounded policy cases shared with Tamarin generation.

- **File:** `openmls_replay_probe.rs`
  - **Owns:** OpenMLS replay and candidate materialization probes.

- **File:** `proptest_invariants.rs`
  - **Owns:** Property tests for selector order, canonicalization, capability matrices, lifecycle/restart behavior,
    generated send/leave histories, and delivery-profile convergence.

- **File:** `report_runner.rs`
  - **Owns:** Report artifact runner, oracle evidence, and coverage matrix coverage.

- **File:** `tracing_audit.rs`
  - **Owns:** Repo-wide production tracing privacy audit.

## Rules

- Use a fixed seed for generated test families.
- Promote a generated failure into a vector when it becomes a regression case.
- Update `../SCENARIOS.md` or `../PROPERTY_TESTS.md` when adding a scenario, generated family, or property-test
  invariant.
- Keep harness tests at the `HarnessClient`/`TransportBus` level. Extend the harness API instead of reaching into engine
  internals.
- Keep default property-test counts fast. Use `conformance-slow` for the wider pass, with case counts chosen by test
  cost.

## Verification

```sh
cargo test -p cgka-conformance-simulator
cargo test -p cgka-conformance-simulator --features conformance-slow
```
