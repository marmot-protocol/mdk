# AGENTS.md - crates/cgka-conformance-simulator/tests

Map for simulator tests.

## Files

| File | Owns |
| --- | --- |
| `candidate_state_graph.rs` | Selector/candidate graph policy tests. |
| `canonical_scenarios.rs` | Scripted scenarios, vector fixtures, generated family checks, reports. |
| `canonicalization_contract.rs` | Executable canonicalization contract behavior, including sync-state edge cases. |
| `generated_policy_cases.rs` | Rust consumer for bounded policy cases shared with Tamarin generation. |
| `openmls_replay_probe.rs` | OpenMLS replay and candidate materialization probes. |
| `proptest_invariants.rs` | Property tests for selector order, canonicalization, capability matrices, lifecycle/restart behavior, generated send/leave histories, and delivery-profile convergence. |
| `report_runner.rs` | Report artifact runner coverage. |
| `tracing_audit.rs` | Repo-wide production tracing privacy audit. |

## Rules

- Use a fixed seed for generated test families.
- Promote a generated failure into a vector when it becomes a regression case.
- Keep harness tests at the `HarnessClient`/`TransportBus` level. Extend the
  harness API instead of reaching into engine internals.
- Keep default property-test counts fast. Use `conformance-slow` for the wider
  pass, with case counts chosen by test cost.

## Verification

```sh
cargo test -p cgka-conformance-simulator
cargo test -p cgka-conformance-simulator --features conformance-slow
```
