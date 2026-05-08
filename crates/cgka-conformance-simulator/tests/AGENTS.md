# AGENTS.md - crates/cgka-conformance-simulator/tests

Map for simulator tests.

## Files

| File | Owns |
| --- | --- |
| `canonical_scenarios.rs` | Scripted scenarios, vector fixtures, generated family checks, reports. |
| `openmls_replay_probe.rs` | OpenMLS replay and candidate materialization probes. |
| `proptest_invariants.rs` | Property tests over generated intent sequences and delivery profiles. |
| `report_runner.rs` | Report artifact runner coverage. |

## Rules

- Use a fixed seed for generated test families.
- Promote a generated failure into a vector when it becomes a regression case.
- Keep harness tests at the `HarnessClient`/`TransportBus` level. Extend the
  harness API instead of reaching into engine internals.

## Verification

```sh
cargo test -p cgka-conformance-simulator
cargo test -p cgka-conformance-simulator --features conformance-slow
```
