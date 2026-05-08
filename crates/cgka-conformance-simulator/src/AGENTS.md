# AGENTS.md - crates/cgka-conformance-simulator/src

Local map for simulator source modules. Read `../AGENTS.md` for scenario and
vector workflow.

## Rules

- Keep the simulator deterministic for a fixed seed and scenario spec.
- Keep `ScenarioTrace` free of OpenMLS bytes and Rust-only internals.
- Add new queue behavior in `bus.rs` and expose it through serializable
  `ScenarioStep` variants before using it in vectors.
- Keep generated families versioned. A generator behavior change should bump
  the family generator version.
- Use `MockPeeler` only as a pass-through boundary witness. Do not add real
  encryption here.
