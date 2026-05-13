# AGENTS.md - crates/cgka-conformance-simulator/src

Local map for simulator source modules. Read `../AGENTS.md` for scenario and
vector workflow.

## Rules

- Keep the simulator deterministic for a fixed seed and scenario spec.
- Keep `ScenarioTrace` free of OpenMLS bytes and Rust-only internals.
- Keep oracle coverage in `oracle.rs` when adding new scenario stimuli,
  expectation kinds, or property-test families.
- Add new queue behavior in `bus.rs` and expose it through serializable
  `ScenarioStep` variants before using it in vectors.
- Keep generated families versioned. A generator behavior change should bump
  the family generator version.
- Keep real relay/network behavior out of this crate. The harness uses the
  production-shaped Nostr peeler over the in-memory `TransportBus`.
