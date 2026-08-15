# AGENTS.md - crates/cgka-conformance-simulator/src

Local map for simulator source modules. Read `../AGENTS.md` for the agent workflow,
`../RUNNING_CAMPAIGNS.md` for operator behavior, and `../SCALING_CAMPAIGNS.md` before changing generated families.

## Rules

- Keep the simulator deterministic for a fixed seed and scenario spec.
- Keep `ScenarioTrace` free of OpenMLS bytes and Rust-only internals.
- Keep oracle coverage in `oracle.rs` when adding new scenario stimuli, expectation kinds, or property-test families.
- Add new queue behavior in `bus.rs` and expose it through serializable `ScenarioStep` variants before using it in
  vectors.
- Keep generated families versioned. A generator behavior change should bump the family generator version.
- Preserve generated-case prefix stability: increasing the case count must not change any existing case index.
- Put legal product actions and their expected-state transitions in the shared stateful model. Keep workload families
  thin and keep transport/process/storage/resource faults separately typed.
- Add strict oracle, reachability, required-interaction, and same-seed/different-seed tests with a new family or motif.
- Keep real relay/network behavior out of this crate. The harness uses the production-shaped Nostr peeler over the
  in-memory `TransportBus`.
