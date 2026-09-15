# AGENTS.md - crates/cgka-conformance-simulator/src

Local map for simulator source modules. Read `../AGENTS.md` for the agent workflow,
`../RUNNING_CAMPAIGNS.md` for operator behavior, and `../SCALING_CAMPAIGNS.md` before changing generated families.

## Rules

- Keep scenario generation and engine bus scheduling deterministic for a fixed seed and scenario spec.
- Keep `ScenarioTrace` free of OpenMLS bytes and Rust-only internals.
- Keep oracle coverage in `oracle.rs` when adding new scenario stimuli, expectation kinds, or property-test families.
- Add new queue behavior in `bus.rs` and expose it through serializable `ScenarioStep` variants before using it in
  vectors.
- Keep generated families versioned. A generator behavior change should bump the family generator version.
- Preserve generated-case prefix stability: increasing the case count must not change any existing case index.
- Put legal product actions and their expected-state transitions in the shared stateful model. Keep workload families
  thin and keep transport/process/storage/resource faults separately typed.
- Add strict oracle, reachability, required-interaction, and same-seed/different-seed tests with a new family or motif.
- Keep engine bus scheduling deterministic and separate from real network faults. `TransportBus` uses the production
  Nostr peeler without sockets; `app_runtime.rs` uses the public app runtime and a real local relay. App scenario
  inputs are reproducible, but OS scheduling, cryptographic randomness and relay timing are not fixed by the seed.
- Keep app process ownership in `app_runtime/process_io.rs`, the public API bridge in `process_backend.rs`, and local
  relay control in `process_relay.rs`; `process_server.rs` dispatches the node helper's private service modes.
  The coordinator must not open participant storage or replace public assertions with private engine observations.
- Default app acceptance uses one process per participant and a separate relay process. Keep `new_in_process_stress`
  explicit for shared-runtime diagnostics. Build and freeze matching node/coordinator feature modes before a campaign;
  preserve the existing protocol, cleanup and execution-layout checks when adding a command.

## Assertion timing

`assertion_wait.rs` shares real-app eventual-assertion pacing and deadlines between `scenario.rs`
and `process_orchestrator.rs`. Keep the first sample immediate, later rounds at least one second,
and the total allowance `(max_iterations + 1)` seconds. Record elapsed/allowed wall time separately
from virtual time. Engine subjects retain deterministic unpaced ticks. Test fast/slow polling,
never-recovering and stalled subjects with paused Tokio time; do not relax predicate expectations.

A process assertion may time out before its first RPC returns: preserve a failed report with zero
completed samples and null actual state, plus the timeout capsule. Never fabricate a sample, extend the
deadline to obtain one, or let the strict success oracle accept that diagnostic report.
