# Convergence lifecycle model

This directory owns temporal convergence/lifecycle claims. Tamarin remains the
symbolic safety, authentication, authorization, and bounded selector-policy
model; it is intentionally not stretched into a scheduler or crash/restart
model.

`ConvergenceLifecycle.tla` models unequal histories, eventual input closure,
freeze/settle, durable frozen state across crash/restart, temporary resource
failure, a pending privileged administrative change, repeated member
self-updates, and a joiner stranded on a losing branch. The only modeled repair
for that joiner is a fresh-state rejoin; consumed signature state is not reused.

TLC is authoritative for temporal claims because `WF` is explicit and infinite
stuttering executions are part of the state space. The fair configuration
assumes:

- convergence-relevant input eventually closes;
- input closure, delivery, restart, resource recovery, freeze, settle, and
  permitted repair actions are strongly fair (if repeatedly enabled, they are
  eventually scheduled despite recurrent crash/resource interference);
- retained inputs remain available through crash and temporary exhaustion.

The unfair configuration deliberately omits those fairness assumptions and must
produce an administrative-progress counterexample. Infinite valid self-updates
violate eventual input closure; an enabled administrative action that is never
chosen violates fair scheduling. Marmot v1 makes no progress guarantee in
either execution.

The Rust/Stateright mirror is in `crates/cgka-conformance-simulator/src/lifecycle_model.rs`
and `tests/lifecycle_model.rs`. It is the trace/action-identity bridge, not the
authority for infinite-run liveness. Stable IDs such as
`model-step-0:self_update` can be projected into the canonical Scenario IR.

Run the fair model with:

```sh
just tla-liveness
```

Run the expected-failure counterexample check with:

```sh
just tla-liveness-counterexample
```

Both recipes download the pinned upstream `tla2tools.jar` v1.7.4 into `target/`
when `TLA2TOOLS_JAR` is not supplied. The jar is never committed.
