# Convergence lifecycle model

TLA+ model of the Marmot convergence lifecycle, checked with TLC. It owns the temporal claims — under which fairness
assumptions convergence and administrative changes eventually make progress — that the symbolic Tamarin model in
[`../tamarin`](../tamarin/) deliberately does not cover. Tamarin remains the safety, authentication, authorization, and
bounded selector-policy model; it is not stretched into a scheduler or crash/restart model.

## What is modeled

`ConvergenceLifecycle.tla` models unequal histories, eventual input closure, freeze/settle, a durable frozen revision
plus a crash-lost volatile staged revision that is rehydrated on restart, temporary resource failure, a pending
privileged administrative change, repeated member self-updates, and a joiner stranded on a losing branch. The only
modeled repair for that joiner is a fresh-state rejoin; consumed signature state is not reused.

TLC is authoritative for temporal claims because fairness assumptions are explicit and infinite stuttering executions
are part of the state space.

| File | Purpose |
| --- | --- |
| `ConvergenceLifecycle.tla` | The specification. |
| `ConvergenceLifecycle.fair.cfg` | Fair configuration; must satisfy every temporal property. |
| `ConvergenceLifecycle.unfair.cfg` | Fairness omitted; must produce an administrative-progress counterexample. |
| `counterexamples/admin-starvation.scenario.json` | That counterexample as canonical Scenario IR. |

The fair configuration assumes:

- convergence-relevant input eventually closes;
- input closure, delivery, restart, resource recovery, freeze, settle, and permitted repair actions are strongly fair
  (if repeatedly enabled, they are eventually scheduled despite recurrent crash/resource interference);
- retained inputs remain available through crash and temporary exhaustion.

The unfair configuration omits those assumptions. Infinite valid self-updates violate eventual input closure; an
enabled administrative action that is never chosen violates fair scheduling. Marmot v1 makes no progress guarantee in
either execution.

## Rust mirror

The Rust/Stateright mirror is
[`crates/cgka-conformance-simulator/src/lifecycle_model.rs`](../../crates/cgka-conformance-simulator/src/lifecycle_model.rs),
tested by
[`crates/cgka-conformance-simulator/tests/lifecycle_model.rs`](../../crates/cgka-conformance-simulator/tests/lifecycle_model.rs).
It is the trace/action-identity bridge, not the authority for infinite-run liveness. Stable ids such as
`model-step-0:self_update` project into canonical Scenario IR, and a test checks that the committed counterexample
compiles to the same action sequence.

## Run

Both recipes need Java. They download the pinned upstream `tla2tools.jar` v1.7.4 into `target/tla/` and verify its
SHA-256 unless `TLA2TOOLS_JAR` points to an existing jar. The jar is never committed.

```sh
# Fair model: must pass.
just tla-liveness

# Unfair model: must fail with a temporal-property violation.
just tla-liveness-counterexample
```

Both run in `just convergence-verification-ci`.
