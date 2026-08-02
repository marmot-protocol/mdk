# Scenario IR and authoring semantics

The simulator has two deliberately separate inputs:

- `ScenarioSpec` v2 is the canonical adapter-neutral JSON IR. It contains only a linear sequence of executable atomic
  actions. Its schema is `schemas/scenario-ir.v2.schema.json`.
- `ScenarioAuthoringSpec` v1 is human-oriented structure. It may be represented as JSON or YAML, but it is never passed
  to an adapter. The repository compiler deterministically lowers it to canonical JSON first. Its schema is
  `schemas/scenario-authoring.v1.schema.json`.

An executor accepts only canonical `ScenarioSpec` JSON. It compiles the entire document, assigns stable action ids,
derives the virtual time before every action, and preflights all adapter capabilities before executing action zero. A
run report records that exact compiled schedule. Adapters do not interpret loops, concurrency, rates, or barriers.

## Deterministic expansion

Expansion is pure and does not read wall time, thread scheduling, randomness, or adapter state.
The compiler rejects expansion beyond 1,000,000 canonical actions before allocating the repeated output.

- `action` appends its nested canonical action.
- `repeat` expands its body once, then appends exact copies `count` times. A count of zero appends nothing.
- `parallel` is deterministic logical concurrency, not host-thread concurrency. Each declared lane contributes at most
  one next action per round, in lane declaration order. A lane at a barrier waits while other lanes continue toward it.
- Every lane in a `parallel` block must reach the same named barriers in the same order. The compiler rejects a lane
  that ends before its peers reach a barrier or lanes that reach different barrier names. After all lanes arrive, one
  canonical `barrier` no-op is emitted. Barriers are scoped to the nearest parallel block; a completed nested barrier is
  an ordinary recorded action from the containing block's perspective.
- A top-level `barrier` lowers directly to a canonical recorded no-op. It has no adapter capability requirement.

The canonical action id is `step-<zero-based canonical index>:<action type>`. Because expansion is deterministic, the
same authoring document produces identical canonical action ids and schedule entries across runs and adapters.

## Rate and burst time

All generated timing uses integer virtual milliseconds. It inserts canonical `advance_time` actions; it never sleeps.

- `rate.actions_per_second = r` starts flattened action `i` at integer offset `floor(i * 1000 / r)` milliseconds from
  the block start. The compiler emits only the delta from the previous absolute offset. This absolute calculation
  distributes rounding error and prevents cumulative drift. Rates above 1,000 actions/second intentionally produce
  multiple actions at the same virtual millisecond.
- `burst` expands one immediate body `count` times and inserts exactly `every_ms` between successive burst starts. A
  zero interval means all bursts start without advancing virtual time.
- A rate or burst body may contain nested `repeat` and `parallel`, but after flattening it may not contain a barrier or
  explicit `advance_time`. This gives each timed block exactly one clock owner and makes ambiguous schedules a compile
  error.

Virtual time is the only time that affects canonical scheduling. Wall time appears only in execution diagnostics and
must not affect expansion or action order.

## Compatibility contract

Canonical JSON is the portable artifact stored in vectors, failure capsules, and cross-adapter campaigns. Human YAML is
only an authoring convenience: parsing YAML must produce `ScenarioAuthoringSpec`, and the resulting canonical JSON is
the reviewed/replayable input. Changing expansion semantics requires a new authoring version; changing canonical action
meaning or serialization requires a new Scenario IR version.
