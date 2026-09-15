# Scenario IR and authoring semantics

The simulator has two deliberately separate inputs:

- `ScenarioSpec` v2 and v3 are canonical adapter-neutral JSON IRs. Both contain only a linear sequence of executable
  atomic actions. V2 remains replayable through `schemas/scenario-ir.v2.schema.json`; v3 adds the full
  `update_group_profile` action and expected tick-error observation through `schemas/scenario-ir.v3.schema.json`.
- `ScenarioAuthoringSpec` v1 is human-oriented structure. It may be represented as JSON or YAML, but it is never passed
  to an adapter. The repository compiler deterministically lowers it to canonical JSON first, emitting v2 unless an
  expanded action requires v3. Its schema is `schemas/scenario-authoring.v1.schema.json`.

The canonical document declares accounts, devices, processes, initial groups, relays, account roles, process
binary/policy versions, and relay implementation/policy versions in `topology`. Each action-facing client label maps to
exactly one device, and every device references one account and process. Process relay sets may differ. The compiler
rejects duplicate or dangling labels and group admins that are not initial members. Existing repository vectors that
omit topology resolve deterministically to one account/device/process per client with explicitly `unspecified`
versions; new cross-adapter and retained-relay scenarios should declare topology rather than relying on that projection.
The initial adapters consume client/process relay placement. Initial groups, account roles, and process binary/policy
versions are validated and preserved as scenario metadata but do not yet alter adapter behavior; later compatibility
and process adapters may interpret them without changing the canonical IR.

An executor accepts only canonical `ScenarioSpec` JSON. It compiles the entire document, assigns stable action ids,
derives `declared_virtual_time_ms` as the sum of explicit `advance_time` deltas before every action, and preflights all
adapter capabilities before executing action zero. A run report records that exact compiled schedule. Assertions and
quiescence may advance the subject clock while an action executes, so the declared schedule is not described as the
adapter's observed clock. Adapters do not interpret authoring loops, `parallel` blocks, rates, or barriers.
Explicit canonical race actions define their own adapter execution semantics, including shared-barrier
concurrent profile updates.

Scenario IR v2's `update_group_data` action is the stable name-only operation. Scenario IR v3's
`update_group_profile` action carries optional `name` and `description` fields and requires at least one of them. A
missing field means preserve the adopted canonical value; an explicitly empty string clears that field. The compiler
rejects the v3 action in a v2 document rather than silently changing v2 serialization or semantics.
V3 also adds `expect_tick_error`, which ticks exactly one participant, records the normalized error when it matches,
and lets the scenario continue. It is intended for retryable transport refusals where a later action replays the same
input after the prerequisite state arrives; an unexpected success or a different error still fails the scenario. An
adapter must advertise both transport delivery and expected-transport-error observation before this action executes.
That split is intentional because canonical JSON is persisted in vectors and failure capsules and exchanged with
external campaign runners; adding fields to an existing action version would change the meaning accepted by a v2
consumer even when this repository's current fixtures omit them.

## Deterministic expansion

Expansion is pure and does not read wall time, thread scheduling, randomness, or adapter state.
The compiler rejects expansion beyond 1,000,000 canonical actions before allocating the repeated output.

- `action` appends its nested canonical action.
- `repeat` expands its body exactly `count` times. A count of zero appends nothing.
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

## Faults, lifecycle, and selectors

Portable transport faults select objects by any conjunction of stable scenario action id, publication label, sender,
and semantic class (`commit`, `proposal`, `application`, `welcome`, or `group_message`). `occurrence` selects among
otherwise identical matches in deterministic emission order. Omit, duplicate, withhold/release, and reorder operations
resolve those selectors immediately before mutation. A selector with no semantic constraint is a compile error.

The IR also declares participant offline/reconnect, process crash/restart, and bounded storage faults (`busy`, read or
write failure, capacity exceeded, or torn write). Adapters advertise these independently. In particular, the packet-bus
engine adapter deliberately does not advertise offline history or process/storage fault support; such a scenario is
rejected during whole-schedule preflight instead of partially running with packet-loss semantics.

## Retained relay execution

`RetainedRelaySubject` maps each scenario process to its declared relay set. Accepted engine emissions fan out into a
durable history per relay; the underlying packet-bus copy is discarded before delivery. `deliver_all` performs a
default incremental query for every online participant. `sync_relay_history` selects incremental cursor, explicit
timestamp floor, full history, or set-reconciliation comparison. A `since.timestamp` floor is compared with retained
message wall-clock timestamps in whole seconds; virtual time does not rewrite those timestamps. A `since` query does
not consume the independent incremental cursor. Each query records queried relays, EOSE relays,
returned/unique/injected counts, whether the result was quiet, and one of these deliberately distinct claims:
`relay_eose_only`, `full_history_queried`, `relevant_set_mismatch`, or `relevant_set_equality_verified`.
If engine ingest refuses retained objects because the deferred-peel capacity is full, the subject keeps a transport
redelivery obligation and performs another complete-history query on a later tick. The obligation remains visible as
pending transport work until a retry is admitted, and repeated full refusals without engine progress fail with the
typed `retained_history_redelivery_no_progress` resource error.

Relay-control actions configure deterministic natural/reverse order and duplicate copies, change per-client event
visibility through semantic selectors, and equalize selected relay event sets. Reconciliation copies missing events
as newly visible on the repaired relay, clearing any source-relay `hidden_from` exclusions. A hidden event still advances an
incremental cursor after EOSE, so making it visible later does not magically replay it; an explicit full-history or set
reconciliation path is required. This is the quiet-group/silent-absence sentinel. The packet bus remains the fast unit
adapter and is not used as evidence of offline recovery.

## Assertions

`assert` actions are executable and write samples to the common report/capsule schema:

- `exactly` samples once at the current action boundary;
- `eventually` samples now and after at most `max_iterations` participant tick rounds (deterministic for engine subjects; paced against wall time for real app subjects);
- `within` samples now, then advances virtual time and ticks participants until the predicate matches or the deadline;
- `never` requires the predicate to remain false at every sample through the virtual-time window; and
- `resource` compares a structural-progress metric to an exact, upper, or lower bound.

Current predicates cover client epoch/member state, exact payload multiplicity, exact canonical equivalence, and no
pending work. Portable semantic outcomes additionally include an exact expected group profile, so clients agreeing on
the same stale name or description cannot satisfy a profile-update oracle. Temporal poll intervals must be non-zero,
client references are compile-checked, and iteration/time bounds
are watchdogs rather than a redefinition of success. Predicate samples are non-destructive: evaluating an assertion
does not drain the event window that a later `observe` action records. Predicates that require exact canonical state add
the exact-observation capability during compilation, so a semantic-only adapter rejects the complete schedule before
action zero.

For real app subjects, each unsuccessful `eventually` round includes catch-up and lasts at least one
second. A total wall-clock watchdog of `(max_iterations + 1)` seconds includes the initial sample;
slow remote operations consume that same budget. This keeps parallel catch-up from spending all
polls before production convergence timers can fire. A matching initial sample still returns
immediately, predicates remain unchanged, and exceeding either budget fails the assertion. Reports
include `wall_timeout_ms` and `elapsed_wall_ms`; older reports deserialize without these optional
fields. Deterministic engine subjects keep unpaced tick counts and omit wall-clock evidence.

The process adapter supports `exactly` and `eventually` with `client_state` through the narrow
`client_state_assertion` capability. It reads the public epoch/member count, samples once before ticking,
and performs at most the declared number of catch-up rounds across running participants. An exhausted
assertion stops the scenario with a failure capsule; `assertion_observations` records the predicate,
source step, sample count and final public state separately from ordinary checkpoints. Virtual-time and
private-state assertions remain subject to their separate capability checks before launch.

A wall-clock deadline can expire before the first process `Observe` RPC completes. Such a failed report
records `samples: 0`, `final_actual: null`, `passed: false`, and the elapsed/allowed wall time; it never
invents a public state. With earlier completed samples, `final_actual` retains the last observed state.
The failure capsule uses `scenario_assertion_timeout` for an elapsed wall deadline and
`scenario_assertion_failed` for a sampled mismatch that exhausts the iteration allowance. Both stop
execution and retain the private failure report. The strict cross-route validator accepts only successful
execution evidence, so it must reject these reports; rejection does not make the diagnostic report malformed.

The public cross-route scenario uses this bounded assertion before sending its branch witness: Yankee
must have epoch 4 and four members before the scenario partitions the participants. Relay EOSE alone
does not establish that state because app convergence can continue after a relay drain ends.

## Initial adapters

`EngineHarnessSubject` executes the IR against the real in-process OpenMLS/SQLite/Nostr-peeler stack.
`ReferenceModelSubject` is a separate logical state machine for the common creation, membership, policy, publication,
delivery, and application-message surface. It never calls the production selector or canonicalization code and does not
claim an MLS exact-state oracle. Both adapters emit the same `ScenarioReport`, observation, assertion, and failure-capsule
schemas; capability preflight defines which scenarios each may run. A repository test executes one compiled scenario
unchanged through both adapters and compares their shared semantic observations.

## Compatibility contract

Canonical JSON is the portable artifact stored in vectors, failure capsules, and cross-adapter campaigns. Human YAML is
only an authoring convenience: parsing YAML must produce `ScenarioAuthoringSpec`, and the resulting canonical JSON is
the reviewed/replayable input. Changing expansion semantics requires a new authoring version; changing canonical action
meaning or serialization requires a new Scenario IR version.


## Real app-runtime stimuli (v3)

- `interrupt_relay { relay, outage_ms }` requires `relay_interruption`. The local app harness cuts live
  sockets and refuses connections for 1–30,000 ms, restores service, and records actual socket and
  running-runtime counts. Zero interrupted connections fails the stimulus check. This is real wall
  time; it does not advertise virtual-clock control or replace `set_client_offline`.
- `race_group_profiles { updates: [{ client, name?, description? }, ...] }` requires
  `concurrent_group_mutation`. Preflight requires 2–8 distinct clients with nonempty edits. The app
  harness validates the batch, releases callers from a shared barrier and records each outcome. All
  requests must be accepted to exercise this action; scenario expectations separately assert the
  surviving effects. The generated disjoint-field race requires both edits to survive.

Reports add optional `stimulus_observations`, bound to compiler action IDs. Missing evidence, zero
socket cuts, or refused concurrent inputs cannot turn into a green assurance report. Older report
JSON remains readable because the field defaults to an empty array. V2 documents cannot select
these v3 actions; incapable adapters refuse them before action zero.

The v3 `public_payload_multiset` predicate takes `client` and `payloads`. It compares the complete
visible public history, including multiplicity, from one participant snapshot. Empty expectations
are valid. It requires the public app observation capability and supports the existing assertion
modes; virtual-time modes still require an adapter with virtual time. Large app families use bounded
`eventually` checks and independent terminal trace expectations. V2 rejects this predicate.
