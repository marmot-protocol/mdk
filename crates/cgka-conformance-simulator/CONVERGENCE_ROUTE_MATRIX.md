# Convergence decision-route matrix

This matrix is the human index for every current production seam that can
select, reject, defer, invalidate, replay, or apply a competing commit. The
machine-readable ownership record is `src/route_assurance.rs`; the
`route_assurance` test fails when a named source marker disappears or this
table drifts from the registered route ids.

Route choice is not part of the canonical result. Once the same authenticated,
dependency-closed durable input set is available, every route is expected to
produce the same canonical state and dispositions. A `partial` or `gap` entry
below is deliberately not treated as passing evidence.

| Route id | Production owner | Independent model | Mutation sentinel | Current campaign evidence | Current limitation |
| --- | --- | --- | --- | --- | --- |
| `ordinary_ingest` | `message_processor/ingest.rs` | partial: `reference_convergence::evaluate` | covered: cutoff admission and output invalidation | observer vectors, both cross-route recovery regressions, and the shared engine/app/process restart journey | Public protocol and application projection overlap now crosses engine, app-runtime, and process adapters; the adversarial four-party topology and exact state remain open outside engine/retained-history. |
| `pairwise_fork_recovery` | `message_processor/ingest.rs`, `fork_recovery.rs` | partial: bounded abstract route lifecycle | partial: sibling-model pairwise-loser terminalization | both cross-route recovery regressions plus the pairwise reconsideration tests | Pairwise displacement and deeper-branch reconsideration are covered through retained-history delivery; app-runtime, distributed, and durable-transition permutations remain open. |
| `stored_convergence` | `distributed_convergence.rs` | partial: selector plus lifecycle models | covered: comparator and frozen membership | both cross-route regressions, restart properties, and convergence chaos | Route choice is not represented in the models, and app-runtime/distributed equivalence remains open. |
| `candidate_materialization` | `openmls_projection.rs` | partial: dependency/disposition model | covered: retention and frozen membership | engine and retained-history cross-route recovery plus OpenMLS replay | One live pairwise/materialization topology is covered through two delivery routes; app-runtime and distributed equivalence remains open. |
| `retained_history_replay` | `message_processor/ingest.rs`, `openmls_projection.rs` | partial: unequal-history lifecycle | covered: retention and witness deduplication | `cross-route-retained-history-recovery/v1`, retained-relay equality, offline journeys, and shared app/process offline full-history recovery | One public-projection recovery journey now crosses app-runtime and process; multi-relay ordering, retention boundaries, the four-party adversarial topology, and distributed adapters remain open. |
| `crash_restart_recovery` | `engine.rs`, `distributed_convergence.rs` | covered: crash/restart lifecycle | covered: frozen membership and scheduler re-arm | both cross-route encrypted-SQLite regressions, durable-phase kill properties, and the shared engine/app/process restart journey | One shared public-state restart checkpoint now crosses engine, app-runtime, and process; every durable transition, the adversarial four-party topology, and distributed adapters remain open. |
| `application_disposition` | `message_processor/ingest.rs`, `openmls_projection.rs` | covered: reference dispositions | covered: output invalidation | scenario-input ledgers and bidirectional decryptability probes in both cross-route regressions | Sender-visible application invalidation during branch replacement remains incomplete. |

## Assurance claims

Cross-route campaigns may produce evidence for these stable claim ids:

- `route_equivalence`
- `reconsiderable_loser`
- `restart_invariance`
- `exact_cryptographic_agreement`
- `active_bidirectional_decryptability`
- `complete_application_disposition`

A passing campaign can move an open claim to covered. Any field, soak,
mutation, or replay counterexample reopens it. Later green runs are retained as
evidence but cannot silently clear a known falsification; the falsification
must be resolved by explicit reviewed evidence.

## Active production work

MDK #1329 has merged the fail-closed missing-anchor behavior and Welcome-repair
retirement. Its formerly stacked #1293 remains open. This inventory describes
current `master` and does not encode #1293's proposed result as an oracle. If a
route is removed or its source marker changes, the source audit fails and the
inventory must be reviewed before evidence is carried forward.
