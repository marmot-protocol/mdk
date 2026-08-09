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
| `ordinary_ingest` | `message_processor/ingest.rs` | partial: `reference_convergence::evaluate` | covered: cutoff admission and output invalidation | observer-ingest fixed vectors | Does not compare every decision route. |
| `pairwise_fork_recovery` | `message_processor/ingest.rs`, `fork_recovery.rs` | covered: bounded route lifecycle | covered: pairwise-loser terminalization | reconsiderable-loser engine regressions | The cross-adapter #1236 topology remains open. |
| `stored_convergence` | `distributed_convergence.rs` | partial: selector plus lifecycle models | covered: comparator and frozen membership | restart properties and convergence chaos | Route choice is not represented in the models. |
| `candidate_materialization` | `openmls_projection.rs` | partial: dependency/disposition model | covered: retention and frozen membership | OpenMLS replay and replay-budget repair | Live pairwise equivalence remains open. |
| `retained_history_replay` | `message_processor/ingest.rs`, `openmls_projection.rs` | partial: unequal-history lifecycle | covered: retention and witness deduplication | retained-relay equality and offline journeys | The #1236 topology has not run through this route. |
| `crash_restart_recovery` | `engine.rs`, `distributed_convergence.rs` | covered: crash/restart lifecycle | covered: frozen membership and scheduler re-arm | durable-phase kill and restart properties | Restarts have not crossed every #1236 transition. |
| `application_disposition` | `message_processor/ingest.rs`, `openmls_projection.rs` | covered: reference dispositions | covered: output invalidation | exact input ledgers and active decryptability | Sender-visible branch-replacement coverage is incomplete. |

## Assurance claims

Cross-route campaigns may produce evidence for these stable claim ids:

- `route-equivalence`
- `reconsiderable-loser`
- `restart-invariance`
- `exact-cryptographic-agreement`
- `active-bidirectional-decryptability`
- `complete-application-disposition`

A passing campaign can move an open claim to covered. Any field, soak,
mutation, or replay counterexample reopens it. Later green runs are retained as
evidence but cannot silently clear a known falsification; the falsification
must be resolved by explicit reviewed evidence.

## Active production work

MDK #1329 and its stacked #1293 are reviewing production behavior in the
missing-anchor and pairwise-route areas. This inventory intentionally describes
current `master` and does not encode either open PR's proposed result as an
oracle. If a route is removed or its source marker changes, the source audit
fails and the inventory must be reviewed before evidence is carried forward.
