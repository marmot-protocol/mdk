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
| `ordinary_ingest` | `message_processor/ingest.rs` | partial: `reference_convergence::evaluate` | covered: cutoff admission and output invalidation | observer vectors plus both cross-route recovery regressions | Engine and retained-history committer/observer equivalence are covered; app-runtime and distributed adapters remain open. |
| `pairwise_fork_recovery` | `message_processor/ingest.rs`, `fork_recovery.rs` | partial: bounded abstract route lifecycle | partial: sibling-model pairwise-loser terminalization | both cross-route recovery regressions plus the pairwise reconsideration tests | Pairwise displacement and deeper-branch reconsideration are covered through retained-history delivery; app-runtime, distributed, and durable-transition permutations remain open. |
| `stored_convergence` | `distributed_convergence.rs` | partial: selector plus lifecycle models | covered: comparator and frozen membership | both cross-route regressions, restart properties, and convergence chaos | Route choice is not represented in the models, and app-runtime/distributed equivalence remains open. |
| `candidate_materialization` | `openmls_projection.rs` | partial: dependency/disposition model | covered: retention and frozen membership | engine and retained-history cross-route recovery plus OpenMLS replay | One live pairwise/materialization topology is covered through two delivery routes; app-runtime and distributed equivalence remains open. |
| `retained_history_replay` | `message_processor/ingest.rs`, `openmls_projection.rs` | partial: unequal-history lifecycle | covered: retention and witness deduplication | `cross-route-retained-history-recovery/v1`, retained-relay equality, and offline journeys | Multi-relay ordering, retention-boundary, and external-adapter permutations remain open. |
| `crash_restart_recovery` | `engine.rs`, `distributed_convergence.rs` | covered: crash/restart lifecycle | covered: frozen membership and scheduler re-arm | both cross-route encrypted-SQLite regressions plus durable-phase kill properties | Every durable transition and external adapter has not yet been crossed. |
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

MDK #1329 and its stacked #1293 are reviewing production behavior in the
missing-anchor and pairwise-route areas. This inventory intentionally describes
current `master` and does not encode either open PR's proposed result as an
oracle. If a route is removed or its source marker changes, the source audit
fails and the inventory must be reviewed before evidence is carried forward.
