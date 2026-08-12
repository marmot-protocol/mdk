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
| `ordinary_ingest` | `message_processor/ingest.rs` | partial: `reference_convergence::evaluate` | covered: cutoff admission and output invalidation | observer vectors, both strict cross-route regressions, the shared engine/app/process restart journey, and the app-runtime cross-route characterization | Corrected reversible relay input can still leave a two-branch public/probe split; process/distributed execution and exact app-runtime state remain open. |
| `pairwise_fork_recovery` | `message_processor/ingest.rs`, `fork_recovery.rs` | partial: bounded abstract route lifecycle | partial: sibling-model pairwise-loser terminalization | both strict cross-route regressions, app-runtime cross-route characterization, and pairwise reconsideration tests | The production-shaped app route does not reliably select the strict reference's winning branch; process/distributed and durable-transition permutations remain open. |
| `stored_convergence` | `distributed_convergence.rs` | partial: selector plus lifecycle models | covered: comparator and frozen membership | both strict cross-route regressions, app-runtime cross-route characterization, restart properties, and convergence chaos | Route choice is not represented in the models, and app-runtime/process/distributed equivalence remains open. |
| `candidate_materialization` | `openmls_projection.rs` | partial: dependency/disposition model | covered: retention and frozen membership | engine and retained-history cross-route recovery plus OpenMLS replay | Exact cryptographic and durable-disposition evidence remains limited to engine-capable subjects; app-runtime/process/distributed equivalence remains open. |
| `retained_history_replay` | `message_processor/ingest.rs`, `openmls_projection.rs` | partial: unequal-history lifecycle | covered: retention and witness deduplication | `cross-route-retained-history-recovery/v1`, `cross-route-app-runtime-recovery/v1`, retained-relay equality, offline journeys, and shared app/process offline full-history recovery | Reversible relay-wide app-runtime history removes the tombstone artifact but does not reliably produce public or active-chat equivalence; process, multi-relay, retention-boundary, and distributed evidence remain open. |
| `crash_restart_recovery` | `engine.rs`, `distributed_convergence.rs` | covered: crash/restart lifecycle | covered: frozen membership and scheduler re-arm | both strict cross-route encrypted-SQLite regressions, the app-runtime cross-route restart, durable-phase kill properties, and the shared engine/app/process restart journey | The adversarial app-runtime topology covers one post-displacement restart; every durable transition plus process/distributed adapters remain open. |
| `application_disposition` | `message_processor/ingest.rs`, `openmls_projection.rs` | covered: reference dispositions | covered: output invalidation | scenario-input ledgers and bidirectional decryptability probes in both strict cross-route regressions; app-runtime corrected-input characterization | Corrected-input runs can split the known chat inputs by branch; exact durable dispositions on external adapters and the existing sender-visible branch-replacement gap remain open. |

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

`cross-route-app-runtime-recovery/v1` keeps `route_equivalence`,
`active_bidirectional_decryptability`, and `complete_application_disposition`
open. The original simulator did contain a real input-contract bug: destructive
database deletion permanently tombstoned temporarily hidden event ids. After a
reversible query-visibility layer removed that artifact, repeated executions
still produced both complete equivalence and a two-branch protocol/probe split.
The corrected-input characterization accepts only reviewed terminal surfaces;
it is counterexample evidence, not passing assurance evidence.

## Active production work

MDK #1329 has merged the fail-closed missing-anchor behavior and Welcome-repair
retirement. Its formerly stacked #1293 remains open. This inventory describes
current `master` and does not encode #1293's proposed result as an oracle. If a
route is removed or its source marker changes, the source audit fails and the
inventory must be reviewed before evidence is carried forward.
