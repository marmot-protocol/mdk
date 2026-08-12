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
| `ordinary_ingest` | `message_processor/ingest.rs` | partial: `reference_convergence::evaluate` | covered: cutoff admission and output invalidation | observer vectors, both strict cross-route regressions, the shared engine/app/process restart journey, and the app-runtime cross-route regression | The controlled app-runtime topology reaches the strict reference's public state and complete active-probe set; process/distributed execution and exact app-runtime state remain open. |
| `pairwise_fork_recovery` | `message_processor/ingest.rs`, `fork_recovery.rs` | partial: bounded abstract route lifecycle | partial: sibling-model pairwise-loser terminalization | both strict cross-route regressions, the app-runtime cross-route regression, and pairwise reconsideration tests | The app-runtime route now reaches the same public winning branch and active chat set; process/distributed and durable-transition permutations remain open. |
| `stored_convergence` | `distributed_convergence.rs` | partial: selector plus lifecycle models | covered: comparator and frozen membership | both strict cross-route regressions, the app-runtime cross-route regression, restart properties, and convergence chaos | Route choice is not represented in the models, and process/distributed equivalence remains open. |
| `candidate_materialization` | `openmls_projection.rs` | partial: dependency/disposition model | covered: retention and frozen membership | engine, retained-history, and app-runtime cross-route recovery plus OpenMLS replay | Exact cryptographic and durable-disposition evidence remains limited to engine-capable subjects; process/distributed equivalence remains open. |
| `retained_history_replay` | `message_processor/ingest.rs`, `openmls_projection.rs` | partial: unequal-history lifecycle | covered: retention and witness deduplication | `cross-route-retained-history-recovery/v1`, `cross-route-app-runtime-recovery/v1`, retained-relay equality, offline journeys, and shared app/process offline full-history recovery | Reversible relay-wide app-runtime history now reaches public equivalence and the complete active chat set; process, multi-relay, retention-boundary, and distributed evidence remain open. |
| `crash_restart_recovery` | `engine.rs`, `distributed_convergence.rs` | covered: crash/restart lifecycle | covered: frozen membership and scheduler re-arm | both strict cross-route encrypted-SQLite regressions, the app-runtime cross-route restart, durable-phase kill properties, and the shared engine/app/process restart journey | The adversarial app-runtime topology covers one post-displacement restart; every durable transition plus process/distributed adapters remain open. |
| `application_disposition` | `message_processor/ingest.rs`, `openmls_projection.rs` | covered: reference dispositions | covered: output invalidation | scenario-input ledgers and bidirectional decryptability probes in both strict cross-route regressions; exact app-runtime witness/probe-set equality | Every app-runtime participant exposes all five known chat inputs exactly once after settlement. Exact durable dispositions on external adapters and the existing sender-visible branch-replacement gap remain open. |

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

`cross-route-app-runtime-recovery/v1` now supplies passing public evidence for
`route_equivalence`, `active_bidirectional_decryptability`, and
`complete_application_disposition`: every app participant matches the strict
reference's public protocol state and exposes the witness plus four active
probes exactly once. Its former three terminal counterexamples were invalid
evidence. The simulator used the Nostr database's destructive delete operation
for temporary visibility; the database permanently tombstoned those event ids,
so the later unchecked restore left relay history incomplete. A reversible
query-visibility layer and focused hide/restore regression now pin the intended
input set. Process/distributed execution and exact external-adapter state remain
open, so this does not close the broader Milestone 6 claims by itself.

## Active production work

MDK #1329 has merged the fail-closed missing-anchor behavior and Welcome-repair
retirement. Its formerly stacked #1293 remains open. This inventory describes
current `master` and does not encode #1293's proposed result as an oracle. If a
route is removed or its source marker changes, the source audit fails and the
inventory must be reviewed before evidence is carried forward.
