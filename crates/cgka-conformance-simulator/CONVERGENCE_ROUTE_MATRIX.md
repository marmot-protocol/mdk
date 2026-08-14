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
| `ordinary_ingest` | `message_processor/ingest.rs` | partial: `reference_convergence::evaluate` | covered: cutoff admission and output invalidation | observer vectors, both strict cross-route regressions, the shared engine/app/process restart journey, and positive app-runtime, isolated-process, and four-container cross-route runs | App/process/container evidence is limited to public projections; VM execution and exact external-adapter state remain open. |
| `stored_convergence` | `distributed_convergence.rs` | partial: selector plus lifecycle models | covered: comparator and frozen membership | both strict cross-route regressions, positive app-runtime, isolated-process, and four-container cross-route runs, restart properties, convergence chaos, and the two reconsideration regressions inherited from the retired pairwise route | Route choice is not represented in the models; exact external-adapter and distributed VM evidence remains open. |
| `candidate_materialization` | `openmls_projection.rs` | partial: dependency/disposition model | covered: retention and frozen membership | engine and retained-history cross-route recovery, OpenMLS replay, and public four-container cross-route equivalence | Exact cryptographic and durable-disposition evidence remains limited to engine-capable subjects; app-runtime/process/container/VM evidence is public-projection only. |
| `retained_history_replay` | `message_processor/ingest.rs`, `openmls_projection.rs` | partial: unequal-history lifecycle | covered: retention and witness deduplication | `cross-route-retained-history-recovery/v1`, `cross-route-app-runtime-recovery/v1`, retained-relay equality, offline journeys, shared app/process offline full-history recovery, the controlled four-process route, and the same four-party IR through containers | Runner-owned reversible retained history now produces public equivalence through app-runtime, isolated-process, and container adapters; multi-relay, retention-boundary, external-relay, and VM evidence remain open. |
| `crash_restart_recovery` | `engine.rs`, `distributed_convergence.rs` | covered: crash/restart lifecycle | covered: frozen membership and scheduler re-arm | both strict cross-route encrypted-SQLite regressions, app-runtime, isolated-process, and four-container cross-route restart, durable-phase kill properties, and the shared engine/app/process restart journey | The adversarial production-shaped adapters cover one post-displacement restart; every durable transition plus VM execution remain open. |
| `application_disposition` | `message_processor/ingest.rs`, `openmls_projection.rs` | covered: reference dispositions | covered: output invalidation | scenario-input ledgers and bidirectional decryptability probes in both strict cross-route regressions; complete duplicate-free public app projections in app-runtime, process, and container cross-route runs | Exact durable dispositions on external adapters and the existing sender-visible branch-replacement gap remain open. |

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

`cross-route-app-runtime-recovery/v1` now supplies positive public
`route_equivalence` evidence through the in-process app runtime, four isolated
app processes, and the scheduled four-container checkpoint. It does not close `exact_cryptographic_agreement`,
`active_bidirectional_decryptability`, or `complete_application_disposition`
for those black-box adapters because their public observation schema does not
expose the required engine-private evidence. The original simulator did contain a real input-contract bug: destructive
database deletion permanently tombstoned temporarily hidden event ids. After a
reversible query-visibility layer removed that artifact, historical
pre-unification executions still produced both complete equivalence and a
two-branch protocol/probe split. Those runs remain counterexample evidence for
their tested snapshots; the post-unification positive app-runtime and process
oracles reject every such terminal split.

Its losing-branch surface is stated as a rule rather than an enumeration of
observed shapes, because which participants transiently hold the losing branch
is a delivery-order detail. Every participant that applies the losing commit
synthesizes that commit's kind-1210 rename row and owes it a withdrawal on
leaving the branch — the losing committer unconditionally, an observer that
adopted the branch before the selected one displaced it, and no one else.

## Retired routes

A deleted route is removed from the table and from `DecisionRouteId` rather
than re-pointed at a surviving seam. Re-pointing would give one seam two route
claims and count its evidence twice, which is exactly the inflation the source
audit exists to prevent. The audit failing on a vanished marker is the intended
trigger for that review, not an obstacle to it.

Retired by MDK #1293 (option C route unification): `pairwise_fork_recovery`,
whose owners were `message_processor/ingest.rs` and `fork_recovery.rs`. The
pairwise same-epoch route was deleted — `fork_recovery.rs` is gone and ingest no
longer calls `.resolve_fork_candidate(` — and same-epoch rivals are now
adjudicated by distributed convergence, which is already registered as
`stored_convergence`. The route's two cited properties survived the unification
as renamed engine regressions,
`incumbent_committer_defers_to_deeper_convergence_branch` and
`rival_win_leaves_displaced_own_commit_reconsiderable`, and are now cited as
campaign evidence for `stored_convergence`; its reconsiderable-loser rule is
folded into that route's adopted rule. The abstract route-lifecycle mutant it
sponsored survives route-agnostically as `provisional_winner_terminalization`
in the mutation catalog.

## Active production work

MDK #1329 and the formerly stacked #1293 have both merged. This inventory
describes current `master`, including #1293's unified same-epoch route. If a
route is removed or its source marker changes, the source audit fails and the
inventory must be reviewed before evidence is carried forward.
