# CGKA Simulator Property Tests

Property tests generate many small cases and check rules that should hold for all of them. When one fails, proptest
shrinks the input so the failing case is easier to read.

General simulator properties live in `tests/proptest_invariants.rs`. The independent-reference differential property
stays in `tests/independent_reference_model.rs` beside the bounded policy corpus and its model/production conversion
helpers. Shared harness generators live in `src/proptest_support.rs`.

## Case Counts

`cargo test -p cgka-conformance-simulator` runs the normal count.

`cargo test -p cgka-conformance-simulator --features conformance-slow` raises the count for broader search.

| Property | Normal cases | Slow cases |
| --- | --- | --- |
| Candidate graph selection | 128 | 1000 |
| Canonicalization dispositions | 128 | 1000 |
| Canonicalization replay | 128 | 1000 |
| Quiescence gate | 128 | 1000 |
| Capability negotiation | 24 | 200 |
| Send/leave convergence | 24 | 1000 |
| Varied delivery convergence | 12 | 500 |
| Stored convergence restart equivalence | 8 | 40 |
| Group-data publish lifecycle | 12 | 200 |
| Same-id replay | 16 | 500 |
| Upgrade publish lifecycle | 8 | 200 |
| Independent reference differential | 256 | 256 |

## Properties

### `small_shrinkable_selector_inputs_match_independent_model`

- Generates: two bounded selector candidates, witness sets, and a convergence policy from a fixed ChaCha seed.
- Checks: the type-independent reference selector and production selector choose the same branch.
- Why: an independently restated policy can detect selector drift without coupling expected behavior to production
  code.

### `prop_candidate_graph_selection_is_order_invariant`

- Generates: candidate branch graphs with different fork depths, tip epochs, digests, witnesses, and policies.
- Checks: the selected branch is the same across original, reversed, rotated, and sorted candidate orderings. The
  selected branch must also be eligible.
- Why: relay order and local enumeration order must not change which branch wins.

### `prop_canonicalization_dispositions_are_order_invariant`

- Generates: symbolic proposal and app-message batches with selected-branch messages, losing-branch messages, pending
  proposals, duplicates, and delivery-order variants.
- Checks: accepted apps, invalidated apps, accepted proposals, dropped proposals, and already-seen messages stay the
  same after reordering.
- Why: the convergence layer must classify messages by branch validity and message id, not by arrival order.

### `prop_canonicalization_replay_is_already_seen`

- Generates: the same symbolic batch shape as the disposition property, with every message id already in the seen set.
- Checks: replay emits no app output, no invalidations, no drops, and no accepted proposals or commits. Every replayed
  occurrence is reported as already seen.
- Why: replay should be idempotent and should not produce app-visible events twice.

### `prop_quiescence_gate_controls_settlement`

- Generates: a selected commit, an outbound app intent, a generated settlement window, and an early timestamp inside that
  window.
- Checks: before the window closes, convergence status stays `Syncing` and outbound work stays queued. At the window boundary,
  the same input becomes `Settled` and releases outbound work.
- Why: the engine should wait for branch races to settle before publishing queued local work.

### `prop_capability_negotiation_matches_matrix`

- Generates: feature requirement levels, invitee support matrices, and create-time required-feature choices.
- Checks: missing required support rejects group creation. Supported required features become `Available`. Optional
  unsupported features become `Unavailable`. Optional supported features become `Upgradeable`.
- Why: capability negotiation should be predictable before a group is created and while deciding if a feature can be
  enabled later.

### `prop_convergence_under_send_leave_sequence`

- Generates: three-client groups plus app sends and self-remove leaves under FIFO delivery.
- Checks: every still-live member converges on the same epoch, member-id set, group name, and app-payload multiset after the
  sequence drains. The payload multiset combines each client's received remote payloads with its own accepted sends, since
  senders never receive their own messages back.
- Why: common user activity should converge across many generated histories, and epoch equality alone would stay green
  under a membership or group-data branch fork.

### `prop_convergence_under_varied_delivery`

- Generates: send/leave intent sequences plus a delivery profile: FIFO, reverse, or seeded random.
- Checks: still-live members converge on the same epoch, member-id set, group name, and app-payload multiset under each
  delivery policy.
- Why: the same logical history should survive realistic relay ordering differences without diverging on membership,
  group metadata, or delivered payloads.

### `prop_stored_convergence_restart_equivalence`

- Generates: a three-client group, a generated group-data name, and a chosen committer.
- Checks: converging stored OpenMLS messages before restart and after rebuilding the engine over the same storage
  produces the same result, epoch, group name, and member count.
- Why: durable convergence input should replay the same way after process restart.

### `prop_group_data_update_publish_lifecycle`

- Generates: a group-data name and a publish outcome: confirm or fail.
- Checks: confirm keeps the projected epoch and group name. Fail restores the previous stable state and permits a retry.
- Why: group metadata updates must obey the same pending-publish lifecycle as other group evolutions.

### `prop_true_same_id_replay`

- Generates: a two-client group and app payload bytes.
- Checks: the first delivery processes. Injecting the exact same transport message again returns
  `Stale { AlreadySeen }`, leaves the epoch unchanged, and emits no new events.
- Why: duplicate relay delivery must be safe.

### `prop_upgrade_confirm_or_fail_round_trip`

- Generates: a two-client group and a publish outcome for an upgrade.
- Checks: confirm advances one epoch. Fail restores the prior epoch and a retry can advance normally.
- Why: pending-publish rollback must leave the group in a reusable stable state.

## Cross-Adapter Contract Tests

### `engine_app_runtime_and_process_adapters_reach_equivalent_public_state`

- Runs: one canonical three-participant IR through the engine harness, the in-process `MarmotAppRuntime` adapter, and
  three isolated app participant processes.
- Checks: explicit accepted-publication checkpoints retain the same meaning for the engine's staged transport and the
  app adapters' already-published commands; all participants agree on epoch, roster, profile, and administrator state
  after a durable restart; app-runtime and process projections retain the same application-message multiset and public
  state commitment.
- Boundary: the engine harness exposes inbound delivery events, not the app's durable local-sender projection, and its
  event window is intentionally cleared by restart. The test compares those narrower engine observations only where
  their semantics overlap. On app/process adapters, a labelled accepted acknowledgement attests that the mutation's
  production command returned after publishing; the resulting `PendingResolution { resolution: "confirmed" }` is not
  independent transport-delivery evidence on those subjects. It does not claim exact MLS-state or
  active-decryptability evidence from app/process adapters.
- Why: fixture portability and capability preflight alone do not prove that production-shaped adapters execute the
  same scenario meaning.

### `app_runtime_and_process_adapters_recover_the_same_offline_projection`

- Runs: a companion form of the same three-participant IR through the app-runtime and separate-process adapters, the
  two subjects that declare participant-connectivity and retained-history capabilities.
- Checks: Bob misses a profile commit and application message while offline, Carol durably restarts, Bob reconnects,
  every participant performs a full-history repair, and both adapters reach the same public protocol commitment,
  roster, profile, administration, and duplicate-free application-message set. Bob's app-local online, reopen, and
  catch-up diagnostics pin the offline/recovery precondition rather than inferring it only from the final projection.
- Boundary: this is public projection evidence. Adapter-local message ids, runtime event counts, database paths, and
  other execution-specific observations are deliberately not compared.

### `four_party_cross_route_recovery_app_runtime_matches_unified_route`

- Runs: the four-participant cross-route topology through both the strict retained-engine subject and the full
  `MarmotAppRuntime` adapter. The app harness's real in-memory Nostr relay associates retained events with stable
  Scenario IR action ids. After verifying every harness participant is offline, a reversible database wrapper filters
  a selected event from relay queries without tombstoning the underlying event, then exposes the same retained event
  before full-history repair. This is deliberately relay-wide rather than the strict retained-relay subject's
  per-recipient visibility model, and avoids treating process timing or a live relay race as controlled delivery.
  Action selectors cover group-message events and action-local Welcome gift wraps admitted before a successful
  serialized app command returns; publications deferred beyond that command boundary (for example, a scheduled
  self-update) are not action-addressable on this adapter.
- Checks: the retained-engine reference reaches exact canonical equality, durable accepted/invalidated/accepted commit
  dispositions, no pending work, and all twelve active decryptability edges. The app run pins the intended split at
  the intermediate checkpoint, then requires every participant to reach the reference epoch, roster, administration,
  and depth-two profile with the complete, duplicate-free probe set and no pending confirmation. Participant-local
  invalidated-row evidence still follows the losing-branch withdrawal rule without comparing opaque local ids.
- Regression: the original harness used the Nostr database's destructive `delete` operation for temporary
  invisibility. That permanently tombstoned the event id, and a later unchecked `save_event` could not restore it. The
  old runs therefore did not prove the claimed restored-input contract. The focused
  `retained_relay_control_restores_hidden_history_for_offline_repair` test now pins that contract. After route
  unification and the queued-send scheduling repair, the positive oracle rejects every previously reviewed lag,
  missing-probe, and branch-split terminal surface. The ignored
  `four_party_cross_route_recovery_app_runtime_equivalence_soak` repeats the complete retained-control/app-runtime
  trial twenty times for reviewed evidence without adding that runtime to normal CI; the post-change PR run reached
  full public equivalence in all twenty trials.
- Boundary: the app adapter exposes public protocol and application projections, not exact MLS-state commitments, the strict
  subject's durable input ledger, or active decryptability probes; those stronger retained-engine checks remain a
  control rather than an app-runtime claim.

### `four_party_cross_route_recovery_processes_match_unified_route`

- Runs: the exact same `cross-route-app-runtime-recovery/v1` Scenario IR and digest through four child processes, each
  owning one full `MarmotAppRuntime` and an isolated encrypted SQLite root. The parent owns the same reversible local
  retained-relay control used by the in-process app harness. Offline actions checkpoint the public observation and
  stop the child/runtime, so open subscriptions cannot buffer events across the intended transport disconnection;
  reconnect reopens the same durable participant root.
- Checks: exact expanded schedule and input digest, four complete public checkpoints, the controlled two-branch
  intermediate state, final epoch/roster/admin/profile agreement, the complete duplicate-free five-message set, no
  pending confirmation, participant-local losing-branch withdrawal rules, one public commitment, and a real durable
  Zeta reopen. An ignored twenty-trial soak repeats the full process route outside normal CI.
- Boundary: runner-owned local relays declare `retained_relay_control`; externally supplied relay URLs fail capability
  preflight rather than pretending the runner can hide or restore their events. The process protocol still does not
  expose exact MLS commitments, durable input dispositions, or active decryptability probes. VM execution remains
  open.

### `four_party_cross_route_recovery_containers_match_unified_route`

- Runs: the exact shared four-party Scenario IR through the distributed container backend, with one non-root OCI
  container and one encrypted durable root per participant plus the runner-owned retained relay on an isolated
  network. Zeta's scenario-owned restart removes and recreates its participant container over the same durable root.
- Checks: the manifest source digest and canonical IR digest, exact expanded schedule, controlled intermediate split,
  stable final public protocol/application projection, losing-branch withdrawal rule, one public commitment, real
  durable reopen, successful infrastructure commands, and complete cleanup.
- Evidence: the nightly and weekly/manual lanes retain the exact scenario, normalized manifest, process report,
  distributed receipt, and any failure-corpus entry under `target/cgka-distributed-container-evidence`. Encrypted
  participant roots and the opaque-token relay control plane are ephemeral and are not uploaded.
- Boundary: this reuses the process protocol's strict public oracle. It does not claim exact MLS-state commitment,
  durable input dispositions, or active decryptability from a black-box container adapter.

## Shared Generators

### `intent_seq(3, range)`

Generates weighted send and leave sequences. Sends carry generated byte payloads. Leaves use non-admin clients.

Used by the send/leave convergence properties.

### `delivery_profile()`

Generates FIFO, reverse, or seeded-random bus delivery.

Used by varied delivery convergence.

### `confirm_outcome()`

Generates `Confirm` or `Fail`, skewed toward confirm.

Used by upgrade and group-data publish lifecycle properties.

### Local Symbolic Generators

Generate candidate graphs, canonicalization batches, quiescence inputs, capability matrices, and restart cases.

Used by selector, canonicalization, capability, quiescence, and restart properties.

### `generate_stateful_chat_journey_family(seed, cases)`

Generates ordinary canonical Scenario IR v3 from a symbolic legality model rather than driving `HarnessClient`
directly. The model tracks membership, administrator authority, connectivity, profile values, epochs, and recipient
delivery. It emits membership and retained-history profiles separately so pre-admission transport retry state is not
misclassified as a no-pending failure.

The generator is deterministic by family name, independent generator version, seed, and case index, plus a separately
versioned workload profile when applicable. Existing semantic reduction minimizes a saved failing scenario after
execution. `tests/stateful_generator.rs` independently replays the legal-action preconditions, checks the complete
action vocabulary across adjacent cases, runs both profiles through the report path, and verifies that the input
fixture was saved privately before execution.

### `generate_large_group_pressure_family(seed, cases)`

Generates a replay-stable large-group catalog with a separately versioned workload profile. Six consecutive arms at
each size cover application-heavy fanout, incremental growth, sparse-admin sequential commits, up to sixteen competing
committers, interleaved application/commit traffic, and administrator handoff with remove/re-add plus restart. Size
blocks are cost-ordered at 10/16/20/32/50/64/100/128/200 members; metadata retains the 16/32/64/128 anchor and
10/20/50/100/200 boundary distinction.

`tests/large_group_family.rs` pins same-seed determinism, different-seed variation, prefix stability, family
registration, every size/admin regime, non-degenerate race arms, required action interactions, profile replay
provenance, exact retained-join versus strict pending-work coverage, and bounded decryptability cohorts that preserve
late-join/re-add and roster-tail representatives. The ordinary lane executes 10-member application-heavy and
incremental-join canaries. The suite compiles all 54 catalog shapes but does not execute large/xlarge cases in the
normal PR path.

### `generate_offline_catchup_pressure_family(seed, cases)`

Generates a replay-stable retained-relay catalog for large terminal catch-up. Bob is a founding member, goes offline
before workload generation, and reconnects only after every application and state commit has been retained. Four
cost-ordered volume blocks contain 24/96/384/1,024 application messages and 4/8/12/16 commit rounds. Six arms cover
natural and reverse history, reverse three-copy replay, natural two-copy incremental plus full repair, reverse two-copy
restart after sync but before processing, and reverse three-copy competing commit waves.

`tests/offline_catchup_family.rs` pins same-seed determinism, different-seed variation, prefix stability, registration,
profile provenance (including exact distinct-committer and retained-copy counts), every volume/recovery arm,
terminal-only reconnect, the pre-catch-up zero-delivery boundary, the post-catch-up exact-one boundary, full Bob payload
multiplicity, exact canonical equivalence, no pending work, active decryptability, and encrypted file-backed
natural/duplicate canaries. The ordinary test lane executes only two 24-message cases; larger blocks belong in isolated
manual or scheduled campaigns.

### `cross-route-restart-permutations/v1`

This bounded current-build catalog adds one reviewed durable reopen to the shared four-party cross-route scenario.
Twelve consecutive cases cover accepted create/admin/profile publications, the branch witness, branch ingestion, and
all four participants after retained-history repair. Seeds rotate the catalog rather than changing its membership, so
shards remain deterministic and a twelve-case run has a clear completeness claim. The generated family exercises the
full app runtime and strict public projection/payload oracle. A separate exact retained-engine family uses the same
isolated child runner so panic-shaped failures do not abort later cases. The complete public seed-0 catalog passed
12/12. The first exact run passed 9/12 and exposed three early Zeta publication-boundary failures. Minimization traced
them to cross-incarnation reuse of process-local pending handles in the simulator harness. Incarnation-scoped
bookkeeping fixed that adapter defect in MDK #1465, and the exact seed-0 catalog now passes 12/12 without a production
engine change. An explicit ignored test replays the catalog through the isolated-process adapter, whose validation
binds every restart action id to a matching durable `restarted` lifecycle event.

## Current Gaps

- The shrinkable `HarnessIntent` strategy remains intentionally limited to send/leave. Invites and group-profile
  updates are now generated by the canonical `chat-journey/v1` family, whose saved failures use semantic reduction
  rather than proptest shrinking.
- Partition behavior is covered by fixed scenarios and generated families. The property-test delivery profiles cover
  FIFO, reverse, and seeded random delivery.
- File-backed restart and subprocess-kill coverage exercises close/reopen and crash recovery with an intact encrypted
  database and WAL. The current cross-route catalog covers reviewed public/durable action boundaries, while the
  engine's separate crash-hook matrix covers its four internal convergence-pass phases. Recovery from genuinely
  missing or corrupted local records is still future work.
