# CGKA Simulator Scenarios

This is the human registry for simulator scenarios.

The JSON manifest and report files are the machine-readable inventory. This file explains what each scenario sets up,
what trouble it introduces, and what result the engine is supposed to produce.

## Scenario Types

Portable vectors live in `vectors/*.json`. They are the cross-implementation cases.

Rust-only harness scenarios live in `tests/canonical_scenarios.rs`. They cover engine behavior that still needs direct
harness access.

Generated families live in `src/family.rs`. They produce seeded adversarial `ScenarioSpec` cases. Promote one into
`vectors/` only when it should become a stable named contract.

Report and mechanics checks live in `tests/report_runner.rs` and `tests/canonical_scenarios.rs`. They check the
simulator tooling itself.

## Portable Scenario Vectors

These are the scenarios another implementation should be able to load from JSON and run.

### `three-client-message-exchange/v1`

- File: `vectors/three-client-message-exchange.v1.json`
- Setup: Alice creates a group with Bob and Carol. Each client sends one app message.
- Pressure: none. This is the smoke path.
- Expected: all three clients stay at epoch 1 with three members. Each client receives the other two payloads.

### `publish-fail/v1`

- File: `vectors/publish-fail.v1.json`
- Setup: Alice starts creating a group with Bob.
- Pressure: the create publish is reported as failed before the group is applied.
- Expected: Alice rolls back to the stable pre-publish state. The pending operation is recorded as rolled back.

### `invite-member/v1`

- File: `vectors/invite-member.v1.json`
- Setup: Alice creates a stable group with Bob, then invites Carol.
- Pressure: normal post-create invite path.
- Expected: Carol joins, recipients advance, and the trace records the member-add observation.

### `invite-publish-fail/v1`

- File: `vectors/invite-publish-fail.v1.json`
- Setup: Alice creates a stable group with Bob, then starts inviting Carol.
- Pressure: the invite publish is reported as failed.
- Expected: Alice restores the pre-invite epoch and member set. The group remains usable.

### `group-data-update/v1`

- File: `vectors/group-data-update.v1.json`
- Setup: Alice creates a group with Bob, then updates group data.
- Pressure: normal metadata commit path.
- Expected: recipients advance one epoch and keep the same member set.

### `current-profile-required-set/v1`

- File: `vectors/current-profile-required-set.v1.json`
- Setup: Alice creates a current-profile group with Bob, Bob joins from the founding Welcome, and Bob sends the
  group’s first application message.
- Contract: GroupContext requires extension `0x0006`, proposal `0x0008`, and application components `0x8003` and
  `0x8009`; `0x8003` has GroupContext state while `0x8009` is LeafNode-only.
- Expected: creation is canonical at epoch 1 without publishing or confirming an ordinary founding commit; both
  clients retain the two-member group, and Alice receives Bob’s first application message.

### `admin-policy-update/v1`

- File: `vectors/admin-policy-update.v1.json`
- Setup: Alice creates a group with Bob as a non-admin, rejects Bob's first admin-policy edit, promotes Bob, lets Bob
  make an admin-gated group-data update, and then Bob removes himself from the admin set.
- Pressure: admin-policy app-component validation, admin authorization, role convergence, and post-demotion denial.
- Expected: empty admin policies fail, non-admin updates fail, both clients observe Bob's promotion and later
  self-demotion, and both clients converge at epoch 4 with Alice as the sole admin.

### `group-data-fork-recovery/v1`

- File: `vectors/group-data-fork-recovery.v1.json`
- Setup: Alice and Bob both update group data from the same epoch.
- Pressure: same-epoch group-data commit race.
- Expected: the engine chooses one branch, rolls the loser back, and both clients converge at epoch 2.

### `concurrent-invite-fork-recovery/v1`

- File: `vectors/concurrent-invite-fork-recovery.v1.json`
- Setup: Alice and Bob both invite a different member from the same epoch.
- Pressure: same-epoch invite commit race.
- Expected: one invite branch wins, the other is invalidated, and active clients converge on the same member set.

### `convergence-committer-selected/v1`

- File: `vectors/convergence-committer-selected.v1.json`
- Setup: Alice and Bob are both admins; each invites a different member from the same epoch. Carol is a passive observer who commits nothing.
- Pressure: two competing privileged commits reach Carol at once, so her convergence selector — not the fork-recovery seam — picks the canonical branch.
- Expected: Carol's settled `convergence_decision` selects the branch by authenticated committer identity (`tip_committer`) at tip epoch 2, with no app-witness quorum.

### `convergence-witness-selected/v1`

- File: `vectors/convergence-witness-selected.v1.json`
- Setup: Alice and Bob are both admins; each invites a different member from the same epoch. Carol is a passive
  observer. Two distinct senders post app messages on Alice's branch, and Carol delivers (applies) them before Bob's
  competing same-epoch commit reaches her.
- Pressure: Carol has already delivered the app messages on Alice's branch when Bob's competing commit arrives, forcing
  a fork reorg. The app-witness quorum must survive that reorg and override the committer tiebreak — the case that
  matches real convergence-driven traffic.
- Expected: Carol's settled `convergence_decision` selects the witnessed branch at tip epoch 2 with `witness_quorum_met`
  and an app-witness score of 2 (decisive rule `effective_commit_depth`), and each app payload is delivered exactly once
  (no re-delivery on the reorg).

### `drop-queued/v1`

- File: `vectors/drop-queued.v1.json`
- Setup: Alice creates a group with Bob, then Bob sends Alice two app messages.
- Pressure: the first queued app message is dropped before delivery; the second is delivered.
- Expected: Alice stays stable, never receives the dropped payload, and receives only the delivered payload.

### `queue-faults/v1`

- File: `vectors/queue-faults.v1.json`
- Setup: Alice creates a group with Bob and Carol. Bob and Carol send app messages.
- Pressure: the bus duplicates, delays, releases, and reorders queued messages.
- Expected: Alice receives each valid payload once in the expected observed order. The Rust mechanics regression for
  this shape additionally captures the strict scenario-input ledger: two ingest attempts for the duplicated Bob event, one
  application acceptance, one delivery, one deduplication, and no remaining work for that event.

### `partition-clear-leave/v1`

- File: `vectors/partition-clear-leave.v1.json`
- Setup: Alice creates a group with Bob. Bob sends while partitioned, then sends after the partition clears and leaves.
- Pressure: partition, partition repair, and self-remove.
- Expected: Alice ignores the hidden partitioned payload, receives the visible payload, and ends with Bob removed.

### `delayed-past-epoch-app-message/v1`

- File: `vectors/delayed-past-epoch-app-message.v1.json`
- Setup: Alice creates a group with Bob and Carol. Bob sends an app message at epoch 1. Alice later invites David.
- Pressure: Bob's app message is delayed until Carol has advanced to epoch 2.
- Expected: Carol peels the late epoch-1 app message from retained context and emits the payload once.

### `restart-delivery-faults/v1`

- File: `vectors/restart-delivery-faults.v1.json`
- Setup: Alice creates a group with Bob and Carol. Bob sends Alice an app message.
- Pressure: Bob's message is delayed, Alice restarts, and the released message is duplicated and reordered.
- Expected: Alice hydrates the stable group after restart and receives Bob's payload once.

## Incident-Replay Vectors

These vectors are synthesized from Goggles `agent-state.json` forensic exports by the `incident-replay` adapter, then
verified against the simulator before they are committed. They live under `vectors/incidents/` and are not yet part of
the top-level portable-vector test (Phase 5 wires the directory into CI).

### `fork-recovery-incident/v1`

- File: `vectors/incidents/fork-recovery-incident.v1.json`
- Setup: two clients create a group, then raise competing group-data commits from the same epoch — the concurrent-fork
  shape the adapter derives from a fork-recovery incident.
- Pressure: same-epoch group-data commit race with deferred delivery (no partition needed; the commits are concurrent).
- Expected: the engine fork-recovers on delivery, the designated winner's branch survives, and both clients converge at
  epoch 2 with the full recovery summary matching the recorded incident.

### `membership-fork-recovery-incident/v1`

- File: `vectors/incidents/membership-fork-recovery-incident.v1.json`
- Setup: two committers create a group, then raise competing membership commits (an invite race) from the same epoch,
  with the two invitees held out by a partition — the membership-fork shape the adapter derives from a fork-recovery
  incident whose contested tip is a membership/admin commit (`member_added`/`member_removed`/`admin_added`/`admin_removed`).
- Pressure: same-epoch membership commit race with deferred delivery; the fork-recovery seam — not the convergence
  selector — resolves it.
- Expected: the engine fork-recovers on delivery and both committers converge at epoch 2 with `member_count == 3` — the
  winner-agnostic proof that exactly one branch's invite survived — and the full recovery summary matching the recorded
  incident. Unlike the group-data fork, the recovery is winner-agnostic (no branch-name label search), because real
  observer-recorded exports cannot join a commit's publisher (`account_ref`, the observing engine) to its committer
  (`actor_member_ref`, an MLS member id).

### `convergence-incident/v1`

- File: `vectors/incidents/convergence-incident.v1.json`
- Setup: two admins create a group with a passive observer, then raise competing invite commits from the same epoch —
  the committer-decided convergence shape the adapter derives from a convergence incident.
- Pressure: two competing same-epoch branches reach the observer, whose convergence selector — not the fork-recovery
  seam — picks the canonical branch.
- Expected: the observer's settled `convergence_decision` is decided by the authenticated-committer tiebreak
  (`tip_committer`) at tip epoch 2 with no app-witness quorum. Witness-decided convergence (the real-traffic case) is a
  documented follow-up: the harness does not yet count app-message witnesses through the stored-convergence path.

## Rust-Only Harness Scenarios

These are real simulator scenarios that are still tied to Rust harness details.

### `three_client_happy_path_via_harness`

- Setup: Alice creates a three-client group. Alice, Bob, and Carol each send one app message.
- Expected: all clients converge and each receives the other two messages.
- Reason: this duplicates the smoke vector at direct harness level.

### `exact_oracle_matches_full_canonical_state_after_join`

- Setup: Alice creates a group with Bob and Bob joins from the Welcome.
- Pressure: the strict conformance projection is captured independently from both live engines.
- Expected: every exact leaf/capability, required and application component, lifecycle/profile/admin field, GroupContext
  hash, and exporter commitment matches. Sentinel unit tests separately prove that different member identities or
  exporter commitments fail `ClientsExactlyEquivalent` even when epoch and member count match. Both joined clients
  also pass `NoPendingWork`.

### `exact_observation_ledgers_commit_proposal_and_application_dispositions`

- Setup: Alice and Bob settle a group, Alice publishes a group-data commit and application event, and Bob publishes a
  self-remove proposal.
- Pressure: the exact observation correlates each action through randomized transport and content-derived ids after the
  commit sender has already advanced MLS state.
- Expected: the ledger contains stable scenario ids for all three input classes, the confirmed commit and published
  application event are accepted, and the proposal exposes its exact current pending, convergence-deferred, or accepted
  disposition. Convergence-deferred proposals are reported distinctly from transport-pending input.

### `exact_oracle_projects_terminal_disband_tombstone_across_restart`

- Setup: a current-profile solo member creates a group, requests disband, and advances the normal convergence path
  until the authenticated disband commit terminalizes the group.
- Pressure: live MLS state is deleted; exact observation must use only the durable tombstone, then survive a full
  engine/storage restart.
- Expected: the tagged terminal canonical state preserves group id, epoch, actor, origin commit, commit digest, and the
  canonical former-member roster; it passes `NoPendingWork` and is byte-for-byte unchanged after restart.
- Sentinel: an engine unit test proves that device-local committer-leaf status, roster order, and duplicate roster rows
  do not change terminal equality.

### `bidirectional_decryptability_probe_passes_for_settled_members`

- Setup: Alice creates a settled three-member group with Bob and Carol.
- Pressure: the active probe sends one exact logical application event from each member and exercises all six directed
  sender-to-recipient edges through normal send, Nostr transport peel, MLS decrypt, and application delivery.
- Expected: all six edges deliver, the exact canonical snapshots remain equivalent, and the probe leaves no pending
  work.

### `bidirectional_decryptability_probe_exposes_asymmetric_epoch_reachability`

- Setup: Alice and Bob begin settled; Alice confirms a group-data commit whose transport object is then dropped, leaving
  Alice one epoch ahead of Bob.
- Pressure: the active probe runs in both directions.
- Expected: Bob's past-epoch event still decrypts at Alice, while Alice's future-epoch event remains
  `transport_deferred` at Bob. `ClientsBidirectionallyDecryptable` reports only the failed Alice-to-Bob edge.

### `bidirectional_decryptability_probe_rejects_a_named_nonmember`

- Setup: Alice and Bob form a group while attached client Carol is deliberately not invited.
- Pressure: Carol is included in the active probe client set.
- Expected: Carol's send is recorded as a typed failed probe and the complete directed matrix cannot pass.

### `no_pending_work_rejects_bus_queue_and_unread_mailbox`

- Setup: Bob sends an application event to Alice after a stable two-member join.
- Pressure: observe once while the transport object remains queued, then again after delivery but before Alice ingests
  her mailbox.
- Expected: the progress snapshot names `bus_queue` and `bus_mailboxes` as blockers; after Alice ticks, the exact
  snapshot is empty.

### `no_pending_work_rejects_delayed_transport_then_accepts_drained_delivery`

- Setup: Bob sends an application event to Alice and the bus moves it into a named delayed queue.
- Pressure: assert before and after release/delivery/ingest.
- Expected: `NoPendingWork` initially fails with `bus_delayed`, then passes after the logical event is delivered and all
  transport work drains.

### `no_pending_work_rejects_unconfirmed_publish`

- Setup: a stable group stages an invite without confirming publication.
- Pressure: exact observation while the engine remains in `PendingPublish`.
- Expected: `NoPendingWork` fails with an engine blocker even if public epoch/member facts otherwise look coherent.

### `no_pending_work_does_not_claim_delivery_of_dropped_application_input`

- Setup: Alice sends an application event to Bob after a stable two-member join, then a transport fault drops the queued
  object before Bob receives it.
- Pressure: compare each client's local pending-work snapshot with Bob's exact recipient ledger/output observation.
- Expected: `NoPendingWork` passes for both clients once their local work is empty, while the independent delivery
  expectation fails because Bob never observed the application input. This sentinel keeps local quiescence distinct
  from end-to-end delivery.

### `convergence_e2e_from_peeler_ingest_to_group_events`

- Setup: two admins create competing invite branches and each sends an application event on its branch; two passive
  observers ingest the real Nostr-wrapped transport objects.
- Expected: each observer delivers the selected branch event exactly once and never projects the losing event. If the
  losing transport object never peels, its ledger entry remains explicitly `transport_deferred` and pending rather than
  being falsely labeled application-accepted or losing-branch-invalidated.

### `delayed_past_epoch_app_message_peels_from_retained_anchor`

- Setup: Bob sends an epoch-1 app message. Alice advances the group by inviting David. The old app message arrives late.
- Expected: Carol processes the late app message by using retained epoch context.
- Reason: the fixed vector covers the same behavior; this test keeps byte-level storage state close.

### `add_then_self_remove_via_harness`

- Setup: Alice creates a group with Bob and Carol. Bob leaves. Alice auto-commits Bob's self-remove proposal.
- Expected: Alice, Bob, and Carol reach epoch 2, and Bob is removed from the active group.
- Reason: the direct harness asserts the auto-commit path and member state.

### `deliberate_fork_via_harness`

- Setup: Alice and Bob concurrently invite different new members while a partition hides each branch.
- Expected: one branch wins by deterministic ordering. One peer rolls back, and Alice and Bob end on the same member
  set.
- Reason: the test inspects recovery observations and exact branch ordering keys.

### `failed_invite_staging_does_not_poison_fork_detection_via_harness`

- Setup: Alice's invite fails during commit staging (duplicate-member KeyPackage). Alice then advances to epoch 2 by
  settling Bob's commit through convergence, and a partitioned Dave later delivers a sibling commit from the same
  source epoch.
- Expected: the sibling commit is adjudicated deterministically (stale losing branch or reorg onto the winner) — never
  a fail-closed `ForkedEpoch` — and Alice's group stays usable for a follow-up invite.
- Reason: regression guard for the phantom `committed_from` bookkeeping bug (fixed by recording it only inside
  `begin_pending`); mirrors the cgka-engine test `failed_invite_staging_does_not_poison_fork_detection` at the
  multi-client bus level.

### `convergence-e2e-group-events/v1`

- Setup: Alice creates a four-member group. Alice and Bob race invite commits and each branch has an app payload. Carol
  and Frank ingest through the real Nostr peeler path.
- Expected: observers accept the selected branch payload, exclude the losing branch payload, and converge at epoch 2.
- Reason: the trace does not yet carry enough selected-branch detail for a portable fixture.

### `welcome_before_commit_rejects_commit_echo_cleanly_via_harness`

- Setup: Bob is already in Alice's group. Alice invites Carol. Carol receives the welcome and the group-message echo
  together.
- Expected: Carol processes the welcome and retains the pre-join group wrapper as transport-deferred until it can be
  peeled or a local resource policy releases it.
- Reason: the trace format does not yet record stale classifications as portable expectations.

## Generated Scenario Families

Generated cases are deterministic for a fixed family, seed, and case index. They are run directly as generated coverage.
A generated case becomes a vector only when we want it to be a stable named contract: for example, when it caught a
regression, covers a new semantic edge, or is the smallest readable example of a behavior.

### `send-leave/v1`

- Generator: `generate_send_leave_family` (generator version `2`)
- Setup: three clients start in one group. The generator emits app sends and self-remove leaves.
- Expected: remaining live members converge on exact canonical state after a final global drain and report no pending
  work. The current leave shapes intentionally expose retained proposal/schedule work as a strict failure.

### `convergence-e2e-delivery/v1`

- Generator: `generate_convergence_e2e_delivery_family`
- Setup: the real-peeler invite-fork scenario runs with generated delivery mutations.
- Pressure: duplicate, delay, release, and reorder before observer clients tick.
- Expected: observers converge on one selected branch and emit only the selected branch payload.

### `convergence-chaos/v1`

- Generator: `generate_convergence_chaos_family` (generator version `6`).
- Setup: the family rotates through the case classes below.
- Expected: each case carries semantic expectations for convergence, rollback, payload delivery, or recovery, then
  performs a final global drain with exact-state and pending-work assertions.
- Seed behavior: the rollback (`2`) and storm shapes (`6`, `7`, `8`, `9`) draw their delivery schedule from the seed,
  so distinct seeds exercise distinct adversarial orderings. Convergence, rollback, and payload-set expectations are
  invariant under delivery schedule, so they stay fixed while coverage grows with the seed. The remaining shapes are
  pure functions of the case index.

#### Chaos Class `0`: Invite Fork

- Setup: Alice creates a group with Bob. Alice invites David while Bob invites Eve.
- Pressure: same-epoch invite race under restricted delivery.
- Expected: Alice and Bob converge at epoch 2 with one added member and one recovery observation.

#### Chaos Class `1`: Group-Data Fork

- Setup: Alice and Bob both update group data at epoch 1.
- Pressure: same-epoch metadata commit race.
- Expected: both clients converge at epoch 2 and record recovery from one losing branch.

#### Chaos Class `2`: Rollback Queue Faults

- Setup: Alice rolls back a group-data update. Bob sends several app messages after the rollback.
- Pressure: a seed-driven delivery reorder of the post-rollback messages, plus a duplicated and delayed copy of one app
  message released after Alice has already processed the original.
- Expected: Alice remains at epoch 1 and receives Bob's post-rollback payloads once each, in the seed-driven delivery
  order (the released app duplicate is deduped). Definite publication failure retracts the undelivered commit before
  local rollback, so Bob remains at epoch 1 and the strict final drain observes exact equivalence.

#### Chaos Class `3`: Partition Leave

- Setup: Bob sends while partitioned, sends again after heal, then leaves.
- Pressure: partition, heal, and self-remove.
- Expected: Alice receives only the post-heal payload and ends with Bob removed.

#### Chaos Class `4`: Delayed Past-Epoch App

- Setup: Bob's epoch-1 app message is delayed while Alice invites David.
- Pressure: late app delivery after an epoch advance, followed by controlled virtual-time advancement past the durable
  local deferred-peel residence deadline.
- Expected: Carol accepts the late app payload from retained context. David receives no historical payload; his opaque
  pre-join wrapper is released as `resource_refused` without terminal dedup, and strict pending work reaches zero.

#### Chaos Class `5`: Stable Queue Faults

- Setup: Bob and Carol send to Alice.
- Pressure: duplicate, delay, release, and reorder on stable app messages.
- Expected: Alice receives each valid payload once.

#### Chaos Class `6`: Large Message Storm

- Setup: Alice creates a 21-member group. Every other member sends.
- Pressure: large group plus a seed-driven app-message delivery reorder.
- Expected: Alice observes all expected payloads and stays at epoch 1 with 21 members.

#### Chaos Class `7`: Large Partitioned Storm

- Setup: Alice creates a 25-member group. Other members send while only Alice is allowed by the partition.
- Pressure: large group with partitioned delivery and a seed-driven reorder.
- Expected: Alice observes the expected payloads and keeps 25 members.

#### Chaos Class `8`: Large Commit Storm

- Setup: Alice creates a 21-member group. Eight members race group-data commits.
- Pressure: multi-committer same-epoch commit storm plus a seed-driven duplicate and reorder.
- Expected: the committers converge at epoch 2 with 21 members and the same branch-sensitive group name. Group-data
  commits change only the group name, so the convergence oracle compares the observed name (not just epoch and member
  count) to reject a permanent fork where committers settle on competing branches.

#### Chaos Class `9`: Mixed Large Storm

- Setup: Alice creates a 21-member group. Members send app messages, then eight members race group-data commits.
- Pressure: large app-message load (seed-driven reorder) followed by a commit storm with a seed-driven duplicate and reorder.
- Expected: the committers converge at epoch 2 with 21 members and the same branch-sensitive group name (see Chaos Class
  `8`). The application phase is not cleared: every observed committer must retain the exact seed-ordered payload set
  addressed to it, so the later commit storm cannot hide a dropped, duplicated, or unaccounted application message.

#### Chaos Class `10`: Restart Delivery Faults

- Setup: Bob sends to Alice, the message is delayed, Alice restarts, then delivery is duplicated and reordered.
- Pressure: restart plus delayed duplicate delivery.
- Expected: Alice hydrates from storage and receives Bob's payload once.
- Fixed vector: `restart-delivery-faults/v1`.

## Tooling And Report Checks

These tests keep the simulator machinery honest.

- `canonical_vector_fixtures_match_generated_traces` checks that every top-level JSON scenario vector still matches its
  expected trace or semantic outcomes.
- `tests/report_runner.rs` checks CLI parsing, report JSON writing, fixture-candidate and restrictive failure-capsule
  writing, exact transport capture, and pass/fail summaries.
- `tests/failure_capsules.rs` checks the v1 schema/round trip, owner-only artifact modes, portable synthetic promotion,
  and exact recipient-checkpoint plus captured-commit replay. Omitting the captured commit must change the fingerprint.
- `src/oracle.rs` and `tests/report_runner.rs` check that reports name their stimuli, expected behavior classes,
  observed behavior classes, and weak-oracle warnings.
- `virtual_time_is_capability_gated_serializable_and_dispatched` checks that `advance_time` round-trips through the
  portable scenario format, fails preflight for adapters without `virtual_time`, and dispatches the exact elapsed time.
- `engine_subject_virtual_time_is_shared_while_participant_wakes_are_selected` checks two real durable disband passes:
  a tick at 999 ms settles neither; at 1,000 ms Alice settles while unticked Bob stays live; Bob then settles on a later
  tick without another time advance.
- `structural_progress_is_stable_sanitized_and_names_publication_work` checks stable tokens for unchanged structure,
  exact outbound/transport work visibility, and the absence of identifiers and payload fields.
- `fixed_point_reports_manual_ack_blocker_then_settles`, `fixed_point_advances_exactly_to_engine_wake`, and
  `fixed_point_names_withheld_transport_without_spinning` check typed publication/withholding blockers and exact
  virtual-time advancement against real OpenMLS/SQLite subjects.
- `fixed_point_is_invariant_to_same_horizon_batch_partitioning` delivers the same competing commits in one frozen batch
  or two completed convergence passes, requires the same semantic canonical result, and diagnoses retention/anchor
  assumption violations separately from a result mismatch.
- `unchanged_runnable_work_times_out_without_becoming_quiescent` and
  `virtual_time_budget_is_a_watchdog_not_a_quiescence_definition` pin terminal timeout artifacts and ensure watchdogs
  cannot manufacture success.
- `outbound_poll_is_non_destructive_and_acknowledgement_is_idempotent` checks exact application artifacts, repeatable
  polling, same-outcome acknowledgement replay, transport delivery, and disappearance after resolution;
  `outbound_poll_preserves_emission_order_past_single_digit_handles` guards deterministic ordering under a burst.
- `pending_publication_identity_is_scoped_by_client` forces equal per-engine pending counters on two participants and
  proves one client's acceptance or rollback cannot resolve, suppress, or remove the other's publication.
- `evolution_commit_acknowledgement_and_welcome_outcome_are_independent` and
  `no_endpoint_commit_outcome_rolls_back_the_complete_unexposed_publication` check that accepted commits advance local
  state independently of Welcome delivery, while definite unexposed commit failure atomically retracts and rolls back
  the complete publication.
- `accepted_welcome_blocks_later_definite_commit_failure` treats transport acceptance as exposure evidence: it preserves
  the accepted Welcome outcome and leaves the state-bearing commit acknowledgeable instead of partially rolling back.
- `create_confirms_on_first_welcome_acceptance_and_keeps_other_welcomes_independent` checks creation acknowledgement
  semantics, `empty_creation_confirms_without_synthetic_outbound_work` covers creation with nothing to
  publish, and `scheduled_group_evolution_waits_for_public_outbound_acknowledgement` proves timer-produced evolution
  work stays pending until the public acknowledgement arrives.
- `regenerated_queued_intent_retries_then_retires_through_outbound_acknowledgement` proves a queued application is
  re-armed after definite failure, regenerated with a fresh artifact, and retired only after transport acceptance.
- `no_endpoint_outcome_is_rejected_after_recipient_exposure` prevents a caller from claiming definite non-publication
  after an artifact reached a recipient mailbox;
  `exposed_welcome_prevents_partial_commit_retraction_and_rollback` applies the same rule to the complete
  commit/Welcome publication so a failed rollback cannot partially mutate transport state.
- `failing_generated_case_records_a_minimized_reproducer` checks that semantic failure identity lets a failing
  generated case remove an entire irrelevant application-message storm even though action indices and the full state
  digest change.
- `failed_campaign_capsule_contains_a_replayable_tick_witness` checks that a real report campaign exports a sensitive
  recipient checkpoint plus exact mailbox bytes and that both the replay API and report CLI reproduce its fingerprint.
- `tests/generated_policy_cases.rs` checks that Tamarin-derived branch selector cases match the Rust selector across
  candidate orderings.

## Byte Fixtures

The `vectors/byte-fixtures/` files are conformance artifacts, but they are not simulator scenarios. They check byte
encoding and validation for app-component data such as Nostr routing component state and updates.

Keep those in the vector manifest. Add them here only if they become runnable `ScenarioSpec` fixtures.
