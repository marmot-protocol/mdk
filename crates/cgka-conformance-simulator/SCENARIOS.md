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

### `drop-queued/v1`

- File: `vectors/drop-queued.v1.json`
- Setup: Alice creates a group with Bob, then Bob sends Alice an app message.
- Pressure: the queued app message is dropped before delivery.
- Expected: Alice stays stable and does not receive the dropped payload.

### `queue-faults/v1`

- File: `vectors/queue-faults.v1.json`
- Setup: Alice creates a group with Bob and Carol. Bob and Carol send app messages.
- Pressure: the bus duplicates, delays, releases, and reorders queued messages.
- Expected: Alice receives each valid payload once in the expected observed order.

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

## Rust-Only Harness Scenarios

These are real simulator scenarios that are still tied to Rust harness details.

### `three_client_happy_path_via_harness`

- Setup: Alice creates a three-client group. Alice, Bob, and Carol each send one app message.
- Expected: all clients converge and each receives the other two messages.
- Reason: this duplicates the smoke vector at direct harness level.

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

### `convergence-e2e-group-events/v1`

- Setup: Alice creates a four-member group. Alice and Bob race invite commits and each branch has an app payload. Carol
  and Frank ingest through the real Nostr peeler path.
- Expected: observers accept the selected branch payload, exclude the losing branch payload, and converge at epoch 2.
- Reason: the trace does not yet carry enough selected-branch detail for a portable fixture.

### `welcome_before_commit_rejects_commit_echo_cleanly_via_harness`

- Setup: Bob is already in Alice's group. Alice invites Carol. Carol receives the welcome and the group-message echo
  together.
- Expected: Carol processes the welcome and treats the pre-join group wrapper as stale peel failure.
- Reason: the trace format does not yet record stale classifications as portable expectations.

## Generated Scenario Families

Generated cases are deterministic for a fixed family, seed, and case index. They are run directly as generated coverage.
A generated case becomes a vector only when we want it to be a stable named contract: for example, when it caught a
regression, covers a new semantic edge, or is the smallest readable example of a behavior.

### `send-leave/v1`

- Generator: `generate_send_leave_family`
- Setup: three clients start in one group. The generator emits app sends and self-remove leaves.
- Expected: remaining live members converge on the same epoch and member set.

### `convergence-e2e-delivery/v1`

- Generator: `generate_convergence_e2e_delivery_family`
- Setup: the real-peeler invite-fork scenario runs with generated delivery mutations.
- Pressure: duplicate, delay, release, and reorder before observer clients tick.
- Expected: observers converge on one selected branch and emit only the selected branch payload.

### `convergence-chaos/v1`

- Generator: `generate_convergence_chaos_family`
- Setup: the family rotates through the case classes below.
- Expected: each case carries semantic expectations for convergence, rollback, payload delivery, or recovery.

#### Chaos Class `0`: Invite Fork

- Setup: Alice creates a group with Bob. Alice invites David while Bob invites Eve.
- Pressure: same-epoch invite race under restricted delivery.
- Expected: Alice and Bob converge at epoch 2 with one added member and one recovery observation.

#### Chaos Class `1`: Group-Data Fork

- Setup: Alice and Bob both update group data at epoch 1.
- Pressure: same-epoch metadata commit race.
- Expected: both clients converge at epoch 2 and record recovery from one losing branch.

#### Chaos Class `2`: Rollback Queue Faults

- Setup: Alice rolls back a group-data update. Bob sends after the rollback.
- Pressure: duplicate and delayed app delivery after rollback.
- Expected: Alice remains at epoch 1 and receives Bob's post-rollback payload once.

#### Chaos Class `3`: Partition Leave

- Setup: Bob sends while partitioned, sends again after heal, then leaves.
- Pressure: partition, heal, and self-remove.
- Expected: Alice receives only the post-heal payload and ends with Bob removed.

#### Chaos Class `4`: Delayed Past-Epoch App

- Setup: Bob's epoch-1 app message is delayed while Alice invites David.
- Pressure: late app delivery after an epoch advance.
- Expected: Carol accepts the late app payload from retained context.

#### Chaos Class `5`: Stable Queue Faults

- Setup: Bob and Carol send to Alice.
- Pressure: duplicate, delay, release, and reorder on stable app messages.
- Expected: Alice receives each valid payload once.

#### Chaos Class `6`: Large Message Storm

- Setup: Alice creates a 21-member group. Every other member sends.
- Pressure: large group plus reversed app-message delivery.
- Expected: Alice observes all expected payloads and stays at epoch 1 with 21 members.

#### Chaos Class `7`: Large Partitioned Storm

- Setup: Alice creates a 25-member group. Other members send while only Alice is allowed by the partition.
- Pressure: large group with partitioned delivery.
- Expected: Alice observes the expected payloads and keeps 25 members.

#### Chaos Class `8`: Large Commit Storm

- Setup: Alice creates a 21-member group. Eight members race group-data commits.
- Pressure: multi-committer same-epoch commit storm plus duplicate and reorder.
- Expected: the committers converge at epoch 2 with 21 members.

#### Chaos Class `9`: Mixed Large Storm

- Setup: Alice creates a 21-member group. Members send app messages, then eight members race group-data commits.
- Pressure: large app-message load followed by a commit storm.
- Expected: the committers converge at epoch 2 with 21 members.

#### Chaos Class `10`: Restart Delivery Faults

- Setup: Bob sends to Alice, the message is delayed, Alice restarts, then delivery is duplicated and reordered.
- Pressure: restart plus delayed duplicate delivery.
- Expected: Alice hydrates from storage and receives Bob's payload once.
- Fixed vector: `restart-delivery-faults/v1`.

## Tooling And Report Checks

These tests keep the simulator machinery honest.

- `canonical_vector_fixtures_match_generated_traces` checks that every top-level JSON scenario vector still matches its
  expected trace or semantic outcomes.
- `tests/report_runner.rs` checks CLI parsing, report JSON writing, fixture-candidate writing, and pass/fail summaries.
- `src/oracle.rs` and `tests/report_runner.rs` check that reports name their stimuli, expected behavior classes,
  observed behavior classes, and weak-oracle warnings.
- `failing_generated_case_records_a_minimized_reproducer` checks that a failing generated case records a smaller
  reproducer when removable delivery noise is enough to keep the same failure.
- `tests/generated_policy_cases.rs` checks that Tamarin-derived branch selector cases match the Rust selector across
  candidate orderings.

## Byte Fixtures

The `vectors/byte-fixtures/` files are conformance artifacts, but they are not simulator scenarios. They check byte
encoding and validation for app-component data such as Nostr routing component state and updates.

Keep those in the vector manifest. Add them here only if they become runnable `ScenarioSpec` fixtures.
