# CGKA Simulator Property Tests

Property tests generate many small cases and check rules that should hold for all of them. When one fails, proptest
shrinks the input so the failing case is easier to read.

The tests live in `tests/proptest_invariants.rs`. Shared generators live in `src/proptest_support.rs`.

## Case Counts

`cargo test -p cgka-conformance-simulator` runs the normal count.

`cargo test -p cgka-conformance-simulator --features conformance-slow` raises the count for broader search.

| Property | Normal cases | Slow cases |
|---|---:|---:|
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

## Properties

### `prop_candidate_graph_selection_is_order_invariant`

- Generates: candidate branch graphs with different fork depths, tip epochs, digests, witnesses, and policies.
- Checks: the selected branch is the same across original, reversed, rotated, and sorted candidate orderings. The
  selected branch must also be eligible.
- Why: relay order and local enumeration order must not change which branch wins.

### `prop_canonicalization_dispositions_are_order_invariant`

- Generates: symbolic proposal and app-message batches with selected-branch messages, losing-branch messages,
  pending proposals, duplicates, and delivery-order variants.
- Checks: accepted apps, invalidated apps, accepted proposals, dropped proposals, and already-seen messages stay the
  same after reordering.
- Why: the convergence layer must classify messages by branch validity and message id, not by arrival order.

### `prop_canonicalization_replay_is_already_seen`

- Generates: the same symbolic batch shape as the disposition property, with every message id already in the seen
  set.
- Checks: replay emits no app output, no invalidations, no drops, and no accepted proposals or commits. Every replayed
  occurrence is reported as already seen.
- Why: replay should be idempotent and should not produce app-visible events twice.

### `prop_quiescence_gate_controls_stability`

- Generates: a selected commit, an outbound app intent, a generated stability window, and an early timestamp inside
  that window.
- Checks: before the window closes, sync state stays `Syncing` and outbound work stays queued. At the window boundary,
  the same input becomes `Stable` and releases outbound work.
- Why: the engine should wait for branch races to settle before publishing queued local work.

### `prop_capability_negotiation_matches_matrix`

- Generates: feature requirement levels, invitee support matrices, and create-time required-feature choices.
- Checks: missing required support rejects group creation. Supported required features become `Available`. Optional
  unsupported features become `Unavailable`. Optional supported features become `Upgradeable`.
- Why: capability negotiation should be predictable before a group is created and while deciding if a feature can be
  enabled later.

### `prop_convergence_under_send_leave_sequence`

- Generates: three-client groups plus app sends and self-remove leaves under FIFO delivery.
- Checks: every still-live member converges on the same epoch after the sequence drains.
- Why: common user activity should converge across many generated histories.

### `prop_convergence_under_varied_delivery`

- Generates: send/leave intent sequences plus a delivery profile: FIFO, reverse, or seeded random.
- Checks: still-live members converge on the same epoch under each delivery policy.
- Why: the same logical history should survive realistic relay ordering differences.

### `prop_stored_convergence_restart_equivalence`

- Generates: a three-client group, a generated group-data name, and a chosen committer.
- Checks: converging stored OpenMLS messages before restart and after rebuilding the engine over the same storage
  produces the same result, epoch, group name, and member count.
- Why: durable convergence input should replay the same way after process restart.

### `prop_group_data_update_publish_lifecycle`

- Generates: a group-data name and a publish outcome: confirm or fail.
- Checks: confirm keeps the projected epoch and group name. Fail restores the previous stable state and permits a
  retry.
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

## Current Gaps

- Generated `HarnessIntent` values do not include invite or group-data updates. Fixed scenarios and separate lifecycle
  properties cover those today.
- Partition behavior is covered by fixed scenarios and generated families. The property-test delivery profiles cover
  FIFO, reverse, and seeded random delivery.
- Storage-loss recovery is still future work. Restart equivalence covers rebuilding over the same storage, not missing
  or corrupted local records.
