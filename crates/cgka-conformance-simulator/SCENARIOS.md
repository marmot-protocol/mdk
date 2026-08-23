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
- Expected: recipients advance one epoch, keep the same member set, and project the requested name with the preserved
  empty description. This remains the backward-compatible Scenario IR v2 name-only contract.

### `group-profile-update/v1`

- File: `vectors/group-profile-update.v1.json`
- Setup: Alice creates a group with Bob, sets only the description, then sets only the name through Scenario IR v3.
- Pressure: partial-update preservation plus full profile propagation through the normal commit, publication,
  transport, and projection path.
- Expected: both clients project the requested values, match exact canonical MLS state, actively decrypt in both
  directions, and retain no pending work. Agreement on the same stale profile fails the expected-value oracle.

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
- Expected: an empty admin policy is refused as admin depletion, non-admin updates fail, both clients observe
  Bob's promotion and later
  self-demotion, and both clients converge at epoch 4 with Alice as the sole admin.

### `group-data-fork-recovery/v1`

- File: `vectors/group-data-fork-recovery.v1.json`
- Setup: Alice and Bob both update group data from the same epoch.
- Pressure: same-epoch group-data commit race.
- Expected: distributed convergence selects one branch, reorgs the loser onto it, and both clients converge at epoch 2 with a settled convergence decision recorded.

### `concurrent-invite-fork-recovery/v1`

- File: `vectors/concurrent-invite-fork-recovery.v1.json`
- Setup: Alice and Bob both invite a different member from the same epoch.
- Pressure: same-epoch invite commit race.
- Expected: one invite branch wins branch selection, the other is parked off the canonical branch, and active clients converge on the same member set with a settled convergence decision recorded.

### `cross-route-own-commit-recovery/v1`

- File: `vectors/cross-route-own-commit-recovery.v1.json`
- Setup: Zeta and Alpha author simultaneous privileged profile commits from epoch 1. Alpha's lower authenticated
  ordering key first displaces Zeta's own branch, and the ordering follows authenticated committer bytes from
  deterministic scenario identities, not lexical labels. Yankee has already applied Zeta's root and extends it, while
  Observer retains the complete competing input set without authoring either root.
- Pressure: the early ordering winner and the eventual convergence winner deliberately disagree once Zeta's branch
  becomes deeper. Zeta restarts after losing its own root and before the deeper child arrives, forcing
  commit-addressed checkpoint recovery rather than in-memory or epoch-addressed rollback.
- Expected: all four clients record a settled convergence decision at tip epoch 3 and project Zeta's depth-two branch
  name (pinned per client, so agreement is not mistaken for attribution), expose exact canonical cryptographic
  equality, retain accepted dispositions for the selected root and child plus an invalidated disposition for Alpha's
  root, have no pending work, and decrypt active application probes in all twelve directions. Alpha's epoch trace
  pins the displacement itself — it leaves the epoch-1 fork source, lands on the winner at epoch 2, and follows it to
  epoch 3 — and the focused Rust regression pins Alpha's own root carrying both withdrawal events. App-runtime,
  process, container, and VM permutations remain separate Milestone 6 evidence.

### `cross-route-retained-history-recovery/v1`

- File: `vectors/generated-inputs/cross-route-retained-history-recovery.generated-input.json`
- Subject: the saved input pins `retained_relay`; replay cannot silently substitute the fast in-process packet bus.
- Setup: the same four participants and competing source-epoch profile commits as
  `cross-route-own-commit-recovery/v1`, with an explicit one-relay deployment topology.
- Pressure: relay visibility and incremental cursors give Yankee only Zeta's root, then give Zeta Alpha's competing
  root while hiding Yankee's deeper child. Zeta restarts after being displaced. The hidden events are then made
  visible and every participant performs a full-history query, which is required because the earlier incremental
  queries advanced beyond the temporarily hidden events.
- Expected: the retained-history path reaches the same epoch-3 Zeta branch — a settled convergence decision at tip
  epoch 3 and the winning branch name pinned per client — with exact canonical cryptographic equality,
  accepted/invalidated/accepted commit dispositions, no pending work, and active decryptability in all twelve
  directions. The regression also requires all four final full-history queries to inject retained objects, so a passing
  result cannot be explained by the packet bus healing the delivery schedule. The saved input's portable outcomes own
  the state, profile, convergence-decision, epoch-trace, pending-work, and decryptability contract; the focused Rust
  regression owns the retained-injection observations, the stable commit-disposition subset, and Alpha's own-commit
  withdrawal event pair.

### `cross-route-app-runtime-recovery/v1`

- File: constructed once by `cross_route_app_runtime_recovery_public_scenario` (with an engine-exact companion) and
  executed unchanged by `four_party_cross_route_recovery_app_runtime_matches_unified_route`,
  `four_party_cross_route_recovery_processes_match_unified_route`, and
  `four_party_cross_route_recovery_containers_match_unified_route`; promotion to a portable saved input still requires
  an adapter-neutral representation of reversible retained-event staging.
- Subject: the strict half uses retained-engine exact observations; the black-box half uses the public
  `MarmotAppRuntime` commands and projections either in-process or in four isolated child processes. Every participant
  has a separate encrypted SQLite root and uses a real runner-owned local Nostr relay.
- Pressure: Alpha and Observer are offline while Zeta's root is retained; Yankee ingests that root, then goes offline.
  The harness reversibly hides Zeta's root from whole-relay queries before Alpha reconnects and authors its competing
  root, hides Alpha's root before Yankee reconnects and extends Zeta's branch, restarts Zeta, restores both retained
  roots, and performs repeated full-history repair. Every harness participant must be offline before relay-wide
  hiding; the step's named clients are not a per-recipient visibility filter.
- Current result: exact retained-engine settlement passes. On the unified same-epoch route with the queued-send
  scheduling repair, the app-runtime oracle now requires the same public epoch, roster, administration, depth-two
  profile, and complete duplicate-free probe set at every participant. The prior lag, missing-probe, and two-branch
  surfaces are historical pre-unification counterexamples and now fail the test; the reviewed post-change soak reached
  full public equivalence in all twenty trials. The process adapter and scheduled container checkpoint now call one
  shared public report oracle after real child-runtime disconnect/reopen boundaries; the process twenty-trial soak
  remains opt-in. Exact external-adapter cryptographic commitment, active-decryptability, complete application
  disposition, VM execution, and per-durable-transition permutations remain open.

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

### `route-equivalence/v1`

- File: `vectors/route-equivalence.v1.json`
- Setup: Alice creates a group with Bob, Carol, and Dave. Alice and Bob (both admins) race same-epoch
  `UpdateGroupData` commits and both confirm publication; both commits are withheld, then Bob — the
  deterministic ordering winner — restarts before either sibling is released, so he consumes the fork over
  durable storage with a fresh engine.
- Pressure: the same depth-1 fork is resolved by every member shape — the live committer (Alice, the
  ordering loser), the restarted committer over hydrated storage (Bob), and the passive observers (Carol and
  Dave) — all through the one distributed-convergence route. Both withheld commits are released in reversed
  order before anyone consumes the sibling branch.
- Expected: all four clients converge at epoch 2 with four members, each projecting the ordering winner's branch
  (`bob branch`, pinned per client so agreement is not mistaken for attribution),
  pass exact canonical equivalence, bidirectional decryptability in every direction, and no-pending-work, and each of
  the four records a settled convergence decision at tip epoch 2. The decryptability probe runs before the terminal
  `observe_exact` — it is a mutating probe, and a later observation is what the per-client convergence-decision pins
  read. Originally authored (as Slice B of option C) to prove the pairwise fast-path and the convergence
  route agreed; flipped into the unified-route acceptance pin when the pairwise route was deleted.

### `conversation/v1`

- File: `vectors/conversation.v1.json`
- Provenance: ported from the external multi-VM harness scenario catalog (`conversation.rb`).
- Setup: Alice creates a group with Bob and Carol. Two round-robin rounds where every member sends one message per
  round. Two rounds are the minimum that pins the no-duplicate-across-rounds property; what this vector adds over
  `three-client-message-exchange/v1` is `observe_exact` and `no_pending_work`, not round count.
- Pressure: none beyond sustained turn-taking traffic. This is the transcript-completeness smoke path.
- Expected: every client holds the exact four-payload transcript of the other members with no duplicates, all clients
  converge at epoch 1 with three members, and no pending work remains.

### `latecomer-forward-secrecy/v1`

- File: `vectors/latecomer-forward-secrecy.v1.json`
- Provenance: ported from the external multi-VM harness scenario catalog (`latecomer.rb`).
- Setup: Alice and Bob chat two pre-join rounds, then Alice invites Carol mid-conversation, then all three chat two
  post-join rounds. Pre-join ciphertext does reach Carol's mailbox.
- Pressure: forward secrecy. Carol must decrypt nothing from before her join even though she holds the ciphertext.
- Expected: originals hold pre+post transcripts; Carol's exact transcript contains only post-join payloads, and
  `payload_count` assertions pin two pre-join payloads at zero for her. Carol legitimately retains one undecryptable
  pre-join input as deferred transport work, so `no_pending_work` covers the original members only.

### `leaver-removal-secrecy/v1`

- File: `vectors/leaver-removal-secrecy.v1.json`
- Provenance: ported from the external multi-VM harness scenario catalog (`leaver.rb`), minus the re-add leg.
- Setup: four members chat, Alice removes Dave, the remaining members chat a gap phase, Carol self-leaves via the
  witness-commit path, and Alice and Bob chat a tail phase. Both departed members stay bus-attached with no partition:
  the gap and tail ciphertext really lands in Dave's mailbox (and the tail ciphertext in Carol's), and both are ticked
  after each delivery, so the zero assertions run against processed ciphertext the engine had to refuse — not against
  an empty or unread mailbox.
- Pressure: post-removal and post-leave secrecy plus the admin-removal and self-leave commit paths.
- Expected: Dave decrypts none of the gap or tail payloads and Carol decrypts none of the tail payloads
  (`payload_count` zero assertions cover every post-departure payload for each departed client); Alice and Bob hold
  the full transcript minus the departed members' silence and converge at epoch 3 with two members. `no_pending_work`
  covers Alice and Bob only: like the latecomer vector's pre-join input, Dave and Carol legitimately retain their
  undecryptable post-departure inputs as deferred transport work. The original harness scenario's re-add leg (removed
  member rejoins via a fresh KeyPackage) lives in `readd-after-eviction/v1`.

### `readd-after-eviction/v1`

- File: `vectors/readd-after-eviction.v1.json`
- Setup: Alice creates a group with Bob and Carol, removes Carol, then re-invites her with a fresh KeyPackage. Carol
  sends the first post-rejoin application message.
- Pressure: the rejoin Welcome lands on stale evicted local state, and the re-add commit reaches Carol as an
  old-epoch group message whose only retained peel snapshots are from her evicted era.
- Expected: the Welcome supersedes the stale live OpenMLS state, evicted-era retained snapshots are skipped as peel
  sources instead of failing ingest with `UseAfterEviction`, and all three clients converge at epoch 3 with Carol's
  post-rejoin payload delivered. The Rust regression for this shape is
  `removed_member_rejoins_via_fresh_welcome` in `tests/canonical_scenarios.rs`.

### `incremental-growth/v1`

- File: `vectors/incremental-growth.v1.json`
- Provenance: ported from the external multi-VM harness scenario catalog (`build.rb` + `growth.rb`).
- Setup: two founders chat, then Alice grows the group one member at a time (Carol, then Dave), renaming the group and
  running a full message round after each add.
- Pressure: staged growth with a commit per phase, and cohort-era forward secrecy across two join boundaries.
- Expected: each member's exact transcript starts at their own join era (`payload_count` assertions pin earlier-era
  payloads at zero for Carol and Dave), and all four clients converge at epoch 5 with four members. `no_pending_work`
  covers the founders only: as in the latecomer vector, Carol and Dave legitimately retain their undecryptable
  pre-join inputs as deferred transport work, so including them would fail on intended behavior.

### `multigroup-isolation/v1`

- File: `vectors/multigroup-isolation.v1.json`
- Provenance: ported from the external multi-VM harness scenario catalog (`multigroup.rb` and `pairs.rb`).
- Setup: the first multi-group vector, covering the full pairwise mesh over three clients. Alice founds group `a`
  with Bob and group `b` with Carol, and Bob founds group `c` with Carol, so every client sits in exactly two groups
  and one group's creator is not Alice. All three groups exchange application traffic through `in_group`-scoped
  steps.
- Pressure: cross-group encryption boundaries under overlapping membership, including a group whose creator is not
  the shared founder.
- Expected: every foreign payload is pinned at zero — Bob never observes group-b plaintext, Carol never observes
  group-a plaintext, and Alice never observes group-c plaintext (six `payload_count` assertions, one per foreign
  edge). Observation buffers are per-client, so each client's exact `received_payloads` list spans both groups it
  belongs to; the zero-count assertions carry the isolation claim. This vector absorbed `pairwise-threads/v1`, whose
  one addition over the two-group form was the group with a non-Alice creator.

### `admin-handover/v1`

- File: `vectors/admin-handover.v1.json`
- Provenance: ported from the external multi-VM harness scenario catalog (`handover.rb`).
- Setup: Alice promotes Bob, Bob renames, Bob promotes Carol, Carol renames, Alice demotes Bob, and the demoted Bob is
  denied a further admin edit. A final all-hands message round follows.
- Pressure: multi-hop admin succession where each newly promoted member exercises its authority, then loses it.
- Expected: all clients settle on the same admin set, converge exactly (`clients_exactly_equivalent`) at epoch 6 with
  the final transcript delivered and no pending work. Complements `admin-policy-update/v1`, which covers policy
  validation on a single promotion.

### `deferred-tick-catchup/v1`

- File: `vectors/deferred-tick-catchup.v1.json`
- Provenance: ported from the external multi-VM harness scenario catalog (`reconnect.rb`, with the soak/hour offline
  essence). Named for what the steps actually do: the engine subject declares no `ParticipantConnectivity`, so no
  transport-level disconnect happens; "offline" is modelled purely as Dave not ticking while his mailbox fills.
- Setup: four members chat, Dave stops ticking (daemon down; transport keeps delivering to his mailbox), the others
  chat and Alice renames the group, then Dave ticks once and catches up on everything.
- Pressure: offline catch-up across both missed application traffic and a missed epoch-advancing commit.
- Expected: Dave's exact transcript contains every message from all three phases, and all four clients converge on
  epoch, member count, and the renamed group with no pending work. Durable-relay offline recovery (subscription
  replay from retained histories) stays in the `adversarial-reliability` generated family per `retained_relay.rs`
  doctrine; this vector models mailbox catch-up.

### `late-welcome-backfill/v1`

- File: `vectors/late-welcome-backfill.v1.json`
- Setup: Alice creates a group with Bob, invites Dave, and the group advances two epochs while Dave's Welcome is
  withheld. The commits reach Dave before he can resolve the group. After the Welcome arrives and Dave joins at the
  invite epoch, duplicates of the missed commits are released, standing in for relay redelivery.
- Pressure: pre-join traffic is dropped without a durable record (the deliberate unknown-route flood posture), so
  the post-join redelivery must not be misclassified as a duplicate of terminal input.
- Expected: Dave joins at epoch 2, applies the redelivered commits to reach epoch 4, and sends the first post-join
  application message; all three clients converge on the tip. The Rust regression for this shape is
  `late_welcome_join_catches_up_via_redelivered_commits` in `tests/canonical_scenarios.rs`, and
  `commit_missing_proposal_defers_and_applies_after_proposal_backfill` pins the sibling missing-proposal deferral.

## Incident-Replay Vectors

These vectors are synthesized from Goggles `agent-state.json` forensic exports by the `incident-replay` adapter, then
verified against the simulator before they are committed. They live under `vectors/incidents/` and are not yet part of
the top-level portable-vector test (Phase 5 wires the directory into CI).

### `fork-recovery-incident/v1`

- File: `vectors/incidents/fork-recovery-incident.v1.json`
- Setup: two clients create a group, then raise competing group-data commits from the same epoch — the concurrent-fork
  shape the adapter derives from a fork-recovery incident.
- Pressure: same-epoch group-data commit race with deferred delivery (no partition needed; the commits are concurrent).
- Expected: distributed convergence resolves the race on delivery, the designated winner's branch survives, and both
  clients converge at epoch 2 with a settled convergence decision at that tip recorded as the resolution evidence.

### `membership-fork-recovery-incident/v1`

- File: `vectors/incidents/membership-fork-recovery-incident.v1.json`
- Setup: two committers create a group, then raise competing membership commits (an invite race) from the same epoch,
  with the two invitees held out by a partition — the membership-fork shape the adapter derives from a fork-recovery
  incident whose contested tip is a membership/admin commit (`member_added`/`member_removed`/`admin_added`/`admin_removed`).
- Pressure: same-epoch membership commit race with deferred delivery, resolved by the convergence selector.
- Expected: distributed convergence resolves the race on delivery and both committers converge at epoch 2 with
  `member_count == 3` — the winner-agnostic proof that exactly one branch's invite survived — and a settled
  convergence decision at that tip recorded as the resolution evidence. Unlike the group-data fork, the resolution
  expectation is winner-agnostic (no branch-name label search), because real
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

### `open_convergence_pass_survives_restart_and_walks_the_backlog_to_the_tip`

- Setup: Alice and Carol settle at epoch 1, the scenario moves onto virtual time, and one inbound commit edge opens
  Carol's convergence pass at base epoch 1.
- Pressure: Carol crashes and reopens (encrypted file storage, real close/reopen) 300ms short of the pass cutoff, then
  three more commits from Alice land on the reopened engine while the recovered pass still holds the boundary.
- Expected: mid-history Carol is still at epoch 1 with Alice four epochs ahead — an active pass pins the tip across the
  crash and the backlog. The settle tick at exactly the original 1000ms deadline clears the recovered pass, and Carol
  then walks 1→2→3→4→5, one generation per quiescence window, ending exactly equivalent to Alice with no pending work.
- Reason: scenario-level companion to the stale-pass-base field incident fixed in mdk#1182, over the durable
  convergence passes mdk#1110 added. The engine tests for that fix install a `base_epoch`/tip disagreement on the
  durable record directly, because the engine keeps a single tip authority and an active pass gates every path that
  could move the tip. This scenario pins that precondition from the
  public boundary: the disagreement the incident needed never arises, and the device still converges. The timing is the
  evidence that the *same* durable pass survived the crash — a pass reopened afterwards would carry a later deadline and
  leave Carol behind.
- Not portable yet, because the multi-process subject cannot carry the contract: `process_subject_descriptor`
  deliberately does not advertise `SubjectCapability::VirtualTime`, so `AdvanceTime` fails preflight as
  `unsupported_subject_capability` and the orchestrator's `tokio::time::sleep` arm never runs — and `node_protocol`
  exposes no clock surface, so there is no subject clock for the step to move. Each node's pass deadlines would run on
  real elapsed time, which is fine for a step that only needs settling slack and wrong for one whose contract is
  landing on a boundary. Promoting this to `vectors/` needs a node-side virtual clock and a capability the process
  subject can honestly advertise.
- The manual `AdvanceTime`/`Tick` walk is a choice, not an oracle workaround. `await_quiescence` advances virtual time
  to a fixed point and settles the recovered pass whenever it comes due, which erases the exact-deadline evidence —
  with it appended, shortening the settle tick to 900ms still passes. Ticking manually costs nothing under
  `--strict-oracle`: `VirtualTimeAdvance` recommends `OracleBehavior::QuiescenceState` *or*
  `OracleBehavior::NoPendingWorkObserved`, and this scenario asserts `NoPendingWork`.
- Mutation evidence: deleting the durable pass on reopen, or ignoring the quiescence cutoff, both turn this scenario
  red. Shortening the post-restart settle tick from 300ms to 200ms — landing at 900ms instead of the recovered pass's
  original 1000ms deadline — leaves Carol with an unresolved convergence input and one epoch behind, which is the direct
  evidence that the deadline survived the reopen rather than being re-derived. Leaving an applied pass active at its old
  base epoch (producing the incident shape live) keeps it green, because the mdk#1182 discard reopens at the tip;
  replacing that discard with the pre-mdk#1182 durable halt turns it red with Carol's canonical `convergence_status`
  stuck at `unrecoverable`.

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
- Expected: one branch wins by deterministic ordering. One peer reorgs onto it, and Alice and Bob end on the same
  member set.
- Reason: the test inspects harness tick outcomes and exact membership directly.

### `failed_invite_staging_does_not_poison_fork_detection_via_harness`

- Setup: Alice's invite fails during commit staging (duplicate-member KeyPackage). Alice then advances to epoch 2 by
  settling Bob's commit through convergence, and a partitioned Dave later delivers a sibling commit from the same
  source epoch.
- Expected: the sibling commit is adjudicated deterministically (stale losing branch or reorg onto the winner) — never
  a fail-closed `ForkedEpoch` — and Alice's group stays usable for a follow-up invite.
- Reason: regression guard for the historical phantom fork-detection bookkeeping bug (routing no longer consults
  committer-side bookkeeping at all); mirrors the cgka-engine test
  `failed_invite_staging_does_not_poison_fork_detection` at the multi-client bus level.

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

### `seven_member_future_epoch_backlog_queues_send_and_regenerates_after_restart`

- Setup: Alice creates a seven-member group. One observer misses Alice's self-update commit but receives 47
  future-epoch application wrappers, then originates an application of its own.
- Pressure: the observer's outbound preflight reaches the four-row foreground deferred-peel limit, restarts with both
  the backlog and queued intent durable, and later receives the withheld epoch-advance commit.
- Expected: accepting the observer's outbound intent emits no wire, reports the bounded foreground outcome, and leaves
  exactly one queued intent. Restart preserves that state. Delivering the missing commit peels the complete backlog,
  advances the observer, and regenerates its queued application for publication; its durable intent remains until the
  harness reports publication acceptance.
- Reason: this is production-shaped Nostr-wrapper and multi-client coverage; the 250ms blocked-peeler timing boundary
  remains a deterministic engine integration test rather than a portable protocol assertion.

## Generated Scenario Families

Generated cases are deterministic for a fixed family name, independent generator version, seed, and case index, plus
a separately versioned workload profile when applicable. They are run directly as generated coverage.
A generated case becomes a vector only when we want it to be a stable named contract: for example, when it caught a
regression, covers a new semantic edge, or is the smallest readable example of a behavior.

### `cross-route-restart-permutations/v1`

- Generator: `generate_cross_route_restart_permutation_family` (generator version `1`).
- Setup: the shared current-build four-party cross-route topology creates simultaneous competing profile branches,
  grows the selected branch, carries an application witness, repairs retained history, and sends a terminal probe from
  every participant.
- Pressure: twelve catalog entries add one durable reopen after each reviewed publication/ingest boundary and after
  retained-history repair for each participant. A seed rotates the catalog order; twelve consecutive cases cover it.
- Expected: the app-runtime subject reaches epoch 5 with the exact four-member roster, three-member admin set,
  depth-two selected profile, and an order-insensitive multiset containing exactly one copy of every witness/probe
  payload. The explicit retained-engine form
  additionally requires exact private state, no pending work, and all twelve decryptability directions. The process
  form binds every restart action to a matching durable lifecycle event and applies the shared strict public oracle.
- Replay: the isolated family runner saves the complete selected input before execution and retains reports, fixture
  candidates, process measurements, and failure capsules per case. The exact retained-engine companion is registered
  separately as `cross-route-exact-restart-permutations/v1`, ensuring a panic in one private-state case cannot stop
  the rest of the catalog. Public and exact inputs use distinct scenario-name prefixes. The complete public seed-0
  execution passes 12/12. The first exact execution passed 9/12 and exposed three early-publication failures;
  minimization traced all three to the simulator carrying process-local pending handles across engine incarnations.
  MDK #1465 scoped that bookkeeping to the issuing incarnation, and the exact seed-0 catalog now passes 12/12 without
  changing production engine or protocol behavior. The original failures remain historical discovery evidence, not
  allowed results.

### `chat-journey/v1`

- Generator: `generate_stateful_chat_journey_family` (generator version `1`).
- Setup: a four-participant legality model emits canonical IR v3 while tracking the roster, administrator set,
  connectivity, epoch, group profile, and application deliveries.
- Profiles: even case indices generate late-invite membership journeys on the engine subject; odd indices generate
  retained-history offline/catch-up journeys whose participants all joined at epoch 1.
- Pressure: every case contains application traffic and a profile update, while adjacent cases rotate invites,
  removals, admin changes, self-updates, restarts, offline windows, and reconnect repair.
- Expected: the modeled terminal epoch, roster size, group profile, admin set, and per-client deliveries match;
  surviving clients have exact canonical agreement and active bidirectional decryptability. Retained-history cases
  additionally reach global quiescence and no pending work for every survivor. Late-join cases do not falsely require
  the invitee's valid pre-admission transport retry rows to disappear.
- Replay: before action zero the report runner saves an owner-only, versioned generated-case input containing the
  selected subject adapter and expectations. `--generated-input FILE` reexecutes it through the same report path; the
  ordinary report, promotable vector candidate, and any failure capsule remain separate artifacts.

### `send-leave/v1`

- Generator: `generate_send_leave_family` (generator version `2`)
- Setup: three clients start in one group. The generator emits app sends and self-remove leaves.
- Expected: remaining live members converge on exact canonical state after a final global drain and report no pending
  work. The current leave shapes intentionally expose retained proposal/schedule work as a strict failure.

### `convergence-e2e-delivery/v1`

- Generator: `generate_convergence_e2e_delivery_family` (generator version `2`).
- Setup: the real-peeler invite-fork scenario runs with generated delivery mutations, then a settle tail delivers and
  ticks the founders, accepts outstanding outbound work, runs an active bidirectional decryptability probe, and
  observes the founders exactly.
- Pressure: duplicate, delay, release, and reorder before observer clients tick.
- Expected: the mid-schedule observation stays branch-dependent, and so does the selected branch itself — app-witness
  scoring can hand the win to either committer depending on the delivery schedule, and the losing branch's commits
  deliberately remain reconsiderable deferred candidates on non-committing clients. The generated expectations
  therefore pin the schedule-invariant claims: every scripted accepted acknowledgement confirms, the founders converge
  and are exactly equivalent, and post-selection application traffic decrypts in every founder direction. Final
  epoch/member-count and a whole-roster no-pending-work claim are deliberately not asserted.

### `admin-churn/v1`

- Generator: `generate_admin_churn_family` (generator version `1`).
- Provenance: ported from the external multi-VM harness scenario catalog (`cheeky.rb`, `committy.rb`, `crashy.rb`
  essences, without their wall-clock scheduling).
- Setup: the family rotates through four arms.
- Expected: each arm carries semantic expectations for convergence, exact transcripts, and pending work, then performs
  the final drain with exact-state assertions.

#### Admin-Churn Arm `0`: Seeded Sequential Churn

- Setup: four members, all promoted to admin. Four rounds where a seeded admin either renames or toggles a non-founder
  in or out of the admin set, with a full message round after each commit.
- Pressure: sustained admin-set and metadata churn with traffic between commits.
- Expected: all clients converge at the deterministic final epoch with exact per-client transcripts.

#### Admin-Churn Arm `1`: Competing Admin-Policy Commits

- Setup: two admins race admin-policy commits from the same epoch; the delivery order of the two commits is drawn from
  the seed. After the race settles, an admin retained under both candidate outcomes pins the admin set with a
  follow-up policy commit.
- Pressure: same-epoch admin-authority race, the admin-set analog of the chaos group-data fork.
- Expected: the race winner stays schedule-dependent and unasserted, but authority is enforced afterward: the
  retained admin's pinning commit must succeed, both non-admins' privileged updates must be rejected in place
  (`not_group_admin`), and every client observes the pinned admin set. All clients converge two epochs past the race
  with exact post-race probe transcripts.

#### Admin-Churn Arm `2`: Restart Between Publish and Delivery

- Setup: a seeded admin publishes a rename commit and restarts before delivery; every member then sends into the
  recovered group.
- Pressure: crash-shaped interruption between commit publish and delivery.
- Expected: the restarted client hydrates the stable group, its post-restart send lands everywhere, and all clients
  converge with exact transcripts.

#### Admin-Churn Arm `3`: Latecomer Under Commit Pressure

- Setup: the founder keeps rename pressure up, then invites a fourth member and publishes another rename before the
  delivery round that completes the join, so the welcome and the next commit travel in the same flight; all four then
  exchange traffic. Pre-join traffic is partitioned away from the latecomer's process (ciphertext-exposure forward
  secrecy is the `latecomer-forward-secrecy/v1` vector's job).
- Pressure: a join genuinely racing sustained commit pressure.
- Expected: the latecomer never observes pre-join plaintext (zero-count assertions), every member holds its exact
  transcript (founders carry pre-join and post-join traffic), and every client converges. The strict pending-work
  assertion is scoped to the founders, and the joiner carries a
  `no_pending_work_except_retained_join_commit` assertion: a welcome-joined member currently retains exactly its own
  join commit as a permanently deferred transport input, and any other pending work still fails the case. The
  retained join commit itself is tracked as a harness coverage gap.
### `bounded-convergence-pressure/v1`

- Generator: `generate_bounded_convergence_pressure_family` (generator version `2`). Version 2 adds the confirmed
  pending-resolution expectations the strict oracle requires for the labelled publication acknowledgements; scenario
  steps are unchanged.
- Setup: four clients, Alice and Bob admins. Both admins race same-epoch `update_group_data` commits and both confirm
  publication; each rival commit is withheld, then released in a seed-derived order so every member ingests the fork.
- Pressure: **finite** and deliberately so. One application send per client is issued after the rival branch is ingested
  — inside the quiescence window the committers wait out — then one committer restarts mid-resolution and a further send
  follows. The settled tail applies exactly three self-updates, one profile commit, and one admin-policy commit, ordered
  by seed.
- Time discipline: an explicit `advance_time` before the race activates controlled virtual time, so the quiescence
  window is a real deadline rather than the far-future tick shortcut. Every settle from that point on is
  `await_quiescence`; the bare ticks that remain deliberately wake participants *without* settling them.
- Expected: eventual quiescence, exact canonical equivalence and no pending work across all four clients, the pinned
  post-race group profile and admin set, and bidirectional decryptability. The decryptability probe runs before the
  terminal `observe_exact` for the reason given in the `route-equivalence/v1` row. Bounded queue behavior is a
  `scenario_inputs_pending` resource assertion at peak pressure; bounded time is the `await_quiescence` watchdog budget
  itself, whose `TimedOut` status is a failure — no separate metric is invented.
- Scope fence: the campaign claims eventual quiescence for **bounded** input only. It makes no progress claim under an
  unbounded self-update stream (reliability plan PDR-2/L3), which is a deliberate non-guarantee.
- Status: `bounded_convergence_pressure_family_generates_the_declared_campaign_shape` gates the generator in CI. The
  runnable gate `bounded_convergence_pressure_family_settles_every_seeded_permutation` passes since mdk#1472 (the
  engine re-arms the queued-intent drain when a pass closes and no longer re-prepares an in-flight regenerated
  intent). It runs in the nightly lane; the PR smoke lane excludes it as one of the multi-minute generated batches.

### `large-group-pressure/v1`

- Generator: `generate_large_group_pressure_family` (generator version `1`, workload-profile version `1`).
- Size curve: six consecutive cases share one size, ordered by execution cost at 10, 16, 20, 32, 50, 64, 100, 128,
  and 200 members. Metadata distinguishes the 16/32/64/128 anchors from the 10/20/50/100/200 boundaries. A complete
  size/arm catalog is therefore 54 cases; larger case counts repeat the stable catalog under new seeded choices.
- Administrator curve: every six-case size block covers founder-only, three-admin, approximately 10%, approximately
  50%, and all-member administrator populations. Administrator population and active committer width are separate:
  a dense administrator group can still run a two- or eight-committer workload. Regimes rotate across arms by size,
  while the competing and mixed arms never receive founder-only because their contract requires an actual race.
- Workload metadata: every generated input and report records size tier, member count, initial/final admin counts,
  committer mode/count, authored application count, workload commit count, traffic profile, formation, and disruption.
  Authored application count is distinct from recipient fanout: one 200-member send round creates 39,800 directed
  recipient deliveries before the active probe.
- Oracle: every case requires exact canonical equivalence across every live member and pins the final member count,
  administrator policy, group profile, input closure, and active decryptability. Exact application payload multisets
  are checked on a deterministic cohort of at most six clients containing representatives of the founder, admin,
  committer, ordinary-member, late-join/re-add, and roster-tail roles. Priority roles are selected before the cohort is
  roster-ordered, so truncation cannot silently discard the re-added or tail representative. This bounds probe cost
  without weakening whole-group state and pending-work checks.
- Join boundary: incremental-growth and remove/re-add arms name the existing welcome-join harness condition directly.
  Every late joiner must retain exactly its own transport-deferred join commit and no other pending work; all other
  clients must have no pending work.

The six arms are:

1. **Bulk Application Fanout** — bulk create, one authored message per member, and two sequential profile commits.
2. **Incremental Growth** — four founding members, bounded invite batches, final admin assignment, checkpoint traffic,
   and a final profile commit.
3. **Sparse-Admin Sequential** — sequential profile commits interspersed with traffic plus a non-admin authorization
   rejection whenever the selected admin regime leaves a non-admin.
4. **Competing Commits** — up to sixteen active admins race same-epoch profile commits under seeded reorder and one
   duplicate, followed by commit-heavy application traffic and a canonical pinning commit.
5. **Mixed Interleaved** — application traffic before and after a seeded multi-admin commit wave, followed by a
   canonical pinning commit.
6. **Admin Handoff / Churn / Restart** — the founder hands authority to a successor, the successor removes a member,
   restarts before delivery settles, re-adds the member, and verifies the rejoined non-admin cannot mutate policy.

`mid_size_application_heavy_canary_passes_strict_oracles` and
`mid_size_incremental_join_canary_passes_strict_oracles` are the ordinary 10-member executable gates; the latter
exercises the retained-join pending-work condition. Generator tests compile the complete 54-case catalog without
executing the expensive large/xlarge cases. Run 32/64-member blocks in nightly isolated workers and keep
128/200-member execution scheduled or manual until measured budgets justify wider promotion.

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

### Adversarial Reliability Catalog

`adversarial-reliability/v1` (generator version `4`) rotates through twelve deterministic workload shapes: retained-history offline floods;
sustained app/proposal/commit traffic; self-update versus admin progress; a named unrecoverable losing-branch invite;
unequal relay reconciliation; restart boundaries plus the engine's real SIGKILL durable-phase matrix; multi-group noisy
neighbors; replay-budget exhaustion; shared-account multi-device witnesses; full-engine app-witness A/B selection;
mixed-binary compatibility with mixed-policy preflight rejection; and clock, scheduler, timestamp, and cursor attacks.
The app-witness case pins the exact payload multiplicity for each candidate branch but deliberately does not claim an
order between messages from different senders; those `PayloadCount` asserts are strict-oracle evidence for
`AppMessage`. Scenarios that inject a transport reorder continue to pin ordered `received_payloads` explicitly.

The normal test target runs small headline regressions. The multi-round sustained case is ignored by default and is
invoked explicitly; the report CLI runs any number of seeded cases with either in-memory or encrypted file-backed
SQLite. Test-only feature `test-policy-overrides` exposes the zero replay-budget repair and witness-disabled paired
engine experiments. Production builds cannot select either override.

The app-witness “multi-parent” sentinel means one MLS commit consuming multiple standalone proposal dependencies
atomically. MLS still has exactly one prior group-state parent; the campaign does not claim that incompatible MLS state
branches can be merged.

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
  digest change. The minimized case remains diagnostic metadata; fixture candidates retain the original executed
  scenario so they cannot silently reproduce a different terminal state under the same broad failure kind.
- `failed_campaign_capsule_contains_a_replayable_tick_witness` checks that a real report campaign exports a sensitive
  recipient checkpoint plus exact mailbox bytes and that both the replay API and report CLI reproduce its fingerprint.
- `tests/generated_policy_cases.rs` checks that Tamarin-derived branch selector cases match the Rust selector across
  candidate orderings.

## Byte Fixtures

The `vectors/byte-fixtures/` files are conformance artifacts, but they are not simulator scenarios. They check byte
encoding and validation for app-component data such as Nostr routing component state and updates.

Keep those in the vector manifest. Add them here only if they become runnable `ScenarioSpec` fixtures.
