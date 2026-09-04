# CGKA Engine Spec

**Status:** draft normative spec for the current CGKA engine boundary.

This document defines the CGKA engine contract Marmot clients must implement to process MLS group state consistently
across unordered transports. The detailed design notes remain in
[`cgka-engine-canonicalization-contract.md`](./cgka-engine-canonicalization-contract.md) and
[`distributed-convergence.md`](./distributed-convergence.md).

## Scope

The CGKA engine starts after transport peeling and ends at application-visible group events plus publishable outbound
transport messages.

```text
transport adapter
  -> transport peeler
  -> CGKA engine
  -> GroupEvent / SendResult
```

The engine owns:

- MLS group state and epoch lifecycle.
- Commit sequencing and convergence.
- Proposal lifecycle.
- Application-message acceptance and invalidation.
- Capability negotiation and MIP-03 admin policy.
- Publish-before-apply for local group evolution.
- Retained anchors, rollback, replay, and message dispositions.

The engine does not own:

- Relay connections or transport subscriptions.
- Nostr event parsing outside the peeler.
- Chat-list projection, message display policy, notifications, or UI.
- Production database choice.
- FFI, CLI, or app account management.

## Required Boundary

The application MUST interact with the engine through the `CgkaEngine` contract. It MUST NOT call OpenMLS directly for
group state transitions.

The engine receives transport-independent `TransportMessage` values and uses an injected `TransportPeeler` to obtain MLS
bytes. Transport order, relay order, relay timestamps, Nostr event ids, and local arrival order are advisory. They MUST
NOT decide the canonical commit branch.

The engine emits:

- `IngestOutcome` for each inbound message.
- `GroupEvent` records for application-visible effects.
- `SendResult` records for local outbound work.
- auto-publish messages created by engine policy, such as SelfRemove commits.

## Core Invariant

Two honest engines with the same retained anchor, pending message set, pinned protocol policy, engine version, and
lifecycle clock inputs MUST select the same canonical branch and produce the same protocol dispositions.

```text
same retained anchor
+ same pending messages
+ same pinned protocol policy
+ same engine version
+ same lifecycle clock inputs
= same canonical branch and dispositions
```

This invariant applies to commits, proposals, application-message acceptance, application-message invalidation,
duplicate detection, and outbound intent gating.

## Engine State

Each group has an `EpochState`:

- `Stable`: no local pending commit; inbound and outbound work may proceed.
- `PendingPublish`: a local group-evolution commit exists and is waiting for transport publication confirmation.
- `Merging`: publication was confirmed and the engine is merging pending MLS state.
- `Recovering`: the engine has detected a fork-shaped conflict and is using retained state to recover.

Only the engine may construct non-`Stable` states. Applications observe state through typed outcomes, not direct state
mutation.

The engine also derives a convergence status:

- `Syncing`: collecting convergence-relevant messages.
- `Resolving`: replaying candidates and assigning dispositions.
- `Settled`: no convergence-relevant input has arrived for at least the configured quiescence window, and the selected
  branch has been applied.
- `Blocked`: convergence cannot safely continue without a repair path or missing retained material.

`convergence_status` is a derived result. It is not an input claim made by the caller.

## Inbound Processing

`ingest(msg)` MAY be called in any order. The engine MUST deduplicate by a transport-independent `MessageId`.

Inbound processing has this shape:

```text
TransportMessage
  -> peel group message or welcome
  -> store durable message bytes
  -> classify commit / proposal / app message / welcome
  -> buffer or process according to group state
  -> emit IngestOutcome and later GroupEvent values
```

The engine MUST keep pre-convergence rejection, convergence disposition, and local canonical state distinct:

- duplicate, own-echo, wrong-recipient, and unknown-group inputs return typed `IngestOutcome::Ignored` categories;
- stale or invalid convergence candidates use convergence dispositions; and
- authenticated local removal and quarantine return `IngestOutcome::LocalState`.

Realizing removal remains an engine side effect even though removal is not a stale convergence disposition. None of
these classifications may require string parsing by the caller.

During `PendingPublish` or `Merging`, inbound group messages MAY be buffered. The engine MUST replay buffered messages
when the group returns to `Stable`.

Stored message payloads are typed:

- `RawTransport`: the original transport-wrapped message, kept for retry when peeling is not yet possible.
- `OpenMlsWire`: the same transport metadata with `payload` replaced by peeled MLS wire bytes, used by canonicalization
  and OpenMLS replay.

For group messages, the engine MUST first peel with the current MLS exporter context. If that fails and retained epoch
snapshots are available, it SHOULD try those retained contexts newest-to-oldest within the retention window before
returning `IngestOutcome::TransportDeferred` and retaining it as `PeelDeferred`.

When a transport supplies authenticated source-epoch evidence and no retained snapshot can peel the object, the engine
MAY establish a specific stale outcome such as `AlreadyAtEpoch`. The Nostr group envelope has no clear source-epoch
hint, so a decrypt miss remains `TransportDeferred`: it might be a future-epoch object whose missing commit will later
change the peel context. A local row or retry cap returns typed `ResourceRefused`, does not establish invalidity or
permanent unreadability, and MUST leave exact-ID redelivery eligible.

`PeelDeferred` rows MUST persist their distinct-context attempt count and conservative local residence deadline.
Restart MUST NOT reset either budget. Live-process expiry uses monotonic time; restart rebases from durable wall time,
and backwards wall movement MUST NOT shorten the remaining residence. The scheduler MUST keep a wakeup armed for the
earliest deferred deadline even when the peel-context fingerprint stays unchanged. Deadline release is a local
`ResourceRefused` outcome, deletes the raw row and releases its cap slot, creates no terminal dedup marker, and arms
transport-history recovery before synchronization is considered complete.

When convergence reaches a settled selected branch, the engine MUST retry `PeelDeferred` raw group messages for that
group. A retry that peels into OpenMLS wire bytes promotes the stored payload from `RawTransport` to `OpenMlsWire`; it
is then either processed immediately if it belongs to the current selected epoch or buffered as convergence input if it
targets a later candidate epoch.

Before preparing any new outbound application message, proposal, or commit, the engine MUST give every deferred row
not yet definitively tested under the current peel-context fingerprint a bounded foreground opportunity. Production
uses the earlier of 250 ms of local monotonic deferred-phase time or four row attempts. Required authenticated
convergence is completed first and does not consume that deferred-phase time budget. If work remains when either bound
is reached, the engine MUST durably retain the original outbound intent and return `AcceptedPending`; it MUST NOT
prepare wire bytes. Current-fingerprint deferred work remains safety-critical ahead of every queued outbound intent.
Rows already definitively tested under that fingerprint are historical-only maintenance and MUST NOT keep a new or
queued outbound intent waiting. The durable per-row fingerprint, rather than a process-local numeric cursor,
determines which row is next after restart.

When candidate-branch peel contexts are involved, the engine MUST persist a contested-generation marker before trying
the first row and MUST retain that marker until every row in the generation has a durable definitive outcome. While
the marker exists, convergence MUST NOT apply a partially recovered prefix. Completion clears the marker before the
complete recovered input set is converged, so a crash can repeat safe work but cannot make a partial prefix canonical.
Raw `PeelDeferred` rows outside this foreground opportunity remain maintenance input; only peeled OpenMLS commits,
proposals, and application messages become ordinary unresolved convergence inputs.

## Welcomes

A welcome join lands the recipient at the post-commit epoch carried by the welcome. If the matching commit arrives
later, the engine MUST classify that commit as already applied. It MUST NOT treat that ordinary handoff as a fork.

Welcomes addressed to another client MUST return `NotForThisClient`.

## Local Publish Lifecycle

Local group-evolution operations use publish-before-apply.

```text
send(intent)
  -> SendResult::GroupEvolution or SendResult::GroupCreated
  -> application publishes commit and welcomes
  -> confirm_published(pending)
  -> engine merges MLS state and emits GroupEvent
```

If publication fails, the application calls `publish_failed(pending)`. The engine MUST discard the pending commit and
return to the prior stable state.

The engine MUST NOT advance local group state for a local commit until the application confirms publication. This rule
prevents local epoch advance for a commit the rest of the group cannot see.

### Auto-publish lifecycle

Auto-publish commits created by engine policy are drained through `drain_auto_publish`. Each drained item carries the
wrapped commit and a `PendingStateRef`. The application MUST publish the commit, then call `confirm_published(pending)`
or `publish_failed(pending)`.

The current example is the SelfRemove auto-commit chosen by `LowestIndexAutoCommitter`: the remaining lowest-index
member stages a commit for a peer's SelfRemove proposal and queues it for publication. The engine may project the
pending epoch/member view in Marmot metadata, but it MUST NOT merge the OpenMLS pending commit or emit removal events
until publication is confirmed.

If publication fails, the engine clears the staged commit and re-derives Marmot metadata from the still-unmerged OpenMLS
group. Auto-publish and explicit `send` paths now share the same publish-before-apply rule.

## Outbound Intent Gating

If a group has unresolved convergence input, `send(intent)` MUST store the intent durably and return
`SendResult::Queued`.

`PendingPublish` and `Merging` are the two steps of resolving a publication this client staged, and neither exit is
something the sender controls — a transport outcome, then the local merge that outcome authorizes. An
application-message intent offered in one of those states MUST also be stored durably and returned as
`SendResult::Queued` rather than refused, so a slow or failing publication cannot discard a user's message. Group-state
intents MUST keep the strict `Stable` requirement, because a second staged evolution has no epoch to apply to.
`Recovering` awaits a convergence decision over remote branches rather than a local publication; whether application
work is retained across it is a separate lifecycle question and MUST NOT be assumed from this rule.

`Disbanded` is terminal and MUST refuse every intent. `Unrecoverable` MUST refuse every intent except
`SendIntent::Disband`, which persists an irreversible request rather than retaining a delivery, and whose Commit
preparation MUST still wait for `Stable`. Neither state resolves on its own, so neither may accept new work.

Refusing new work is not discarding accepted work. Intents retained before a group entered a terminal state MUST persist
for that state's one legal exit: a verified repair returns an `Unrecoverable` group to `Stable`, and the drain then
prepares the retained intents under the post-repair epoch. They MUST NOT be purged on the transition into
`Unrecoverable`. `Disbanded` is the sole exception, and only because its terminal Commit purges the queue in the same
transaction that writes the tombstone.

Because retention stores the *intent*, not ciphertext, a message retained across an epoch change MUST be encrypted under
the epoch it is regenerated at, never the epoch it was accepted at. That is what makes holding across a halt
deliverable rather than a promise the engine cannot keep.

Whenever a group returns to `Stable`, the engine MUST schedule it for convergence if it still holds durable outbound
intents. Both returns count: a publish outcome that resolves the pending publication, and a verified repair that lifts
`Unrecoverable`. Nothing else would release them, and scheduling only on the publish outcome would leave a repaired
group's intents waiting for an unrelated event.

Retention is not unconditional. Two transitions end a retained intent permanently, and both discard the whole queue
rather than individual intents: a disband, whose terminal Commit purges the queue in the tombstone transaction, and the
local copy being removed from the group, which leaves no state to regenerate under. Neither is recoverable by
convergence, so the engine MUST NOT report those intents as still pending. The application layer MUST be able to name
that outcome per message rather than infer it from a message that never arrives; how it is surfaced is an application
concern, not a protocol one.

Releasing a retained intent is not ordered against a new send: a send accepted once the group is `Stable` publishes
immediately if its convergence inputs have settled, while a retained intent waits for the next convergence drain, so a
message accepted later MAY reach the transport first — by up to the settlement quiescence delay. Display order is
unaffected, because the application timeline stamps a message when it is accepted rather than when it publishes;
per-sender FIFO publication is not a protocol promise.

When the group becomes stable, the application calls:

```text
advance_convergence(group_id) -> Vec<SendResult>
```

The engine MUST regenerate queued outbound work from the selected canonical state. It MUST remove a queued intent only
after regeneration succeeds.

If regeneration creates a group-evolution commit, `advance_convergence` MUST return that one publishable result and
pause later queued work until `confirm_published` or `publish_failed` resolves the pending commit.

## Commit Convergence

Commits are the consensus log. All honest engines that see the same valid commit set under the same pinned protocol
policy MUST process commits in the same canonical order.

The engine builds a bounded candidate-state graph from retained MLS snapshots. Production engines MUST derive candidate
edges by replaying MLS bytes against retained snapshots. They MUST NOT trust transport-provided parent metadata.

Commit rules:

- A commit creates a candidate edge only if it validates against exactly one parent state.
- A child commit whose parent is unavailable is explicitly deferred until the parent appears or the child expires.
- A commit at or after the retained anchor MAY be replayed from the greatest retained snapshot at or below its source
  epoch; anchors exist only where a device stopped, so a traversed source epoch has none of its own.
- A commit older than the retained anchor MUST be dropped with `BeyondAnchor`.
- A commit that needs a retained snapshot inside the rewind window, when no snapshot at or below its source epoch
  survives there, MUST return `MissingRetainedAnchor` without mutating group state or message state.
- Candidate states outside the retention horizon MUST be dropped.

Same-epoch commit recovery uses an authenticated ordering key:

```text
CommitOrderingKey {
  source_epoch,
  priority,       // privileged < ordinary
  committer,      // authenticated Marmot account id
  commit_digest = SHA-256(mls_bytes)
}
```

`commit_digest` is only the final same-committer fallback; cross-member races are decided by authenticated metadata, not
by grindable commit bytes.

Lower ordering keys win. Transport metadata MUST NOT affect this recovery rule.

## Branch Selection

Only branches inside `max_rewind_commits` are eligible:

```text
eligible =
  current_tip_epoch - branch.fork_epoch <= max_rewind_commits
```

Ineligible branches MUST NOT be selected.

Branch selection uses these values:

- `fork_epoch`: the epoch where this branch diverged from the retained canonical state.
- `tip_epoch`: the epoch reached by replaying the branch's valid commits.
- `raw_commit_depth`: the number of valid commits from `fork_epoch` to `tip_epoch`.
- `app_witness`: an application message that decrypts against a candidate branch state.
- `app_witness_score`: the sum of distinct app-message senders counted per branch epoch, capped by that epoch's sender
  quorum.
- `witness_quorum_met`: true when the branch has enough distinct app-message senders in enough branch epochs under the
  pinned protocol policy.
- `effective_commit_depth`: `raw_commit_depth` plus the bounded witness boost when `witness_quorum_met` is true.

Witnesses are evidence that group members used a branch after it was created. They do not create epochs, apply commits,
or replace MLS validation.

Branches are compared in this order:

1. Higher effective commit depth.
2. Witness quorum beats no quorum.
3. Higher app-witness score.
4. Lower tip commit priority (`Privileged` before `Ordinary`).
5. Lower authenticated tip committer account id.
6. Lower tip commit digest.

Raw commit depth remains an input to effective depth and a diagnostic field, but it has no separate comparison step.

The conformance scenario
`app_witness_score_beats_priority_after_depth_and_quorum_ties` pins the adjacency between rules 3 and 4.

Application witnesses are valid application messages that decrypt against a candidate state. Witness score counts
distinct senders per epoch. One sender cannot increase score by sending many messages in the same epoch.

The pinned protocol policy defines the quorum through:

```text
witness_quorum_senders_per_epoch
witness_quorum_epochs
max_witness_override_depth
```

For each branch epoch, the engine counts distinct senders with valid app messages on that branch:

```text
epoch_witness_score =
  min(distinct_valid_app_senders_at_epoch,
      witness_quorum_senders_per_epoch)
```

A branch meets witness quorum when at least `witness_quorum_senders_per_epoch` distinct senders witnessed at least
`witness_quorum_epochs` branch epochs.

When a branch meets witness quorum, the selector adds the pinned bounded boost:

```text
effective_commit_depth =
  raw_commit_depth
  + (witness_quorum_met ? max_witness_override_depth : 0)
```

This boost is capped. Under the pinned v1 policy, `max_witness_override_depth = 1`, so witness quorum can make a branch
compare as one commit deeper. It cannot compare as two or more commits deeper, no matter how many app messages exist.

Example with the pinned v1 policy:

```text
live branch:
  raw_commit_depth = 3
  witness_quorum_met = true
  effective_commit_depth = 4

private branch:
  raw_commit_depth = 4
  witness_quorum_met = false
  effective_commit_depth = 4

winner: live branch, because effective depth ties and witness quorum beats no quorum
```

The witnessed branch wins because the group had broad app-message evidence on that branch, and the competing branch is
only one commit deeper.

Another example with the pinned v1 policy:

```text
live branch:
  raw_commit_depth = 3
  witness_quorum_met = true
  effective_commit_depth = 4

private branch:
  raw_commit_depth = 5
  witness_quorum_met = false
  effective_commit_depth = 5

winner: private branch, because it is more than one valid commit deeper
```

The cap keeps app-message evidence secondary to the commit log. Witness quorum can protect the branch most members were
using from a small late private branch dump. It MUST NOT let application traffic overrule an arbitrarily longer valid
commit branch.

## Proposals

Proposals are pending until a canonical commit consumes them.

Proposal rules:

- A proposal is canonical only if a canonical commit consumes it.
- A valid proposal not yet consumed MAY remain pending until policy expiry.
- A proposal consumed only by an eligible losing branch is deferred until a later pass accepts it or the branch becomes
  permanently ineligible.
- A duplicate proposal MUST be reported as `AlreadySeen`.

Production engines derive proposal consumption from OpenMLS `ProposalRef` values observed before the staged commit is
merged.

## Application Messages

Application messages are not the consensus log. The engine processes them in the MLS epoch where they decrypt, then the
application orders accepted payloads with its application-level timestamp.

Application-message rules:

- A message that decrypts on the selected branch and is within the MLS past-epoch decryption limit MUST be emitted as
  `GroupEvent::MessageReceived`.
- A transport-wrapped application message for a past epoch SHOULD be retried against retained epoch contexts before it
  returns `TransportDeferred`; authenticated source-epoch evidence can instead establish a specific stale outcome.
- A transport-wrapped application message for a future candidate epoch SHOULD stay in `PeelDeferred` until branch
  selection advances the local MLS context; then it MUST be retried and emitted only if it decrypts on the selected
  branch.
- A message that decrypts only on a losing branch MUST be reported as `GroupEvent::AppMessageInvalidated`.
- A message older than the MLS past-epoch decryption limit MUST expire.
- A duplicate app message MUST be reported as `AlreadySeen`.
- If the engine stored a decrypted payload before invalidation, the invalidation event MUST retain a reference to that
  stored payload.

The engine MUST NOT emit an invalidated message as a normal received message.

## Policy

The adopted v1 convergence policy is pinned by the protocol:

```text
max_rewind_commits = 5
app_payload_past_epoch_limit = 5
settlement_quiescence_ms = 1000
witness_quorum_senders_per_epoch = 2
witness_quorum_epochs = 1
max_witness_override_depth = 1
```

These are protocol constants, not group state or local preferences. A future policy change requires a new app component
behind a required capability; clients MUST NOT negotiate or accept alternate values under v1. The canonical definition
lives in the adopted Marmot
[`protocol-core/convergence.md`](https://github.com/marmot-protocol/marmot/blob/master/protocol-core/convergence.md).

The branch selection function MUST NOT depend on wall-clock time. Local monotonic time only gates sync stability and
outbound publication.

## Storage Requirements

The engine MUST persist enough state to reproduce canonicalization after restart.

Required storage:

- group metadata and current epoch,
- OpenMLS state,
- retained Marmot and OpenMLS snapshots from current tip back through `max_rewind_commits`,
- durable message records for retained commits, proposals, app messages, and welcomes, with typed stored payloads
  distinguishing raw transport bytes from peeled OpenMLS wire bytes,
- message states and dispositions,
- pending commits, proposals, and application messages still inside retention,
- decrypted payload references retained by application policy,
- app invalidation records already surfaced to the application,
- dedupe index,
- queued outbound intents,
- last convergence-relevant input time.

The current storage does not persist convergence-policy constants or an engine version per group. V1 constants are
protocol-pinned, and the on-disk schema is versioned through storage migrations. A future policy revision that needs
on-disk compatibility detection requires an explicit policy-version stamp and migration.

Snapshot and rollback MUST be atomic across Marmot metadata and OpenMLS state. A rollback that restores only one side is
invalid.

Storage MAY discard artifacts outside the pinned protocol retention horizons. Once discarded, those artifacts cannot
cause rollback or app-message acceptance.

## Errors And Dispositions

Canonicalization errors are local engine results. They MUST NOT mutate group state unless a canonical branch was
selected and applied.

Required canonicalization errors:

- `UnsupportedPolicy`
- `MissingRetainedAnchor`
- `CandidateStateUnavailable`
- `MlsValidationFailed`
- `OutboundIntentStale`
- `StorageUnavailable`

Dropped messages use explicit reasons:

- `BeyondRollbackHorizon`
- `BeyondAnchor`
- `BeyondAppRetention`
- `InvalidAgainstCandidateState`
- `UnsupportedPolicy`
- `Malformed`

`AlreadySeen` is observable for commits, proposals, and application messages.

## Conformance Requirements

A conforming engine MUST pass scenario tests for:

- same pending set delivered in different orders,
- equal-depth fork resolved by app witnesses,
- witness quorum overriding only a bounded private-branch lead,
- child commit delivered before parent,
- proposal consumed by canonical commit,
- proposal on an eligible losing branch deferred,
- app message on losing branch invalidated with payload reference when known,
- late same-epoch commit replayed from a retained anchor,
- missing retained anchor reported without mutation,
- commit older than retained anchor dropped as `BeyondAnchor`,
- duplicate commit, proposal, and app message reported as `AlreadySeen`,
- outbound app and commit intents queued while syncing,
- app message retained across a pending publish and regenerated under the epoch the publish established,
- queued commit regenerated after settled convergence,
- restart reproducing the same canonicalization result from persisted storage,
- peeler-ingest to `GroupEvent` output across multiple in-memory clients.

The Rust simulator, property tests, generated delivery variants, and Tamarin model define the current conformance
baseline:

- [`crates/cgka-conformance-simulator`](../../crates/cgka-conformance-simulator)
- [`formal/tamarin/README.md`](../../formal/tamarin/README.md)

## Non-Goals For This Spec

This spec does not define:

- Nostr relay behavior.
- Relay receipts or first-seen metadata.
- A SQLite schema.
- FFI bindings.
- Application message rendering policy.
- Push notifications.
- Media/blob storage.

Those systems must preserve the engine boundary above when they are added.
