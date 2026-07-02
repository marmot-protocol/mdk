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

Two honest engines with the same retained anchor, pending message set, negotiated policy, engine version, and lifecycle
clock inputs MUST select the same canonical branch and produce the same protocol dispositions.

```text
same retained anchor
+ same pending messages
+ same negotiated policy
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

The engine MUST return stale and non-applicable messages as typed `IngestOutcome::Stale` values. Duplicate messages,
messages for unknown groups, messages addressed to another client, own echoes, and already-applied messages MUST NOT
require string parsing by the caller.

During `PendingPublish` or `Merging`, inbound group messages MAY be buffered. The engine MUST replay buffered messages
when the group returns to `Stable`.

Stored message payloads are typed:

- `RawTransport`: the original transport-wrapped message, kept for retry when peeling is not yet possible.
- `OpenMlsWire`: the same transport metadata with `payload` replaced by peeled MLS wire bytes, used by canonicalization
  and OpenMLS replay.

For group messages, the engine MUST first peel with the current MLS exporter context. If that fails and retained epoch
snapshots are available, it SHOULD try those retained contexts newest-to-oldest within the retention window before
classifying the message as `PeelDeferred`.

Transport group envelopes SHOULD carry a clear source-epoch hint. If the peeler reports that the source epoch is older
than the current local context and no retained snapshot can peel the message, the engine MUST classify the message as a
terminal `PeelFailed`, not `PeelDeferred`. This is the expected path for an invitee who joined via welcome and later
receives the invite commit that created that welcome: the invitee never had the pre-welcome epoch secret. Future-epoch
group messages, or group messages without a usable source-epoch hint, MAY remain `PeelDeferred`.

When convergence reaches a settled selected branch, the engine MUST retry `PeelDeferred` raw group messages for that
group. A retry that peels into OpenMLS wire bytes promotes the stored payload from `RawTransport` to `OpenMlsWire`; it
is then either processed immediately if it belongs to the current selected epoch or buffered as convergence input if it
targets a later candidate epoch. Raw `PeelDeferred` messages MUST NOT by themselves block outbound work; only peeled
OpenMLS commit, proposal, or application messages are unresolved convergence inputs.

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

When the group becomes stable, the application calls:

```text
advance_convergence(group_id) -> Vec<SendResult>
```

The engine MUST regenerate queued outbound work from the selected canonical state. It MUST remove a queued intent only
after regeneration succeeds.

If regeneration creates a group-evolution commit, `advance_convergence` MUST return that one publishable result and
pause later queued work until `confirm_published` or `publish_failed` resolves the pending commit.

## Commit Convergence

Commits are the consensus log. All honest engines that see the same valid commit set and policy MUST process commits in
the same canonical order.

The engine builds a bounded candidate-state graph from retained MLS snapshots. Production engines MUST derive candidate
edges by replaying MLS bytes against retained snapshots. They MUST NOT trust transport-provided parent metadata.

Commit rules:

- A commit creates a candidate edge only if it validates against exactly one parent state.
- A child commit whose parent is unavailable remains pending until the parent appears or the child expires.
- A commit at or after the retained anchor MAY be replayed from the retained snapshot for its source epoch.
- A commit older than the retained anchor MUST be dropped with `BeyondAnchor`.
- A commit that needs a retained snapshot inside the rewind window, when that snapshot is missing, MUST return
  `MissingRetainedAnchor` without mutating group state or message state.
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
  group policy.
- `effective_commit_depth`: `raw_commit_depth` plus the bounded witness boost when `witness_quorum_met` is true.

Witnesses are evidence that group members used a branch after it was created. They do not create epochs, apply commits,
or replace MLS validation.

Branches are compared in this order:

1. Higher effective commit depth.
2. Witness quorum beats no quorum.
3. Higher raw commit depth.
4. Higher app-witness score.
5. Lower tip commit digest.

Application witnesses are valid application messages that decrypt against a candidate state. Witness score counts
distinct senders per epoch. One sender cannot increase score by sending many messages in the same epoch.

The group policy defines the quorum. A typical policy uses:

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

When a branch meets witness quorum, the selector MAY add a bounded boost:

```text
effective_commit_depth =
  raw_commit_depth
  + (witness_quorum_met ? max_witness_override_depth : 0)
```

This boost is capped. If `max_witness_override_depth = 2`, witness quorum can make a branch compare as up to two commits
deeper. It cannot compare as three or more commits deeper, no matter how many app messages exist.

Example with `max_witness_override_depth = 2`:

```text
live branch:
  raw_commit_depth = 3
  witness_quorum_met = true
  effective_commit_depth = 5

private branch:
  raw_commit_depth = 5
  witness_quorum_met = false
  effective_commit_depth = 5

winner: live branch, because effective depth ties and witness quorum beats no quorum
```

The witnessed branch wins because the group had broad app-message evidence on that branch, and the competing branch is
only two commits deeper.

Another example with the same policy:

```text
live branch:
  raw_commit_depth = 3
  witness_quorum_met = true
  effective_commit_depth = 5

private branch:
  raw_commit_depth = 6
  witness_quorum_met = false
  effective_commit_depth = 6

winner: private branch, because it is more than two valid commits deeper
```

The cap keeps app-message evidence secondary to the commit log. Witness quorum can protect the branch most members were
using from a small late private branch dump. It MUST NOT let application traffic overrule an arbitrarily longer valid
commit branch.

## Proposals

Proposals are pending until a canonical commit consumes them.

Proposal rules:

- A proposal is canonical only if a canonical commit consumes it.
- A valid proposal not yet consumed MAY remain pending until policy expiry.
- A proposal consumed only by a losing branch MUST be dropped.
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
  is left in `PeelDeferred` or, when source-epoch metadata proves it is older than every retained context, terminally
  classified as `PeelFailed`.
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

Convergence policy is group policy. Engines MUST persist the negotiated policy per group and load it before convergence
after restart.

The policy contains:

- `max_rewind_commits`, default 5 for v0 groups.
- app-message past-epoch limit, derived from the MLS configuration.
- stable quiescence duration.
- witness quorum parameters.
- `max_witness_override_depth`.

Unsupported policy is a capability mismatch. A local default is only a fallback for groups that do not yet have a stored
policy.

The branch selection function MUST NOT depend on wall-clock time. Local monotonic time only gates sync stability and
outbound publication.

## Storage Requirements

The engine MUST persist enough state to reproduce canonicalization after restart.

Required storage:

- group metadata and current epoch,
- OpenMLS state,
- negotiated convergence policy and engine version,
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

Snapshot and rollback MUST be atomic across Marmot metadata and OpenMLS state. A rollback that restores only one side is
invalid.

Storage MAY discard artifacts outside negotiated retention horizons. Once discarded, those artifacts cannot cause
rollback or app-message acceptance.

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
- proposal on losing branch dropped,
- app message on losing branch invalidated with payload reference when known,
- late same-epoch commit replayed from a retained anchor,
- missing retained anchor reported without mutation,
- commit older than retained anchor dropped as `BeyondAnchor`,
- duplicate commit, proposal, and app message reported as `AlreadySeen`,
- outbound app and commit intents queued while syncing,
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
