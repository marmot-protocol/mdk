# CGKA Engine Spec

**Status:** draft normative spec for the current CGKA engine boundary.

This document defines the CGKA engine contract Marmot clients must implement to
process MLS group state consistently across unordered transports. The detailed
design notes remain in
[`cgka-engine-canonicalization-contract.md`](./cgka-engine-canonicalization-contract.md)
and [`distributed-convergence.md`](./distributed-convergence.md).

## Scope

The CGKA engine starts after transport peeling and ends at application-visible
group events plus publishable outbound transport messages.

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

The application MUST interact with the engine through the `CgkaEngine` contract.
It MUST NOT call OpenMLS directly for group state transitions.

The engine receives transport-independent `TransportMessage` values and uses an
injected `TransportPeeler` to obtain MLS bytes. Transport order, relay order,
relay timestamps, Nostr event ids, and local arrival order are advisory. They
MUST NOT decide the canonical commit branch.

The engine emits:

- `IngestOutcome` for each inbound message.
- `GroupEvent` records for application-visible effects.
- `SendResult` records for local outbound work.
- auto-publish messages created by engine policy, such as SelfRemove commits.

## Core Invariant

Two honest engines with the same retained anchor, pending message set,
negotiated policy, engine version, and lifecycle clock inputs MUST select the
same canonical branch and produce the same protocol dispositions.

```text
same retained anchor
+ same pending messages
+ same negotiated policy
+ same engine version
+ same lifecycle clock inputs
= same canonical branch and dispositions
```

This invariant applies to commits, proposals, application-message acceptance,
application-message invalidation, duplicate detection, and outbound intent
gating.

## Engine State

Each group has an `EpochState`:

- `Stable`: no local pending commit; inbound and outbound work may proceed.
- `PendingPublish`: a local group-evolution commit exists and is waiting for
  transport publication confirmation.
- `Merging`: publication was confirmed and the engine is merging pending MLS
  state.
- `Recovering`: the engine has detected a fork-shaped conflict and is using
  retained state to recover.

Only the engine may construct non-`Stable` states. Applications observe state
through typed outcomes, not direct state mutation.

The engine also derives a convergence sync state:

- `Syncing`: collecting convergence-relevant messages.
- `Canonicalizing`: replaying candidates and assigning dispositions.
- `Stable`: no convergence-relevant input has arrived for at least the
  configured quiescence window, and the selected branch has been applied.

`sync_state` is a derived result. It is not an input claim made by the caller.

## Inbound Processing

`ingest(msg)` MAY be called in any order. The engine MUST deduplicate by a
transport-independent `MessageId`.

Inbound processing has this shape:

```text
TransportMessage
  -> peel group message or welcome
  -> store durable message bytes
  -> classify commit / proposal / app message / welcome
  -> buffer or process according to group state
  -> emit IngestOutcome and later GroupEvent values
```

The engine MUST return stale and non-applicable messages as typed
`IngestOutcome::Stale` values. Duplicate messages, messages for unknown groups,
messages addressed to another client, own echoes, and already-applied messages
MUST NOT require string parsing by the caller.

During `PendingPublish` or `Merging`, inbound group messages MAY be buffered.
The engine MUST replay buffered messages when the group returns to `Stable`.

## Welcomes

A welcome join lands the recipient at the post-commit epoch carried by the
welcome. If the matching commit arrives later, the engine MUST classify that
commit as already applied. It MUST NOT treat that ordinary handoff as a fork.

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

If publication fails, the application calls `publish_failed(pending)`. The
engine MUST discard the pending commit and return to the prior stable state.

The engine MUST NOT advance local group state for a local commit until the
application confirms publication. This rule prevents local epoch advance for a
commit the rest of the group cannot see.

Auto-publish commits created by engine policy are drained through
`drain_auto_publish`. In v0 they do not have a per-message confirm callback.

## Outbound Intent Gating

If a group has unresolved convergence input, `send(intent)` MUST store the
intent durably and return `SendResult::Queued`.

When the group becomes stable, the application calls:

```text
advance_convergence(group_id) -> Vec<SendResult>
```

The engine MUST regenerate queued outbound work from the selected canonical
state. It MUST remove a queued intent only after regeneration succeeds.

If regeneration creates a group-evolution commit, `advance_convergence` MUST
return that one publishable result and pause later queued work until
`confirm_published` or `publish_failed` resolves the pending commit.

## Commit Convergence

Commits are the consensus log. All honest engines that see the same valid
commit set and policy MUST process commits in the same canonical order.

The engine builds a bounded candidate-state graph from retained MLS snapshots.
Production engines MUST derive candidate edges by replaying MLS bytes against
retained snapshots. They MUST NOT trust transport-provided parent metadata.

Commit rules:

- A commit creates a candidate edge only if it validates against exactly one
  parent state.
- A child commit whose parent is unavailable remains pending until the parent
  appears or the child expires.
- A commit at or after the retained anchor MAY be replayed from the retained
  snapshot for its source epoch.
- A commit older than the retained anchor MUST be dropped with `BeyondAnchor`.
- A commit that needs a retained snapshot inside the rewind window, when that
  snapshot is missing, MUST return `MissingRetainedAnchor` without mutating
  group state or message state.
- Candidate states outside the retention horizon MUST be dropped.

Same-epoch commit recovery uses a content-derived ordering key:

```text
CommitOrderingKey {
  source_epoch,
  commit_digest = SHA-256(mls_bytes)
}
```

Lower ordering keys win. Transport metadata MUST NOT affect this recovery rule.

## Branch Selection

Only branches inside `max_rewind_commits` are eligible.

Branches are compared in this order:

1. Higher effective commit depth.
2. Witness quorum beats no quorum.
3. Higher raw commit depth.
4. Higher app-witness score.
5. Lower tip commit digest.

Application witnesses are valid application messages that decrypt against a
candidate state. Witness score counts distinct senders per epoch. One sender
cannot increase score by sending many messages in the same epoch.

The witness quorum MAY add a bounded depth boost. It MUST NOT override more
than `max_witness_override_depth` commits.

## Proposals

Proposals are pending until a canonical commit consumes them.

Proposal rules:

- A proposal is canonical only if a canonical commit consumes it.
- A valid proposal not yet consumed MAY remain pending until policy expiry.
- A proposal consumed only by a losing branch MUST be dropped.
- A duplicate proposal MUST be reported as `AlreadySeen`.

Production engines derive proposal consumption from OpenMLS `ProposalRef`
values observed before the staged commit is merged.

## Application Messages

Application messages are not the consensus log. The engine processes them in
the MLS epoch where they decrypt, then the application orders accepted payloads
with its application-level timestamp.

Application-message rules:

- A message that decrypts on the selected branch and is within the MLS
  past-epoch decryption limit MUST be emitted as `GroupEvent::MessageReceived`.
- A message that decrypts only on a losing branch MUST be reported as
  `GroupEvent::AppMessageInvalidated`.
- A message older than the MLS past-epoch decryption limit MUST expire.
- A duplicate app message MUST be reported as `AlreadySeen`.
- If the engine stored a decrypted payload before invalidation, the
  invalidation event MUST retain a reference to that stored payload.

The engine MUST NOT emit an invalidated message as a normal received message.

## Policy

Convergence policy is group policy. Engines MUST persist the negotiated policy
per group and load it before convergence after restart.

The policy contains:

- `max_rewind_commits`, default 5 for v0 groups.
- app-message past-epoch limit, derived from the MLS configuration.
- stable quiescence duration.
- witness quorum parameters.
- `max_witness_override_depth`.

Unsupported policy is a capability mismatch. A local default is only a fallback
for groups that do not yet have a stored policy.

The branch selection function MUST NOT depend on wall-clock time. Local
monotonic time only gates sync stability and outbound publication.

## Storage Requirements

The engine MUST persist enough state to reproduce canonicalization after
restart.

Required storage:

- group metadata and current epoch,
- OpenMLS state,
- negotiated convergence policy and engine version,
- retained Marmot and OpenMLS snapshots from current tip back through
  `max_rewind_commits`,
- durable message records for retained commits, proposals, app messages, and
  welcomes,
- message states and dispositions,
- pending commits, proposals, and application messages still inside retention,
- decrypted payload references retained by application policy,
- app invalidation records already surfaced to the application,
- dedupe index,
- queued outbound intents,
- last convergence-relevant input time.

Snapshot and rollback MUST be atomic across Marmot metadata and OpenMLS state.
A rollback that restores only one side is invalid.

Storage MAY discard artifacts outside negotiated retention horizons. Once
discarded, those artifacts cannot cause rollback or app-message acceptance.

## Errors And Dispositions

Canonicalization errors are local engine results. They MUST NOT mutate group
state unless a canonical branch was selected and applied.

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
- queued commit regenerated after stable convergence,
- restart reproducing the same canonicalization result from persisted storage,
- peeler-ingest to `GroupEvent` output across multiple in-memory clients.

The Rust simulator, property tests, generated delivery variants, and Tamarin
model define the current conformance baseline:

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
