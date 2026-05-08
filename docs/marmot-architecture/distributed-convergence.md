# Distributed Convergence

**Status:** design draft. This is the target model for Marmot clients that need
to converge on one MLS group state from unordered multi-relay input.

The engine contract that packages this model as a state-machine operation lives
in
[`cgka-engine-canonicalization-contract.md`](./cgka-engine-canonicalization-contract.md).

## Problem

Marmot commits are the consensus log. Every honest client that receives the
same set of valid messages should select the same commit sequence and reach the
same MLS epoch and group state.

Application messages are not part of the consensus log. They are processed in
the epoch they belong to, then the application orders payloads with its own
message timestamp. Application messages can still witness that a branch was
used by real group members.

The hard case is a returning client that fetches a bag of messages from several
relays:

- some commits are from the live branch,
- some commits are from branches the group later abandoned,
- some valid commits may have been created offline and published late,
- relay order and local arrival order are not correctness inputs.

The engine must choose a canonical branch from protocol evidence, not from
Nostr `created_at`, outer event ids, or local first-seen time.

## Pipeline Boundary

The transport adapter may buffer relay output, retry fetches, and make an early
best-effort ordering pass. That ordering is advisory. The peeler turns
transport events into protocol messages and hands those messages to the engine.

The engine owns the authoritative ordering decision for commits. It may hold a
short convergence buffer while relay input quiesces, then canonicalizes stored
commits, proposals, and app-message witnesses before mutating the live
`MlsGroup`. Accepted application messages and invalidation records are then
available for the application layer to render, hide, mark, or otherwise handle.

## Shape

The engine keeps a bounded candidate-state graph. The live `MlsGroup` is a
materialized view of the selected branch.

```mermaid
flowchart LR
    A["Finalized anchor<br/>oldest retained state"] --> B["Candidate state<br/>epoch N"]
    B --> C["Candidate state<br/>epoch N+1"]
    B --> D["Competing state<br/>epoch N+1"]
    C --> E["Selected tip"]
    D --> F["Losing branch<br/>messages invalidated"]
```

Graph terms:

- **Finalized anchor:** oldest retained group state usable as a rollback
  parent. The engine stores this as an epoch snapshot of both Marmot metadata
  and OpenMLS group state.
- **Candidate state:** materialized MLS state at an epoch, derived by applying
  valid commits from the anchor.
- **Edge:** commit that validates against exactly one parent candidate state.
- **Commit depth:** number of valid commits from fork epoch to branch tip.
- **App witness:** valid app message that decrypts against a candidate state.

Edges are discovered by replay. A v0.1 commit does not need an explicit parent
pointer.

## Retained Anchors

The retained anchor is the oldest epoch from which the engine may rebuild a
candidate branch. Implementations MUST retain epoch snapshots for the current
tip and every epoch inside `max_rewind_commits`. They MUST prune older retained
anchors once the current tip advances past the rewind window.

Late commits are handled by their source epoch:

- If the commit source epoch is at or after the retained anchor, the engine may
  roll back to that retained snapshot, replay candidate paths, and select the
  canonical branch.
- If the required retained snapshot is missing, canonicalization returns
  `MissingRetainedAnchor` and leaves group state and message state unchanged.
- If the commit source epoch is older than the retained anchor, the commit is
  dropped with `BeyondAnchor` and persisted as invalidated.

This rule is the local storage boundary for the forward-secrecy tradeoff. A
client cannot be forced to replay commits older than the group policy says it
will retain.

## Sync Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Stable
    Stable --> Syncing: reconnect / relay dump starts
    Syncing --> Canonicalizing: relay input quiesces
    Canonicalizing --> Stable: selected branch applied
    Syncing --> Syncing: queue outbound intents
```

During `Syncing`, outbound app messages and group changes are queued as local
intents. App-message intents are encrypted after sync against the selected
canonical state. Commit intents are regenerated after sync because any pending
MLS state created before sync may have been based on a stale epoch.

The application drives this lifecycle through `advance_convergence(group_id)`.
That call runs the convergence pass against the engine's monotonic clock and,
when the group is stable, returns regenerated `SendResult`s for queued local
work. A regenerated group evolution pauses draining until its publish lifecycle
is resolved; timer ticks in that pending-publish window return no work.

## Branch Selection

Only eligible branches are scored.

```text
eligible =
  current_tip_epoch - branch.fork_epoch <= max_rewind_commits
```

Witness score counts distinct senders per epoch:

```text
app_witness_score =
  sum over epochs:
    min(distinct_valid_app_senders_at_epoch,
        witness_quorum_senders_per_epoch)
```

A branch meets witness quorum when at least
`witness_quorum_senders_per_epoch` distinct senders produced valid app messages
on at least `witness_quorum_epochs` branch epochs.

```text
effective_commit_depth =
  valid_commit_depth
  + (witness_quorum_met ? max_witness_override_depth : 0)
```

Branches are compared in this order:

1. Higher `effective_commit_depth`.
2. Witness quorum beats no quorum.
3. Higher `valid_commit_depth`.
4. Higher `app_witness_score`.
5. Lower tip commit digest.

```mermaid
flowchart TD
    A["Message bag"] --> B["Build candidate states by MLS replay"]
    B --> C["Drop branches outside rewind horizon"]
    C --> D["Count distinct app witnesses per epoch"]
    D --> E["Apply bounded quorum boost"]
    E --> F["Tie-break by raw depth, witness score, digest"]
    F --> G["Materialize selected branch"]
    F --> H["Mark losing-branch messages invalidated"]
```

This lets a broadly used live branch beat a private branch that is only a few
commits longer. It does not let app traffic defeat an arbitrarily longer valid
branch. Counting distinct senders per epoch prevents one sender from winning
with message volume.

## Policy

The convergence policy should be group-negotiated. Working defaults:

```text
convergence_policy = {
  max_rewind_commits: 5,
  witness_quorum_senders_per_epoch: <group policy>,
  witness_quorum_epochs: <group policy>,
  max_witness_override_depth: <group policy>,
}
```

`max_rewind_commits` also bounds snapshot retention, so the forward-secrecy
cost is explicit. The engine persists the per-group policy and uses that stored
value after restart. Once MLS app components are available, the policy should
live there. Until then, Marmot can carry it in a group context extension and
treat an unsupported policy as a capability mismatch.

## Examples

### Equal-depth fork

Two branches both have depth 2. One branch has app witnesses from more distinct
members. The witnessed branch wins before digest tie-break.

### Withheld private branch

The live branch has 3 commits and witness quorum across 2 epochs. A private
branch later publishes 5 commits from the same fork. If
`max_witness_override_depth = 2`, the live branch receives a bounded boost and
wins the tie:

```text
live:     depth 3 + quorum boost 2 = effective 5
private:  depth 5 + quorum boost 0 = effective 5
winner:   live branch, because quorum beats no quorum
```

### Longer valid branch

The live branch has 3 commits plus quorum boost 2. A competing branch has 6
valid commits. The longer branch wins:

```text
live:      effective 5
competing: effective 6
winner:    competing branch
```

The quorum boost protects against short private branch dumps. It is not a way
for application traffic to overrule any valid branch.

## Current Implementation

The executable policy model lives in
[`crates/cgka-engine/src/convergence.rs`](../../crates/cgka-engine/src/convergence.rs).
The model tests live in
[`crates/cgka-conformance/tests/candidate_state_graph.rs`](../../crates/cgka-conformance/tests/candidate_state_graph.rs).
The executable canonicalization contract model lives in
[`crates/cgka-engine/src/canonicalization.rs`](../../crates/cgka-engine/src/canonicalization.rs).
That model materializes symbolic commit edges into candidate branches before
calling the branch selector. The OpenMLS projection layer builds production
candidate paths from stored commit bytes, probes them from retained snapshots,
applies the selected path, and persists message dispositions.

Those tests cover:

- equal-depth fork resolved by app witnesses,
- quorum overriding a small commit-depth lead,
- quorum failing to override a larger commit-depth lead,
- distinct senders counted per epoch,
- stale branch rejected by rewind horizon,
- digest as final tie-break.

Engine integration and OpenMLS conformance tests also cover:

- multi-commit path reconstruction from stored commits,
- child commit pending until its parent arrives,
- late same-epoch commits replayed from a retained anchor,
- missing retained anchor reported without mutation,
- retained anchor pruning by `max_rewind_commits`,
- stale commits older than the retained anchor invalidated,
- retained-anchor replay and stale invalidation after engine rebuild.

## Formal Verification

Tamarin is a good fit for the security-adjacent part of this model if we keep
the first model small.

The initial scaffold lives in
[`formal/tamarin/distributed_convergence_v0.spthy`](../../formal/tamarin/distributed_convergence_v0.spthy).
It models the selector boundary only: two honest clients, the same valid
candidate set, the same negotiated policy, and deterministic branch selection.
Scores are represented as bounded symbolic classes so the model can prove the
comparison order without modeling MLS internals.

Model first:

- commits as signed facts with `group`, `source_epoch`, `tip_epoch`, `sender`,
  and `digest`;
- app witnesses as authenticated facts tied to a branch epoch and sender;
- a bounded policy fact containing rewind horizon and quorum thresholds;
- adversary control over delivery order, withholding, duplication, and replay;
- honest clients applying the same deterministic `select` relation.

Initial lemmas:

1. **Deterministic convergence:** two honest clients with the same valid input
   set and policy select the same branch.
2. **Rewind bound:** no selected branch forks earlier than
   `max_rewind_commits`.
3. **Bounded witness override:** app witnesses cannot override more than
   `max_witness_override_depth` commits.
4. **Spam resistance:** multiple app witnesses from the same sender in one
   epoch count once.
5. **Outbound gate:** outbound intents queue while convergence is syncing and
   release only after the stability gate opens.
6. **Three-branch convergence:** clients that enumerate the same three
   candidate branches in different orders select the same winner.
7. **Late withheld commit rejection:** a branch published after the retained
   anchor is rejected when its rewind distance exceeds policy.
8. **Bounded policy seeds:** generated-family seed cases select the expected
   winner and reason.
9. **Loaded policy boundary:** selected and applied branches require a loaded
   convergence policy, and retained anchors are computed from that policy's
   rewind value.
10. **Retained-anchor replay:** a branch at or after an available retained
    anchor can be replayed and applied from that anchor.
11. **Anchor failure dispositions:** missing retained anchors report
    `MissingRetainedAnchor` without applying, while commits older than the
    retained anchor are invalidated with `BeyondAnchor` and are never selected
    or applied.
12. **Canonical app output:** accepted app messages become application-visible
    only after their canonical branch is applied; losing-branch app messages
    produce an invalidation disposition and are never delivered as normal
    output.
13. **Welcome/commit handoff:** a welcome-derived join lands the recipient at
    the post-commit epoch; the matching commit arriving afterward is
    `AlreadyAtEpoch` and does not trigger convergence selection or fork
    recovery. A stale same-source commit is fork-shaped only when the local
    client previously committed from that source epoch.
14. **Proposal disposition:** a proposal is accepted only when a canonical
    branch consumes it; proposals that belong only to losing branches are
    dropped and cannot also become accepted.

The v0 model currently verifies deterministic selection, eligible-only
selection, score-order justifications, stale-rewind rejection derived from
anchor/distance facts, sender/epoch witness dedupe, queued outbound gating,
three-branch permutations, late withheld publication after anchor, loaded-policy
requirements, retained-anchor replay, missing-anchor no-mutation, `BeyondAnchor`
invalidation, canonical app output, losing-branch app invalidation disposition,
welcome/commit handoff, proposal disposition, generated bounded seed cases, and
executable traces for each modeled scenario.
The bounded seed source is
[`formal/tamarin/policy_cases.json`](../../formal/tamarin/policy_cases.json);
`cgka-policy-casegen` emits matching Tamarin seed rules from the same file that
Rust selector tests consume.

The proof-to-test workflow is documented in
[`formal/tamarin/README.md`](../../formal/tamarin/README.md). Tamarin captures
the abstract convergence design; Rust unit, property, and scenario tests check
that the implementation follows it.

Leave full MLS cryptography abstract in the first model. Tamarin should reason
about ordering, eligibility, and adversarial message scheduling. The Rust tests
and OpenMLS integration cover implementation details.
