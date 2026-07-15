# AGENTS.md — incident-replay

Goggles forensic export → CGKA conformance-vector adapter. Two wire formats are
read — the `agent-state.json` document and the streamed NDJSON group export
(`goggles-group-export/v1`) — into one model. The pipeline is **parse →
classify → recover → synthesize → accept**: a fork-recovery or convergence
incident becomes a vector only if the simulator reproduces the recorded outcome
(fail-closed).

## Pieces

- **Module:** `src/export.rs`
  - **Role:** Lenient, self-owned model of the export plus `parse`. Models only
    the fields the pipeline needs and ignores everything else, so it tolerates
    the export growing new fields. Deliberately decoupled from `marmot-forensics`:
    it tracks the stable `marmot-forensics-audit/v2` wire shape Goggles
    serialises, not the engine's internal `AuditEventKind` enum.
- **Module:** `src/ndjson.rs`
  - **Role:** `parse_stream` — the second parser: the streaming NDJSON group
    export into the same `AgentStateExport`. Enforces the stream's completeness
    contract fail-closed at parse time (leading `manifest`, terminal `eof` with
    `complete: true`, per-section counts matching what arrived, and no in-band
    `error` line — the server's only failure surface once the HTTP status is
    committed), which replaces the `has_more` truncation signal of the document
    shape. `is_stream` detects the format from the contract's manifest-first
    rule, so the CLI needs no format flag.
- **Module:** `src/classify.rs`
  - **Role:** The `classify` gate → `Verdict`: `Healthy | ForkRecovery |
    ConvergenceSelected | Quarantine { reason }`. Everything downstream is gated
    behind this, so a healthy export yields zero vectors and a clean exit. Also
    home of the liveness gate (rule 5 below), which keeps a silently split
    group from reading as healthy. `liveness_advisory` exposes that same rule-5
    computation independent of the verdict, so a co-occurring liveness incident
    that loses the single verdict to a higher-precedence incident (fork or
    convergence) is still surfaced — the CLI prints it as a secondary advisory.
- **Module:** `src/fork.rs`
  - **Role:** `recover_fork` turns a fork-recovery export into a `RecoveredFork`
    (source epoch + commit kind), or a `ForkRecoveryError` when it cannot be
    replayed. Two `ForkCommitKind`s are synthesizable: **group-data** forks
    (topic/name/avatar/retention) and **membership** forks (member add/remove,
    admin grant/revoke — all collapse to one `Membership` kind, so a real
    add-vs-promote race is one shape, not `MixedCommitKinds`). Rule-3 tier-b
    winner attribution (the invalidated message's publisher is the loser) runs
    **only for group-data forks** — the membership fork is winner-agnostic, and
    real observer-recorded exports cannot join a publisher's `account_ref` (the
    observing engine) to a committer's `actor_member_ref` (an MLS member id), so
    the join is structurally impossible on real data.
- **Module:** `src/convergence.rs`
  - **Role:** `recover_convergence` turns a convergence-selected export into a
    `RecoveredConvergence` (the decisive rule + a `ConvergenceDecisionKind`), or a
    `ConvergenceRecoveryError`. It reproduces the **committer-decided** case
    (`tip_committer` decisive, no quorum) and the **witness-decided** case
    (`effective_commit_depth` decisive between two *equal-depth* branches, where
    the winner's app-witness quorum boost broke the tie — the real-traffic case).
    Any other shape fail-closes: a committer tiebreak that itself met a quorum, a
    witness winner whose branches were not at equal `valid_commit_depth` (so it won
    on raw commit depth, not the boost), indistinct candidate branch ids, or a
    priority/digest rule.
- **Module:** `src/synth.rs`
  - **Role:** `synthesize` builds the concurrent-fork `VectorFixture`, dispatching
    on the commit kind: a **group-data** fork (two committers race `UpdateGroupData`
    commits, no `SetPartition`) or a **membership** fork (two committers race
    competing invites with the two invitees held out by a partition; after
    recovery `member_count == 3` proves exactly one branch survived — the proven
    `convergence-chaos/v1` invite-fork shape). `synthesize_convergence`
    dispatches on `ConvergenceDecisionKind`: the committer-decided vector (two
    admins race invite commits observed by a passive third client) or the
    witness-decided vector (the observer delivers two senders' app messages on one
    branch, then a held competing commit is released — the app-witness quorum
    overrides the committer tiebreak on the reorg). Both normalise real epochs to
    the simulator's `1 → 2` range; the convergence assertion is winner-agnostic.
- **Module:** `src/accept.rs`
  - **Role:** `accept` (fork) dispatches on the commit kind. A **group-data** fork
    tries both label orderings and returns the vector only when the full
    `RecoverySummary` matches **and** the designated winner's branch survives. A
    **membership** fork is a single run-and-compare (winner-agnostic ⇒ no label
    search): `member_count == 3` is the survival proof. `accept_convergence` is a
    single run-and-compare (winner-agnostic
    ⇒ no label search) that returns the vector only when the recorded convergence
    decision reproduces. No reproduction ⇒ `AcceptError` (no vector).
- **Module:** `src/main.rs`
  - **Role:** CLI — classify one export file; for a fork-recovery or convergence
    incident, run the recover → accept → write pipeline. Exits 0 for any
    classification (healthy, quarantine, and accepted are all valid), 2 on
    usage/IO/parse/write failure. Also prints a secondary `advisory (liveness):`
    line whenever `liveness_advisory` fires and the primary verdict is not
    already the epoch-divergence quarantine, so an accepted or quarantined
    incident never masks a co-occurring engine left behind (the real e1a04e82
    export carried both an accepted membership fork and a lag-12 stuck device).

## Classification rules (verified against real Goggles exports)

Precedence, highest first:

1. **Quarantine `truncated_projections`** — any `derived_projections.pagination`
   section has `has_more == true`. A capped export is incomplete, so reproduction
   could silently miss witnesses or state.
2. **`ConvergenceSelected`** — any `convergence_decision` is *contested*
   (`losing_branch_ids` non-empty, or ≥2 candidates). Routine single-branch passes
   are not incidents; healthy real traffic is full of them.
3. **Quarantine `missing_snapshot`** — a `fork_resolution` won with
   `missing_snapshot` (the winning snapshot was unavailable, so it can't be
   replayed) on the fork-recovery route.
4. **`ForkRecovery`** — any other `fork_resolution`.
5. **Quarantine `epoch_divergence`** — an engine trails the group's epoch
   high-water mark by ≥ 2 epochs (one epoch is routine commit propagation).
   The reason names every engine left behind with its epoch and a per-engine
   mode: **`went_dark`** (its events end before — or within one hour of — the
   group provably advancing past it: a dead device, stopped uploads, or a
   member who left; telling a departure apart needs a member↔engine linkage
   the export does not carry yet) or **`active_while_behind`** (it kept
   recording events for over an hour after the group moved past it without
   catching up: commits are not reaching it while its other traffic flows).
   A real liveness incident, but not a branch contest, so there is nothing to
   replay — the named engines are the triage starting point.
6. **`Healthy`** — none of the above.

Rule 5 ranks *below* the incident routes on purpose: a reproducible contest is
worth replaying even when another engine's data is stale (recovery fail-closes
downstream if the data it needs is missing). It fires only on positive
evidence — no engine ids or timestamps means the gate stays unarmed — so
synthetic fixtures and older exports classify as before. Lag is measured in
epochs, not wall-clock silence: a device that is offline while nothing is
committed misses nothing, and an idle group never reads as stale. The ≥ 2
threshold is derived, not tuned — lag 1 is the propagation noise floor, so 2 is
the smallest lag that cannot be a single in-flight commit; the backtest over the
incident's hourly slices is the falsification check, not the calibration.
Verified against both real exports on hand (2026-07-09): the reported incident
(three engines dark at epochs 11–14 of 16, one active engine cut off from
commits for hours) and a second real export (one engine eighteen hours behind
the other's epoch 17) — **both previously classified `Healthy`**; the second
export's earlier "healthy" label predates this gate and was a false negative.
Both come from one cohort on a single day, so the healthy-side margins are
demonstrated, not proven general.

A single quarantine is a re-pull trigger, not a verdict: read it across pulls.
Entries that vanish on the next pull were catch-up in flight — a pre-merge
backtest (hourly slices of the 2026-07-09 incident export replayed through the
CLI) measured the overnight batch-delivery shape (a device quiet through a
burst of commits, then processing the backlog in one go) on half the engines,
and every one labeled `went_dark` on the pull that caught it. Entries that
persist across pulls are the signal.

Gate designs evaluated against real exports and deliberately **rejected**:

- *Member-count coverage* (`group_context.member_count` > exporting engines):
  audit is opt-in, so healthy groups routinely have more members than engines
  (a real six-member group exported from only two engines) — the gate would
  quarantine them all, permanently, and its precedence masked the sharper
  per-engine signals on the real incident.
- *Wall-clock staleness* (engine silent > 24 h behind the export's latest
  activity): a device that is merely offline while no commits land misses
  nothing and converges on return; epoch-anchored lag subsumes the cases that
  matter.
- *Softer arming* (two variants, both refuted by the same backtest): arming only
  on `active_while_behind` would have missed the incident's genuinely-stuck
  device entirely — its uploads had stopped, so it read as dark in the export,
  and absent a second, active stuck device there would have been nothing to fire
  on. And grace-gating the arming (fire only once the group's evidence extends
  past `moved_past + grace`) delays the first true detection by an hour on the
  backtest while still firing on any device offline longer than the grace —
  nearly all the noise, none of the earliness.

## Fixtures

- `tests/fixtures/*.json` / `*.ndjson` are **synthetic and non-sensitive** — the
  committed test set. Real exports carry relay URLs / message ids and must never
  enter VCS.
- Real exports are the manual pre-PR verification set:
  `cargo run -p incident-replay -- <export.json | export.ndjson>`.

## Verification

```sh
cargo test -p incident-replay
cargo clippy -p incident-replay --all-targets
```
