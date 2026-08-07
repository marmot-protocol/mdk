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
    home of the two liveness gates (rules 5 and 6 below), which keep a halted or
    silently split group from reading as healthy. `halt_advisory` and
    `liveness_advisory` expose those same computations independent of the verdict,
    so a co-occurring incident that loses the single verdict to a
    higher-precedence one is still surfaced — the CLI prints each as a secondary
    advisory.
- **Module:** `src/fork.rs`
  - **Role:** `recover_fork` turns a fork-recovery export into a `RecoveredFork`
    (source epoch + commit kind), or a `ForkRecoveryError` when it cannot be
    replayed. Two `ForkCommitKind`s are synthesizable: **group-data** forks
    (topic/name/avatar/retention) and **membership** forks (member add/remove,
    admin grant/revoke — all collapse to one `Membership` kind, so a real
    add-vs-promote race is one shape, not `MixedCommitKinds`). Rule-3 tier-b
    winner attribution (the invalidated commit's actor is the loser) runs
    **only for group-data forks** — the membership fork is winner-agnostic, and
    joins `fork_resolution.invalidated_msg_id` to the matching
    `group_state_changed.origin_commit_id`, then uses that row's
    `actor_member_ref` as the loser. This keeps attribution wholly in the MLS
    member-ref namespace.
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
    tries both label orderings and returns the vector only when every expectation
    matches — winner survival among them, since a per-client `GroupProfile`
    expectation pins the winner's group name, so the ordering search and the
    acceptance gate are one comparison and the persisted vector carries the
    winner check into CI. A
    **membership** fork is a single run-and-compare (winner-agnostic ⇒ no label
    search): `member_count == 3` is the survival proof. `accept_convergence` is a
    single run-and-compare (winner-agnostic
    ⇒ no label search) that returns the vector only when the recorded convergence
    decision reproduces. No reproduction ⇒ `AcceptError` (no vector).
- **Module:** `src/artifact.rs`
  - **Role:** Versioned evidence envelope and producer-attested normalized-history gate. Legacy exports produce an
    explicitly `outcome_equivalent_archetype` artifact with derived confidence and named unavailable fields. Attested
    import checks a complete Scenario IR claim, one bounded source-event mapping per step, explicit source rows
    establishing the contested incident, semantic expected outcomes, successful IR compilation, and simulator
    reproduction. It does not independently prove action-to-event correspondence and marks unredacted imported
    Scenario IR confidential. Raw MLS bytes and the engine checkpoint remain unavailable; byte replay requires the
    separate local sensitive capsule path.
- **Module:** `src/route.rs`
  - **Role:** `route` composes classify → import/recover → accept into one
    `Routing`: the primary `Outcome` (`Healthy | Accepted | Quarantine |
    InfrastructureFailure`) plus an `Advisory` per co-occurring finding. An
    incident verdict reads the producer's attested normalized history first
    (`src/artifact.rs`) and only synthesizes an archetype when the export carries
    none — the gate reads the export rather than the verdict, so it runs once,
    ahead of route dispatch, and both incident routes ask it the same question.
    An attested history that is rejected is fail-closed like any other route,
    *except* when the simulator could not be run at all: that decided nothing, so
    it is an `InfrastructureFailure` (the CLI's only non-classification exit-2)
    rather than a quarantine nobody reached. `route` also owns the
    **fall-through**: when the route the verdict selected fails its recovery
    closed, the remaining lower-precedence routes are tried rather than
    discarding a reproducible incident that shares the export (the real 26a9f546 export fail-closed on convergence
    `WitnessBoostNotDecisive` while carrying a cleanly acceptable membership fork
    at the same epoch). Classification precedence is untouched — fall-through runs
    only *after* a failure — and one rule keeps it honest: a lower route may
    override a higher route's quarantine only by producing an accepted vector. A
    second quarantine never displaces the higher-precedence one; it becomes an
    `advisory (fallback route):` instead. When the fall-through *does* produce an
    accepted vector, the superseded finding is also written into that artifact's
    `unavailable_fields` as `contested_convergence_replay`, with the same sentence
    the advisory carries: the advisory is stdout, the artifact is what gets
    persisted and read later as evidence, and an envelope showing a clean accepted
    archetype with no trace of the higher-precedence incident that shared the
    export fails the standard `archetype` already enforces on itself. The
    `fallback route` finding has no such home by construction — both routes failed
    closed, so there is no accepted artifact — and the advisory line is its only
    surface. Vector names live here too: they are pipeline facts, not CLI ones.
- **Module:** `src/main.rs`
  - **Role:** CLI — read one export file, detect its format, print the `Routing`.
    Reading and formatting only; route policy is `src/route.rs`. Exits 0 for any
    classification (healthy, quarantine, and accepted are all valid), 2 on
    usage/IO/parse/write failure and on an `InfrastructureFailure`. Output is one
    primary line plus an `advisory (<label>):` line per finding that line does not
    report: `superseded route` / `fallback route` (the fall-through above), `halt`
    (rule 5), and `liveness` (rule 6) — the last two suppressed only when the
    finding *is* the primary. So an accepted or quarantined incident never masks
    a co-occurring halted or stranded engine (the real e1a04e82 export carried
    both an accepted membership fork and a lag-12 stuck device). When an output
    directory is supplied, writes both the portable vector and the
    `incident-scenario-artifact.v1` evidence envelope owner-only, and refuses to
    persist an unreproduced attested artifact; it never copies the source export,
    transport ciphertext, or an MLS checkpoint.

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
5. **Quarantine `unrecoverable_halt`** — an engine recorded halting
   unrecoverably, so its group stays blocked until a verified repair clears the
   marker. Two audit surfaces arm it, and the reason string from whichever fired
   is reported per engine — **causes first-class, re-assertions only when there is
   no cause**. `already_unrecoverable` (emitted on every convergence attempt
   against an already-halted group) and `hydrate_unrecoverable_group` (every
   session open over one) *arm* the gate like any other reason, because a window
   of nothing but re-assertions is still a live halt, but they never say why the
   engine stopped: beside a real cause they are noise in the line an operator
   reads first, and `BTreeSet` order puts `already_unrecoverable` ahead of the
   diagnosis. Once the cause is known they add nothing — that a halt is durable
   and still being retried is what rule 5 *means*. When re-assertions are all the
   export has (the real 26a9f546 shape: the halt predates the window) they are
   reported, because the engine still has to be named and "the halt stands, cause
   not in this window" is the honest reading. The two surfaces are
   `convergence_run_state` with `phase: unrecoverable`
   (mdk#1110 — reason `frozen_pass_integrity_failure` from `error_kind:
   frozen_member_integrity`, and the reason-less `error_kind:
   missing_retained_anchor`, which is why the gate falls back to `error_kind`.
   mdk#1182 retired a third, `convergence_pass_base_changed` /
   `base_epoch_mismatch`: a pass whose base epoch disagrees with the tip is now
   discarded and reopened, emitting the non-terminal
   `convergence_pass_discarded`. Nothing emits the retired pair today, but the
   gate matches no reason whitelist, so historical exports carrying it still
   arm), and `epoch_state_changed` with `new_state:
   unrecoverable` (mdk#1106 — reason `hydrate_unrecoverable_group`, a durable
   halt that survived a restart). Unlike rule 6 this is not an inference from
   lag: the engine *stated* that it stopped, so *arming* the gate needs no
   timestamps to order evidence and no threshold to clear noise — only an
   `engine_id` to attribute the halt to. **Clearing** it needs more, because
   "until a verified repair clears the marker" is part of the rule, not a
   footnote: an engine that halted and then completed the repair is repaired, and
   reporting it would send the operator after a healed device. The clearing signal
   is `epoch_state_changed` with `new_state: stable` **and** `reason:
   join_welcome_repair` — `Engine::join_welcome` routes a halted group's re-join
   through `EpochManager::repair_to_stable` (its only caller, and the state
   machine's only accepted exit from `Unrecoverable`) and emits that row
   unconditionally right after. The `reason` is the whole signal; `new_state:
   stable` alone is the engine's ordinary healthy state (see the rejected designs
   below). Clearing is decided per **`(engine_id, group_ref)`** — `Unrecoverable`
   is per-group state, so a repair in one group must not clear another group's
   halt — by **repair strictly after the newest halt**, with surviving halts
   folded back
   per engine so an engine halted in two groups is still one halted engine with
   the union of its reasons. Newest-wins needs no global event ordering because a
   live halt is continuously re-asserted (every session open re-emits
   `hydrate_unrecoverable_group`; every convergence attempt emits
   `already_unrecoverable`), so a halt that outlived its repair leaves rows after
   it. Both rows come from one engine — one clock, one recorder file — so rule 6's
   cross-device grace does not apply here. Two boundaries of that comparison are
   contract, not incident: a repair sharing the halt's millisecond does **not**
   clear it (a tie orders nothing, and the two orders mean opposite things), and
   **one untimed halt row makes the whole halt side unorderable** — not just that
   row. The untimed row may be the newest halt evidence there is, so the newest
   *timed* halt is only a lower bound on the halt's position and a repair after
   that bound proves nothing; taking it as the halt's position is the fail-open
   direction, clearing a live halt on partially instrumented input. It therefore outranks rule 6, which it usually
   explains: on the real 26a9f546 export the halted engine is exactly the one
   rule 6 labelled `went dark`, and reporting the inference over the diagnosis
   would send the operator to re-pull for a confirmation they already have.
   A halt is a client failure, not a branch contest, so there is still nothing
   to replay. `halt_advisory` exposes the same computation verdict-independently,
   as `liveness_advisory` does for rule 6.
6. **Quarantine `epoch_divergence`** — an engine trails the group's epoch
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
7. **`Healthy`** — none of the above.

Rules 5 and 6 rank *below* the incident routes on purpose: a reproducible contest is
worth replaying even when another engine's data is stale (recovery fail-closes
downstream if the data it needs is missing). Each fires only on positive
evidence, with its own arming requirement: rule 5 arms on an attributable
self-reported halt — an `engine_id` plus a halt reason, no timestamps needed —
while rule 6 needs both an `engine_id` and `wall_time_ms` activity evidence.
Events missing those fields leave the respective rule unarmed, so synthetic
fixtures and older exports classify as before. Rule 5's asymmetry is deliberate:
*arming* needs no timestamps, because a halt is self-reported and repetition
carries no extra meaning, but *clearing* is an ordering claim about two rows and
absent timestamps therefore fail closed — the halt stands. The same applies to a
missing `group_ref`: `None` is its own scope, never a wildcard, so an
unattributed repair cannot clear an attributed halt. The asymmetry is the
fail-closed direction on purpose — a missed repair costs a re-pull, a missed halt
costs the incident. Rule 6 measures lag in
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
- *Reading Goggles' `epoch_state_transition` projection* for the rule-5 halt.
  That NDJSON section is where a halt carries `severity: error`, so it looks like
  the obvious input, but it is a *derived* row: its `evidence_ref.event_type` is
  `epoch_state_changed`, and on the real 26a9f546 export its 12 error rows are a
  1:1 projection of 12 audit events that state `new_state: unrecoverable`
  outright. Reading the audit event instead keeps the gate on primary evidence,
  keeps it working for the `agent-state.json` shape (whose projection layout is
  not verified here — no real document export was on hand), and keeps this model
  decoupled from Goggles' derivation rather than only from the engine's enum.
  No evidence is lost: every error-severity transition on that export is an
  unrecoverable one, and every unrecoverable one is error-severity.
- *A separate gate per halt surface.* `convergence_run_state{phase:
  unrecoverable}` and `epoch_state_changed{new_state: unrecoverable}` are two
  views of one incident — on the real export the same engine recorded both — so
  they fold into one per-engine report rather than two rules that would both fire
  and disagree about precedence. Each distinct reason is listed once: a halt is a
  state, not a count, so repetition is not severity.
- *Clearing a halt on any `new_state: stable` row.* The obvious reading of "the
  group returns to stable" is wrong: `stable` is the engine's ordinary state and
  is entered from `publish_confirmed`, `publish_failed`, `join_welcome`,
  `founding_create`, `auto_commit_stage_failed`, and
  `update_group_data_stage_failed` — none of which repairs anything.
  `publish_confirmed` alone is among the commonest rows in a healthy export, so
  this rule would clear every halt on the halted engine's next successful publish
  and delete the gate in practice. Only `reason: join_welcome_repair` marks the
  transition that actually exited `Unrecoverable`.
- *A presence-only downgrade* ("the engine halted but a repair row also exists ⇒
  not halted"). It cannot tell a repaired halt from a re-halt: halt→repair and
  repair→halt carry identical row sets and opposite meanings, and the rule gets
  the second one wrong on the worse side, reporting a currently-halted device as
  healthy. Ordering the newest of each is what separates them, which is why the
  fixture set carries both orders.
- *Ordering the two rows by `seq` or by line order.* `seq` is recorder-local and
  restarts at `0` on every recorder open *within the same file*
  (`docs/marmot-architecture/audit-logging.md`), so it cannot order rows across a
  restart — precisely the boundary a durable halt survives, making it wrong exactly
  where it matters. Line order would be an unverified server guarantee: Goggles
  does not document the export as clock-ordered, and depending on it would put a
  correctness claim on someone else's undocumented behaviour. `wall_time_ms` is
  the engine's own clock, and both rows compared come from one engine, so no
  cross-device skew enters.
- *Recognizing `convergence_pass_reopened`* (the non-terminal kind open PR #1182
  adds) ahead of its merge. Its wire shape can still change; it is non-terminal,
  so no rule would read it and the variant would be dead on arrival; and the
  parser is already lenient — an unmodelled kind maps to `EventKind::Other`
  harmlessly — so waiting costs nothing. Add it with the rule that needs it.
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
  The CLI rejects inputs larger than 64 MiB before JSON/NDJSON parsing.
- Keep real inputs under ignored `incident-exports/` and generated local output under `target/` or ignored
  `incident-replay-output/`. Producer-attested artifacts may contain unredacted Scenario IR labels and payloads;
  treat them as confidential unless separately redacted and reviewed. Never add sensitive local replay capsules or
  raw forensic exports to version control.

## Verification

```sh
cargo test -p incident-replay
cargo clippy -p incident-replay --all-targets
```
