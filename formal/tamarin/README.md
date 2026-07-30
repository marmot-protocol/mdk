# Tamarin Convergence Model

This directory contains the first formal model for Marmot distributed convergence.

The v0 model is intentionally abstract. It does not model MLS internals, transport timestamps, relay receipts, Nostr
event ids, or OpenMLS serialization. It models only the convergence boundary:

- two honest clients see the same valid candidate set,
- those clients may enumerate the candidate pair in different orders,
- the engine loads a convergence policy before selecting or applying a branch,
- a deterministic policy chooses one branch,
- a branch outside policy evidence cannot be selected,
- witness quorum can only act through a bounded override rule.
- score comparison follows the same priority order as the Rust conformance selector.
- branches beyond the rewind horizon are ineligible even when they have higher raw depth.
- the retained anchor is computed from the loaded policy's rewind value.
- a branch at or after an available retained anchor can be replayed from that anchor.
- a missing retained anchor reports `MissingRetainedAnchor` and does not apply any canonical branch.
- a commit older than the retained anchor is invalidated with `BeyondAnchor` and is never selected or applied.
- accepted app messages become application-visible only after their canonical branch is applied.
- app messages tied only to a losing branch are invalidated and never delivered as normal application output.
- duplicate app witnesses from the same sender in the same epoch do not inflate witness score.
- stale rewind status is derived from retained anchor, branch fork epoch, rewind distance, configured limit, and the
  distance ordering fact.
- outbound intents are queued while convergence is syncing and released after the settlement gate opens.
- three-branch candidate sets converge even when clients enumerate branches in different orders.
- reordered, duplicated, and delayed delivery after peeling does not change canonical selection, duplicate the logical
  pending input, or duplicate app output/disposition emission.
- late withheld commits published after the retained anchor are rejected when their rewind distance exceeds policy.
- bounded generator seed cases preserve the expected selection reason.

The starting model is [`distributed_convergence_v0.spthy`](distributed_convergence_v0.spthy). Bounded generated-family
seeds live in [`policy_cases.json`](policy_cases.json). The Rust selector test and the Tamarin seed-rule generator both
read that file.

## Targets

- `just tamarin` runs Tamarin on the model with `--quit-on-warning` and an explicit 60-second derivation-check timeout,
  and requires `tamarin-prover` on `PATH`. Successful runs print only Tamarin's `summary of summaries`; prover errors,
  warnings, derivation-check timeouts, or a missing summary print the full output and fail the target.
- `just tamarin-interactive` opens the model in Tamarin's interactive UI and requires `tamarin-prover` on `PATH`.
- `just policy-casegen` emits Tamarin seed rules and executable lemmas from `policy_cases.json`.

## Install

Install Tamarin separately, then run:

```sh
just tamarin
```

To raise the derivation-check timeout on a slower machine without weakening the warning gate:

```sh
make -C formal/tamarin prove DERIVCHECK_TIMEOUT=120
```

To inspect generated policy-case output:

```sh
just policy-casegen
```

The command-line shape follows the official Tamarin manual: a `.spthy` file can be checked directly with
`tamarin-prover`, and lemmas can be proved with `--prove`.

References:

- [Tamarin model specification using
  rules](https://tamarin-prover.com/manual/master/book/005_protocol-specification-rules.html)
- [Tamarin property specification](https://tamarin-prover.com/manual/master/book/007_property-specification.html)
- [Tamarin command-line proving
  example](https://tamarin-prover.com/manual/master/book/003_example.html#running-tamarin-on-the-command-line)

## Modeling Notes

The first useful proof slice is not "MLS is secure." We inherit that from MLS and OpenMLS. The useful first slice is:

```text
same valid input set + same negotiated policy => same selected branch
```

That keeps the selector part of the formal model aligned with the Rust conformance model in
`crates/cgka-engine/src/convergence.rs`.

The current engine-lifecycle proof slice is:

```text
loaded group policy + retained anchor state => replay, invalidation, or
no-mutation error follows the same boundary as engine ingest
```

That keeps the lifecycle part aligned with `crates/cgka-engine/src/distributed_convergence.rs` and
`crates/cgka-engine/src/openmls_projection.rs`.

The current app-output proof slice is:

```text
applied canonical branch + app decrypt evidence => application-visible output;
losing-branch app invalidation => public invalidation disposition;
invalidated apps => no normal application-visible output
```

That maps to `GroupEvent::MessageReceived` and `GroupEvent::AppMessageInvalidated` emission in the engine integration
tests. The model now makes these emissions one-shot: the same client/app pair cannot produce duplicate accepted app
output, and the same invalidated app cannot produce duplicate invalidation dispositions.

The current delivery-order proof slice is:

```text
same logical peeled inputs + reordered delivery + delayed release + duplicate
delivery => same canonical branch; one pending input per logical message; one
visible or invalidated output disposition
```

That maps to the generated `convergence-e2e-delivery/v1` variants. Tamarin proves the abstract delivery contract; the
Rust variants check that queued delivery permutations preserve the real end-to-end group events.

The agreement lemmas explicitly premise the initializer's `SameInputSet` action facts and one run-scoped
`PolicyLoaded` action fact. Policy is global to a model run, so the latter is the model's same-policy premise for both
clients. This makes the theorem boundary visible, but it does not turn v0 into a parametric arbitrary-set proof:
candidate sets and policies are still supplied by the bounded initializer rules. Unequal input sets, policy mismatch,
clock/restart behavior, and liveness remain outside this Tamarin model.

The current welcome/commit handoff proof slice is:

```text
welcome for invite commit => recipient joins at post-commit epoch;
matching commit after welcome => AlreadyAtEpoch with no mutation;
own local commit from the same source epoch => fork-shaped stale commit
```

That maps to the welcome-before-commit ingest tests and the fork-detection boundary where only a client's own local
commit history makes stale same-source commits fork candidates.

The current proposal proof slice is:

```text
applied canonical branch + consumed proposal relation => accepted proposal;
proposal on an eligible losing branch => deferred proposal;
deferred proposal => retained eligibility and a different applied branch;
proposal on a permanently ineligible branch => dropped proposal;
dropped proposal => stale losing branch and never accepted
```

That maps to canonicalization's accepted, deferred, and dropped proposal dispositions, with OpenMLS supplying the
consumed-proposal relation during replay. A deferred proposal can be accepted by a later pass, so the model does not
assert terminal rejection merely because it lost one selection. A proposal is dropped only when its consuming branch
is permanently ineligible.

The v0 model now uses bounded symbolic score classes instead of an opaque `ScoreCase` fact:

```text
dN       commit-depth or effective-depth class
wN       app-witness score class
qyes/qno witness quorum class
p0/p1    commit-priority rank class, where lower wins
cHEX     authenticated-committer rank class, where lower wins
g00/gff  digest rank class, where lower wins final ties
```

The derivation rules mirror the selector order:

1. higher effective depth,
2. quorum tie,
3. higher app-witness score,
4. lower/preferred commit-priority rank,
5. lexicographically lower authenticated-committer rank,
6. lower digest rank.

Raw commit depth remains an input to effective depth and a diagnostic score field. It has no separate selector step:
once effective depth and quorum status tie, raw depth is necessarily tied as well.

## How Proofs Map To Tests

Tamarin is the design model for the convergence properties in scope. It proves claims about the abstract rules in
`distributed_convergence_v0.spthy`. Rust tests then check that the implementation follows those rules with real data
structures, OpenMLS objects, storage, and scenario harnesses.

If behavior is outside the model, Tamarin says nothing about it. That behavior can still be specified in prose and
tested in Rust, but it has no formal proof until the model includes it.

## Proof Inventory

Every v0 lemma belongs to exactly one verification category:

| Category | Lemmas |
| --- | --- |
| Agreement and selector safety | `same_input_set_converges`, `selected_branches_are_eligible`, `selected_branches_require_loaded_policy`, `effective_depth_selection_requires_score_order`, `quorum_tie_selection_requires_quorum_and_bound`, `witness_score_selection_requires_score_order`, `priority_tie_selection_requires_preceding_equality_and_lower_priority`, `committer_tie_selection_requires_preceding_equality_and_lower_committer`, `digest_tie_selection_requires_lower_digest`, `opponent_ineligible_selection_requires_stale_opponent`, `duplicate_witness_dedupe_selection_uses_distinct_sender_epochs`, `three_branch_selection_requires_dominance`, `generated_bounded_case_selection_matches_expected_reason`, `no_conflicting_better_for_same_run` |
| Lifecycle and application-output safety | `applied_branch_requires_prior_selection`, `accepted_app_output_requires_applied_branch`, `application_visible_requires_accepted_app_output`, `losing_app_invalidation_requires_applied_different_branch`, `invalidated_apps_are_never_application_visible`, `app_invalidation_disposition_requires_invalidation`, `invalidated_dispositions_are_never_application_visible`, `accepted_app_output_once_per_client_app`, `app_invalidation_disposition_once_per_app`, `welcome_acceptance_requires_matching_commit_context`, `commit_after_welcome_requires_prior_welcome`, `welcome_replayed_commit_does_not_select_branch`, `welcome_replayed_commit_does_not_detect_fork`, `fork_detection_requires_prior_local_commit`, `accepted_proposal_requires_applied_consuming_branch`, `deferred_proposal_requires_applied_different_branch`, `deferred_proposal_requires_eligible_losing_branch`, `dropped_proposal_requires_applied_ineligible_branch`, `dropped_proposals_are_never_accepted`, `queued_outbound_requires_syncing`, `released_queued_outbound_requires_prior_queue`, `syncing_outbound_is_never_published_directly`, `settled_publish_requires_lifecycle_stable_state` |
| Delivery safety | `released_delayed_input_requires_prior_delay`, `delivery_pending_input_requires_delivery_observation`, `delivery_pending_input_is_deduplicated`, `duplicate_delivery_requires_prior_pending_input`, `delivery_reordered_clients_select_same_branch`, `delivery_losing_app_never_application_visible` |
| Retained-history safety | `computed_anchor_requires_loaded_policy_rewind`, `retained_anchor_replay_requires_available_anchor_and_policy`, `missing_retained_anchor_requires_missing_snapshot_and_policy`, `missing_retained_anchor_does_not_apply`, `beyond_anchor_invalidation_requires_source_before_anchor`, `beyond_anchor_invalidated_commits_are_never_selected`, `beyond_anchor_invalidated_commits_are_never_applied`, `stale_rewind_is_derived_from_anchor_and_distance`, `stale_branches_are_never_selected`, `late_withheld_rejection_requires_publish_after_anchor_and_stale` |
| Executability and bounded-case coverage | `quorum_override_executable`, `raw_depth_lead_executable`, `witness_score_tie_executable`, `digest_tie_executable`, `stale_rewind_executable`, `duplicate_witness_dedupe_executable`, `outbound_queue_release_executable`, `outbound_settled_publish_executable`, `three_branch_permutation_executable`, `withheld_published_after_anchor_executable`, `retained_anchor_within_horizon_executable`, `missing_retained_anchor_executable`, `beyond_anchor_invalidated_executable`, `commit_application_app_output_executable`, `welcome_before_commit_handoff_executable`, `own_commit_fork_handoff_executable`, `proposal_canonical_consumption_executable`, `delivery_order_robustness_executable`, `generated_quorum_override_executable`, `generated_quorum_capped_by_depth_executable`, `generated_depth_priority_executable`, `generated_witness_priority_executable`, `generated_priority_tie_executable`, `generated_committer_tie_executable`, `generated_digest_priority_executable` |

The inventory classifies proof scope; it is not a coverage claim for clocks, restart, durable pass generations,
fairness, resource exhaustion, or unbounded self-update traffic.

- **Tamarin artifact:** `Init_*` rule
  - **What it means:** A named abstract scenario.
  - **Rust counterpart:** A named fixture or setup in an integration/scenario test.

- **Tamarin artifact:** `exists-trace` lemma
  - **What it means:** The scenario is reachable in the model.
  - **Rust counterpart:** A minimum end-to-end scenario the implementation should handle.

- **Tamarin artifact:** `Derive_*` rule
  - **What it means:** One policy step, such as score comparison or stale derivation.
  - **Rust counterpart:** Unit tests for the selector/comparator and its selected reason.

- **Tamarin artifact:** all-traces lemma
  - **What it means:** An invariant that must hold in every modeled trace.
  - **Rust counterpart:** Property tests, invariant assertions, or both.

- **Tamarin artifact:** `*_requires_*` lemma
  - **What it means:** A selected outcome must have matching evidence.
  - **Rust counterpart:** Debug assertions or tests that inspect selection reasons and evidence.

- **Tamarin artifact:** lifecycle lemma
  - **What it means:** A canonicalization handoff, such as policy load, retained replay, missing anchor, `BeyondAnchor`,
    or app output, has the required evidence and mutation boundary.
  - **Rust counterpart:** Engine integration tests in `crates/cgka-engine/tests/distributed_convergence.rs`, OpenMLS
    replay tests in `crates/cgka-conformance-simulator/tests/openmls_replay_probe.rs`, and harness E2E coverage in
    `crates/cgka-conformance-simulator/tests/canonical_scenarios.rs`.

- **Tamarin artifact:** delivery-order lemma
  - **What it means:** Reordered, delayed, and duplicate delivery after peeling is normalized before canonical output.
  - **Rust counterpart:** `generate_convergence_e2e_delivery_family` in
    `crates/cgka-conformance-simulator/src/family.rs` and `convergence_e2e_delivery_family_runs_generated_variants`.

- **Tamarin artifact:** model assumption
  - **What it means:** A fact the model accepts as already validated.
  - **Rust counterpart:** Tests or review at the layer that owns the assumption.

Keep names aligned across the proof and tests. If the Tamarin scenario is `quorum_override`, the Rust test or fixture
should use the same phrase. Grep should connect the formal model, the unit/property test, and the integration scenario.

For bounded policy seeds, update `policy_cases.json` first. Then check both consumers:

```sh
cargo test -p cgka-conformance-simulator --test generated_policy_cases
cargo run -p cgka-conformance-simulator --bin cgka-policy-casegen -- --format tamarin formal/tamarin/policy_cases.json
```

The six-rule adjacency cases stay grep-aligned across both consumers:

- `generated_priority_tie` / `generated_priority_tie_executable` /
  `generated_priority_tie_matches_selector_before_digest`
- `generated_committer_tie` / `generated_committer_tie_executable` /
  `generated_committer_tie_matches_selector_before_digest`

Use the executable lemmas as a fixture catalog. Each one says "this situation exists and the system must handle it." Use
the universal lemmas as property-test targets. For example, `same_input_set_converges` maps to generated branch sets fed
through the real selector from different client enumeration orders.

Use Tamarin for behavior where local reasoning is weak: cross-client convergence, adversarial scheduling, branch
eligibility, commit ordering, retained-anchor lifecycle, and state handoff between subsystems. Prefer Rust tests for
storage behavior, wire parsing, serialization, and pure input-to-output functions.

The model has done its job for this subsystem when the lemmas answer the convergence questions under the stated
assumptions. If someone asks what happens in a case and there is no lemma, scenario, or explicit assumption to point at,
that is a model gap.

Next refinements:

1. Generate broader bounded scenario families from the Rust policy model.
2. Replace symbolic score classes with generated bounded numeric families.
3. Add a code-generation path that emits both Tamarin seed scenarios and Rust property-test cases from one policy-case
   source.
4. Add generated lifecycle cases once retained-anchor policy families move beyond the current one-rewind hand-written
   scenarios.
