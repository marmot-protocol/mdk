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

- `just tamarin` runs Tamarin on the model and requires `tamarin-prover` on `PATH`. Successful runs print only Tamarin's
  `summary of summaries`; failing runs print the full prover output.
- `just tamarin-interactive` opens the model in Tamarin's interactive UI and requires `tamarin-prover` on `PATH`.
- `just policy-casegen` emits Tamarin seed rules and executable lemmas from `policy_cases.json`.

## Install

Install Tamarin separately, then run:

```sh
just tamarin
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
proposal on losing branch => dropped proposal;
dropped proposal => never accepted
```

That maps to canonicalization's `accepted_proposals` and `dropped_messages` dispositions, with OpenMLS supplying the
consumed-proposal relation during replay.

The v0 model now uses bounded symbolic score classes instead of an opaque `ScoreCase` fact:

```text
dN       commit-depth or effective-depth class
wN       app-witness score class
qyes/qno witness quorum class
g00/gff  digest rank class, where lower wins final ties
```

The derivation rules mirror the selector order:

1. higher effective depth,
2. quorum tie,
3. higher raw commit depth,
4. higher app-witness score,
5. lower digest rank.

## How Proofs Map To Tests

Tamarin is the design model for the convergence properties in scope. It proves claims about the abstract rules in
`distributed_convergence_v0.spthy`. Rust tests then check that the implementation follows those rules with real data
structures, OpenMLS objects, storage, and scenario harnesses.

If behavior is outside the model, Tamarin says nothing about it. That behavior can still be specified in prose and
tested in Rust, but it has no formal proof until the model includes it.

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
