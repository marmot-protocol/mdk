# Existing MDK evidence

Paths below are relative to the repository root. This is a navigation map
checked on 2026-11-04, not a record of fresh proof runs. Read the owning
sources for current scope and command requirements.

| Question | Start here | What the evidence establishes and excludes |
| --- | --- | --- |
| Abstract branch selection, eligibility, handoff, and output safety | `formal/tamarin/AGENTS.md`, `formal/tamarin/README.md`, `formal/tamarin/distributed_convergence_v0.spthy` | Symbolic model under its initializers, score classes, and same-input/same-policy premises. Does not verify MLS cryptography or arbitrary Rust execution. |
| Device-pairing confirmation and Welcome-sender authentication | `formal/pairing/README.md`, `formal/pairing/device_pairing_v1.spthy` | Symbolic authentication for one account, unbounded roles, shared groups and fixed honest identities, assuming ideal full-code comparison and combined MLS artifact validation. Excludes code-guessing bounds, timers, crashes, cancellation, Move, liveness and full Rust refinement. |
| Progress through closure, freeze/settle, crash/restart, resource recovery, and administrative changes | `formal/liveness/README.md`, `formal/liveness/ConvergenceLifecycle.tla`, both `.cfg` files | TLC checks temporal properties with explicit fairness assumptions in the configured finite model. The unfair configuration is an expected-failure control. |
| Executable lifecycle mirror and counterexample action identity | `crates/cgka-conformance-simulator/src/lifecycle_model.rs`, `tests/lifecycle_model.rs` in that crate | Stateright explores the Rust model; stable action ids connect a counterexample to Scenario IR. The mirror does not replace TLC's authority for infinite-run temporal claims. |
| Production selector/canonicalizer agreement with an independent specification | `crates/cgka-conformance-simulator/src/reference_convergence.rs`, `tests/independent_reference_model.rs`, `PROPERTY_TESTS.md` | Shared corpus and generated differential checks against production code. These tests are not exhaustive over arbitrary inputs. Preserve the reference model's independence. |
| Shared Tamarin/Rust cases | `formal/tamarin/policy_cases.json`, simulator `src/policy_cases.rs`, `src/bin/cgka-policy-casegen.rs`, `tests/generated_policy_cases.rs`, `tests/policy_case_tamarin_drift.rs` | Shared bounded cases exercise Rust; generated definitions are compared with the committed Tamarin model. The drift check does not compare every hand-written model rule with Rust. |
| Sensitivity to named semantic defects | Simulator `MUTATION_MATRIX.md`, `src/mutation_adequacy.rs`, `tests/mutation_adequacy.rs` | Simulator-only alternate rules and their witnesses. These are not mutations of the production implementation or a proof that every production defect is caught. |
| Which production convergence routes a claim covers | Simulator `CONVERGENCE_ROUTE_MATRIX.md`, `src/route_assurance.rs`, `tests/route_assurance.rs` | Source-marker/ownership checks, claim lifecycle, and evidence limitations. The abstract route lifecycle is not an exhaustively explored production route-equivalence proof. |
| Behavior with real OpenMLS, persistence, delivery, and process boundaries | Simulator `AGENTS.md`, `SCENARIO_IR.md`, `RUNNING_CAMPAIGNS.md`, relevant engine/storage tests | Production execution evidence through capability-declared adapters. Public app observations do not establish hidden engine-private state. |

## Use existing entrypoints

Select commands for the files and claim involved; this list is not a required
all-at-once gate. Read the nearest `AGENTS.md` before editing.

- Tamarin model edits: `just tamarin`. Read every lemma's result and heed
  warnings and derivation-check failures.
- Lifecycle model: `just tla-liveness` and
  `just tla-liveness-counterexample`. The latter must report a temporal
  property violation. Both use the root `Justfile`'s pinned TLC setup;
  `TLA2TOOLS_JAR` can select caller-supplied tooling, so record that provenance.
- Shared policy cases: `just policy-casegen`, then
  `cargo test -p cgka-conformance-simulator --locked --test generated_policy_cases --test policy_case_tamarin_drift`.
- For a focused Rust witness, select the relevant test by its actual name in
  `independent_reference_model`, `lifecycle_model`, `mutation_adequacy`, or
  `route_assurance`. Preserve dedicated-binary filters and required features.
- Changes to the simulator verification layers require
  `just convergence-verification-ci` under that crate's `AGENTS.md`.
  Convergence/delivery changes also follow the root simulator-smoke rule.

Do not add a second download/bootstrap path for TLC or replace existing
verification commands with a wrapper that hides incomplete results.

## Questions that can justify new work

These are starting points for coverage investigation, not newly established
defects or claims that no existing check covers them:

- **Model-to-code correspondence.** Which actions assume atomicity that the
  engine, session, or store implements across multiple writes or awaits?
  What checks detect a new writer or a changed crash boundary?
- **Route equivalence.** The route matrix documents that route choice is not
  represented in the existing selector/lifecycle models, and
  `src/route_assurance.rs` explicitly excludes exhaustive exploration and a
  production route-equivalence proof. Determine which transitions and
  production witnesses would make a stronger route claim possible.
- **Code-level selector guarantees.** Could a direct Rust verifier establish
  a concrete invariant over a justified input domain in
  `crates/cgka-engine/src/convergence.rs` beyond the current differential
  sample? Establish tool compatibility before extracting or rewriting code.
- **Local concurrency.** For publication stop/permission state such as
  `crates/marmot-app/src/unlinked_publish_gate.rs` or attachment resume state,
  what are the promised linearization point and cancellation semantics?
  Identify an actual uncovered schedule before proposing a concurrency tool.
- **C ABI ownership.** `crates/marmot-c/src/memory.rs` already has ownership
  contracts and allocation-audit support. Could a focused Miri or code-level
  check catch aliasing, ownership, or lifetime faults those checks miss?
  Include the caller's pointer-validity obligations and native-library limits.
- **Stronger generality.** Would arbitrary candidate counts or unbounded
  execution require an inductive proof, and what implementation bridge would
  make that theorem useful? More bounded seeds do not establish that theorem.
- **Security assumptions.** Which admitted-input, authorization, epoch/key
  binding, or compromise-recovery assumptions are justified outside the
  convergence model? Identify a concrete missing security argument before
  proposing a dedicated protocol or computational cryptographic model.

Keep gaps in their existing owner documentation or tracking issue. Do not
close an open assurance claim merely because a new model or green run exists;
follow the route claim lifecycle and preserve unresolved counterexamples.
