# AGENTS.md - formal/tamarin

Agent map for the Tamarin proof directory. [`README.md`](README.md) explains what the model proves, the selector order,
and how lemmas map to Rust tests.

## Files

| Path | Owns |
| --- | --- |
| `distributed_convergence_v0.spthy` | Abstract convergence, lifecycle, delivery-order, and app-output lemmas. |
| `policy_cases.json` | Shared bounded policy cases used by Rust and Tamarin generation. |
| `Makefile` | `prove` and `interactive` targets used by the root `Justfile`. |
| `README.md` | Human explanation of what the model proves and how proofs map to tests. |

Rust consumers: `crates/cgka-conformance-simulator/src/policy_cases.rs`, `src/bin/cgka-policy-casegen.rs`,
`tests/generated_policy_cases.rs`, and `tests/policy_case_tamarin_drift.rs` (generated `Init_Generated_Family_*` rules
and `generated_*_executable` lemmas must match the committed model).

## Rules

- Keep model scenario names aligned with Rust test or fixture names so grep connects model, unit/property test, and
  integration scenario.
- Model only the global convergence properties that need proof. Storage schema, parsing, and simple max-by-input
  behavior belong in Rust tests. Temporal/liveness claims belong in `formal/liveness` (TLA+), not here.
- When adding, removing, or renaming a lemma, update the README's Proof Inventory table: every lemma belongs to exactly
  one category.
- Keep the README selector order in step with `crates/cgka-engine/src/convergence.rs`.
- If `policy_cases.json` changes, run `just policy-casegen` and
  `cargo test -p cgka-conformance-simulator --test generated_policy_cases --test policy_case_tamarin_drift`.
- If the `.spthy` file changes, run `just tamarin` (requires `tamarin-prover` on `PATH`; warnings fail the target).

## Boundaries

Tamarin proves the abstract design. Rust tests prove the implementation follows that design with real OpenMLS bytes,
storage, and engine state.
