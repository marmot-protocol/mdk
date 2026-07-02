# AGENTS.md - formal/tamarin

Agent map for the Tamarin proof directory.

## Files

| Path | Owns |
| --- | --- |
| `distributed_convergence_v0.spthy` | Abstract convergence, lifecycle, delivery-order, and app-output lemmas. |
| `policy_cases.json` | Shared bounded policy cases used by Rust and Tamarin generation. |
| `Makefile` | `prove` and `interactive` targets used by the root `Justfile`. |
| `README.md` | Human explanation of what the model proves and how proofs map to tests. |

## Rules

- Keep model scenario names aligned with Rust test or fixture names.
- Model only the global convergence properties that need proof. Storage schema, parsing, and simple max-by-input
  behavior belong in Rust tests.
- If `policy_cases.json` changes, run `just policy-casegen` and the relevant Rust tests.
- If the `.spthy` file changes, run `just tamarin`.

## Boundaries

Tamarin proves the abstract design. Rust tests prove the implementation follows that design with real OpenMLS bytes,
storage, and engine state.
