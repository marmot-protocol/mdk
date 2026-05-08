# AGENTS.md - crates/cgka-conformance-simulator/vectors

Map for portable JSON vector fixtures.

## Rules

- Each fixture is a `VectorFixture` with `scenario` input and `expected_trace`
  output.
- Keep fixture names stable and versioned, usually `name.v1.json`.
- Do not store OpenMLS protocol bytes in fixtures.
- Keep traces implementation-neutral: epochs, members, payload observations,
  app invalidations, and recovery observations are fine.
- After editing a fixture, run the vector fixture test.

## Verification

```sh
cargo test -p cgka-conformance-simulator canonical_vector_fixtures_match_generated_traces
```
