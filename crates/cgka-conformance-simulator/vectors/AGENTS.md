# AGENTS.md - crates/cgka-conformance-simulator/vectors

Map for portable JSON vector fixtures.

## Rules

- Each fixture is a `VectorFixture` with `scenario` input and either exact `expected_trace` output or semantic
  `expected_outcomes`.
- Keep `manifest.v1.json` updated when adding a portable scenario, generated family, formal case fixture, or byte-level
  vector.
- Subject-pinned `GeneratedScenarioInputV1` artifacts live under `generated-inputs/` and are deliberately outside both
  `manifest.v1.json` and `VectorFixture` directory discovery. Keep their `*.generated-input.json` suffix: renaming one
  to `*.v1.json` would make the vector sweep try to parse it as a `VectorFixture`.
- Keep `../SCENARIOS.md` updated when adding or changing a runnable scenario vector.
- Byte-level fixtures live under `byte-fixtures/` and follow `byte-fixtures/schema.v1.json`.
- Keep fixture names stable and versioned, usually `name.v1.json`.
- Do not store OpenMLS protocol bytes in fixtures.
- Keep traces implementation-neutral: epochs, members, payload observations, pending resolutions, app invalidations, and
  recovery observations are fine. Use semantic expectations when randomized MLS bytes can change which client observes
  recovery.
- After editing a fixture, run the vector fixture test. Use the report CLI when you also want JSON reports and a
  pass/fail summary.

## Verification

```sh
cargo test -p cgka-conformance-simulator canonical_vector_fixtures_match_generated_traces
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --out target/cgka-conformance-simulator-reports
```
