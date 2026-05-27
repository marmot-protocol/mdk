# AGENTS.md - marmot-forensics-analyzer

Internal analyzer for Marmot forensic bundles.

## Scope

- Read one or more `marmot-forensics/v1` dumps.
- Compare device/account views side by side and report branch conflicts, epoch skew, and missing observations.
- Emit an initial conformance `ScenarioSpec` scaffold that can be refined into a reproducer.
- Do not add this crate as a dependency of production app/runtime crates.

## Verification

```sh
cargo test -p marmot-forensics-analyzer
```
