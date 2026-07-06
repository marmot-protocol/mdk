# AGENTS.md — incident-replay

Goggles `agent-state.json` forensic export → CGKA conformance-vector adapter. This
crate is the Phase 2 skeleton: **parse + classify**. Extraction, fault synthesis,
and run-and-compare against `cgka-conformance-simulator` are later phases and are
deliberately absent.

## Pieces

- **Module:** `src/export.rs`
  - **Role:** Lenient, self-owned model of the export plus `parse`. Models only
    the fields the classifier needs and ignores everything else, so it tolerates
    the export growing new fields. Deliberately decoupled from `marmot-forensics`:
    it tracks the stable `marmot-forensics-audit/v2` wire shape Goggles
    serialises, not the engine's internal `AuditEventKind` enum.
- **Module:** `src/classify.rs`
  - **Role:** The `classify` gate → `Verdict`: `Healthy | ForkRecovery |
    ConvergenceSelected | Quarantine { reason }`. Everything downstream is gated
    behind this, so a healthy export yields zero vectors and a clean exit.
- **Module:** `src/main.rs`
  - **Role:** CLI — classify one export file, print the verdict JSON, exit 0 for
    any classification (quarantine included), 2 on usage/IO/parse failure.

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
5. **`Healthy`** — none of the above.

## Fixtures

- `tests/fixtures/*.json` are **synthetic and non-sensitive** — the committed test
  set. Real exports carry relay URLs / message ids and must never enter VCS.
- Real exports are the manual pre-PR verification set:
  `cargo run -p incident-replay -- <export.json>`.

## Verification

```sh
cargo test -p incident-replay
cargo clippy -p incident-replay --all-targets
```
