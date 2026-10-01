# incident-replay

Turns a Goggles forensic export of a real Marmot group into a triage verdict and, for a fork-recovery or convergence
incident, a portable conformance vector for [`cgka-conformance-simulator`](../cgka-conformance-simulator/). Use it when
investigating a production convergence report: it tells you whether the export shows a reproducible branch contest, a
halted or lagging device, or nothing wrong, and it only emits a vector the simulator actually reproduces.

## Pipeline

**parse → classify → recover → synthesize → accept.**

1. **Parse** either export shape into one model: the `agent-state.json` document or the streamed NDJSON group export
   (`goggles-group-export/v1`). The format is detected from content, so there is no format flag. The stream's
   completeness contract (leading `manifest`, terminal `eof` with `complete: true`, matching section counts, no in-band
   `error` line) is enforced fail-closed.
2. **Classify** the export into one verdict: `Healthy`, `ForkRecovery`, `ConvergenceSelected`, or `Quarantine` with a
   reason. A healthy export yields zero vectors.
3. **Recover** the fork (group-data or membership) or the contested convergence decision (committer- or
   witness-decided). Shapes it cannot replay fail closed.
4. **Synthesize** a simulator scenario for that shape, preferring the producer's attested normalized history when the
   export carries one.
5. **Accept** the vector only if the simulator reproduces the recorded outcome. No reproduction, no vector.

When the selected route fails closed, lower-precedence routes are still tried, so a reproducible incident that shares
the export is not discarded.

## Usage

```sh
cargo run -p incident-replay -- <agent-state.json | group-export.ndjson> [out-dir]
```

Output is one primary line plus an `advisory (<label>):` line for each co-occurring finding the primary line does not
report:

- `healthy: 0 vectors`
- `quarantine: <reason>` — not a branch contest, or not replayable. Reasons include `truncated_projections`,
  `missing_snapshot`, `unrecoverable_halt` (an engine stated it halted), and `epoch_divergence` (an engine trails the
  group by two or more epochs, reported per engine as `went_dark`, `active_while_behind`, or `rolled_back`).
- `accepted (<fidelity>, <sensitivity>)` — the simulator reproduced the incident. With an `out-dir`, the vector and its
  `incident-scenario-artifact.v1` evidence envelope ([schema](schemas/incident-scenario-artifact.v1.schema.json)) are
  written owner-only; without one, the line lists the fields the artifact could not capture.

Advisories (`halt`, `liveness`, `superseded route`, `fallback route`) make sure an accepted or quarantined incident
never masks a co-occurring halted or stranded device.

The CLI exits 0 for every successful classification — healthy, quarantine, and accepted are all valid outcomes — and 2
on usage, I/O, parse, or write failure, or when the simulator could not run at all.

**Reading quarantines.** A single quarantine is a re-pull trigger, not a verdict. Entries that vanish on the next pull
were catch-up in flight; entries that persist across pulls are the signal.

## Limits

- An `agent-state.json` document is read whole and rejected above 256 MiB. A stream is parsed line by line with no total
  size cap, bounded to 16 MiB per line and 16 Mi lines.
- Accepted vectors normalize real epochs to the simulator's range and assert a winner-agnostic outcome where the
  export cannot establish the winner. Legacy exports produce an explicitly labelled `outcome_equivalent_archetype`,
  never a claim of source-verified replay.
- Byte-exact replay is never available from an export: raw MLS bytes and engine checkpoints are not in it.

## Handling real exports

Real exports carry relay URLs, message ids, and other identifiers. Keep them under the ignored `incident-exports/`
directory and write output under `target/` or the ignored `incident-replay-output/`. Producer-attested artifacts may
contain unredacted Scenario IR labels and payloads; treat them as confidential unless separately redacted and reviewed.
The CLI never copies the source export, transport ciphertext, or an MLS checkpoint into its output. Never commit a raw
export; reviewed synthetic vectors belong in
[`cgka-conformance-simulator/vectors/incidents/`](../cgka-conformance-simulator/vectors/incidents/).

[`docs/marmot-architecture/audit-logging.md`](../../docs/marmot-architecture/audit-logging.md) describes the audit
events this tool reads.

## Development

```sh
cargo test -p incident-replay
```

The committed fixtures under `tests/fixtures/` are synthetic. [`AGENTS.md`](AGENTS.md) has the module map and the full
classification rules, including the designs that were evaluated against real exports and rejected.
