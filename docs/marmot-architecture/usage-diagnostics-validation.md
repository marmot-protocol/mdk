---
updated: 2026-09-07
---
# Usage and diagnostics implementation checkpoint

This implementation starts from `0b268b47`. Workspace versions are unchanged.
The evidence below covers local validation; deployment acceptance remains pending.

## Implemented

- Shared-store migration 2, combined consent, legacy compatibility, revocable
  generations, fail-closed persistence, and consent-bound diagnostic identity.
- Independent OTLP and stock-Aptabase delivery, OTLP cumulative baselines,
  bounded product collection, clock/session/window rules, finite host schemas,
  shared DNS/address-pinning safety, and bounded lifecycle draining.
- Rust, UniFFI and C records/commands; local CLI and agent consent controls;
  silent frozen/short-lived runtimes; optional features and artifact passthrough.
- Backend observations across the 17 catalogue families, including autonomous
  maintenance, retention, media completion/cancellation, inbound processing,
  sync/backfill/recovery, group/message actions, notifications and agent streams.
- Machine-readable schemas, host integration guidance, reporting queries,
  sample report input/output, and a synthetic staging executable.

The registry describes the permitted vocabulary. A reserved operation name does
not prove that every operation/outcome combination has an automatic observation
site, and absence of a row does not establish that an operation never occurred.

## Counting and coverage boundaries

- Storage failures use typed busy/corruption/capacity classifications. Command
  completion owns a failure; sync completion owns forwarded partial-progress
  errors. SQLCipher recovery records performed/no-work/failure without key or
  path information. Numbered migrations count only newly applied ledger entries.
- KeyPackage lookup actions are canonical member-resolution commands; lookup
  attempts are package validations with usable/invalid/expired/unavailable
  outcomes. Directory source counts describe cache reuse versus network
  resolution, including search hydration. They do not identify relays or peers.
- Message `publication/transition` is one committed outgoing source-retention
  finalization, including initially pending/unknown sends. This is separate from
  the original message action. A replay or sibling failure does not add an edge.
- Welcome `publish/transition` is successful removal of a pending repair record
  after relay acknowledgement. Startup repair-index reconstruction is silent.
  Retry attempts are bounded retry invocations; a batch may contain multiple
  Welcomes. Neither measurement proves recipient receipt or decryption.
- Maintenance attempts and persisted transitions remain separate. Execution
  durations use the account runtime's injected monotonic clock. At most 256
  neutral duration samples are retained between drains; overflow retains the
  attempt counts without durations. Pending, ambiguous and terminal-failure
  backlog rows are latest durable state samples, not per-tick sums.
- Agent control attempts include real handler invocations. Logical final-message
  actions remain owned after the idempotency leader is selected; do not add
  handler attempts to logical-action denominators.

`media/cache_hit` is reserved: MDK has no general media cache completion site to
instrument in this checkout. Native host observations can report reviewed cache
interactions through their approved registry, but must not invent backend cache
hits. Similarly, catalogue vocabulary is not evidence that every combination
of operation, outcome and unit can occur.

## Focused replay evidence

The mixed-publication fixtures exercise direct sends, drained work, scheduled
recovery and retry paths with a successful sibling plus a failed sibling. Under
product collection, ten repeated finalizations still leave exactly one confirmed
transition. Maintenance tests distinguish loaded state, actual attempts, drained
durations and persisted edges. Directory tests exercise cache and network paths;
collector tests reject stale source observations and unregistered source values.

## Local evidence

The following checks have passed during implementation; their scope is narrower
than deployment or full catalogue acceptance:

- `just fast-ci`: formatting, workspace/default and exporter feature builds,
  clippy, binding parity, repository policy checks, and pinned convergence tests.
- Product tests: 23 passed, covering exact bucket edges, registry/serialization privacy, queue and
  clock/session boundaries, consent migration/identity/persistence, stale work,
  HTTP batch limits/prefixes, retry/rejection behavior, background draining and
  close-before-drain ordering.
- Shared-store tests: 40 passed. Account migration suite: 58 passed, three
  pre-existing ignored tests. An additional open/reopen migration-summary test
  verifies that existing ledger rows are not counted as new migrations.
- OTLP HTTP integration: seven passed. Baseline arithmetic tests cover counters,
  histogram buckets/sums, ratios, collection start times and source reset cases.
- Directory tests: 68 passed. Mixed-publication and related selection tests: nine
  passed. SQLCipher tests: 15 passed.
- Autonomous maintenance collection and frozen silence passed; seven existing
  maintenance regressions passed after adding neutral execution deltas.
- C DTO/deep-free checks pass with allocation auditing. C parity reports 223
  exports. Static/shared C smoke checks passed; Valgrind was unavailable.
- Generated Swift and Kotlin/JVM DTO round trips passed against the native Rust
  library. Reproducible fixtures and the runner live in `crates/marmot-uniffi`.
- Product-only feature builds pass independently of OTLP.

## External acceptance still pending

Real staging ingestion and persisted-event inspection have not run: the staging
endpoint and a locally accessible app-key source have not been supplied. An HTTP
2xx alone would still not prove persistence because stock ingestion can filter
invalid events.

Native White Noise consent-screen adoption and inspection/hardening of the actual
Aptabase installation are separate work items. No installed-server version,
logging minimization, enrichment results, or 180-day retention enforcement has
been verified here. No GitHub CI run or production rollout is claimed.
