# cgka-engine

OpenMLS-backed implementation of the [`CgkaEngine`](../traits/src/engine.rs) trait — the local group state machine
for Marmot. Read this if you are building on the engine directly or changing how groups evolve, converge, or recover.

The engine sits above OpenMLS, governs commit sequencing, adjudicates forks through distributed convergence, enforces
MIP-03 admin rules, and returns typed outcomes for every ingest path.

## Contents

- [What this crate does](#what-this-crate-does)
- [KeyPackage validation before membership changes](#keypackage-validation-before-membership-changes)
- [Promoting state-bearing app components](#promoting-state-bearing-app-components)
- [Background recovery](#background-recovery)
- [Tests and measurements](#tests-and-measurements)
- [Reading order](#reading-order)
- [Status](#status)

## What this crate does

- Wraps `MlsGroup` for each joined group and manages its `EpochState` lifecycle (`Stable`, `PendingPublish`, `Merging`,
  `Recovering`, `Unrecoverable`, `Disbanded`).
- Translates `SendIntent`s (app message, invite, remove members, leave, self-update, update app components, update
  group data) into MLS commits or messages. Group creation and capability upgrade are separate trait calls
  (`create_group`, `upgrade_group_capabilities`). Inbound `TransportMessage`s become typed `IngestOutcome`s and
  `GroupEvent`s.
- Stages local group changes publish-before-apply: the caller publishes, then confirms or reports failure.
- Stores inbound payloads as typed raw-transport or peeled-OpenMLS records so peel-deferred messages can be retried
  without polluting convergence replay.
- Resolves same-epoch forks deterministically through stored-message distributed convergence.
- Retains a small, configurable OpenMLS past-epoch window for delayed application messages.
- Maintains a per-leaf capability cache so `feature_status` lookups do not walk the ratchet tree.
- Stages SelfRemove-only commits for eligible remaining members, keeps durable local leave requests gated, and
  re-proposes stale SelfRemove proposals for newer epochs.

It does **not** do transport (plug in a `TransportPeeler`), persistence beyond `StorageProvider` (pair with
[`storage-sqlite`](../storage-sqlite/README.md); tests use its in-memory mode), CLI, FFI, or application logic.

## KeyPackage validation before membership changes

Create and Invite validate transported KeyPackages through OpenMLS and the Marmot identity/profile checks before
adding members. They also reject LeafNode capabilities that explicitly advertise RFC 9420 section 7.2 default
extension or proposal types. Unknown capability values remain accepted for protocol extensibility.

This is an explicit admission policy beyond the
[RFC 9420 section 7.3 validation checks](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.3): OpenMLS accepts
these advertisements, but MDK keeps known nonconforming signed leaves out of new membership state. An inviter cannot
repair a signed advertisement, so Create/Invite to a peer still publishing an affected package fails with
`InvalidKeyPackageCapabilities` until that peer publishes a conforming package. The refusal carries an authenticated
member id for typed callers and identity-free diagnostic text, and is classified as an expected refusal rather than a
resource failure.

Peers whose published packages carry the former default-capability advertisement must generate a fresh package with
the corrected client. The account runtime records a per-account-device generator revision, and MarmotApp attempts a
one-time fresh publication on activation after upgrading; offline or signing failures remain retryable, and the
revision advances only with an acknowledged replacement. This cannot repair packages on peers that have not upgraded.

The check does not change local private-bundle retention or historical Welcome processing. Directory metadata can still
describe an older package; that does not make it eligible for a new membership operation.

## Promoting state-bearing app components

`upgrade_group_capabilities` only promotes state-bearing app components whose optional state already exists in the
GroupContext. Use two published commits:

1. send `SendIntent::UpdateAppComponents` to install the optional component state, then confirm that commit was
   published;
2. call `upgrade_group_capabilities`, then publish and confirm its promotion commit.

The upgrade fails closed without staging a commit when required state is missing. MDK does not currently expose an
atomic require-and-populate API.

## Background recovery

**Resumable candidate reconstruction.** Live convergence and background deferred peeling retain candidate-search
progress between calls. Each evaluator slice admits at most 32 probes and observes the caller's cooperative time
budget; a started probe always finishes. Live state is restored before the evaluator returns pending work, and
selection and input dispositions are published only after the complete search and application-witness replay finish.
Scratch progress is memory-only and tied to the exact inputs, group state, retained snapshots, policy, and pass
generation. SQLCipher fingerprints live canonical/OpenMLS state and retained snapshots/checkpoints, so unrelated app
writes through another connection do not discard progress; other tracking backends use strict MLS-write-generation
equality, and backends without mutation tracking use the synchronous evaluator. Invalidation or restart discards
scratch work while durable input remains available. Explicit-time convergence entry points and foreground preflight
keep their existing semantics.

**Buffered application handoff.** A frozen convergence batch can advance one epoch beyond its admission ceiling.
Already-unwrapped applications at that new tip remain durable input even when no commit can open another pass.
Background advancement drains them against the stable canonical state after convergence and deferred peeling finish,
sharing the 64-row allowance and cooperative 500 ms background budget; a started MLS operation completes before
yielding, and once reached the drain processes at least one candidate. This is scheduling work, not branch ambiguity:
it opens no convergence pass, gates no foreground send, and consumes no queued-intent fairness slot.
`prepare_convergence_cutoff_delay_ms` reports remaining work ready independently of `has_pending_convergence_inputs`,
which keeps its branch-ambiguity safety-gate meaning. An advance may report branch settlement while application work
remains. Future-epoch input waits for canonical state to advance.

The drain uses the same OpenMLS sender/payload validation and source-state retention decision as canonical replay.
Direct ingestion and replay attribute applications using the authenticated source-epoch credential carried by OpenMLS,
so a later removal or leaf reuse cannot erase or substitute the original author: a valid, retained application authored
before removal can still be delivered after the sender is removed, without authorizing that sender in a later epoch.
Proposals and commits keep live-tree authorization, and the inner app author must still match the credential. Ratchet
writes, the terminal input disposition, and pending app output commit in one storage transaction, so crash recovery
either retries an untouched input or recovers its durable app output, and never reopens a processed or terminally
invalidated input.

## Tests and measurements

```sh
cargo test -p cgka-engine
```

These tests cover the engine boundary with one or a few `Engine<SqliteAccountStorage>` instances over in-memory
SQLite and a mock peeler: command validation, snapshot persistence, processed-message idempotency, restart behavior,
and the exact outputs of a single engine call. [`tests/AGENTS.md`](tests/AGENTS.md) maps the files.

Multi-client behavior is covered by the [conformance simulator](../cgka-conformance-simulator/README.md), which drives
real engines through an in-memory transport bus with the Nostr peeler and checks they converge after realistic delivery
faults. Use this crate's tests to prove an engine method does the right thing; use the simulator to prove many engines still
agree after the world gets messy.

**Speculative replay transactions and resumable reconstruction.** Regression, crash, and paired measurement runs:

```sh
cargo test --locked -p cgka-engine --lib replay_transaction_preserves
cargo test --locked -p cgka-engine --features test-policy-overrides,test-conformance-snapshot --lib resumable_
cargo test --locked -p cgka-engine --features test-crash-hooks,test-policy-overrides --test crash_recovery_sqlite
cargo test --locked -p cgka-engine --lib replay_transaction_measurement -- --ignored --nocapture
cargo test --locked --release -p cgka-engine --config 'profile.release.package.cgka-engine.debug-assertions=true' --lib replay_transaction_measurement -- --ignored --nocapture
cargo test --locked --release -p cgka-engine --config 'profile.release.package.cgka-engine.debug-assertions=true' --lib candidate_reconstruction_measurement -- --ignored --nocapture
```

The replay-transaction measurement alternates the previous unbatched probe body and transactional replay on identical
20-member inputs over encrypted file storage with production WAL/FULL defaults, three candidate probes per sample, and
checks restoration. The reconstruction measurement varies group size, fork width, and history depth, comparing sliced
and uninterrupted search. Neither has a timing threshold; they are microbenchmarks (the simulator's 50-member public
app canary measures runtime contention). The optimized commands keep engine debug assertions because legacy-profile
test helpers require them; production app measurements should use a normal release build.

**Negative application-discovery scan.** The drain's stopping visitor bounds returned candidates, but a negative query
still reads and decodes every retained pending non-application record:

```sh
cargo test -p cgka-engine --release --locked \
  --config profile.release.package.cgka-engine.debug-assertions=true \
  --lib measure_negative_application_discovery_prefix -- --ignored --nocapture
```

The synthetic fixture copies one valid commit into distinct pending rows, takes ten negative-query samples per size,
then adds an unseen old application and verifies its `BeyondAnchor` disposition even with an expired drain allowance.
It does not model distinct commit histories, network behavior, or app end-to-end latency. A local run on 2026-09-14
(593-byte payloads):

| Pending commit rows | Decoded rows per negative query | Mean query time | Late-arrival drain time |
| --- | --- | --- | --- |
| 0 | 0 | 0.025 ms | 0.225 ms |
| 100 | 100 | 0.271 ms | 0.698 ms |
| 1,000 | 1,000 | 2.402 ms | 5.084 ms |
| 10,000 | 10,000 | 33.178 ms | 66.962 ms |

These are diagnostic samples, not thresholds. The late-arrival drain visits `2 * rows + 1` records (discover the
candidate, then check for remaining work). A content-kind index or invalidation-safe classifier/cache remains open
performance work; it must preserve late arrivals, payload replacement, restart, foreign-connection writes, and terminal
dispositions.

## Reading order

1. [Target architecture](../../docs/marmot-architecture/overview/target-architecture.md)
2. [Engine spec](../../docs/marmot-architecture/cgka-engine-spec.md)
3. [Post-peeling canonicalization contract](../../docs/marmot-architecture/cgka-engine-canonicalization-contract.md)
4. [Branch selection and distributed convergence](../../docs/marmot-architecture/distributed-convergence.md)
5. [`AGENTS.md`](AGENTS.md) — module map, design deviations, and invariants

For the Marmot app-component model used by new groups, see
[marmot-protocol/marmot](https://github.com/marmot-protocol/marmot) and [`src/app_components.rs`](src/app_components.rs).

## Status

Single internal consumer; not semver-stable. Versioned with the workspace. For readiness and open production work, see
[`current-state.md`](../../docs/marmot-architecture/overview/current-state.md).
