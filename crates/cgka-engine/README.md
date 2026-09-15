# cgka-engine

OpenMLS-backed implementation of the [`CgkaEngine`](../traits/src/engine.rs) trait.

This crate owns the local group state machine. It sits above OpenMLS, governs commit sequencing, enforces MIP-03 admin
rules, and returns typed outcomes for every ingest path.

## What this crate does

- Wraps `MlsGroup` for each joined group and manages its `EpochState` lifecycle (`Stable`, `PendingPublish`, `Merging`,
  `Recovering`, `Unrecoverable`).
- Translates `SendIntent`s (app-message, invite, remove-members, leave, update-app-components, update-group-data) into
  MLS commits — group creation and capability upgrade are separate trait calls (`create_group`,
  `upgrade_group_capabilities`); translates inbound `TransportEnvelope`s into typed `IngestOutcome`s and `GroupEvent`s.
- Stores inbound payloads as typed raw-transport or peeled-OpenMLS records so peel-deferred messages can be retried
  without polluting convergence replay.
- Retains a small, configurable OpenMLS past-epoch window for delayed application messages.
- Maintains a per-leaf capability cache so `feature_status` lookups do not walk the ratchet tree.
- Stages SelfRemove-only commits for eligible remaining members and returns that work as publish-before-apply
  obligations; keeps durable local leave requests gated and re-proposes stale SelfRemove proposals for newer epochs.

## What it does _not_ do

- No transport (no Nostr, no relays). Plug in a `TransportPeeler` impl.
- No persistence beyond what `StorageProvider` exposes. Pair with `storage-sqlite` for SQLCipher-backed persistence;
  tests can use its in-memory SQLite mode.
- No CLI, no FFI, no application logic.

## Run the tests

```sh
cargo test -p cgka-engine
```

These tests cover the engine boundary directly. They use one or a few `Engine<SqliteAccountStorage>` instances with in-memory
SQLite storage and a mock peeler. They are the right place for local rules: command validation, snapshot persistence,
processed-message idempotency, restart behavior, and the exact outputs from a single engine call.

Run the simulator when you change convergence, delivery, branch selection, group data, or anything that depends on more
than one client:

```sh
cargo test -p cgka-conformance-simulator
cargo test -p cgka-conformance-simulator --features conformance-slow
```

The simulator is the integration and conformance layer for this engine. It wraps real engine instances with the Nostr
peeler, drives them through an in-memory transport bus, and checks that clients converge after realistic delivery
weirdness. Its README explains the scenario format, vector fixtures, generated families, reports, and property tests:

- [`../cgka-conformance-simulator/README.md`](../cgka-conformance-simulator/README.md)

Use this crate's tests to prove that an engine method does the right thing. Use the simulator to prove that many engines
still agree after the world gets messy.

See [`tests/AGENTS.md`](tests/AGENTS.md) for the test file map.

## KeyPackage validation before membership changes

Create and Invite validate transported KeyPackages through OpenMLS and the Marmot identity/profile checks before
adding members. They also reject LeafNode capabilities that explicitly advertise RFC 9420 section 7.2 default
extension or proposal types. Unknown capability values remain accepted for protocol extensibility.

This is an explicit admission policy beyond the [RFC 9420 section 7.3 validation checks](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.3):
OpenMLS accepts these advertisements, but MDK chooses to keep known nonconforming signed leaves out of new
membership state. An inviter cannot repair a signed advertisement. The accepted compatibility cost is that
Create/Invite to a peer still publishing an affected package fails with `InvalidKeyPackageCapabilities` until that
peer regenerates and publishes a conforming package. Automatic migration in this release only helps recipients
that upgrade and activate successfully; it cannot repair packages on peers that have not upgraded.

Recipients whose published packages contain the former default-capability advertisement must generate a fresh
package using the corrected client. The account runtime records a per-account-device generator revision and
MarmotApp attempts a one-time fresh publication on activation after upgrading. Offline or signing failures remain
retryable; the revision advances only with an acknowledged replacement. The refusal is `InvalidKeyPackageCapabilities`,
with an authenticated member id for typed callers and identity-free diagnostic text; it is classified as an expected
refusal rather than a resource failure.

This membership check does not change local private-bundle retention or historical Welcome processing. Directory
metadata can still describe an older package; that does not make it eligible for a new membership operation.

## Promoting state-bearing app components

`upgrade_group_capabilities` only promotes state-bearing app components whose
optional state already exists in the GroupContext. Use two published commits:

1. send `SendIntent::UpdateAppComponents` to install the optional component
   state, then confirm that commit was published;
2. call `upgrade_group_capabilities`, then publish and confirm its promotion
   commit.

The upgrade fails closed without staging a commit when required state is
missing. MDK does not currently expose an atomic require-and-populate API.

## Speculative replay transaction checks

Run the regression, paired SQLCipher measurement, and process-crash checks with:

```sh
cargo test --locked -p cgka-engine --lib replay_transaction_preserves
cargo test --locked -p cgka-engine --lib replay_transaction_measurement -- --ignored --nocapture
cargo test --locked --release -p cgka-engine --config 'profile.release.package.cgka-engine.debug-assertions=true' --lib replay_transaction_measurement -- --ignored --nocapture
cargo test --locked -p cgka-engine --features test-crash-hooks,test-policy-overrides --test crash_recovery_sqlite
```

The measurement alternates the previous unbatched probe body and transactional replay on identical
20-member inputs, using encrypted file storage with production WAL/FULL defaults. It measures three
candidate probes per sample, checks restoration, and imposes no timing assertion. It is a microbenchmark;
the simulator's 50-member public app canary measures the separate effect under runtime contention.
The optimized unit-test command retains engine debug assertions because existing legacy-profile test
helpers require them. Production app measurements should use the normal release build without that override.

## Resumable candidate reconstruction

Live convergence and background deferred peeling retain candidate-search progress between calls.
Each evaluator slice admits at most 32 probes and observes the caller's cooperative time budget;
a started probe always finishes. Both the probe transaction and any outer historical rewind restore
live state before the evaluator returns pending work. Selection and input dispositions are published
only after the complete search and application-witness replay finish.

Scratch progress is memory-only and tied to the exact inputs, group state, retained snapshots,
policy and frozen pass generation. SQLCipher also fingerprints the live canonical/OpenMLS state and
all retained snapshots/checkpoints, so unrelated app writes through another database connection do
not discard progress. Other tracking backends use strict MLS-write-generation equality. Invalidation
or restart discards scratch work while durable input remains available. Backends without mutation-generation tracking
use the synchronous evaluator. Explicit-time convergence entry points and foreground preflight
retain their existing execution semantics.

```sh
cargo test --locked -p cgka-engine --features test-policy-overrides,test-conformance-snapshot --lib resumable_
cargo test --locked -p cgka-engine --features test-crash-hooks,test-policy-overrides --test crash_recovery_sqlite
cargo test --locked --release -p cgka-engine --config 'profile.release.package.cgka-engine.debug-assertions=true' --lib candidate_reconstruction_measurement -- --ignored --nocapture
```

The isolated measurement varies group size, fork width, and history depth. It records complete-search
time, probe counts, repeated message inputs, and maximum probe/slice duration, comparing sliced and
uninterrupted results without a timing pass/fail threshold.

## Reading order for a new contributor

1. Target architecture: `../../docs/marmot-architecture/overview/target-architecture.md`
2. [`../../docs/marmot-architecture/cgka-engine-spec.md`](../../docs/marmot-architecture/cgka-engine-spec.md) — the
   current engine spec
3. Detailed post-peeling contract: `../../docs/marmot-architecture/cgka-engine-canonicalization-contract.md`
4. Branch-selection and convergence model: `../../docs/marmot-architecture/distributed-convergence.md`
5. [`AGENTS.md`](AGENTS.md) — module-by-module map of this crate, design deviations, where to look for what

For the Marmot app-component model now used by new groups, see
[marmot-protocol/marmot](https://github.com/marmot-protocol/marmot) and [`src/app_components.rs`](src/app_components.rs).

## Status

`0.9.0`, single internal consumer, not semver-stable. For current readiness and open production work, start with
[`../../docs/marmot-architecture/overview/current-state.md`](../../docs/marmot-architecture/overview/current-state.md).

## Buffered application handoff

A frozen convergence batch can advance one epoch beyond its admission ceiling. Already-unwrapped
applications at that new tip remain durable input, even when no commit can open another pass.
Background advancement drains these inputs against the stable canonical state after convergence and
deferred peeling finish. It shares the existing 64-row allowance and cooperative 500 ms background
budget; a started MLS operation completes before yielding. Once the drain is reached, it processes
at least one candidate even when discovery or earlier phases have spent that allowance. Input discovery streams state-filtered
storage rows and stops once it has enough matches; classification may still scan a nonmatching prefix.

This is scheduling work, not branch ambiguity: it does not open a convergence pass, gate a foreground
send, or consume the completed pass's queued-intent fairness slot. Remaining work recreates a scheduling
edge, including after hydration; `prepare_convergence_cutoff_delay_ms` reports it ready independently
of `has_pending_convergence_inputs`, which retains its branch-ambiguity safety-gate meaning. An advance
may report branch settlement while application work remains for another turn. Future-epoch input waits
for canonical state to advance.

The drain uses the same OpenMLS sender/payload validation and source-state retention decision as
canonical replay. Direct ingestion and replay attribute applications using the authenticated source-epoch
credential carried by OpenMLS, so a later removal or reuse of that member's leaf cannot erase or substitute
the original author. A valid, retained application authored before removal can therefore still be
delivered after the sender is removed; this does not authorize messages from that sender in a later
epoch. Proposals and commits retain live-tree authorization. The inner app author must still match
that credential. Ratchet writes, the terminal
input disposition, and pending app output commit in one storage transaction. Crash recovery therefore
retries an untouched input or recovers its durable app
output. Encrypted SQLite process-kill tests cover both sides of that commit and acknowledgement followed
by another restart. It never reopens a processed or terminally invalidated input.

### Negative application-discovery scan measurement

The stopping visitor bounds the number of returned application candidates, but a negative query still
reads and decodes all retained pending non-application records. Do not start this scan at the retained
anchor: a newly arrived below-anchor application still needs its terminal invalidation.

Run the focused encrypted-file measurement with:

```sh
cargo test -p cgka-engine --release --locked \
  --config profile.release.package.cgka-engine.debug-assertions=true \
  --lib measure_negative_application_discovery_prefix -- --ignored --nocapture
```

The engine-only debug-assertion override exposes the legacy fixture builder in this optimized test build;
it is not a production app campaign. The synthetic fixture copies one valid commit into distinct pending
ledger rows, takes ten negative-query samples per size, then adds a previously unseen old application
and verifies its `BeyondAnchor` disposition even with an expired/zero-row drain allowance. It does not
model distinct legitimate commit histories, network behavior or app end-to-end latency.

A local run on 2026-09-14 used 593-byte stored payloads:

| Pending commit rows | Decoded rows per negative query | Mean query time | Late-arrival drain time |
| --- | --- | --- | --- |
| 0 | 0 | 0.025 ms | 0.225 ms |
| 100 | 100 | 0.271 ms | 0.698 ms |
| 1,000 | 1,000 | 2.402 ms | 5.084 ms |
| 10,000 | 10,000 | 33.178 ms | 66.962 ms |

These are diagnostic samples, not thresholds or a claim that this explains the approximately 31-second
app recovery observation. The negative scan remains performance work: evaluate a content-kind index or
invalidation-safe classifier/cache separately, preserving late arrivals, payload replacement, restart,
foreign-connection writes and terminal dispositions. The late-arrival drain visits `2 * rows + 1`
records because it discovers the candidate and then checks for remaining pending work.
