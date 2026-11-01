---
name: test-audit
description: >-
  Gate every new or changed mdk test, prune existing ones and fill coverage
  gaps: name the contract and the regression a test catches, give each
  contract one owner at the cheapest layer that runs the real production code,
  reject duplicate or implementation-coupled proof, and retire test-only
  production seams. Use when writing, changing, reviewing or deleting tests,
  or when asked to audit, trim, consolidate, speed up or add missing tests.
  For a whole crate or subsystem, also read CAMPAIGN.md.
---

# Test audit

A test earns its place by catching a credible regression in a contract that no
cheaper test already catches. Every other test costs compile time, run time
and review attention, and makes refactors harder. This skill applies in two
places:

- **Authoring.** The gate below applies to every test you add or change, in
  any crate.
- **Auditing.** Remove low-value proof in coherent batches, one production
  owner at a time, and add proof for the owner's contracts that no test
  reaches. Never chase deletion counts, line counts or coverage
  percentages: they are measurements, not goals.

For a whole crate or subsystem, read [CAMPAIGN.md](CAMPAIGN.md) before
starting.

## Authoring gate

Before adding or changing a test, answer four questions:

1. **What contract?** The observable behavior, invariant or external contract
   (wire bytes, storage shape, API, ordering) the test protects.
2. **What regression?** A credible code change that makes it fail. If you
   cannot name one, the test proves nothing.
3. **Why does existing proof miss it?** Each contract has one primary owner:
   the cheapest layer at which the production code implementing it runs
   unmocked. Engine tests run real OpenMLS and SQLite, so they are both cheap
   and real. A higher layer earns a test only for the risk it adds
   (transport, persistence, process restart, FFI, concurrency), and that test
   targets the added risk, not the contract again. Extend an existing table,
   harness or property instead of copying setup.
4. **Does it need a seam production doesn't use?** A new `pub` helper, a
   `*_for_test` function, a `test-policy-overrides` branch, a `test-support`
   export, or an injection parameter with no production caller. If so, move
   the proof to the real boundary instead (see
   [Test-only seams](#test-only-seams)).

A regression test must fail before the fix for the reason the bug describes,
not because of fixture setup, and pass after it. Say so in the PR; if you
could not show the failing run, say that. One owner-level regression covers a
bug: do not replay it at every layer it crossed. A behavior-preserving
refactor should not break a test; if one does, the test is coupled to the
implementation.

## Junk patterns

Reject these in new tests. In an audit they are candidates, not verdicts:
check the [retention bar](#retention-bar) first.

- **Assertion-free probes.** The test only calls code, or asserts `is_ok()` or
  `is_some()` without checking the outcome.
- **Self-comparisons and identity copiers.** Build a value, read its fields
  back. Round-trips through derived `Serialize`, `Clone` or `PartialEq` with
  no custom impl and no cross-boundary byte contract test the compiler.
- **Expected values the subject produced.** The expectation is computed by
  calling the code under test, or a snapshot was accepted without being read.
- **Vacuous negatives.** `assert!(r.is_err())`, `matches!(r, Err(_))`, or
  `#[should_panic]` without `expected` pass on any error, including the wrong
  guard. Match the variant the intended guard produces and, where several
  guards share a variant (`StorageError::Backend`), its message.
- **Unreachable rejections.** A negative case whose input the production path
  never produces, or that a sibling guard rejects first.
- **Mocks supplying the asserted behavior.** A mock relay, peeler or clock
  decides the ordering, acknowledgement or delivery the test then asserts.
  Fixtures must not fabricate receipts, acknowledgements or ordering the
  owner should produce, or assert persistence through a path the store never
  writes.
- **Call-shape assertions.** Counting calls to a private helper, or asserting
  internal sequencing that no caller can observe and no protocol or storage
  contract requires.
- **Layer replays.** The same scenario rerun at engine, session, app,
  simulator and CLI level with no assertion specific to the layer.
- **Copied inventories.** A hand-maintained list of variants, exports or
  files that the test compares against another hand-maintained list.
- **Sleep-to-settle.** A `sleep` before an assertion instead of awaiting the
  produced state, or a flake "fixed" by raising a timeout or adding retries.
- **Timed races.** A contention or transaction-scope claim staged by holding
  a lock for a fixed time. A descheduled thread runs the operation after the
  lock is gone and the test passes without contention. Prove it by behavior:
  a second connection, a trigger that raises, or a busy handler that observes
  the wait.
- **Unpromised order.** Reading an unordered listing by index, or comparing
  it with a `Vec` in insertion order. Sort or compare as a set unless the API
  promises the order.
- **Misleading names.** The name promises behavior the inputs or assertions
  never exercise. Judge a test by its assertions, not its name.
- **Dead tests.** `#[ignore]` with no recipe, CI job or documented manual
  command that runs it.

## Retention bar

Keep a test that is the only proof of any of these, however slow, static or
ugly it is. Slow or static is a reason to move or speed up a test, never to
delete it.

- **Wire and protocol bytes:** conformance and byte-level vectors, MLS
  extension and Nostr event encodings, NIP-44 framing.
- **Storage:** migrations, persisted shapes and their `insta` snapshots, the
  SQLCipher file-backed rail, rollback and savepoint behavior.
- **Binding surfaces:** UniFFI and C ABI shapes and parity, and the defaults
  bindings see.
- **Convergence, delivery and branch selection:** simulator vectors, scenario
  families, fixed-seed properties, observable ordering.
- **`AGENTS.md` invariants, root and nested:** privacy-safe tracing, dial
  safety, the retired-relay denylist, restrictive file modes, torn-write-free
  multi-step state changes, MLS group ids kept apart from Nostr route ids,
  and every guard a nested `AGENTS.md` names (for example the engine's ban on
  calling OpenMLS `leave_group`).
- **Named regressions:** a test tied to an issue or incident stays until a
  keeper provably catches the same failure.
- **Cross-referenced names:** tests named by Tamarin models, vectors,
  `SCENARIOS.md`, `PROPERTY_TESTS.md`, `MUTATION_MATRIX.md`, CI or nextest
  filters, or the land-change smoke. Deleting or renaming one means updating
  the reference in the same change.

A test that reads source is valid only when it is the cheapest guard of an
invariant above, such as a ban on a call. Keep it failing closed: when the
marker or file it reads moves, it should fail, not pass vacuously. A failing test may be
reporting a product bug: reproduce it and fix the owner. Never delete a test
because it fails.

## Test-only seams

Production code carries test-only surface: `test-policy-overrides` gates,
`test-support` features, `cfg(any(test, feature = ...))` items and
`*_for_test` functions. Each one is code a release build never runs the way
the tests do.

- **Acceptable:** a seam that only changes a value the same production path
  reads (a settlement window, retry budget or clock), or that skips cost
  without changing what the test asserts. `in_memory_for_test()` copies a
  template that the same fresh open migrated and turns off SQLCipher memory
  security, so tests that assert production settings
  (`crates/storage-sqlite/tests/test_support_defaults.rs`) and the encrypted
  rail (`crates/cgka-engine/tests/sqlite_storage.rs`) keep their own stores.
- **Fault, observation and replay seams:** a feature that serves a contract
  no public boundary can reach, such as `test-crash-hooks` (a crash between
  two writes), `test-conformance-snapshot` (a parked convergence pass's
  backoff) or storage's `test-conformance-replay` (the simulator replays
  captured commit bytes from a checkpoint). Keep it and its tests. Before
  judging any seam unused, check which features dependent crates enable in
  their `Cargo.toml`.
- **Not acceptable:** any other seam that skips a production step, injects
  state the owner should produce, or exposes internals so a test can assert
  on them. Move the proof to the public boundary first, then delete the seam
  together with the tests that needed it. If the proof cannot move, the seam
  belongs in the category above: keep it.
- A seam whose last test caller you delete is dead: remove it in the same
  change. The compiler does not warn about unused `pub` items or
  feature-gated code, so grep for callers.

## Cost

- **Binaries.** Every `tests/*.rs` file is its own binary that links the
  whole dependency graph (OpenMLS, SQLCipher, nostr). Add a module to an
  existing binary of the crate. A new file needs a reason: different
  features, a nextest test group, or process isolation.
- **Time.** Await produced state; never sleep. Use `tokio::time::pause` or an
  injected clock where the code reads time. Reuse the existing harnesses
  (`HarnessClient` and `TransportBus`, the Nostr stack harness, the
  app-runtime journeys) rather than booting a new stack per test.
- **Budget.** Report the wall time of each new or changed test from nextest's
  output. A test over 5 seconds must prove a contract no cheaper layer can.
  Over 30 seconds, it belongs in a dedicated CI job or nextest test group, with the
  reason in the PR.
- **Storage.** Use in-memory storage unless the contract is about the file,
  encryption, locking or what survives a reopen. A test you keep or move
  keeps every drop-and-reopen and second-connection read it had, even one
  that looks incidental: open-time code (startup sweeps, recovery, cleanup)
  can break what survives a restart, and only those reopens catch it. Cut
  their cost with a raw SQLCipher key (`SqlCipherKey::raw`) unless the key is
  itself the contract (key derivation, a fixture's key, a legacy
  passphrase), and never by dropping an open. A whole test can still go when
  a keeper that reopens the same way proves its contract.

## Audit evidence

Discovery is read-only, and its candidates are reported before any edit.
Record for each candidate:

- the exact test, and the failure it detects today;
- non-test callers of the production code or support seam it covers;
- the proof that remains (the keeper), or why there is no contract;
- why the test exists (`git log -S`, the issue or PR that added it) and what
  deleting it unlocks: a seam, a binary, a fixture;
- the risk, and the focused command that validates the change.

No evidence, no deletion. Prefer a few high-confidence candidates to a long
list. Keep ledgers in scratch space or the tracking issue, never in the
repository.

## Validation and report

- Run the owner's tests and its siblings, then the root `AGENTS.md`
  Verification steps for each crate you touched. Clippy with `--all-targets
  --all-features` catches imports and private helpers a deletion orphans.
- Update everything that names tests or binaries. Grep the whole repository
  for every old test and binary name; the usual places are
  `.config/nextest.toml` overrides, every workflow in `.github/workflows/`
  (the nightly jobs pin exact names too), `Justfile` filters (run
  `just simulator-filter-contract` for simulator changes), `scripts/`,
  registries such as the simulator's `PROPERTY_TESTS.md` and `SCENARIOS.md`,
  the land-change smoke, and the test file maps in the crate's `AGENTS.md`
  files. A stale exact-name filter does not always fail.
  An exclusion (`not test(=...)`) silently stops excluding, and the
  partitioned workspace CI job runs with `--no-tests=pass`.
- For each contract you consolidated, break the production owner once by
  hand, confirm the keeper fails, then restore the source exactly.
- Report what you removed and why (by junk pattern), the contracts kept and
  their keepers, test and production lines before and after (counted
  separately), wall time and binary count before and after, seams removed,
  and follow-ups.
- Land through `.agents/skills/land-change`.
