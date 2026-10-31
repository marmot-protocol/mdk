# AGENTS.md — cgka-engine tests

Three tiers, each owning a different correctness question. The crate's tests are Tier 2; Tiers 1 and 3 live in sibling
crates and are listed here for navigation.

## Tier 1 — In-crate unit tests (other crates)

**Where:** `crates/traits/src/engine_state.rs::tests`, `crates/traits/tests/snapshots.rs`,
`crates/storage-sqlite/src/**::tests`. **What they prove:**
pure-data-structure correctness — state-machine transitions, storage round-trips, snapshot/rollback, JSON shape
stability of cross-boundary value types. No engine, no MLS.

```sh
cargo test -p cgka-traits
cargo test -p storage-sqlite
```

To accept new snapshot shapes after a deliberate change:

```sh
cargo insta review
```

## Tier 2 — Engine integration tests (this directory)

**What they prove:** real OpenMLS-backed engine behavior across one or more engine instances using a pass-through
`MockPeeler`. Most files use in-memory `Engine<SqliteAccountStorage>` opened with `in_memory_for_test()`, which skips
SQLCipher's per-allocation memory locking; `sqlite_storage.rs` keeps the encrypted file-backed backend on the same rail.

**Transport visibility.** The pass-through `MockPeeler` gives every test client perfect cross-branch visibility, which
production does not have: a real transport seals a group message under the sender's current-epoch exporter secret and
carries no epoch hint, so a device that never entered that epoch state reads opaque bytes. Tests whose subject is
*what a device can see* must opt into `support::epoch_sealed_peeler::EpochSealedPeeler`, which models that sealing
(`tests/epoch_sealed_transport.rs` owns the resulting behaviors). Reach for it whenever a scenario turns on branch- or
epoch-scoped readability; `MockPeeler` stays right for everything else.

- **File:** `application_data_wire.rs`
  - **Owns:** OpenMLS integration-contract tests for the MLS application-data carriers Marmot uses (pins fork codec
    behavior the engine relies on)

- **File:** `scaffold.rs`
  - **Owns:** `EngineBuilder` validation and empty-engine behavior

- **File:** `group_creation.rs`
  - **Owns:** Fresh KeyPackage, create, join welcome, confirm

- **File:** `group_context_view.rs`
  - **Owns:** `GroupContextView` exporter-secret length contract

- **File:** `ingest.rs`
  - **Owns:** Every `StaleReason` variant; send(AppMessage) round-trip

- **File:** `invite_leave.rs`
  - **Owns:** Invite, MIP-03 SelfRemove auto-commit, auto-publish confirm/fail

- **File:** `capabilities.rs`
  - **Owns:** `feature_status` and `upgradeable_capabilities` read from every leaf (several devices per account
    included), KeyPackage-based `constructable_capabilities`, capability matrix

- **File:** `leaf_advertisement.rs`
  - **Owns:** Own-leaf re-advertisement on self-update (peer acceptance), and staleness reported only while a refresh
    would change the leaf

- **File:** `fork_detection.rs`
  - **Owns:** Same-epoch fork resolution through the unified distributed-convergence route (committer, observer,
    and restarted-committer shapes) plus the missing-anchor fail-closed halt

- **File:** `deferred_peel_lifecycle.rs`
  - **Owns:** Durable deferred retry lifecycles, generation barriers, capacity limits, context-cache invalidation,
    foreground budgets, and background work/time budgets with restart and eventual-completion checks. Also the
    publish-cycle replay's cost: rows it keeps parked are not lineage-classified, and each retained anchor's context
    is derived once per replay rather than once per row. A retry that re-defers a row at a new epoch records no
    `peel_deferred -> peel_deferred` audit row.

- **File:** `distributed_convergence.rs`
  - **Owns:** Stored-message convergence, stale classification, retained-anchor behavior, and the canonical
    application handoff after catch-up (horizon boundary, restart, bounded turns, and independent send gate).

- **File:** `distributed_convergence/historical_application_sender.rs`
  - **Owns:** Source-epoch application attribution after removal, replacement leaf reuse, and rejoin; direct
    ingestion and buffered replay after restart, duplicate suppression, and forged replacement-author rejection.

- **File:** `distributed_convergence/delivered_witnesses.rs`
  - **Owns:** Which delivered applications a convergence pass holds (mdk#2330): inert ones at or below the witness
    floor are left out, a lower-epoch rival admitted mid-pass takes them back, a pending application keeps its
    epoch's delivered ones for its sender's receive ratchet, and SQLite's content-filtered listing leaves out exactly
    what the engine's own projection of real messages would.

- **File:** `distributed_convergence/phantom_own_commit_branch.rs`
  - **Owns:** An own-commit checkpoint never restores after a sibling of the parent it was built on (mdk#2657): a
    parked own commit and the canonical rival at its epoch yield one branch per tip commit, and a pass whose tie
    would pick the phantom still applies on its first attempt. Also an ignored measurement of host advances and
    wall time to the first delivered message over a widened group.

- **File:** `distributed_convergence/refused_queued_intents.rs`
  - **Owns:** A queued admin change the settled state refuses (the sender was demoted while it waited) is retired and
    announced as `GroupEvent::QueuedIntentRefused` for each admin intent kind, the work queued behind it still drains,
    and no later drain prepares it again (mdk#2694). The storage-held counterpart lives in `record_write_atomicity.rs`.

- **File:** `distributed_convergence/encrypted_media_source_secret.rs`
  - **Owns:** A replayed media application carries its source-epoch encrypted-media secret on `MessageReceived`
    even when the same pass advances past the anchor horizon and prunes that epoch's retained anchor.

- **File:** `convergence_policy_pin.rs`
  - **Owns:** Default-build pinned v1 policy rejection (mdk#970). Run
    `just test-convergence-policy-pin` without `test-policy-overrides`; the broader integration
    matrix enables that feature explicitly for settlement/rewind fixtures.

- **File:** `mip03_guards.rs`
  - **Owns:** Committer-MUST-NOT-be-leaver, admin-not-last, admin-self-remove

- **File:** `publish_lifecycle.rs`
  - **Owns:** Explicit publish-before-apply lifecycle for local group evolution

- **File:** `pending_commit_recovery.rs`
  - **Owns:** Crash-during-publish recovery at session open — `hydrate_all_stored_groups` detects a surviving
    `PendingCommit`, clears it, and surfaces `GroupEvent::PendingCommitRecovered` (mdk#150)

- **File:** `record_write_atomicity.rs`
  - **Owns:** Group-projection atomicity under injected record write failures (mdk#333, mdk#794), one test per
    seam that projects the record. No torn record,
    orphaned pending publish, leaked snapshot, stale stored proposal, or epoch split between the record and the epoch
    manager; the group stays usable, and an apply the fault abandoned hands its still-retained winning commit back to
    stored convergence so it is eventually applied. Also owns the snapshot-guard durability pair: a guard whose
    rollback fails keeps its snapshot for open-time recovery, and a historical peel context is derived once per
    candidate generation rather than once per bounded slice. A failed canonical apply rolls back inside a caller
    transaction that still commits, without a full pre-apply snapshot (mdk#2326). A reorg onto a legacy full anchor
    keeps live rows, queued intents and pending app output on SQLite and on the generic rewind, including when a
    write fails part way through the generic one (mdk#2330). `record_write_atomicity/convergence_pass_retry.rs`: a
    frozen batch whose apply keeps failing backs off and parks after its budget, reopens on a commit or a
    current-epoch proposal it does not hold, including one a direct-path peel rewrote into an older row, but not on
    application traffic or input beyond its horizon, reseeds nothing on loads with no new input, takes one explicit
    retry (none for a quarantined group, whose park reads as none), and keeps its count, delay and park across a
    restart; with `test-conformance-snapshot`, structural progress reports the backoff as a wake, the park as idle,
    a due SelfRemove auto-commit behind either as waiting, and new input as runnable (mdk#2684)

- **File:** `apply_history_cost.rs`
  - **Owns:** Ignored regression benchmark for canonical-apply cost against stored message history (mdk#2326). Run in
    release with `--ignored --nocapture`; it reports timings and never asserts a threshold

- **File:** `hydration_quarantine.rs`
  - **Owns:** Group hydration-quarantine path — `GroupHydrationQuarantineReason` classification on session open

- **File:** `two_phase_hydration.rs`
  - **Owns:** mdk#1161 two-phase hydration — cheap-pass seeding vs `GroupNotHydrated` gating, `ensure_hydrated`
    promotion and quarantine parity, cheap-pass idempotency, durable transport-route seeding, the bounded ingest
    route backfill (missing and stale-stamped route sets), eager full hydration of unrecoverable groups, and
    retention-window route retirement across rotation and restart

- **File:** `snapshot_privacy.rs`
  - **Owns:** Snapshot names do not expose plaintext group ids

- **File:** `sqlite_storage.rs`
  - **Owns:** SQLCipher-backed `Engine<SqliteAccountStorage>` create + confirm smoke

- **File:** `crash_recovery_sqlite.rs`
  - **Owns:** Debug-feature-gated subprocess-kill coverage at retained-anchor rewind and historical-apply transaction
    boundaries. Reopens encrypted SQLite, observes the stranded pre-hydration state, then verifies hydration restores
    live state and releases convergence snapshots. The historical apply is one savepoint, so its kill strands no
    snapshot. Candidate replay kills after temporary processing and restoration
    also verify exact pre-probe group state, epoch authenticator, snapshots, input ledger and queued work before
    hydration, both standalone and inside an outer transaction.
    Resumable selection and peeling also kill after historical rewind and after a restored slice; reopening must
    recover live state and queued work, discard scratch progress, and select the same winning branch.
    Every parent spawns and waits through `spawn_crash_child` / `CrashChild::kill_when_ready`; the ready bound is
    120 s (`MDK_CGKA_CRASH_READY_TIMEOUT_SECS` overrides). Keep child fixture peers on the migrated in-memory template
    so setup cost does not eat that bound on loaded CI runners.

- **File:** `update_group_data.rs`
  - **Owns:** Group profile `AppDataUpdate` commits and convergence-side Marmot record refresh

- **File:** `account_devices.rs`
  - **Owns:** The `marmot.group.account-devices.v1` (0x800d) rules in groups that require it: no data, support, the
    per-account leaf limit, never un-require, and Welcome acceptance. Each rule is checked by the committer, by replay
    of a raw OpenMLS commit, at ingest for standalone proposals, and by the joiner of a raw OpenMLS Welcome, which
    applies the state rules and the GroupInfo rule and accepts a Welcome from its own account; before activation, and on
    the legacy profile, 0x800d data stays unknown data and only an admin's Welcome joins. Also same-account Commits
    (mdk#2628 item 2.1c): which shapes a non-admin may commit, from both sides; the stamp's priority equal to replay's
    for every class; and races settled the same way on every client. Also that the builder accepts 0x800d and still
    refuses protocol ids the engine does not implement. Its `found_group(.., false, ..)` founds with a member that
    does not advertise 0x800d and then removes it, because creation requires 0x800d whenever every founder advertises
    it.

- **File:** `account_devices/creation.rs`
  - **Owns:** Creating a group (mdk#2628 item 2.3): the founding state requires 0x800d exactly when the creator's leaf
    and every founding KeyPackage advertise it, without the host asking; a founding Add over the leaf limit is refused
    with no group, Welcome or event left; invitees join the requiring group, a non-admin member then adds and removes
    its own devices, and a device that does not advertise 0x800d cannot be added later, from both sides.

- **File:** `account_devices/activation.rs`
  - **Owns:** Turning account-devices on in an existing group (mdk#2628 item 2.4), `EnableAccountDevices`: an admin's
    Commit that every member accepts; each refusal (not an admin, already required, a leaf without support or with data
    under the id, an account over the leaf limit) comes before staging with the same aggregate reason the eligibility
    read gives; a stray GroupContext entry is removed; a pending standalone Add of a device without support stays out
    of the Commit. The legacy refusal is in `account_devices.rs`'s legacy test.

- **File:** `account_devices/device_roster.rs` (test-policy builds only)
  - **Owns:** `marmot.account.device-roster.v1` (0x800e, mdk#2628 item 3.1): a device group holds its roster from
    creation; a roster update is a diff every member applies to the parent's roster, and a committer that writes the
    update's bytes as the state is dropped; the roster's own invariants, one tag signature key per device included; every leaf is one
    account, at creation, on invite, on replay and at join; the roster is required from creation or never, for
    Commits and standalone proposals; and outside a device group roster bytes are unknown data. A device entry
    replacement (`ReplaceDeviceEntry`) never lands on an entry that changed since it was read: not from its own
    send's settlement, a rival branch at the same epoch, or the drain, and a lost one is re-issued only while its
    entry is untouched (`DeviceEntryChanged`). The
    `Parts::app_data_state` override in `account_devices.rs` lets a crafted Commit write resulting bytes of its own.

- **File:** `account_devices/link_device.rs` (test-policy builds only)
  - **Owns:** The link Commit (mdk#2628 item 3.3b), `LinkDevice`: one privileged admin Commit that adds the linked
    device and sets its roster entry, accepted by every member, with the device joining through its Welcome. Each
    refusal leaves the group as it was: not a device group, another account's KeyPackage, a device already in the
    group, a KeyPackage without the group's required components, an update that doesn't set exactly one device entry,
    an entry not for a new slot or not announcing the KeyPackage, a roster the link would leave invalid. Also the sender
    rule refusing any own device-group Commit that takes an Add from the proposal store, and `LinkDeviceUnsettled`
    instead of a queued link while convergence is unsettled or an own Commit is in flight. Its undo, `UnlinkDevice`
    (D40): one privileged Commit removing the linked leaf and its entry, which the removed device sees as its removal;
    refused for another leaf than one other leaf of the account, an update that doesn't remove exactly one listed
    entry, or while an own Commit is in flight. A device it removed that forgot its copy joins again through the next
    link's Welcome, which no forget cutoff dates.

- **File:** `account_devices/device_group_welcome.rs` (test-policy builds only)
  - **Owns:** Which Welcome a new device joins its device group through (mdk#2628 D28, D30): only the one a stored
    expectation names, from the existing device's leaf and before the wait ends, which the join consumes. A
    device-group Welcome no link expects, a forged one from another leaf, a chat Welcome under the reserved id, and a
    Welcome after the wait or a withdrawal are refused before the join, and a refused forgery leaves the real Welcome
    able to join. Also that this engine signs every leaf of a device with its one signature key (an implementation
    fact, not a protocol rule, mdk#2628 D33), which lets a first link's Confirm name the creator's key before the
    group exists.

- **File:** `account_devices/device_tag.rs` (test-policy builds only)
  - **Owns:** `marmot.member.device-tag.v1` (0x800f, mdk#2628 item 3.1d) through the engine: a member leaf whose tag
    verifies under a roster device's key reads as that device, in the tree of the epoch asked for (a past one from its
    own retained anchor, writing nothing; one with no anchor reads nothing); a tag that doesn't open never invalidates
    a Commit; another account's leaf is unclaimed; a Commit, standalone proposal or Welcome that requires 0x800f is
    rejected; a GroupContext entry under it is unknown data the engine never writes. Producing them:
    a device that sets its own key in a roster update tags that Commit's UpdatePath; every KeyPackage it then builds
    carries a fresh tag, and an untagged or no longer matching one is stale; only the entry at its own slot tags, so
    another entry carrying its key tags nothing and an entry moved off its slot stops it tagging; a founder tags its
    founding leaf from the roster it founds, from its own entry only; each kind of own Commit tags a leaf that needs a
    tag, and the members accept it; a leaf whose tag reads as its own keeps it; without a named device group nothing is
    tagged; naming a seeded group hydrates it, and a quarantined one tags nothing while a tagged KeyPackage stays
    current. The tag crypto and the spec vector are unit-tested in `src/device_tag.rs`.

- **File:** `account_devices/private_key_packages.rs`
  - **Owns:** Private KeyPackages (mdk#2628 item 3.4b) through the engine: issued ones keep their keys in the same
    transaction as their records and stay out of the KeyPackage inventory; a request stops earlier records counting
    without deleting their keys, is answered once, and past the per-sibling cap is answered with the newest ones handed over again (D42); records that no longer
    advertise this client's capabilities stop counting; an ordinary Welcome never consumes one; and a hand-off keeps
    only KeyPackages tagged as its sender's slot (D33; the tagged case runs in test-policy builds only). A sibling
    Welcome (3.5b) consumes only the private KeyPackage it names, issued to its sender, and one back into a chat still
    held active is held, writing nothing, until that copy reads removed or unrecoverable. One carried no later than a
    local forget is refused for that carrier alone, so the same Welcome in a later carrier joins.

- **File:** `account_devices/send_intents.rs`
  - **Owns:** The same-account send intents (mdk#2628 item 2.1e), `AddOwnAccountDevices` and
    `RemoveOwnAccountDevices`: the committer's Commit is classified same-account, stamped `ordinary`, carries its
    proposals by value and leaves the proposal store alone; each refusal publishes and changes nothing; every member
    and sibling accepts, an added device joins through its Welcome and a removed one sees its removal; restart treats
    them like an Invite and a removal; and fair scheduling gives a queued one the attempt an admin intent gets, never a
    self-update or a Leave, and only while the group requires 0x800d.

- **File:** `epoch_sealed_transport.rs`
  - **Owns:** Engine behavior under production transport visibility via `support::epoch_sealed_peeler` — the sealing
    model's own semantics, the fork shapes that only appear when post-fork traffic on an unadopted branch is
    unreadable, and `Group::local_copy_welcome_created_at`: the join-time clamp, and the quiet release of a deferred
    row older than this copy's Welcome (retained and released exactly as any other, minus the
    `TransportObjectResourceRefused` announcement) while unopenable traffic from an epoch ahead keeps its deferred
    retry. The predicate's own margin is a `cgka-traits` unit test

- **File:** `audit_log.rs`
  - **Owns:** Append-only forensic audit log wiring — recorder install, JSONL round-trip, no-op default behavior, and
    the in-flight operation context: a send or group creation dropped mid-await leaves no context for later rows

```sh
cargo test -p cgka-engine
cargo test -p cgka-engine --features test-policy-overrides   # suites that install custom policies
```

The default build pins the v1 convergence policy. CI runs the workspace with the `test-features` list in the root
`Justfile` (`wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks`).

## Benchmarks

`benches/group_lifecycle.rs` (criterion) measures engine CPU + storage cost over in-memory SQLite with a pass-through
peeler. Groups: `retained_anchor_snapshot`, `create_group` (1/8/32 invitees, retention on/off), `join_welcome`,
`join_welcome_large_group`, `send_app_message`, `deferred_outbound_preflight`, `ingest_app_message`,
`rejoin_welcome_with_history`, `canonical_advance_with_history`. Run:

```sh
cargo bench -p cgka-engine --bench group_lifecycle
```

These benches are the measurement rail for engine-lifecycle performance work; extend them when a
change claims a lifecycle speedup.

## Tier 3 — Simulator scenarios + proptest

**Where:** `crates/cgka-conformance-simulator/tests/`. Multi-client convergence under a deterministic in-memory bus.
File map: [`../../cgka-conformance-simulator/tests/AGENTS.md`](../../cgka-conformance-simulator/tests/AGENTS.md).
Core files: `canonical_scenarios.rs` (scripted + portable scenarios, `ScenarioSpec`, vector fixtures, scheduled
faults), `proptest_invariants.rs` (property tests), `canonicalization_contract.rs`, `candidate_state_graph.rs`.

```sh
cargo test -p cgka-conformance-simulator --test <file>   # the file you changed
just simulator-smoke                                     # PR-lane selection
```

`--features conformance-slow` is the pre-release pass; run it locally only when asked.

## Workspace-wide

For broad storage/engine changes, run CI's workspace lint once (root `AGENTS.md` Verification) and let GitHub CI run
the dependents' tests. Run `cargo test --workspace` locally only when asked.

## When adding a new test

- New `EpochState` transition → unit test in `crates/traits/src/engine_state.rs::tests` first; add an integration test
  only if the engine is involved in the transition.
- New `StaleReason` variant → add a case to `tests/ingest.rs` and a dedicated assertion that the typed variant fires.
  A variant a scenario can only reach under a real transport's epoch sealing belongs in
  `tests/epoch_sealed_transport.rs` instead, because the pass-through `MockPeeler` peels everything.
- New capability requirement type → extend `tests/capabilities.rs` and the simulator capability property so fixed
  examples and generated matrices agree.
- New MIP-03 rule → add to `tests/mip03_guards.rs`. These tests assert at the engine boundary, not via the harness.
- Multi-client convergence question → harness scenario in
  `crates/cgka-conformance-simulator/tests/canonical_scenarios.rs`. If it should hold for _any_ sequence of intents,
  encode as a proptest in `proptest_invariants.rs`.
- Cross-implementation or reportable scenario → prefer `ScenarioSpec` / JSON fixtures in
  `crates/cgka-conformance-simulator/vectors/`, and use `cgka-conformance-simulator-report` for generated report
  artifacts.

## In-crate unit tests

Engine-behavior assertions need an `Engine<S>` and a storage backend, so they live in `tests/*.rs` using
`storage-sqlite` in-memory mode (encrypted file-backed only when the test needs it). Pure-data logic (state
transitions, diff helpers, policy ordering, codecs, caches) uses in-crate `#[cfg(test)]` modules; `src/` has many, and
`src/openmls_projection/tests/` and `src/message_processor/tests/` hold `--lib` replay and measurement tests.
