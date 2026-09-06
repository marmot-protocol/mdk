# Offline catch-up fixes and regression coverage

The strict public app workload recovers all 1,024 original messages, agrees on public group state,
exchanges fresh traffic and preserves the recipient timeline after restart. The engine regressions
also require complete payload multiplicity, exact canonical state, active decryptability and no pending work.

## Production changes

- **Complete each deferred generation before commit replay.** Extend the durable generation barrier to
  uncontested catch-up so advancing commits cannot prune epoch context before raw application rows are tried.
  Capacity-refused history stays transport-owned, and background work yields for its redelivery after advancing.
- **Keep background recovery responsive.** Share a 64-row allowance and cooperative 500-ms budget across
  sweeps. Materialize historical peel contexts once per sweep, restoring live storage before awaiting the peeler.
  Preserve context invalidation, historical retention policy, durable resume and the generation barrier.
- **Project each recovered event with its own source ID.** Scheduled/send/inbound effects may release multiple
  messages. Reusing one triggering or empty ID caused uniqueness collisions in the app event projection;
  the common observer now follows the same per-event identity rule as restart replay.
- **Repair events hidden by SDK deduplication.** Explicitly materialize fetched event bodies even when the SDK
  has already seen an ID but the account has not durably admitted it. Reconcile the current window during
  explicit backfill and rotate bounded batches past refused prefixes. Advisory cursors do not acknowledge delivery.
- **Retain the cap mitigation.** The raw-row cap is 2,048, up from 512; byte limits and epoch-retention policy
  remain unchanged. The cap alone did not fix the public regression.

The 500-ms budget is cooperative between complete operations, not a hard timeout or cancellation inside a
snapshot rollback. No query deadline, key-retention limit, storage schema or SQLCipher library is changed by
these fixes. Upstream schema/deadline changes were merged separately from master.

## Maintained coverage

`crates/cgka-conformance-simulator/tests/support/offline_catchup.rs` reconstructs generator v1, seed 17001,
case 19, with the original Current-profile founding acknowledgement and a 368-message reduction that retains
all 16 commit rounds. The engine and app tests share this definition. SHA-256 pins cover the complete
serialized metadata, actions and expected outcomes. Before removing the two expanded JSON files, both
reconstructions were compared with the original parsed fixtures and matched exactly.

The original expanded fixtures and investigation history remain available in signed checkpoint `9282a643`.
The large app journey writes its expanded `backlog-input.json` alongside its observations. A future generator
change fails the hash check before a scenario executes; do not update the pins without comparing the workloads.

The harness progress guard includes completed distinct-context attempts on retained rows. A bounded sweep
can do useful durable work while row count and epoch remain unchanged. Tests still reject a repeated state
with no new attempts; the guard change does not weaken payload or settlement assertions.

Cleanup validation also exposed a probe observation bug: Bob's fresh message queued during convergence,
then published and reached every peer, but the probe retained its initial queued status before the next
transport turn. The engine subject now drains up to eight ready transport turns and refreshes queued status
only from authenticated publication evidence. A small deterministic regression reproduces the old failure;
a companion still rejects queued-but-unpublished messages. Exact recipient delivery remains mandatory.

Public coverage includes six ordinary journeys (messaging, profile update, late invite, removal, restart and
small offline recovery), the explicit slow 1,024-message gate, and seeded public send/leave, membership re-entry
and offline-recovery companion families. Capability inventory is preflight only; it is not a runtime pass.
See `crates/cgka-conformance-simulator/APP_PATH_COVERAGE.md` for the exact coverage boundaries and family gaps.

## Verification and reproduction

Before fixture cleanup, both large public runs passed in 213.53 and 215.27 seconds, with all participants at
epoch 22. Fresh messaging and recipient restart passed; both runtimes closed cleanly. All four engine history
regressions passed, as did the six basic app journeys, small offline canary, full engine suite and focused
projection, SDK, deferred-peel and progress-guard tests. Cleanup validation uses the same pinned workloads.
After cleanup and the probe correction: all four history runs plus the pin check pass (160.34 seconds),
all seven public journeys pass (330.50 seconds), and the small public offline canary passes (84.79 seconds).
The full engine suite passes 540 tests; the SDK adapter suite passes 122; the three app projection regressions,
33 subject tests, three neighboring decryptability scenarios and two public catalog contracts pass. `just fast-ci`
passes on the final source. The GitHub full test matrix remains separate.

Detailed local evidence is under `target/background-recovery-20260906/` and `target/fixture-cleanup-20260906/`.

For production-policy scenario runs, set `CARGO_BUILD_JOBS=4`, `CARGO_TARGET_DIR=target/offline-build` and
`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false`; omit test-policy override features:

```sh
cargo test --release --locked -p cgka-conformance-simulator --test offline_catchup_regression -- --test-threads=1
cargo test --release --locked -p cgka-conformance-simulator --test app_runtime_journeys -- --include-ignored --test-threads=1
cargo test --release --locked -p cgka-conformance-simulator --test public_app_families public_offline_recovery_strict_canary -- --ignored --test-threads=1
```

Run `just fast-ci` before pushing. It checks the workspace and OTLP builds but does not replace the scenario tests
or the full GitHub test matrix. Set `MDK_OFFLINE_REGRESSION_ARTIFACTS` to retain expanded engine inputs and
full reports in fresh private subdirectories. Direct execution of built test binaries requires `RUST_MIN_STACK=4194304`.

## Remaining boundaries

- Public app tests use real loopback Nostr relays and encrypted participant databases. Their native relay order
  differs from the engine's forced reverse order. They do not establish device performance or broad real-relay reliability.
- Keep the large public test as an explicit slow gate pending an appropriate CI lane. Skipped does not mean passed.
- Resolve the public send/leave family's epoch expectation before claiming that family passes. Its mismatch is
  documented in `APP_PATH_COVERAGE.md`; do not relax it merely to obtain a green result.
- Next discovery work should target publication/invite faults: partial success, relay rejection/disconnect,
  restart with queued messages or Welcomes, relay-list changes, and history repair without reconciliation support.
- The earlier native SQLCipher crash was reproduced during unsafe diagnostic process exit while workers were
  writing. Stop-and-join teardown corrected that diagnostic. No general production SQLCipher fix is claimed.

## Preservation

Signed checkpoints `77356248`, `775e6459` and `9282a643` preserve the original consolidation, projection fix
and recovery-responsiveness fix. The original worktrees and private diagnostic artifacts were preserved.
Do not commit diagnostic databases, generated keys, crash dumps or copied executables.
