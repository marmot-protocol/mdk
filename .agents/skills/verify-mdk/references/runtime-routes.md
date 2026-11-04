# Runtime verification routes

Paths are repository-relative. This reference was checked against MDK source
on 2026-11-04; it is a routing aid, not a record that every route passed. Read
the named test and owning documentation before choosing a command.

Initial authoring validation exercised the frozen-binary development recipe
for journey 05 through evidence inspection and cleanup. The other routes are
source-checked starting points, not recipes exercised by that validation.

## Find the owner

| Requested behavior | Starting point | Acceptance evidence and limits |
| --- | --- | --- |
| Public messaging, invite, removal, and continuing communication | `crates/cgka-conformance-simulator/tests/app_runtime_journeys.rs`; `APP_SCENARIO_INVENTORY.md` in that crate | Public journeys 01, 03, and 04. Default app harness uses separate participant processes, private SQLCipher roots, and a separate local relay. This does not exercise CLI parsing, native app UI, or public-relay deployment limits. |
| Orderly restart and small offline backlog | Same binary, journeys 05 and 06; `APP_PATH_COVERAGE.md` | Inspect exact timelines/state and continued communication across the selected offline/reopen sequence. Read the actual steps: do not describe orderly shutdown as an abrupt crash or a repair-driven journey as autonomous recovery. |
| Abrupt process kills or scheduled relay faults | `RUNNING_CAMPAIGNS.md`, `tests/app_generated_variance.rs`, `tests/process_orchestrator.rs` | Select the documented fault-capable route and inspect kill/reopen or socket-cut observations. Action-boundary kills do not establish mid-transaction crash behavior. Broader campaigns remain subject to local-run limits. |
| CLI commands, JSON, and daemon lifecycle/forwarding | `crates/cli/AGENTS.md`, `crates/cli/tests/cli.rs`, `crates/cli/README.md` | Actual `wn`/`wnd` commands and their effects. The quick CLI smoke uses test-policy overrides and a mock relay; it is not production-timing or native-app acceptance. |
| Exact engine-private state, persistence, or wire contracts | Nearest engine/storage/peeler `AGENTS.md`; simulator `SCENARIOS.md` and `PROPERTY_TESTS.md` | Use the real owner and the cheapest adequate harness. Public projections cannot stand in for private dispositions, wire-byte assertions, or exact MLS state. |
| C ABI or generated-language behavior | `crates/marmot-c/AGENTS.md`, `crates/marmot-uniffi/AGENTS.md`, their binding smoke recipes | Execute the binding boundary relevant to the claim. A Rust conversion test does not establish a generated Swift/Kotlin ABI or device lifecycle. Follow platform prerequisites and existing bindings documentation. |
| Container/VM host boundaries | `crates/convergence-campaign-runner/AGENTS.md`, simulator `RUNNING_CAMPAIGNS.md` and `SCALING_CAMPAIGNS.md` | Use only when the host/kernel/network boundary answers a stated question and the requested scope allows it. Larger execution layers do not increase semantic coverage on their own. |

The maintained feature/scenario descriptions remain in the linked owners.
Do not copy their counts, complete commands, or coverage claims into another
registry. Shared Scenario IR is the replay boundary for moving supported
scenarios between adapters without dropping expectations.

## Public journey recipe

Run from the repository root. Choose one of these exact test names after
reading its acceptance conditions in `tests/app_runtime_journeys.rs`:

- `public_app_01_bidirectional_messaging`
- `public_app_03_late_join_and_messaging`
- `public_app_04_removal_and_remaining_member_messaging`
- `public_app_05_restart_and_continue_messaging`
- `public_app_06_small_offline_backlog`

For a targeted development check, this example selects the orderly-restart
journey, retains its artifacts, and runs no other test:

```sh
umask 077
MDK_VERIFY_EVIDENCE=$(mktemp -d "${TMPDIR:-/tmp}/mdk-verify.XXXXXX")
export MDK_APP_JOURNEY_ARTIFACTS="$MDK_VERIFY_EVIDENCE"
git rev-parse HEAD > "$MDK_VERIFY_EVIDENCE/source-revision.txt"
git status --porcelain > "$MDK_VERIFY_EVIDENCE/source-status.txt"
cargo nextest run -p cgka-conformance-simulator --locked \
  --test app_runtime_journeys --no-tests=fail --retries 0 --test-threads 1 \
  -E 'test(=public_app_05_restart_and_continue_messaging)'
```

Retain the exact command and runner output beside the artifacts. The default
development profile is a development check; follow `APP_PATH_COVERAGE.md`'s
release/production-policy recipes when that is the acceptance claim. Never use
the half-second `precheck` profile as runtime acceptance evidence. Do not
enable `test-policy-overrides` for this default production-settlement recipe.
Keep CLI override builds separate so Cargo feature unification does not alter
the app journey's timing policy.

Cargo integration-test builds supply the sibling `cgka-conformance-node`.
The harness checks helper protocol and timing-policy compatibility during
startup. For shared-target execution, first build without running; retain
Cargo's artifact metadata, copy the matching selected test executable and node
helper into the private run directory, and set `MDK_APP_PROCESS_NODE` to the
copied helper. Run the copied libtest executable with the selected test name,
`--exact --nocapture --test-threads 1`, and `RUST_MIN_STACK=4194304`. Retain both
binary hashes and the build configuration. Frozen binaries prevent later
builds from replacing the helper between participant starts.

Direct report/inventory binaries need an explicitly built matching node;
follow `APP_SCENARIO_INVENTORY.md`. Do not guess that an older installed helper
matches the current runner.

### Readiness, results, and teardown

The selected journey creates its own relay and participants; do not attach to
an installed daemon or personal identity. Setup/RPC failures are readiness or
execution failures, not passing scenarios. `input.json` records the chosen
journey/configuration and `execution-layout.json` records participant/relay
processes. Inspect those receipts rather than inferring layout from the test
name. Confirm an expected outage or kill in the fault route's observations.

With `MDK_APP_JOURNEY_ARTIFACTS` set, the test retains an
`app-journey-<journey>-*` subdirectory on success as well as failure. Inspect:

- `result.json`: `passed`, `error`, and `close_errors`. Require a successful
  scenario and empty cleanup errors.
- The journey-specific checkpoints and `terminal.json`: expected public
  state, exact payload multiplicity, pending confirmation, and the effects
  actually claimed. An absent terminal observation is an evidence gap.
- `execution-layout.json`: isolation and the recorded process identities.

The journey closes participants, shuts down the subject, reaps owned children,
and only then records its result. Verify that recorded processes are gone
after execution, taking PID reuse into account, and confirm artifacts remain.
Retain evidence on failure before a fresh attempt. On a watchdog or externally
terminated run, cleanup must be checked separately; absence of `result.json`
is not success. Do not remove the evidence directory during teardown.

## CLI/daemon recipe

Read `crates/cli/AGENTS.md` and the selected test first. Existing narrow starts:

```sh
cargo nextest run -p wn-cli --locked --test cli \
  --features test-policy-overrides --no-tests=fail --retries 0 --test-threads 1 \
  -E 'test(=local_group_message_workflow_runs_through_the_dm_contract)'

cargo nextest run -p wn-cli --locked --test cli \
  --features test-policy-overrides --no-tests=fail --retries 0 --test-threads 1 \
  -E 'test(=daemon_start_status_execute_and_stop_are_user_facing_commands)'
```

The legacy phrase in the messaging test's name identifies the existing test;
do not rename it from this recipe. Retain source/build provenance and runner
output in a private evidence directory. Check assertions against the task:
one lifecycle smoke does not cover every command, streaming mode, or dev-device
feature. These tests own disposable homes, relay fixtures, and child daemons;
use their teardown and verify no owned processes survive. Manual driving must
select an explicit private home and owned socket, preserve the CLI's stdin
secret handling and loopback guards, and never fall back to the user's daemon.

## Saved-input recovery and broader evidence

Use `RUNNING_CAMPAIGNS.md` for saved generated input, report replay,
failure-capsule replay, strict oracles, and fault evidence. Preserve family and
generator version, seed/case, input digest, adapter, storage, and exact source
revision. Saved logical input reproduces the schedule, not randomized MLS
bytes; exact byte replay needs the appropriate sensitive checkpoint.

Start with a small named case. An ordinary suite excludes explicit slow
journeys, including the 1,024-message recoveries. A whole-catalog run or
container/VM campaign is not a default check for this skill. Distinguish
public-state evidence, exact engine evidence, and actual host/platform runs.

For `saved_app_recovery_diagnostic`, a passing test can mean the diagnostic
captured a failing workload. Read its `result.json` `scenario_passed` field
and the scenario report. Do not confuse that schema with the fixed public
journey's `passed` field. Preserve stopped private fixtures as sensitive
evidence, separately from shareable synthetic reports.
