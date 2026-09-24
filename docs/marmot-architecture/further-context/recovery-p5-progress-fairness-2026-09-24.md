# P5 progress and fairness: bounded worker evidence

This note covers the inactive, test-enabled real-SDK bounded known-event path at
`b9ffb8f0` plus the focused tests in
`crates/marmot-app/src/runtime/account_worker/tests/real_sdk_progress_fairness_tests.rs`.
The production activation flag remains off.

| Acceptance question | Source boundary | Focused witness |
| --- | --- | --- |
| Can ready local work advance while history waits? | `account_worker.rs`: bounded `Job::wait` is selected alongside commands, receive, and scheduled convergence; admission is one event per turn. | In Normal mode, a conforming local relay holds an exact request for the group creator. An admin peer publishes three valid MLS profile commits and an update in a second group. All four are durably retained before scheduled local passes. Epoch, projection, another group, send, read, and live receive are checked before the SDK result is accepted. |
| Do distinct missing known IDs get owner turns? | `bounded_recovery::prepare` chooses one known-event ticket, then the recovery owner freezes a one-obligation grant. | Two real MLS messages are published while the receiving account is signed out. The local relay refuses ordinary history. Direct retained-event checks prove both IDs missing at the first held query, the first present after its demand clears, and the second still missing at its held query. Exact request counts and frozen scopes show distinct turns with no restart of the first request. |
| Can a broad comparison occupy the worker separately from exact acquisition? | `run_pending_epoch_backfill_reporting_arm` awaits `client.run_pending_epoch_backfill` on the serialized worker. | Unqualified in this slice. A separate real-SDK experiment observed a held NIP-77 frame and a queued send, but comparison grant selection and frame-to-worker attribution were not repeatable enough for a regression assertion. |

The source-level P5 responsiveness gap remains: the worker's receive,
maintenance, and scheduled-convergence arms still await legacy broad recovery.
The maintenance path enters `run_pending_epoch_backfill_reporting_arm`,
`AppClient::run_pending_epoch_backfill`, and the broad grant executor. In a
separate local experiment, a held `NEG-OPEN` sometimes delayed a same-account
send until release. Other runs left the comparison revision pending while an
incremental-history obligation spent retry grants without a new `NEG-OPEN`.
`join_recovery_comparison` itself creates that durable incremental-history
ticket, so the comparison is not the only legitimate next candidate.
A restart-first experiment held a startup `NEG-OPEN` while a same-account send
completed. These observations do not reliably identify the selected worker
operation and do not establish permanent starvation or a command-latency
bound. No broad-comparison qualification is claimed here.

The exact-request fixture uses a five-second SDK request limit. Its order
assertions require useful work before the result-ready notification and while
the durable known-event request remains pending. The local convergence
settlement override is 100 ms and the extra scheduled delay is 500 ms in the
`test-policy-overrides` build. A four-second elapsed-time assertion from relay
entry covers retention, local backlog and other-group progress, send/read,
and live receive before the five-second SDK request expires. The test also allows at
most three seconds between observed local epoch advances. These are
controlled CI fixture values, not production latency guarantees.

## Limits

- The retained-epoch fixture proves progress for a creator account with three small
  valid commits from an admin peer, one other due group, and a held known-event request. It does
  not prove the approximately 36-group/11,000-event/51-member workload or
  device latency budgets from #1947 and #1948.
- The two-ID fixture proves consecutive owner opportunities after the retry
  gate is crossed, using the frozen ticket and attempt serial while each
  relay query is held. It does not establish a global scheduling weight or
  fairness across arbitrary accounts and relay failures. This branch pins
  rust-nostr at `0efbb4ee20cd2d48ff9ffc19d307ec5a3658d6b9`, which can
  also route acquisition events into its ordinary notification path. The
  overlapping path means durable retention here cannot be attributed solely
  to bounded result admission. [SDK PR #2](https://github.com/erskingardner/rust-nostr/pull/2)
  has merged, but this slice does not change or qualify the production pin.
- The command responsiveness requirement under broad comparison remains
  unqualified until the worker-held wait and comparison selection are covered
  by a separately reviewed P5 execution change and deterministic regression.
- The worker still has legacy broad history calls in receive, maintenance,
  and scheduled-convergence arms. Their whole-turn occupancy, fallback
  budgets, cold-reopen workload, and device measurements are not qualified by
  these tests. `run_pending_epoch_backfill_reporting_arm` awaits
  `run_pending_epoch_backfill`, which can await the broad grant executor.

No schema, scheduler weight, SDK dependency, binding, or production activation
change is part of this slice.

## Local verification

- `cargo test -p marmot-app --features test-policy-overrides --lib real_sdk_progress_fairness_tests -- --nocapture`: both focused tests pass.
- `cargo test -p marmot-app --lib real_sdk_progress_fairness_tests -- --nocapture`: the default-build two-ID test passes.
- `just fast-ci`: passes, including workspace checks and Clippy.
