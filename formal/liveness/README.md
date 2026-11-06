# Convergence lifecycle model

TLA+ model of the Marmot convergence lifecycle, checked with TLC. It owns the temporal claims — under which fairness
assumptions convergence and administrative changes eventually make progress — that the symbolic Tamarin model in
[`../tamarin`](../tamarin/) deliberately does not cover. Tamarin remains the safety, authentication, authorization, and
bounded selector-policy model; it is not stretched into a scheduler or crash/restart model.

## What is modeled

`ConvergenceLifecycle.tla` models unequal histories, eventual input closure, freeze/settle, a durable frozen revision
plus a crash-lost volatile staged revision that is rehydrated on restart, temporary resource failure, a pending
privileged administrative change, repeated member self-updates, and a joiner stranded on a losing branch. The only
modeled repair for that joiner is a fresh-state rejoin; consumed signature state is not reused.

TLC is authoritative for temporal claims because fairness assumptions are explicit and infinite stuttering executions
are part of the state space.

| File | Purpose |
| --- | --- |
| `ConvergenceLifecycle.tla` | The specification. |
| `ConvergenceLifecycle.fair.cfg` | Fair configuration; must satisfy every temporal property. |
| `ConvergenceLifecycle.unfair.cfg` | Fairness omitted; must produce an administrative-progress counterexample. |
| `counterexamples/admin-starvation.scenario.json` | That counterexample as canonical Scenario IR. |

The fair configuration assumes:

- convergence-relevant input eventually closes;
- input closure, delivery, restart, resource recovery, freeze, settle, and permitted repair actions are strongly fair
  (if repeatedly enabled, they are eventually scheduled despite recurrent crash/resource interference);
- retained inputs remain available through crash and temporary exhaustion.

The unfair configuration omits those assumptions. Infinite valid self-updates violate eventual input closure; an
enabled administrative action that is never chosen violates fair scheduling. Marmot v1 makes no progress guarantee in
either execution.

## Rust mirror

The Rust/Stateright mirror is
[`crates/cgka-conformance-simulator/src/lifecycle_model.rs`](../../crates/cgka-conformance-simulator/src/lifecycle_model.rs),
tested by
[`crates/cgka-conformance-simulator/tests/lifecycle_model.rs`](../../crates/cgka-conformance-simulator/tests/lifecycle_model.rs).
It is the trace/action-identity bridge, not the authority for infinite-run liveness. Stable ids such as
`model-step-0:self_update` project into canonical Scenario IR, and a test checks that the committed counterexample
compiles to the same action sequence.

## Run

Both recipes need Java. They download the pinned upstream `tla2tools.jar` v1.7.4 into `target/tla/` and verify its
SHA-256 unless `TLA2TOOLS_JAR` points to an existing jar. The jar is never committed.

```sh
# Fair model: must pass.
just tla-liveness

# Unfair model: must fail with a temporal-property violation.
just tla-liveness-counterexample
```

Both run in `just convergence-verification-ci`.

## Device-linking lifecycle

`DeviceLinking.tla` is a separate, bounded model of a new device's first
link and a fresh attempt under the same group id. Its protocol sources are
[device pairing](https://github.com/marmot-protocol/marmot/blob/98171929665451d48c1ca1cf6dd9666a38e6ec0e/features/device-pairing.md)
and [device-group joining and reset](https://github.com/marmot-protocol/marmot/blob/98171929665451d48c1ca1cf6dd9666a38e6ec0e/features/device-group.md).
It does not change their rules. Cryptographic verification is abstracted
here; the pairing role tests and independent derivation vectors retain
ownership of the actual implementation checks.

### Domain and claims

There is one new device, one approver, one intended group/signing key, two
fresh attempts/KeyPackageRefs, one other group/signing key for negative input,
and at most one crash of the new device. Peer confirmations, Adds and emitted
Welcomes are retained per attempt: local retry does not cancel peer work or
erase old traffic. Incoming Welcomes explore both refs, groups, signers and
required-roster flags. Time is abstracted to before/after expiry, not numerical
clock arithmetic. Histories in `admission`, `durableBeforeSend`, `recordedRef`, `retired`
and the peer sets are specification monitors, not new database fields.
`recordedRef` independently remembers the current attempt's completed recording;
`retired` latches withdrawal or expiry. Neither enables an action, and restart
does not clear them. Only a fresh authenticated attempt resets these monitors;
old traffic remains indexed by its original ref.

The fair configuration checks confirmation order, recording the durable wait
before publishing the new confirmation, current-ref/group/signer/roster
admission, atomic expectation consumption, trust following a recorded join,
and Made requiring selected first-Commit evidence. A pre-admission history
monitor checks that no admission happened without a live expectation. An
independent history invariant also forbids admission after this attempt was
withdrawn or expired and binds it to the ref recorded for this attempt.
Controls corrupting restart, withdrawal and expectation recording exercise
that invariant across actions, separately from guard-consistency checks.
`TypeOK` also checks the peer-confirmation/Add/publication provenance chain.

The temporal property is deliberately narrower than eventual successful
linking: a pending Welcome wait eventually resolves. It assumes strongly fair
restart, expiry, withdrawal, orphan-row cleanup, join recording and trust
promotion. This means time eventually crosses the deadline and the required
local writes eventually succeed. It makes no delivery guarantee during an
indefinite outage. The unfair configuration must produce a pending-wait
counterexample; it is not counted as a model defect.

### Implementation correspondence and limits

The correspondence baseline is MDK `2e0c9859c3f344b8f746d903fde9307b9a3b892d`.
Each successful store operation is abstracted as atomic only where the real
store/engine provides that boundary. The two initial writes and the later app
trust promotion are explicitly separate, so a crash can leave an orphan wait
or a joined group the app has not promoted yet.

| Actions | Production owner | Corresponding Rust checks |
| --- | --- | --- |
| `Answer`, `Reveal`, comparison and ordered confirmations | `marmot-pairing` role methods; app `on_new_device_linked` | `pairing_confirmations_go_in_a_fixed_order`; [`pairing_generated_schedules_preserve_confirmation_authority`](https://github.com/marmot-protocol/mdk/blob/5542e9cbdc761aa4a792746806cf9dd9f7ab65b8/crates/marmot-pairing/tests/lifecycle.rs#L32) (landed separately in #3018) |
| `RecordAwaiting`, `RecordExpectation`, `PublishNewConfirm` | `AppClient::record_confirmed_device_link`, then `on_new_device_linked` sends | `a_waiting_row_left_without_its_expectation_is_dropped` |
| Per-attempt `DeliverNewConfirm`, `ConfirmAdd`, `ReleaseWelcome` | app `approve_link`, `link_device_into_group`, `follow_link_publications` | `a_link_commit_that_failed_in_transit_links_once_it_lands`; `a_first_links_undelivered_welcome_is_published_again_until_it_lands` |
| `TryWelcome` | engine `group_lifecycle.rs` expectation validation and transactional consumption | `the_link_welcome_joins_and_consumes_its_expectation`; wrong-leaf, wrong-KeyPackage, reserved-id and expired/withdrawn-Welcome tests in `account_devices/device_group_welcome.rs` |
| `WithdrawExpectation`, `CleanWaitingRow`, `Restart` | app `withdraw_confirmed_device_link`, `end_welcome_waits`, startup reconciliation | `an_expired_or_withdrawn_link_joins_no_welcome`; `a_waiting_row_left_without_its_expectation_is_dropped` |
| `RecordJoin`, `PromoteTrust` | app `settle_held_device_group` writes the join record before changing trust | `a_join_the_app_never_saw_settles`; `a_restart_that_settles_trust_announces_it` |
| `SelectFirstCommit`, `ObserveMade` | app `own_first_commit_landed`, `link_outcome` and `link_verdict` | `a_link_is_made_across_a_restart_by_the_new_devices_first_commit` |
| `RequestReset`, `Reset`, `Retry` | app `reset_device_group_for_repair` and fresh pairing | `a_completed_link_can_disappear_from_the_approvers_selected_roster`; `a_device_whose_link_failed_links_again_into_the_same_device_group` |

These are corresponding cases and production-owner checks, not a mechanically
checked refinement theorem. The model does not run Rust. The separately landed generated role
property named above covers only the in-memory exchange; app/engine tests own persistence
and MLS admission. An orderly app reopen is not a mid-write process crash.

`TrustRequiresJoined` and `MadeRequiresFirstCommit` check consistency with
modeled guards. They do not independently establish freshness across attempts:
current-attempt join and selection evidence is assumed. The native detector
and reset behavior remain outside this model.

The model retains a pending cancel across restart as an overapproximation.
Production's cancel flag is volatile: a crash before withdrawal finishes can
leave the expectation usable, so its Welcome may still join or the wait may
expire. Pending-wait progress relies on fair expiry and cleanup, not durable
replay of cancellation.

Crypto-valid code comparison and matching-session authentication are assumed.
`ConfirmAdd` abstracts successful ordinary roster admission, not a proof of
its capacity/duplicate/removal checks. `Reset` means an already-admitted
explicit local reset: its busy, live-pairing, native-work and Move guards
remain assumptions owned by runtime tests. `SelectFirstCommit` abstracts the
real stable, quiet, selected matching-tag evidence; it does not verify the
detector. The abstraction can admit schedules those guards exclude, so its
reachability witnesses alone are not executable Rust traces. Full Move,
failed-link undo, later branch loss, ordinary chat admission/data/credentials,
physical storage, clock rollback and the cryptographic implementation are
outside this model. The native reset regression owns ordinary-data preservation.
This model tracks device-group admission only. After a wait ends, an ordinary
roster-less invitation can take the same id under normal chat admission; the
model does not guarantee that every later same-id pairing can start or finish.
The fresh-attempt witness establishes one reachable successful path.

### Reproduce the linking checks

The existing `just tla-liveness` recipe runs the generic fair model and this
linking gate. Its existing CI invocation therefore checks both models. To run
only the linking checks, use the existing pinned TLC setup (`just _tla-tools`)
and then:

```sh
python3 formal/liveness/verify_device_linking.py --out target/device-linking
```

It requires the fair result, the unfair temporal counterexample, eleven named
model-mutant failures (order, durable-before-send, signer, fresh ref, roster,
withdrawal, restart re-arming, restart clearing expiry, withdrawal retaining an
expectation, stale-ref recording, blocked cleanup), and four expected-failure reachability probes (join, fresh
same-group join, partial-record crash, old peer work surviving local retry).
Every run uses a fresh output directory and preserves source/config hashes,
commands, state counts, exit status and logs, including incomplete runs.
The per-case ceiling is 300 seconds; changing that budget changes no model
action, property, fairness premise or input bound. A timeout, missing named result or checker
exception fails the gate. The reachability probes and mutants are properties
of the abstract model, not production Rust mutation evidence.

The gate selects the pinned jar's built-in `MemFPSet`, one worker and a 2 GiB
heap for this small model. The default disk backend hit division by zero in
`AbstractChecker.reportSuccess` while reporting fingerprint-distance statistics
after checking the graph. Selecting the supported in-memory backend changes
no action, property, bound or tool version; failed disk-backend runs remain
failed evidence. This backend also stores fingerprints: TLC/tool correctness
and its reported collision risk remain trusted limitations.
