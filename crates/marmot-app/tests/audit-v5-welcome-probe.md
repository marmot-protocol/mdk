# v5 Welcome evidence probe

`src/client/audit_v5_probe.rs` records v5 Welcome evidence from actual
`AppClient` execution whenever app audit logging is enabled. It started as a
test-only experiment after the v5 contract (PR #2040, tracked by #2043) and has
been live since PR #2054: new app audit sessions write v5, not v4. The tests
below drive that path with synthetic accounts, real NIP-59/MLS Welcomes,
SQLCipher storage, and a localhost Nostr `MockRelay`.

Run the bounded scenarios (also included in ordinary library tests):

```sh
cargo test -p marmot-app --lib audit_v5_probe -- --nocapture --test-threads=1
```

Every session wraps its Nostr inbox sealer in the delegating `ProbeSealer`, and a
session with an enabled v5 recorder installs `WelcomeProbe::live`. The live probe
queues at most 128 pending events and flushes them to the installed recorder,
which assigns source, session and sequence alongside the engine audit rows and
validates each record. The audit-enable setting is the only switch; delivery uses
the v5 OTLP sender (see `docs/marmot-architecture/audit-logging.md`). Per-label
peel-slot selection, the checkpoint fault injection and the in-memory capture
mode stay `#[cfg(test)]`. The scenarios check that every row in the accounts'
audit files carries the v5 schema version.

Authenticated recovery and pairing controls produce neither Welcome evidence
nor Welcome product analytics. A dismissed or duplicate delivery that never
reaches the peeler also produces no Welcome evidence.

## Evidence boundaries

| Record | Actual observation | What it does not establish |
| --- | --- | --- |
| `welcome_prepared` | A create returns after the engine atomically retained the canonical group and exact outbound Welcome as `Sent`. The account runtime reads the Welcome's stored row, which names the transport event of the exact KeyPackage the engine wrapped it for, on every create path. | A relay send, ACK, recipient observation, engine join, or app/UI availability. Failure before the returned artifact has no terminal row in this subset. |
| `welcome_prepared`, `invite` | The account runtime holds a Welcome the engine staged with an Add commit: a host's invite when its commit is accepted, a queued invite when the drain publishes its commit. The row comes from the Welcome's stored row, which names the commit (`basis`) and the transport event of the exact KeyPackage the engine wrapped it for; a Welcome whose KeyPackage had no transport source has no row. | That the commit confirms, so the Welcome becomes owed; a send, ACK or recipient observation. A process that restarts while the commit is pending may record the row again. |
| `welcome_event_size` | The size class of the Welcome's outer event as the transport sends it, for every invite and founding Welcome. | Which relays accept that size. |
| `welcome_publish_started`, `welcome_publish_finished` | Each pass over a Nostr-wrapped retained Welcome's relays: the first send, a startup retry, an explicit redelivery and maintenance's retry of its stored fanout, including retries after the Welcome met its policy. The started row is written when the transport is called, after the last hold check, with a fresh random attempt id; a pass a hold stops writes neither row. `route_source` is `resolved_inbox` for a first pass and `retained_target` for a retry. The finished row's `accepted_total_count` and a `met` policy come from the stored fanout even when this pass's endpoint results are incomplete; The attempt that meets the policy marks the Welcome delivered before its finished row, so `retained_state` is the Welcome's delivery status as the pass left it: `completed` once delivered, `pending` while owed and unmet, otherwise `unknown`, including a met policy whose delivered mark failed (the row stays owed) and a Welcome that expired or lost its commit during the pass. When the pass's bookkeeping cannot be saved, or its results are dropped because the host deleted the chat while it ran, the row still carries the relays' answers, with no `accepted_total_count` and `unknown` policy and retention. | Recipient arrival. An acknowledgement is a relay's answer only. |
| `welcome_withdrawn` | The Welcome will never be published. A size refusal's rollback reports each Welcome it retired (its row went from `Sent` to `Failed` in that rollback): `commit_too_large` for all of them when the commit fits no group relay, with the commit's size class; when Welcomes fit no inbox relay, `welcome_too_large` with its own size class for each the size check refused and `withdrawn` for the rest. Otherwise the runtime's Welcome watcher reports one it watched settling undelivered: `withdrawn` (by the sender, or with its commit rolled back), `commit_superseded` (its commit lost for good, before or after convergence retires the Welcome) or `expired` (past a device link's deadline, once no pass started before it is still out and no saved relay acceptance can mark it delivered). | A Welcome that settles while this process does not watch it, as across a restart, has no row: one read from the store already settled is not watched. A commit displaced but still reconsiderable holds its Welcome; that is not a withdrawal. |
| `welcome_observed` | After checking the envelope's NIP-01 event hash, the app's normal peeler returns a Welcome or a peel failure rather than an authenticated private control. The row is emitted with the matching unwrap result. | Signature/unwrap validity, engine join, endpoint provenance, live versus history acquisition. Acquisition is explicitly `unknown`. Deliveries rejected or deduplicated before peeling have no observation row. |
| `welcome_unwrapped` | The same engine-invoked Nostr peeler either validates the authenticated rumor and strict inner `e` KeyPackage event ID, or returns a typed transport error. The row shares the receive ID and outer reference with `welcome_observed`. | MLS KeyPackage secret availability, engine join, app checkpoint, or sender publication. SDK NIP-59 extraction errors are coarsely `failed/unwrap_failed`, not a specific bad-key diagnosis. |
| `welcome_join_finished`, `joined` | This exact observed Welcome returns `Processed` with its own `GroupJoined` event, which the engine journaled in the successful join transaction. The row uses the group's durable local-copy install epoch, written by that transaction; it precedes any fallible app checkpoint. | App persistence or acceptance, UI display, recipient history completeness, or another delivery's join. This subset omits other join dispositions and ambiguous initial/replacement cases. |
| `app_group_update_finished`, `welcome_join` | A dirty group projection from an observed engine Welcome event reaches the account checkpoint. | The entire engine transaction history, every projection row, UI rendering or notification delivery. |
| `app_group_update_finished`, `invite_confirmation` | Explicit acceptance prepares a changed app row and returns from its checkpoint. | Recipient notification or screen visibility. |

A committed pending invitation and a committed accepted invitation are distinct
rows, linked to the same outer event reference with separate local update IDs.
The sender's Welcome rows come from the account runtime, which reads each
Welcome's stored row, with each Welcome's operation ID derived from its outer
event. KeyPackage source IDs come from the Commit-purpose relay fetch: the
directory verifies each event signature, kind and author, and no cached package
is used as a fallback; the engine stores the source ID of the exact KeyPackage
it wraps each Welcome for. The probe records the new group's baseline after the
first post-canonical idempotency binding, before repairable app indexing and
publication. The sender and recipient use distinct synthetic source/session
identities.
Each session installs one bounded peel slot when it opens; tests can pre-select
the slot for a labeled client. The app arms that slot after policy prechecks and
just before engine ingress, consumes the peeler result immediately afterward, and
records through the existing probe's source, session and sequence. The production trait method returns the same peeled
message and errors as before; the concrete peeler also has a narrow provenance
return for the wrapper. The SDK verifies the signed gift wrap and seal but
does not verify an optional ID on its unsigned rumor, so the probe references the
rumor's computed NIP-01 ID from authenticated fields, never that optional claim.
The join row uses the same per-delivery receive ID and exact outer ID, requires
`Processed` plus a unique returned `GroupJoined` whose `via_welcome` matches
that outer ID, and reads the current-profile group under the same AppClient
ingest. The engine writes `local_copy_install_epoch` and the durable
`GroupJoined` event in one transaction. Unlike the current group epoch, this
install anchor remains the joined epoch after buffered group messages advance
the copy. The initial-join guard requires `join_epoch` to equal that anchor
and be nonzero. Zero is the stored unknown-bound sentinel, and a replacement
also resets `join_epoch` to zero. A replacement/explicit consent,
duplicate delivery, or older event drained alongside unrelated input cannot
produce another join row. Account effect-publication or buffered-replay errors
after the engine transaction can leave a real commit without a row; absence
does not imply rollback. No new engine/account observer or replay ledger is used.
Generic checkpoint errors use `checkpoint: unknown` and `invite_state: unknown`:
an error alone is insufficient to assert that no commit occurred. Only the
explicit fault placed before all checkpoint writes produces
`failed_before_commit`. A retained-client retry gets a new update ID. The catch-up drain intentionally
saves changed group rows before acknowledging its engine outbox events; this
probe does not confuse those two commits.

The projection path supplies the cause explicitly. The no-delivery drain uses
`retained_event_replay` only when the group projection actually changes; a no-op
replay leaves no origin for a later unrelated save. Missing receive evidence
never selects that cause. Acceptance uses the same checkpoint hook, temporarily
replacing any pending Welcome cause. Failed acceptance restores the prior origin
alongside the app candidate rollback, so a single save emits one result.
The current real failure scenario covers retry in the same client, not a
process crash/reopen. App-open capture and durable probe identities are absent.
An aborted or failed projection before checkpoint selection can leave no
completion row; that absence is not success. This is not complete failure-event
coverage.

The in-memory test capture validates every row through `v5::Record`, bounds
captured rows to 128 and bodies to 256 KiB, and bounds pending projection origins
to 64. Validation failures and overflow have separate counters, which the
scenarios require to be zero. Its source/session/build values are explicit
synthetic test metadata; they do not claim real installation identity or build
provenance. A live recorder supplies its own envelope. Body identities and
facts are taken from the running scenario, not converted from v4 records.

## Scenarios and measurements

1. Actual successful Welcome: the recipient joins; the app checkpoints a pending
   invitation; explicit acceptance checkpoints accepted state. Independent
   product assertions inspect persisted app rows, member count, matching epochs,
   and a subsequent delivered plaintext message. The audit assertions correlate
   the receive, committed join, and checkpoint records by outer reference.
2. The engine joins, then a unit-test-only fault stops the app checkpoint before
   its first write. The MLS roster exists while the persisted app invitation
   does not. Evidence records failure/unknown invitation, followed by a distinct
   successful pending checkpoint after retry.
3. Replay an actual joined event after acceptance, then archive the group. The
   replay changes no group row and must not label that unrelated checkpoint.
4. Seed a pending probe origin alongside the real persisted invitation to model
   an uncertain earlier save, then fail and retry actual acceptance. Each attempt
   emits exactly one result with the acceptance cause; failure restores the prior
   origin, success clears it. This seeds probe state, not a real crash scenario.
5. A hash-valid unsigned gift wrap reaches the app ingress and is explicitly
   rejected at the peeler, with no inner references, group join or app checkpoint.
   This is a controlled malformed input, not a diagnosis of real incidents.
6. A separate peeler-wrapper test uses a wrong local NIP-59 key to check the
   coarse `failed/unwrap_failed` mapping and null inner references. It does not
   claim app ingress or a real incident cause.
7. Collector bounds and a generic uncertain checkpoint result are checked
   independently of the successful product scenario.
8. The sender pauses after canonical creation, before fanout, and compares the
   emitted preparation row with the exact engine-retained outbound Welcome.
   Two actual selected recipients yield two distinct retained artifacts and sender rows;
   reordering the artifacts in a probe check preserves recipient-to-KeyPackage
   links, while a missing selection emits no partial success rows.
9. Direct redelivery of the exact retained Welcome keeps one joined group and
   one join row. A separate bounded mapping check raises the current epoch of
   an actual joined group record and confirms the row still names its install
   epoch; resetting its first-membership anchor suppresses an ambiguous
   replacement row. This is not a claim that the test caused a later network
   Commit to replay in the same ingress call.

The probe discards its pending operation token when runtime preparation returns
an error, but this subset has no real post-selection fault injection and does
not establish behavior for construction/retention failure classes. It also
does not exercise a publication retry or reconciliation replay; those paths
are separate from the creation hook.

The measurements below are historical: they were taken on 2026-09-25 against
the test-only subset, before live recording added publication, baseline and
operational rows. Rerun the command above for current counts.

A local run on 2026-09-25 of the earlier three-row subset measured 2,072 compact
body bytes, 2,075 JSONL bytes and a 742-byte largest body. With successful unwrap
added, the same success path measured four rows, 2,836 body bytes, 2,840 JSONL
bytes and a 764-byte largest body. Two invalid-signature runs each measured two
rows: 1,239–1,240 body bytes, 1,241–1,242 JSONL bytes, and a 649–650-byte
largest body. The recorded `elapsed_us` can change the decimal width. In the
success run, `welcome_observed` contributed 1/592 B,
`welcome_unwrapped` 1/764 B, and `app_group_update_finished` 2/1,480 B;
rejection contributed `welcome_observed` 1/590 B and `welcome_unwrapped`
1/649–650 B. A sender-side founding preparation added one
`welcome_prepared` row of 915 body bytes/916 JSONL bytes in the one-recipient
run. Two recipients produced two such rows, 1,832 body bytes/1,834 JSONL bytes,
with a 916-byte largest body. These are local compact JSON bytes by kind and
account-device source; no HTTP request or full-v5 budget is measured.

With `welcome_join_finished` added, a 2026-09-25 focused run measured five
recipient rows: 3,525 body bytes, 3,530 JSONL bytes, largest body 764 bytes.
The join row contributed 689 body bytes. The sender still emitted one
`welcome_prepared` row of 915 body/916 JSONL bytes. These counts are from the
local selected-probe success scenario; they are not transport or upload bytes.

In that historical subset, the successful scenario emitted one sender row and
five recipient rows: one receive, one unwrap, one committed join, one pending
checkpoint and one accepted checkpoint. The command prints per-kind counts/body
bytes, total compact JSON body bytes, JSONL bytes (including one newline per
row), and largest body. The test's aggregate byte assertion is only a gross
regression guard for the captured recipient subset. The scenarios send no v5
HTTP request; these are **not upload bytes**, a full Welcome budget, or a
device/day estimate. Source/session identifiers have fixed encoded width; timing values can
change the byte count between runs.

Live recording now also writes Welcome publication rows (from the
`marmot-session` runtime owner) and bounded group baselines. Non-success engine
join dispositions, crash-and-reopen scenarios, broad rejected-input
classification, and reader missing-source conclusions are still not covered here. In
particular this does not claim complete W01/W03/W04/W08 acceptance or resolve
#2043. Do not compare the historical five-row subset with the complete measured
v4 Welcome lifecycle and claim a bandwidth reduction.

Recovery rows have their own owner seams (`src/client/audit_recovery.rs`); the
Rust investigation API is outside this probe.
