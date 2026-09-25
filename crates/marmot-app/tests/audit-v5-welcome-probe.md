# Controlled v5 Welcome probe

This is a **partial** real-recording experiment after the v5 contract
(PR #2040), tracked by #2043. It observes actual `AppClient` execution with two
synthetic accounts, real NIP-59/MLS Welcomes, SQLCipher storage, and a localhost
Nostr `MockRelay`. It does not replace v4 recording.

Run the bounded scenarios (also included in ordinary library tests):

```sh
cargo test -p marmot-app --lib audit_v5_probe -- --nocapture --test-threads=1
```

The app probe, its selection field, delegating peeler and fault injection are `#[cfg(test)]`.
Only these unit tests select it. There is no feature flag, public API, recorder
setting, file destination, uploader, worker, binding or production activation.
The existing v4 recorder runs alongside the selected probe in the scenarios;
its output is checked to remain v4. Probe records stay in bounded memory.

## Evidence boundaries

| Record | Actual observation | What it does not establish |
| --- | --- | --- |
| `welcome_prepared` | On the sender's current-profile founding path, the runtime preparation call returns after the engine atomically retained the canonical group and exact outbound Welcome as `Sent`. The test-only probe matches the returned artifact to the selected, relay-validated public KeyPackage event by recipient identity and checks the outer event hash. | A relay send, ACK, recipient observation, engine join, or app/UI availability. Failure before the returned artifact has no terminal row in this subset. |
| `welcome_observed` | The app admits a Welcome envelope to its ingest path, after checking its NIP-01 event hash for reference derivation. | Signature/unwrap validity, engine join, endpoint provenance, live versus history acquisition. Acquisition is explicitly `unknown`. |
| `welcome_unwrapped` | The same engine-invoked Nostr peeler either validates the authenticated rumor and strict inner `e` KeyPackage event ID, or returns a typed transport error. The row shares the receive ID and outer reference with `welcome_observed`. | MLS KeyPackage secret availability, engine join, app checkpoint, or sender publication. SDK NIP-59 extraction errors are coarsely `failed/unwrap_failed`, not a specific bad-key diagnosis. |
| `welcome_join_finished`, `joined` | This exact observed Welcome returns `Processed` with its own `GroupJoined` event, which the engine journaled in the successful join transaction. The row uses the group's durable local-copy install epoch, written by that transaction; it precedes any fallible app checkpoint. | App persistence or acceptance, UI display, recipient history completeness, or another delivery's join. This subset omits other join dispositions and ambiguous initial/replacement cases. |
| `app_group_update_finished`, `welcome_join` | A dirty group projection from an observed engine Welcome event reaches the account checkpoint. | The entire engine transaction history, every projection row, UI rendering or notification delivery. |
| `app_group_update_finished`, `invite_confirmation` | Explicit acceptance prepares a changed app row and returns from its checkpoint. | Recipient notification or screen visibility. |

A committed pending invitation and a committed accepted invitation are distinct
rows, linked to the same outer event reference with separate local update IDs.
The sender probe allocates one operation ID per selected founding recipient before
runtime preparation and emits only after the returned `FoundingGroupCreated`
artifact. KeyPackage source IDs come from the Commit-purpose relay fetch: the
directory verifies each event signature, kind and author, and no cached package
is used as a fallback. The probe matches Welcome recipients to those selected
identities, rejects duplicate/missing matches, and does not decode an inner
rumor or repeat MLS construction. It runs after the first post-canonical
idempotency binding, before repairable app indexing and publication. The
sender and recipient use distinct synthetic source/session identities.
The app test installs one bounded per-client peel slot before opening the session.
It arms that slot after policy prechecks and just before engine ingress, consumes
the peeler result immediately afterward, and records through the existing probe's
source, session and sequence. The production trait method returns the same peeled
message and errors as before; the concrete peeler also has a narrow provenance
return for the test wrapper. The SDK verifies the signed gift wrap and seal but
does not verify an optional ID on its unsigned rumor, so the probe references the
rumor's computed NIP-01 ID from authenticated fields, never that optional claim.
The join row uses the same per-delivery receive ID and exact outer ID, requires
`Processed` plus a unique returned `GroupJoined` whose `via_welcome` matches
that outer ID, and reads the current-profile group under the same AppClient
ingest. The engine writes `local_copy_install_epoch` and the durable
`GroupJoined` event in one transaction. Unlike the current group epoch, this
install anchor remains the joined epoch after buffered group messages advance
the copy. The initial-join guard requires `join_epoch` to equal that anchor
and be nonzero; an epoch-zero first join is deliberately omitted because a
replacement also resets `join_epoch` to zero. A replacement/explicit consent,
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
coverage or a production recorder design.

The collector validates every row through `v5::Record`, bounds captured rows to
128 and bodies to 256 KiB, and bounds pending projection origins to 64. Validation
failures and overflow have separate counters, which the scenarios require to be
zero. Source/session/build values are explicit synthetic test metadata; they do
not claim real installation identity or build provenance. Body identities and
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

The successful scenario emits one sender row and five recipient rows: one
receive, one unwrap, one committed join, one pending checkpoint and one accepted checkpoint. Its
command prints per-kind counts/body
bytes, total compact JSON body bytes, JSONL bytes (including one newline per
row), and largest body. The 6.5 KiB aggregate assertion is only a gross
regression guard for the five-row recipient subset. No v5 HTTP request is
sent; these are **not upload bytes**, a full Welcome budget, or a device/day
estimate. Source/session identifiers have fixed encoded width; timing values can
change the byte count between runs.

Sender publication, non-success engine disposition records, roster baselines,
process-reopen capture, broad rejected-input classification, and reader
missing-source conclusions remain separate slices. In
particular this does not claim complete W01/W03/W04/W08 acceptance or resolve
#2043. Do not compare these five rows with the complete measured v4 Welcome
lifecycle and claim a bandwidth reduction.

Recovery instrumentation, the Rust investigation API, server acceptance of v5,
client rollout and production cutover remain outside this experiment.
