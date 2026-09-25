# Controlled v5 recipient Welcome probe

This is the first **partial** real-recording experiment after the v5 contract
(PR #2040), tracked by #2043. It observes actual `AppClient` execution with two
synthetic accounts, real NIP-59/MLS Welcomes, SQLCipher storage, and a localhost
Nostr `MockRelay`. It does not replace v4 recording.

Run the bounded scenarios (also included in ordinary library tests):

```sh
cargo test -p marmot-app --lib audit_v5_probe -- --nocapture --test-threads=1
```

The entire probe, its selection field and fault injection are `#[cfg(test)]`.
Only these unit tests select it. There is no feature flag, public API, recorder
setting, file destination, uploader, worker, binding or production activation.
The existing v4 recorder runs alongside the selected probe in the scenarios;
its output is checked to remain v4. Probe records stay in bounded memory.

## Evidence boundaries

| Record | Actual observation | What it does not establish |
| --- | --- | --- |
| `welcome_observed` | The app admits a Welcome envelope to its ingest path, after checking its NIP-01 event hash for reference derivation. | Signature/unwrap validity, engine join, endpoint provenance, live versus history acquisition. Acquisition is explicitly `unknown`. |
| `app_group_update_finished`, `welcome_join` | A dirty group projection from an observed engine Welcome event reaches the account checkpoint. | The entire engine transaction history, every projection row, UI rendering or notification delivery. |
| `app_group_update_finished`, `invite_confirmation` | Explicit acceptance prepares a changed app row and returns from its checkpoint. | Recipient notification or screen visibility. |

A committed pending invitation and a committed accepted invitation are distinct
rows, linked to the same outer event reference with separate local update IDs.
Generic checkpoint errors use `checkpoint: unknown` and `invite_state: unknown`:
an error alone is insufficient to assert that no commit occurred. Only the
explicit fault placed before all checkpoint writes produces
`failed_before_commit`. A retained-client retry gets a new update ID. The catch-up drain intentionally
saves changed group rows before acknowledging its engine outbox events; this
probe does not confuse those two commits.

The projection path supplies the cause explicitly. The no-delivery drain uses
`retained_event_replay`; missing receive evidence never selects that cause.
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
   the receive and checkpoint records by outer reference.
2. The engine joins, then a unit-test-only fault stops the app checkpoint before
   its first write. The MLS roster exists while the persisted app invitation
   does not. Evidence records failure/unknown invitation, followed by a distinct
   successful pending checkpoint after retry.
3. Sender publication completes its retained delivery obligation, but the
   recipient app is not drained. It has neither an engine group nor a persisted
   invitation, and emits no recipient records. This withholds app admission,
   **not** relay delivery into the transport queue; it does not prove network loss.
4. Collector bounds and a generic uncertain checkpoint result are checked
   independently of the successful product scenario.

A local run on 2026-09-25 measured 2,072 compact body bytes, 2,075 JSONL bytes
and a 742-byte largest body for this subset (timing values vary between runs).

The successful scenario emits three rows: one receive, one pending checkpoint,
one accepted checkpoint. Its command prints compact JSON body bytes, JSONL bytes
(including one newline per row), and largest body. The 4 KiB aggregate assertion
is only a gross-regression guard for this three-row subset. No v5 HTTP request is
sent; these are **not upload bytes**, a full Welcome budget, or a device/day
estimate. Source/session identifiers have fixed encoded width; timing values can
change the byte count between runs.

Sender preparation/publication, validated unwrap/inner KeyPackage references,
engine disposition records, roster baselines, process-reopen capture, rejected
inputs, and reader missing-source conclusions remain separate slices. In
particular this does not claim complete W01/W03/W04/W08 acceptance or resolve
#2043. Do not compare these three rows with the complete measured v4 Welcome
lifecycle and claim a bandwidth reduction.

Recovery instrumentation, the Rust investigation API, server acceptance of v5,
client rollout and production cutover remain outside this experiment.
