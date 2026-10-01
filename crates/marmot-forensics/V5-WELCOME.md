# v5 Welcome contract

`marmot_forensics::v5` is the active opt-in audit format. When app audit logging
is enabled, `marmot-app` opens `JsonlRecorder::open_v5_with_account_ref` and
writes `<account_dir>/audit-<engine_id>-v5.jsonl`. The Welcome events below are
recorded on the live app paths: founding preparation, receipt, peel, engine join,
app checkpoints and group baselines in `marmot-app`'s `client/audit_v5_probe.rs`,
and publication start/finish/not-started at the `marmot-account` runtime owner.
v5 network delivery uses the dedicated OTLP sender, which hosts
configure with the UniFFI/C `set_audit_otlp_config_v5` and drive with
`post_audit_log_tracker_update_v5`.

`AUDIT_LOG_SCHEMA_VERSION` still names the frozen v4 contract. Historical v4
files stay readable, and the whole-file Goggles upload accepts only v4. See
[audit-logging.md](../../docs/marmot-architecture/audit-logging.md#v5-recording-and-delivery)
for recording and delivery.

## Validated boundary

Use `Record::from_json` for one original UTF-8 JSON body, excluding its JSONL
newline, or `Record::new(RecordFields)` for a new typed candidate. `Record` is
immutable after validation; `to_json` produces a compact body for newly created
records. Keep the original input bytes when forwarding/replaying existing
records: parsing and re-encoding is not byte preservation.

`RecordFields` and event structs are public candidate DTOs. Their ordinary serde
shape decoding alone is **not** semantic validation; go through `Record` before
accepting or emitting a record. Nullable fields are required and explicitly null
when unknown. The validated body boundary rejects unknown/duplicate keys,
invalid UTF-8, non-integer numeric tokens, out-of-range/canonically malformed
numeric strings, multiline bodies and bodies exceeding 65,535 bytes.

The standalone draft-2020-12 JSON schema checks structure, scalar ranges and
expressible conditional rules. Consumers must also apply the documented Rust
semantic rules: sorted reference lists, uniqueness by endpoint/member identity,
list/count agreement and acknowledgment-policy consistency. Standard JSON Schema
cannot compare sibling counts. Duplicate-key/byte/framing checks require the raw
body, before a generic JSON parser discards duplicate keys. JSON Schema's integer
type also cannot distinguish the lexical token `1` from `1.0`; this profile does.

This contract validates records, not evidence authenticity, cross-record sequence
continuity, actual transactions, group convergence or complete acquisition. It
cannot prove that a producer used a real clock, a validated event or consent.

## Event boundaries

- `welcome_prepared`: founding versus actual commit-backed invitation; selected
  public KeyPackage, outer artifact, construction and authoritative retention.
- `welcome_publish_started`, `welcome_publish_finished`,
  `welcome_publish_not_started`: actual attempt, bounded endpoint results,
  cumulative versus current-attempt acknowledgments and retained obligation state.
- `welcome_observed`, `welcome_unwrapped`: outer observation separately from
  validated inner rumor/KeyPackage references. Local replay is not fresh arrival.
- `welcome_join_finished`: engine transaction outcome, distinct from app state.
- `app_group_update_finished`: coarse computation/checkpoint and pending versus
  accepted invitation. No projection-field history or UI visibility claim.
- `group_baseline`: local epoch and bounded membership/admin status, with explicit
  partial/failed capture. No keys, MLS state, payloads or invented global state.

For `welcome_unwrapped`, `validated` requires both inner references and no
reason. `rejected` establishes a classified wrong-target or invalid transport
input and permits only `wrong_recipient`, `invalid_signature`, or
`invalid_encoding`. `failed` means validation did not complete and the source
is not established as invalid input; it permits only `unwrap_failed`,
`internal_failed`, or `unclassified`. Failed/rejected records have no inner
references. The current NIP-59 extraction boundary coalesces its SDK errors to
`unwrap_failed`; that category cannot diagnose bad keys, missing local MLS
KeyPackage material, malformed encrypted data or a local defect. The unsigned
rumor's optional claimed ID is not authenticated by the pinned SDK; producers
derive its reference from the canonical ID computed over authenticated fields.

Publication endpoint classifications follow the Nostr publish boundary: an
acknowledged result has no failure kind and may carry only the `duplicate`
category (already stored). Failed `not_exposed` has no category;
`possibly_exposed` allows null or `error`; `retryable_unavailable` allows null,
`rate-limited` or `auth-required`; `terminal_rejected` requires `pow`, `blocked`,
`invalid`, `unsupported` or `restricted`. A duplicate acknowledgment is not a
failed publication. These are observed outcomes, not a new retry policy.

Per-record comparisons cannot check a finished attempt against a missing start
row. A reader must preserve independent facts, expose missing evidence
and conflicts, and never infer delivery failure merely from absent recipient rows.

## Encodings, references and bounds

Source/session/local IDs are 128-bit lowercase hex. Shared diagnostic references
are 256-bit lowercase hex, with distinct Rust types for group, member, Nostr event,
engine message and endpoint domains. All u64/i64 values are canonical decimal
strings so agent clients preserve precision. Counts are u32 JSON integers; sequence
must be positive. Durations are local monotonic microseconds; clocks across
sources/sessions are not comparable.

Reference derivation is SHA-256 over:

```text
"marmot-audit-ref/v5\0" || UTF8(kind) || "\0" || u32be(input_length) || input
```

Kinds: `group`, `member`, `nostr_event`, `engine_message`, `endpoint`. These are
pseudonyms, not anonymization or authentication. The same known identifier can
be correlated across sources. Group input is the variable-length MLS group ID;
it is not a 32-byte transport route ID. KeyPackage references are public event
references, never hashes of key material. Never use plaintext or ciphertext as
reference input.

V5 is a new-pipeline format, not mixed-version member correlation. Its member
references intentionally differ from v4; do not join the two by equality or infer
an identity from unrelated records. Historical v4 evidence stays with existing
tooling. New audit sessions write v5 files; old v4 records are not converted, and
queued v4 data is not discarded.

The forensic crate deliberately does not depend on a URL parser or transport SDK.
`EndpointRef::from_normalized_url` requires owner-normalized input. For Nostr this
is `RelayUrl::parse` → `url::Url` → `to_string`, exactly as relay telemetry uses.
The adapter's test checks the shared endpoint fixtures against that real parser;
forensics tests verify the hashes independently. Path/query distinctions remain.
The helper does not normalize or authenticate supplied strings itself.

Candidates allow at most 16 target/result endpoints and 64 baseline members.
Lists are reference-sorted and unique. Omitted detail requires incomplete status;
complete lists require exact counts. Counts may exceed captured detail. Complete
baselines require known admin flags; failed baselines cannot invent epoch/roster.
Only the producer can decide which known evidence to omit and record limitations;
this library rejects overlarge candidates instead of silently trimming them.

The app recorder uses the account-device's persistent audit engine reference as
the source and derives a fresh session at each recorder open, unchanged across
segment rotation. `recording_session_started` and `recording_session_stopped`
bracket a writer session (see [README.md](README.md#opt-in-v5-recording)).
Copies/restores do not establish physical device uniqueness. Existing records
preserve identity/bytes across delivery replay. This module validates those
identities; the app recorder allocates and persists them.

## Fixtures and verification

`tests/fixtures/v5/valid.json` supplies synthetic contract examples covering all
nine event variants and success/failure/deferred/partial outcomes. It is a catalog,
not one chronological execution trace or proof of real emission coverage.
`references.json` and `endpoints.json` are portable reference vectors.

Tests mutate every object to remove each required field and inject unknown fields,
exercise contradictory successes, null/absent distinctions, precision boundaries,
duplicate discriminators, list caps and sensitive-value-safe errors. Existing v4
recorder/delivery tests must still pass. Golden hashes were independently computed
from the specified byte framing, not copied from the Rust implementation.

```sh
cargo test -p marmot-forensics
cargo test -p transport-nostr-adapter --lib audit_v5_endpoint_vectors_match_owner_normalization
```

A contract fixture cannot establish real Welcome coverage or claim v5 bandwidth;
the [app Welcome tests](../marmot-app/tests/audit-v5-welcome-probe.md) exercise
the emitted evidence. v5 is never uploaded to the strict v4 Goggles receiver.
