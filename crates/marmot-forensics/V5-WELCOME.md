# Inactive v5 Welcome contract

`marmot_forensics::v5` is a data-only foundation for a new investigation format.
It does not change `AUDIT_LOG_SCHEMA_VERSION`, `AuditEvent`, `JsonlRecorder`, local
cursor handling, the OTLP sender, receiver acceptance or current Goggles uploads.
Those remain v4. There is no v5 recorder, source-ID persistence, emitter, analyzer,
network call, runtime timer, migration or activation in this change.

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

Per-record comparisons cannot check a finished attempt against a missing start
row. The future reader must preserve independent facts, expose missing evidence
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

Source/session generation and consent lifecycle are future recorder work. Proposed
rule: source per account's continuous consent period; fresh session at each recorder
open, unchanged across segment rotation. Copies/restores do not establish physical
device uniqueness. Existing records preserve identity/bytes across delivery replay.
This module does not allocate, persist, rotate or delete any such identity.

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

Next slices: instrument real sender and recipient boundaries under explicit test
selection, then evaluate actual emitted evidence and rerun volume measurements.
A contract fixture cannot establish real Welcome coverage or claim v5 bandwidth.
No upload of v5 to the existing strict v4 receiver is enabled by this foundation.
