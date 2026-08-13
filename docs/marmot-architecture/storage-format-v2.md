---
title: "Storage Format v2"
created: 2026-08-13
updated: 2026-08-13
tags: [marmot, storage, sqlite, migration, encoding]
status: current
---

# Storage Format v2

This document owns MDK's local SQLCipher storage-format contract. It is not a
Marmot wire format and does not constrain other Marmot implementations. The
canonical protocol specifies which state must be reproducible; this document
specifies how `storage-sqlite` currently persists that state.

## Versioning model

There is no database-wide `format_version` independent of schema migrations.
That value would be ambiguous while rows and opaque artifacts intentionally
coexist at different versions.

- `cgka_schema_migrations` is the database compatibility gate. Every writer
  change that an older binary cannot safely read lands with a numbered
  migration. `reject_unknown_future_migrations` makes an older binary refuse
  the database before it reads or writes application tables.
- Every independently decoded opaque artifact has its own version. A binary
  envelope starts with an artifact-specific magic value and a fixed-width
  network-order version. Untagged legacy JSON is recognized only at the
  artifact's documented v1 fallback boundary.
- Readers accept supported old versions. Writers emit only the newest version.
  Unsupported or malformed versions fail closed; readers never guess from a
  partially decoded value.
- Golden byte fixtures pin each binary artifact. Schema migration tests pin
  old-row reads and downgrade refusal.

## Binary grammar

MDK-local binary artifacts reuse the Marmot binary grammar for consistency:

- fields appear in the documented order;
- fixed-width integers use network byte order;
- variable byte strings use the shortest canonical QUIC-varint byte-length
  prefix;
- list fields are one QUIC-length-prefixed byte vector containing concatenated
  item encodings;
- option fields use a one-byte discriminator (`0` absent, `1` present);
- decoders reject non-minimal length prefixes, unknown discriminants, truncated
  values, invalid UTF-8 for string fields, and trailing bytes.

Using the same grammar is an MDK implementation convention. It does not make
these storage artifacts Marmot protocol values.

## `cgka_messages` authority model

Migration `0047_normalized_message_records` supports two row formats:

| Column | Format 1 | Format 2 |
| --- | --- | --- |
| `id`, `group_id`, `epoch`, `state` | indexed copy; legacy `record` remains the decoded authority | authoritative |
| `storage_format` | `1` | `2` |
| `record` | complete JSON `MessageRecord` | `NULL` |
| `payload` | `NULL` | exact `MessageRecord.payload` bytes |
| `deferred_peel` | `NULL`; represented inside `record` | optional JSON `DeferredPeelLifecycle` metadata |

Existing rows remain format 1 at migration time so opening a large account does
not perform an unbounded history rewrite. Current writes are format 2. Updating
a legacy row promotes it atomically; updating a format-2 state changes only the
scalar `state` and, when leaving `PeelDeferred`, clears `deferred_peel`. It does
not read, decode, copy, or rewrite `payload`.

The retained legacy `record` column is a compatibility read path, not an
ongoing second authority. `promote_legacy_message_rows` promotes at most 256
rows in one atomic, idempotent batch and reports only aggregate progress so a
host can schedule it away from account-open latency. Removing format-1 reads
requires a later migration and release decision.
Reclaiming freed SQLCipher pages is an explicit maintenance operation; opening
an account never runs `VACUUM` implicitly.

## `StoredMessagePayload` v2

New `MessageRecord.payload` values use this envelope:

```text
opaque magic[5] = "MDKMP";
uint16 version = 2;
uint8 variant;
PayloadVariant body;
```

Variant values are stable:

| Value | Body |
| --- | --- |
| `0` | one `TransportMessage`, `RawTransport` |
| `1` | one `TransportMessage`, `OutboundWelcome` |
| `2` | one `TransportMessage`, `OpenMlsWire` |
| `3` | exact `TransportMessage`, OpenMLS `TransportMessage`, optional own-commit stamp, optional own-application stamp |
| `4` | one `TransportMessage`, required own-commit stamp |

A stored `TransportMessage` contains, in order:

```text
opaque id<V>;
opaque payload<V>;
uint64 timestamp;
MessageId causal_dependencies<V>;
opaque source_utf8<V>;
uint8 envelope_variant; // 0 group message, 1 welcome
opaque envelope_id<V>;  // transport group id or recipient id
```

Each `MessageId` inside `causal_dependencies` is itself a length-prefixed opaque
value. An own-commit stamp contains the length-prefixed committer id, a one-byte
priority (`0` privileged, `1` ordinary), a vector of length-prefixed UTF-8
proposal references, optional checkpoint id, and optional resulting epoch
authenticator. An own-application stamp contains the sender id and source epoch
authenticator.

Each field is limited to at most `2^30` bytes and each decoded list to at most
`2^20` items. These are defensive local resource bounds, not protocol limits.

The decoder falls back from a missing `MDKMP` magic to the previous tagged JSON
envelope and then the oldest bare-`TransportMessage` JSON shape. A value that
starts with `MDKMP` never falls back after a binary decoding failure.

## Snapshot v2

Retained-anchor snapshots no longer copy the message ledger or queued outbound
work. Their 32-invitee capture cost measured roughly 1.23 ms. Full rollback
snapshots still include the live message ledger and measured roughly 11.0 ms,
so that path justified a binary format.

Snapshot and group-state checkpoint v2 start with `MDKS`, network-order `uint16` version `2`, and then
length-delimited group JSON, optional normalized message rows, optional queued
outbound rows, member capabilities, optional convergence-policy and validation
bytes, and raw OpenMLS key/value rows. Message ids, group ids, payloads, and
OpenMLS fields remain raw bytes rather than JSON number arrays. The exact
encoded length is computed before allocating the zeroizing output buffer; the
encoder cannot grow it. Temporary list bodies that can contain secret material
also use zeroizing ownership.

A blob without `MDKS` is decoded as the corresponding unversioned JSON v1
snapshot or checkpoint. A blob with `MDKS` never falls back following a v2
error. Full snapshots, state-scoped snapshots, and branch-addressed checkpoints
use the envelope. State-scoped snapshots and checkpoints encode the message and
queue options as absent; checkpoints additionally reject rollback-only message,
queue, or convergence-policy fields during decoding.

## Decision evidence

Measured on 2026-08-13 in the release profile on the same local machine and
Criterion harness used to identify the original regression:

| Measurement | Current result |
| --- | --- |
| `create_group/32 invitees` | 15.62–15.73 ms; the pre-v2 current-head baseline was about 28.09 ms |
| retained-anchor capture, empty group | 177–185 us |
| retained-anchor capture, 32 invitees | 1.23–1.29 ms |
| full rollback snapshot, 32 invitees, JSON | 10.95–11.03 ms |
| full rollback snapshot, 32 invitees, v2 | 3.62–4.40 ms |
| representative 16,727-byte Welcome, JSON payload envelope | 67,254 bytes |
| representative 16,727-byte Welcome, explicit MDK v2 envelope | 16,821 bytes |
| MDK v2 encode / decode | about 686 ns / 335 ns |
| JSON encode / decode | about 40.4 us / 114.4 us |

A Postcard 1.1.3 spike produced 16,810 bytes and encoded in about 6.42 us, but
could not deserialize the existing internally tagged `StoredMessagePayload`
Serde shape (`WontImplement`). Supporting it would therefore require a second
Postcard-specific DTO/schema in addition to the explicit compatibility
contract. The explicit MDK format is smaller than JSON, faster than both tested
encoders, already decodes the production type, and has stable golden bytes, so
Postcard is not adopted.

The group-state-only retained-anchor capture is roughly 1.25 ms at the
32-invitee fixture and the headline create benchmark is below the 20 ms target.
Snapshot v2 is justified by the separately measured full rollback path, not by
the obsolete pre-#1406 claim that retained anchors still contain messages.

## Operational policy

- Upgrade is automatic through numbered transactional migrations.
- Downgrade across migration 47 is unsupported: an older binary refuses the
  newer migration before reading account data.
- Migration 47 changes table shape atomically but does not backfill history, so
  session-open time is bounded independently of message-history size.
- The promotion sweep uses batches of at most 256 rows, aggregate privacy-safe
  progress, and an idempotent transaction; malformed input rolls back the
  whole batch.
- `VACUUM` is opt-in maintenance on an already keyed connection and is never
  part of automatic session open.
