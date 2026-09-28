# AGENTS.md - marmot-forensics

Shared JSONL forensic audit schema for Marmot incident capture.

## Scope

- Own the append-only audit-log schema and the `ForensicRecorder` trait (with `JsonlRecorder` and `NoopRecorder`
  implementations) used by engine/runtime incident capture.
- Keep this crate independent of engine, app, storage, transport SDK, and simulator crates.
- Keep static snapshot dump analysis out of this repo; external tools should consume JSONL audit files.
- Keep `JsonlRecorder` segment rotation transparent (mdk#1181). Sealing the active file at
  `AUDIT_LOG_SEGMENT_MAX_BYTES` is a rename into an `audit-*-seg<NNNNNN>.jsonl` sibling that deletes and truncates
  nothing; `seq`, the recorder session id, and health counters carry across the boundary and no `recorder_started` row
  is written. Each fresh segment repeats the latest explicit `source_context` with a fresh sequence number; ordinary
  events and sealed bytes remain unchanged. Retention and disk
  bounding of sealed segments belong to mdk#1014. Destructive `rotate()` — which discards the current file — stays a
  separate, explicit operation.
- Retry failed segment rolls after bounded backoff, without requiring a recorder restart or destructive rotation.
  A failed flush must not seal buffered data. Preserve the actual writer path if rename compensation fails.
- Keep audit logging opt-in and explicit. The sole supported event model is privacy-safe: hashed/truncated identifiers,
  digests, lengths, counts, and typed outcomes only. Never add decrypted content, cleartext group values, full account
  or member identities, bearer/upload tokens, auth headers, private keys, ciphertext, or raw MLS bytes.
- New opt-in app audit sessions record v5 into separate files. Keep `schema/audit-log-event.v5.schema.json`, the Rust
  types/semantic validator, and `tests/audit_v5.rs` in lockstep, including the 44 typed operational kinds and Welcome
  evidence. The v5 local-delivery path sends original validated bodies; v4 files and the v4-only whole-file Goggles
  contract remain separate. Rust validation remains authoritative for rules JSON Schema cannot express. Coordinate
  any v5 wire changes with the strict receiver before deployment.
- Keep the schema (`schema/audit-log-event.v4.schema.json`) and the Rust kind catalog in lockstep. Two tests enforce
  two different halves of that, and both are load-bearing: `audit_log_event_schema_tracks_kind_catalog` compares the
  set of `type` tags, so it catches an added or removed *event kind* — it does not look at properties and passes
  cleanly with a property missing. `sample_events_serialize_within_schema_property_names` walks every sample kind's
  serialized JSON against the schema's `additionalProperties: false` branches, so it is what catches an added *field*
  the schema does not list. A new field therefore needs a `sample_audit_event_kinds` entry that populates it, or
  nothing checks it. Coordinate even optional additions with strict downstream consumers such as Goggles before
  shipping producers: its `additionalProperties: false` validation rejected whole v4 uploads containing
  `local_member_ref` until its schema was synchronized. Bump `AUDIT_LOG_SCHEMA_VERSION` and add a new versioned schema file when changing required
  fields; analyzers reject unknown versions. An additive optional field needs no bump, but note in its doc comment
  that absence is then ambiguous between "old row" and "value known absent".

## Verification

```sh
cargo test -p marmot-forensics
```
