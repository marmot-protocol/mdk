# AGENTS.md - marmot-forensics

Shared JSONL forensic audit schema for Marmot incident capture.

## Scope

- Own the append-only audit-log schema and the `ForensicRecorder` trait (with `JsonlRecorder` and `NoopRecorder`
  implementations) used by engine/runtime incident capture.
- Keep this crate independent of engine, app, storage, transport SDK, and simulator crates.
- Keep static snapshot dump analysis out of this repo; external tools should consume JSONL audit files.
- Keep audit logging opt-in and explicit. The sole supported event model is privacy-safe: hashed/truncated identifiers,
  digests, lengths, counts, and typed outcomes only. Never add decrypted content, cleartext group values, full account
  or member identities, bearer/upload tokens, auth headers, private keys, ciphertext, or raw MLS bytes.
- Keep the schema (`schema/audit-log-event.v3.schema.json`) and the Rust kind catalog in lockstep; the
  `audit_log_event_schema_tracks_kind_catalog` test enforces it. Bump `AUDIT_LOG_SCHEMA_VERSION` and add a new versioned
  schema file when changing required fields; analyzers reject unknown versions.

## Verification

```sh
cargo test -p marmot-forensics
```
