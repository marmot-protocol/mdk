# AGENTS.md - marmot-forensics

Shared JSONL forensic audit schema for Marmot incident capture.

## Scope

- Own the append-only audit-log schema and the `ForensicRecorder` trait (with `JsonlRecorder` and `NoopRecorder`
  implementations) used by engine/runtime incident capture.
- Keep this crate independent of engine, app, storage, transport SDK, and simulator crates.
- Keep static snapshot dump analysis out of this repo; external tools should consume JSONL audit files.
- Keep audit logging opt-in and explicit because JSONL audit files can include sensitive operational identifiers.
- Stamp an `AuditDataMode` on every event. `obfuscated_sensitive_data` is the default safety posture (hashed/truncated
  identifiers, no plaintext, decoded content, or full pubkeys); `full_data` is an explicit opt-in that additionally
  carries decrypted content and full identifiers. Never emit bearer/upload tokens, auth headers, private keys,
  ciphertext, or raw MLS bytes in either mode. Switching modes (`ForensicRecorder::set_data_mode`) rotates the backing
  store so each file has one unambiguous mode.
- Keep the schema (`schema/audit-log-event.v2.schema.json`) and the Rust kind catalog in lockstep; the
  `audit_log_event_schema_tracks_kind_catalog` test enforces it. Bump `AUDIT_LOG_SCHEMA_VERSION` and add a new versioned
  schema file when changing required fields; analyzers reject unknown versions.

## Verification

```sh
cargo test -p marmot-forensics
```
