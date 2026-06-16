# AGENTS.md - marmot-forensics

Shared JSONL forensic audit schema for Marmot incident capture.

## Scope

- Own the append-only audit-log schema and the `ForensicRecorder` trait (with `JsonlRecorder` and `NoopRecorder`
  implementations) used by engine/runtime incident capture.
- Keep this crate independent of engine, app, storage, transport SDK, and simulator crates.
- Keep static snapshot dump analysis out of this repo; external tools should consume JSONL audit files.
- Keep audit logging opt-in and explicit because JSONL audit files can include sensitive operational identifiers.

## Verification

```sh
cargo test -p marmot-forensics
```
