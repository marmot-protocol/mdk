# marmot-forensics

Shared JSONL forensic audit schema for Marmot incident capture.

This crate defines the append-only audit event model, the `ForensicRecorder` trait, and opt-in recorder
implementations used by the engine and app runtime when operators enable forensic logging.

## What this crate does

- Owns the versioned v4 and v5 JSONL schemas and the Rust event kind catalog.
- Provides privacy-safe `JsonlRecorder` and `NoopRecorder` implementations. There is no full-data mode.
- Stays independent of engine, storage, transport, and simulator crates.

## What it does not do

- No log upload, tracker, or analysis tooling (external consumers read JSONL files).
- No always-on logging — forensic capture remains opt-in.

See [`docs/marmot-architecture/audit-logging.md`](../../docs/marmot-architecture/audit-logging.md) for the full
implementation inventory.

## Opt-in v5 recording

The `v5` module provides checked lifecycle, app, Welcome and operational events,
their strict schema, and contract fixtures. New opt-in app sessions write v5
JSONL; historical v4 files and their legacy upload contract remain separate.
`recording_session_started` identifies a writer session, while
`recording_session_stopped` is present only after an observed graceful runtime
shutdown. Disabling recording writes no post-consent stop. A later
`recording_capture_loss` reports observed failed local record attempts with
unknown durable loss extent; a missing row never proves complete capture. See
[V5-WELCOME.md](V5-WELCOME.md) for the Welcome-specific boundaries.

## Run the tests

```sh
cargo test -p marmot-forensics
```

See [`AGENTS.md`](AGENTS.md) for schema/kind lockstep rules.
