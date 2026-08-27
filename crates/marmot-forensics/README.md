# marmot-forensics

Shared JSONL forensic audit schema for Marmot incident capture.

This crate defines the append-only audit event model, the `ForensicRecorder` trait, and opt-in recorder
implementations used by the engine and app runtime when operators enable forensic logging.

## What this crate does

- Owns the versioned JSONL schema (`schema/audit-log-event.v3.schema.json`) and the Rust event kind catalog.
- Provides privacy-safe `JsonlRecorder` and `NoopRecorder` implementations. There is no full-data mode.
- Stays independent of engine, storage, transport, and simulator crates.

## What it does not do

- No log upload, tracker, or analysis tooling (external consumers read JSONL files).
- No always-on logging — forensic capture remains opt-in.

See [`docs/marmot-architecture/audit-logging.md`](../../docs/marmot-architecture/audit-logging.md) for the full
implementation inventory.

## Run the tests

```sh
cargo test -p marmot-forensics
```

See [`AGENTS.md`](AGENTS.md) for schema/kind lockstep rules.
