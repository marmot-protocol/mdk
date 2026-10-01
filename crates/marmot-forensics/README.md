# marmot-forensics

Shared JSONL forensic audit schema for Marmot incident capture. It defines the append-only audit event model, the
`ForensicRecorder` trait, and the opt-in recorders that the engine and app runtime use when a user or operator enables
forensic logging. Read this if you produce, validate, or analyze Marmot audit files.

## What this crate does

- Owns the versioned JSONL schemas under [`schema/`](schema/) (v1–v5; new sessions record v5, historical v4 files remain
  readable) and the Rust event kind catalog.
- Provides privacy-safe `JsonlRecorder` and `NoopRecorder` implementations. There is no full-data mode: rows carry
  hashed or truncated identifiers, digests, lengths, counts, and typed outcomes only.
- Provides a local delivery boundary (`local_delivery`, Unix only) that prepares bounded batches of original, complete
  JSONL lines for a sender. It does no network I/O itself; `marmot-app` owns the upload path.
- Stays independent of engine, storage, transport, and simulator crates.

## What it does not do

- No network upload, tracker, or analysis tooling. External consumers read the JSONL files.
- No always-on logging. Forensic capture is opt-in.

See [`docs/marmot-architecture/audit-logging.md`](../../docs/marmot-architecture/audit-logging.md) for the full
implementation inventory.

## Opt-in v5 recording

The `v5` module provides checked lifecycle, app, Welcome, and operational events, their strict schema
(`schema/audit-log-event.v5.schema.json`), and contract fixtures. New opt-in app sessions write v5 JSONL into separate
files; historical v4 files and their legacy upload contract remain separate.

- `recording_session_started` identifies a writer session.
- `recording_session_stopped` is present only after an observed graceful runtime shutdown. Disabling recording writes no
  post-consent stop.
- A later `recording_capture_loss` reports observed failed local record attempts with unknown durable loss extent. A
  missing row never proves complete capture.

See [V5-WELCOME.md](V5-WELCOME.md) for the Welcome-specific boundaries.

## Run the tests

```sh
cargo test -p marmot-forensics
```

See [`AGENTS.md`](AGENTS.md) for schema/kind lockstep rules.
