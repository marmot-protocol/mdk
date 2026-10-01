# AGENTS.md - agent-stream-compose

Reusable live-preview stream composition for Marmot agent integrations. Human overview and entry points:
[`README.md`](README.md).

## Scope

- Own `run_stream_compose_session` (plus the `_candidates` and `_without_live` variants) and the
  `StreamComposeCommand`/`StreamComposeReport` surface for driving a single agent text-stream preview over the QUIC
  broker publisher.
- Reuse the canonical record framing and limits from `cgka_traits::agent_text_stream` (plaintext frame cap, record
  status/text-delta/progress-delta tags); do not redefine framing here.
- Keep this crate transport-aware (QUIC stream + broker) but free of engine, account, and app orchestration logic.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Command/report DTOs, session entry points, the compose task, live-record queue bounds and broker timeouts. |
| `src/tests.rs` | Unit and in-process broker tests. |

## Invariants

- Keep finish-expectation validation inside the compose task, before teardown: a mismatch must leave the session
  running so a retried finish works.
- Candidate failover must reuse the same start-bound crypto and publisher store so one sequence space continues.
- Live transport failure disables only provisional writes; the authoritative transcript and finalization continue.
- Keep pending live records bounded (`MAX_PENDING_LIVE_RECORDS`, `MAX_PENDING_LIVE_RECORD_BYTES`).

## Verification

```sh
cargo test -p agent-stream-compose
```
