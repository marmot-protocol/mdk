# AGENTS.md - agent-stream-compose

Reusable live-preview stream composition for Marmot agent integrations.

## Scope

- Own `run_stream_compose_session` and its `StreamComposeCommand`/`StreamComposeReport` surface for driving a single
  agent text-stream preview over the QUIC broker publisher.
- Reuse the canonical record framing and limits from `cgka_traits::agent_text_stream` (plaintext frame cap, record
  status/text-delta/progress-delta tags); do not redefine framing here.
- Keep this crate transport-aware (QUIC stream + broker) but free of engine, account, and app orchestration logic.

## Verification

```sh
cargo test -p agent-stream-compose
```
