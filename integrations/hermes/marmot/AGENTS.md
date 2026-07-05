# AGENTS.md - integrations/hermes/marmot

Hermes platform plugin for Marmot through the local `wn-agent` control socket.
The Hermes counterpart of `integrations/openclaw/marmot`. Read `README.md` first.

## Scope

- A thin, **control-plane-only** Hermes platform plugin. `wn-agent` owns the Marmot account, MLS state, Nostr
  transport, and QUIC previews; this plugin only speaks `marmot.agent-control.v1` (NDJSON over a Unix socket).
- Keep transcript hashing and stream chunking byte-for-byte with the authoritative Rust
  `AgentTextStreamTranscriptV1` (`crates/traits/src/agent_text_stream.rs`).
- No QUIC, crypto, relay, or MLS logic here.
- Privacy-safe logging only: no account ids, group ids, message ids, pubkeys, relay URLs, payloads, ciphertext,
  plaintext, or key material.

## Key files

- `plugin.yaml` — Hermes platform plugin manifest.
- `__init__.py` — plugin entry registration.
- `adapter.py` — agent-control client, inbound/outbound bridging, and live-preview state machine.
- `tests/` — unit tests and dev-script smoke coverage.

## Rules

- Regenerate OpenClaw transcript parity vectors in `integrations/openclaw/marmot/test/vectors/` from Rust if transcript
  hashing changes; keep Hermes chunking aligned with the same Rust source.
- Treat release installs (`install-hermes-marmot.sh`) and dev harness scripts (`just hermes-dev-*`) as the operational
  verification path for end-to-end behavior.

## Verification

```sh
python3 -m unittest discover -s integrations/hermes/marmot/tests
integrations/hermes/marmot/tests/test_dev_scripts.sh
# or from the repo root:
just hermes-dev-script-test
just hermes-dev-smoke
just hermes-dev-e2e-deterministic
just hermes-dev-e2e-connector
```
