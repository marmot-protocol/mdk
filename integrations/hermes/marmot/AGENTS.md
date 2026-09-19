# AGENTS.md - integrations/hermes/marmot

Hermes platform plugin for Marmot through the local `wn-agent` control socket.
The Hermes counterpart of `integrations/openclaw/marmot`. Read `README.md` first.

## Scope

- A thin, **control-plane-only** Hermes platform plugin. `wn-agent` owns the Marmot account, MLS state, Nostr
  transport, and QUIC previews; this plugin only speaks `marmot.agent-control.v2` (NDJSON over a Unix socket).
- Use `stream_finish` with acknowledged final text; Rust owns transcript hashing and chunking.
- No QUIC, crypto, relay, or MLS logic here.
- Privacy-safe logging only: no account ids, group ids, message ids, pubkeys, relay URLs, payloads, ciphertext,
  plaintext, or key material.

## Key files

- `plugin.yaml` — Hermes platform plugin manifest.
- `__init__.py` — plugin entry registration.
- `adapter.py` — agent-control client, inbound/outbound bridging, and live-preview state machine.
- `diagnostics.py` — shared doctor report helpers and the plugin-owned diagnostics socket.
- `doctor.py` — privacy-safe, non-mutating installation collector used by `install-hermes-marmot.sh --doctor`.
- `tests/` — unit tests and dev-script smoke coverage.

## Rules

- Treat release installs (`install-hermes-marmot.sh`) and dev harness scripts (`just hermes-dev-*`) as the operational
  verification path for end-to-end behavior.

- Keep the adapter's effective-configuration resolution and the doctor's projection in `diagnostics.py`
  aligned in the same change, with parity tests for enablement, dotenv/YAML precedence, welcomers,
  socket/account/auth, home and media settings. Projection drift can contact the wrong endpoint or
  falsely recommend a restart. Follow-up [#1920](https://github.com/marmot-protocol/mdk/issues/1920)
  tracks replacing this duplication with an adapter-owned diagnostic contract.

## Verification

```sh
python3 -m unittest discover -s integrations/hermes/tests/marmot
integrations/hermes/tests/marmot/test_dev_scripts.sh
# or from the repo root:
just hermes-dev-script-test
just hermes-dev-smoke
just hermes-dev-e2e-deterministic
just hermes-dev-e2e-connector
```
