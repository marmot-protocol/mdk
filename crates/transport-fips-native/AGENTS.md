# AGENTS.md - transport-fips-native

Native FIPS transport for Nostr-shaped Marmot relay traffic.

## Scope

- Implement `transport_nostr_adapter::FipsRelayApi` on Linux and FreeBSD.
- Own the local FIPS Unix-socket connection, WFP1 handshake/framing,
  per-endpoint flow supervision, reconnects, and Nostr `OK` receipt matching.
- Keep endpoint parsing and semantic Nostr relay routing in
  `transport-nostr-adapter`.
- Keep MLS, app-component, storage, account orchestration, and WebSocket relay
  mechanics out of this crate.

## Key files

- `src/lib.rs` - configuration, platform gating, and public API.
- `src/native.rs` - native FIPS flow actors and WFP1 lifecycle.
- `src/wire.rs` - Nostr client/relay JSON encoding and strict response parsing.
- `src/unsupported.rs` - explicit unsupported-platform backend.
- `examples/relay-smoke.rs` - live Wok interoperability probe.
- `../../testing/fips-native/` - disposable Linux Compose lab.

## Invariants

- Accept only canonical `fips://<npub>` endpoint identities; port `7777` is
  configuration, not part of endpoint identity.
- Never perform HTTP or WebSocket handshakes on a FIPS flow.
- Require a matching Nostr `OK true` before reporting publication success.
- Replay active subscriptions after reconnect, but never invent durable
  publication success or silently persist a failed publication.
- Keep tracing privacy-safe: no endpoint, pubkey, subscription id, event id,
  payload, ciphertext, plaintext, or key material.

## Verification

```sh
cargo test -p transport-fips-native
just fips-native-e2e
```
