# AGENTS.md - crates/marmot-app

App runtime bridge for the first real Marmot app surfaces.

## Scope

- Own the app-facing runtime that ties `AccountHome`, SQLCipher session storage, Nostr peeling, Nostr transport adapter,
  and local development relay support together.
- Keep CLI/TUI presentation out of this crate.
- Keep protocol engine behavior in `cgka-engine` and session ownership in `cgka-session`.
- Keep local development relay code clearly separate from production Nostr relay-list setup and discovery.
- Do not print or log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key
  material.

## Verification

```sh
cargo test -p marmot-app
```
