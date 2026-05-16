# AGENTS.md - crates/marmot-app

App runtime bridge for the first real Marmot app surfaces.

## Scope

- Own the app-facing runtime that ties `AccountHome`, SQLCipher session storage, Nostr peeling, Nostr transport adapter,
  and local development relay support together.
- Keep CLI/TUI presentation out of this crate.
- Keep the Nostr user directory app-facing and pubkey-keyed. It may cache local-account links, profile metadata, follow
  lists, relay lists, and KeyPackages, but it must not become an unbounded Nostr social-graph crawler.
- Keep directory search bounded over cached follow edges. Do not add web-of-trust scoring unless that is reopened as a
  deliberate product decision.
- Keep protocol engine behavior in `cgka-engine` and session ownership in `cgka-session`.
- Keep Nostr group routing sourced from `marmot.transport.nostr.routing.v1` component bytes; local filtering may affect
  connections, but must not rewrite signed routing state.
- Keep local development relay code clearly separate from production Nostr relay-list setup and discovery.
- Keep local relay discovery endpoint-scoped: a fetch from one `marmot-local://...` relay must not see records that were
  only published to another local relay.
- Do not print or log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key
  material.

## Verification

```sh
cargo test -p marmot-app
```
