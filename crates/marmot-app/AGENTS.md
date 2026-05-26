# AGENTS.md - crates/marmot-app

App runtime bridge for the first real Marmot app surfaces.

## Scope

- Own the app-facing runtime that ties `AccountHome`, SQLCipher session storage, Nostr peeling, and Nostr transport
  adapter support together.
- Keep runtime orchestration, managed account workers, subscriptions, and live agent stream watches in `src/runtime.rs`
  instead of regrowing `src/lib.rs`.
- Keep CLI/TUI presentation out of this crate.
- Keep the Nostr user directory app-facing and pubkey-keyed. It may cache local-account links, profile metadata, follow
  lists, relay lists, and KeyPackages, but it must not become an unbounded Nostr social-graph crawler.
- Keep directory search bounded over cached follow edges. Do not add web-of-trust scoring unless that is reopened as a
  deliberate product decision.
- Keep runtime directory subscriptions chunked and privacy-safe. Subscription identifiers must not embed raw pubkeys.
- Treat Marmot kind `30443` KeyPackages as long-lived last-resort packages. Normal publish should reuse the cached
  package and stable replaceable d-tag; only explicit rotate/manual repair should create a new package ref.
- Incoming welcomes may auto-join MLS state, but app projections must preserve local confirmation state. Pending invites
  should stay visible until accepted, and decline should leave the group before archiving the local projection.
- Keep protocol engine behavior in `cgka-engine` and session ownership in `cgka-session`.
- Keep Nostr group routing sourced from `marmot.transport.nostr.routing.v1` component bytes; relay filtering may affect
  connections, but must not rewrite signed routing state.
- Keep local test relay code in tests; production app runtime should talk to Nostr relay URLs through the adapter.
- Do not print or log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key
  material.

## Verification

```sh
cargo test -p marmot-app
```
