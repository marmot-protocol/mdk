# AGENTS.md - crates/marmot-account

Agent-facing map for the Marmot account orchestration crate.

## Scope

This crate owns the thin future app-core shell around:

- `AccountDeviceSession`;
- a pluggable `TransportAdapter`;
- transport routing policy;
- key-package publication;
- publish confirmation and rollback.

It should not own MLS internals, transport event parsing, SQLCipher key derivation, UI projection, notifications, or
real relay auth.

## Rules

- Keep the crate transport-generic. Nostr-specific publication belongs behind an injected boundary or in a
  transport-specific crate.
- Treat `StaticTransportRouting` as a test/simple harness implementation. A production Nostr routing policy should
  derive account inbox routes, KeyPackage publication routes, and group routes from Nostr/account state and the
  `marmot.transport.nostr.routing.v1` app component.
- Treat `KeyPackagePublisher` as provisional. The likely production direction is to move KeyPackage publication into the
  transport adapter family rather than keeping it as a separate app-core-owned publisher.
- Keep `AccountDeviceSession` as the owner of engine state.
- Confirm pending work only after the adapter reports enough acknowledgements.
- Roll back pending work when publication fails or does not meet the required acknowledgement count.
- Do not log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key material.

## Verification

```sh
cargo test -p marmot-account
```
