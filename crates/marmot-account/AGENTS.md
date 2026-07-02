# AGENTS.md - crates/marmot-account

Agent-facing map for the Marmot account orchestration crate.

## Scope

This crate owns the account/session orchestration layer around:

- account home layout;
- local account records and signing-key storage;
- `AccountDeviceSession`;
- a pluggable `TransportAdapter`;
- transport routing policy;
- key-package publication;
- publish confirmation and rollback.

It should not own MLS internals, transport event parsing, SQLCipher key derivation, UI projection, notifications, real
relay auth, or transport-specific relay discovery.

## Layout

`src/lib.rs` is a thin facade: crate docs, `mod` declarations, and `pub use` re-exports. Every public item keeps its
`marmot_account::Item` path. Source is split into focused modules:

- `error.rs` — `AccountError`/`AccountHomeError` enums and the `AccountResult`/`AccountHomeResult` aliases.
- `home.rs` — `AccountHome` and `AccountSummary`; owns the account-record layout and signing-key lifecycle.
- `secret_store.rs` — `AccountSecretStore` trait with `LocalFileSecretStore` and `KeychainSecretStore`.
- `keyring.rs` — platform keyring store init (per-OS `#[cfg]` cascade) and keyring-error mapping.
- `io.rs` — JSON read/write helpers, private-file writes, and account-label validation.
- `key_package.rs` — `KeyPackagePublisher` trait, `KeyPackagePublication`, and `NoopKeyPackagePublisher`.
- `routing.rs` — `TransportRoutingPolicy` trait, `TransportRoutingError`, and `StaticTransportRouting`.
- `runtime.rs` — `AccountDeviceRuntime` plus its effect aggregates (`AccountDeviceEffects`, `AccountIngestEffects`,
  `PublishFailure`, `PendingResolution`).

## Rules

- Keep the crate transport-generic. Nostr-specific publication belongs behind an injected boundary or in a
  transport-specific crate.
- Treat `StaticTransportRouting` as a test/simple harness implementation. A production Nostr routing policy should
  derive account inbox routes, KeyPackage publication routes, and group routes from Nostr/account state and the
  `marmot.transport.nostr.routing.v1` app component.
- Treat `KeyPackagePublisher` as provisional. The likely production direction is to move KeyPackage publication into the
  transport adapter family rather than keeping it as a separate app-core-owned publisher.
- Keep `AccountDeviceSession` as the owner of engine state.
- Keep CLI account-selection ergonomics and relay-list repair out of this crate; those belong in `dm` and `marmot-app`.
- Confirm pending work only after the adapter reports enough acknowledgements.
- Roll back pending work when publication fails or does not meet the required acknowledgement count.
- Do not log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key material.

## Verification

```sh
cargo test -p marmot-account
```
