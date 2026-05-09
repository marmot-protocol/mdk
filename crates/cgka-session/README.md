# cgka-session

Production-shaped account-device wrapper around `Engine<SqliteStorage>`.

This crate is where app integration starts to become concrete. Callers provide
an identity, SQLCipher database key, database path, feature registry, and
transport peeler. The session opens encrypted storage, builds the engine,
hydrates stable group epochs from stored group records, and returns app events
plus publishable transport work from each lifecycle method.

## What this crate does

- Opens one encrypted SQLite database for one Marmot account-device identity.
- Builds `Engine<SqliteStorage>` with an injected `TransportPeeler`.
- Surfaces `GroupEvent`s and publishable transport work as `SessionEffects`.
- Preserves the publish-before-apply contract: callers still confirm or fail
  pending group operations after transport publish.
- Exposes convergence advancement so queued outbound work can be regenerated
  from canonical state.

## What it does not do

- No account key derivation, recovery, or key rotation.
- No relay sync, network publish, or transport adapter.
- No UI projection or application database.

Those live above this crate.

## Test coverage

`tests/session_lifecycle.rs` covers:

- encrypted SQLCipher open, create, confirm, close, and reopen;
- welcome ingest producing `GroupJoined`;
- app-message ingest producing `MessageReceived`;
- auto-publish work after SelfRemove proposal ingest;
- convergence advancement releasing queued outbound app messages.

`tests/nostr_stack.rs` covers the production-shaped non-relay stack:

- `AccountDeviceSession` using SQLCipher storage and the real
  `NostrMlsPeeler`;
- `NostrTransportAdapter` activation, inbox delivery, group subscription, and
  publish reports over an in-memory relay client;
- NIP-59 welcome publication/delivery into `GroupJoined`;
- kind `445` group message publication/delivery into `MessageReceived`.

Run:

```sh
cargo test -p cgka-session
```
