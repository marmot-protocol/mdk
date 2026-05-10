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
- Preserves the publish-before-apply contract: callers confirm or fail pending
  group operations after transport publish, including auto-publish work created
  while ingesting inbound messages.
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
- auto-publish work after SelfRemove proposal ingest, including the pending ref
  callers must confirm or fail;
- convergence advancement releasing queued outbound app messages.

`tests/nostr_stack.rs` covers the production-shaped non-relay stack:

- `AccountDeviceSession` using SQLCipher storage and the real
  `NostrMlsPeeler`;
- `NostrTransportAdapter` activation, inbox delivery, group subscription, and
  publish reports over an in-memory relay client;
- NIP-59 welcome publication/delivery into `GroupJoined`;
- kind `445` group message publication/delivery into `MessageReceived`.
- publish lifecycle resolution for successful acks, insufficient acks, and
  relay publish errors;
- group subscription gating, duplicate relay delivery, out-of-order delivery,
  and invite group evolution with both commit and welcome outputs.

`tests/nostr_stack_chaos.rs` runs seeded no-network delivery-chaos scripts
against the same stack. It writes reproducibility reports to
`target/session-stack-chaos/` and currently keeps generated same-epoch
app-message reordering inside a shallow delivery window. It also includes an
invite lifecycle chaos path for wrong-route drops, welcome replay, shared commit
fanout, welcome-before-commit delivery, and commit-before-welcome delivery.

Run:

```sh
cargo test -p cgka-session
```
