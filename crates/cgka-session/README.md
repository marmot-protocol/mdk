# cgka-session

Production-shaped account-device wrapper around `Engine<SqliteAccountStorage>`.

This crate is where app integration starts to become concrete. `SessionConfig::new` takes an identity, SQLCipher
database key, database path, and transport peeler; opening the session also requires an account identity-proof signer.
A feature registry, supported app-component set, convergence policy, and an optional forensic recorder are set through
builder methods on `SessionConfig`. The session opens encrypted storage, builds the engine, hydrates stable group epochs
from stored group records, and returns app events plus publishable transport work from each lifecycle method.

## What this crate does

- Opens one encrypted SQLite database for one Marmot account-device identity.
- Builds `Engine<SqliteAccountStorage>` with an injected `TransportPeeler`.
- Surfaces `GroupEvent`s and publishable transport work as `SessionEffects`.
- Preserves the publish-before-apply contract: callers confirm or fail pending group operations after transport publish,
  including auto-publish work created while ingesting inbound messages.
- Exposes convergence advancement so queued outbound work can be regenerated from canonical state.
- Provides compact `group_authority` reads and `with_group_authority_snapshot` for composing host-owned
  persisted reads with current engine facts on this session's store. The callback is synchronous and read-only;
  unhydrated groups return `GroupNotHydrated`. It does not serve a frozen startup snapshot or start relay work.

## What it does not do

- No account key derivation, lost-key recovery, or key rotation.
- No relay sync, network publish, or transport adapter.
- No UI projection or application database.

Those live above this crate.

## Explicit group-history recovery

Use `AccountDeviceSession::prepare_group_recovery(config, group, history, directory)`
when normal convergence and history refetch have failed. Stop account mutation first,
collect the available history without the normal sync watermark, and supply the same
identity, peeler, identity-proof signer, feature registry and components as normal open.
The operation requires a Tokio runtime and performs synchronous encrypted backup work;
run it off the UI thread.

Preparation creates private, encrypted `before.sqlite` and `candidate.sqlite` files,
rewinds the candidate to its oldest retained anchor, and replays through the normal
engine without a publisher. The original database remains unchanged. The opaque result
exposes an aggregate report; epoch advancement alone is not proof of agreement with peers.
The host remains responsible for reporting unavailable relays or truncated history.

After approval, consume the result with `apply_group_recovery()`, discard the old session,
and reopen it. Promotion is one group-scoped transaction and rejects any intervening
account write. Recovered application events use the normal durable projection outbox;
existing app history and other groups remain intact. Verify both reception and sending.
Dropping a prepared result cancels promotion. The host explicitly removes the encrypted
scratch files when they are no longer needed; existing files are never overwritten.

This first version refuses removed/disbanded membership, missing anchors, retained own
commits, queued sends, and unfinished publications. Resolve those publications explicitly
before recovery. In particular, an oversized event with unknown acknowledgements must not
be silently discarded or reported as sent. Recovery requires authenticated application
deliveries at a tip newer than the original epoch, preventing reuse of that tip’s send
ratchet. It cannot recreate missing keys or promise recovery of every opaque event.
Inputs are limited to 100,000 events and 512 MiB of payload; replay has a five-minute
cooperative deadline. Cancellation or any preparation error leaves the source unchanged.

## Test coverage

`tests/session_lifecycle.rs` covers:

- encrypted SQLCipher open, create, confirm, close, and reopen;
- welcome ingest producing `GroupJoined`;
- app-message ingest producing `MessageReceived`;
- auto-publish work after SelfRemove proposal ingest, including the pending ref callers must confirm or fail;
- auto-proposal work when a durable SelfRemove leave request has to be re-proposed for a newer epoch;
- convergence advancement releasing queued outbound app messages.

`tests/nostr_stack.rs` covers the production-shaped non-relay stack:

- `AccountDeviceSession` using SQLCipher storage and the real `NostrMlsPeeler`;
- `NostrTransportAdapter` activation, inbox delivery, group subscription, and publish reports over an in-memory relay
  client;
- NIP-59 welcome publication/delivery into `GroupJoined`;
- kind `445` group message publication/delivery into `MessageReceived`;
- signed `marmot.transport.nostr.routing.v1` component state driving the Nostr `h` tag, group subscriptions, and group
  publish targets instead of assuming the transport id equals the MLS group id.
- publish lifecycle resolution for successful acks, insufficient acks, and relay publish errors;
- group subscription gating, duplicate relay delivery, out-of-order delivery, and invite group evolution with both
  commit and welcome outputs.

`tests/nostr_stack_chaos.rs` runs seeded no-network delivery-chaos scripts against the same stack. It writes
reproducibility reports to `target/session-stack-chaos/` and currently keeps generated same-epoch app-message reordering
inside a shallow delivery window. It also includes an invite lifecycle chaos path for wrong-route drops, welcome replay,
shared commit fanout, welcome-before-commit delivery, and commit-before-welcome delivery.

Run:

```sh
cargo test -p cgka-session
```

See [`AGENTS.md`](AGENTS.md) and [`tests/AGENTS.md`](tests/AGENTS.md) for scope and test placement rules.
