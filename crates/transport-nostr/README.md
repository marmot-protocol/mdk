# transport-nostr

Marmot's Nostr relay plane: the long-lived owner of relay sessions that every account in a process shares. It sits on
top of [`transport-nostr-adapter`](../transport-nostr-adapter/README.md), which handles single relay subscriptions and
publishes, and below [`marmot-app`](../marmot-app/README.md), which drives it per account.

## What this crate does

- Runs the relay client the process's accounts share and a delivery queue per account, with a durable overflow tail
  (`delivery_spill.rs`) when an account's queue is full.
- Forwards relay notifications to the right account, re-issues subscriptions after notification lag, and reports the
  losses it could not repair.
- Builds and caches each account's signer-bound publish client, so setup publishes and the account worker share one
  relay pool.
- Counts each account's publishes, and keeps relay telemetry snapshots and the export rollup (`telemetry.rs`).
- Fetches directory events by author and kind, and keeps the directory subscriptions the app asks for
  (`directory.rs`).
- Filters every relay endpoint through `RelaySafetyPolicy` (`safety.rs`) before any connect.

## What this crate does not do

- No account or group state: the app owns storage, recovery decisions and the delivery spill's storage, and hands the
  plane callbacks for them.
- No MLS peeling (`transport-nostr-peeler`) and no relay socket mechanics (`transport-nostr-adapter`, `nostr-sdk`).

`marmot-app` drives it through `transport_nostr::`. See the
[relay-plane brief](../../docs/marmot-architecture/review/brief-relay-plane.md) for how it moved out of the app.
