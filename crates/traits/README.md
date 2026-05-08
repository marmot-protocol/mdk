# cgka-traits

The shared trait surface and cross-boundary value types for the CGKA stack.
Anything that crosses a crate boundary between engine, peeler, storage, and
caller imports from here.

## What lives in here

- `CgkaEngine` — the engine trait the rest of the system depends on.
- `TransportPeeler` — four-method async peeler trait (group-message + welcome × peel + wrap).
- `StorageProvider` and the Marmot storage traits it aggregates
  (`GroupStorage`, `MessageStorage`, `OutboundIntentStorage`,
  `WelcomeStorage`, `CapabilityStorage`, `ConvergencePolicyStorage`) — plus an
  accessor for the underlying OpenMLS `StorageProvider`.
- `EpochState`, `WelcomeState`, `IngestOutcome`, `StaleReason`, `EngineError` — the typed state-machine + error vocabulary.
- All cross-boundary value types: `TransportMessage`, `TransportEnvelope`, `PeeledMessage`, `EncryptedPayload`, `SendIntent`, `SendResult`, `GroupEvent`, `PendingStateRef`, `MessageId`, `GroupId`, `MemberId`, `EpochId`, `Group`, `Member`.

## Run the tests

```sh
cargo test -p cgka-traits
```

`tests/snapshots.rs` uses `insta` to lock the JSON / debug shape of every cross-boundary value type. After a deliberate shape change:

```sh
cargo insta review
```

## Stability

`0.1.0`, no public consumers outside this workspace. Snapshot tests will catch accidental drift; deliberate drift is a normal trait-evolution change for now.

For the responsibility breakdown of each trait method (which states are legal, which errors fire, what ordering guarantees apply), see the rustdoc on each trait in `src/`.
