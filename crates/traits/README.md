# cgka-traits

The shared trait surface and cross-boundary value types for the CGKA stack. Anything that crosses a crate boundary
between engine, peeler, storage, and caller imports from here.

## What lives in here

- `CgkaEngine` — the engine trait the rest of the system depends on.
- `TransportPeeler` — five-method async peeler trait (group-message + welcome × peel + wrap, plus
  `wrap_welcome_with_metadata`).
- `TransportAdapter` — account-aware network boundary for activation, subscription refresh, publish receipts, and
  inbound deliveries.
- `StorageProvider` and the Marmot storage traits it aggregates (`GroupStorage`, `MessageStorage`,
  `OutboundIntentStorage`, `WelcomeStorage`, `CapabilityStorage`, `ConvergencePolicyStorage`,
  `AccountDeviceSignerStorage`) — plus an accessor for the underlying OpenMLS `StorageProvider`.
- `EpochState`, `WelcomeState`, `IngestOutcome`, `StaleReason`, `EngineError` — the typed state-machine + error
  vocabulary.
- `MessageRecord`, `MessageState`, `StoredMessagePayload` — durable message state plus the typed envelope that
  distinguishes raw transport bytes from peeled OpenMLS wire bytes.
- All cross-boundary value types: `TransportMessage`, `TransportEnvelope`, `TransportAccountActivation`,
  `TransportPublishRequest`, `TransportDelivery`, `PeeledMessage`, `EncryptedPayload`, `SendIntent`, `SendResult`,
  `AutoPublish`, `GroupEvent`, `PendingStateRef`, `MessageId`, `GroupId`, `MemberId`, `EpochId`, `Group`, `Member`.
- App-component value types: `AppComponentSet`, `AppComponentData`, and the typed component states
  (`NostrRoutingV1`, `BlobStoreEndpointV1`, `EncryptedMediaPolicyV1`, `GroupAvatarUrlV1`).
- `MarmotAppEvent` — the typed application-message event (in `app_event.rs`).
- Capability negotiation types: `Capability`, `Feature`, `RequirementLevel`, `CapabilityRequirement`,
  `GroupCapabilities`, `FeatureStatus`.
- `GroupContextSnapshot` — the cross-boundary group-context view.
- Agent text stream preview values: QUIC policy/component state (`AgentTextStreamQuicPolicyV1`), role/feature bits,
  length-delimited stream records (`AgentTextStreamRecordV1`), and key-context/transcript-hash helpers
  (`AgentTextStreamKeyContextV1`, `AgentTextStreamTranscriptV1`).

`AutoPublish` follows the same publish-before-apply contract as explicit group evolution: callers publish the message,
then confirm or fail the attached `PendingStateRef`.

## Run the tests

```sh
cargo test -p cgka-traits
```

`tests/snapshots.rs` uses `insta` to lock the JSON / debug shape of every cross-boundary value type. After a deliberate
shape change:

```sh
cargo insta review
```

## Stability

`0.1.0`, no public consumers outside this workspace. Snapshot tests will catch accidental drift; deliberate drift is a
normal trait-evolution change for now.

For the responsibility breakdown of each trait method (which states are legal, which errors fire, what ordering
guarantees apply), see the rustdoc on each trait in `src/`.
