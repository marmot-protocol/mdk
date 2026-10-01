# cgka-traits

The shared trait surface and cross-boundary value types for the CGKA stack. Anything that crosses a crate boundary
between engine, peeler, transport adapter, storage, and caller imports from here (`cgka_traits::...`).

## What lives in here

- `CgkaEngine` — the engine trait the rest of the system depends on.
- `TransportPeeler` — async crypto-boundary trait: `peel_group_message`, `peel_welcome`, `wrap_group_message`,
  `wrap_welcome`, plus `wrap_group_message_with_metadata` / `wrap_welcome_with_metadata` (default to the plain wraps).
- `TransportAdapter` — account-aware network boundary for activation, subscription refresh, publish receipts, and
  inbound deliveries.
- `StorageProvider` and the Marmot storage traits it aggregates (groups, messages, outbound intents and fanouts,
  leave/disband requests and tombstones, Welcomes, capabilities, convergence policy and passes, deferred-peel
  generations, member-validation cache, account-device signer, KeyPackage bundles, maintenance) — plus an accessor for
  the underlying OpenMLS storage provider.
- `EpochState`, `WelcomeState`, `IngestOutcome`, `StaleReason`, `EngineError` — the typed state-machine and error
  vocabulary.
- `MessageRecord`, `MessageState`, `StoredMessagePayload` — durable message state plus the typed envelope that
  distinguishes raw transport bytes, delivery-aware outbound Welcomes, and peeled OpenMLS wire bytes.
- Cross-boundary value types: `TransportMessage`, `TransportEnvelope`, `TransportAccountActivation`,
  `TransportPublishRequest`, `TransportDelivery`, `PeeledMessage`, `EncryptedPayload`, `SendIntent`, `SendResult`,
  `AutoPublish`, `GroupEvent`, `PendingStateRef`, `MessageId`, `GroupId`, `MemberId`, `EpochId`, `Group`, `Member`.
- App-component value types: `AppComponentSet`, `AppComponentData`, and typed component states (`NostrRoutingV1`,
  `GroupProfileV1`, `GroupLifecycleV1`, `GroupAvatarUrlV1`, `GroupBlossomImageV1`, frozen `BlobStoreEndpointV1` /
  `EncryptedMediaPolicyV1`, current `BlobStoreEndpointV2` / `EncryptedMediaPolicyV2`), plus the public-IP / loopback
  host classifiers used by the dial-safety rules.
- `MarmotAppEvent` — the typed application-message event — and the poll (NIP-88 profile) and group-report
  interpretations carried in app messages.
- Capability negotiation types: `Capability`, `Feature`, `RequirementLevel`, `CapabilityRequirement`,
  `GroupCapabilities`, `FeatureStatus`.
- `GroupContextSnapshot` — the cross-boundary group-context view.
- Durable convergence-pass and maintenance/publication-recovery records.
- Agent text stream preview values: QUIC policy/component state (`AgentTextStreamQuicPolicyV1`), role/feature bits,
  length-delimited records (`AgentTextStreamRecordV1`), and key-context/transcript-hash helpers
  (`AgentTextStreamKeyContextV1`, `AgentTextStreamTranscriptV1`).

The rustdoc on each trait in `src/` is the reference for method responsibilities: legal states, which errors fire, and
ordering guarantees.

## Key contracts

**Publish-before-apply.** `AutoPublish` follows the same contract as explicit group evolution: callers publish the
message, then confirm or fail the attached `PendingStateRef`.

**Publish receipts.** `TransportEndpointReceipt` carries optional typed ACK detail in `ack_kind`. Rust callers that
construct a receipt must set it, usually to `None` for an injected or reconstructed receipt:

```rust
TransportEndpointReceipt {
    endpoint,
    accepted_at: None,
    ack_kind: None,
}
```

`Some(Affirmative)` means an affirmative endpoint ACK was observed without a typed duplicate marker; `Some(Duplicate)`
means the endpoint reported an already-held exact event; `None` means the detail was unavailable, not that the event
was new. Serialized receipts without `ack_kind` decode as `None`, and `None` is omitted when serializing. `ack_kind`
does not change publish quorum decisions.

## Run the tests

```sh
cargo test -p cgka-traits
cargo bench -p cgka-traits --bench stored_message_codec
```

`tests/snapshots.rs` uses `insta` to lock the JSON / debug shape of cross-boundary value types.

## Stability

Versioned with the workspace; no public consumers outside it. Snapshot tests catch accidental drift; deliberate drift
is a normal trait-evolution change for now.

Agent-facing scope and file map: [`AGENTS.md`](AGENTS.md).
