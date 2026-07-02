# AGENTS.md - crates/traits

Agent-facing map for the shared trait and type crate.

## Scope

This crate owns values and traits that cross crate boundaries:

- `CgkaEngine`
- `TransportPeeler`
- `TransportAdapter`
- Marmot storage traits and `StorageProvider`
- transport envelopes and peeled messages
- group/member/message ids
- engine state and error vocabulary
- app-component value types and the `AppComponentSet`
- the typed `MarmotAppEvent` application-message event
- capability negotiation types
- the `GroupContextSnapshot` group-context view
- agent text stream component, record, and transcript helper types

It should not depend on engine internals, storage implementations, Nostr libraries, or OpenMLS concrete engine types.
OpenMLS appears only where the storage aggregate needs the OpenMLS storage trait bound.

## Key files

| Path | Owns |
| --- | --- |
| `src/engine.rs` | Public engine trait, send/create requests, outputs, group events. |
| `src/storage.rs` | Storage trait aggregate and snapshot/rollback contract. |
| `src/engine_state.rs` | Epoch and welcome state machines. |
| `src/welcome.rs` | `PendingWelcome` pending-welcome persistence record. |
| `src/error.rs` | `EngineError` and `PeelerError` — the engine/peeler error vocabulary. |
| `src/types.rs` | Core id newtypes (`GroupId`/`MemberId`/`MessageId`), `EpochId`, and the `Backend` enum. |
| `src/group.rs` | `Group` and `Member` storage records. |
| `src/message.rs` | `MessageRecord`, `MessageState`, and the `StoredMessagePayload` envelope. |
| `src/peeler.rs` | The `TransportPeeler` crypto-boundary trait. |
| `src/transport.rs` | Transport-facing message envelope types. |
| `src/transport_adapter.rs` | Account-aware adapter trait, publish targets, delivery metadata. |
| `src/ingest.rs` | Peeled-message content and ingest outcomes. |
| `src/app_components/mod.rs` | Shared component ids, schema-name strings, length limits, `AppComponentData`, `AppComponentSet`; re-exports everything so `cgka_traits::app_components::*` paths are unchanged. |
| `src/app_components/codec.rs` | QUIC-varint / var-bytes primitives and the `ComponentsList` encoder. |
| `src/app_components/host_safety.rs` | Canonical public-IP / loopback host classifiers shared by app-component URL policy and media SSRF guards. |
| `src/app_components/routing.rs` | `NostrRoutingV1` state and codec. |
| `src/app_components/encrypted_media.rs` | `EncryptedMediaPolicyV1` / `BlobStoreEndpointV1` state, codec, and endpoint-URL validation. |
| `src/app_components/avatar_url.rs` | `GroupAvatarUrlV1` state, codec, and avatar-URL validation. |
| `src/app_event.rs` | Typed `MarmotAppEvent` application-message event and sender-validation errors. |
| `src/capabilities.rs` | Capability/feature negotiation types and requirement levels. |
| `src/group_context.rs` | `GroupContextSnapshot` group-context view. |
| `src/agent_text_stream.rs` | Agent text stream component policy, record framing, and transcript helpers. |
| `tests/snapshots.rs` | JSON/debug shape checks for cross-boundary types. |
| `tests/error_display.rs` | Asserts `EngineError`/`PeelerError` `Display` output leaks no group/member ids or pubkeys. |

## Verification

```sh
cargo test -p cgka-traits
```

After deliberate snapshot changes:

```sh
cargo insta review
```
