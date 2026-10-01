# AGENTS.md - crates/traits

Agent map for the shared trait and type crate.

## Scope

Values and traits that cross crate boundaries (engine, peeler, transport adapter, storage, callers). The human list of
what lives here is in [`README.md`](README.md#what-lives-in-here).

- Do not depend on engine internals, storage implementations, Nostr libraries, or OpenMLS concrete engine types.
  OpenMLS appears only where the storage aggregate needs the OpenMLS storage trait bound (`openmls_traits`).
- Keep `cgka_traits::app_components::*` paths stable: `app_components/mod.rs` re-exports every submodule.
- Cross-boundary types must keep their `insta` snapshots current; error `Display` must not leak ids or pubkeys.

## Key files

| Path | Owns |
| --- | --- |
| `src/engine.rs` | Public engine trait, send/create requests, outputs, group events. |
| `src/storage.rs` | Storage traits, the `StorageProvider` aggregate (`type Mls` / `mls_storage()`), and the snapshot/rollback contract. |
| `src/engine_state.rs` | Epoch and welcome state machines. |
| `src/welcome.rs` | `PendingWelcome` pending-welcome persistence record. |
| `src/error.rs` | `EngineError` and `PeelerError` — the engine/peeler error vocabulary. |
| `src/types.rs` | Core id newtypes (`GroupId`/`MemberId`/`MessageId`), `EpochId`, and the `Backend` enum. |
| `src/group.rs` | `Group` and `Member` storage records. |
| `src/message.rs` | `MessageRecord`, `MessageState`, and the `StoredMessagePayload` envelope. |
| `src/peeler.rs` | The `TransportPeeler` crypto-boundary trait (wasm32 builds drop the `Send` bound). |
| `src/transport.rs` | Transport-facing message envelope types. |
| `src/transport_adapter.rs` | Account-aware adapter trait, publish targets, delivery metadata. |
| `src/ingest.rs` | Peeled-message content and ingest outcomes. |
| `src/app_components/mod.rs` | Shared component ids, schema-name strings, length limits, `AppComponentData`, `AppComponentSet`; re-exports everything so `cgka_traits::app_components::*` paths are unchanged. |
| `src/app_components/codec.rs` | QUIC-varint / var-bytes primitives and the `ComponentsList` encoder. |
| `src/app_components/host_safety.rs` | Canonical public-IP / loopback host classifiers shared by app-component URL policy and media SSRF guards. |
| `src/app_components/routing.rs` | `NostrRoutingV1` state and codec. |
| `src/app_components/profile.rs` | `GroupProfileV1` state and codec. |
| `src/app_components/blossom_image.rs` | `GroupBlossomImageV1` state, codec, and Marmot media-type canonicalization. |
| `src/app_components/encrypted_media.rs` | Frozen `EncryptedMediaPolicyV1` / `BlobStoreEndpointV1` state, codec, and endpoint-URL validation. |
| `src/app_components/encrypted_media_v2.rs` | Current `marmot.group.encrypted-media.v2` state and codec. |
| `src/app_components/lifecycle.rs` | `GroupLifecycleV1` (`marmot.group.lifecycle.v1`) authenticated terminal lifecycle state. |
| `src/app_components/tests.rs` | Byte-level component codec unit tests. |
| `src/app_components/avatar_url.rs` | `GroupAvatarUrlV1` state, codec, wire URL validation, and contact-safety helper. |
| `src/app_event.rs` | Typed `MarmotAppEvent` application-message event and sender-validation errors. |
| `src/capabilities.rs` | Capability/feature negotiation types and requirement levels. |
| `src/group_context.rs` | `GroupContextSnapshot` group-context view. |
| `src/agent_text_stream.rs` | Agent text stream component policy, record framing, and transcript helpers. |
| `src/convergence_pass.rs` | Durable state for one bounded convergence pass. |
| `src/maintenance.rs` | Durable maintenance and publication-recovery value types. |
| `src/polls.rs` | Bounded Marmot profile of NIP-88 polls carried in MLS app messages. |
| `src/reporting.rs` | Typed group reports, dismissal labels, and admin deletion. |
| `tests/snapshots.rs` | JSON/debug shape checks for cross-boundary types. |
| `tests/error_display.rs` | Asserts `EngineError`/`PeelerError` `Display` output leaks no group/member ids or pubkeys. |
| `tests/host_safety_public.rs` | Public host-safety classifier surface (`reject_non_public_ip` and friends). |
| `tests/async_send.rs` | Native-only `Send` bounds on async trait futures. |
| `benches/stored_message_codec.rs` | `StoredMessagePayload` codec benchmark. |

## Verification

```sh
cargo test -p cgka-traits
```

After deliberate snapshot changes:

```sh
cargo insta review
```
