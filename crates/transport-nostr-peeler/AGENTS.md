# AGENTS.md - crates/transport-nostr-peeler

Agent-facing map for the Nostr transport peeler crate. Read [`README.md`](README.md) for the human overview, Welcome
validation checklist, and boundary shape.

## Scope

This crate owns the Nostr transport-edge peeler:

- Nostr-shaped event DTOs,
- mapping kind `445` / `1059` events into `TransportMessage`,
- kind `445` group envelope encryption and decryption (`content = base64(nonce || ciphertext)`, empty AAD),
- per-event ephemeral signing of outbound kind `445` events,
- NIP-59 welcome wrapping/peeling with injected signer/decrypter,
- explicit errors for malformed or unsupported Nostr boundary input.

It must not own relay networking, relay selection, account-device sessions, app message projection, or application
storage. Keep those in adapters or the app layer above this crate.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Public exports and Nostr/Marmot constants. |
| `src/event.rs` | `NostrTransportEvent` DTO and `TransportMessage` conversion. |
| `src/peeler.rs` | `TransportPeeler` implementation for Nostr/MLS group messages. |
| `src/signer.rs` | `MarmotNostrSigner` account signer boundary and `SdkSigner` adapter over rust-nostr's signer traits. |
| `src/error.rs` | Nostr boundary error vocabulary. |

## Boundary validation contract

Default contract for every field read off an ingest path (#709). A new tag or identifier that uses a loose helper or
skips content validation is a contract violation, not a style choice.

- **Routing-significant tags are strict single-tag.** The kind `445` `h` tag, the kind `1059` `p` tag, and the kind
  `444` rumor `e` and `relays` tags are extracted with exactly-one-tag enforcement (`single_tag_value` on the outer
  event, `rumor_single_tag_*` on the rumor). Missing and duplicate tags are both rejected — never first-matched. Any
  future routing-significant tag gets the same treatment.
- **Content-validate at extraction.** Tag values are validated before they surface: ids are hex/length-checked
  (`decode_hex_exact`), and `relays` values are count-bounded (`MAX_WELCOME_RELAYS`), length-bounded
  (`MAX_WELCOME_RELAY_URL_LEN`), and ws/wss-scheme-validated (`RelayUrl::parse`) on both wrap and peel.
- **No self-reported identifier is trusted before verification.** `to_transport_message` verifies the event `id`
  against the recomputed NIP-01 event hash before it becomes `TransportMessage.id` (which keys routing metrics,
  telemetry, and the forensic `wire_id`); a mismatch fails closed on every ingest path, including telemetry-only
  observation. Signature verification still happens at peel time.
- **Loose first-match helpers (`tag_value`, `tag_values`) are for non-routing, genuinely multi-valued fields only**,
  and any such field must carry explicit count/length bounds. Do not reach for them when wiring up a new tag.

## Wire invariants

- Sign each outbound kind `445` event at wrap time with a fresh per-event ephemeral Nostr key; the account identity
  never appears as the outer event pubkey. The event id is final, so the adapter publishes as-is (no pre-signing-id
  replacement). See the Nostr transport spec in [marmot-protocol/marmot](https://github.com/marmot-protocol/marmot).
- Kind `445` content is `base64(nonce || ciphertext)` of a single ChaCha20-Poly1305 sealing under the empty AAD. Do not
  add a source-epoch hint: an undecryptable message returns `DecryptFailed`, and the engine falls back to retained-epoch
  snapshots / deferred-peel retry.
- Welcomes wrap/peel through NIP-59 only with a caller-injected signer/decrypter; this crate must not decide where that
  signer comes from. The kind `444` rumor carries base64 content plus the required `["e", <keypackage event id>]` and
  `["relays", ...]` tags supplied through `wrap_welcome_with_metadata`.

## Verification

```sh
cargo test -p transport-nostr-peeler
```
