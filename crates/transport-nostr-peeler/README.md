# transport-nostr-peeler

Nostr transport peeler for the Marmot CGKA engine.

This crate sits below `cgka-engine` and above the relay adapter (`transport-nostr-adapter`, which depends on this crate
for Nostr event DTO conversion). It turns Nostr-shaped events into `cgka_traits::TransportMessage` values, and
wraps / peels Marmot group MLS bytes for Nostr kind `445`.

## What this crate does

- Maps kind `445` events with an `h` tag into group `TransportMessage`s.
- Maps kind `1059` events with a `p` tag into welcome `TransportMessage`s.
- Encrypts and decrypts kind `445` group envelopes with ChaCha20Poly1305 (`content = base64(nonce || ciphertext)`,
  empty AAD) using the engine exporter snapshot.
- Carries no source-epoch hint in the kind `445` envelope: an undecryptable message returns `DecryptFailed`, and the
  engine falls back to retained-epoch snapshots / deferred-peel retry rather than a transport-carried epoch.
- Wraps and peels MLS Welcome bytes as NIP-59 gift wraps when a local Nostr signer/decrypter is injected through the
  `MarmotNostrSigner` boundary (`SdkSigner` adapts it to rust-nostr's signer traits).

## What this crate does not do

- No relay connections, subscriptions, retry policy, relay selection, or relay persistence.
- No application session or account-device lifecycle.
- No Nostr SDK key management. The caller supplies the signer/decrypter that already belongs to the account-device
  identity.

## Welcome validation

Welcome peeling fails closed unless all of these hold:

- the outer event is kind `1059` and verifies as a signed Nostr event,
- the event `p` tag matches the `TransportEnvelope::Welcome` recipient,
- NIP-59 unwrap succeeds with the injected local signer/decrypter,
- the NIP-59 seal verifies and the seal signer matches the rumor author,
- the decrypted rumor is Marmot kind `444`,
- the rumor carries an `e` tag holding a 32-byte hex KeyPackage event id,
- the rumor carries a `relays` tag with at least one non-empty relay,
- the rumor content decodes to non-empty MLS Welcome bytes.

## Boundary shape

Inbound group events must be signature-verified before engine admission. The relay adapter uses SDK verification
for SDK events and verifies events supplied through its public DTO boundary. Other callers must authenticate their
source or call `to_verified_nostr_event` before ingesting a DTO; `to_transport_message` checks the hash and routing
shape but does not verify signatures. A public `NostrTransportEvent` is not proof of authenticity.

Group peeling checks the payload's event hash against both the event id and `TransportMessage.id`, enforces the
strict routing tags, and decrypts the envelope without rebuilding an SDK event or verifying Schnorr signatures.
Welcome peeling still decodes an SDK event for NIP-59, whose unwrap verifies the outer event and encrypted seal.

Inbound:

```text
real Nostr event -> NostrTransportEvent -> TransportMessage -> NostrMlsPeeler -> PeeledMessage
```

Outbound:

```text
EncryptedPayload + GroupContextSnapshot -> NostrMlsPeeler -> TransportMessage
```

The outbound `TransportMessage` carries a Nostr DTO payload. Outbound kind `445` events are signed at wrap time with a
fresh ephemeral Nostr key generated per event, so the event id is final and the adapter publishes the event as-is (no
pre-signing-id replacement). Welcome outputs are already signed NIP-59 gift wraps because NIP-59 construction needs the
local signer.

## Run tests

```sh
cargo test -p transport-nostr-peeler
```

See [`AGENTS.md`](AGENTS.md) for the strict tag validation contract. The Nostr transport spec lives in
[marmot-protocol/marmot](https://github.com/marmot-protocol/marmot).
