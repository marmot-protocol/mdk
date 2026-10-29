# marmot-pairing

Device pairing for one Marmot account: the short-authentication-string exchange that links a new device to a device
the account already has. Both screens show the same code only when nobody sat between them, and the user compares the
codes. It ends in a verified result: the new device's exact `KeyPackageRef`, which the existing device may add to the
account's device group, and that group's id, the only group whose Welcome the new device accepts.

Holding the account key never authenticates a device. Every device of the account, and anyone who has stolen its key,
can read and send pairing messages. Only the compared code does.

The crate is transport-neutral and does no I/O. Hosts deliver messages and supply the time; the Nostr events that carry
the messages live in `transport-nostr-adapter`'s `pairing` module.

**Unreleased.** The wire format follows a spec that has not merged. Nothing sends it until it does: the adapter's
`pairing` module builds only with its `unreleased-device-pairing` feature, which no release enables.

## The exchange

The construction is Matrix's `m.sas.v1` (`curve25519-hkdf-sha256`, `hkdf-hmac-sha256.v2`) in Marmot's encodings.

1. The new device sends a **Request** naming its published KeyPackage and committing to a fresh X25519 key.
2. An existing device fetches and validates that KeyPackage, then sends an **Answer** with its own fresh key.
3. The new device takes the first answer and sends a **Reveal** with its key. Each side now derives the code from the
   shared secret, the session, the account, the `KeyPackageRef`, the existing device's slot and both keys.
4. Each user compares the codes and may tap at any time. The existing device's **Confirm** goes first and covers the
   device group's id. The new device sends its own, covering its `KeyPackageRef`, only once that one has verified.
5. When the new device's confirmation verifies, both sides hold the same `ConfirmedLink`. If a confirmation is lost,
   nothing is added: the new device never confirms, or the existing device times out and its cancel withdraws the new
   device's link. Either side may send a **Cancel**.

The rules: no code before an answer, one decision per session, ten minutes for a request and ten more after the answer,
at most ten answers an hour per answering device, and no Link at all while two requests are live.

## Use

```rust
use marmot_pairing::{ExistingDevicePairing, NewDevicePairing, PairingMessage};

// New device.
let (mut pairing, request) = NewDevicePairing::start(account, key_package_event_id, key_package_ref, now);
send(PairingMessage::Request(request));

// Existing device, one per device.
let mut pairing = ExistingDevicePairing::new(account, own_slot);
pairing.receive(&message, created_at, now);
let answer = pairing.answer(&session_id, &fetched_key_package, now)?;
```

Show `code(now)` while it returns one, as the seven emoji from `SasCode::emoji()`, each labelled with its
`description` for screen readers. Call `expire(now)` on a timer while a session is live. It ends sessions that ran out and returns
the cancels to send.

## Code tables

`src/emoji.rs` is Matrix's emoji table, `data-definitions/sas-emoji.json` from
[matrix-org/matrix-spec](https://github.com/matrix-org/matrix-spec).

## Tests

- `tests/vectors.rs`: known answers from `testdata/pairing_vectors.py`, an independent Python implementation, through
  both state machines, plus the emoji table's digest.
- `tests/attacks.rs`: each attack the code defends against, shown failing.
- `tests/lifecycle.rs`: expiry, the rate limit, competing requests and cancellation.
