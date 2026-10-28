# AGENTS.md - crates/marmot-pairing

Device pairing's short-authentication-string exchange. For the human overview see [`README.md`](README.md).

## Scope

- Keep this crate transport-neutral: no Nostr, relays, storage, async or clocks. Hosts pass every time in. Nostr
  events for these messages belong in `transport-nostr-adapter`'s `pairing` module.
- This crate stops at a verified `ConfirmedLink`. Joining the device group, the link prompt and every other runtime
  flow belong above it.
- The construction is Matrix's `m.sas.v1` transcribed into Marmot encodings, as #2628 decision D18 settled. Never add
  crypto beyond it, and hand-roll none: X25519, HKDF, HMAC and SHA-256 come from `x25519-dalek`, `hkdf`, `hmac` and
  `sha2`. A change to what the commitment, code or confirmations bind is a wire change: regenerate the vectors and
  change the spec with it.

## Layout

- `src/sas.rs`: the commitment, code and confirmation derivations, their labels and binary encodings.
- `src/code.rs`: `SasCode` and Matrix's emoji method, the only one (#2628 D25). `src/emoji.rs`: Matrix's table, verbatim.
- `src/message.rs`: the five messages, their kinds and JSON content.
- `src/new_device.rs`, `src/existing_device.rs`: the two state machines. `src/session.rs`: shared limits, outcomes
  and `ConfirmedLink`. `src/types.rs`: ids and keys.
- `testdata/pairing_vectors.py`: independent implementation that writes `testdata/pairing-v1.json`.

## Rules

- Never log, persist or print a key, shared secret, code, MAC, session id, slot or KeyPackageRef. `SasCode`'s
  `Debug` stays redacted, secrets stay in `Zeroizing` with no `Debug`, and errors carry no ids. Ids, public keys and
  MACs format as hex in `Debug`, as `cgka_traits::GroupId` does: hosts keep them out of logs under the workspace
  tracing rules. Nothing here persists: a session lives in memory and ends with it.
- Every `&mut self` call that takes `now` starts with the role's `tick`, which ends the sessions that ran out by then,
  so their secrets go even if the host never calls `expire`; their timeout cancels wait for `expire`. Never notice a
  timeout anywhere else. Getters treat a session past its deadline as over.
- A device shows a code only once it has both keys, and a user decides once per session. Keep every rejection path
  (commitment, low-order key, MAC, competing requests, rate limit, expiry) ending the session or refusing the call
  before any confirmation goes out.
- Confirmations are ordered (#2628 D26). The existing device's goes first. The new device holds its own until that one
  verifies. The existing device links only on the new device's verified confirmation, and ignores one that arrives
  before its own. On the new device a cancel withdraws a link. Either order would let the existing device add a device
  that never learned which group to trust.
- `src/emoji.rs` is generated from Matrix's `sas-emoji.json`. Never edit an entry by hand; the vectors pin its digest.
- `start_pinned`, `answer_pinned` and the secret probes (`holds_secrets`, `sessions_holding_secrets`) exist for tests,
  under the `test-support` feature. Release code never enables it.

## Verification

```sh
cargo nextest run -p marmot-pairing
cargo clippy -p marmot-pairing --all-targets --all-features --locked -- -D warnings
# After an intentional derivation change, regenerate the vectors (needs Python's `cryptography`):
python3 -I crates/marmot-pairing/testdata/pairing_vectors.py <matrix-spec>/data-definitions/sas-emoji.json
```
