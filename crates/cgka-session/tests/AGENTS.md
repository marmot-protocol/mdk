# AGENTS.md - crates/cgka-session/tests

Session integration tests exercise the public `AccountDeviceSession` boundary. Keep helper code in `support/` and do
not reach into engine, storage, adapter, or peeler internals. File coverage is summarized in
[`../README.md#tests`](../README.md#tests).

## Nostr stack harness

`support/nostr_stack.rs` is a no-network harness: the real `NostrTransportAdapter` and `NostrMlsPeeler` with relay
sockets replaced by an in-memory `NostrRelayClient`. Use it for production-shaped session/adapter/peeler behavior:
publish ack/fail lifecycle, inbox and group subscription routing, NIP-59 Welcome delivery, kind `445` group delivery,
and duplicate, dropped, or reordered relay deliveries.

`nostr_stack_chaos.rs` is the seeded chaos runner. Keep reports reproducible by seed and write artifacts under
`target/`, never into the repo. Lifecycle chaos stays at the adapter/session boundary: assert routed `IngestOutcome`s
and emitted `GroupEvent`s, not internal engine state.

Never connect to real relays from these tests.

## Fixtures

`../fixtures/session-promotion-v1.bin` backs the promotion-facade regression; see
[`../fixtures/README.md`](../fixtures/README.md) before regenerating or replacing it.

## Verification

```sh
cargo test -p cgka-session
```
