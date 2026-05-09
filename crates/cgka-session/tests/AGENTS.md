# AGENTS.md - crates/cgka-session/tests

Session integration tests should exercise the public `AccountDeviceSession`
boundary. Keep helper code in `support/` and avoid reaching into engine,
storage, adapter, or peeler internals.

## Nostr stack harness

`support/nostr_stack.rs` is a no-network harness. It uses the real
`NostrTransportAdapter` and `NostrMlsPeeler`, but replaces relay sockets with
an in-memory `NostrRelayClient`.

Use it for production-shaped session/adapter/peeler behavior:

- publish ack/fail lifecycle,
- account inbox and group subscription routing,
- NIP-59 welcome delivery,
- kind `445` group delivery,
- duplicate, dropped, or reordered relay deliveries.

`nostr_stack_chaos.rs` is the seeded chaos runner. Keep chaos reports
reproducible by seed and write artifacts under `target/`, not into the repo.

Do not connect to real relays from these tests.

## Verification

```sh
cargo test -p cgka-session
```
