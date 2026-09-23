# Fork SDK relay qualification for MDK #1358

Loopback-only, synthetic-data experiments pinned to an exact revision of
`erskingardner/rust-nostr`. This directory is an isolated Cargo workspace with
its own lockfile. MDK's production `nostr-sdk = "0.44"` and root lockfile are
unchanged. The test-only `CandidateRelay` implements the existing
`transport-nostr-adapter::NostrRelayClient` seam for subscriptions and sends;
it is deliberately limited to loopback endpoints and is not a production
socket backend.

From the MDK checkout root:

```sh
cargo test --locked --manifest-path experiments/relay-backend-probe/Cargo.toml --target-dir target -- --nocapture
cargo clippy --locked --manifest-path experiments/relay-backend-probe/Cargo.toml --target-dir target --all-targets -- -D warnings
cargo fmt --manifest-path experiments/relay-backend-probe/Cargo.toml --check
```

Tests cover typed notification gaps with continued reception; bounded
acquisition and per-relay MDK-owned evidence; known-inventory reacquisition;
byte and item limits; cancellation with a partial result and live subscription;
Alice/Bob authenticated sessions and explicit anonymous reads; adapter
activation, reactivation, and account removal; and accepted, rejected, and
acknowledgement-unknown publication with zero read queries on publish-only
connections. An ignored diagnostic retains the immediate-reconnect race
reproducer from the earlier 0.45.4 probe.

See [QUALIFICATION.md](QUALIFICATION.md) for limits, outcome mapping, measured
traffic, and the exact production migration gate.
