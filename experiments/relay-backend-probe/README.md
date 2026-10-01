# Fork SDK relay qualification for MDK #1358

Loopback-only, synthetic-data experiments that qualified the `erskingardner/rust-nostr` fork SDK against MDK's relay
transport seam before production adopted it. Read this if you need to re-run that qualification or reuse its
measurements; it is not part of the production build.

This directory is an isolated Cargo workspace with its own lockfile, pinned to the exact fork revision it qualified
(see `Cargo.toml`). It does not change the root workspace's dependency graph; production MDK has since adopted the fork
at its own pinned revision in the root `Cargo.toml` (MDK #2009). The test-only `CandidateRelay` implements the existing
`transport-nostr-adapter::NostrRelayClient` seam for subscriptions and sends; it is deliberately limited to loopback
endpoints and is not a production socket backend.

## Run

From the MDK checkout root:

```sh
cargo test --locked --manifest-path experiments/relay-backend-probe/Cargo.toml --target-dir target -- --nocapture
cargo clippy --locked --manifest-path experiments/relay-backend-probe/Cargo.toml --target-dir target --all-targets -- -D warnings
cargo fmt --manifest-path experiments/relay-backend-probe/Cargo.toml --check
```

## Coverage

Tests cover typed notification gaps with continued reception; bounded acquisition and per-relay MDK-owned evidence;
known-inventory reacquisition; byte and item limits; cancellation with a truthful partial report and live
subscription; Alice/Bob authenticated sessions and explicit anonymous reads; adapter activation, reactivation, and
account removal; accepted, rejected, and acknowledgement-unknown publication with zero read queries on publish-only
connections; and a same-relay immediate-reconnect regression that checks restored live delivery.

See [QUALIFICATION.md](QUALIFICATION.md) for limits, outcome mapping, measured traffic, and the production migration
gate.
