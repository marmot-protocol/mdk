# AGENTS.md - crates/transport-nostr

Agent map for the relay plane crate. Human overview: [`README.md`](README.md). Its extraction from `marmot-app` follows
the [relay-plane brief](../../docs/marmot-architecture/review/brief-relay-plane.md).

## Scope

The shared, process-wide relay plane: relay sessions, per-account delivery and overflow, notification forwarding and
lag repair, publish accounting, relay telemetry, directory fetches and subscriptions, and the relay host-safety
chokepoint. It depends on `transport-nostr-adapter`, `transport-nostr-peeler`, `cgka-traits` and `nostr-sdk`; it must
not depend on `marmot-app` or `storage-sqlite`. The app supplies storage and policy through callbacks and traits
(`AccountDeliverySpillStore`, `AccountDeliveryRecoveryMarker`, `RelayExportGate`).

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | `MarmotRelayPlane`: relay sessions, per-account delivery queues and publish clients, notification forwarding, lag repair, publish accounting, `nostr_builder()`. |
| `src/delivery_spill.rs` | The plane's side of the durable overflow tail: when a full queue spills and how it reports the disposition. |
| `src/directory.rs`, `src/directory_wire.rs` | Directory fetches and subscriptions, and their relay wire handling. |
| `src/safety.rs` | `RelaySafetyPolicy`: the host-safety chokepoint every relay endpoint passes before a connect. |
| `src/telemetry.rs` | Relay telemetry snapshots and the export rollup. |
| `src/test_support.rs` | Publish-accounting fixtures shared with `marmot-app`'s tests (`test-support` feature). |

## Rules

- Route every relay endpoint through `RelaySafetyPolicy` and build every relay client with `nostr_builder()`;
  `clippy.toml` rejects direct `nostr_sdk` client constructors. See
  `docs/marmot-architecture/overview/dial-safety.md`.
- Keep logs privacy-safe: aggregate values only, no account ids, group ids, relay URLs, pubkeys or payloads. The
  tracing target stays `marmot_app::relay_plane` until the brief's later rename.
- Handle a new kind of SDK notification in `transport_nostr_adapter::dispatch_sdk_notification`, which this crate's
  consumer and the adapter's test forwarder share; the consumer adds only queueing, lag repair and loss accounting.
- Test hooks and accessors (`*_for_test`, `test_support`) are `cfg(any(test, feature = "test-support"))`.
  `marmot-app` enables `test-support` only through its dev-dependency; never enable it in app artifacts.
- Widen an item to `pub` only when another crate names it. `marmot-app` re-exports `MarmotRelayPlane` and
  `MarmotRelayPlaneAccountAdapter` to hosts, so methods on them that only the app calls are `#[doc(hidden)] pub`.
- Construct `MarmotRelayPlane` inside a Tokio runtime. `spawn_router` returns early without one, so construction
  succeeds and nothing is routed. Follow-up: take an explicit runtime handle.
- Shutdown aborts the router and the notification forwarders, but does not join the spill writer (`delivery_spill.rs`
  spawns `write()`), the loss-marker task (`persist_marker_before_drop`) or the directory fetch tasks; the plane
  registers nothing in the app's close registry (#2341). Follow-up: join or register them.
- The plane owns each account's signer-bound publish client (`account_publish_client`). Order matters: the signer is
  installed before activation, and the client is evicted (`evict_account_publish_client`) before its account reopens
  or its signer is replaced, because a cache hit ignores the signer passed in.

## Verification

```sh
cargo clippy -p transport-nostr --all-targets --all-features --locked -- -D warnings
cargo nextest run -p transport-nostr --all-features
```

Changes that alter what `marmot-app` sees also need its relay tests:
`cargo nextest run -p marmot-app --lib --features test-policy-overrides,otlp-export -E 'test(/^(tests::relay_plane_runtime|relay_telemetry_export)::/)'`.
