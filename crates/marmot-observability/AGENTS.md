# AGENTS.md - crates/marmot-observability

The code that ships diagnostics off the device (step 6 of the 2026-10 architecture review, mdk#2627). Human overview:
[`README.md`](README.md).

## Boundary

- **No `marmot-app`, no storage crate, no `fs-private`.** The direct workspace dependencies are `cgka-traits`,
  `marmot-forensics` (the audit delivery batch types), `transport-nostr` (the relay-telemetry rollup, relay health and
  the retired-relay denylist) and `transport-nostr-adapter` (histogram and relay-label types). `marmot-forensics`
  reaches `fs-private`; nothing here names it. Dependency direction: these crates -> `marmot-observability` ->
  `marmot-app`.
- **Recording never names `AppError`.** Recording methods take this crate's outcome values: the performance outcome,
  the closed set of product outcomes and a storage-failure kind. `marmot-app` classifies its own errors into them
  (its `app_outcome.rs`).
- **The surface is the crate root.** `marmot-app` is the only crate that depends on this one. Every module is private
  except three whose path is part of the surface: `product_analytics` and `audit_otlp_sender`, which `marmot-app`
  re-exports as modules hosts name, and `wiring`, whose functions read only qualified. (`metric_names`, a module of
  constants, is re-exported at the root for the same reason.) An item another crate's production code needs is `pub`
  on its module and re-exported at the root, with every type its signature names; anything else is `pub(crate)`. Do
  not make another module public.
- **`marmot-app` records through `Observer`'s views and runs the collectors through `wiring`.** Hosts name
  `ProductAnalytics`, `AppPerformanceTelemetry`, `ProductObservation`, `DiagnosticsPermit` and `AuditOtlpSender`
  through `marmot-app`'s re-exports, so those types gain no new `pub` method. A recording method goes on a view
  (`ProductRecorder`, `PerformanceRecorder`, `ProductOperation`); starting workers, consent receipts, silencing, the
  telemetry origin, the exporters' runtime config and the audit destination go on `wiring`.
- **No files.** Production code creates and opens no files. `marmot-app` keeps every audit, checkpoint and id file on
  `fs-private` and hands the uploader the open file or the checkpoint record. `clippy.toml` bans std and tokio file
  creation and opening; only a test that writes a temporary file allows the lint.
- **Every collector client goes through `collector_host_safety`.** It validates every resolved address, pins it,
  disables redirects and system proxies, takes TLS trust from the configured URL, and applies the connect and request
  timeouts; loopback is allowed only for an exact loopback test endpoint. It builds clients through the process-wide
  `http_builder` `marmot-app` hands in (`hand_in_http_builder`, the process SOCKS5 policy); until then it builds none,
  so nothing dials. `clippy.toml` bans direct reqwest constructors: allow the lint only where a fresh builder goes
  straight into the helper, or in a test fixture. The audit upload and the audit OTLP sender also reject retired hosts
  before the helper; product analytics and relay telemetry have no denylist (adding one is its own change). See
  `docs/marmot-architecture/overview/dial-safety.md`.
- **Privacy-safe logs only:** explicit `target` and `method` fields and aggregate values
  (`docs/marmot-architecture/overview/observability.md`). Each target is `marmot_observability::<module>`, the module
  that emits the event: `marmot_observability::app_telemetry` or `marmot_observability::relay_telemetry_export` today.

## Code map

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Module declarations and the root re-exports, which are the surface: what hosts name through `marmot-app`, what `marmot-app`'s production code calls, and the `test-support` fixtures. |
| `src/observer.rs` | `Observer`, the runtime's recording handle (the app's shared collector plus the runtime's own performance recorder), and its recorder views. |
| `src/wiring.rs` | What `marmot-app` runs the collectors and exporters through: consent receipts and the consent lock, silencing, the telemetry origin, collector configuration, the product delivery worker, the exporters' runtime config and the audit sender's destination. |
| `src/product_analytics/` | Product analytics: the event catalogue and schemas (`catalogue.rs`, `builtins.rs`), the in-memory collector and its permits (`mod.rs`), the consent state (`consent.rs`), recording outcomes (`recording.rs`, `observed.rs`), Aptabase delivery (`delivery.rs`, behind `product-analytics-export`) and the collector fixtures (`fixtures.rs`). |
| `src/app_telemetry.rs`, `src/app_telemetry/` | The app-performance recorder and its snapshots; runtime operation observations in `app_telemetry/runtime.rs`. |
| `src/relay_telemetry_export.rs` | The relay-telemetry exporter: the privacy mapping (`build_export_batch`) and opt-in gate in the default build, OTLP encoding and push behind `otlp-export`. |
| `src/audit_otlp_sender.rs` | The configured audit OTLP/HTTP sender. |
| `src/audit_upload.rs` | The v4 audit upload's HTTP half: snapshot capture, the checkpoint record, endpoint validation, the request, the response handling and `AuditUploadError`. |
| `src/collector_host_safety.rs` | The collector dial-safety helper and the injected HTTP builder slot. |
| `src/export_config.rs` | The exporters' resolved config and the collector endpoint parsers. |

## Rules

- Nothing collected changes without a deliberate, reviewed change: the same events, properties, buckets, OTLP points
  and audit envelopes, the same consent gating, endpoints, defaults and schedules. The payload, batch and envelope
  tests pin this. Product payloads report `sdkVersion` from this crate's `CARGO_PKG_VERSION`, so the crate keeps
  `version.workspace = true`.
- Consent changes take the consent lock, then the state lock, and fail closed around a durable write; `marmot-app`'s
  consent code reaches the collector only through `wiring`.
- Tests here use only this crate. A test that needs a `MarmotApp`, its runtime or the network-proxy policy belongs in
  `marmot-app`'s `src/observability_tests/`. A test here that dials a loopback collector hands in a direct builder
  (`hand_in_direct_http_builder`).
- What only `marmot-app`'s tests reach is built only with `test-support`, gated `cfg(any(test, feature =
  "test-support"))`, and reaches state through methods, never fields. Free items (the collector fixtures, the
  resolver hook and the collector timeouts) are re-exported from the root's gated block; methods and fields get a
  `_for_test` hook beside their type. A hook only this crate's own tests use is `cfg(test)`. Never widen an item for a
  test alone.

## Features

- `otlp-export`: OTLP protobuf encoding and HTTP push for relay telemetry.
- `product-analytics-export`: product analytics delivery.
- `test-support`: the fixtures and `_for_test` hooks `marmot-app`'s tests use. Enable it only as a dev-dependency.

Hosts enable the first two on `marmot-app`, whose features of the same names forward here.

## Verification

- `cargo nextest run -p marmot-observability --features otlp-export,product-analytics-export`, plus `cargo nextest run
  -p marmot-app --features otlp-export,product-analytics-export --lib -E 'test(/observability_tests|usage_diagnostics/)'`
  for the app-side tests, and CI's "Test consent and both diagnostic exporters" commands.
- `cargo clippy -p marmot-observability --all-targets --all-features --locked -- -D warnings`; a change to a `pub` item
  `marmot-app` uses runs CI's workspace lint once (root `AGENTS.md`).
- Audit OTLP envelope changes also run `just audit-otlp-receiver-contract`.
