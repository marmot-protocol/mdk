# marmot-observability

The code that ships a Marmot app's diagnostics off the device, all of it opt-in and off by default:

- **Relay telemetry.** The exporter that maps the relay plane's rollup and the app-performance snapshot into an
  aggregate batch, and, with the `otlp-export` feature, encodes it as OTLP and pushes it to a collector.
- **Product analytics.** The event catalogue and schemas, the in-memory collector with its bounded buckets, the
  usage-diagnostics consent state whose permits gate both exporters, and, with `product-analytics-export`, Aptabase
  delivery.
- **App performance.** The recorder for aggregate operation timings and outcomes, whose snapshots the relay-telemetry
  exporter ships.
- **Audit delivery.** The audit OTLP sender and the HTTP half of the v4 audit upload.
- **Collector dial safety.** The one helper every collector connection goes through: it validates and pins every
  resolved address, disables redirects and system proxies, and builds clients with the host's proxy policy.

It persists nothing and opens no files. In MDK the host is [`marmot-app`](../marmot-app): it keeps consent
receipts, audit files and the other local state, classifies its own errors into this crate's outcome values, records
through an `Observer` handle, and re-exports the types hosts name at their `marmot_app::` paths. Hosts enable
`otlp-export` and `product-analytics-export` on `marmot-app`, which forwards them here.

The API is the crate root. Three modules are public because `marmot-app` names them by path: `product_analytics`
and `audit_otlp_sender`, which hosts reach as `marmot_app::product_analytics` and `marmot_app::audit_otlp_sender`,
and `wiring`, the collector and exporter controls only `marmot-app` calls. The `test-support` feature adds the
fixtures and `_for_test` hooks `marmot-app`'s tests use; only a dev-dependency enables it.

What is collected, and when and where it is sent, is described in
[`docs/marmot-architecture/telemetry.md`](../../docs/marmot-architecture/telemetry.md) and
[`docs/marmot-architecture/usage-diagnostics.md`](../../docs/marmot-architecture/usage-diagnostics.md).

## Run the tests

```sh
cargo test -p marmot-observability --features otlp-export,product-analytics-export
```

See [`AGENTS.md`](AGENTS.md) for the code map and rules.
