---
title: "Telemetry, Logging, and Tracing Inventory"
created: 2026-06-10
updated: 2026-06-10
tags: [marmot, architecture, telemetry, logging, tracing, privacy]
status: current
---

# Telemetry, Logging, and Tracing Inventory

This is a source-grounded inventory of the telemetry, logging, and tracing surfaces currently present in the app
runtime. It complements the policy docs:

- [`overview/observability.md`](./overview/observability.md) defines what runtime tracing/logging may contain.
- [`relay-delivery-telemetry.md`](./relay-delivery-telemetry.md) explains the relay/convergence measurement model.
- [`relay-observability.md`](./relay-observability.md) explains the opt-in relay telemetry export privacy contract.

## Current status

| Surface | Current state | Leaves device? | Primary source |
| --- | --- | --- | --- |
| Structured tracing/logging | Code uses `tracing` macros with explicit `target` and `method` fields. The app/CLI does not install a global tracing subscriber in the current source, so host apps or tests decide whether these events are collected. | No, unless a host installs and exports a subscriber. | [`overview/observability.md`](./overview/observability.md), [`tracing_audit.rs`](../../crates/cgka-conformance-simulator/tests/tracing_audit.rs) |
| Device-local relay telemetry | Always collected by the shared Nostr relay plane while it runs: lifecycle counters, delivery-spread histograms, sync timing, and redacted relay health. | No. Exposed locally via `MarmotApp::relay_telemetry`, runtime `relay_plane().relay_telemetry()`, and `dm relay-stats`. | [`relay_plane.rs`](../../crates/marmot-app/src/relay_plane.rs), [`telemetry.rs`](../../crates/transport-nostr-adapter/src/telemetry.rs) |
| Device-local app performance telemetry | Always available inside `RuntimeSharedServices` while the runtime exists: aggregate duration histograms plus attempts/success/failure counters for startup, directory subscription sync, account reconcile/open/sync/catch-up, one-sided outbound message send, and media upload/download. | No by itself. Included in the OTLP export batch only after the same opt-in export gate passes. | [`app_telemetry.rs`](../../crates/marmot-app/src/app_telemetry.rs), [`runtime.rs`](../../crates/marmot-app/src/runtime.rs) |
| Opt-in telemetry export | Implemented and off by default. Requires opt-in settings to be persisted, plus runtime endpoint, bearer token, and resource metadata. OTLP wire encoding and HTTP push are behind the `otlp-export` feature. Exports relay metrics and app-performance metrics in one batch. | Yes, only after the export gate passes. Relay URL is the only metric label, and only relay metrics may carry it; app-performance metrics are unlabeled population metrics. | [`relay_telemetry_export.rs`](../../crates/marmot-app/src/relay_telemetry_export.rs), [`config.rs`](../../crates/marmot-app/src/config.rs) |
| Engine reorg telemetry | Implemented inside `cgka-engine` as aggregate post-settle reorg counters/histograms. Exposed by `Engine::engine_metrics()`. The relay-plane/export structs have an optional seam for it, but the periodic runtime exporter currently passes `None`. | No via the runtime exporter today. Engine metrics can be exported only if a caller explicitly folds a snapshot into the rollup/batch. | [`engine_metrics.rs`](../../crates/cgka-engine/src/engine_metrics.rs), [`relay_plane.rs`](../../crates/marmot-app/src/relay_plane.rs) |
| Product analytics / crash reporting | No product analytics or crash reporting SDK integration was found in the current source. Aptabase is mentioned only as future product-analytics context in a doc; it is not wired. | No. | Workspace search on 2026-06-10 |

## Source map

| Area | Files |
| --- | --- |
| Privacy policy and tracing guardrail | [`docs/marmot-architecture/overview/observability.md`](./overview/observability.md), [`crates/cgka-conformance-simulator/tests/tracing_audit.rs`](../../crates/cgka-conformance-simulator/tests/tracing_audit.rs) |
| Nostr adapter counters and local timing | [`crates/transport-nostr-adapter/src/lib.rs`](../../crates/transport-nostr-adapter/src/lib.rs), [`crates/transport-nostr-adapter/src/telemetry.rs`](../../crates/transport-nostr-adapter/src/telemetry.rs), [`crates/transport-nostr-adapter/src/sdk_client.rs`](../../crates/transport-nostr-adapter/src/sdk_client.rs) |
| Relay plane local snapshot and export rollup | [`crates/marmot-app/src/relay_plane.rs`](../../crates/marmot-app/src/relay_plane.rs) |
| App performance telemetry snapshot | [`crates/marmot-app/src/app_telemetry.rs`](../../crates/marmot-app/src/app_telemetry.rs), [`crates/marmot-app/src/runtime.rs`](../../crates/marmot-app/src/runtime.rs) |
| Relay telemetry settings and export config | [`crates/marmot-app/src/config.rs`](../../crates/marmot-app/src/config.rs), [`crates/storage-sqlite/src/shared.rs`](../../crates/storage-sqlite/src/shared.rs) |
| OTLP export batch and push | [`crates/marmot-app/src/relay_telemetry_export.rs`](../../crates/marmot-app/src/relay_telemetry_export.rs) |
| Runtime lifecycle wiring | [`crates/marmot-app/src/runtime.rs`](../../crates/marmot-app/src/runtime.rs) |
| CLI/local inspection | [`crates/cli/src/lib.rs`](../../crates/cli/src/lib.rs), [`crates/cli/README.md`](../../crates/cli/README.md) |
| UniFFI settings bridge | [`crates/marmot-uniffi/src/lib.rs`](../../crates/marmot-uniffi/src/lib.rs), [`crates/marmot-uniffi/src/conversions.rs`](../../crates/marmot-uniffi/src/conversions.rs) |
| Engine post-settle reorg metrics | [`crates/cgka-engine/src/engine_metrics.rs`](../../crates/cgka-engine/src/engine_metrics.rs), [`crates/cgka-engine/src/engine.rs`](../../crates/cgka-engine/src/engine.rs) |

## What is collected locally

### Adapter lifecycle counters

`NostrAdapterMetrics` is returned by `NostrTransportAdapter::metrics()` and included in
`RelayTelemetrySnapshot.metrics`.

| Field | Meaning | Sensitivity |
| --- | --- | --- |
| `active_accounts` | Number of account routes currently active in the shared adapter. | Aggregate count. |
| `active_group_subscriptions` | Number of group subscriptions currently active across accounts. | Aggregate count. |
| `subscriptions_created` | Cumulative subscriptions issued by activation/sync. | Aggregate count. |
| `subscriptions_removed` | Cumulative subscriptions removed by replacement, sync, or deactivation. | Aggregate count. |
| `inbound_events_seen` | Deduplicated relay events passed into the delivery path. | Aggregate count. |
| `inbound_events_delivered` | Account-scoped deliveries successfully enqueued. A single event may deliver to more than one account route. | Aggregate count. |
| `inbound_events_dropped` | Deduplicated relay events with no matching active route. | Aggregate count. |
| `publish_attempts` | Publish attempts through the adapter. | Aggregate count. |
| `publish_successes` | Publish calls where the relay client returned an outcome. | Aggregate count. |
| `publish_failures` | Publish calls where the relay client returned an error. | Aggregate count. |

These counters are diagnostic only. They must not feed convergence or branch selection.

### Cross-relay delivery spread

`RelayDeliveryTelemetry` records one local-time sighting per logical `MessageId` and per opaque relay index. Its
snapshot is `RelayDeliverySpread`, included as `RelayTelemetrySnapshot.delivery_spread`.

| Field | Meaning | Sensitivity |
| --- | --- | --- |
| `observed` | Distinct logical messages first observed within the tracking table. | Aggregate count. |
| `corroborated` | Messages seen from at least two distinct relays before pruning. | Aggregate count. |
| `single_source` | Messages pruned after being seen from exactly one relay. | Aggregate count. |
| `spread` | Histogram of local-time delta from first relay copy to each later distinct-relay copy. | Histogram buckets only. |
| `per_relay[].relay_index` | Opaque device-local relay index. | Local-only index; not a URL. |
| `per_relay[].delivered_first` | Times this relay index surfaced a copy first. | Per-relay local count by opaque index. |
| `per_relay[].delivered_later` | Times this relay index corroborated a message after another relay surfaced it first. | Per-relay local count by opaque index. |

Derived value: `RelayDeliveryStats::first_deliverer_rate()` returns
`delivered_first / (delivered_first + delivered_later)`.

Important details:

- The clock is the adapter's local monotonic clock, never Nostr `created_at`.
- The tracking table is pruned after `60_000ms`; messages that never get a second relay copy before pruning increment
  `single_source`.
- Re-delivery of the same message by the same relay is ignored for spread.
- A third relay copy adds another spread sample, but does not increment `corroborated` again.

### Subscription sync timing

`RelaySyncTelemetry` records subscription start, first event, and EOSE timing per subscription and opaque relay index.
Its snapshot is `RelaySyncSnapshot`, included as `RelayTelemetrySnapshot.sync`.

| Field | Meaning | Sensitivity |
| --- | --- | --- |
| `tracked_subscriptions` | Number of subscriptions currently tracked for sync timing. | Aggregate count. |
| `synced_subscriptions` | Tracked subscriptions where every relay has reached EOSE. | Aggregate count. |
| `first_event` | Aggregate histogram of time from subscription start to first event. | Histogram buckets only. |
| `eose` | Aggregate histogram of time from subscription start to EOSE. | Histogram buckets only. |
| `per_relay[].relay_index` | Opaque device-local relay index. | Local-only index; not a URL. |
| `per_relay[].first_event` | Per-relay first-event latency histogram. | Histogram by opaque index. |
| `per_relay[].eose` | Per-relay EOSE latency histogram. | Histogram by opaque index. |

`NostrTransportAdapter::subscription_synced(subscription_id)` can answer whether every relay in a tracked subscription
has reached EOSE, but subscription ids are not included in telemetry snapshots.

### Duration histogram shape

Relay delivery-spread, first-event, and EOSE histograms use the same inclusive millisecond bucket bounds:

```text
1, 2, 5, 10, 20, 30, 50, 75, 100, 150, 200, 300, 500, 750,
1000, 1500, 2000, 3000, 5000, 7500, 10000, 15000, 20000, 30000
```

`DurationHistogramSnapshot` contains:

| Field | Meaning |
| --- | --- |
| `buckets[].upper_bound_ms` | Inclusive bucket upper bound. |
| `buckets[].count` | Samples in that bucket. |
| `overflow_count` | Samples above `30000ms`. |

`approx_percentile_ms()` returns the upper bound of the bucket containing the requested percentile, `None` when there
are no samples, and `None` if the percentile falls in overflow.

### Relay-plane health

`RelayPlaneHealth` is included in `RelayTelemetrySnapshot.health`. When the relay plane is backed by `nostr-sdk`,
`NostrSdkRelayHealth` summarizes SDK relay status without relay URLs. The relay plane also adds directory-sync counters.

| Field | Meaning | Exported today? |
| --- | --- | --- |
| `sdk_backed` | Whether the relay plane is backed by `nostr-sdk`. | No. |
| `total_relays` | Number of relays known to the SDK client. | No. |
| `initialized`, `pending`, `connecting`, `connected`, `disconnected`, `terminated`, `banned`, `sleeping` | Counts of relays in each SDK status. | No. |
| `connection_attempts` | Sum of SDK relay connection attempts. | Yes, as `relay_connection_attempts`. |
| `connection_successes` | Sum of SDK relay connection successes. | Yes, as `relay_connection_successes`. |
| `directory_inflight_fetches` | Directory fetches currently in flight. | No. |
| `directory_active_subscriptions` | Active directory subscription ids. | No. |
| `directory_completed_fetches` | Completed directory fetches. | No. |
| `directory_coalesced_waiters` | Fetch waiters coalesced onto an existing request. | No. |
| `directory_failed_fetches` | Failed directory fetches. | No. |
| `directory_completed_subscription_syncs` | Completed directory subscription sync passes. | No. |
| `directory_subscriptions_created` | Directory subscriptions created. | No. |
| `directory_subscriptions_removed` | Directory subscriptions removed. | No. |

### Engine post-settle reorg metrics

`EngineMetrics` lives inside `cgka-engine` and is read through `Engine::engine_metrics()`. It is not part of
`RelayTelemetrySnapshot`. The relay-plane export rollup has an optional `EngineReorgMetrics` field, but the current
periodic exporter passes `None` for that engine snapshot, so engine metrics are not sent by the runtime exporter today.

| Field | Meaning |
| --- | --- |
| `settles` | Times a group reached `Settled` and applied a branch, summed across groups. |
| `post_settle_reorgs` | Settles later superseded by a branch that diverged below the previously applied tip. |
| `reorg_rewind_depth` | Histogram in commits: `previous_applied_tip - new_fork_epoch`. |
| `reorg_lateness_ms` | Histogram in milliseconds: local time from superseded settle to reorg. |
| `observed_reorg_rate()` | Derived `post_settle_reorgs / settles`, `None` with no settles. |

`reorg_lateness_ms` uses the same millisecond bucket bounds as relay timing. `reorg_rewind_depth` uses commit-count
buckets:

```text
1, 2, 3, 4, 5, 6, 8, 10, 16, 32
```

Engine metrics keep an in-memory per-group last-applied branch record for classification, but snapshots contain only
aggregate counts and histograms.

### App performance telemetry

`AppPerformanceTelemetry` lives in `RuntimeSharedServices` and exposes an `AppPerformanceSnapshot`. Each operation has
the same shape:

| Field | Meaning | Sensitivity |
| --- | --- | --- |
| `attempts` | Cumulative operation attempts since process start. | Aggregate count. |
| `successes` | Cumulative successful operations since process start. | Aggregate count. |
| `failures` | Cumulative failed operations since process start. | Aggregate count. |
| `duration_ms` | Cumulative fixed-bucket duration histogram, measured with local monotonic time. | Histogram buckets only. |

Collected operations:

| Operation | Measurement envelope | Notes |
| --- | --- | --- |
| `app_start` | `MarmotAppRuntime::start()`, from method entry through directory-storage warmup, telemetry config construction, directory subscription sync, account reconciliation, and running-state mark. | Success means `start()` reached exporter configuration; the sample is recorded before the exporter task starts so the first export can include it. |
| `directory_subscription_sync` | `MarmotAppRuntime::sync_user_directory_subscriptions()`, including directory worker creation if needed and `request_rebuild_and_wait()`. | Covers how long the directory subscription rebuild path takes to become ready. |
| `account_reconcile` | `AccountManager::reconcile()`, including local-signing account enumeration, stale-worker stop, pending-worker spawn, and ready wait. | Recorded every time reconcile runs, including implicit reconcile before catch-up. |
| `account_open` | One sample per newly spawned account worker, from worker spawn until the ready signal. | The ready signal is sent after runtime client construction and startup `client.sync()`, so this is an account-ready envelope rather than just database/session open. |
| `account_catch_up` | `AccountManager::catch_up_accounts()`, including its reconcile step, catch-up command fanout, and waiting for every worker response. | Multi-account aggregate. |
| `account_sync` | Each account worker `client.sync()` during startup and catch-up. | Coarse envelope for transport activation, subscription setup, relay data drain, processing, projection/state update, and returning a `SyncSummary`. |
| `outbound_message_send` | Worker `SendMessage` and `SendAppEvent` commands until their send call returns a `SendSummary` or error. | One-sided local send/publish confirmation only. It is not end-to-end remote delivery or read latency. |
| `media_upload` | Worker `UploadMedia` command until `client.upload_media()` returns. | Measures local encryption/upload pipeline and endpoint response time as seen by this device. |
| `media_download` | Worker `DownloadMedia` command until `client.download_media()` returns. | Measures local fetch/decrypt pipeline and endpoint response time as seen by this device. |

App-performance histograms use wider inclusive millisecond bucket bounds than relay timing so startup and media transfer
latencies do not immediately fall into overflow:

```text
1, 2, 5, 10, 20, 30, 50, 75, 100, 150, 200, 300, 500, 750,
1000, 1500, 2000, 3000, 5000, 7500, 10000, 15000, 20000, 30000,
60000, 120000, 300000
```

These app-performance samples deliberately do not include account labels, account ids, group ids, message ids, relay
URLs, media URLs, payload sizes, content types, upload endpoints, download endpoints, or error strings.

## How local relay telemetry is recorded

The Nostr relay plane intentionally splits delivery from telemetry:

| Tap | Source notification | What it does | What it avoids |
| --- | --- | --- | --- |
| Delivery tap | `RelayPoolNotification::Event` | Converts the deduplicated Nostr event into a `TransportMessage`, routes it to matching account/group queues, and increments inbound lifecycle counters. | It does not record delivery spread or first-event timing because this SDK path only sees the first copy across the pool. |
| Telemetry tap | Raw `RelayPoolNotification::Message::Event` | Observes every relay copy, assigns/uses an opaque `RelayIndex`, records cross-relay spread, and records first-event latency for the subscription. | It performs no delivery. |
| EOSE tap | Raw `RelayPoolNotification::Message::EndOfStoredEvents` | Records per-relay EOSE latency and advances the initial-sync gate. | It performs no delivery. |

The opaque `RelayIndex` to relay URL map is held in `RelayIndexRegistry`. A reverse lookup is available only through
`resolve_relay_labels(RelayExportConsent)`, and the relay plane only mints that consent after export is opted in and the
export config passes validation.

## Local inspection surfaces

`dm relay-stats` prints the current process/runtime's `RelayTelemetrySnapshot` as human text. `dm relay-stats --json`
serializes the full snapshot shape. The plain text intentionally says:

```text
relay telemetry (device-local, aggregate, no relay URLs)
```

The command shows:

- adapter lifecycle counters;
- delivery spread observed/corroborated/single-source counts;
- delivery spread p50 and p99 derived from histogram buckets;
- subscription sync p50 first-event and EOSE latency;
- one per-relay row per opaque relay index, never a relay URL;
- redacted relay health counts.

## Persisted settings and runtime configuration

Relay telemetry export settings are stored in shared SQLite, one row per app root:

| Table | Field | Meaning |
| --- | --- | --- |
| `relay_telemetry_settings` | `export_enabled` | Persisted opt-in switch. Default `false`. |
| `relay_telemetry_settings` | `export_interval_seconds` | Persisted poll/push interval. Default `60`. Must be from `10` through `3600` seconds. |
| `relay_telemetry_settings` | `updated_at_ms` | Local wall-clock update time in milliseconds. |
| `telemetry_install` | `install_id` | Stable random UUID-like install id generated per app root. Host apps can use it as OTLP `service.instance.id`. |
| `telemetry_install` | `updated_at_ms` | Local wall-clock update time in milliseconds. |

The OTLP endpoint itself is not persisted in the current schema. If a legacy `otlp_endpoint` column exists,
`SqliteSharedStorage::clear_legacy_relay_telemetry_endpoint()` clears it.

Runtime-only config is supplied by the host app:

| Field | Meaning | Persisted by Marmot? |
| --- | --- | --- |
| `RelayTelemetryRuntimeConfig.otlp_endpoint` | Optional full OTLP/HTTP metrics URL override. If absent, the app can use the compiled/default endpoint. | No. |
| `authorization_bearer_token` | Bearer token from host/platform secret storage. | No. |
| `resource` | OTLP resource attributes from the platform shell. | No. |

Compiled/default endpoints come from `MarmotServiceEndpoints`, which reads `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT` at
compile time if present.

The UniFFI bridge exposes:

- `relay_telemetry_settings()`;
- `set_relay_telemetry_settings(...)`;
- `telemetry_install_id()`;
- `set_relay_telemetry_runtime_config(...)`.

## Export gate

`RelayTelemetryExportConfig::export_allowed()` must be true before the exporter can be constructed or relay labels can
be resolved. The gate requires all the following:

- `enabled == true`;
- an endpoint is configured;
- the endpoint is `https`, or `http` to a loopback host (`localhost`, `127.0.0.1`, or `::1`) for local testing;
- `authorization_bearer_token` is present and non-empty;
- `resource` is present and has all required attributes.

If export is enabled but the URL/auth/resource gate is incomplete, construction fails closed and logs a warning without
resolving relay identities or pushing metrics. If `marmot-app` is built without `otlp-export`, runtime configuration
logs a warning when export is requested, but no exporter task is started.

Runtime behavior:

- `MarmotAppRuntime::start()` reads persisted settings, combines them with runtime config and service endpoints, then
  configures the exporter after directory sync and account reconciliation.
- The runtime exporter snapshots `AppPerformanceTelemetry` on every push and appends those population-level points to
  the relay batch. Engine reorg metrics are still passed as `None` by the periodic loop.
- Changing settings while the runtime is running restarts the exporter with the new config.
- Changing runtime config while the runtime is running restarts the exporter with the current persisted settings.
- Runtime shutdown aborts the exporter task.

## What leaves the device in opt-in telemetry export

The export batch is `RelayTelemetryExportBatch`, a flat list of `ExportMetricPoint`s. Despite the historical type name,
the batch now carries both relay metrics and app-performance metrics. Each point has:

| Field | Meaning |
| --- | --- |
| `name` | Static metric name from `metric_names`. |
| `relay` | Optional relay URL label. This is the only metric label the batch type permits. Population metrics use `None`. |
| `value` | `Counter(u64)`, `Gauge(f64)`, or `Histogram(ExportHistogram)`. |

`ExportHistogram` carries:

| Field | Meaning |
| --- | --- |
| `bounds_ms` | Millisecond bucket upper bounds copied from local snapshots. |
| `bucket_counts` | Count per bucket. |
| `overflow_count` | Samples above the largest bound. |

Per-relay points are emitted only when an opaque relay index resolves to a relay URL at the opt-in export boundary.
Unresolved relay indices are skipped rather than exported as opaque ids.

### Export metric catalogue

| Metric | Label | Value type | Source |
| --- | --- | --- | --- |
| `relay_first_event_latency_ms` | `relay` | Histogram | `RelayRollupEntry.first_event_latency` |
| `relay_eose_latency_ms` | `relay` | Histogram | `RelayRollupEntry.eose_latency` |
| `relay_delivery_count` | `relay` | Counter | `delivered_first + delivered_later` |
| `relay_redundant_count` | `relay` | Counter | `delivered_later` |
| `relay_first_deliverer_rate` | `relay` | Gauge | `delivered_first / delivery_count`, omitted when delivery count is zero |
| `cross_relay_spread_ms` | none | Histogram | Population-level `RelayTelemetryRollup.cross_relay_spread` |
| `relay_connection_attempts` | none | Counter | `RelayPlaneHealth.connection_attempts` |
| `relay_connection_successes` | none | Counter | `RelayPlaneHealth.connection_successes` |
| `relay_publish_attempts` | none | Counter | Adapter `publish_attempts` |
| `relay_publish_successes` | none | Counter | Adapter `publish_successes` |
| `relay_publish_failures` | none | Counter | Adapter `publish_failures` |
| `message_observed` | none | Counter | `RelayDeliverySpread.observed` |
| `message_corroborated` | none | Counter | `RelayDeliverySpread.corroborated` |
| `message_single_source` | none | Counter | `RelayDeliverySpread.single_source` |
| `relay_settles` | none | Counter | Optional `EngineReorgMetrics.settles`; not included by the periodic runtime exporter today |
| `relay_post_settle_reorgs` | none | Counter | Optional `EngineReorgMetrics.post_settle_reorgs`; not included by the periodic runtime exporter today |
| `relay_observed_reorg_rate` | none | Gauge | Optional derived rate when engine metrics have `settles > 0`; not included by the periodic runtime exporter today |
| `relay_reorg_lateness_ms` | none | Histogram | Optional `EngineReorgMetrics.reorg_lateness_ms`; not included by the periodic runtime exporter today |
| `app_start_duration_ms` | none | Histogram | `AppPerformanceSnapshot.app_start.duration_ms` |
| `app_start_attempts` | none | Counter | `AppPerformanceSnapshot.app_start.attempts` |
| `app_start_successes` | none | Counter | `AppPerformanceSnapshot.app_start.successes` |
| `app_start_failures` | none | Counter | `AppPerformanceSnapshot.app_start.failures` |
| `app_directory_subscription_sync_duration_ms` | none | Histogram | `AppPerformanceSnapshot.directory_subscription_sync.duration_ms` |
| `app_directory_subscription_sync_attempts` | none | Counter | `AppPerformanceSnapshot.directory_subscription_sync.attempts` |
| `app_directory_subscription_sync_successes` | none | Counter | `AppPerformanceSnapshot.directory_subscription_sync.successes` |
| `app_directory_subscription_sync_failures` | none | Counter | `AppPerformanceSnapshot.directory_subscription_sync.failures` |
| `app_account_reconcile_duration_ms` | none | Histogram | `AppPerformanceSnapshot.account_reconcile.duration_ms` |
| `app_account_reconcile_attempts` | none | Counter | `AppPerformanceSnapshot.account_reconcile.attempts` |
| `app_account_reconcile_successes` | none | Counter | `AppPerformanceSnapshot.account_reconcile.successes` |
| `app_account_reconcile_failures` | none | Counter | `AppPerformanceSnapshot.account_reconcile.failures` |
| `app_account_open_duration_ms` | none | Histogram | `AppPerformanceSnapshot.account_open.duration_ms` |
| `app_account_open_attempts` | none | Counter | `AppPerformanceSnapshot.account_open.attempts` |
| `app_account_open_successes` | none | Counter | `AppPerformanceSnapshot.account_open.successes` |
| `app_account_open_failures` | none | Counter | `AppPerformanceSnapshot.account_open.failures` |
| `app_account_catch_up_duration_ms` | none | Histogram | `AppPerformanceSnapshot.account_catch_up.duration_ms` |
| `app_account_catch_up_attempts` | none | Counter | `AppPerformanceSnapshot.account_catch_up.attempts` |
| `app_account_catch_up_successes` | none | Counter | `AppPerformanceSnapshot.account_catch_up.successes` |
| `app_account_catch_up_failures` | none | Counter | `AppPerformanceSnapshot.account_catch_up.failures` |
| `app_account_sync_duration_ms` | none | Histogram | `AppPerformanceSnapshot.account_sync.duration_ms` |
| `app_account_sync_attempts` | none | Counter | `AppPerformanceSnapshot.account_sync.attempts` |
| `app_account_sync_successes` | none | Counter | `AppPerformanceSnapshot.account_sync.successes` |
| `app_account_sync_failures` | none | Counter | `AppPerformanceSnapshot.account_sync.failures` |
| `app_outbound_message_send_duration_ms` | none | Histogram | `AppPerformanceSnapshot.outbound_message_send.duration_ms` |
| `app_outbound_message_send_attempts` | none | Counter | `AppPerformanceSnapshot.outbound_message_send.attempts` |
| `app_outbound_message_send_successes` | none | Counter | `AppPerformanceSnapshot.outbound_message_send.successes` |
| `app_outbound_message_send_failures` | none | Counter | `AppPerformanceSnapshot.outbound_message_send.failures` |
| `app_media_upload_duration_ms` | none | Histogram | `AppPerformanceSnapshot.media_upload.duration_ms` |
| `app_media_upload_attempts` | none | Counter | `AppPerformanceSnapshot.media_upload.attempts` |
| `app_media_upload_successes` | none | Counter | `AppPerformanceSnapshot.media_upload.successes` |
| `app_media_upload_failures` | none | Counter | `AppPerformanceSnapshot.media_upload.failures` |
| `app_media_download_duration_ms` | none | Histogram | `AppPerformanceSnapshot.media_download.duration_ms` |
| `app_media_download_attempts` | none | Counter | `AppPerformanceSnapshot.media_download.attempts` |
| `app_media_download_successes` | none | Counter | `AppPerformanceSnapshot.media_download.successes` |
| `app_media_download_failures` | none | Counter | `AppPerformanceSnapshot.media_download.failures` |

Current implementation note: publish telemetry is device-wide attempts/successes/failures. It is not currently
per-relay or per-Nostr-kind, even though the relay observability design doc names those as desired future ranking
signals.

### OTLP encoding

When the `otlp-export` feature is enabled:

- counters encode as monotonic cumulative OTLP sums;
- gauges encode as OTLP gauges;
- histograms encode as cumulative OTLP histograms with the same explicit bounds as local snapshots plus an overflow
  bucket;
- metric unit is `ms` for histograms and `1` for counters/gauges;
- instrumentation scope name is `marmot.relay_telemetry`;
- HTTP body content type is `application/x-protobuf`;
- the request is sent with bearer auth to the configured full OTLP metrics URL.

Resource attributes on every OTLP request:

| Attribute | Source |
| --- | --- |
| `service.name` | Constant `darkmatter`. |
| `service.namespace` | Constant `marmot`. |
| `service.version` | `RelayTelemetryResource.service_version`. |
| `service.instance.id` | `RelayTelemetryResource.service_instance_id`, typically the app-root `telemetry_install_id()`. |
| `deployment.environment.name` | `RelayTelemetryResource.deployment_environment`. |
| `tenant` | `RelayTelemetryResource.tenant`. |
| `os.type` | `RelayTelemetryResource.os_type`. |
| `os.version` | `RelayTelemetryResource.os_version`. |
| `device.model.identifier` | Optional `RelayTelemetryResource.device_model_identifier`. |

Exporter timing:

- first push happens immediately when `run()` starts, unless shutdown was already requested;
- later pushes happen on the configured interval with jitter up to half the interval, capped at `10s`;
- `export_once_with_retries()` performs the initial attempt plus up to three retries within one export window;
- retry base delay is one-tenth of the interval, clamped from `50ms` through `1000ms`, then exponentially backed off;
- HTTP connect timeout is `10s`, request timeout is `30s`;
- failures are logged with a privacy-safe warning and are not persisted to disk or queued for later.

## Tracing and logging

The repo has the `tracing` and `tracing-subscriber` dependencies, but the current `dm`, `dmd`, `dm-agent`, and
`marmot-app` runtime source does not install a global tracing subscriber. As a result, these `tracing::*` calls are
instrumentation points. They are collected only if a host application, test harness, or future binary initializes a
subscriber.

The guardrail test `production_tracing_calls_are_structured_and_privacy_safe` scans production Rust source under
`crates/` and enforces:

- every tracing call has an explicit `target:`;
- every tracing call has a `method =` field;
- tracing macro bodies must not contain known-sensitive token names:
  `account_id`, `member_id`, `group_id`, `message_id`, `transport_group_id`, `relay_url`, `pubkey`, `event_id`,
  `subscription_id`, `payload`, `content`, `plaintext`, `ciphertext`, `key_material`, `private_key`, `mls_bytes`.

The guardrail test `production_library_sources_do_not_write_direct_output` rejects `println!`, `eprintln!`, and `dbg!`
from production library source. CLI binaries may write explicit command output to stdout/stderr.

Notable tracing targets currently present:

| Target | Typical methods / fields |
| --- | --- |
| `transport_nostr_adapter::adapter` | `metrics`, `delivery_spread`, `relay_sync`, `handle_relay_event`, `activate_account`, `sync_account_groups`, `deactivate_account`, `publish`; fields are counts such as `delivered`, endpoint counts, subscription counts, required ack count. |
| `marmot_app::relay_plane` | Relay notification forwarding, directory subscription/fetch lifecycle, router shutdown/drop warnings; fields are status/counts and bounded error categories. |
| `marmot_app::relay_telemetry_export` | Exporter construction, `export_once`, `run`; fields include `point_count` and safe warning categories. |
| `marmot_app::audit_log` | Audit tracker scheduling/upload summaries; fields include `trigger`, `skipped_reason`, uploaded/failed counts, and file index. Audit content is not logged. |
| `marmot_app::runtime` | Startup/shutdown and worker lifecycle; fields include elapsed times and active operation counts. |
| `cgka_session::session` | Session lifecycle method markers such as open, send, ingest, publish confirmation, and catch-up. |
| `cgka_engine::engine_metrics` | Snapshotting engine metrics. |
| `cgka_engine::snapshot_guard` | Snapshot retention/cleanup warnings with safe counts/status only. |
| `marmot_account::*` and `marmot_app::*` | Account/app lifecycle warnings and projection/cache method markers. |
| `agent_connector::*` | Connector warning paths with safe error categories. |

Direct CLI output:

- `dm` and `dmd` write command outputs produced by `darkmatter_cli` to stdout/stderr and print only a safe write-output
  failure message if writing fails.
- `dm-agent` prints startup failures with safe error codes/details from argument parsing and token-file setup. Its
  `ConnectorError` display path is reduced through `privacy_safe_code()` for startup failure output.

## What is deliberately not collected in telemetry/tracing

Outside the separate forensic audit-log mode documented in [`audit-logging.md`](./audit-logging.md), telemetry and
tracing must not collect:

- account ids, member ids, group ids, message ids, transport group ids, subscription ids, event ids, or pubkeys;
- relay URLs, except as the single opt-in relay metric label in the export channel;
- plaintext, ciphertext, MLS bytes, Nostr event content, payloads, key material, private keys, SQLCipher keys, or
  database paths;
- per-event or per-message telemetry rows in the export channel;
- end-to-end message latency across devices; the current send metric stops at this device's local send/publish result;
- media endpoint URLs, media object ids, media payload sizes, content types, or transfer error strings;
- source IP fields in the export batch.

## Verification commands

Focused checks for this surface:

```sh
cargo test -p transport-nostr-adapter
cargo test -p marmot-app
cargo test -p marmot-app --features otlp-export
cargo nextest run -p cgka-conformance-simulator --test tracing_audit
```

The repo-level `just check` and `just test` recipes include the `otlp-export` feature set through the shared
`otlp-features` variable.
