# Relay Observability and Telemetry Export

**Status:** design draft; privacy carve-out **accepted**, `observability.md` amendment applied. This specifies the
*export contract* for client-side relay performance telemetry: which signals leave the device, under what privacy
guarantees, and how they reach a first-party metrics stack. It is the broad-observability counterpart to
[`relay-delivery-telemetry.md`](./relay-delivery-telemetry.md), which is scoped to device-local convergence tuning and
exports nothing.

The privacy carve-out below is accepted and the matching amendment is now in
[`overview/observability.md`](./overview/observability.md). Local visibility (`dm relay-stats`), the opt-in
index→identity resolution boundary, the relay-plane rollup, and the opt-in OTLP exporter are now implemented; the
exporter's wire encoding and push live behind the `marmot-app` `otlp-export` build feature, and the dashboards plus the
k-anonymity gate remain ops work. No telemetry leaves the device unless a user opts in **and** a first-party endpoint is
configured.

## Purpose

We want to rank relays by the quality clients actually experience — latency, delivery, EOSE timing, publish acceptance —
so we can choose good relays, tune the negotiated `settlement_quiescence_ms` from real data, and watch a self-hosted
strfry fleet (which reconciles internally over negentropy) behave in the wild. None of that is answerable from
device-local snapshots alone, because the interesting question is cross-client: *which relays are good for the
population*, not *what did my one client see*.

Answering it requires relay identity in the exported series. That is the entire tension this document resolves, because
the current rule forbids relay identity from ever leaving the device.

## Scope boundaries

Three telemetry concerns are easy to conflate. They are separate and only one is specified here.

| Concern | Relay identity | Leaves device | Owner | Where |
| --- | --- | --- | --- | --- |
| Convergence quiescence tuning | none (device-local) | no | adapter | `relay-delivery-telemetry.md` |
| **Client-side relay ranking (this doc)** | **yes, as a metric label** | **yes, opt-in + aggregated** | relay plane → exporter | here |
| Server-side strfry fleet health | n/a (you own the boxes) | n/a (scrape directly) | ops | outside this repo |

Server-side fleet telemetry (strfry stats, negentropy sync lag between your relays, kind accept/reject) is the cheapest
source of truth for relays you operate and has no client-privacy issue; scrape it directly. This document is only about
the client-experienced view, which is the part with a privacy cost.

## The privacy contract

This is the heart of the document. Exporting relay-identified telemetry is safe **only** under all of the following.
Each is a hard requirement.

1. **Opt-in.** Export is off by default and requires explicit user consent, disclosed in plain language and revocable.
   A client that has not opted in exports nothing and behaves exactly as today.
2. **First-party endpoint only.** Telemetry is sent only to a Marmot-operated metrics endpoint over TLS. It is never
   sent to relays, third parties, or arbitrary push gateways.
3. **No client-identifying labels.** The only high-cardinality label permitted is **relay identity** (the metric subject
   we are ranking). The export MUST NOT carry — in any label, value, or series — an account id, member id, device id,
   group id, transport group id, subscription id, pubkey, message id, event id, IP-derived field, or any user- or
   membership-derived value. Relay identity is the sole exception to the device-local rule, and only because it is the
   thing being measured, not an identifier of the reporter.
4. **Aggregate only.** Exported series are counts and fixed-bucket histograms (fine-grained for collection resolution —
   see [Histogram resolution](#histogram-resolution)) accumulated over a window. No per-event, per-message, or
   per-timestamp rows. This is the same shape the device-local snapshots already produce (`RelayDeliverySpread`,
   `RelaySyncSnapshot`, `NostrAdapterMetrics`).
5. **k-anonymity at the dashboard.** A relay's experienced-quality series is shown only when at least `k` distinct
   reporters have contributed to it, enforced at aggregation/query time in the metrics stack. `k` is a deployment
   parameter. **During internal testing `k = 1`**, to gather as much data as possible while the only reporters are our
   own builds. `k` MUST be raised to a conservative value — and the IP-stripping proxy of requirement 6 stood up —
   before any non-internal rollout.
6. **No source attribution at rest.** The receiving endpoint MUST NOT persist source IPs joined to series, and SHOULD
   terminate behind a proxy that strips them, so the stored data cannot re-link a series to a reporter after the fact.

The threat this defends against: a client reporting "I use relays X, Y, Z" leaks the user's relay set, which is a
social-graph / deanonymization vector. Requirements 3–6 ensure an exported series says "*some* clients experienced this
latency to relay X," never "*this* client uses relay X."

Runtime tracing and logging rules do not change. This contract governs a **separate, explicit, opt-in export channel**;
it does not loosen what `observability.md` allows in logs.

## Metric catalogue

All metrics are per-relay (label: relay identity) unless noted, aggregated over the export window, histograms in
local-time milliseconds. Most already exist as device-local snapshots and need only per-relay attribution and an export
binding.

| Metric | Shape | Source today | Ranks |
| --- | --- | --- | --- |
| `relay_first_event_latency_ms` | histogram | `RelaySyncSnapshot.first_event` (currently aggregate) | responsiveness |
| `relay_eose_latency_ms` | histogram | `RelaySyncSnapshot.eose` (currently aggregate) | sync speed |
| `relay_first_deliverer_rate` | ratio | new: how often this relay delivered a copy first | redundancy value |
| `relay_delivery_count` / `relay_redundant_count` | counters | adapter inbound path | reliability |
| `relay_publish_accept` / `relay_publish_reject` (by kind) | counters | publish path / `NostrAdapterMetrics` | write health, kind policy |
| `relay_connection_success_rate` | ratio | `NostrSdkRelayHealth` | connectivity |
| `cross_relay_spread_ms` | histogram | `RelayDeliverySpread` (global, not per-relay) | population delivery jitter → quiescence |
| `message_observed` / `message_corroborated` / `message_single_source` | counters | `RelayDeliverySpread` population counts | coverage health |

`cross_relay_spread_ms` is exported as a population-level distribution (no relay label — it is inherently cross-relay), and
is the direct input to the static quiescence decision in `relay-delivery-telemetry.md`. The per-relay metrics are the
ranking signal. Per-relay attribution of the latency histograms and the first-deliverer rate is **recorded today**,
behind opaque device-local indices (`RelayLatencyStats`, `RelayDeliveryStats`); that is allowed under the current rules
because no relay identity leaves the device. Only *resolving* an index to a relay label for export needs this contract
accepted.

## Collection and export architecture

```
adapter (per-relay raw)  ->  relay plane (aggregate across accounts)  ->  exporter (opt-in push)  ->  first-party stack
   device-local snapshots        RelayPlaneHealth + telemetry rollup        TLS, no client labels       Prometheus/Grafana
```

- **Adapter** already records the raw per-relay signals as device-local aggregates (`delivery_spread`, `relay_sync`,
  `metrics`) plus SDK relay health. Per-relay attribution of latency is added here, behind opaque indices locally and
  resolved to relay identity only at the export boundary.
- **Relay plane** is the aggregation home: it already wraps the adapter and exposes a redacted `RelayPlaneHealth`, and it
  is the one component with the cross-account view. It rolls per-relay aggregates up across local accounts so the
  exporter never sees per-account structure.
- **Exporter** is a new, opt-in component that converts the rollup into the export series and pushes them. It is the only
  code that resolves relay identity into a label, and it enforces the contract (no client labels, aggregate only).
  Implemented as `marmot_app::RelayTelemetryExporter`, constructed only through the opt-in gate
  `MarmotRelayPlane::telemetry_exporter`. The privacy-critical mapping (`build_export_batch`) lives in the default build
  and is fully tested; the OTLP protobuf encoding and HTTP `POST` to the configured full metrics URL are behind the
  `otlp-export` feature. Exporter construction requires the persisted opt-in settings plus host-supplied full metrics
  URL, bearer auth, and resource metadata; these runtime values are not persisted by Marmot. The export batch is a flat
  list of points each carrying at most a single `relay` label — there is
  structurally no field for any other identifier.

Export mechanism: clients roam and are not scrapeable servers, so this is **push**, not pull — Prometheus `remote_write`
to a first-party receiver, or OTLP to a collector, behind an IP-stripping proxy. Cardinality is bounded by the number of
distinct relays (hundreds), which is fine as a single label dimension. The metrics stack applies the k-anonymity gate at
query time.

**Backend — decided: Grafana.** Relay data goes to Grafana (Prometheus/TSDB behind it), which is the right home for
latency histograms and percentile/ranking dashboards, and where the server-side strfry fleet metrics already live — so
client-experienced and server-side relay views sit side by side. **Aptabase is reserved for future product analytics**
(usage, retention, feature events); its anonymous event-count model is a poor fit for latency distributions and has no
native histogram/percentile story, so relay telemetry does not go there. During internal testing (`k = 1`), clients push
directly to the first-party Grafana/OTLP endpoint; the IP-stripping proxy and dashboard k-anonymity gate are stood up
before any external reporters are added.

### Histogram resolution

Buckets are deliberately fine-grained, since the collected data is only as precise as the bucket edges and we want
high-resolution percentiles for both relay ranking and quiescence tuning. The device-local histograms in
[`telemetry::DurationHistogram`](../../crates/transport-nostr-adapter/src/telemetry.rs) define the bucket edges (ms);
the exporter forwards those same edges. Memory is bounded — a handful of `u64` counters per relay per metric — so finer
buckets are cheap.

## Proposed observability.md amendment

`observability.md` currently states relay URLs must never appear in telemetry and that Marmot exposes only
aggregate/redacted relay-health summaries. Add a bounded carve-out:

> ## Opt-in relay telemetry export
>
> Separately from runtime tracing and logging (whose rules are unchanged), Marmot MAY export relay performance
> telemetry to a first-party metrics endpoint, carrying **relay identity as a metric label**, only when all of the
> following hold: the user has explicitly opted in; the endpoint is Marmot-operated and reached over TLS; the export
> carries no account, member, device, group, subscription, pubkey, message, event, or IP-derived field; the data is
> aggregate counts and histograms over a coarse window; per-relay series are gated by k-anonymity at the dashboard; and
> source IPs are not persisted against series. Relay identity is the sole identifier permitted to leave the device, and
> only as the subject being measured. This carve-out applies to the export channel alone and never to logs or traces.

This amendment is **accepted and now applied** in [`overview/observability.md`](./overview/observability.md).

## Phasing

1. **Spec accepted** (this document) and the `observability.md` amendment applied.
2. **Per-relay attribution** in the adapter — *done*: per-relay first-event / EOSE latency histograms and the
   first-deliverer rate, behind opaque local indices (`RelayLatencyStats`, `RelayDeliveryStats`). Useful for local
   analysis today and independent of the export decision.
3. **Relay-plane rollup** — *done*: cross-account aggregation of the per-relay series into an export-ready snapshot
   (`MarmotRelayPlane::telemetry_rollup`), keyed by opaque relay index, with an optional engine-metrics seam.
4. **Opt-in exporter** — *done*: off-by-default opt-in gate, index→identity resolution behind a consent token, contract
   enforcement in the export-batch types, and an OTLP/HTTP push binding (behind the `otlp-export` feature). Local
   visibility landed first via `dm relay-stats`.
5. **Dashboards and k-anonymity gate** in the first-party stack; relay ranking and the quiescence-tuning view.

Wiring the exporter's periodic `run` loop into a long-running host (e.g. `dmd`) against the production first-party
endpoint is an ops step and is intentionally out of scope here; `RelayTelemetryExporter::export_once` / `run` are the
entry points, and the production endpoint must be stood up behind the IP-stripping proxy with `k` raised before any
external reporters are added.

Server-side strfry fleet telemetry is independent and can proceed in parallel at any time.

## Decided

- **k value: `k = 1` for now.** During internal testing we want as much data as possible; the only reporters are our own
  builds. Raise to a conservative value (and stand up the IP-stripping proxy) before any external rollout.
- **Backend: Grafana** for relay data; Aptabase reserved for future product analytics (see
  [Collection and export architecture](#collection-and-export-architecture)).
- **Histogram buckets: fine-grained** (see [Histogram resolution](#histogram-resolution)).

## Open questions

- **Push transport.** `remote_write` vs OTLP vs a thin custom receiver into Grafana — which best supports the
  IP-stripping and no-client-label requirements without bespoke infrastructure?
- **Consent granularity.** One toggle for all relay telemetry, or separate consent for ranking vs quiescence-tuning
  data? The latter is population-level and arguably lower-risk.
- **Mobile cost.** Export window and batching that respect battery and metered-network constraints.
- **Self-relay shortcut.** For relays we operate, server-side scraping already gives ground truth; should clients skip
  exporting experienced-quality for first-party relays to reduce volume, or is the client view still worth it for
  comparison against the server view?
