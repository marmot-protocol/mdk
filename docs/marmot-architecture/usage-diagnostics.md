---
updated: 2026-09-08
---
# Usage and diagnostics

MDK uses stock self-hosted Aptabase for optional product analytics and OTLP for
optional diagnostics. One local **Share usage and diagnostics** decision controls
both independent exporters. Forensic audit logging has its own consent.

See [implementation coverage and validation](usage-diagnostics-validation.md) for
implemented surfaces, counting boundaries and external acceptance.

## Consent and host integration

Supply both exporter configurations and the complete host event registry before
starting the runtime or asking for acceptance. Read `usage_diagnostics_settings()`
to render the decision. Display `USAGE_DIAGNOSTICS_DISCLOSURE`, the configured
operator, and the operator's verified retention policy. Call
`set_usage_diagnostics_consent(true)` only after an explicit affirmative action.
False revokes both pipelines. A failed save disables export in the current process
and returns an error; it must not be presented as a durably saved preference.

Shared-store migration 2 creates the sole consent receipt. The frozen v1 schema is
unchanged. Existing enabled telemetry settings require acceptance of the expanded
scope; `previously_enabled` supports a one-time explanation. Intervals, directory
records, and audit settings survive. Consent belongs to the app root, not the
machine; White Noise and `wn-agent` can ask separately.

The legacy telemetry setter cannot grant consent. Its enable path requires an
existing combined grant; its disable path revokes both pipelines. Endpoint,
resource, and interval configuration remain available. MDK owns the OTLP
installation ID, creates it under consent, and rotates it after revocation.
Host-supplied cached IDs cannot restore an earlier identity. C exposes typed
consent/configuration/observation errors alongside equivalent Swift/Kotlin records.

Each exporter checks its own feature and configuration. Aptabase does not need
OTLP credentials. Replacing a credential or app release does not expand consent;
changing registered schemas, operator, or destination origin requires acceptance.
A consent generation cancels queued and pending work. Already sent data cannot be
recalled. An aborted or suspended process may lose memory-only observations.

## Stock Aptabase privacy boundary

Product payloads contain reviewed finite properties, coarse metadata, bucketed
measurements, and temporary UUIDs. They exclude message contents, user/account/group
identifiers, installation IDs, addresses, relay URLs, exact media sizes, filenames,
search terms, emoji, push tokens, agent prompts, tool arguments, and raw errors.
Diagnostics retains its separate random installation ID during uninterrupted
consent. Existing relay-label dashboard safeguards still apply to OTLP.

The server receives source IP information. Stock Aptabase uses IP/user-agent data
for daily grouping and enriches events with approximate country/region. Different
product sessions can therefore be associated by the server. These are approximate
activity groupings, not verified people. Ephemeral client identifiers do not remove
rare-event, timing, or infrastructure-log risks.

The upstream [daily hasher](https://github.com/aptabase/aptabase/blob/main/src/Features/Privacy/DailyUserHasher.cs)
and [event retention code](https://github.com/aptabase/aptabase/blob/main/src/Features/Ingestion/Buffer/EventRow.cs)
are part of this accepted boundary. Stock release-event TTL is five years. The
180-day operating target requires separately verified deployment controls; MDK
cannot enforce it. No fork or geolocation-disable prerequisite is required.

## Configuration and lifecycle

Enable `product-analytics-export` independently from `otlp-export`. Supply the full
Aptabase events URL and the app's ingestion key through
`set_product_analytics_runtime_config`. `MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT`
can supply an optional compiled route default. Prefix paths are preserved.
Credentials are not saved to shared storage and Debug/status output redacts them.
Production and staging must use separate Aptabase applications. Development has
no implicit production-key fallback.

The CLI hosts accept explicit `MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT`,
`MARMOT_PRODUCT_ANALYTICS_APP_KEY`, `MARMOT_PRODUCT_ANALYTICS_OPERATOR`, and
`MARMOT_PRODUCT_ANALYTICS_ENVIRONMENT` environment configuration. The development
loopback override is `MARMOT_PRODUCT_ANALYTICS_ALLOW_LOOPBACK=1`; it permits only
an exact loopback destination. Environment configuration never grants consent. Invalid optional analytics settings produce a fixed, redacted warning and leave host startup and diagnostic authorization intact.

Use `wn [--json] usage-diagnostics show|enable|disable` or
`wn-agent usage-diagnostics show|enable|disable [--home PATH] [--json]` for local
controls. Active `wnd` owns its changes. `wn-agent` exposes a separate owner-only
local management socket; its agent-control credentials and remote messages cannot
accept this permission. Standalone `wn`/TUI collectors are silent. Frozen-cursor
notification runtimes are always silent. The local controls report the
saved permission separately from current exporter readiness. A standalone process
can inspect a saved grant without loading the daemon's destination or registry;
this does not authorize that process to export. Rust local administration uses
`stored_usage_diagnostics_settings()`; normal export authorization still uses the
effective settings and generation gate. Management connections have a separate
four-client limit and cannot block regular agent-control admission.

Report foreground/background/account-context boundaries through
`set_product_analytics_activity`. Foreground sessions expire after 30 minutes of
inactivity or one hour maximum. Background work does not extend a session.
A background transition seals once and attempts a two-second best-effort flush.
Shutdown closes storage before attempting a bounded drain. No disk queue or
account/database lock is retained by delivery.

## Collection and counting

The source catalogue is `crates/marmot-app/src/product_analytics/catalogue.rs`;
`product-event-catalogue.json` is its versioned, machine-readable contract.
`approved_host_product_schemas()` supplies the reviewed screen, onboarding,
compose, search, attachment, settings, and notification-permission observations.
Additional host `app_` schemas freeze before collection: at most 32 schemas,
eight properties per schema, 16 enum choices, 60-character names, 40-character
keys, and 180-character registered string values. There is no free-text escape
hatch. Hosts cannot override built-ins, identity, timestamps, or common metadata.

An **action** is one logical command; an **attempt** is one execution including a
real retry; a **transition** is a changed persisted phase; **backlog** is current
outstanding state; **coverage** describes an enabled reporting interval. Never sum
backlog over scheduler ticks. Maintenance observes successful persistence edges,
and per-worker backlog samples are combined across accounts. Backfill reporting
belongs to `run_pending_epoch_backfill_reporting_arm`; an incomplete pass is an
attempt, not a newly started recovery. Broadcast fan-out does not record analytics.
Message acceptance and relay publication are distinct from recipient receipt,
decryption, display, and reading. Provisional preview success is separate from
final MLS acceptance.

UTC quarter-hour windows get fresh UUIDs. First/background/shutdown windows may be
partial. Counts use `1`, `2`, `3_5`, `6_10`, `11_20`, `21_50`, `51_100`, `101_250`,
`251_1000`, and `1001_plus`. Zero is reserved for backlog/coverage, not empty
activity. Product duration upper bounds are inclusive: 10/25/50/100/250/500 ms;
1/2/5/10/30 seconds; 1/5/15/60 minutes; overflow. Built-in operations feed product
and OTLP separately from the same durations. Custom host events feed product only.
Product sends neither raw durations nor sums.

OTLP lifetime counters stay local. Each export collection period subtracts a
counter/histogram baseline, retains cumulative temporality with the period's
start time, and recomputes derived ratios. Gauges remain current values. Source
resets begin a new period instead of concealing underflow.

Delivery bounds are 256 aggregate cells, 512 queued events/256 KiB, 2 KiB per event,
25 events per request, one request in flight, and one-hour monotonic expiry.
Journeys flush every minute; aggregates seal every quarter hour. Known
nonacceptance permits bounded retries; ambiguous post-send failures are dropped.
Authentication/configuration rejection suspends the affected exporter. Both
exporters validate every resolved address, pin it, preserve configured-host TLS
trust, disable redirects/proxies, and bound DNS/connect/request time.

## Custom host timings

Register app-specific stages before requesting consent, then call
`record_host_timing(name, duration, outcome)` with a monotonic elapsed duration.
For example, add this schema to `ProductAnalyticsRuntimeConfig.registry`:

```rust
ProductEventSchema {
    name: "app_inbox_layout".into(),
    mode: ProductEventMode::Aggregate,
    properties: vec![
        ProductPropertySchema {
            name: "elapsed".into(),
            rule: ProductPropertyRule::DurationBucket,
        },
        ProductPropertySchema {
            name: "outcome".into(),
            rule: ProductPropertyRule::Enum(vec!["success".into(), "failure".into()]),
        },
    ],
}
```

Measure each stage with the host's monotonic clock. Rust accepts `Duration`;
Swift/Kotlin and `marmot_record_host_timing` accept unsigned milliseconds plus
`HostPerformanceOutcome` (`Success`/`Failure`). For example, Swift calls
`try marmot.recordHostTiming(name: "app_inbox_layout", durationMs: 250, outcome: .success)`.
Use static stage names such as `app_inbox_layout` or `app_attachment_decode`,
never names derived from messages, accounts, files, or user input. Existing app
metadata and separate operator app keys distinguish app versions and surfaces.

The helper records exactly `elapsed` and `outcome`, validating the registered
schema through `record_product_event`. Aggregate mode counts matching stage,
duration bucket, and outcome combinations per window; Journey mode records each
foreground observation. Disabled/unconfigured collection returns the existing
ignored result; unregistered names or incompatible schemas return an error while
collection is enabled. Consent revocation clears pending events. Extra registered
dimensions can use `record_product_event` directly with a duration bucket value.

These events reach Aptabase under their registered names and do not enter OTLP
or `app_performance_snapshot`. Compare `elapsed` buckets by stage, outcome, app
version, and OS; a 250 ms sample is `le_250ms`, and 251 ms is `le_500ms`. They do not
provide exact percentiles, raw durations, or per-message trace correlation.

## Operator reports

The parameterized `usage-diagnostics-queries.sql` supplies stock ClickHouse queries.
Use `usage-diagnostics-report.py` on sanitized Aptabase event exports (JSONL in
wire shape, or persisted rows with JSON `stringProps`). It reports bucket bounds
by family, operation, outcome, unit, duration bucket, and partial flag. It counts
foreground sessions only from `mdk_session_started`; aggregate-window UUIDs never
enter that denominator. Onboarding counts describe observed opted-in steps.

Report feature distributions, local acceptance/publication, group/Welcome outcomes,
media, notifications, sync/connectivity/recovery/storage, maintenance attempts and
transitions, backlog, and agent/preview activity separately. Split partial and
complete windows. Bucket-derived totals/rates are approximate intervals; overflow
has no finite upper bound. Backlog is not a count of failed operations. Local
export status describes queue/drop/batch loss and cannot establish server storage.
Do not claim exact users, retention, full-population opt-in rates, crash rates, or
recipient delivery rates. Do not reconstruct cross-session identities.

## Separate deployment acceptance

Record the actual Aptabase image/version, backend, proxy/CDN path, and existing
retention before changing deployment settings. Inspect identifying logging at
proxy/CDN/application/container/database layers; disable unnecessary ingestion
logging, protect administrative access, and bound remaining logs. Enforce the
180-day target using supported database retention or scheduled cleanup covering
derived sessions, exports, and backups. Default event TTL is insufficient.

Send synthetic staging events, inspect persisted records and expected enrichment,
and inspect logs without publishing IPs or keys. Record these findings separately
from MDK unit/wire tests and native host consent-screen adoption. Local test
success does not prove deployed retention, log minimization, or real staging
compatibility. Native White Noise consent screens and deployment changes are
separate work items.

The checked-in `usage-diagnostics-examples/` directory contains sanitized report
input and its sample report; it is not a batch to POST to the ingestion API.
The Rust `usage_diagnostics_staging` example exercises the public host contract
against an explicitly configured staging application, with a temporary app root
and no user accounts:

```sh
cargo run -p marmot-app --features product-analytics-export \
  --example usage_diagnostics_staging -- --send-synthetic
```

Supply the endpoint, app key, operator and `MARMOT_PRODUCT_ANALYTICS_ENVIRONMENT=staging`
through the environment. The example prints only safe exporter status. A successful
HTTP acknowledgement does not verify persistence, server enrichment, logging, or
retention; those remain separate deployment checks.

Use the legacy-opt-in explanation only when `previously_enabled` is true and the
policy revision is empty (the initial migration receipt). Later schema/destination
changes require a scope-change explanation. Notification and deep-link launches
use `ForegroundNotification` and `ForegroundDeepLink`; pass no URL or notification ID.
Media upload batches containing different MIME classes are classified as `other`.
Maintenance `sweep` counts scheduler executions and their durations; `self_update`
and `key_package` attempts and persisted transitions are separate measurements.

## Reproducing binding checks

`crates/marmot-uniffi/usage-diagnostics-smoke.sh swift` generates bindings and
round-trips the consent, exporter status, metadata and activity records against
the local Rust library. The Kotlin runner takes `kotlin` and an explicit
`MDK_KOTLIN_CLASSPATH` containing JNA (including its native libraries), an Android
platform jar, AndroidX annotations and kotlinx-coroutines. These are native/JVM
record checks, not device consent-screen tests. C uses `just c-header`,
`just c-parity-gate`, allocation-audit tests and `just c-smoke`.

The published `wn-agent` build enables both optional exporters; configuration and
consent still default off. Source builds of `wn`/`wnd` can enable both with
`cargo build -p wn-cli --bins --features otlp-export,product-analytics-export`.

Connectivity coverage uses the latest bounded minute sample of app-wide relay
health and emits one availability cell per sealed window. Quarantined groups are
backlog samples, not newly failed transitions on startup. Storage migration rows
count newly committed numbered migrations; reopening an unchanged database does
not emit migration success. The migration attempt duration covers the migration
runner, while the storage-open measurement covers the surrounding open operation.

### Optional exporter lifecycle

An unreadable consent record disables diagnostics and is reported by explicit
settings reads; it does not prevent the app runtime from starting. Explicit
configuration updates still return the consent-read error and keep delivery
disabled, so hosts can surface the failed reconfiguration. Synchronous host
setters restart exporters on the executor captured during runtime startup. If
that executor is unavailable, exporters stay stopped and log a fixed warning.
The legacy telemetry settings getter reports the effective in-memory export
state, so an unstarted instance reports export disabled. Read the combined
consent settings to inspect the saved decision before starting the runtime.

A cumulative OTLP series first supplied after collection starts establishes its
own baseline at first observation. Its initial exported count and histogram are
zero; gauges remain current values. Temporarily absent series retain their
baselines and previous values so later source resets are still detected.

If the agent management socket is unavailable while a connector owns the root,
local controls return an error instead of writing consent behind the active
runtime. Stop the connector before using offline controls in this degraded case.
