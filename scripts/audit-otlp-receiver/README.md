# Isolated audit OTLP receiver contract

This loopback-only contract uses synthetic v4 records and disposable HTTP
services to specify the receiver for a future MDK sender. It does not activate
one. The existing Goggles upload and tracker path is unchanged.

## Request and validation

`POST /v1/logs` uses `Content-Type: application/json`, exactly one
`Content-Length`, no compression or transfer encoding, and
`Authorization: Bearer <dedicated audit token>`. The harness binds loopback and
reads the token from a named environment variable. Missing or wrong credentials
return 401 before body processing. A deployment needs TLS and ingress/access
controls; this slice supplies no deployment configuration.

The only accepted OTLP/HTTP JSON shape is one `resourceLogs` entry containing
one `scopeLogs` entry, `scope: {"name":"marmot.audit"}`, and 1–96
`logRecords`, each exactly `{"body":{"stringValue":"<v4 JSON body>"}}`.
Resource, scope, record, and event extras are refused. No client tenant,
timestamp, resource attribute, trace context, or arbitrary log attribute is
accepted. Protobuf and gzip are outside this profile. The encoded request is at
most 1 MiB; each original UTF-8 JSONL body is at most 65,535 bytes, leaving
one LF within the local cursor's 64 KiB line ceiling. The body string excludes
that LF and may not contain a raw CR or LF.

The receiver parses JSON with duplicate-key and nonfinite-number rejection at
every nesting level. It validates **every** body against MDK's bundled v4 JSON
Schema before making the single downstream call. Malformed, unknown-version,
unknown-kind, unknown-field, duplicate-key, oversized, and mixed valid/invalid
batches return 400 (oversized HTTP requests return 413). They cause no durable
queue, WAL, rejected-body log, or downstream write. This receiver has no server
spool or request-body logging. Any future proxy, collector, or dead-letter path
must preserve that validation-before-persistence boundary.

The receiver passes the original body string byte-for-byte as the Loki log line
and hashes those bytes for metadata. It never reserializes the v4 event. It
derives 64 fixed bucket labels and correlation metadata from validated bodies;
receipt nanoseconds, service, and environment labels come from the receiver.
Client `wall_time_ms` remains inside the original body and is never used as the
Loki ingestion timestamp. A retry receives a new receipt time and can create a
second occurrence of the same exact body. No server deduplication is promised.

## Response boundary and future `AuditReceiver` action

The receiver calls a direct Loki push endpoint. Only Loki HTTP **204 with an
empty body**, inspected by this receiver, yields HTTP **200 `{}`** to the sender.
That is full acceptance of this batch by the direct write API. It is **not**
confirmed durable, replicated, or later queryable Loki persistence. A lost
receiver response after that write can cause an exact-body duplicate on retry.

| Receiver result | Future MDK action |
| --- | --- |
| HTTP 200 `{}` | Advance the prepared range cursor after its local durable acknowledgement commit. |
| HTTP 409 (downstream 4xx, including 400 or 429) | Retain and block the whole range for explicit reconciliation; Loki may have accepted a subset. |
| HTTP 503, timeout, connection loss, or other transient 5xx | Retain and retry the exact range with bounded backoff; accepted prefixes may duplicate. |
| Receiver HTTP 400/413, 401/403, other terminal 4xx, malformed success, or any other 2xx | Retain and block until input, credential, or configuration is corrected. |

Loki's push API has no OTLP `partialSuccess` body. Its
[distributor](https://github.com/grafana/loki/blob/main/pkg/distributor/distributor.go)
can write valid entries and then return 400 for rejected entries, or 429 when
some streams are accepted.
The receiver maps any downstream 4xx to 409 without copying Loki's error body;
this blocks even a 429 that may have written nothing. An unexpected downstream
2xx, 5xx, malformed response, or exception becomes 503. A 5xx or connection
failure may also follow accepted writes. The receiver **never** reports full
success after a known or uncertain partial acceptance. Without a receipt ledger
or an atomic downstream transaction, this stack cannot provide exactly-once
delivery or identify the accepted subset. Loki 204 is API acceptance, not a
persistence proof. The future sender must inspect the full response, not just
the 2xx status class.

## Run the synthetic contract

From the MDK repository root:

```sh
just audit-otlp-receiver-contract
```

This starts an ephemeral receiver and an ephemeral fake Loki HTTP service for
each test and reads the fake service back over HTTP. No Docker, real audit data,
external network service, or production credential is involved. To run the
receiver manually against a disposable loopback Loki-compatible push service:

```sh
export AUDIT_CONTRACT_TEST_TOKEN='replace-with-local-test-token'
uv run --with 'jsonschema==4.25.1' python scripts/audit-otlp-receiver/receiver.py \
  --sink-url http://127.0.0.1:3100/loki/api/v1/push \
  --token-env AUDIT_CONTRACT_TEST_TOKEN
```

The printed listener URL is also loopback and ephemeral. Production Alloy/Loki
configuration, Goggles ingestion, MDK runtime ownership, client bindings,
retention, and a real Loki durability/readback gate require separate work.
