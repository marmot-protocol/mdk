---
title: "Observability & Privacy"
created: 2026-05-09
updated: 2026-07-02
tags: [marmot, overview, observability, tracing, privacy]
status: overview
---

# Observability & Privacy

Marmot diagnostics must help operators understand lifecycle and failure modes without exposing protocol state, transport
routes, or user data.

## What tracing may include

- Crate/module `target` and method name.
- Counts, booleans, enum/status names, and coarse outcomes.
- Retry or lifecycle state that is not tied to a specific account, group, message, relay, pubkey, or payload.

## What tracing must not include

- Account ids, member ids, group ids, message ids, transport group ids, relay URLs, Nostr pubkeys, event ids,
  subscription ids, or payload references.
- Plaintext, ciphertext, MLS wire bytes, Nostr event content, key material, private keys, database paths, or raw
  SQLCipher keys.
- Values derived from user messages, group membership, or transport routing.

## Shape

Use explicit `target` and `method` fields:

```rust
tracing::debug!(
    target: "transport_nostr_adapter::adapter",
    method = "publish",
    endpoint_count,
    required_acks,
    "publishing transport message"
);
```

Keep field names neutral. Prefer `endpoint_count` over a field or local name that contains a concrete relay URL. Prefer
`delivered` over a message id.

## Sensitive-value classification

A sensitive value can escape through more than one exit. Each value class below lists the required posture per escape
route, so "does not leak" holds by construction rather than by author vigilance at every call site (tracked in
mdk#379).

| Value class | Memory | `Debug`/`Display` | FFI | Tracing/logs | Forensic audit |
| --- | --- | --- | --- | --- | --- |
| Key material (account secret, SQLCipher keys, media/avatar keys, exporter secrets) | `Zeroizing` for raw buffers and copies | Redacted (hand-written `Debug`, never derive on the holding struct) | Setters accept, accessors never return | Never | Never, either mode |
| Bearer/upload tokens (OTLP, audit tracker) | Short-lived; avoid long-lived copies | Redacted | Write-only: setters in, no read-back | Never | Never, either mode |
| Plaintext / decoded content | n/a | Only on message DTOs that never reach tracing | Allowed (it is the product) | Never | Full-data mode only; scrubbed at the sink in obfuscated mode |
| Full pubkeys / npubs | n/a | Allowed on DTOs | Allowed | Never | Full-data mode only; scrubbed at the sink; salted member refs are the obfuscated form |
| Relay URLs / endpoints | n/a | Structured fields only (never inside error `reason` strings) | Allowed | Never — log `endpoint_count` or a privacy-safe error kind | Allowed (audit is local-only, explicit opt-in) |
| Account/group/message ids | n/a | Allowed on DTOs | Allowed | Never | Allowed (hashed/truncated forms preferred) |
| Errors wrapping any of the above | n/a | Constructors keep `Display` free of URLs/ids/values | n/a | Log `error_kind = privacy_safe_kind()` (or `io::ErrorKind`, variant names) — never `{err}`/`error = %err` | `error_kind` strings only |

## Current enforcement

`crates/cgka-conformance-simulator/tests/tracing_audit.rs` scans production Rust source for qualified and imported
tracing calls. It requires explicit `target` and `method` fields, rejects known-sensitive token names inside tracing
macro bodies, and rejects raw-error interpolation (`error = %err`, `{err}`-style message formatting) so error `Display`
values — which may carry relay URLs, paths, or attacker-controlled content — never reach logs verbatim.

The same audit rejects direct `println!`, `eprintln!`, and `dbg!` output from production library source.

Sink-side enforcement backs up the producer rules: the forensic recorder scrubs full-data-only fields in obfuscated
mode (`marmot-forensics`), the Nostr adapter constructs operation-only error reasons, and `traits`/adapter tests pin
that `TransportAdapterError` `Display` carries no relay URL.

CLI output generators such as the conformance report writer and Tamarin policy-case generator may use `println!` /
`eprintln!` for their explicit artifact output. That output is not runtime application logging.

## Transport note

The Nostr adapter does not implement its own reconnect loop. The optional `nostr-sdk` client relies on SDK
`RelayOptions` for reconnect/backoff, retry interval adjustment, jitter, relay status, and connection stats. Marmot
exposes only aggregate/redacted relay-health summaries.

## Opt-in relay telemetry export

Separately from runtime tracing and logging (whose rules above are unchanged), Marmot MAY export relay performance
telemetry to a first-party metrics endpoint, carrying **relay identity as a metric label**, only when all of the
following hold:

- the user has explicitly opted in (off by default, revocable);
- the endpoint is Marmot-operated and reached over TLS;
- the export carries no account, member, device, group, subscription, pubkey, message, event, or IP-derived field;
- the data is aggregate counts and fixed-bucket histograms over a window — no per-event or per-timestamp rows;
- per-relay series are gated by k-anonymity at the dashboard (deployment parameter `k`; `k = 1` is permitted only for
  internal testing and MUST be raised before any external rollout);
- source IPs are not persisted against series.

Relay identity is the sole identifier permitted to leave the device, and only as the subject being measured, never as an
identifier of the reporter. This carve-out applies to the export channel alone and never to logs or traces. The full
contract, metric catalogue, and architecture live in
[`../relay-observability.md`](../relay-observability.md).
