---
title: "Dial Safety Collector Inventory"
created: 2026-09-15
updated: 2026-09-15
tags: [marmot, security, network, ssrf, collector, audit]
status: current-implementation
---

# Dial Safety Collector Inventory

This is the implementation inventory behind the
[Dial Safety](../overview/dial-safety.md) overview for the shared collector helper and
the forensic audit uploader that reuses it. It is not an assurance that every other
workspace HTTP client has been audited.

## Shared helper

`crates/marmot-app/src/collector_host_safety.rs` is the default-build chokepoint for
OTLP export, product analytics, and forensic audit-log POST uploads.

- Parse the configured URL with `config::parse_relay_telemetry_endpoint` before DNS.
  Reject missing hosts, unusable ports, userinfo, fragments, unsupported schemes, and
  nonlocal HTTP.
- Preserve the configured hostname, port, path, and query. Never rewrite the URL to a
  resolved IP; Host and SNI stay hostname-derived.
- Resolve once per attempt. Validate every DNS answer with
  `cgka_traits::app_components::reject_non_public_ip`. Empty or mixed-unsafe answers
  reject the whole attempt. Literal IPs skip DNS.
- Only an explicitly configured exact `localhost` or loopback IP literal gets the
  local-test exception, for HTTP or HTTPS. Every resolved address must then be
  loopback. Ordinary hostnames, `localhost` subdomains, and trailing-dot aliases do
  not receive that exception even when they resolve locally.
- Private, link-local, CGNAT, metadata, and unsafe IPv6/mapped addresses stay
  forbidden, including under the local-test exception.
- Pin with `resolve_to_addrs` on a fresh client. There is no DNS cache or
  cross-attempt connection pool; each retry resolves again.
- Disable automatic redirects and system proxies. Proxy-side DNS would bypass the
  pin. A `3xx` is a non-success status; no request, body, or bearer token is sent to
  the `Location` target, regardless of original or target scheme.
- Keep TLS verification enabled, including for local HTTPS collectors.
- DNS and connect are bounded at 10 seconds. The helper's request timeout is 30
  seconds. It does not wrap resolve-plus-send in an enclosing attempt deadline.

## Forensic audit upload

`crates/marmot-app/src/audit_log.rs` uses the same helper after snapshot capture and
v4 eligibility. It adds:

- retired-host rejection at the configured-URL gate, including case and trailing-root-dot
  equivalents, without copying endpoint literals;
- a 60-second request-level override and enclosing network-attempt deadline so explicit
  DNS cannot outlive the audit budget;
- bearer auth and the existing source headers only after validation and pinning;
- context-free `AppError::AuditLogUpload` messages or a numeric HTTP status, without
  endpoint, address, auth, header, or body material.

See [Forensic Audit Logging Inventory](../audit-logging.md) for the upload contract,
checkpointing, and header set.

## Timeouts

The shared helper supplies DNS/connect and request bounds only. Enclosing
attempt deadlines belong to callers.

| Budget | Shared helper | OTLP export | Product analytics | Audit upload |
| --- | --- | --- | --- | --- |
| DNS / connect | 10s | 10s (helper) | 10s (helper) | 10s (helper) |
| Request | 30s | 30s (helper) | 30s (helper) | 60s request override |
| Enclosing attempt | none | 30s resolve+send wrapper | none on send; 2s explicit-flush wrapper | 60s network-attempt deadline |

## Residual

This inventory documents the collector helper and the audit uploader that shares it.
Other workspace HTTP clients keep their own chokepoints on the overview page.
