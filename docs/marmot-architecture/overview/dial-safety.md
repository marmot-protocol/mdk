---
title: "Dial Safety"
created: 2026-07-04
updated: 2026-07-22
tags: [marmot, overview, security, network, ssrf, transport]
status: overview
---

# Dial Safety

Every outbound network connection Marmot opens must clear one host-safety discipline before a socket is opened. A dial
target is often attacker-influenced — a peer's agent-stream `Start` event, an agent-supplied `quic://` candidate, a
signed routing component, a welcome-rumor relay list, an imeta media locator — so a name or address that points at a
loopback / private / link-local / CGNAT / metadata endpoint is an SSRF vector, and a trust decision made from a
*resolved* address is a resolution-dependent downgrade. This is the network twin of
[Local Artifact Safety](local-artifact-safety.md).

## The rules

- **Validate every resolved address.** Resolve once, then run **each** resolved address through the shared classifier
  `cgka_traits::app_components::reject_non_public_ip` (or `reject_non_public_socket_addr`). It rejects the canonical
  unsafe-host set: `0.0.0.0/8`, RFC1918 private, `100.64.0.0/10` CGNAT, `127.0.0.0/8` loopback, `169.254.0.0/16`
  link-local (including `169.254.169.254`), multicast/reserved, and the IPv6 equivalents (loopback, ULA `fc00::/7`,
  link-local `fe80::/10`, IPv4-mapped, and the 6to4/Teredo/documentation transition ranges).
- **Pin the validated address.** Connect to the address that was validated, so the check and the connection cannot
  diverge (no DNS-rebind window). reqwest pins with `resolve_to_addrs`; the QUIC paths connect to the validated
  `SocketAddr` directly. Where a transport owns its own resolution (see the Nostr residual below) this degrades to a
  literal-host check.
- **Trust comes from configuration, not from a resolved IP.** No-certificate-verification trust (`InsecureLocal` /
  skip-verification) is reachable only via an explicit dev/config flag **and** a *literal* loopback candidate host
  parsed before resolution — never because a name happened to resolve to loopback.
- **Loopback is opt-in, never inferred.** A local/loopback endpoint is reachable only when an explicit dev/test flag is
  set (`MarmotAppConfig::allow_loopback_relay_endpoints` / `allow_loopback_blob_endpoints`, `WN_ALLOW_LOOPBACK_RELAYS` /
  `WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS`, `wn --insecure-local`, `wn-agent --insecure-local-broker`). The flag opens
  loopback only; private/link-local/CGNAT ranges stay rejected even in dev mode. Production leaves every flag unset.
- **Public Nostr relays require TLS.** Runtime relay connections use `wss://`. Plaintext `ws://` remains structurally
  valid signed routing data, but local policy admits it only for a literal loopback/`localhost` endpoint behind
  `allow_loopback_relay_endpoints`; the flag never admits public or private-network plaintext relays.
- **A connect timeout on every dial.** A hung handshake to a black-holed target must not park indefinitely (media 5s,
  Nostr relay 5s, QUIC broker 5s).

## The chokepoints

| Transport | Where the discipline lives |
| --- | --- |
| Blossom media (reqwest, download + upload) | `crates/marmot-app/src/media/blossom.rs`: `media_http_client_for_url` → `validate_blossom_fetch_url` + `resolve_media_host` (per-address `reject_non_public_ip`, `resolve_to_addrs` pin, connect/read/total timeouts, per-redirect re-validation). |
| Agent-stream broker watch (quinn) | `crates/marmot-app/src/runtime/agent_stream_watch.rs`: `resolve_broker_addr` validates + pins; `broker_trust_for_candidate` keys `InsecureLocal` on the literal candidate host + `insecure_local`. |
| Agent-connector broker dial (quinn) | `crates/agent-connector/src/quic.rs`: `resolve_quic_candidate_addr` validates + pins; `broker_trust_for_candidate` gated on `AgentConnectorConfig::allow_insecure_local_broker` + literal loopback. |
| CLI stream (quinn) | `crates/cli/src/commands/stream.rs`: `resolve_quic_candidate_addr` (`socket_addr_is_unsafe`), `broker_trust` / `ensure_insecure_local_endpoint`. |
| Nostr relays (nostr-sdk) | `crates/marmot-app/src/relay_plane/safety.rs`: `RelaySafetyPolicy::sanitize_endpoints` → `reject_unsafe_relay_host`, the single funnel for activation, group sync, publish, and directory routes. |
| QUIC broker client connect timeout | Shared QUIC-preview hardening (`connect_with_timeout` / `QUIC_PREVIEW_CONNECT_TIMEOUT`, #710), applied at both broker client connects in `crates/transport-quic-broker/src/client.rs`. |

The broker TLS client (`crates/transport-quic-broker/src/tls.rs`) keeps a resolved-address backstop
(`InsecureLocalRequiresLoopback`): even if a caller mis-selects `InsecureLocal`, a non-loopback resolved address is
refused. That backstop complements — it does not replace — the caller-side literal-host trust gate.

## The shared classifier

`cgka_traits::app_components::host_safety` owns the canonical unsafe-host set: `is_public_ip`, `is_loopback_ip`,
`is_loopback_host`, and the dial gate `reject_non_public_ip` / `reject_non_public_socket_addr`. Every outbound path
calls the same functions so SSRF hardening cannot drift between transports. Adding a new outbound connection without
routing through this discipline is a contract violation — the transport crates' `AGENTS.md` files point here.

## Accepted residual

Nostr relays are the one path that cannot pin: nostr-sdk owns DNS resolution and the WebSocket, so a public-looking
`wss://` domain is accepted after scheme/format validation and only its literal-IP form (and `localhost`) can be
classified before the SDK connects. A hostname that resolves to a private address at connect time is a TOCTOU
residual, rated LOW. Public plaintext `ws://` is rejected before this residual is reachable. A resolve-time pre-check
inside the adapter is a possible future complement, not a close condition.
