---
title: "Local Daemon Protocol Boundaries"
created: 2026-09-04
updated: 2026-09-04
tags: [marmot, daemon, cli, agent-control, unix-socket]
status: current-implementation
---

# Local Daemon Protocol Boundaries

MDK currently has two local Unix-socket protocols. They both use newline-terminated JSON and deliberately bounded
inbound messages, but they serve different consumers and are not wire-compatible.

## Protocol Comparison

| Property | `wnd` CLI daemon protocol | `wn-agent` agent-control protocol |
| --- | --- | --- |
| Consumer | MDK's own CLI and TUI | Local agent integrations |
| Wire model | Internal `DaemonRequest` variants carrying the CLI command shape | Stable, typed request/response/event DTOs inside `marmot.agent-control.v2` envelopes |
| Correlation and versioning | No request id or explicit protocol version | Optional correlation id, an explicit protocol label, and request-id idempotency for stream begin |
| Authorization | Owner-only socket plus same-UID peer checks | Same-UID peer checks by default, or an explicitly configured full-control bearer token |
| Errors | CLI output envelopes; no protocol-wide retryability field | Typed error responses with an explicit, fail-closed `retryable` field |
| Size boundary | 1 MiB cap on each inbound daemon request; responses do not yet have a symmetric protocol cap | 1 MiB per-frame cap in the shared agent-control codec |
| Sensitive input buffers | Request assembly and decoded request bytes use zeroizing buffers; buffered read-ahead is not guaranteed to be erased | The generic frame codec uses ordinary byte buffers |

Both servers accept one request per connection. A non-streaming `wnd` client reads its response to EOF, while its
subscription clients read newline-delimited stream records until `stream_end` or EOF. Agent control returns a typed
response envelope or keeps an inbound-subscription connection open for typed event envelopes; the envelope id is
echoed on those responses and events.

These differences are intentional. The CLI daemon protocol is an internal presentation transport and can evolve with
the command surface. Agent control is an integration API whose version label, typed data transfer objects, error
retryability, authentication option, and idempotency behavior are part of its compatibility boundary.

## Framing Consolidation Boundary

The similar newline framing is an implementation pattern, not a shared semantic contract. A future consolidation
should be limited to a small framing primitive that can:

- enforce a caller-selected payload cap symmetrically;
- distinguish clean EOF from an incomplete frame;
- optionally erase its input buffer; and
- allow the owning protocol to apply its own read and write deadlines.

Protocol versioning, data transfer objects, request ids, authorization, retry semantics, connection lifetime, and
response framing must remain owned by their respective protocols. Until a shared primitive preserves the CLI daemon's
zeroization requirement and adds a symmetric response bound, replacing its reader directly with the generic
agent-control codec would regress the CLI daemon's handling of sensitive request material.
