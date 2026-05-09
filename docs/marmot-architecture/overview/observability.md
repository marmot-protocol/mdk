---
title: "Observability & Privacy"
created: 2026-05-09
updated: 2026-05-09
tags: [marmot, overview, observability, tracing, privacy]
status: overview
---

# Observability & Privacy

Marmot diagnostics must help operators understand lifecycle and failure modes
without exposing protocol state, transport routes, or user data.

## What tracing may include

- Crate/module `target` and method name.
- Counts, booleans, enum/status names, and coarse outcomes.
- Retry or lifecycle state that is not tied to a specific account, group,
  message, relay, pubkey, or payload.

## What tracing must not include

- Account ids, member ids, group ids, message ids, transport group ids, relay
  URLs, Nostr pubkeys, event ids, subscription ids, or payload references.
- Plaintext, ciphertext, MLS wire bytes, Nostr event content, key material,
  private keys, database paths, or raw SQLCipher keys.
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

Keep field names neutral. Prefer `endpoint_count` over a field or local name
that contains a concrete relay URL. Prefer `delivered` over a message id.

## Current enforcement

`crates/cgka-conformance-simulator/tests/tracing_audit.rs` scans production
Rust source for qualified and imported tracing calls. It requires explicit
`target` and `method` fields and rejects known-sensitive token names inside
tracing macro bodies.

The same audit rejects direct `println!`, `eprintln!`, and `dbg!` output from
production library source.

CLI output generators such as the conformance report writer and Tamarin
policy-case generator may use `println!` / `eprintln!` for their explicit
artifact output. That output is not runtime application logging.

## Transport note

The Nostr adapter does not implement its own reconnect loop. The optional
`nostr-sdk` client relies on SDK `RelayOptions` for reconnect/backoff, retry
interval adjustment, jitter, relay status, and connection stats. Marmot exposes
only aggregate/redacted relay-health summaries.
