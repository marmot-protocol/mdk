---
title: "Nostr's Role in Marmot — Three Layers"
created: 2026-04-19
updated: 2026-05-09
tags: [marmot, overview, nostr, identity, transport]
status: overview
---

# Nostr's Role in Marmot — Three Layers

"Marmot uses Nostr" is imprecise. Nostr plays three distinct roles, and they're deliberately independent. Understanding the separation clarifies what can be changed, what can't, and why.

---

## Layer 1: Identity (non-negotiable)

Marmot uses **Nostr keypairs as identity**. Every participant is a Nostr pubkey (npub). Group membership is defined in terms of npubs. KeyPackages are published to Nostr relays; users are discovered via NIP-65.

This is foundational. Marmot is deliberately built on Nostr's identity ecosystem — you get existing users, existing relay infrastructure, existing social graph, without bootstrapping a new naming system.

**No matter what transport Marmot uses, participants are identified by Nostr keypairs.**

---

## Layer 2: Application message format (always Nostr, never signed)

Inside every MLS-encrypted payload, the application message is structured as a **Nostr event** — `{ kind, content, pubkey, tags }`. This is the chat message, the reaction, the reply.

**Critically: these inner events are never signed.**

A signed Nostr event can be taken out of context and republished to relays — it's permanently attributable to the sender. An unsigned inner event (a "rumor" in Nostr terminology) can't be published to any relay — relays reject unsigned events. MLS group encryption provides the authentication that a Nostr signature would normally provide; omitting the signature removes attribution risk without losing integrity.

The inner event structure is **tied to Nostr identity** (the `pubkey` field is the author's npub) but **independent of transport**. Whether the outer MLS blob travels via Nostr relays or a different transport, the inner event is identical.

---

## Layer 3: Transport (pluggable)

**Nostr relays are Marmot's default transport** — MLS ciphertext wrapped in kind 445 events (for group messages) or kind 1059 gift-wraps (for welcomes), published to relays.

But transport is explicitly pluggable. A different transport (FIPS mesh, direct P2P, BLE, etc.) would have its own wrapping. The outer envelope is purely a transport concern; the inner application message stays Nostr-structured regardless.

The `TransportAdapter` and `TransportPeeler` traits are the explicit seams
where this pluggability happens (see [`target-architecture.md`](./target-architecture.md)).

In this workspace, `crates/transport-nostr-adapter` is the Nostr adapter core:
account activation, group subscription sync, relay-event routing, and publish
reports behind an injectable relay-client boundary. It also removes stale group
subscriptions on group sync and exposes adapter-local diagnostics. Its optional
`sdk` feature provides the first `nostr-sdk` backed relay client and exposes
redacted relay-health summaries. Reconnect/backoff, retry interval adjustment,
jitter, and relay status mechanics remain owned by `nostr-sdk`.
`crates/transport-nostr-peeler` is the Nostr/MLS peeler layer. It maps kind
`445` / `1059` event shapes into engine transport messages, peels kind `445`
group envelopes, and handles NIP-59 welcome gift-wraps when the account-device
layer supplies the local signer/decrypter. Production relay auth, app-level
relay policy, telemetry export, and account key-management integration still
sit above those crates.

---

## The full picture

```
  Application message (Layer 2)
    Unsigned Nostr event: { kind, content, pubkey, tags }
    • pubkey = sender's npub (Layer 1)
    • no signature — authentication comes from MLS group membership
      ↓ MLS encryption (CgkaEngine)
  MLS ciphertext (opaque blob)
      ↓ TransportPeeler wraps for transport
  Transport envelope (Layer 3 — transport-specific)
    Nostr:  kind 445 gift wrap → relay
    FIPS:   raw bytes → mesh routing
    Direct: raw bytes → connection
```

---

## What can change and what can't

| Layer | Pluggable? | Why |
|---|---|---|
| Identity | No | Foundational design choice; Marmot is Nostr-identity-native |
| Application message format | No | All Marmot messages have Nostr-event structure inside MLS |
| Transport | **Yes** | The `TransportAdapter` + `TransportPeeler` traits make this explicit |

---

## Common misconception

> *"Marmot messages are Nostr events."*

Sort of, but imprecisely. **Inside** MLS encryption, application messages have Nostr-event structure. **Outside** MLS (when using Nostr relay transport), they're wrapped in Nostr events too. These are different things. Using a non-Nostr transport, there are no outer Nostr events — but the inner application messages are still Nostr-structured.

---

## See also

- Deep reference: [`../further-context/nostr-role-in-marmot.md`](../further-context/nostr-role-in-marmot.md)
