---
title: "The Role of Nostr in Marmot"
created: 2026-04-16
tags: [marmot, nostr, identity, wire-format, transport, architecture]
status: reference
related:
  - [[target-architecture]]
  - [[cgka-engine-design]]
---

# The Role of Nostr in Marmot

**The problem this solves:** "Marmot uses Nostr" gets treated as a single architectural decision, which leads to
confusion about what can be changed and what can't. Engineers reasonably ask: if we add FIPS mesh transport, do we still
use Nostr? The answer is "yes and no" — which is only clear once you understand that Nostr plays three distinct roles in
Marmot, each independently. This document separates them.

"Marmot uses Nostr" is true but imprecise. Nostr plays three distinct roles, and they are deliberately independent.
Understanding the separation is important because it explains what can be changed, what can't, and why.

---

## Layer 1: Identity (non-negotiable)

Marmot uses **Nostr keypairs as identity**. Every participant is a Nostr pubkey (npub). Group membership is defined in
terms of npubs. Key packages are published to Nostr relays and discovered via NIP-65. The social graph, relay discovery,
and user lookup all run on Nostr infrastructure.

This is foundational and not pluggable. Marmot is deliberately built on top of Nostr's network and its identity
ecosystem — that's the point. You get existing users, existing relay infrastructure, existing social graph, and no need
to bootstrap a new naming/discovery system from scratch.

No matter what transport you use to carry Marmot messages, the participants are identified by Nostr keypairs.

---

## Layer 2: Application message format (always Nostr, never signed)

Inside every MLS-encrypted payload, the application message is structured as a **Nostr event** — it has a `kind`,
`content`, `pubkey` (the author's npub), and `tags`. This is the chat message, the reaction, the reply — whatever the
application is sending.

**Critically: these inner events are never signed.**

This is a deliberate security property, not an oversight. In standard Nostr, a signed event can be taken out of context
and republished to relays — it's permanently attributable to the sender. The unsigned inner event (a "rumor" in Nostr
terminology) cannot be published to any relay, because relays reject unsigned events. If the MLS encryption were somehow
broken and the payload exposed, the message content would be visible but couldn't be cryptographically attributed to the
sender.

The MLS group encryption provides the authentication that a Nostr signature would normally provide — you know who sent
the message because they're a group member and MLS authenticates group messages. The Nostr signature is redundant and
adds attributability risk, so it's omitted.

**The inner event structure is tied to Nostr identity** (the `pubkey` field is the author's npub) but it is independent
of transport. Whether the outer MLS blob travels via Nostr relays or a FIPS mesh or a direct connection, the inner event
structure is identical.

### Why Nostr event structure?

Using the Nostr event format for application messages means:

- Rich, flexible content model (kinds, tags) that the ecosystem already understands
- Unsigned events are a well-defined concept in Nostr (rumors/rumours)
- Easy for developers familiar with Nostr to reason about message structure
- Future extensibility: new message kinds can be added without changing the encryption layer

---

## Layer 3: Transport (pluggable)

**Nostr relays** are Marmot's default transport — encrypted MLS blobs are wrapped in Nostr events (kind 445,
gift-wrapped) and published to relays. This provides censorship-resistant distribution: any relay that will store the
ciphertext keeps the group alive.

But transport is explicitly pluggable. The outer wrapping is the `TransportPeeler`'s job (see [[target-architecture]]):

- **Nostr relay transport**: MLS blob → kind 445 gift wrap → relay. The gift wrap uses a random ephemeral key (not the
  sender's identity key) so relay operators can't determine who sent what to whom.
- **FIPS mesh transport** (potentially future): MLS blob → raw bytes → FIPS mesh. FIPS provides its own hop-by-hop and
  end-to-end encryption, so no Nostr outer wrapper is needed. The inner Nostr event is still there inside the MLS
  payload.
- **Direct transport** (hypothetical): MLS blob → raw bytes → direct connection.

The key point: **the outer envelope is purely a transport concern**. It exists to carry the MLS blob from sender to
recipient over a specific network. Different transports use different envelopes. The inner application message (unsigned
Nostr event inside the MLS encryption) is the same regardless of which transport carries it.

---

## The full picture

```
┌─────────────────────────────────────────────────────────────┐
│  Application message (Layer 2)                              │
│                                                             │
│  Unsigned Nostr event: { kind, content, pubkey, tags }      │
│  • pubkey = sender's npub (Nostr identity, Layer 1)         │
│  • no signature — intentionally deniable                    │
│  • authentication comes from MLS group membership           │
└───────────────────────┬─────────────────────────────────────┘
                        │ MLS encryption (CGKA Engine)
                        ↓
┌─────────────────────────────────────────────────────────────┐
│  MLS ciphertext                                             │
│  (opaque encrypted blob — transport doesn't see inside)     │
└───────────────────────┬─────────────────────────────────────┘
                        │ TransportPeeler wraps for transport
                        ↓
┌─────────────────────────────────────────────────────────────┐
│  Transport envelope (Layer 3) — transport-specific          │
│                                                             │
│  Nostr relay:  kind 445 gift wrap → relay                   │
│  FIPS mesh:    raw bytes → mesh routing                     │
│  Direct:       raw bytes → connection                       │
└─────────────────────────────────────────────────────────────┘
```

---

## What this means for the spec

The three layers should be specified independently:

- **Identity layer spec**: How Marmot uses Nostr keypairs, NIP-65 relay discovery, key package publication and lookup.
  This spec doesn't change regardless of transport.
- **Application message format spec**: The unsigned Nostr event structure inside MLS payloads. Wire format, supported
  kinds, tagging conventions. Transport-agnostic.
- **Transport specs** (one per transport): How MLS blobs are wrapped and carried for a specific transport. The Nostr
  relay transport spec defines kind 445, gift wrapping, relay selection. A future FIPS transport spec would define how
  MLS blobs are addressed and carried over the FIPS mesh.

The transport spec is the only one that changes when you add a new transport. The identity and message format specs are
stable.

---

## Common misconception

> "Marmot messages are Nostr events"

Sort of — but imprecisely. The _application messages inside_ the MLS encryption have Nostr event structure. The _outer
transport envelopes_ are Nostr events (when using Nostr relay transport). These are different things. When using a
non-Nostr transport, there are no outer Nostr events at all — but the inner application messages are still
Nostr-structured.
