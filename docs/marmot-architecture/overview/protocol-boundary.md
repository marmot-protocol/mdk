---
title: "The Protocol / Application Boundary"
created: 2026-04-19
tags: [marmot, overview, protocol, application, interop]
status: overview
---

# The Protocol / Application Boundary

Marmot's central architectural principle: **be the thinnest protocol that still guarantees messaging interop across
independent clients and devices**. Thicker than MLS alone; thinner than a typical full messenger.

---

## The test

When deciding whether a new feature belongs in the protocol or at the application layer, ask:

> **Would inconsistent interpretation across clients break the feature for members of the same group?**

- **Yes → protocol layer.** All compliant clients must agree bit-for-bit.
- **No → application layer.** Clients are free to differentiate.

Default answer should NOT be "add it to the protocol." Default should be "what's the smallest protocol surface this
feature needs, if any?"

---

## What lives in the protocol layer

Every compliant Marmot client must agree on:

- **Surface:** **Group state & evolution**
  - **Examples:** Creation, add/remove, commit sequencing, epoch advance, two-layer message model, race handling rules

- **Surface:** **Wire formats**
  - **Examples:** Every byte layout across the wire; every extension type, proposal type, Nostr event kind,
    `authenticated_data` contribution Marmot defines

- **Surface:** **Identity binding**
  - **Examples:** Nostr identity → MLS credential mapping; signing key relations; identity proof patterns (e.g. `kind:
    450` from MIP-06)

- **Surface:** **Capability negotiation**
  - **Examples:** KeyPackage capability advertisement, `RequiredCapabilities` computation at group creation, upgrade
    rules

- **Surface:** **Exporter derivation labels**
  - **Examples:** How cryptographic material is derived from MLS group state (raw `MLS-Exporter` labels today;
    `SafeExportSecret(ComponentID)` going forward)

Changes to any of these require coordinated client updates. **Protocol changes are slow and deliberate.**

---

## What lives in the application layer

Clients are free to differentiate on:

- **Domain:** **Display & UX**
  - **Examples:** Message rendering, group list UI, threading, reactions, themes, accessibility

- **Domain:** **Which Nostr kinds the client renders**
  - **Examples:** Kind 9 (chat) baseline; replies/polls/link previews/embeds are per-client choices; unknown kinds
    degrade gracefully

- **Domain:** **Notification strategy**
  - **Examples:** Whether to support push (MIP-05 is optional), local notification logic, DND hours

- **Domain:** **Key custody & signers**
  - **Examples:** Local vs NIP-46 remote vs hardware (Amber, Nunchuk); backup and recovery UX

- **Domain:** **Storage & caching**
  - **Examples:** Database schema, retention policy beyond `disappearing_message_secs`, offline behavior

- **Domain:** **Integrations**
  - **Examples:** Zaps, Slack/Discord mirrors, AI agents — protocol doesn't prevent or require

- **Domain:** **Performance & reliability**
  - **Examples:** Connection pooling, retry logic, relay selection, local-first choices

**The net effect:** two Marmot clients can differ substantially in feel, features, and strategy while still being in the
same group and exchanging messages correctly. That's the explicit goal.

---

## Why we draw the line here

- **Thicker than MLS alone** — MLS is explicitly agnostic about application concerns, so Marmot has to define enough
  structure that disappearing messages, admin authorization, media encryption, etc. work consistently across clients.
- **Thinner than Signal/WhatsApp** — they bundle everything into one shippable product. Marmot deliberately doesn't.
- **Thinner than we've been reflexively adding to MIPs** — past MIPs sometimes pushed content into the protocol when
  client-level would have worked. Going forward, the test above gets applied explicitly at design time.

---

## Implications

- **The line is load-bearing for capability negotiation.** Different clients WILL support different features; the
  protocol layer needs to handle that gracefully (see [`capability-negotiation.md`](./capability-negotiation.md)).
- **The line is the main input to every new MIP decision.** Before writing a MIP, ask whether it needs to be one.
- **Client innovation lives above the line.** A new Marmot client can ship unique features without MIP coordination, as
  long as its protocol behaviour is compliant.

---

## See also

- Full principles doc: [`../../required-features.md`](../../required-features.md)
- Why thick-protocol: Bitcoin / Lightning-style reference-implementation model — [`direction.md`](./direction.md)
