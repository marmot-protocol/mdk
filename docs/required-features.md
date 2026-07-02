---
title: "Required Features — What Marmot the Protocol Defines, and What It Doesn't"
created: 2026-04-19
updated: 2026-05-08
tags: [marmot, architecture, protocol, interop, capability-negotiation, decoupling]
status: principles
related:
  - [[marmot-architecture/target-architecture]]
  - [[marmot-architecture/capability-negotiation]]
  - [[marmot-architecture/custom_extensions]]
---

# Required Features — What Marmot the Protocol Defines, and What It Doesn't

**Purpose of this doc.** Name, concretely, the interop-required surface of Marmot — what every compliant client must
implement — and the parts that stay at the application layer where clients are free to differentiate. This is a
principles document, not a spec: it defines the _shape_ of the line between protocol and application, so that future
MIPs and future features can be placed on the correct side of that line deliberately rather than by reflex.

The central framing: **Marmot is a thick protocol where it needs to be and a thin one everywhere it can be.** Messaging
interop across independent clients and devices demands protocol-level agreement on some things. Everything else should
stay with the client.

---

## 1. The principle: the thinnest protocol that still guarantees messaging interop

Marmot's job is to define what's required for independent clients and devices to exchange encrypted group messages
correctly. That's a tighter surface than most messenger protocols draw — specifically:

- **We are a thicker protocol than MLS alone.** MLS is explicitly agnostic about application concerns. Marmot has to
  define enough application-layer structure that two different Marmot clients can be in the same group and have its
  features work consistently.
- **We are a thinner protocol than most messenger "apps." ** A product like Signal bundles protocol, UI, storage, key
  management, notification strategy, and social graph into one shippable thing. Marmot doesn't. Marmot defines only the
  interop-required substrate; everything above it is client freedom.

The rule of thumb for whether something belongs in the protocol:

> **If inconsistent interpretation across clients would break the feature for members of the same group, it belongs in
> the protocol. Otherwise it can stay at the application layer.**

This is the test to apply when a new feature is proposed. The default answer should NOT be "add it to the protocol." The
default should be "what's the smallest protocol surface this feature needs, if any?"

---

## 2. What lives in the protocol layer (interop-required)

These are the things every compliant Marmot client must agree on, bit-for-bit, for groups to work across
implementations:

### 2.1 Group state and state evolution

- How groups are created, including the capability-negotiation phase at creation time (§5)
- How members are added, removed, and how identity-scoped operations behave
- How commits advance epochs and how remaining members converge
- The two-layer message model (transport wrap + CGKA ciphertext) and how each layer is peeled
- Race / fork handling rules (auto-commit patterns, committer-not-in-removed-set rules, proposal visibility rules)

### 2.2 Wire formats

- Every byte layout that crosses the wire, in both directions
- Every extension type Marmot defines, its byte layout, and its versioning rules
- Every proposal type Marmot defines (currently none; `IdentityRemove` is the first candidate — see
  `custom_extensions.md` §7)
- Every Nostr event kind Marmot uses or defines, and its tag / content semantics
- Every `authenticated_data` contribution Marmot makes

### 2.3 Identity binding

- How a Nostr identity maps to an MLS credential
- How signing keys relate to that identity
- How identity is proven for operations that span the Nostr / MLS boundary (e.g., the `kind: 450` Nostr identity proof
  pattern used by MIP-06)

### 2.4 Capability negotiation itself

- The mechanism by which clients advertise which features they implement
- The rule for computing a group's `RequiredCapabilities` at creation time
- The rule for upgrading a group's capabilities over time
- See §5 below for why this is load-bearing

### 2.5 Exported secrets and their derivation labels

- How any Marmot subsystem derives cryptographic material from the MLS group state (currently:
  `MLS-Exporter("marmot", "group-event", 32)` for kind-445 outer wrap,
  `MLS-Exporter("marmot", "encrypted-media", 32)` for encrypted media, and similar labels for MIP-06)
- Whether that derivation is via raw MLS-Exporter or via the MLS Extensions Safe Framework's
  `SafeExportSecret(ComponentID)` (direction: Safe framework for one-shot component secrets; reusable per-epoch secrets
  must keep a registered raw exporter label until the protocol defines another shape)

**What "protocol-level" means concretely:** if a change to any of these breaks byte compatibility, it's a protocol
change requiring coordinated client updates, capability negotiation rules, and (if needed) migration strategy. Protocol
changes are slow and deliberate.

---

## 3. What lives in the application layer (client freedom)

The protocol line stops at message content _interpretation_ and everything above. Clients are free to differentiate on:

### 3.1 Display and UX

- How chat messages are rendered, formatted, styled
- How groups are presented in lists, pinned, archived
- Search, filtering, threading, reaction UI
- Avatars, themes, accessibility choices

### 3.2 Which Nostr kinds a chat client supports inside MLS application messages

- Kind 9 (chat message) is the baseline almost every client will support
- Kinds for replies, reactions, polls, link previews, embeds — clients choose which to render and which to ignore
- An unknown-to-this-client kind should degrade gracefully (display as "unsupported content" or similar), not break the
  group

### 3.3 Notification strategy

- Whether to support push notifications (MIP-05 is optional)
- Local notification logic, bundling, do-not-disturb hours
- Whether to integrate with platform notification services

### 3.4 Key custody and signer integration

- Local key storage vs. NIP-46 remote signer vs. hardware signer (Amber, Nunchuk, etc.)
- Backup and recovery UX
- Multi-device key handoff beyond what MIP-06 specifies

### 3.5 Storage and caching

- Local database schema (the protocol says nothing about this)
- Message retention policy beyond what `disappearing_message_secs` prescribes
- Cache eviction, offline behavior

### 3.6 Integrations

- Zaps, Slack/Discord mirrors, AI agents, etc.
- Nothing in the protocol prevents these; they're client-level extensions built on top

### 3.7 Performance and reliability strategy

- Connection pooling, retry logic, relay selection
- Local-first or server-assisted architectural choices above the protocol line

**The net effect:** two Marmot clients can differ substantially in feel, features, and strategy while still being in the
same group and exchanging messages correctly. That's the explicit goal.

---

## 4. Technology decoupling — the swap points

A major goal going forward is to make sure that **no specific underlying technology choice is baked into what "Marmot"
means**. The protocol should be expressible independently of its current implementation stack. The current target
architecture uses explicit trait boundaries to keep that true.

### 4.1 CGKA backend — swappable

MLS (RFC 9420, via OpenMLS) is Marmot's CGKA today. That's an implementation choice, not a protocol requirement. The
protocol package defines a `CgkaEngine` interface; any CGKA that can satisfy it (a different MLS library, a future
BeeKEM-based CGKA, a hypothetical causal-order CGKA) could be the backend. The CGKA backend is the interoperability
boundary — clients in the same group must use the same CGKA — but **which CGKA** is a swappable decision.

### 4.2 Transport — swappable

Nostr relays are Marmot's transport today (kind 445 outer wrap, kind 1059 gift-wrap for welcomes, kind 30443 for
KeyPackages). That's also an implementation choice. The protocol package defines `TransportAdapter` and
`TransportPeeler` interfaces; any transport that can move opaque encrypted blobs between members can be plugged in —
Nostr relays today, FIPS mesh or direct P2P tomorrow. Multiple transports can run simultaneously for the same group.

### 4.3 Blob storage — swappable

Blossom is the reference content-addressed blob storage Marmot uses today for `encrypted-media-v1` and group images.
But Blossom is **just one of many possible content-addressed blob backends**. The same shape — encrypted blob identified
by content hash, uploaded and fetched via some authenticated HTTP-ish channel — could be served by S3, IPFS, a plain
filesystem over a self-hosted API, a corporate content server, etc. The protocol should define what the blob is
(encrypted media, encrypted group image) and how keys are derived for it, not which specific storage service stores it.
This probably means our current MIPs around this are underspecified because how to find the image should be baked into
the spec.

### 4.4 Identity backend (with a caveat)

Nostr is Marmot's identity backend, and per `nostr-role-in-marmot.md` this is foundational and **not intended to be
swappable** the way the others are. Marmot is built on Nostr identity deliberately. But the structural boundary still
matters: the protocol package should be clear about which parts are Nostr-identity-specific (credential format,
`kind: 450` proof pattern, NIP-44 for device-to-device encryption) vs. which parts are transport-layer Nostr use (kind
445, kind 1059 — these are Nostr-transport, not Nostr-identity).

### 4.5 The general principle

**The protocol package must not bake in the specifics of any replaceable technology.** Where a specific technology is in
use today (MLS, Nostr relays, Blossom), the protocol should document the interface it needs from that technology and
define how a replacement would plug in. The current boundary model is
`Application -> CgkaEngine -> TransportPeeler -> TransportAdapter`, with storage below the engine.

---

## 5. Capability negotiation — a first-class protocol requirement

Capability negotiation is not an optional add-on. It's load-bearing for everything else this doc says.

### 5.1 Why it's load-bearing

- **Different clients will support different features.** Some clients will implement disappearing messages; some won't.
  Some will support multi-device; some won't. That diversity is a feature, not a bug — it's what makes Marmot an
  ecosystem rather than a single codebase.
- **Groups must form correctly given whichever clients the members happen to be on.** If Alice is on a feature-rich
  client and Bob is on a basic client, the group they create must be the best group _they can both participate in_ — not
  the union of what Alice's client wants, which would exclude Bob.
- **Groups must evolve over time as capabilities improve.** If Bob later upgrades to a feature-rich client, the group
  should be able to activate features both members now support, without forcing a full rebuild.
- **Without capability negotiation, the protocol either forces all clients to implement every feature (impossible at
  scale) or breaks silently when mismatches occur.**

### 5.2 What's required of every compliant client

Every Marmot client must implement capability negotiation natively. Specifically:

- **Advertise capabilities.** Each client's KeyPackage must accurately declare which extensions and proposal types the
  client supports (via `LeafNode.capabilities`).
- **Negotiate at group creation.** When a client creates a group, it must compute `RequiredCapabilities` as the
  intersection of the proposed members' advertised capabilities (or specifically: the most-capable group all members can
  participate in, per the progressive-enhancement principle in `capability-negotiation.md`).
- **Enforce on add.** When a new member is added to an existing group, their KeyPackage must cover the group's
  `RequiredCapabilities`. If it doesn't, the add must be refused with a clear error.
- **Respect progressive enhancement.** Never block communication on a feature being optional. If a capability isn't
  universally supported, the feature it enables simply isn't active for that group.
- **Support upgrade over time.** If every current member of a group gains support for a new capability (via self-updates
  advertising new caps), the group can upgrade its `RequiredCapabilities` to include it. This is native MLS behavior we
  should lean into.

### 5.3 What this gives us

- **Flexible group construction.** Starting groups with more powerful clients is still an option — the capability system
  just ensures the group is correctly scoped to what all members can do.
- **Swap-in paths for new CGKA backends.** The CGKA backend itself is effectively a capability — a group expressing "I
  use backend X" via its extensions. Different CGKA backends can coexist in the ecosystem even if a given group must
  pick one.
- **Swap-in paths for new transports.** Transports are capabilities too. A group can declare "this group uses transport
  Y" and member KeyPackages advertise which transports they speak.
- **Swap-in paths for new blob stores.** Blob store choice might be group-scoped (everyone uses the same Blossom server)
  or member-scoped (each member chooses their own, with handoff conventions) — either way expressible via the capability
  system.
- **Evolution without lockstep migration.** We never need to say "every Marmot client must upgrade by date X." Clients
  advertise what they support; groups use what's universally available; features activate progressively.

### 5.4 Where this lives in the implementation

Capability negotiation is part of **the protocol implementation itself** — MDK today, any future Marmot protocol library
tomorrow. It is NOT a client-level responsibility to bolt on. Every client that links against MDK (or another compliant
implementation) gets capability negotiation for free, correctly, by default.

This is the single most important "baked into every client from the beginning" requirement. The architecture explicitly
depends on it.

---

## 6. Relationship to other architecture docs

- **[[marmot-architecture/target-architecture]]** — the component-level architecture (CgkaEngine / TransportAdapter /
  TransportPeeler / application) that implements the decoupling described in §4.
- **[[marmot-architecture/capability-negotiation]]** — the detailed design for what §5 of this doc requires.
- **[[marmot-architecture/custom_extensions]]** — the decision framework for how to place a new custom primitive on the
  protocol-or-application line, including the Safe Extensions framework that informs how new protocol-level data should
  be structured.

---

## 7. TL;DR

- **Marmot is the thinnest protocol that still guarantees messaging interop across independent clients and devices.**
  Thicker than MLS alone; thinner than a typical full messenger.
- **Protocol layer:** group state and its evolution, wire formats, identity binding, capability negotiation, exporter
  derivations. Byte-compatible across implementations.
- **Application layer:** display, UX, which message kinds to render, notification strategy, key custody, storage,
  integrations. Clients differentiate freely.
- **Technology decoupling goal:** CGKA backend, transport, and blob storage are all swappable. Nostr identity is
  foundational but structurally bounded.
- **Capability negotiation is not optional.** Every compliant client implements it natively (via MDK or equivalent).
  Groups negotiate the best group their members can all participate in at creation time, and can evolve capabilities
  over time via MLS's native mechanisms.
- **The test for any new feature:** would inconsistent interpretation across clients break this for members of the same
  group? If yes → protocol layer. If no → application layer.
