---
title: "Capability Negotiation"
created: 2026-04-19
tags: [marmot, overview, capability-negotiation, interop]
status: overview
updated: 2026-05-08
---

# Capability Negotiation

Capability negotiation is a **first-class protocol requirement**, not an optional add-on. It's load-bearing for every other interop goal Marmot has.

---

## Why it exists

- **Different Marmot clients will support different features.** Some will implement disappearing messages; some won't. Some will support multi-device; some won't. This diversity is the point — it's what makes Marmot an ecosystem rather than a single codebase.
- **Groups must form correctly given whichever clients the members happen to be on.** If Alice is on a feature-rich client and Bob is on a basic one, the group they create must be the best group *they can both participate in* — not the superset of Alice's features.
- **Groups must evolve over time as capabilities improve.** If Bob later upgrades, features both members support can activate without rebuilding the group.
- **Without capability negotiation, the protocol either forces every client to implement everything (impossible at scale) or breaks silently on mismatches.**

---

## The philosophy: progressive enhancement

Borrowed from the web: HTML renders on any browser; progressive enhancement layers in richer experiences for capable clients. The underlying communication always works; the experience improves with capability.

For Marmot:
- Create the best group possible given current participants' capabilities.
- Show what's available; show what could be available.
- Never block communication on ideal conditions.

---

## The MLS mechanism

RFC 9420 provides the building blocks:

- Every member's **`KeyPackage`** declares their supported extension types and proposal types.
- The **`RequiredCapabilities`** group extension declares which types all current and future members must support.
- When adding a new member, their KeyPackage must cover everything in `RequiredCapabilities`.

Marmot builds three queries on top:

1. **`constructable_capabilities(members)`** — given these members' KeyPackages, what's the maximum feature set a group with them can support?
2. **`feature_status(group_id, feature)`** — for a specific feature in a specific group: Available, Upgradeable, or Unavailable (with what's missing).
3. **`upgradeable_capabilities(group_id)`** — which features could be upgraded to required in this group right now?

---

## What every compliant client must do

- **Advertise accurately.** Each client's `KeyPackage` declares the extension types and proposal types the client supports.
- **Negotiate at group creation.** Compute `RequiredCapabilities` from the intersection of intended members' capabilities; create the best group all members can participate in.
- **Enforce on add.** New member's `KeyPackage` must cover the group's `RequiredCapabilities`. If it doesn't, refuse with a clear error naming what's missing.
- **Respect progressive enhancement.** Never hard-block communication on an optional feature. If a capability isn't universal, the feature it enables simply isn't active.
- **Support upgrade.** If every current member advertises a new capability (via self-update), the group can upgrade `RequiredCapabilities` to include it.

---

## Where it lives in the implementation

Capability negotiation is part of **the protocol implementation itself** (MDK today, any future Marmot protocol library). It is NOT a client-level responsibility to bolt on. Every client linking against a compliant implementation gets capability negotiation for free, correctly, by default.

This is the single most important "baked into every client from the beginning" requirement.

---

## What it unlocks

- **Flexible group construction** — starting a group with more powerful clients stays an option; the capability system scopes the group correctly to what all members can do.
- **Swap-in path for new CGKA backends** — a different CGKA is effectively a capability; ecosystem-wide adoption is progressive, not lockstep.
- **Swap-in path for new transports** — same pattern; FIPS mesh or future transports can land without forcing all existing groups to migrate.
- **Swap-in path for new features** — disappearing messages, multi-device, media encryption, future things — each gets added as a capability and used by groups whose members support it.
- **No forced migration flag days.** Clients upgrade on their own timelines. Groups adapt as members upgrade.

---

## Current implementation status

The current engine has runtime `FeatureRegistry` support, required/optional
capability registration, group creation checks, invite checks, and structured
errors for missing capabilities.

The per-leaf capability cache is still load-bearing: OpenMLS exposes
capabilities on leaf nodes, but the engine cannot walk arbitrary public-group
leaves through a stable public API in the shape we need. The cache is populated
from KeyPackages, staged Add proposals, and the local member's own leaf node.

---

## See also

- Deep reference: [`../further-context/capability-negotiation.md`](../further-context/capability-negotiation.md)
- The principles doc this implements: [`../../required-features.md`](../../required-features.md)
