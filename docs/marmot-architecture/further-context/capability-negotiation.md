---
title: "Capability Negotiation"
created: 2026-04-16
tags: [marmot, mls, capabilities, key-packages, feature-flags, progressive-enhancement]
status: reference
related:
  - [[target-architecture]]
  - [[decision-points]]
  - [[index]]
---

# Capability Negotiation

**The problem this solves:** Marmot adds new features over time — disappearing messages, self-remove, media encryption —
but not all clients support all features. Without a clear capability system, adding a new feature either breaks old
clients or requires hard-forcing everyone to upgrade at the same time. Both are bad. This document describes a better
model: create the best group possible given current participants, upgrade gracefully as capabilities improve, and never
block communication on ideal conditions.

How Marmot determines which features are available in a group, how groups upgrade over time, and how the UI communicates
this to users.

---

## Where this lives in the architecture

Capability negotiation is a concern of the **CGKA Engine layer** — specifically, the part that understands KeyPackages
and MLS group extensions. It is not the transport's concern, not the application facade's concern, and not the UI's
concern.

```
┌─────────────────────────────────────────────┐
│  whitenoise-core (application)              │
│  calls: engine.feature_status(feature)      │
│  acts on result, never inspects internals   │
├─────────────────────────────────────────────┤
│  CgkaEngine / MDK                           │
│  ← capability negotiation lives here        │
│  reads: KeyPackages, GroupExtensions        │
│  computes: FeatureStatus for any feature    │
├─────────────────────────────────────────────┤
│  TransportAdapter / relays                  │
│  no knowledge of capabilities               │
└─────────────────────────────────────────────┘
```

The application layer only ever sees `FeatureStatus`. It never inspects KeyPackages or `RequiredCapabilities` directly.

---

## The core philosophy: progressive enhancement over hard breaks

**The wrong approach:** hard upgrades. Force everyone to update before they can participate. Block group creation if any
member runs an old client. This maximises feature correctness but minimises usability and creates cliff edges.

**The right approach:** progressive enhancement. Create the best group possible given the current participants'
capabilities. Show what's available. Show what could be available. Never block communication on ideal conditions.

This mirrors how the web works: HTML renders on any browser, progressive enhancement layers in richer experiences for
capable clients. The underlying communication always works; the experience improves with capability.

**For Marmot specifically:**

- A group between a Whitenoise user and an old client should still work — just without features the old client can't
  support
- A group between two Whitenoise users should automatically get the full feature set
- Users should see what features they're missing and why — as contextual hints, not blocking errors
- Groups should be able to upgrade automatically as capabilities improve, without user intervention where possible

---

## The MLS mechanism: RequiredCapabilities

MLS provides the building blocks via RFC 9420:

- Every member's **KeyPackage** declares their supported extension types and proposal types
- The **RequiredCapabilities** group extension declares which extension and proposal types all current and future
  members must support
- When adding a new member, their KeyPackage must include all types listed in `RequiredCapabilities`

This gives us everything we need:

1. **At group creation**: compute the intersection of all initial members' capabilities → set `RequiredCapabilities` to
   that intersection
2. **At any time**: compare current members' KeyPackages against the group's `RequiredCapabilities` to determine what's
   available, what's upgradeable, and who's blocking what

---

## The three capability queries

The engine exposes three fundamental queries:

### 1. `constructable_capabilities(members) → GroupCapabilities`

Given a set of members (by their KeyPackages), what is the maximum feature set a group with these members can support?

This is the **intersection** of all members' advertised capabilities. Used at group creation to set
`RequiredCapabilities` correctly.

```rust
fn constructable_capabilities(key_packages: &[KeyPackage]) -> GroupCapabilities {
    key_packages
        .iter()
        .map(|kp| &kp.extensions.capabilities)
        .fold(GroupCapabilities::all(), |acc, caps| acc.intersection(caps))
}
```

### 2. `upgradeable_capabilities(group) → GroupCapabilities`

Given the current group, what features could be enabled right now (all current members support them, but the group's
`RequiredCapabilities` hasn't been updated yet)?

This is: intersection of current members' capabilities MINUS what's already in `RequiredCapabilities`.

```rust
fn upgradeable_capabilities(group: &Group) -> GroupCapabilities {
    let member_intersection = constructable_capabilities(&group.current_member_key_packages());
    member_intersection.difference(&group.required_capabilities)
}
```

### 3. `feature_status(group, feature) → FeatureStatus`

For a specific feature, what's the current status in this group?

```rust
fn feature_status(group: &Group, feature: Feature) -> FeatureStatus {
    if group.required_capabilities.includes(feature) {
        return FeatureStatus::Enabled;
    }

    let blocking: Vec<Member> = group.current_members()
        .filter(|m| !m.key_package.capabilities.supports(feature))
        .collect();

    if blocking.is_empty() {
        // All members support it but group hasn't been upgraded yet
        return FeatureStatus::UpgradeAvailable;
    }

    // Check if blocking members are on Whitenoise (could update) or external clients
    let (can_update, external): (Vec<_>, Vec<_>) = blocking
        .iter()
        .partition(|m| m.is_whitenoise_client());

    FeatureStatus::MembersNeedUpdate { blocking: blocking }
}

pub enum FeatureStatus {
    /// Feature is active in this group
    Enabled,

    /// All members support it — admin can upgrade the group with one commit
    UpgradeAvailable,

    /// Some members' KeyPackages don't advertise support for this feature.
    /// We don't know why (old client, different client, haven't updated) —
    /// just that their KeyPackage capability advertisement is missing it.
    MembersNeedUpdate { blocking: Vec<Member> },
}
```

---

## Group creation: best-effort capability matching

When creating a group, the engine automatically sets `RequiredCapabilities` to the intersection of all initial members'
KeyPackages.

```
Alice (Whitenoise latest) + Bob (Whitenoise latest)
→ GroupCapabilities::all() — full feature set

Alice (Whitenoise latest) + Charlie (old Whitenoise)
→ GroupCapabilities without features Charlie's version doesn't support

Alice (Whitenoise latest) + Dave (Signal)
→ GroupCapabilities::mls_base_only — just the MLS fundamentals
```

The user never has to think about this. They select participants; the engine figures out the right capability set. The
UI can optionally show "this group supports X, Y, Z features" at creation time.

---

## Automatic progressive upgrade via self-updates

MLS requires periodic key rotation (self-updates). Whitenoise already does this. The enhancement: **every self-update
commit also updates the member's leaf node capabilities** to reflect the latest version of Whitenoise.

This means: as users keep Whitenoise updated, their capability advertisements automatically improve. Over time, groups
they're in silently become eligible for upgrades — no user action required until an admin chooses to activate them.

The self-update flow:

```
Client runs self-update
  → generates new KeyPackage with latest capabilities
  → publishes self-update commit
  → other members see updated capabilities in leaf node
  → engine re-evaluates feature_status for all features
  → UI reflects newly available upgrades
```

---

## Group upgrade: the admin action

When `upgradeable_capabilities()` is non-empty, an admin can upgrade the group. This is a single MLS commit that updates
the `RequiredCapabilities` group extension.

The admin-facing UX:

> "Everyone in this group now supports disappearing messages, end-to-end media encryption, and self-remove. Upgrade your
> group to enable these features?" [Upgrade group] [Remind me later]

After the upgrade commit is applied, `feature_status()` returns `Enabled` for those features and the UI unlocks them.

**Important:** upgrading `RequiredCapabilities` means future members must also support those features to join. This is
intentional — it prevents capability regression as the group evolves. If you need to add a member who doesn't support
the upgraded capabilities, the admin gets a clear message: "Dave doesn't support end-to-end media encryption — adding
him would require downgrading the group. Do you want to add Dave anyway?" (with clear consequences explained)

---

## The `ExternalClientsUnsupported` case: the product opportunity

When a feature is unavailable because some members are on non-Whitenoise clients, this is valuable signal for the
product — not just an error state.

The UX pattern:

> 🔒 _Disappearing messages aren't available because Dave is on an MLS-compatible client that doesn't support this
> feature. If Dave switched to Whitenoise, you'd be able to enable this for the group._

This is non-pushy, factual, and plants a seed. It's not a "download Whitenoise" ad — it's a genuine capability
explanation. The feature name makes the value concrete.

---

## What needs to be built in MDK

### New capability APIs

```rust
impl<Storage: MdkStorageProvider> MDK<Storage> {
    /// Compute maximum capabilities for a set of KeyPackages
    pub fn constructable_capabilities(
        &self,
        key_packages: &[KeyPackage],
    ) -> GroupCapabilities;

    /// What capabilities can this group's current members support that aren't yet required?
    pub fn upgradeable_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupCapabilities>;

    /// Status of a specific feature in a specific group
    pub fn feature_status(
        &self,
        group_id: &GroupId,
        feature: Feature,
    ) -> Result<FeatureStatus>;

    /// Upgrade group to support all currently upgradeable capabilities
    pub fn upgrade_group_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<EvolutionEvent>;
}
```

### Updated group creation

`create_group()` should automatically call `constructable_capabilities()` on the initial member set and set
`RequiredCapabilities` accordingly. This should not be optional or caller-controlled — it should always happen.

### Updated self-update

`self_update()` (key rotation) should always include the latest capability set in the new leaf node. The caller should
not need to think about this.

### Feature registry

A canonical list of all Marmot features with their required `ProposalType` or extension type, and whether they are
`Required` (must be in `RequiredCapabilities`) or `Optional` (group can use if currently all-members-supported, but not
enforced for future members).

Every new feature added to Marmot requires a corresponding entry in this registry as part of the design/review process —
this is the checklist that prevents the self-remove-style compatibility breaks from happening again.

---

## Relationship to the MIP process

Every MIP that introduces a new proposal type or group extension must answer:

1. **What KeyPackage capability does it require?** (What clients must advertise to participate)
2. **Required or Optional?** (Must it be in `RequiredCapabilities`, or can it be used opportunistically?)
3. **Graceful degradation behavior:** What happens in a mixed group where some members don't support it?
4. **Migration path:** How do existing groups adopt this feature?

This should be a mandatory section in the MIP template. The self-remove migration pain was the cost of not having this.

---

## How this fits the target architecture

Capability negotiation is fully contained within the `CgkaEngine` layer:

```
whitenoise-core
  → engine.feature_status(feature) → FeatureStatus
  → engine.upgrade_group_capabilities(group_id) → EvolutionEvent (if admin)
  → never touches KeyPackages or RequiredCapabilities directly

CgkaEngine (MDK)
  → reads KeyPackages from local state (no network needed)
  → reads RequiredCapabilities from group state (already loaded)
  → all queries are local, cheap, synchronous
  → FeatureStatus is the only thing that escapes this layer

TransportAdapter
  → no knowledge of capabilities whatsoever
```

The `CgkaEngine` trait (see [[target-architecture]]) should include `feature_status()` as a first-class method — any
future CGKA backend (hypothetical alternatives to MLS) would implement its own capability query mechanism but expose the
same `FeatureStatus` enum to the application layer.

If the CGKA backend changes (hypothetically), the capability model changes with it — but the application layer's
contract stays identical: call `feature_status()`, get a `FeatureStatus`, render appropriate UI. The application layer
is fully insulated from how capabilities work under the hood.
