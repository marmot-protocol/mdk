---
title: "Custom Extensions & Safe Framework"
created: 2026-04-19
tags: [marmot, overview, extensions, safe-framework, mls]
status: overview
---

# Custom Extensions & Safe Framework

When Marmot needs new protocol-level data — a new extension, a new proposal type, a new group-state field — there's a decision: **inherit an MLS-standard primitive, or define a Marmot-specific one?** This doc names the framework and the direction.

---

## Three registries, often conflated

MLS has three separate registries for custom primitives:

| Term | What it is | Example |
|---|---|---|
| **Custom extension** | A new `ExtensionType` number carrying app-specific data | `marmot_group_data` (0xF2EE) |
| **Safe-framework component** | A ComponentID under draft-09 Safe Extensions, using SafeExportSecret / AppDataDictionary / etc. | Future Marmot subsystems |
| **Custom proposal type** | A new `ProposalType` number with custom semantics | Hypothetical `IdentityRemove` |

All three can coexist. Marmot today uses only the first; draft-ietf-mls-extensions-09 adds the second as a new option.

---

## The decision framework

When a new primitive is proposed, ask these in order:

1. **Does inheriting a standard buy us real cross-implementation interop?** Marmot isn't targeting cross-MLS-implementation interop at the CGKA layer — our own extensions, event kinds, and (future) proposal types are all Marmot-only. So "standard = interop" is weaker than it sounds.
2. **Does the standard's validation logic meaningfully reduce implementation burden?** For standard Add/Remove, yes. For Marmot-specific operations, usually not.
3. **Does the standard's wire-format rule align with Marmot's threat model?** SelfRemove's MUST-PublicMessage is an example where the answer is no (the rationale is external-commit interop that Marmot doesn't use).
4. **What's the migration cost if we change later?**
5. **Do we need extensible metadata on this primitive?** Standard proposals have fixed bodies; custom can carry more.

If questions 1–3 lean "no" and questions 4–5 lean toward flexibility, custom is right. Otherwise inherit.

---

## The Safe Extensions framework (draft-ietf-mls-extensions-09)

A standardized toolkit for application-layer subsystems inside MLS groups:

- **Component** — a 16-bit identifier for an application subsystem (private range `0x8000–0xFFFF`).
- **AppDataDictionary** — a shared GroupContext extension holding a map from ComponentID → opaque bytes. Replaces "claim a new extension type per feature."
- **AppDataUpdate / AppEphemeral proposals** — atomic state updates and ephemeral per-commit data.
- **SafeExportSecret(ComponentID)** — per-component forward-secure secret derivation via a dedicated Exporter Tree. Replaces ad-hoc `MLS-Exporter(label, ...)` calls.
- **SafeEncryptWithLabel / SafeSignWithLabel** — HPKE and signatures with ComponentID baked into the domain separator. Structural isolation, not label discipline.
- **SafeAAD** — component-attributed contributions to `authenticated_data`.

**Think of it as a namespace / module system** for MLS application subsystems. Pre-Safe mechanics were like a single global namespace where label discipline was the only guard against collisions.

---

## What the framework does NOT cover

**Custom proposal semantics.** No "SafeProposal" wrapper. Any new proposal type with distinct meaning (e.g. `IdentityRemove`) is a classical `ProposalType::Custom(u16)` with Marmot-owned validation. Important to internalize.

---

## Direction

**If Marmot were starting fresh today, we'd use the Safe framework as the base for most customizations.** Going forward:

- **New subsystems** default to Safe framework components. Evaluate classical extensions only if there's a reason (e.g. LeafNode-scoped extensions — framework is GroupContext-focused).
- **Existing customs (`0xF2EE`, `0xF2EF`, `0xF2F0`)** don't need emergency migration.
- **Long-term target:** split the monolithic `marmot_group_data` into multiple AppDataDictionary entries (identity, transport, admin, message-lifecycle).
- **Gated on backend library support.** OpenMLS 0.8's Safe framework support is an open question; investigating it is a near-term next step.

---

## Marmot's first custom proposal type

**`IdentityRemove`** — remove every leaf of a given identity atomically.

Motivated by MIP-06 multi-device: a user with N devices who wants to leave a group must currently SelfRemove from each device individually. An admin kicking such a user must bundle N Remove proposals and hope none are missed due to race. Both are fragile.

Recommended shape: `ProposalType::Custom(marmot-assigned-u16)` carrying a target identity. Resolves to leaves at commit-time (not proposal-time, to capture new leaves added during the race window). Committed by any remaining non-same-identity member, following the same lowest-index-remaining auto-commit rule used for SelfRemove. Stands outside the Safe framework.

Deep design in [`../further-context/custom_extensions.md`](../further-context/custom_extensions.md) §7.

---

## See also

- Full framework teaching + per-MIP review: [`../further-context/custom_extensions.md`](../further-context/custom_extensions.md)
- The decision framework in principle form: [`../../required-features.md`](../../required-features.md)
