---
title: "Custom Proposals & Extensions — When to Inherit vs Define"
created: 2026-04-18
updated: 2026-04-19
tags: [marmot, mls, extensions, proposals, capabilities, design]
status: exploration
related:
  - [[capability-negotiation]]
  - [[cgka-engine-design]]
---

# Custom Proposals & Extensions — When to Inherit vs Define

**What this doc is.** An exploration, not a decision. SelfRemove / PublicMessage exposed a case where Marmot inherits a constraint from a more general spec for reasons that only partly apply. That surfaced a broader question: *where else in the Marmot spec are we inheriting MLS / MLS-Extensions primitives with rationales that may or may not apply, and where could Marmot-defined extensions — particularly under the MLS-Extensions draft's new Safe Extensions framework — serve us better?*

This doc now reflects a close reading of **draft-ietf-mls-extensions-09**, all merged MIPs (00, 01, 02, 03, 04, 05), and the MIP-06 multi-device PR (#44). The early "likely finding" speculation from the first draft has been replaced with fact-checked per-MIP analysis.

---

## 1. The trigger: SelfRemove and PublicMessage — corrected

### What the draft says

From draft-ietf-mls-extensions-09 §6.3.1:
> *"Because the point of a SelfRemove Proposal is to be available to external joiners (which are not yet members), these proposals MUST be sent in an MLS PublicMessage."*

MIP-03 §141 inherits this:
> *"SelfRemove proposals MUST be sent as MLS `PublicMessage` (required by the MLS Extensions draft)"*

### What PublicMessage vs PrivateMessage actually means operationally

**PublicMessage** authenticates via:
- A signature from the sender's LeafNode signing key (long-term identity)
- A `membership_tag` MAC using the epoch's `membership_key` (shared by every current member)

**PrivateMessage** wraps the same authenticated content in symmetric encryption keyed by the sender's position in their application/handshake ratchet chain.

The relevant difference: PublicMessage can be validated by an entity holding only `GroupInfo`-level state (membership_key), whereas PrivateMessage requires the full secret tree.

### Why the draft says "MUST PublicMessage"

External commits. A non-member can construct their own commit (using `external_init` plus their own Add) without being Added by an existing member. Such an external commit may need to reference pending proposals in the current epoch — including pending SelfRemoves. External joiners don't have the epoch's secret tree, so any referenced proposal must be validatable with only the `membership_key` they obtained from `GroupInfo`.

### CORRECTION to the earlier draft of this doc: Marmot DOES use external commits

**The first version of this doc asserted "Marmot does not use external commits" and built on that.** That was wrong in general and specifically for **MIP-06 (Multi-Device Support, PR #44)**, whose entire join path uses MLS External Commits ([RFC 9420 §12.4.3.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.2)):

> "Devices join existing groups via MLS External Commits. An External Commit allows a new party to add themselves to a group using a `GroupInfo` object, without requiring an existing member to come online and issue an Add proposal."

So the PublicMessage-for-SelfRemove rationale **does apply to Marmot in the MIP-06 context**. In an MIP-06-enabled group, if a member has a pending SelfRemove and another same-identity device is joining via External Commit, the draft's visibility argument matches the Marmot scenario: the joining device is *exactly* the "non-member about to become a member" that the constraint protects.

### But MIP-06's External Commits are narrowly constrained

Per MIP-06's §"External Commit Authorization":
> "The External Commit contains no proposals other than the required `ExternalInit` proposal and the MIP-06 join PSK `PreSharedKey` proposal. MIP-06 permits only join-style External Commits, not resync-style External Commits that replace an existing leaf or External Commits that perform unrelated group changes."

So even with MIP-06 active, the joining device **cannot** reference pending SelfRemoves by value or by reference in its External Commit. MIP-06's join-style commits are explicitly single-purpose.

**What this means:** the MLS-Extensions draft's external-commit rationale for PublicMessage-SelfRemove technically applies to any MLS-level client that might process External Commits with referenced proposals. In Marmot, MIP-06 constrains External Commits narrowly enough that the rationale is *still vestigial for Marmot clients* — a Marmot-only implementation following MIP-06 would never build an External Commit that references a SelfRemove. But the constraint is no longer "entirely unused by Marmot" the way the first draft of this doc claimed.

**Revised verdict for SelfRemove/PublicMessage:**
- The PublicMessage requirement is **primarily** about MLS-ecosystem external-commit interop.
- Marmot's External Commit use (MIP-06) is narrowly scoped and does not reference SelfRemoves.
- The MLS-Extensions inheritance still imposes OpenMLS's wire-format-policy constraint (no mixed outgoing) on Marmot groups.
- The three paths (inherit, custom, hedge) discussed in §3 below still apply. The "hedge" recommendation stands, but the motivation is slightly weaker than I first stated — the rationale isn't purely vestigial, just narrowly unused.

### The concrete cost of the inherited constraint

OpenMLS 0.8 enforces the MUST: `leave_group_via_self_remove()` rejects groups configured with `OutgoingWireFormatPolicy::AlwaysCiphertext`. And OpenMLS 0.8 offers only `AlwaysPlaintext` or `AlwaysCiphertext` — **no mixed option**. So any group that ever wants to issue a SelfRemove must use plaintext for all outgoing MLS messages.

Options:
- **Option A:** `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` for the group. The outer kind-445 layer (ChaCha20Poly1305 keyed by `group_event_key` per MIP-03) still encrypts everything on the wire.
- **Option B:** Patch OpenMLS upstream for mixed-outgoing wire format.
- **Option C:** Move to a Marmot-specific leave proposal type — see §3.

---

## 2. Decision framework — when is "inherit" load-bearing?

Questions to ask when weighing "inherit standard MLS primitive" vs "define Marmot custom":

**Q1. Does the standard buy us cross-implementation interop at a layer where Marmot actually wants cross-implementation interop?**
Marmot has several Marmot-specific primitives that already make cross-MLS-client interop at the group-data layer unworkable (marmot_group_data, admin model, kind-445 wrap). Before invoking "interop" as a reason to inherit, name the concrete party who would benefit.

**Q2. Does the standard's validation logic meaningfully reduce implementation burden?**
Standard Add/Remove get rich OpenMLS validation. Custom proposals require Marmot to implement all validation itself.

**Q3. Does the standard's wire-format rule align with Marmot's threat model?**
If the MUST in the inherited spec protects a failure mode that can't arise in Marmot, the inheritance is vestigial.

**Q4. What is the migration cost if we change later?**
Standard→custom migration is typically harder than custom→standard. Bias toward standard when semantics are still uncertain.

**Q5. Do we need metadata room?**
Standard primitives have fixed bodies. Custom can be extensible.

**Q6 (new, since Safe Extensions draft-09).** Would the MLS-Extensions Safe framework serve the same need as a Marmot-custom extension, with better forward-secrecy and domain-separation guarantees?
The Safe framework (§5) gives you component-scoped ExportSecret, EncryptWithLabel, SignWithLabel, and AAD — all domain-separated by ComponentID. For anything that needs cryptographic material derived from the MLS group state, this is architecturally cleaner than rolling a label into a raw `MLS-Exporter()` call.

---

## 3. SelfRemove: three paths, updated for MIP-06 context

### Path 1: Standard SelfRemove (status quo)
Wire value 0x000a, empty body, MUST PublicMessage. Inherits MLS Extensions validation. Bound by PublicMessage → OpenMLS mixed-outgoing limitation.

### Path 2: Custom Marmot leave proposal
`ProposalType::Custom(marmot-assigned-u16)`, extensible body, free wire format.

### Path 3: Hedge — abstract at the engine trait
`SendIntent::Leave { group_id }` is already abstract. Ship standard today, document the inheritance, keep the option open.

**Recommendation (unchanged):** Path 3. Standard SelfRemove today. Document MIP-03's inheritance explicitly. Watch for (a) OpenMLS mixed-outgoing support landing upstream, (b) demand for richer leave semantics (reason codes, replacement-admin nomination, soft-leave), and (c) any future MIP that references pending SelfRemoves from external commits. If (c) happens, the PublicMessage requirement becomes load-bearing for Marmot too, and the custom path becomes weaker.

### What MIP-03 should say

Rather than the current one-line parenthetical, MIP-03 §141 should explicitly document the inheritance:

> **Note on PublicMessage requirement.** The `MUST be PublicMessage` rule for SelfRemove proposals is inherited from draft-ietf-mls-extensions-09 §6.3.1. Its rationale is visibility to external joiners during External Commits that reference pending proposals. In Marmot, External Commits are used only by MIP-06 for same-identity multi-device joins and are constrained to contain no proposals other than `ExternalInit` and the MIP-06 join PSK. No Marmot-defined flow references pending SelfRemoves by reference from an External Commit. The constraint is therefore retained for MLS wire-format interop rather than for Marmot-internal safety, and Marmot implementations currently satisfy it by using `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` at the MLS layer (the outer kind-445 wrap still provides network-level confidentiality).

---

## 4. Inventory of Marmot's custom primitives (as of 2026-04-19)

Factual list from the merged MIPs + MIP-06 PR. No speculation.

### 4.1 Custom MLS Extension Types

| Extension ID | Name | Defined by | Scope | Role |
|---|---|---|---|---|
| `0xF2EE` | `marmot_group_data` | MIP-01 | GroupContext (required) + LeafNode.capabilities | Monolithic group metadata: `nostr_group_id`, name, description, admin_pubkeys, relays, image_hash/key/nonce/upload_key, disappearing_message_secs. Version 3 current. |
| `0xF2EF` | `encrypted_device_name` | MIP-06 PR #44 | LeafNode (optional) | Optional NIP-44-encrypted device label, decryptable only by holder of the user's Nostr private key. |
| `0xF2F0` | `marmot_multi_device` | MIP-06 PR #44 | GroupContext (required) + LeafNode.capabilities | Boolean signaling gate that enables MIP-06 External Commit behavior. Body: `struct { uint16 version; }`. |

All three are in the Marmot-private range above 0xF000. None are Safe-Extensions-framework components.

### 4.2 Custom MLS Proposal Types

**None currently.** Marmot uses only standard MLS proposals (Add, Remove, Update, GroupContextExtensions, SelfRemove, ExternalInit, PreSharedKey) plus the SelfRemove proposal from draft-ietf-mls-extensions.

### 4.3 Marmot-specific Nostr Event Kinds

| Kind | Name | Defined by | Published to relays? | Signed? | Purpose |
|---|---|---|---|---|---|
| `9` | Chat message (rumor) | NIP-17 (used by MIP-03) | No (inside MLS payload) | No | Application message content |
| `444` | Welcome rumor | MIP-02 | No (inside NIP-59 gift wrap) | No | Welcome payload |
| `445` | Group message outer | MIP-03 | Yes | Yes (ephemeral) | Outer wrap for all group-level MLS messages |
| `446` | Push notification rumor | MIP-05 | No (inside NIP-59 gift wrap) | No | Ferries encrypted tokens to notification server |
| `447` | Token request | MIP-05 | No (inside MLS application message) | No | "What tokens does this group have?" gossip |
| `448` | Token list response | MIP-05 | No (inside MLS application message) | No | Share stored tokens with requester |
| `449` | Token removal | MIP-05 | No (inside MLS application message) | No | Signal that a device's token is no longer valid |
| `450` | External commit identity proof | MIP-06 PR #44 | **No — signing template only** | Signed by Nostr identity key | Embedded in `FramedContent.authenticated_data`; proves Nostr identity for External Commits |
| `1059` | NIP-59 gift wrap | NIP-59 (used by MIP-02, MIP-05) | Yes | Yes (ephemeral) | Outer wrap for recipient-addressed events |
| `10050` | Notification server relay list | MIP-05 | Yes | Yes | Relay discovery for push notification server |
| `10051` | KeyPackage relay list | MIP-00 | Yes | Yes | Relay discovery for a user's KeyPackages |
| `30443` | KeyPackage (addressable) | MIP-00 | Yes | Yes | The user's MLS KeyPackage |

### 4.4 Marmot-specific uses of `authenticated_data`

| Where | Content | Purpose |
|---|---|---|
| MIP-06 External Commit | TLS-serialized `NostrIdentityProof` = signed `kind: 450` event | Binds External Commit to Nostr identity key (not just MLS signing key) |
| All other Commit messages | **Empty** (per MIP-06 PR's update to MIP-03) | Reserved for future Marmot specs |

### 4.5 Marmot-specific External PSKs

| Name | psk_id | Derivation | Purpose |
|---|---|---|---|
| MIP-06 join PSK | `MarmotMultiDeviceJoinPskId { label: "marmot-mip06-join-psk-v1", group_context_hash }` | `MLS-Exporter("marmot-mip06-join-psk-v1", join_psk_id, KDF.Nh)` | Proves the new device received current-epoch secret material via pairing; blocks unauthorized External Commits |

### 4.6 Marmot-specific exporter labels

| Label | Used by | Output | Purpose |
|---|---|---|---|
| `"marmot" / "group-event"` | MIP-03 (outer kind-445 wrap) | 32 bytes | ChaCha20-Poly1305 key for outer encryption |
| `"marmot" / "encrypted-media"` | MIP-04 media | Indirect via HKDF + file metadata | Per-file ChaCha20-Poly1305 key for encrypted media |
| `"marmot-mip06-join-psk-v1"` | MIP-06 | `KDF.Nh` bytes | External PSK for multi-device join |

---

## 5. MLS-Extensions draft-09's Safe Extensions framework — in depth

Draft-09 introduced a formal **Safe Extensions framework** for application-layer extensions. This is new relative to the earlier drafts MIP-03 references, and it substantially changes the landscape for how Marmot extends MLS cleanly. Team consensus after working through this: **if we were starting fresh with Marmot today, we would use the Safe Extensions framework as the base for most customisations.** The pre-Safe-framework pattern (custom extension type + ad-hoc MLS-Exporter labels) is what Marmot has today, but it's no longer the best available tool.

This section builds the mental model from first principles.

### 5.1 The pre-Safe world (baseline)

Before draft-09, MLS gave you two mechanisms for extending the protocol:

- **Custom extension types.** Pick a number from the MLS Extension Types IANA registry (or the private range), define a new extension — a blob of TLS-encoded bytes attached to `GroupContext`, `LeafNode`, or `KeyPackage`. Marmot's `marmot_group_data` (0xF2EE) is exactly this. If a second subsystem wanted its own group-level data, it claimed another extension type with its own number and serialisation.
- **Raw `MLS-Exporter(label, context, length)`.** Want cryptographic material derived from the group's epoch state? Call the MLS exporter with an application-chosen label. MIP-03's `MLS-Exporter("marmot", "group-event", 32)` is this. MIP-04 and MIP-06 do the same with their own labels.

Both mechanisms work, but you're on your own for:

- **Domain separation between your subsystems** — just label discipline, no structural guarantee that subsystem A can't confuse its keys with subsystem B's.
- **Atomic state updates** — updating a group extension means a `GroupContextExtensions` update that rewrites the whole extension. No per-component deltas.
- **Forward secrecy per subsystem** — you can call `MLS-Exporter` multiple times, but nothing stops accidental re-derivation, and there's no per-subsystem deletion.
- **Ephemeral data** — want to tag a commit with "this message includes a delivery ack from subsystem X"? No generic mechanism; you'd roll it into an extension or AAD.
- **AAD sharing** — `FramedContent.authenticated_data` is a single opaque blob. Two subsystems wanting to contribute have to negotiate a framing.

This is the "roll it yourself with label discipline" world. Every new subsystem adds new surface area where someone could get the discipline wrong.

### 5.2 The central concept: Component

Draft-09 introduces **Component** as the unit of application-layer concern. A component is identified by a `ComponentID` — a 16-bit value. There's a new IANA registry for ComponentIDs (separate from the MLS Extension Types registry), and the `0x8000–0xFFFF` range is Private Use, so applications can claim ComponentIDs without IETF coordination.

Think of a component as "a subsystem of your application that lives inside an MLS group." Marmot might have components for group identity / display metadata, for Nostr transport routing, for admin authorisation, for disappearing-messages policy, for encrypted-media key derivation, for the MIP-06 multi-device gate, etc. Each gets its own ComponentID.

Once you have a ComponentID, the framework gives you a toolkit — and you pick which tools you need.

### 5.3 The framework's toolkit, piece by piece

**AppDataDictionary (persistent state).** A single standardised GroupContext extension whose body is a map from ComponentID → opaque bytes. Your component's persistent group-level state goes in here. You don't claim a new MLS extension type; you claim a ComponentID and store your data in this shared dictionary.

**AppDataUpdate proposal** (proposal type `0x0008`). A standard proposal type that atomically updates one or more entries in AppDataDictionary. No more "rewrite the whole monolithic extension to change one field."

**AppEphemeral proposal** (proposal type `0x0009`). A standard proposal type that carries component data **attached to a commit** but does NOT change persistent state. Useful for delivery acknowledgments, progress markers, and "tag this commit with my component's transient info."

**SafeExportSecret(ComponentID).** The headline feature. Instead of calling `MLS-Exporter(label, ...)`, you call `SafeExportSecret(your_component_id)`. Internally, the framework maintains an "Exporter Tree" with 2^16 leaves — one per ComponentID — and derives your secret from your leaf. Three properties come for free:

- **Per-component isolation.** Component `0x8001`'s secret cannot be derived by component `0x8002` and vice versa.
- **Forward-secure deletion.** After you consume the secret, the source material is deleted per MLS deletion rules (RFC 9420 §9.2), so you can't accidentally re-derive it.
- **No label collisions.** The ComponentID is the label; you don't invent one.

**SafeEncryptWithLabel / SafeDecryptWithLabel.** HPKE encryption with the ComponentID baked into the domain separator. The framework wraps your label inside `ComponentOperationLabel { base_label: "MLS Component", component_id, label }`. Encryption with a given ComponentID can only be *decrypted* by code running as that ComponentID — structural isolation, not just discipline.

**SafeSignWithLabel / SafeVerifyWithLabel.** Analogous for signatures. A signature authored as ComponentID `0x8001` can't be forged by code running as ComponentID `0x8002` even if they share the same underlying signing key.

**SafeAAD.** A framing convention for `FramedContent.authenticated_data` where each component contributes its own slice: `[SafeAADItem(0x8001, data1), SafeAADItem(0x8002, data2), ...]` sorted by ComponentID. Enabled per-group by an entry in AppDataDictionary. Lets multiple components write to AAD without stepping on each other.

### 5.4 What the Safe framework does NOT cover

**Custom proposal types.** There's no "SafeProposal" wrapper. If your component needs a proposal type with genuinely distinct semantics — say, the "remove all leaves with this identity" proposal discussed in §7 below — you still have to use raw `ProposalType::Custom(u16)` and implement all the validation yourself.

The Safe framework's proposal types (`AppDataUpdate`, `AppEphemeral`) are **generic containers**, not a mechanism for defining new proposal semantics. This is the single most important limitation to internalise:

- Custom component data → Safe framework handles it.
- Custom persistent state → Safe framework handles it via AppDataDictionary.
- Custom ephemeral per-commit data → Safe framework handles it via AppEphemeral.
- **Custom proposal semantics → not covered. Still a classical `ProposalType::Custom(u16)` with Marmot-owned validation.**

### 5.5 Terminology — the three registries pretending to be one

| Term | What it is | Registry | Example |
|---|---|---|---|
| **Custom extension** (pre-Safe) | A new MLS `ExtensionType` number carrying app-specific data | MLS Extension Types IANA registry | Marmot's `marmot_group_data` (0xF2EE) |
| **Safe-framework component** | A ComponentID using the framework's toolkit | MLS Component Types IANA registry (new, draft-09) | Hypothetical future Marmot `nostr_transport` component (e.g., 0x8002) |
| **Custom proposal type** | A new `ProposalType` number with custom semantics | MLS Proposal Types registry | Hypothetical Marmot `identity_remove` (see §7) |
| **"Custom primitive"** | Loose / colloquial term | N/A | Could be any of the above, plus Nostr event kinds, bespoke crypto, etc. |

"Custom extension" and "Safe-framework component" can coexist — an application can use both simultaneously. Marmot today is entirely in the classical extensions bucket; draft-09 adds the option to put new things in the Safe bucket.

### 5.6 Mental model: namespaces vs global names

**Pre-Safe MLS extension mechanics are like a single-global-namespace programming language.** Want to add a new feature? Pick a name nobody else uses. Hope nobody else picks one that collides with yours. Label discipline is the only guard.

**The Safe framework is like a namespace / module system.** You declare a module (ComponentID) and the language gives you scoped names, private data, and structural isolation from other modules. If two modules accidentally pick the same internal label, the language keeps them separated — you don't rely on programmer discipline for correctness.

### 5.7 How Marmot's current primitives would map

Concrete mapping of every Marmot custom primitive against the Safe framework:

| Marmot thing | Currently | Safe-framework analog |
|---|---|---|
| `marmot_group_data` (0xF2EE) | Classical custom extension, monolithic | Multiple AppDataDictionary entries — each a separate ComponentID (identity, nostr-transport, admins, disappearing-messages) |
| MIP-03 `group_event_key` | `MLS-Exporter("marmot", "group-event", 32)` | `SafeExportSecret(marmot_group_event_component_id)` |
| MIP-04 media per-file key | `MLS-Exporter("marmot", "encrypted-media", 32)` → HKDF | `SafeExportSecret(marmot_media_component_id)` → HKDF (or directly via SafeEncryptWithLabel) |
| MIP-06 `join_psk` | `MLS-Exporter("marmot-mip06-join-psk-v1", ...)` | `SafeExportSecret(marmot_mip06_component_id)` |
| MIP-06 `NostrIdentityProof` in `authenticated_data` | Raw bytes at the start of `authenticated_data` | SafeAADItem keyed by MIP-06's ComponentID |
| `marmot_multi_device` gate (0xF2F0) | Classical custom extension, boolean body | Either stays classical (boolean gates are fine as extensions) OR becomes an AppDataDictionary entry |
| `encrypted_device_name` (0xF2EF) | Classical custom LeafNode extension | Stays classical — Safe framework targets GroupContext-level components, not LeafNode extensions |
| Future "identity-scoped remove" proposal (§7) | N/A | **Raw `ProposalType::Custom(u16)` — outside the Safe framework** |
| MIP-01 group image encryption | `HKDF(image_key, "mip01-image-encryption-v2")` — persistent, epoch-independent by design | Stays as-is (see §6.2) — Safe framework's forward-secrecy properties don't fit the use case |

Notice the pattern. Classical extensions stay classical for things that are truly group-level metadata with static wire format (the multi-device gate, the device name) or for deliberate trade-offs like epoch-independent image encryption. The big wins are in:

- **Secret derivation** — SafeExportSecret replaces three scattered `MLS-Exporter` calls with one uniform primitive (MIP-03, MIP-04, MIP-06).
- **Splitting `marmot_group_data`** into coherent AppDataDictionary entries, each with its own ComponentID, each independently versioned and updated.
- **Authenticated-data sharing** — once more than one Marmot subsystem needs to write to AAD, SafeAAD gives them structural attribution.

### 5.8 Practical caveat: OpenMLS support

The Safe Extensions framework is still draft (draft-09 as of this writing). **OpenMLS 0.8 and other major MLS-library support for the Safe framework require investigation.** Adopting it in Marmot is gated on backend support. If OpenMLS doesn't implement it, Marmot would need either (a) upstream contributions to add it, or (b) application-layer reimplementation of the framework's invariants (which partially defeats the point — you'd be rolling your own label discipline again, just wrapped in framework-shaped names).

The recommendation in §7 defers Safe-framework adoption precisely because of this gate. But the direction is clear.

---

## 6. Spec-wide review — per-MIP findings (fact-checked)

Each MIP was read in full. For each, the analysis is based on what the MIP actually says, not guesses.

### 6.1 MIP-00 — Credentials & KeyPackages

**Current approach:** Uses standard MLS `BasicCredential` with Nostr pubkey in the identity field. Uses standard kind-30443 addressable Nostr events for KeyPackage distribution. MUST advertise `0xF2EE` (marmot_group_data) and `0x000a` (last_resort — standard MLS extension draft).

**Inherit vs Custom check:**
- Credential type: standard BasicCredential — **inherit, correct.** Q1 (interop at this layer matters for MLS baseline)? Yes. Q2 (validation)? Heavy. Verdict: inherit.
- KeyPackage event format: Marmot-specific (kind 30443, `d` tag, `i` tag, `mls_ciphersuite` tag, `mls_extensions` tag, `mls_proposals` tag, `encoding` tag, `relays` tag). **Correct custom** — this is Nostr-layer event format, not MLS-layer; no standard exists.
- `last_resort` extension: standard, inherited. **Correct.**
- `KeyPackageRef` calculation: standard RFC 9420. **Correct to inherit.**

**No issues.** MIP-00 is cleanly split: MLS-layer primitives are inherited; Nostr-layer event structure is Marmot-custom as it must be.

### 6.2 MIP-01 — Group Construction & marmot_group_data

**Current approach:** Single monolithic `marmot_group_data` extension (0xF2EE) in the Marmot-private extension range, with a version field (currently v3) and 11 concrete fields covering identity, membership policy, relays, group image, and disappearing messages.

**Issues worth flagging:**

**A. The monolith is heterogeneous.** `marmot_group_data` bundles:
- Transport routing (`nostr_group_id`, `relays`) — Nostr-transport-specific
- Display metadata (`name`, `description`, `image_*`) — transport-agnostic
- Authorization policy (`admin_pubkeys`) — protocol-level
- Message lifecycle (`disappearing_message_secs`) — content-processing policy

Each has a different lifecycle, different update-frequency, and different "who cares about this." The monolithic versioning (single version field, append-only fields) means any change to any field is a group-wide extension version bump.

The earlier architecture split was `BasicGroupData` + `NostrTransportData`. In light of the Safe Extensions framework, the more principled split is into **multiple `AppDataDictionary` entries under the Safe framework** — one ComponentID per coherent concern. For example:
- ComponentID `0x8001` → GroupIdentity { name, description, image_* }
- ComponentID `0x8002` → NostrTransport { nostr_group_id, relays }
- ComponentID `0x8003` → MarmotAdmins { admin_pubkeys }
- ComponentID `0x8004` → DisappearingMessages { secs }

Each gets independent versioning, independent forward-secure key derivation (via SafeExportSecret), independent capability gating, and the ability to add new fields to one without affecting others.

**This is a major migration** — existing groups are on `0xF2EE` v3. Not a short-term move. But it's the architecturally clean target.

**B. Admin model (`admin_pubkeys`) is NOT modeled as a Feature/Capability in MIP-00/01.** A client that doesn't understand Marmot's admin model would still parse `marmot_group_data` and ignore the admin field, potentially accepting commits from non-admins. This is partly mitigated by the fact that all Marmot clients are required to implement MIP-01 — but a `Feature::MarmotAdmins` capability would make the dependency explicit and let the capability system enforce it.

**C. Group image encryption** uses Marmot-custom ChaCha20-Poly1305 + HKDF with label `"mip01-image-encryption-v2"`, with the `image_key` seed stored directly in `marmot_group_data`. MIP-01 explicitly documents this as "encryption independence: image encryption keys persist across MLS epochs."

**This is a deliberate design trade-off, not a flaw.** The alternative — re-deriving the image key on every epoch change via something like `SafeExportSecret(image_component_id)` — would require downloading, re-encrypting, and re-uploading the group image on every epoch advance (and deleting the old blob from Blossom). That's operationally expensive for an asset that changes rarely. The residual threat model is "a former or current group insider can decrypt historical group images," which is an acceptable loss given the operational cost.

**So this one is correctly Marmot-custom as-is.** The Safe framework's forward-secrecy properties don't fit the use case; re-deriving the encryption key on epoch changes would create work disproportionate to the threat it defends against. MIP-01's current approach stands.

The same logic does NOT apply to MIP-04 (encrypted media), which correctly derives per-file keys from the epoch's exporter and accepts forward-secrecy behaviour — because media files are individually small, receive-and-forget, and per-message. MIP-04 is a clean Safe-framework candidate; MIP-01's image encryption is not.

### 6.3 MIP-02 — Welcomes

**Current approach:** Standard MLS Welcome wrapped in NIP-59 gift wrap (kind 1059 → kind 13 seal → kind 444 unsigned rumor). Uses `KeyPackageRef` to link the Welcome to the consuming KeyPackage.

**Inherit vs Custom check:** All MLS layer standard. All Nostr layer appropriately Marmot-custom (NIP-59 gift-wrapping choice is Marmot-policy; kind 444 is Marmot-assigned).

**No issues.** The split is clean.

### 6.4 MIP-03 — Group Messages

**Current approach:** Standard MLS application and control messages wrapped in kind-445 outer events. Uses `MLS-Exporter("marmot", "group-event", 32)` as the outer encryption key. SelfRemove (standard MLS Extensions proposal 0x000a) is explicitly required.

**Issues:**

**A. The outer encryption key is a candidate for SafeExportSecret.** Current approach:
```
group_event_key = MLS-Exporter("marmot", "group-event", 32)
```
Safe-framework approach:
```
group_event_component_id = 0x8005  // Marmot-assigned private-range ComponentID
group_event_key = SafeExportSecret(group_event_component_id)  // internally: per-component Exporter Tree derivation
```
Benefits: per-component secret tree (domain-separated from MIP-04 media and MIP-06 PSK, which also derive from the exporter); automatic consumption/deletion per Safe framework rules.

**B. SelfRemove inheritance** — covered in §1/§3 above.

**C. MIP-06's authenticated_data usage** — the PR correctly updates MIP-03 to say: "For all Commit messages that are not MIP-06 External Commits, clients MUST set `FramedContent.authenticated_data` to the empty byte string unless another Marmot specification explicitly defines a non-empty value." This is the pre-Safe-framework pattern. A Safe-framework approach would use **SafeAAD** — each Marmot subsystem writing to authenticated_data would declare a ComponentID and have its contribution component-attributed. Today there's only one contributor (MIP-06), so SafeAAD overhead is unnecessary; if a second Marmot subsystem ever needs authenticated_data, SafeAAD prevents collision.

### 6.5 MIP-04 — Encrypted Media

**Current approach:** Marmot-custom ChaCha20-Poly1305 with key derived from `MLS-Exporter("marmot", "encrypted-media", 32)` → HKDF with version label `"mip04-v2"` and per-file metadata. Random nonce stored in `imeta` tag.

**Inherit vs Custom check:**
- The idea of using MLS-exporter-derived per-file keys is architecturally sound.
- The raw `MLS-Exporter()` call with the label `"marmot" / "encrypted-media"` is **a candidate for `SafeExportSecret`** with a Marmot-assigned ComponentID (e.g., `0x8006 = marmot_encrypted_media`). Same benefit as MIP-03: per-component forward-secure derivation, proper consumption, domain separation from other Marmot subsystems.
- The `imeta` tag format is Nostr-layer metadata; appropriately Marmot-custom.
- The HKDF with `mip04-v2` label is providing version-based domain separation. The Safe framework would fold this into ComponentID-based domain separation: bumping to `mip04-v3` could be a new ComponentID rather than a label change.

**Verdict:** current approach works but doesn't take advantage of Safe framework. **Candidate for Safe-framework adoption in a future MIP-04 revision.**

### 6.6 MIP-05 — Push Notifications

**Current approach:** Multiple mechanisms here, each Marmot-custom:
- **Token encryption for gossip among group members**: Uses ECDH (to notification server's Nostr pubkey) + HKDF + ChaCha20-Poly1305 with labels `"mip05-v1"` and `"mip05-token-encryption"`.
- **Kinds 447/448/449**: Custom Nostr event kinds carried as unsigned rumors inside MLS application messages. Mini-protocol for token gossip (request / list / removal).
- **Kind 446**: Push notification trigger event, gift-wrapped to the notification server.
- **kind-10050**: Notification server's relay discovery event.

**Inherit vs Custom check:**
- **Token encryption is to an external party** (the notification server) — the server is not an MLS group member. **The Safe framework does not apply** because SafeEncryptWithLabel is for operations whose keys come from MLS group state. Notification-server communication is classical public-key crypto with an outsider. Custom is correct.
- **Kinds 447/448/449 as application-message rumors** — this is Marmot's gossip-style protocol layered inside MLS app messages. An alternative would be `AppDataDictionary` (tokens as persistent group state, updated via `AppDataUpdate` proposals). The gossip approach has better properties for the asynchronous/intermittent Nostr relay environment (passive learning, redundancy, convergence without coordinator). **The gossip approach is probably better in context**; the AppDataDictionary alternative would work but wouldn't improve things.
- **Kind 446 gift-wrapped to server** — intentionally Marmot-custom; no standard exists. Correct.

**Verdict:** MIP-05's customs are appropriate. Safe framework doesn't apply to out-of-band server comms, and the in-band gossip is genuinely better than the persistent-state alternative.

### 6.7 MIP-06 (PR #44) — Multi-Device Support

**Current approach:** External Commits (standard MLS), gated by `marmot_multi_device` extension (`0xF2F0`). MIP-06 join PSK derived from `MLS-Exporter("marmot-mip06-join-psk-v1", ...)`. Nostr identity proof in `authenticated_data` using a canonical unsigned `kind: 450` event signed by the user's Nostr key. Optional `encrypted_device_name` extension (`0xF2EF`).

**Issues / opportunities:**

**A. The `marmot_multi_device` gate (`0xF2F0`) is a boolean signaling extension in the Marmot-private range.** A Safe-framework alternative would be an entry in `app_data_dictionary` with a Marmot-assigned ComponentID. The pros of the custom extension approach: simpler, tighter body (`struct { uint16 version; }`), no dependency on draft-09's SafeExtensions framework being implemented by the MLS library. The pros of the Safe-framework alternative: aligned with the ecosystem direction, composable with other future Safe-framework entries. **Current approach is pragmatic for PR stage; Safe-framework migration could come later.**

**B. MIP-06 join PSK derivation is an exporter-derived External PSK:**
```
join_psk = MLS-Exporter("marmot-mip06-join-psk-v1", join_psk_id, KDF.Nh)
```
Same analysis as MIP-03 and MIP-04: this is a **candidate for SafeExportSecret** with a ComponentID, and `join_psk_id` could live in the ComponentID's label space rather than being ad-hoc.

**C. The `kind: 450` Nostr identity proof in `authenticated_data` is a clever pattern worth calling out:**
- Uses a canonical unsigned Nostr event as the signing target (never published).
- Signs via standard Nostr event signing (compatible with NIP-07/NIP-46/Amber signers).
- Carries only the 64-byte signature in the MLS-layer structure (`NostrIdentityProof { uint16 version; opaque nostr_event_sig[64]; }`).
- Verifier reconstructs the proof event from known inputs (credential_identity, signature_key, GroupContext) plus a fixed SHA-256 challenge prefix.

**This pattern — "sign a canonical unsigned Nostr event, embed just the signature, let the verifier reconstruct" — is a reusable Marmot primitive.** Other MIPs that need to prove Nostr-identity-to-MLS bindings could adopt it. Worth documenting as a pattern in its own right, not just inside MIP-06.

**D. SelfRemove is leaf-scoped, NOT identity-scoped — by design, with a real gap.** MIP-06 PR explicitly notes:
> "A SelfRemove only removes the sending leaf. If same-identity sibling leaves remain, clients SHOULD warn the user and MUST NOT present that action as having left the group entirely."

Keeping SelfRemove leaf-scoped is correct — its security property depends on "leaver identified by sender.leaf_index" (MIP-03 §147), and making it identity-scoped would break that. **But the UX gap is real**: a user with 3 devices who wants to leave a group entirely must SelfRemove from each device. Admin-initiated full-user removal has the same shape — bundle of N Remove proposals that can miss leaves if the admin's view is stale. And there are related gaps — removing a lost device, removing your own siblings without admin coordination — that share structure.

**This is the clearest concrete case where Marmot would need its first custom MLS proposal type.** The full design space — scenarios, options, edge cases — is explored in §7. Short version: a combination of (a) a same-identity authorisation carve-out on standard Remove and (b) a Marmot-custom `IdentityRemove` proposal type covers the cases cleanly, with `IdentityRemove` standing outside the Safe Extensions framework (per §5.4) because the framework doesn't cover custom proposal semantics.

**E. `0xF2EF` encrypted_device_name** — LeafNode extension encrypted with NIP-44 to-self. Correctly Marmot-custom (this is a LeafNode extension, not a GroupContext extension, and the Safe framework doesn't target LeafNode extensions specifically).

### 6.8 Cross-MIP observations

**A. Marmot's MLS-Exporter usage is scattered.** Three different Marmot subsystems derive keys from raw `MLS-Exporter()` calls with ad-hoc labels: MIP-03 (`"marmot" / "group-event"`), MIP-04 (`"marmot" / "encrypted-media"`), and MIP-06 (`"marmot-mip06-join-psk-v1"`). The Safe framework's `SafeExportSecret(ComponentID)` would **replace all three with a single well-typed primitive**, with domain separation baked in rather than relying on label discipline.

**B. Marmot has no custom MLS proposal types.** All proposals are standard MLS or MLS-Extensions. If this stays the case, `ProposalType::Custom(_)` may never be needed. But if future MIPs want features like "rotate relays" or "identity-scoped leave," a custom proposal type would be the right mechanism.

**C. Three places where Marmot rolls its own crypto** with pattern discipline but no formal domain separation:
- MIP-01 image encryption (HKDF labels `"mip01-image-encryption-v2"`, `"mip01-blossom-upload-v2"`)
- MIP-04 media encryption (HKDF label `"mip04-v2"` + file metadata)
- MIP-05 token encryption (HKDF labels `"mip05-v1"`, `"mip05-token-encryption"`)

The MIP-04 case could migrate to the Safe framework. The MIP-01 case is a deliberate design trade-off and should stay as-is (see §6.2). The MIP-05 case is classical public-key crypto to an external server and stays custom.

---

## 7. Design exploration — Identity-scoped removal

This section walks the full design space for "remove every leaf of a given identity" operations. It was triggered by the MIP-06 gap (SelfRemove being leaf-scoped, no way to leave-all-my-devices in one operation), but on exploration the problem space is broader than that one case.

**Working hypothesis going in:** a single MLS commit bundling N Remove proposals (one per target leaf) might cover the space without needing a new proposal type.

**Conclusion after walking it:** a bundle covers some cases but misses important ones (race with new-leaf-added during removal; self-reference when committer is same-identity; missed-leaf if committer's snapshot is stale). A minimal-but-complete design combines an authorisation carve-out on standard Remove with a new Marmot-custom `IdentityRemove` proposal type. Details below.

### 7.1 The scenario space

Each row is a distinct situation that identity-scoped removal needs to handle:

| # | Scenario | Initiated by | Target | Who's in possession of target's keys? |
|---|---|---|---|---|
| A | User wants to leave group entirely | User (any of their devices) | All of user's own devices | All still trusted |
| B | Admin kicks a user entirely | Admin | All of target-user's devices | Target not necessarily present |
| C | User's single device is compromised | User (from another device) OR admin | One specific leaf | One device compromised; rest fine |
| D | Lost device (out of user's possession) | User (from another device) OR admin | One specific leaf | Lost device cannot participate |
| E | Selective consolidation | User (from the keeper device) | Some of user's own other devices | All trusted; user is migrating |
| F | Last admin wants to leave entirely | User (the sole admin, any device) | All of user's own devices | Must self-demote first (per MIP-01) |
| G | Simultaneous identity-remove race | Two of user's own devices | All of user's devices | Both trusted; racing |
| H | New leaf added mid-removal | Admin (or any committer) | All of target-identity's current + newly-added leaves | Target identity adds a new device via External Commit between "committer computes set" and "commit applies" |
| I | Self-reference: committer is same-identity as target | Same-identity leaf of removed user | All of user's own devices (including committer) | RFC 9420 §12.2 conflict — committer can't be in removed set |

Scenario C is fully covered today by standard Remove (admin-initiated) or SelfRemove (user from the compromised device, if attacker hasn't locked them out). No identity-scoped primitive needed.

Scenarios A, B, F need bulk identity-scoped operations. Scenarios D, E need single-leaf-same-identity operations. Scenarios G, H, I are edge cases that constrain the design.

### 7.2 Three design options

**Option 1: Client-side bundle of standard Remove proposals.**
Committer enumerates all leaves of the target identity from their current view of the ratchet tree and bundles N standard Remove proposals into one commit.

- **Authorisation:** standard Remove rules — admin-only per MIP-01.
- **Covers:** Scenario B (admin kicks user). Partially covers A and F if an admin happens to be the user (they can admin-commit the bundle of their own leaves).
- **Fails:** Scenario A for non-admins (they can't issue Remove proposals). Scenario H (if a new leaf is added between "enumerate" and "commit," the new leaf is missed). Scenario I (committer's own leaf can't be in the bundle).
- **Pros:** no protocol change; uses proven MLS machinery.
- **Cons:** no atomicity guarantee on the identity set; every client can get the enumeration wrong differently.

**Option 2: Same-identity authorisation carve-out on standard Remove.**
Extend MIP-01's authorisation rule: a leaf MAY issue a Remove proposal targeting another leaf if both leaves share the same credential identity, even without admin privileges.

- **Authorisation:** admin OR same-identity as target leaf.
- **Covers:** Scenario D (user removes their own lost device from another of their devices). Scenario E (user consolidates — removes their other devices).
- **Fails:** Doesn't help with bulk identity-scoped ops (A, B, F) beyond what Option 1 already does.
- **Pros:** minimal protocol change; just an authorisation rule amendment.
- **Cons:** not sufficient alone; covers only the single-leaf-same-identity cases.

**Option 3: Marmot-custom `IdentityRemove` proposal type.**
Raw `ProposalType::Custom(marmot-assigned-u16)` carrying a target identity (Nostr pubkey). Semantically: "remove every leaf whose credential identity equals this pubkey, resolved at commit-time against the committer's post-proposals ratchet tree." Body:

```tls
struct {
    uint16 version;              // current: 1
    opaque identity[32];         // target Nostr pubkey (raw 32 bytes)
} MarmotIdentityRemove;
```

Resolution: the MLS implementation expands this one proposal into N leaf-Remove operations at commit-application time, where N is the number of leaves with that identity at the commit's epoch. If N is 0, no-op.

- **Authorisation:** same policy as SelfRemove — any remaining member (not in the removed set) can commit it. Similarly: identity-targeted proposal, any-member commit, with the committer-not-in-removed-set rule enforced naturally because the committer's identity is checked against the target.
- **Covers:** Scenarios A and B atomically. Scenario F with the admin-self-demote dance layered in. Scenario H correctly — resolution at commit time captures newly-added leaves.
- **Needs:** race protection like SelfRemove (auto-commit-by-lowest-index-remaining-non-target-identity-member).
- **Pros:** atomic, race-resistant, semantically clear intent in the commit log, wire-efficient (one proposal, not N).
- **Cons:** new proposal type with Marmot-owned validation; coordination overhead.

### 7.3 Recommended shape: Option 2 + Option 3

Together:

- **For "I want to leave this group entirely" or "kick this user entirely":** use `IdentityRemove` (Option 3). Atomic, race-resistant, captures new-leaf-added-during-removal.
- **For "remove this specific other device of mine" (lost, selective migration):** use standard Remove with same-identity authorisation carve-out (Option 2). Targets one leaf, no new proposal type.
- **For "just me, just this device":** standard SelfRemove (unchanged). Leaf-scoped, stays as-is because its security property depends on "leaver identified by sender.leaf_index."

The three primitives form a coherent matrix:

| Scope | Primitive | Who can author | Who can commit |
|---|---|---|---|
| One leaf — the sender | `SelfRemove` (standard) | Any non-admin member | Any other member |
| One leaf — a specific other leaf | `Remove` (standard, with authorisation carve-out) | Admin OR same-identity-as-target | Admin (commit side stays admin; carve-out is on authoring) |
| All leaves of a specific identity | `IdentityRemove` (Marmot-custom) | Admin OR same-identity-as-target | Different-identity member (same restriction as SelfRemove) |

One-identity-scoped-leave is naturally modelled as "any of my devices authors `IdentityRemove` targeting my own identity; any remaining non-same-identity member commits it."

### 7.4 Edge cases and design choices

**Wire format.** `IdentityRemove` is Marmot-only — no external-commit interop pressure (MIP-06's External Commits are narrowly constrained and don't reference pending proposals). Can be PrivateMessage. No OpenMLS wire-format-policy issue.

**Committer ≠ target identity.** If `IdentityRemove` targets the committer's own identity, the committer is in the removed set, violating RFC 9420 §12.2. Enforce: "the committer's credential identity MUST NOT equal the target identity of any `IdentityRemove` proposal in the commit." This mirrors SelfRemove's rule and uses the same auto-commit-by-remaining-member pattern.

**Admin depletion.** `IdentityRemove` targeting an admin identity must trigger the same admin-depletion check as SelfRemove (MIP-03 §150): after applying, at least one active-admin leaf must remain. If the target is the last-admin identity, the commit MUST be rejected. Scenario F (last admin leaves) needs the admin-first-self-demote flow from MIP-01/MIP-03, but at the identity level: demote all of their admin status via a GroupContextExtensions update first, then `IdentityRemove` themselves.

**Admin-cannot-identity-remove-self.** Same as MIP-03 §149: a member whose public key is in `admin_pubkeys` MUST NOT author an `IdentityRemove` targeting their own identity. Demote first, then leave.

**Remove-beats-IdentityRemove.** If a pending Remove proposal targets a specific leaf and a pending `IdentityRemove` would also remove that leaf, the Remove wins (consistent with MIP-03 §151's Remove-beats-SelfRemove rule).

**Empty result.** If `IdentityRemove` resolves to zero matching leaves at commit-time (e.g., the target identity's last leaf was just removed by a concurrent commit), the proposal is a no-op — accept the commit, don't treat as error.

**Proposal-time vs commit-time resolution.** Commit-time. This is the feature that distinguishes `IdentityRemove` from Option 1's bundle — at commit-time, the MLS implementation walks the post-proposals ratchet tree and expands the one proposal into the correct N leaf-removes.

**Race handling: auto-commit rule.** Analogous to SelfRemove's lowest-index-remaining-member rule: among remaining members whose credential identity is NOT the target, the lowest-leaf-index member auto-commits. Others observe the commit via normal inbound and advance.

**Interaction with MIP-06 multi-device signaling.** `IdentityRemove` only makes sense in groups where multi-device is possible. In a group where every user has exactly one leaf, `IdentityRemove` and `SelfRemove`/`Remove` collapse to the same outcome. This means `IdentityRemove` could be gated on `marmot_multi_device` (`0xF2F0`) being enabled — or it could work universally with the identity→leaves map being trivially 1-to-1 in non-multi-device groups.

**Wire format within the Safe framework.** `IdentityRemove` is a custom proposal type — **the Safe framework does not help here** (§5.4). Marmot would define the proposal body, the validation rules, and the auto-commit policy entirely in the MIP and in the CgkaEngine implementation. This is the clearest concrete case where Marmot would claim its first `ProposalType::Custom(u16)` number.

### 7.5 Authorisation carve-out on standard Remove (Option 2) — specifics

Minimal MIP-01 / MIP-03 amendment:

> A Remove proposal targeting a leaf L MAY be authored by another leaf L' without admin privileges if and only if L and L' share the same credential identity. Validation: receivers MUST verify the sender leaf's credential identity equals the target leaf's credential identity at proposal-authoring time. Committing a Remove proposal remains restricted to admin-issued commits unless the commit is a SelfRemove-only commit or (future) an IdentityRemove-only commit.

This is an authorising rule on who can *propose* Remove. Committing still follows MIP-01's admin-only rule. In practice this means:

- A user's non-admin device can *propose* Remove of a sibling leaf, but an admin's commit is still required to process it.
- If the user IS admin (or any admin is available), the proposal is committed normally.
- Without admin availability, the sibling-Remove proposal waits — same pattern as any non-SelfRemove proposal.

**Optional extension:** a "SiblingRemove-only commit" carve-out analogous to SelfRemove-only — any member MAY commit a Remove proposal issued by a same-identity leaf of the target, without admin privileges, provided the commit contains only Remove proposals where author and target share identity. Makes Scenario D (lost device) workable without admin coordination.

### 7.6 Open questions for the identity-remove design

- **Is the authorisation carve-out on Remove (Option 2) worth the validation complexity, or is `IdentityRemove` alone enough?** If users rarely want to remove just-some-of-their-devices, Option 2 could be deferred. Walking through UX: device-loss (Scenario D) is important; selective consolidation (E) is nice-to-have.
- **Should `IdentityRemove` be gated on `marmot_multi_device` (0xF2F0)?** Technically it still works in single-device groups (trivially). Gating keeps the new proposal type narrowly scoped to the feature that motivates it. Leaving it ungated makes the primitive available for any group.
- **What's the interaction with pairing flows?** If device B is being removed via `IdentityRemove` while device C is joining via MIP-06 External Commit, both targeting the same identity — ordering matters. Commit-time resolution handles this naturally but the UX might be confusing.
- **Do we need an identity-scoped Remove at all, or can admins just be trusted to bundle correctly?** If groups always have a responsive admin, Option 1's bundle works for Scenario B and user-initiates-via-admin-request works for Scenario A. The argument for `IdentityRemove` is strongest in admin-absent or non-admin scenarios — which are precisely the cases SelfRemove was invented to solve.

---

## 8. Recommendations (in priority order)

### 8.1 Immediate (no spec changes)

- **Update MIP-03 §141** with the explicit note about SelfRemove PublicMessage inheritance (§3 of this doc has the proposed wording).
- **Document the `kind: 450` Nostr-identity-in-authenticated_data pattern** as a reusable Marmot primitive, not just an MIP-06 detail. Future MIPs that need to prove Nostr-identity-to-MLS bindings can use it.

### 8.2 Near-term (one-MIP changes)

- **Add `Feature::MarmotAdmins` capability** to the feature registry (if/when capability registry formalizes). Makes the admin-model dependency explicit and capability-gated.
- **Clarify in MIP-01 that `disappearing_message_secs` is conceptually separate** from transport/identity concerns in marmot_group_data, even if wire-formatted together for v3 compatibility. This prepares future splits.

### 8.3 Medium-term (Safe-framework adoption)

- **Investigate whether OpenMLS (or alternative MLS backends) supports draft-09's Safe Extensions framework.** Marmot adoption is gated on backend support. If no backend supports it yet, the medium-term work is upstream contributions.
- **Add a "Safe Extensions adoption plan" MIP.** Walks through MIP-03's `group_event_key`, MIP-04's media keys, and MIP-06's `join_psk`, showing how each migrates from raw `MLS-Exporter()` to `SafeExportSecret(ComponentID)`. Includes a migration strategy since existing groups have keys derived from the old labels. **Note: MIP-01's image encryption is deliberately excluded — see §6.2, its epoch-independence is a considered trade-off, not a Safe-framework candidate.**
- **Claim a Marmot ComponentID block.** Even before adopting Safe framework, declare that Marmot will use `0x8000–0x80FF` (or similar) for its own ComponentIDs when it does. Establishes a namespace.

### 8.4 Long-term (architectural)

- **Split `marmot_group_data` into multiple AppDataDictionary entries** as discussed in §6.2. Major migration; requires coordinated client rollout. The clean long-term shape.
- **Define Marmot's first custom proposal type: `IdentityRemove`.** Per §7 — addresses the MIP-06 leave-all-my-devices gap, admin-kicks-user-entirely races, and related identity-scoped flows. Also amend standard Remove authorisation with a same-identity carve-out (§7.5). Specifically won't use the Safe framework because the framework doesn't cover custom proposal semantics (§5.4).
- **Other custom proposal candidates for future consideration:** "rotate relays" (currently a GroupContextExtensions update), "change admin set" (currently a GroupContextExtensions update). These are well-served by the existing approach; they don't need proposals of their own yet.
- **If starting fresh today, Marmot would build on the Safe Extensions framework** rather than the classical custom-extension-type + ad-hoc-MLS-Exporter-label pattern. Existing customs don't need emergency migration, but every new subsystem should be evaluated against the Safe framework as its first-choice home.

---

## 9. Open questions still requiring more work

**Implementation diversity:**
- **Marmot currently has two protocol implementations** — MDK (Rust, via rust-nostr) and Marmot-TS (TypeScript, written independently by a team member). Marmot-TS has already surfaced real stress points and spec ambiguities that MDK-alone wouldn't have caught, which validates the "multiple independent implementations keep the spec honest" principle. Worth continuing to invest in Marmot-TS parity, and considering at least one more independent implementation (a different language / ecosystem) as a 12-24-month goal. Thick protocols benefit disproportionately from this kind of cross-checking.

**Safe framework adoption:**
- **Does OpenMLS support draft-09's Safe Extensions framework?** If not, Marmot adoption is blocked on upstream work. Needs investigation — the Safe framework is relatively new in the draft. Marmot-TS's support story for the Safe framework is a separate question worth checking alongside.
- **What's the migration path for existing groups** if `marmot_group_data` is split across multiple `AppDataDictionary` entries? A simultaneous `GroupContextExtensions` update removing the old extension and adding the new ones is technically possible but coordinationally expensive.
- **Should Marmot commit to a specific ComponentID sub-range** (e.g., `0x8000–0x80FF`) before any Safe-framework adoption, to establish namespace hygiene?

**Identity-scoped removal (§7):**
- **Is the authorisation carve-out on Remove worth the validation complexity**, or is `IdentityRemove` alone enough? Depends on how often users want selective-not-all device removal.
- **Should `IdentityRemove` be gated on the `marmot_multi_device` extension (0xF2F0)** or available universally? Gating keeps it scoped to the motivating feature; ungating makes it a general primitive.
- **What's the race/ordering story when `IdentityRemove` collides with concurrent `SelfRemove` or External Commit for the same identity?** The commit-time resolution helps, but the interaction with the MIP-06 pairing flow deserves a dedicated walk-through.
- **Is there appetite for a Marmot custom proposal type registry?** `IdentityRemove` would be the first; specifying value-number coordination, a validation framework, and a pattern library would make future custom-proposal work cheaper.

**Nostr identity proof pattern:**
- **Should `kind: 450`-style identity proofs be generalised** into a single `MarmotNostrIdentityProof` primitive that different MIPs can reference, or stay per-MIP-use? MIP-06 PR treats it as MIP-06-specific.
- **How does the `kind: 450` pattern interact with NIP-42 / NIP-46 / Amber signers?** The MIP-06 PR says they MUST support signing the canonical proof event exactly as specified. Is this already supported by existing signer implementations?

---

## 10. Corrections to earlier drafts of this doc

**The 2026-04-18 draft asserted "Marmot does not use external commits"** — based on reading only the merged MIPs and missing the MIP-06 PR. MIP-06 uses External Commits for multi-device joins. The PublicMessage-for-SelfRemove rationale therefore isn't as purely vestigial as the earlier draft claimed; it's narrowly unused because MIP-06 explicitly forbids non-ExternalInit-or-PSK proposals in External Commits. The three-paths-for-SelfRemove recommendation in §3 stands but the motivation for switching to custom is slightly weaker than first stated.

**The 2026-04-18 draft speculated about MIP-04/MIP-05/MIP-06 shape without reading them.** §6 above replaces that speculation with readings of the actual specs. Several of the earlier doc's "likely findings" were wrong in specifics (e.g., "MIP-05 likely application-layer, no custom proposal type" was right; "MIP-04 should be a `Feature::EncryptedMedia`" missed the more important finding that MIP-04's exporter-derived key is a Safe-framework candidate).

**The 2026-04-18 draft did not include the Safe Extensions framework.** Draft-09's formalization is a significant development and substantially changes the "custom vs inherit" calculus going forward.

**The 2026-04-19 draft framed MIP-01's group image encryption as "works against forward secrecy."** That framing missed the deliberate design trade-off. MIP-01 stores the `image_key` seed directly in the extension precisely so that the image doesn't need to be re-encrypted and re-uploaded on every epoch change. The residual threat model — "former or current group insiders can decrypt historical group images" — is an accepted loss vs. the operational cost of per-epoch re-derivation. §6.2 has been corrected: MIP-01 image encryption is **correctly Marmot-custom as-is and should not migrate to the Safe framework**. Per-file media encryption (MIP-04) is a different story — per-file keys are short-lived and accept forward-secrecy behaviour naturally.

**The 2026-04-19 draft underplayed the identity-scoped removal problem.** After further exploration (added as §7), the problem space is broader than just "leave all my devices" — it includes admin-kicks-user-entirely, lost-device-removal, selective consolidation, and edge cases around new-leaf-added-during-removal. The recommended shape is a combination of a same-identity Remove authorisation carve-out plus a new Marmot-custom `IdentityRemove` proposal type. This would be Marmot's first custom MLS proposal type. It stands outside the Safe framework (which doesn't cover custom proposal semantics).

## 11. TL;DR

- **The SelfRemove trigger was real but narrower than first stated.** SelfRemove's PublicMessage requirement is narrowly vestigial for Marmot (MIP-06 uses External Commits but constrains them enough that pending SelfRemoves can't be referenced through them). Recommendation to hedge — abstract leave at the CgkaEngine trait, ship standard today — still stands.
- **The bigger opportunity is the MLS Extensions draft-09 Safe Framework.** It's the right architectural home for several places where Marmot currently rolls its own MLS-Exporter labels (MIP-03 group_event_key, MIP-04 media keys, MIP-06 join_psk). Gradual migration is feasible; upfront commitment to a ComponentID namespace is cheap. **If starting fresh today, Marmot would build on the Safe framework as the base for most customisations.**
- **`marmot_group_data` should eventually split into multiple Safe-framework entries.** Current monolithic shape conflates transport, identity, policy, and message-lifecycle concerns. Long-term migration.
- **MIP-01's group image encryption is correctly Marmot-custom as-is.** The epoch-independent image key is a deliberate operational trade-off, not a flaw. Do not migrate it to the Safe framework.
- **The `kind: 450` Nostr-identity-proof pattern from MIP-06 is reusable** and worth documenting as a first-class Marmot primitive.
- **Marmot's first custom MLS proposal type should be `IdentityRemove`.** Addresses the MIP-06 leave-all-my-devices gap plus admin-kicks-user-entirely races, new-leaf-during-removal edge cases, and lost-device scenarios. Paired with a same-identity authorisation carve-out on standard Remove. Stands outside the Safe framework (§5.4). Full design space in §7.
- **Most of Marmot's current Marmot-specific extensions (`0xF2EE`, `0xF2EF`, `0xF2F0`) are appropriately custom** — no gain from inheriting a standard. The opportunity is in the exporter-derived secrets, the authenticated_data contributions, and splitting the `marmot_group_data` monolith.
