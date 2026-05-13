# Decision Points

Historical note: this April 2026 decision log predates the current `CgkaEngine` / `TransportPeeler` / `TransportAdapter`
crate split. Keep it as background rationale; use the overview docs and CGKA engine spec for current status.

**The problem this addresses:** Good architecture docs can still leave engineers uncertain about what's actually decided
vs. what's still open. This document makes that explicit. Each decision either has a clear recommendation or is flagged
as requiring team input.

**Historical status summary:** Decision 6 (PCS) was resolved at the time. Decision 8 (refactor vs. greenfield) was the
major unresolved decision in this note and affected the priority and sequencing of everything else. All other decisions
had recommendations but had not been formally confirmed by the team.

_Last updated: 2026-05-09._

---

## 1. Complete the session-projection refactor before anything else

**Decision:** Should the team proceed with the 19-phase session-projection refactor as designed, or pursue a more
aggressive restructuring (crate decomposition, state machine rewrite)?

**Options:**

- A) Execute the session-projection plan as written
- B) Skip it and go straight to crate decomposition
- C) Hybridize — do session projection but plan crate boundaries during the refactor

**Key tradeoff:** Velocity vs. architectural ambition. The session-projection refactor is well-designed, scoped, and
ready to execute. A more ambitious restructuring would deliver more architectural value but delays shipping.

**Recommendation: Option A, then extract crates incrementally.** The session-projection refactor is the prerequisite for
everything else. It establishes the ownership boundaries that become crate boundaries later. Trying to decompose the
monolith without first resolving the singleton problem means fighting two structural issues simultaneously. Ship the
refactor. Then extract `whitenoise-push` (most self-contained), then `whitenoise-relay-pool` (most reusable).

---

## 2. Build the coordinator now, as a standalone library

**Decision:** How to formalize the MLS commit ordering strategy?

**Options:**

- A) Keep the current ad-hoc approach (EpochSnapshotManager + timestamp tie-breaking)
- B) Build a coordinator as a library (in-process, deterministic sequencing)
- C) Build/deploy a sequencing relay
- D) Wait for causal-order CGKA (BeeKEM) to eliminate the need

**Key tradeoff:** Engineering effort now vs. operational pain later. The current approach works for small groups with
low concurrency. It will break under load or with many simultaneous updates.

**Recommendation: Option B.** Build the coordinator as a standalone Rust struct with a pure function interface:
`ingest(event) → Vec<OrderedOperation>`. This is low-risk, testable, and directly useful. It subsumes the existing
`EpochSnapshotManager`. Design it with a clean interface so that a sequencing relay (Option C) could use the same logic
server-side if needed later. Do NOT wait for BeeKEM — that's a 6-12 month horizon and may never ship for messaging
workloads.

**Before building: instrument the current rollback system.** Measure how often commit races actually occur, at what
group sizes, and what the recovery cost is. This data determines whether the coordinator needs to be sophisticated or
simple.

---

## 3. Abstract the CGKA interface now, even if BeeKEM is years away

**Decision:** Should MDK's MLS implementation be abstracted behind a CGKA trait?

**Options:**

- A) Keep MDK as-is (direct OpenMLS dependency, Nostr types in API)
- B) Introduce a CGKA trait in whitenoise-rs that MDK implements
- C) Refactor MDK's API to remove Nostr types, then introduce the trait

**Key tradeoff:** Abstraction cost vs. future flexibility. The trait itself is cheap. Cleaning Nostr types out of MDK's
API is more work but pays for itself in testability.

**Recommendation: Option C.** MDK's `process_message` currently takes a `nostr::Event`. It should take MLS-typed data
(bytes + metadata). A thin adapter in whitenoise-rs converts Nostr events to this format. This makes MDK a genuine MLS
library (usable outside Nostr), makes the CGKA trait natural to define, and enables testing MDK without constructing
Nostr events. The adapter is ~200 LOC.

This also positions the codebase for BeeKEM evaluation. Whether or not BeeKEM is production-ready, the ability to
prototype it against the same interface is valuable for making an informed decision later.

---

## 4. Don't build transport abstraction yet, but design the interface

**Decision:** Should whitenoise-rs abstract over the transport layer now?

**Options:**

- A) No abstraction — keep Nostr relay code inline
- B) Full transport adapter trait with pluggable implementations
- C) Design the trait, implement only for Nostr, refactor call sites when a second transport arrives

**Key tradeoff:** YAGNI vs. preparation cost. FIPS is v0.2.0 with no mobile support. There is no second transport today.

**Recommendation: Option C.** Design a `TransportAdapter` trait on paper (in the wiki, not in code). Implement it only
for Nostr. Don't refactor call sites yet. When FIPS reaches native API + mobile support, or when a sequencing relay is
built, implement the second adapter and refactor then. The design exercise is free and prevents painting yourself into a
corner. The implementation work should wait for a real second transport.

---

## 5. Invest in the testing transition at Phase 12

**Decision:** How much to invest in the Tier 1 / Tier 2 / Tier 3 testing migration?

**Options:**

- A) Minimal — rewrite broken tests to pass, keep Docker
- B) Full migration as documented — unit tests, MockRelay, Docker only for Blossom
- C) Full migration plus add the deterministic event replay testing the state machine model enables

**Key tradeoff:** Test infrastructure investment vs. feature velocity. Tests are not features. But untestable code is
unmaintainable code.

**Recommendation: Option B, with an eye toward C.** The MockRelay-based testing model is a genuine quality-of-life
improvement — developers stop needing Docker for routine work, parallel tests become possible, and multi-instance
scenarios (Alice sends to Bob) become testable for the first time. This is worth the investment.

If the coordinator (Decision 2) is built with a pure function interface, Option C comes almost for free — feed recorded
event sequences, assert on output. Start collecting event logs from real usage now so you have replay data when the
coordinator is ready.

---

## 6. ~~Decide whether PCS is a product requirement~~ — DECIDED

**Decision:** Is post-compromise security (PCS) essential to Marmot's value proposition?

**✅ RESOLVED (2026-04-15):** PCS is categorically required. FS + PCS are both non-negotiable for Marmot. A Signal-style
Sender Keys architecture is not on the table. MLS (or a future causal-order CGKA like BeeKEM) remains the foundation.

This decision closes the question. The complexity budget that comes with MLS is accepted. The coordinator exists to
manage that complexity pragmatically, not to avoid it.

~~Options and tradeoffs below retained for historical context:~~

MLS exists primarily to provide PCS. Sender Keys (Signal/WhatsApp) drops PCS, eliminates the ordering problem, but is a
step backwards on security. Not acceptable for Marmot's threat model regardless of group size or user type.

---

## 7. Extract push notifications into a standalone crate immediately

**Decision:** Should `push_notifications.rs` (3,632 LOC, single file) be extracted?

**Options:**

- A) Leave it — it works, the refactor will restructure ownership anyway
- B) Extract into `whitenoise-push` crate with clear API boundary
- C) Split into multiple files within the existing crate

**Key tradeoff:** Minimal. This is almost pure upside.

**Recommendation: Option C now, Option B after the session refactor.** The file is too large to reason about. Split it
into a `push_notifications/` directory with separate files for token management, rate limiting, MDK integration, and
relay operations. This is mechanical and low-risk. After the session refactor establishes ownership boundaries, extract
the directory into its own crate.

This is also the lowest-risk test of the crate extraction pattern. If extracting push notifications is painful, the team
learns what the extraction process looks like before attempting higher-stakes extractions (relay pool, MLS bridge).

---

---

## 8. Refactor or greenfield?

**Decision:** Should the team continue refactoring the existing whitenoise-rs + MDK codebase toward the target
architecture, or start a greenfield implementation built against the target architecture spec from scratch?

**Context:** The target architecture (see [[target-architecture]]) and the current codebase differ significantly. The
refactor path requires working against accumulated coupling at every step — Nostr types in MDK storage, the singleton
shape, static capabilities. The greenfield path starts from a clean slate but abandons working code and battle-tested
logic.

**Options:**

- A) Continue the refactor incrementally (session projection → coordinator → CGKA trait → transport adapter)
- B) Greenfield — new repos, new spec structure (FIPS-style layered docs instead of numbered MIPs), agent-assisted
  implementation
- C) Selective extraction — take what's genuinely right from the existing codebase (storage traits, OpenMLS integration,
  epoch snapshot system), put it in a new repo, build the target architecture on top

**What's genuinely reusable from the existing code:**

- `mdk-storage-traits` — the storage trait design is clean and well-tested
- OpenMLS integration patterns — a lot of edge cases have been worked out
- The epoch snapshot / rollback / retry system — genuinely clever and battle-tested
- The Flutter presentation layer — unchanged regardless of option

**What would be rewritten in any option:**

- The `Whitenoise` singleton and all of whitenoise-rs above MDK
- MDK's public API (remove Nostr types)
- The capability system (doesn't exist yet)
- The MIP spec structure (numbered MIPs → FIPS-style layered docs)

**Key tradeoff:** The refactor is lower-risk in the short term but higher-friction at every step. The greenfield is
higher-risk (rediscovering solved problems) but gives you the right architecture from day one and allows the spec and
implementation to be designed together rather than retrofitted.

**Recommendation: Option C (selective extraction) over pure greenfield, but with a greenfield mindset.** Take the 15-20%
of MDK that is genuinely right (storage traits, OpenMLS integration, snapshot system) and carry it forward. Rewrite
everything else against the target architecture. This avoids rediscovering solved problems while not inheriting the
coupling that makes Option A painful. The spec restructuring (FIPS-style layered docs) should happen simultaneously —
you can't do one without the other.

**This decision is currently open.** It requires team input and a clearer sense of appetite. The technical case for
Option C is strong; the organizational question is whether the team has the bandwidth to run a parallel implementation
track.

---

## Summary Matrix

| # | Decision | Urgency | Risk | Status / Recommendation |
| --- | --- | --- | --- | --- |
| 1 | Session-projection refactor | **Now** | Low | Execute as designed |
| 2 | Coordinator in MDK | **Soon** | Medium | Build as standalone library |
| 3 | CGKA abstraction | **Soon** | Low | Clean Nostr types from MDK |
| 4 | Transport abstraction | Later | Low | Design only, don't build yet |
| 5 | Testing migration | Phase 12 | Low | Full Tier 1/2/3 migration |
| 6 | PCS requirement | ✅ Resolved | — | PCS required. MLS stays. |
| 7 | Push notifications extraction | **Now** | Very low | Split file now, extract crate later |
| 8 | Refactor vs. greenfield | **Soon** | **High** | ⚠️ Open — team input needed |

At the time of writing, decisions 1, 6, and 8 were the critical path. Decision 8 was the major unresolved item because
its answer affected the priority and sequencing of everything else.
