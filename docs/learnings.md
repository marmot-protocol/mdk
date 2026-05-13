# Historical Engineering Learnings

Historical log of surprises, rough edges, and design frictions from the early
Marmot architecture work. This file is kept for archaeology only. Current
contracts live in `docs/marmot-architecture/`, `crates/*/README.md`, and
`crates/*/AGENTS.md`.

Format: date → area → observation → takeaway for the real system.

---

## 2026-05-09 — Engine line-by-line audit + fix pass

A read-only audit of every file under `crates/cgka-engine/src/` produced
15 findings. Of those, 14 were addressed in code or docs in the same
session; one (zeroize for `SignatureKeyPair`) is upstream-blocked.

The bug class that consistently slipped past the original review: **the
engine had two write paths for Marmot record fields** — `confirm_published`
mirrors `epoch + members + required_capabilities + name + description`,
while `update_group_record_from_replay` (the convergence-side apply path)
only mirrored `epoch + members`. Any GCE commit (capability upgrade,
update_group_data) accepted via convergence rather than direct publish-
confirm left two of the five fields stale on the recipient. Fix:
load the post-replay MlsGroup once and refresh all five fields. Tests
in `tests/update_group_data.rs` and `tests/capabilities.rs` now exercise
this path explicitly. Lesson: when a value is derived from MlsGroup,
keep ONE function that does the mirror and call it from every apply
site.

The privacy class that slipped: **operational identifiers (snapshot
names) were embedding plaintext group ids**. Storage error messages
propagate snapshot names; future tracing might surface them; SQLCipher
encryption protects the file at rest but not the in-process names. Fix:
hash the group id into an 8-byte digest before composing the snapshot
name. Lesson: the observability rule "no group_ids in tracing" should
extend to "no group_ids in any string that storage might surface."

The state-machine subtlety: **`EpochState` transitions in `EpochManager`
removed the entry from `states` before attempting the transition.** A
failing inner transition would orphan the group with no way to recover.
Fix: clone-then-replace pattern. Lesson: when `&mut self` operations
chain Result-returning transitions, never leave the data structure
inconsistent on the failure path.

---

## 2026-04-25 — Production refactor in progress

The CGKA engine production refactor (`plans/2026-04-22-cgka-engine-production-refactor-v1.md`) was largely complete at this checkpoint. The old prototype tree has since been removed. At the time, the workspace had these four core crates:

- `crates/traits` — shared trait surface + value types (zero Nostr leakage; verified by grep)
- `crates/cgka-engine` — OpenMLS-backed `CgkaEngine` impl
- `crates/storage-memory` — `Arc<RwLock>`-cloneable in-memory backend
- `crates/cgka-conformance-simulator` — multi-client `TransportBus` + `HarnessClient` + proptest

Test totals at this checkpoint: ~80 tests across the workspace, 0 failing. The
current workspace has more crates; use the root `README.md` as the current map.

Key corrections to earlier spike claims surfaced during implementation:
- Earlier notes said per-leaf `Capabilities` access was blocked by `MlsGroup::member_at`. Implementation revealed the deeper truth: `LeafNode::capabilities()` IS public, but `MlsGroup::public_group()` is `pub(crate)`. The cache (`CapabilityStorage`) is **load-bearing for correctness**, populated from KeyPackages we directly handle (invite path, ingested commits' Add proposals) plus `MlsGroup::own_leaf_node()` for self.
- The creator's commit at `create_group` has no consumer — every other initial member lands via welcome with the post-commit state. Dropped from the engine output; new `SendResult::GroupCreated { welcomes, pending }` variant. Side-benefit: the welcome-before-commit `AlreadyAtEpoch` bounce that this learnings file cataloged earlier no longer fires for initial creation (still fires for invites, where existing members do need the commit).

Now landed after this checkpoint: publish-before-apply, MIP-03 admin guards, first-pass deterministic fork recovery, and recovery observations in the canonical trace surface. Remaining recovery work is productionizing snapshot retention and packaging portable vectors beyond Rust tests.

See `crates/cgka-engine/tests/AGENTS.md` for the test-tier map and `crates/cgka-engine/AGENTS.md` for the per-subsystem responsibility map.

---

## 2026-05-04 — Fork recovery landed

The first working `ForkRecoveryManager` is in `crates/cgka-engine/src/fork_recovery.rs`. Same-epoch competing commits now use a deterministic content-derived ordering key: `SHA-256(mls_bytes)`, scoped by source epoch, with the lower digest winning. If a late inbound commit beats the local incumbent, the engine rolls storage back to the pre-commit snapshot and replays the winning commit. If it loses, the message becomes stale with `AlreadyAtEpoch`.

Storage snapshots are now part of engine correctness, not a dormant hook. `storage-memory` snapshots the full OpenMLS memory map as a pragmatic harness backend. `storage-sqlite` now snapshots group-scoped OpenMLS rows plus CGKA metadata atomically and uses Rust migrations for schema/data evolution; follow-up work should add retention/pruning and persist enough ordering metadata to recover after restart.

Follow-up: recovery observability now has a first contract.
`cgka_traits::GroupEvent::ForkRecovered` records the source epoch, recovered
epoch, winner ordering key, and invalidated incumbent ordering key.
`cgka_conformance_simulator::ScenarioTrace` exposes that as
`ClientObservation::recoveries` with hex message ids, and the deliberate fork
scenario asserts that exactly one peer rolls back to the deterministic winner.
That work has since moved into portable semantic fixtures such as
`group-data-fork-recovery/v1` and `concurrent-invite-fork-recovery/v1`; exact
randomized MLS commit bytes are outside the scenario contract.

---

## 2026-04-18 — Spike kickoff

**Setup predictions (to confirm/refute as we build):**

- `&dyn GroupContext` lifetime across crate boundary will force an Arc-or-clone decision in the peeler trait.
- OpenMLS extension registration for custom types (0xF2EA BasicGroupData, 0xF2EB NostrTransportData) may require more ceremony than the trait sketches suggest.
- `RequiredCapabilities` computation order vs. group creation is fiddly — extensions must be registered *before* we can advertise them in KeyPackage capabilities.
- Gift-wrap (kind 1059) for welcomes — `nostr` crate's NIP-59 helpers may not match MDK's construction exactly; might need to hand-roll.
- `nostr-sdk` subscription filter for `#h` tag on kind 445 requires the nostr_group_id hex — chicken-and-egg if we haven't peeled the welcome yet.

**Architectural decisions made for the spike:**

- Workspace split into 7 crates mirroring target-architecture seams: `cgka-engine` (trait), `transport` (traits), `mdk-spike` (engine impl), `nostr-adapter` (transport impl), `nostr-mls-peeler` (peeler impl), `whitenoise-core-spike` (wiring), `dm-cli` (binary).
- `NostrGroupDataExtension` split into two: `BasicGroupData` (name/description/image, transport-agnostic, ext type 0xF2EA) + `NostrTransportData` (nostr_group_id, relay hints, ext type 0xF2EB). Tests the "Nostr as transport feature" thesis.
- Feature registry includes `BasicGroupData` (Required), `NostrTransportData` (TransportRequired), `Reactions` (Optional, declared but not wired) — proves the three `RequirementLevel` shapes without over-building.
- Single-committer pattern (terminal A creates group + sends welcomes; B and C only send app messages) to avoid concurrent-commit race handling in the spike coordinator.

---

## 2026-04-18 — mdk-spike / OpenMLS 0.8 API friction

First real friction points hitting the OpenMLS 0.8.1 API. Caught at `cargo check`.

- **`openmls_basic_credential` version lock-in, silent.** OpenMLS 0.8.1 uses `openmls_traits` 0.5, but the transitively-visible `openmls_basic_credential` 0.4.1 still uses `openmls_traits` 0.4. If you default to `"0.4"` on the credential crate, you get cross-version `Signer` trait mismatches with no helpful error — just confusing "trait not implemented". Fix: pin `openmls_basic_credential = "0.5"` explicitly. Lesson: **MDK's CgkaEngine wrapper should pin the companion credential crate version tightly, not defer to semver.** Version skew inside the OpenMLS crate family is a real footgun.
- **`MlsMessageIn::tls_deserialize` requires explicit trait import.** `openmls::prelude::*` re-exports the types but not the `tls_codec::Deserialize` trait that provides `tls_deserialize`. Must `use openmls::prelude::tls_codec::Deserialize;` explicitly. The `tls_deserialize_bytes` associated fn is the alternative — slightly different semantics (returns `(Self, &[u8])`). Lesson: the CGKA trait should abstract this; application code must never see tls_codec.
- **`KeyPackageIn` → `KeyPackage` is not `Into`.** You must call `kp_in.validate(crypto, ProtocolVersion::Mls10)` to convert. This makes sense for security but is surprising — "deserialise a keypackage" is a multi-step operation, not a cast. Lesson: the spec parsing step belongs inside the CGKA engine, never leaks out.
- **`export_secret` takes `&OpenMlsCrypto`, not `&OpenMlsProvider`.** `provider.crypto()` to get the crypto subcomponent. Minor but annoying — most other methods take the provider.
- **`MlsGroup::required_capabilities()` is `pub(crate)`.** You must walk `group.extensions()` and pattern-match `Extension::RequiredCapabilities(rc)` yourself. Lesson: the trait `CgkaEngine::feature_status` must do this internally; exposing `RequiredCapabilities` to application code would be bad.
- **`MlsGroupCreateConfigBuilder::with_group_context_extensions` returns `Self`, not `Result<Self>`.** The builder doesn't validate ext-type conflicts at build-time. If you pass two extensions with the same type, failure happens later. Lesson: validate extension lists before passing to builder.
- **`Capabilities::new(...)` signature ergonomics.** Five `Option<&[T]>` args, easy to pass in the wrong order. The positional API is error-prone at the public boundary. Lesson: our wrapper should expose named-field builder, not the positional one.

---

## 2026-04-18 — Peeler design finding (disagrees with target-architecture.md)

The doc says `TransportPeeler::peel(&self, msg, ctx: &dyn GroupContext)`. In practice, `nostr-sdk` 0.44 made `gift_wrap` and `extract_rumor` async (for hardware signer support), which forces the peeler trait to be async. Once the trait is `#[async_trait]`, passing `ctx: &dyn GroupContext` across await boundaries triggers `E0195 lifetime parameters or bounds on method ... do not match the trait declaration` — async_trait's lifetime elision clashes with trait-object default lifetimes.

**Fix:** added a new type `GroupContextSnapshot` (owned `HashMap<String,[u8;32]>` of exporter secrets + epoch + transport_group_id). Engine materialises one via `GroupContextSnapshot::from_context(&ctx, &["nostr"])` right before each peeler call. Peeler takes `&GroupContextSnapshot` instead of `&dyn GroupContext`.

**This is actually better than the doc's design:**
1. The peeler doesn't need a live callback — it just needs values. Snapshot is "here's the data you need" vs. "here's an opaque handle you can call methods on". More honest.
2. The `labels: &[&str]` argument to `from_context` lets the engine decide which secrets a given peeler is allowed to see. Per-peeler isolation is free.
3. No dyn-trait allocation per peel call.
4. Works with `#[async_trait]` without lifetime gymnastics.

**Recommendation for target-architecture.md §"The TransportPeeler":** change `ctx: &dyn GroupContext` to `ctx: &GroupContextSnapshot`. The `GroupContext` trait can stay as the engine's internal abstraction; it should not cross the peeler interface.

Also: **nostr-sdk 0.44's async migration is broader than expected.** `EventBuilder::sign`, `EventBuilder::gift_wrap`, `nip59::extract_rumor` — all async now. Any trait that uses them must be async too. Worth noting when designing any new trait surface over nostr.

---

## 2026-04-18 — End-to-end working. Findings from the 3-terminal run.

**The demo succeeded:** 3 terminals on `wss://relay.primal.net` exchanged MLS-encrypted messages after A created a group with B and C, each received the welcome gift-wrap, joined, and then all three could send and decrypt messages visible to the others.

**Real rough edges discovered at runtime (not at compile time):**

1. **Self-welcome echo of the commit produces `WrongEpoch`.** When A creates a group with B and C, A publishes *both* a commit (wrapped kind 445) and welcomes (kind 1059) to each new member. B and C receive the welcome first — which contains the MLS group state at the post-commit epoch (epoch 1). They advance to epoch 1. THEN they receive the commit, which MLS correctly rejects because it's the epoch-0→epoch-1 commit and they're already at epoch 1. OpenMLS reports `ValidationError(WrongEpoch)`. This is logged as an ingest warning but otherwise a no-op.

   **For the real system:** either (a) the engine should recognize "already at or past this epoch" as deduplication rather than a processing error, or (b) the committer should NOT publish the commit when all members are also receiving a welcome (initial group creation case). Option (a) is cleaner. Option (b) is wrong once groups have pre-existing members across multiple adds.

   **Architectural finding:** `EngineError::Backend(String)` is hiding a structured error that the ingest loop should actually pattern-match on. The target trait should have typed error variants — `EngineError::AlreadyAtEpoch { .. }` or similar — so the coordinator can decide "drop silently" without stringly-typed error parsing. **Recommendation:** define a typed error enum on `CgkaEngine::ingest`'s result.

2. **nostr-sdk notifications are multiplexed across ALL subscriptions.** Every subscribe task has to filter notifications by its own `SubscriptionId`. If two tasks both call `client.notifications()` each gets its own broadcast receiver, but every event is still delivered to every receiver (N copies). This works, but it's silently O(N*M) — fine at this scale, expensive at Whitenoise scale.

   **For the real system:** either a centralised notification router that demuxes by subscription and sends only to the right downstream channel, or `nostr-sdk` should ideally expose per-subscription streams natively. Marmot today presumably already handles this in `relay_control/router.rs`; worth checking that its architecture survives the target refactor.

3. **Timing-sensitive bootstrapping.** First smoke test had the group create race ahead of B's welcome subscription being established — welcomes were missed. Fixed in the script by waiting 6s after process start. Lesson: in a real client, **publishing a key package is not sufficient to be invitable** — the client must also have an established welcome subscription BEFORE peers can successfully invite them. For the real system, the welcome subscription must be opened before announcing "I'm online". Already implicit in Whitenoise's account inbox plane, but worth writing down as a contract.

4. **The happy path runs under 2 seconds on primal.** Group create + welcome fan-out + 3 messages exchanged in well under 10 seconds total, mostly waiting on my sleeps. MLS overhead is negligible; latency is all transport.

5. **KeyPackage discovery via author filter works.** `Filter::new().kind(30443).author(pk).limit(1)` returned the latest KeyPackage in <1s on primal. No NIP-65 lookup needed for this test — useful shortcut to remember.

6. **`&dyn GroupContext` via `Box<dyn>` works cleanly for read-only queries.** The CgkaEngine trait still returns `Box<dyn GroupContext>` from `group_context()`, and that works fine — the consumer can call `.transport_group_id()` synchronously without ever hitting the async-trait lifetime issue. Only the peeler trait needed the snapshot indirection. The two patterns coexist without trouble.

**Summary of this spike vs. the target-architecture doc:**

- The crate-boundary design *is* the right design. Every seam I implemented maps cleanly to an architecture-doc component, and the boundaries held up under real integration.
- Three specific additions needed in target-architecture.md: `TransportEnvelope` discriminator on `TransportMessage`, `welcomes: Vec<TransportMessage>` on `SendResult::GroupEvolution`, and `GroupContextSnapshot` (value type) crossing the `TransportPeeler` interface instead of `&dyn GroupContext`.
- One addition needed in cgka-engine-design.md: typed error variants on `ingest()` so the coordinator can distinguish dedup-worthy conditions from real errors.
- The split of `NostrGroupDataExtension` into `BasicGroupData` + `NostrTransportData` is validated — FeatureRegistry flows work, RequiredCapabilities assembles correctly, multi-transport story is plausibly clean.
- OpenMLS 0.8 has enough pub(crate) surface (notably `required_capabilities()`) that a real CgkaEngine wrapper is well-motivated: the trait would forbid access to things application code shouldn't need.

---

## 2026-04-18 — Iteration 2: Invite, SelfRemove (MIP-03), typed ingest results, capability rejection

Added post-creation invite, spec-compliant SelfRemove (per MIP-03 and draft-ietf-mls-extensions-07), structured `IngestOutcome`, and a negative-capability test. All validated across 4 terminals on `wss://relay.primal.net`.

### What now works end-to-end

- **`/invite <npub>`** — 4th member invited after group creation. Existing members receive the commit, advance epoch, see `MemberAdded`. New member receives the welcome and joins at the current epoch.
- **`/leave`** — full MIP-03 SelfRemove flow. Leaver emits a SelfRemove proposal (PublicMessage, kind 445, via `MlsGroup::leave_group_via_self_remove`). Remaining members' clients automatically commit it (per spec §144: "any member MAY create a SelfRemove Commit"). All remaining members advance one epoch with the leaver removed.
- **`/features`** — shows FeatureStatus for each registered feature. `SelfRemove → AVAILABLE` after group creation confirms RequiredCapabilities is being respected.
- **`DM_DROP_CAPS=selfremove`** — drives a client that advertises a KeyPackage omitting the SelfRemove proposal capability. Group creation or invite refuses this client cleanly at the capability check, with a structured error naming exactly what's missing.
- **Post-SelfRemove chat** — B, C, D continue messaging at epoch 3 without errors after A leaves.

### Real findings (all have implications for the target architecture)

**1. `IngestOutcome` typed result is a clear win.** Replacing `Result<(), EngineError>` with `Result<IngestOutcome { Processed | Stale { reason } }, EngineError>` made the coordinator code dramatically cleaner. The wiring layer now decides log level per reason (debug for `AlreadySeen` / `NotForThisClient` / `AlreadyAtEpoch` / `OwnEcho` / `UnknownGroup`; warn only for real errors). No more `ValidationError(WrongEpoch)` warning noise on welcome-echoed commits. **Recommendation for cgka-engine-design.md:** adopt this as the trait contract.

**2. MIP-03's SelfRemove needs three pieces working together.** Not just "OpenMLS supports it":
- **Wire format policy must allow PublicMessage outgoing.** OpenMLS 0.8's `WireFormatPolicy` has only `AlwaysPlaintext` or `AlwaysCiphertext` for the outgoing direction — no mixed. `leave_group_via_self_remove` rejects pure-ciphertext groups (`CannotSelfRemoveWithPureCiphertext`). The spike uses `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` because the outer kind 445 ChaCha20Poly1305 layer still provides network-level encryption. **For real Marmot this is a problem** — app messages want PrivateMessage at the MLS layer. Options: (a) patch OpenMLS for mixed outgoing, (b) accept PublicMessage at MLS layer and rely entirely on transport encryption (the spike's choice), (c) use a different signing approach. Worth flagging to the OpenMLS team.
- **Auto-commit by one deterministic member.** If multiple remaining members auto-commit a SelfRemove proposal independently, they fork the epoch. Spike rule: "lowest-index remaining member commits." This produced clean convergence across 4 terminals with zero errors. **Recommendation:** codify the lowest-index rule in the MIP or the client spec. Alternatively, a small randomized delay + wait-for-other-commit would also work but is more complex.
- **Committer MUST NOT be the leaver** (RFC 9420 §12.2). Check the proposal's `sender.leaf_index` against `own_leaf_index` before attempting the commit.

**3. `leave_group()` vs `leave_group_via_self_remove()` in OpenMLS 0.8 are different paths.** `leave_group()` emits a regular `Remove` proposal targeting self — legacy-style, pre-SelfRemove-proposal-type. `leave_group_via_self_remove()` emits the new SelfRemove proposal type. Only the latter is spec-compliant for Marmot. Worth documenting in whatever wrapper MDK exposes — the name difference is subtle and the default `leave_group()` is probably the wrong choice.

**4. `remove_members([own_index])` is an error** (`CreateCommitError::CannotRemoveSelf`). Validated spec intent — OpenMLS refuses this specifically to force use of the SelfRemove proposal path. The architecture correctly forbids shortcuts.

**5. Relay backlog causes spurious peeler decrypt errors.** Any subscription without a `since` filter receives historical events encrypted with old-epoch secrets that the new joiner doesn't have. Fix in spike: `Filter::new()...since(Timestamp::now())`. The deeper fix was to treat peel-decrypt failures as `IngestOutcome::Stale` rather than hard errors. Current code uses `StaleReason::PeelFailed`, and stale source-epoch group envelopes can be terminal when no retained snapshot can peel them.

**6. Forked commit recovery is out of scope for the spike, but real.** When a commit race *does* produce a fork (e.g. two admins committing concurrent adds), some members end up at irreconcilable epoch-N-alpha / epoch-N-beta states. The spike dodges this via the lowest-index-auto-commit rule for SelfRemove, but the general mechanism is absent. The target architecture's `EpochState::Recovering { last_stable_epoch, buffered_events }` (cgka-engine-design.md) is the right home for this — worth prioritizing.

**7. Engine-emitted side-effect messages (auto-publish queue).** Adding `drain_auto_publish() -> Vec<AutoPublish>` to the `CgkaEngine` trait covers a real case the doc didn't explicitly name: sometimes processing an inbound message produces an outbound group-evolution message (e.g. auto-committing a received proposal). The app layer must publish these and then confirm or fail the attached `PendingStateRef`, just like explicit group evolution. **Recommendation for target-architecture.md:** keep `drain_auto_publish` in the CgkaEngine trait signature or fold it into a unified publish-obligation result.

**8. Per-leaf capabilities — spike used the wrong access path (corrected 2026-04-22).** The spike concluded that per-leaf `Capabilities` access is blocked in OpenMLS 0.8 because `MlsGroup::member_at(idx)` returns a `Member` struct with `credential` but no capabilities. **This is a mis-diagnosis, not a real limitation.** `LeafNode::capabilities()` has been `pub` since OpenMLS ≥ 0.7.0 and remains `pub` in 0.8.1. The supported access path is `group.public_group().leaf(idx)? → LeafNode::capabilities()`. `Member` is deliberately a thin summary type; the full leaf data lives on the public group. **Real-Marmot impact:** `feature_status()` can distinguish `Upgradeable` from `Unavailable` with no fork, no upstream PR. `CapabilityStorage` caching is still a worthwhile optimization (avoids tree walks; retains caps for removed members for audit/replay) — just not the *workaround* it was originally framed as.

**9. Capability rejection errors contain exactly the information a human or UI needs.** The spike's error message reads:
> `invitee KeyPackage missing required capabilities: required=GroupCapabilities { extensions: {62186, 62187}, proposals: {10} } had=GroupCapabilities { extensions: {62186, 62187}, proposals: {65281} }`
That's: required has proposal `10` (SelfRemove), had has proposal `65281` (Reactions) instead. The diff is obvious. **Recommendation:** promote this from `EngineError::Other(String)` to a typed variant like `EngineError::MissingRequiredCapabilities { required, had }` so the UI can render it directly instead of regex-parsing.

### Confirmed working from the previous iteration

- `wrap/peel_group_message` with exporter-secret ChaCha20Poly1305 holds across epochs 1→2→3 without re-keying anything in the peeler — the snapshot is rebuilt per call with the current epoch's secret, as designed.
- Kind 30443 KeyPackage publish/fetch is fast and reliable on primal.
- `GroupContextSnapshot` (value type crossing the peeler boundary) continues to be the right abstraction — no regressions even with the new proposal path.

### What I'd still change if this weren't a throwaway

- Add `EngineError::MissingRequiredCapabilities { required, had }` typed variant (see finding 9).
- Add `StaleReason::PeelFailed` to distinguish peel-level stale from MLS-level stale. Superseded: this now exists, and the Nostr group envelope carries a source-epoch hint so pre-join stale messages can be terminal.
- Fix the auto-commit race properly — the "lowest-index" rule is a shortcut that breaks when the lowest-index member is offline. Real fix: short randomized delay + observer-of-commit suppression.
- Store members' advertised capabilities in a local index so `feature_status()` can give real `Unavailable`/`Upgradeable` answers without LeafNode access.
- Use a custom OpenMLS build with mixed-outgoing wire format so MLS-layer encryption isn't sacrificed for SelfRemove support.
