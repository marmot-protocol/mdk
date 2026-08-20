# Explorations of multi-device

Status: exploratory and non-normative.

Last updated: 2026-08-20.

This document preserves the current design discussion around multi-device Marmot accounts. It is an architecture
exploration, not an interoperability specification. If any of these ideas become protocol behavior, the normative
design belongs in the `marmot-protocol/marmot` repository.

The main conclusion so far is that "multi-device" contains several separate problems:

1. authorizing a new device and adding it to existing MLS groups;
2. deciding which device KeyPackages should be used when another account is invited;
3. synchronizing accepted message history and private application state;
4. removing or recovering devices and rotating the authority they held.

These problems can share one user-facing workflow without sharing one protocol mechanism. In particular, content
sync should not be implemented by copying live MLS state between devices.

## Agreed working baseline

The following decisions are the current working baseline for a possible first version. They remain non-normative
until matching protocol text is adopted in `marmot-protocol/marmot`.

### Same-account admission

- A new, separately assigned `marmot.same-account-add.v1` capability gates the behavior. It does not reuse the
  earlier draft's `marmot.multi-device.v1` identifier or semantics.
- Every current member advertises support, and the GroupContext explicitly enables and requires the capability.
  Creating a group may enable it only when all initial members support it; enabling it in an existing group requires
  the ordinary administrator-authorized capability-upgrade flow.
- A non-administrator may commit one to four inline `Add` proposals when every added KeyPackage has a valid
  `marmot.member.account-identity-proof.v2` and every added credential identity exactly equals the committer's
  MLS-authenticated account identity.
- The Commit may contain no referenced proposals or other proposal types. Its normal MLS UpdatePath is required and
  permitted. Standalone Add proposals remain administrator-only.
- The resulting group may contain at most five current leaves for one account, including the sponsoring leaf. This
  resulting-state limit applies regardless of whether an administrator or same-account member authored the Add.
- The KeyPackages and leaf signature keys added by one Commit must be distinct and must not duplicate a current leaf.
- A valid same-account Add has ordinary rather than administrator-privileged convergence priority.

An account-identity proof establishes account-key authorization of a leaf signature key, not a human identity. The
authorization chain is the combination of a current member's MLS-authenticated control of a leaf, the new leaf's
account-key proof, exact equality of their account identities, and the current member's signature over the Commit.

### Welcome validation

The joining device recognizes two distinct authorization paths: the existing administrator invitation path and the
negotiated same-account path. For the same-account path, it requires:

- the exact KeyPackage created for the active pairing session;
- the expected MLS group id and sponsor account from the authenticated pairing manifest;
- `marmot.same-account-add.v1` enabled and required in the joined GroupContext;
- a current, non-blank GroupInfo signer whose validated account identity equals the joining leaf's identity;
- valid account-identity proofs on the sponsor and joining leaves; and
- no more than five resulting leaves for that account.

The receiver records which authorization path succeeded and does not silently fall back from a failed same-account
check unless the GroupInfo signer independently qualifies as an active administrator. A Welcome receiver cannot
reconstruct the candidate parent and revalidate the inline-Add-only Commit shape. Existing members validate that
candidate-parent rule; the joining device validates the authenticated pairing intent and resulting group state.

### Pairing and enrollment

- One new device initiates a short-lived, single-use pairing session. Its QR descriptor contains a version, random
  session id, ephemeral X25519 public key, account public key, expiry, rendezvous hints, and an account signature. It
  contains no group graph, KeyPackages, or MLS secrets.
- The QR lifetime defaults to two minutes and MUST NOT exceed five minutes. An expired descriptor is replaced rather
  than extended.
- The scanning device verifies the descriptor against its own account, asks for explicit approval, contributes a
  signed ephemeral key, and derives a transcript-bound encrypted channel. A separate visual short-authentication
  string is not required for the first version.
- The existing device sends an encrypted eligibility catalog. The user selects a bounded set of groups, and the new
  device creates one fresh, group-bound KeyPackage for each selection.
- Enrollment is a durable per-group operation, not one cross-group transaction. The implementation records intent,
  stages and publishes the Commit under publish-before-apply, delivers the Welcome redundantly, validates the join,
  and records an authenticated acknowledgement.
- Progress distinguishes pending, Commit published, Welcome delivered, joined, retryable failure, terminal failure,
  and skipped. Lost acknowledgement retries the same Welcome rather than another Add. A Commit that loses
  convergence restarts from canonical state with a fresh KeyPackage.
- Pairing channel keys may remain memory-only. Durable progress survives restart, but continuing unfinished work
  requires a newly authenticated pairing session that first reconciles already-completed membership.

### Same-account removal

- A separately negotiated `marmot.same-account-remove.v1` capability permits a non-administrator to commit one to
  four inline `Remove` proposals targeting current sibling leaves with the committer's exact account identity.
- The committer cannot target its own leaf; SelfRemove remains the self-departure path. The Commit contains no
  referenced proposals or other proposal types, carries the normal UpdatePath, and has ordinary convergence priority.
- Every current leaf has reciprocal authority to remove its own siblings. This deliberately accepts that compromise
  of one current device can cause denial of service by removing other devices.
- The protocol operation is scoped to one group. There is no first-version cross-group tombstone, atomic "remove this
  device everywhere" operation, or claim of global completion.
- Pairing may maintain a private device identifier and per-group leaf mapping for local presentation. That mapping is
  not protocol authority and does not appear in public KeyPackages or MLS credentials. Any later bulk-removal UX is a
  best-effort orchestrator over independently evidenced per-group results.

### Initial invitation

- When an account is not represented in a group, an administrator selects exactly one valid, compatible KeyPackage
  using the existing deterministic candidate-ranking rules and admits one initial leaf.
- Public KeyPackage publication-slot `d` tags remain opaque and are not physical device identifiers. Discovery never
  fans out automatically across every apparently valid KeyPackage.
- After admission, that account uses the negotiated same-account Add path to enroll siblings.
- Ambiguous Welcome delivery retries the same Welcome. It does not trigger an automatic Add for another KeyPackage.
  Replacing an unreachable initial leaf requires an explicit administrator removal followed by a new invitation with
  a fresh KeyPackage.

### Optional history bootstrap

Content bootstrap is not required for multi-device v1 interoperability or for a pairing operation to succeed. It is
an optional companion that may be omitted from the first implementation.

If implemented, it is an explicitly selected, one-time direct transfer of accepted, locally retained application
history over the authenticated pairing channel. It uses stable record ids, a typed versioned envelope, a per-group
high-water mark, chunk hashes, and a final completion manifest. Imported records retain provenance and are represented
as account-synchronized history, not as freshly MLS-verified traffic.

The transfer never includes a SQLCipher database, OpenMLS state, current or historical epoch secrets, sender
ratchets, KeyPackage private keys, pending operations, or unaccepted raw input. Continuous synchronization, CRDT
conflict resolution, asynchronous journals, cloud or relay backup, sync-key rotation, and cross-device presentation
state remain separate future work.

## Candidate direction

The most promising near-term design is:

- each physical device is an independent MLS client with its own leaf in every group;
- leaves belonging to the same account use credentials bound to the same Nostr identity;
- an existing leaf may sponsor an `Add` of another authenticated leaf for the same account, without being a group
  administrator;
- a short-lived, encrypted pairing session coordinates additions across a selected set of groups;
- an inviter from another account normally admits one device, after which that device can add its siblings;
- accepted content and private application state, if synchronized, use a separate typed record format;
- optional initial history transfer may happen directly during pairing, while continuous synchronization remains a
  separate future design;
- P2Panda remains a promising possible implementation of the journal and replication layer, rather than a
  replacement for MLS group membership.

This keeps the MLS model conventional: one leaf owns one leaf secret and receives an ordinary `Welcome`. The unusual
part is confined to an application authorization rule for adding another leaf belonging to the same account.

## 1. Adding another device to existing groups

### Why reconsider External Commits

The earlier multi-device proposal used an External Commit, a group-derived join PSK, externally supplied `GroupInfo`,
and additional administrator authorization. That machinery makes sense when a prospective member must join without
the assistance of a current group member.

Device pairing is different. A current device is deliberately online, already has current group state, and is
authorizing another endpoint belonging to its own account. An ordinary `Add` Commit already supplies:

- a current, authenticated sponsor;
- an exact KeyPackage to admit;
- normal MLS path-secret evolution;
- a standard `Welcome` for the new leaf; and
- the usual group convergence and Commit delivery behavior.

The administrator proof in the earlier design also creates the availability problem it was intended to avoid: a
non-administrator cannot add its own device until an administrator comes online.

### Same-account `Add` authorization

A candidate application rule is:

> A current member may commit an Add-only membership change when every added KeyPackage carries a valid account
> identity proof, every added credential identifies the same account as the committer, the group has negotiated this
> behavior, and all resource and device-count limits pass.

The exact language and validation inputs still need specification. Conceptually, this divides authority as follows:

- administrators admit accounts that are not already represented;
- an existing account leaf may admit additional leaves for that same account;
- an account leaf cannot use this exception to add another identity;
- ordinary administrator rules continue to apply to mixed or unrelated membership changes.

One Commit could add one or several same-account KeyPackages, subject to a group-wide limit and a per-account leaf
limit. Keeping the change Add-only makes the exception easier to validate and reason about.

This removes the need for pairing-specific use of:

- External Commits;
- a join PSK;
- externally provisioned `GroupInfo`;
- a second administrator signature; and
- transfer of a group event key.

It does not remove the normal publish-before-apply, `Welcome` delivery, retry, or convergence requirements around an
MLS Commit.

### Validation by existing and joining members

Existing group members need to recognize the candidate parent as either:

- an administrator using the ordinary admission path; or
- an existing leaf adding only authenticated leaves for its own account under the negotiated feature.

The joining device should validate at least:

- that the `Welcome` consumes the expected KeyPackage;
- that it names the expected group from the pairing manifest;
- that the sponsoring credential belongs to the paired account;
- that the resulting group state contains the expected same-account relationship; and
- that the group advertises the required feature.

The last checks are application-level authorization checks around the MLS result, not substitutes for MLS
cryptographic validation.

### Security consequences

Possession of the Nostr account key alone should not be sufficient to add a device to an existing group. The sponsor
must also control a current MLS leaf capable of producing the Commit. Conversely, compromising a current device would
allow an attacker to add a persistent same-account leaf. The design therefore treats a device as a real account
endpoint, not a disposable presentation of a central identity.

A stale sponsor cannot create a valid current-epoch Commit. Conflicting additions are ordinary MLS concurrency and
convergence problems; a retry may require a fresh KeyPackage.

Older clients will reject a non-administrator Add unless this behavior is negotiated. Existing groups may therefore
need a one-time administrator-authorized capability upgrade, or the rule may need to wait for a new protocol
baseline.

### Removal is a companion design

Admission should not silently define removal. A later proposal might permit a same-account leaf to issue a
Remove-only Commit for one of its sibling leaves. Removing an entire account remains an administrator action.

An identity-wide removal operation is useful only if it adds semantics beyond several leaf removals—for example, an
identity tombstone that prevents a concurrently added sibling from keeping the account represented.

## 2. Pairing and batch group enrollment

Adding a leaf remains a per-group MLS operation. There is no protocol shortcut that places a device in every group at
once. The UX can nevertheless make the work feel like one bounded operation.

### Proposed user flow

1. The user signs in to the same Nostr account on the new device.
2. The new device creates a device-specific synchronization identity and starts a short-lived pairing session.
3. It displays a QR code containing a signed rendezvous descriptor.
4. An existing device scans the code and establishes a mutually authenticated, encrypted channel.
5. The existing device sends a private group catalog and the capabilities required by each group.
6. The user selects active, non-archived groups by default, all groups, or a custom subset.
7. The new device creates a fresh KeyPackage for each selected group.
8. The existing device creates and publishes the per-group Add Commits and transfers the corresponding Welcomes.
9. The new device processes only the Welcomes expected by the pairing manifest.
10. Content bootstrap proceeds independently of MLS enrollment and may overlap it.

The existing device must be online long enough to authenticate the new endpoint, transfer the group catalog and
KeyPackages, and create the Commits. Once a Commit and its `Welcome` have been delivered to the shared transport, the
new device can finish asynchronously.

### QR and pairing descriptor

The QR code should identify a short-lived session, not directly contain a group list or a single KeyPackage. A
conceptual descriptor might include:

- a protocol version;
- an account fingerprint;
- an ephemeral public key;
- a nonce or session identifier;
- rendezvous information;
- an expiry; and
- an account signature over the descriptor.

Group identifiers, KeyPackages, the selected group set, and synchronization material should travel through the
encrypted session. This avoids leaking the user's group graph through the QR code and prevents a fixed-size code from
becoming the batch transport.

### KeyPackage lifecycle

The new device should generate a distinct KeyPackage for each selected group. A failed attempt should consume or
retire that KeyPackage and retry with a fresh one. Published last-resort KeyPackages remain useful for unsolicited
invitations, but a paired enrollment should not need to depend on public relay discovery.

The batch needs durable progress rather than one all-or-nothing transaction. A client should be able to show
completed, pending, failed, and skipped groups; retry individual groups; cancel remaining work; and bound parallel
Commit publication.

Automatic `Welcome` acceptance should be restricted to the active pairing manifest: expected group, expected
KeyPackage reference, expected same-account sponsor, unexpired session, and compatible feature set.

## 3. Inviting an account with multiple devices

Public KeyPackage discovery creates a related but distinct problem. An account may have several valid, unexpired
KeyPackage events with different `d` tags.

The `d` tag should not be interpreted as a physical device identifier. It is an opaque, stable publication-slot
identifier. Multiple slots may belong to one device, an apparently valid slot may belong to a lost device, and a
relay query may return an incomplete view.

### Why "invite every valid KeyPackage" is awkward

MLS can add several KeyPackages in one Commit, and MDK can construct a multi-Add Commit and produce a `Welcome` for
each source KeyPackage. Mechanically, inviting every discovered slot is possible. Semantically, it can cause:

- duplicate leaves for one physical device;
- leaves for lost or abandoned devices;
- group-size inflation or resource exhaustion;
- inconsistent results from incomplete relay discovery; and
- an accidental equation of "unexpired" with "currently authorized."

### Conservative default

The cleaner default is:

1. an inviter selects one compatible KeyPackage using the existing candidate-ranking rules;
2. that leaf accepts the invitation and represents the newly admitted account;
3. the account then uses the same-account Add rule to enroll its other devices.

This separates authorities cleanly: another member admits the account, while the account manages its own device
fleet.

A bounded multi-KeyPackage invitation could remain an optional UX later, but it should depend on an authenticated
device directory or other semantics stronger than distinct `d` tags.

### Device directory

Some minimal account-device directory will likely be useful. It could map a physical device to its public
KeyPackage slots and, privately, to the leaves it owns in each group. It should not redefine the `d` tag as a device
label, and should reveal as little of the account's device graph as possible.

An account-level invitation notice could be visible to every device even when the actual `Welcome` is consumable only
by the owner of the selected KeyPackage. That would improve responsiveness without adding every endpoint preemptively.

## 4. MLS Virtual Clients

The [MLS Virtual Clients draft][virtual-clients] is a useful alternative model, but not a good baseline for Marmot
today.

In that design, physical devices are members of a private emulation group. Together they emulate one virtual leaf in
each higher-level MLS group. A KeyPackage upload protocol allows the emulators to derive the private material for the
same public virtual KeyPackage, so any emulator can process a resulting `Welcome`.

This has real advantages:

- higher-level groups contain one account-shaped leaf rather than one leaf per device;
- adding a physical device can be hidden from other group members;
- device count is not exposed through higher-level MLS membership; and
- the same-account Add authorization exception is unnecessary.

It also introduces substantial costs for a relay-oriented, eventually consistent system:

- every emulator holds the virtual client's secret state for every higher-level group;
- compromise of one emulator compromises the shared virtual client;
- concurrent senders share one sender ratchet and can select the same generation;
- a reuse guard prevents nonce reuse but can make the losing message undecryptable after key deletion;
- safely coordinating sender generations normally expects stronger delivery-service serialization than Nostr
  provides;
- a KeyPackage upload must reach the required emulators before the public KeyPackage is used;
- higher-level messages must be distributed to every emulator;
- adding or removing an emulator still requires state transfer and per-group secret rotation or resynchronization;
  and
- none of this supplies historical application content that MLS no longer retains.

The draft is active, experimental work rather than a settled MLS deployment profile. It is worth tracking if one
leaf per account or device-count privacy becomes a hard requirement. Marmot might also borrow its private
account-device control group without adopting shared virtual-client state in higher-level groups.

## 5. Content synchronization boundaries

Content sync should replicate logical, accepted application data. It should never clone:

- the SQLCipher database;
- OpenMLS group state;
- current or old epoch secrets;
- sender ratchets;
- KeyPackage private keys; or
- unpublished MLS operations.

MDK intentionally uses one database per account-device identity. Copying that database would collapse the security
and lifecycle boundary between devices and would make concurrent use unsafe.

A newly admitted device generally cannot independently revalidate old application messages through MLS after the
relevant epoch secrets have been deleted. It is receiving an authorized account archive. The archive should retain
useful provenance—such as original event identifiers, authors, timestamps, and an attestation by the exporting
device—without pretending that replay is fresh MLS verification.

### Candidate data classes

The sync model should distinguish at least:

**Accepted group history**

- stable message identifiers and accepted plaintext;
- edits, deletions, reactions, and replies;
- media references, encryption material, and provenance;
- relevant application metadata; and
- enough ordering information for deterministic presentation.

**Private account or presentation state**

- read positions;
- archive, mute, and pin state;
- drafts;
- notification preferences; and
- user-assigned device labels.

**Binary objects**

- media and thumbnails;
- draft attachments; and
- encrypted snapshot chunks.

**Live cryptographic state**

- explicitly excluded from content sync.

Users may eventually need policies such as full history, retained history, selected groups, or from-now-on only.

## 6. A layered synchronization design

The proposed layering is:

1. a canonical, typed account-sync record format;
2. narrow deterministic merge rules for each record type;
3. an append-only journal plus periodic encrypted snapshots;
4. versioned sync encryption and device signing keys; and
5. interchangeable carriers for direct, relay, object-store, or peer-to-peer delivery.

This avoids committing the logical data model to P2Panda, Nostr, Blossom, or any one CRDT library.

### Narrow merge semantics

Many fields need CRDT-like behavior, but not a general collaborative-document model. Example starting points are:

| State | Candidate merge rule |
| --- | --- |
| Accepted message | Set union by stable message identifier |
| Edit | Latest authenticated logical revision using deterministic ordering |
| Delete | Tombstone wins over retained content |
| Reaction | Add/remove operation scoped by author and reaction |
| Read position | Monotonic high-water mark where the timeline permits it |
| Archived or muted | Last-writer-wins register |
| Draft | Last-writer-wins or multi-value register |
| Pin ordering | Explicit ordering merge, or device-local in the first version |

The exact rules need adversarial treatment of clocks, replay, duplicate records, malicious same-account devices, and
late arrival. "Last writer" cannot simply mean an untrusted wall-clock timestamp.

### Sync keys and device authority

Content should be encrypted under random, versioned account-sync keys rather than directly under the long-term Nostr
account key. Each device should also have a synchronization signing identity authorized by the account-device
control plane.

Removing a device can rotate the key for future records and checkpoints. It cannot revoke content the removed device
has already downloaded. Adding a device requires an explicit policy for which historical key versions it receives.

## 7. Transport and implementation options

### Direct pairing transfer

The devices exchange an encrypted snapshot and journal tail over the pairing channel.

This is the best first milestone: private, fast, and simple, with immediate progress feedback. It requires both
devices to overlap online and does not by itself provide ongoing sync or disaster recovery.

### Encrypted Nostr journal

Devices publish typed, encrypted synchronization records or batches through the existing relay stack.

This supports asynchronous operation and reuses deployed transport. Its weaknesses are relay retention,
completeness, event-size limits, metadata leakage, weak deletion, and the need for gap detection and compaction.
Nostr is a plausible delta carrier, not a complete backup promise.

### Private account-device MLS group

An MLS group containing the account's devices could carry device authorization, sync-key distribution, manifests,
and small control records.

It is attractive as a control plane, but it is not a historical archive on its own. A new device still needs a
checkpoint or an online peer, and device-group convergence must not become a prerequisite for every higher-level
message.

### Encrypted Blossom checkpoints

A device uploads a compressed, chunked, encrypted snapshot and publishes a signed, encrypted manifest that identifies
the chunks and journal position.

This is well suited to bootstrap and backup, less suited to live conflict resolution. The stronger composition is
"checkpoint on Blossom, deltas elsewhere," with explicit retention, garbage collection, and re-upload behavior.

### Custom append-only journal

A narrow Marmot journal can encode only the application operations that actually need synchronization. This keeps
authorization and merge behavior reviewable and avoids importing a general-purpose document model.

The journal is useful regardless of carrier and is the current recommended logical foundation.

### General CRDT library

Automerge, Yjs, or a similar library could provide mature merging for genuinely collaborative structures such as
drafts. Applying one to all message and account state may add large metadata, dependency, migration, and security
costs without removing the need to define authorization.

A selective use is more promising than making a general CRDT document the entire archive.

### P2Panda

[P2Panda][p2panda] is interesting because its signed append-only logs, causal operation model, persistence, and
synchronization protocols align closely with the journal layer described above. It could provide more principled
replication than a collection of ad hoc encrypted Nostr events.

It should initially be treated as an implementation experiment, not as Marmot's canonical content format. Questions
to validate include:

- mobile and UniFFI integration cost;
- storage and compaction behavior for long-lived accounts;
- encryption and authorization boundaries;
- offline and partially replicated behavior;
- compatibility with Nostr and Blossom as available transports;
- dependency and protocol stability before 1.0; and
- whether operating another networking and replication stack is justified.

A useful prototype would encode the same proposed `AccountSyncRecord` schema in a P2Panda log and exercise direct
pairing, two offline writers, deletion, snapshot bootstrap, device removal, and long-history compaction. If the
prototype fails, the logical format should remain usable by another carrier.

### Dedicated synchronization service

A simple encrypted mailbox service could provide reliable cursors, retention, and availability while remaining
unable to read content. It creates centralized operations, metadata, and dependency concerns, but may be a pragmatic
optional carrier.

### User-owned cloud storage

WebDAV, S3-compatible storage, iCloud, or Drive could support optional backup and restore. Provider-specific storage
is unlikely to be a good interoperable baseline or a complete live-sync system.

## 8. Suggested incremental path

### Phase 1: pairing and enrollment

- specify the same-account Add authorization rule and capability negotiation;
- define the pairing descriptor and encrypted session;
- implement per-group KeyPackage generation and durable batch enrollment;
- specify same-account per-group removal; and
- preserve exact per-group publication, Welcome, join, and failure evidence.

### Optional companion: direct history bootstrap

- define a typed snapshot envelope without making it a multi-device interoperability requirement;
- transfer only accepted, locally retained history over the authenticated pairing channel;
- preserve provenance while excluding all live MLS state; and
- allow implementations to omit this companion without blocking enrollment or future messaging.

### Phase 2: asynchronous continuity

- carry encrypted deltas over Nostr or an account-device control group;
- add encrypted Blossom checkpoints and manifests;
- implement gap detection, compaction, retention, and key rotation; and
- define device removal and recovery behavior.

### Parallel experiment: P2Panda

- use the same logical record schema;
- compare correctness, mobile cost, storage growth, and operational complexity;
- test eventual convergence under realistic relay and offline schedules; and
- keep adoption contingent on evidence from the prototype.

## 9. Things to avoid

- copying the SQLite or SQLCipher database between devices;
- sharing OpenMLS state or sender ratchets;
- transferring old epoch secrets as a history mechanism;
- treating relay replay as a complete archive;
- treating an unexpired KeyPackage as proof of an active physical device;
- deriving device identity from the public KeyPackage `d` tag;
- using Blossom as the only copy of live state;
- encrypting the archive solely to the long-term Nostr account key; and
- letting synchronized application records override canonical current MLS group state.

## 10. Open questions

- What history scope is offered by default: all retained, active groups, selected groups, or from-now-on?
- What exact proof binds an MLS credential and a device synchronization key to the same Nostr account?
- How is the same-account Add feature negotiated and introduced into existing groups?
- What limits apply to leaves per account, additions per Commit, and pairing batch size?
- Can a sibling remove another leaf, and how is account-wide removal made race-safe?
- What is the smallest useful private device directory?
- Should third-party invitation ever add more than one discovered KeyPackage?
- Which private presentation fields synchronize, and which remain device-local?
- What are the deterministic merge rules for edits, tombstones, drafts, pins, and read state?
- How is an exported archive attested, and what trust claims does the receiving device show?
- Which historical sync keys does a newly authorized or recovered device receive?
- How are media retention, cache eviction, and missing encrypted objects represented?
- What is the availability promise when no existing device is online?
- How are snapshots compacted, garbage-collected, and recovered after partial upload?
- Does P2Panda remove enough custom machinery to justify its integration and maturity risk?
- Which parts of this design belong in the Marmot protocol versus MDK-local account orchestration?

## References

- [RFC 9420: The Messaging Layer Security Protocol][rfc9420]
- [MLS Virtual Clients, draft-ietf-mls-virtual-clients-01][virtual-clients]
- [P2Panda][p2panda]
- [MDK SQLite storage architecture](../crates/storage-sqlite/README.md)

[p2panda]: https://p2panda.org/
[rfc9420]: https://www.rfc-editor.org/rfc/rfc9420
[virtual-clients]: https://www.ietf.org/archive/id/draft-ietf-mls-virtual-clients-01.html
