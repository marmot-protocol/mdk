# marmot-uniffi

UniFFI bindings for the Marmot app runtime.

The Rust API in `src/` is the source of truth for both generated Swift and generated Kotlin. Platform scripts only
package that shared surface:

- `./crates/marmot-uniffi/xcframework.sh` builds `output/MarmotKit.xcframework` plus `output/MarmotKit.swift` and
  `output/PrivacyInfo.xcprivacy` for iOS.
- `./crates/marmot-uniffi/xcframework-macos.sh` builds `output/macos/MarmotKit.xcframework` plus
  `output/macos/MarmotKit.swift` and `output/macos/PrivacyInfo.xcprivacy` for macOS on Apple Silicon
  (`aarch64-apple-darwin`). Its output directory is separate from the iOS one so building both in one workspace
  cannot clobber either artifact.
- `./crates/marmot-uniffi/kotlin-bindings.sh` builds `output/android/kotlin/.../marmot_uniffi.kt` plus Android
  `jniLibs` shared libraries.

The generated Swift file is platform-independent: `output/MarmotKit.swift` and `output/macos/MarmotKit.swift` are the
same UniFFI surface, and releases publish it once.

`MarkdownBlockFfi` now includes an additive `Details` variant for bounded
`<details>` / `<summary>` display blocks. Hosts must regenerate Swift/Kotlin
bindings to handle the new tag; older generated sources cannot render it.
No generated Swift or Kotlin files are committed here.

## Deletion provenance and custom events

Timeline records (including conversation windows and `reportedMessage`), reply previews,
and chat-list previews expose `deletionSource: DeletionSourceFfi`:

- `Author`: the selected accepted deletion is an author-authorized kind 5.
- `Admin`: the selected accepted deletion is kind 4891, authorized by authenticated
  source-state evidence. This includes an admin removing their own message.
- `Unknown`: no classified deletion evidence is available, including older projected tombstones
  and legacy kind-5 removals of another author's content.

Consult this field only when `deleted` is true. Use the existing ordinary-deletion wording
for `Author`, “This message was deleted by an admin.” for `Admin`, and a neutral deleted-message
fallback for `Unknown`. Clients own localization. The message's `kind` remains its original
inner event kind, never the deletion kind. Existing deletion IDs and content masking are retained.
`invalidationStatus` describes convergence separately and does not imply deletion.

See [deletion semantics](../../docs/marmot-architecture/overview/content-moderation.md)
for the storage and authorization contract.

When multiple accepted deletions apply, the largest `(authenticated event timestamp, event ID)`
pair wins, matching `deletedByMessageIdHex`. Arrival order, reports, and current admin status
play no part. Invalidated deletion evidence is withdrawn; projections update to the remaining
winner (or restore the undeleted state). Provenance-only changes participate in live projection
and conversion-cache updates.

Database migration 0082 adds provenance columns with an `unknown` default.
It preserves older tombstones, deletion IDs, and cached chat presentation without scanning or
reinterpreting history. No historical backfill is scheduled: existing tombstones can remain `Unknown` indefinitely.
If a later operation reprojects a target or rebuilds its group, it uses available accepted evidence.
Legacy serialized records with an absent field also default to `Unknown`. No client database
migration or deletion index is needed. Regenerate Swift/Kotlin bindings and consume the matching
native libraries together; C consumers must rebuild against the updated header and library.
Older MDK binaries reject the upgraded database schema; do not roll back only the library.
This is a binding layout change, not an MLS/wire-format change.

Custom events retain their numeric `kind` and verbatim `plaintext` content. Conversation windows
now also carry their ordered `tags`, so clients can render app-defined event types without fetching
raw events. Deleted rows expose no raw tags in timeline reads, moderation reads, or conversation windows. MDK-owned kinds continue
to use prepared fields and references there. Custom-event tag changes invalidate the conversion
cache. This does not change custom-event chat-list activity or notification policy.

## Group-system previews

`ChatListMessagePreviewFfi.groupSystem` and timeline `groupSystem` now carry
`GroupSystemEventProvenanceFfi`. MDK verifies local synthesis against the exact
stored row and payload. The optional commit link is for rollback invalidation;
self-removal and reorg-derived rows remain authenticated without it.
Render authenticated membership/admin changes
only for `AuthenticatedGroupState`; `MemberAuthored` is an assertion and carries
no trusted actor/subject IDs on projected records. Malformed, oversized and deleted
payloads have no typed event. Provenance records origin; timeline invalidation
status still applies. Raw plaintext remains available to narrow consumers.

Chat previews include separate actor/subject IDs and MDK-prepared display names
from local caches, with the same safe-name/pseudonym fallback used by conversation
identities. Subject profile updates refresh live chat lists without changing message
identity or activity order. Clients own localized wording and the viewer's “you” label.
Conversation windows continue to supply their bounded identity dictionary.
This adds no wire format or database migration. Regenerate Swift/Kotlin bindings
and use the matching native library; Android follow-through is tracked in
[whitenoise-android#1581](https://github.com/marmot-protocol/whitenoise-android/issues/1581).

### Reactions on group activity

Use the existing reaction commands with the activity row's `messageIdHex`.
Authenticated system rows retain that deterministic ID across reaction changes,
replay and restart; the same timeline record exposes both `groupSystem` and
`reactions`. Retraction uses the existing unreact command, and subscriptions
update the target row without adding a second activity row. Do not synthesize or
send a kind-1210 event to react to local group activity.

Reaction notifications use the supported system payload's text fallback, never
its JSON envelope. Only the stored target sender receives an alert; activity
without an attributable actor does not invent a recipient. Deleted or invalidated
targets and malformed or unsupported payloads expose no target preview.
For synthesized system rows, `reactedToPreview` is an English fallback. The
notification DTO has neither the target ID nor a structured system event, so this
field cannot support client localization; hosts can omit it and use their generic
localized reaction notification. Conversation rows still expose `groupSystem` for
client-localized rendering and layout. This adds no binding fields or methods and
requires no client-owned reaction map.

## Identity references and profile pseudonyms

`accountIdHex` / `normalizeMemberRef` now accept `nprofile` and
`nostr:nprofile` mentions and QR scans in addition to hex, `npub`,
`nostr:npub`, and `marmot://profile/` links. Relay hints inside an
nprofile are discarded and never used for routing or directory mutation.
Duplicate type-0 TLV entries keep the first key. After FFI wrapper
normalization, the nprofile fallback rejects encoded tokens longer than
1023 UTF-8 bytes (the locked Bech32/Bech32m ceiling); a valid 1023-byte
token still decodes when wrapped in `nostr:` or `marmot://profile/...`.
The app helper strips one lowercase `nostr:` prefix itself; profile-link
and whitespace normalization belong to FFI. The app helper's legacy NIP-21
parser may still accept a colon-suffixed `nostr:<npub>:` form before the
fallback runs; FFI normalization rejects that form. Decode a scanned reference
first, then pass
the canonical lowercase hex account id to `defaultProfilePseudonym` so
the shared text-hash seed is preserved. Passing uppercase hex or an undecoded
`npub` silently produces a different name, not an error. `randomProfilePseudonym`
replaces client-owned random-roll wordlists; it is cosmetic, may
collide, and does not create an account.

`accountKeyPackages` lists the current KeyPackage winner per addressable slot
plus local-only rows. `accountKeyPackageRelayEvents` is the additive observed
history for that same fetch window: current and superseded kind-30443 events,
with `isCurrent` set only among those observed valid events. Hosts can pass a
superseded `eventIdHex` and its `sourceRelays` to the existing delete API.
This does not change the Published-list filter (`relay == true`) and does not
replace Android history UI work.

`localAccountKeyPackages` is the local-first inventory: render it immediately.
It is a synchronous SQLCipher read on the calling thread; do not invoke it on a
UI or main thread. `refreshAccountKeyPackages` is the explicit network merge;
replace the displayed snapshot with its result. On refresh failure or
cancellation, keep the local result. Both return
`AccountKeyPackageInventoryEntryFfi` (`record` plus `localState`). Existing
`AccountKeyPackageFfi` is unchanged. `localState` and `record.relay` are the
authoritative display distinctions; empty event IDs and `publishedAt` are not
publication proof. A retained package stays `RetainedPrivateMaterial` even when
that exact event is observed; `record.relay` becomes true while `localState`
remains retained. Empty bootstrap relays remain network-enabled. After a
mutation, re-read the local inventory instead of applying an out-of-order
refresh.

Regenerate Swift/Kotlin bindings after pulling this surface. Hosts must use a
matching library: the new methods and enum are additive, but older generated
sources cannot call them. Android device rendering remains a separate consumer
adoption issue.

Android mention/QR/edit-profile migration remains
[whitenoise-android#1584](https://github.com/marmot-protocol/whitenoise-android/issues/1584);
MDK completion enables that follow-through but does not replace it.

See [`DISTRIBUTION.md`](DISTRIBUTION.md) for immutable Apple and Android artifacts, exact release and snapshot URLs,
checksums, provenance, and generated-source synchronization rules.

The Kotlin binding is generated from the same release host library metadata as Swift, so it exposes the same `Marmot`
object, subscription objects, records, enums, and error variants.

## Audit v4 adoption

Audit uploads now accept only `marmot-forensics-audit/v4`; old local files are never migrated or sent.
App construction automatically removes recognized v1-v3 forensic files and rotated segments after acquiring the
root lease, including files in failed account-wipe remnants, even with recording disabled. V4 files and the separate
key-reveal log are preserved; failures are nonfatal and retried on the next open. No additional Swift/Kotlin cleanup
call is needed.
Regenerate Swift/Kotlin bindings and use `AuditLogTrackerConfigV4Ffi` with
`AuditLogUploadSourceV4Ffi.hardwareModel` in place of the old source record and its `deviceLabel`.
The versioned config type changes the setter ABI checksum so old generated bindings cannot silently
reinterpret a device label as a hardware model.
Populate this field from system model information (e.g. `iPhone17,3` or `Pixel 9a`), never from a device name,
hostname or serial number. Omit it if unavailable. Platform and app version are unchanged.
Deploy a v4-compatible Goggles endpoint before expecting successful uploads from these bindings.
Native metadata lift/lower checks: `./crates/marmot-uniffi/audit-v4-smoke.sh swift` and
`MDK_KOTLIN_CLASSPATH=<JNA:Android:annotations:coroutines jars> ./crates/marmot-uniffi/audit-v4-smoke.sh kotlin`.
These regenerate host bindings and execute DTO round trips; platform package builds remain separate.

## Exclusive Root Ownership

Every `Marmot` constructor acquires a nonblocking exclusive lease on
`.marmot-runtime.lock` in `rootPath`. The lease prevents the foreground app and
an independently launched notification service extension from hydrating and
writing the same Marmot state at the same time. The lock is owned by an open
file descriptor, so the kernel releases it if iOS terminates the process; the
lock file itself is stable and must not be deleted.

When another process or runtime owns the root, construction throws the typed
Swift error `MarmotKitError.RuntimeBusy`. An NSE should take its bounded
fallback path, while a foreground app can retry after the current owner exits.
Calling `shutdown()` stops runtime work but intentionally does not release the
lease while the `Marmot` object or one of its runtime handles is still alive.
Release the final object reference before constructing a replacement.

## Service Endpoint Defaults

`marmotkit-endpoints.env` sets the public build-time defaults consumed by Marmot's compiled endpoint config:

- `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT`
- `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT`

These are route URLs only. Host apps still supply audit and telemetry bearer tokens at runtime. Set either environment
variable before invoking a build script to override the default for staging or local testing.

Public profile-image uploads default to `https://blossom.primal.net`. Rust
hosts can override or disable that third-party service with
`MarmotServiceEndpoints::profile_image_blob_endpoint`; FFI callers can continue
to pass an explicit Blossom server to `uploadProfileImage`.

## Kotlin / Android

Prerequisites:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
# macOS Android Studio default:
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/<version>"
# Linux / common CI default:
# export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/<version>"
```

CI jobs can also set `ANDROID_SDK_ROOT` or `ANDROID_HOME`; the build script will discover the newest NDK under
`$ANDROID_SDK_ROOT/ndk` or `$ANDROID_HOME/ndk` when `ANDROID_NDK_HOME` is not set.

Build all Android ABIs:

```sh
./crates/marmot-uniffi/kotlin-bindings.sh
```

The script keeps the host library's UniFFI metadata intact while stripping
debug and static symbol sections from each packaged Android JNI library.

To build a subset:

```sh
ANDROID_ABIS="arm64-v8a x86_64" ./crates/marmot-uniffi/kotlin-bindings.sh
```

Generated Kotlin uses package `dev.ipf.marmotkit`, loads `libmarmot_uniffi.so`, and requires the normal
UniFFI Kotlin runtime dependencies used by the generated file: JNA, Kotlin coroutines, and AndroidX annotations.

### Android initialization (required before the first `Marmot(...)`)

`Marmot(...)` constructs the Android-native keyring store, which talks to the Android Keystore over JNI and needs the
`ndk-context` initialized with the application `Context` first. The build copies two hand-written helpers
(`kotlin-support/`) next to the generated binding:

- `dev.ipf.marmotkit.MarmotAndroid` — the call consumers use.
- `io.crates.keyring.Keyring` — the JNI shim the `android-native-keyring-store` crate requires (statically linked into
  `libmarmot_uniffi.so`, so its symbol is exported from that library).

Android consumers MUST call `MarmotAndroid.initialize(this)` from `Application.onCreate` before constructing `Marmot`,
otherwise the first constructor crashes with `android context was not initialized`:

```kotlin
class MarmotApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        MarmotAndroid.initialize(this)
    }
}
```

iOS does not need this — `apple-native-keyring-store` uses Keychain APIs that do not require a `JavaVM`. If the host
framework already initialized `ndk-context`, do not call `initialize` again.

The output directories are ignored because generated bindings and packaged native libraries are derived artifacts.
Regenerate them from this crate before vendoring into an app repository.

See [`AGENTS.md`](AGENTS.md) for scope, invariants, and verification commands.

## Interactive account onboarding

Imported identities can use the durable preflight API instead of `login`:

1. Call `begin_onboarding(nsec, options)` or
   `begin_external_signer_onboarding(public_key, signer, options)`. Supply the
   same `default_relays` as new-account creation and a separate set of trusted
   `discovery_relays`. These methods return a persisted account and snapshot
   before fetching or publishing Nostr records.
2. Display the snapshot steps in their returned order (profile, follows, general
   relays, inbox relays, single-device notice, KeyPackage). Use step identities,
   not enum discriminants, as positions. Subscribe with `subscribe_onboarding`, read its initial
   `snapshot`, and drive `next` concurrently with `run_onboarding`.
3. Localize the typed status, findings, and actions. A healthy account advances
   automatically until the single-device acknowledgment. `NeedsInput` offers a repair or, for profile/follows, an
   explicit `continue_onboarding_without`. Empty follow lists are valid.
4. `propose_onboarding_recommended_relays`, `propose_onboarding_relays`,
   `propose_onboarding_profile`, and `propose_onboarding_follows` only prepare
   a proposal. Profile fields left unset preserve their current values; an
   explicit empty string clears a field. Display the proposed edits, then pass the returned
   snapshot revision to `approve_onboarding_repair`. For an inbox proposal use
   `read_relays` and an empty `write_relays`. `cancel_onboarding_repair` dismisses
   a proposal until approval has been recorded.
5. `retry_onboarding_step` requires an offered `Retry` action; `set_onboarding_discovery_relays`
   retries with explicitly chosen discovery sources without publishing them.
   After process restart, read `onboarding_snapshot`, register the external
   signer again if applicable, and run/resume or retry the indicated step.
6. Enter the normal app only when `snapshot.ready` is true. Normal worker
   commands reject unfinished onboarding; the workflow alone can publish its
   initial KeyPackage. `account_setup_readiness` stays `Initializing` until the
   interactive workflow is complete.

#### Explicit recovery and checkpoint compatibility

When `begin_*_onboarding` or cancellation returns `OnboardingActionUnavailable`,
query `onboarding_recovery_required(account_ref)`. A true result means an
unreadable/unsupported checkpoint, an exhausted revision counter, or an
interrupted recovery needs attention. Invalidate the old UI attempt and obtain
the user's acknowledgment of latest-only evidence retention, then call
`recover_onboarding(account_ref, true)`. It supports local and external-signer
accounts and does not wait for the signer or publish any repair.

Recovery durably records the exact opaque active/cancelled bytes in the private
`onboarding-recovery.json` before replacing their gates. It preserves identity,
credentials, setup journals/context and unrelated account data, signs out,
reaps the worker and establishes a random 256-bit approval epoch. Unknown
counters are never interpreted as zero within their old epoch. A later explicit
begin starts with fresh checks and no inherited proposal, approval, or signed
repair. The new epoch is returned by recovery and included in future snapshots;
use the epoch-aware approval and device-acknowledgment methods described below.

An interrupted recovery remains gated and resumes through retry or reconcile;
dropping its caller cannot detach a removed worker. The latest recovery journal
is readable through `AccountHome::account_onboarding_recovery`; an unreadable
previous recovery journal is retained as opaque evidence there. A subsequent
explicit recovery may replace older evidence. Keep any evidence needing longer
retention outside this latest-only workflow before acknowledging recovery.

Ordinary checkpoints remain version 3, with supported version 1/2 upgrades.
Version 3 is a semantic barrier: old version 2 code rejects approved cancellation
and cannot safely restart it. Recovery checkpoints use version 4 because a
version 3 reader cannot validate epoch-scoped approvals. Completed recovery
leaves a version 4 cancellation tombstone even before a new begin, so older
readers fail closed. Downgrading during recovery is unsupported; finish recovery
with an epoch-aware build. Do not relabel versions or delete checkpoints to
force a downgrade. Restore/upgrade to a supporting build, or explicitly recover
unsupported evidence with this API.

Persisted generation/pending state supplies durable admission checks after
restart; the retirement watch only supplies prompt wake-up for this runtime.
They are not interchangeable, so this change does not introduce watch-only
caching or prune retirement senders. Test holds remain test-only and retain
explicit interleaving coverage.

The `SingleDevice` step always pauses before initial KeyPackage publication.
Display a general notice that White Noise does not yet support synchronized
multi-device use and recommends one device. The snapshot's `single_device_notice`
adds evidence with `OtherInstallationPossible`, `NoneFound`, or `Unknown` discovery.
When another installation is possible, explain that invitations may reach only
one installation and conversations will not automatically appear on both.
Reinstallation or cleared local state can produce the same evidence; do not
claim to have identified a physical device or a particular app.

Offer **Cancel** and **Continue anyway**. For Cancel, invalidate the current UI
attempt first, then await `cancel_onboarding(account_ref)` before any new
`begin_*_onboarding`. Cancellation is legal at every interactive step, including
an approved but unconfirmed repair and a ready checkpoint that the host has not
yet opened with Open Chats. Success signs the identity out, reaps its worker,
delivers a terminal non-ready snapshot, and closes that subscription. It retains
local data, credentials, setup journals, and the latest cancellation checkpoint,
including its signed publication evidence. A subsequent cancellation replaces
`onboarding-cancelled.json` even if the earlier publication is still uncertain.
This is a latest-only retention limit, not proof of remote reconciliation.
Previously written content-addressed archives are left untouched; new
cancellations do not create them. It does not delete, replace, or prove non-publication of
events that may already be on relays. A later explicit interactive begin starts
a new attempt with the supplied options and no old proposal, approval, or
signed repair; observing a previously published record is not replay permission.
Legacy `login` remains available and does not consume archived onboarding
choices. Reconcile, runtime start, signer attachment, and connectivity
restoration are not explicit sign-in. If the call returns
`AccountWorkerResponseTimedOut`, the pending fence remains and the host should
retry the same cancel; dropping the waiter does not abort cleanup. Do not treat
`ready` as an Open Chats command — the host still owns that transition.
For Continue anyway, call `acknowledge_onboarding_single_device(account_ref, snapshot.revision)`.
If `snapshot.recovery_epoch` is present, use
`acknowledge_onboarding_single_device_in_epoch(account_ref, snapshot.revision, epoch)`
and `approve_onboarding_repair_in_epoch(account_ref, snapshot.revision, epoch)`
for approvals. Pass the epoch from the same displayed snapshot. The original
revision-only methods reject recovered attempts, even when the number matches.
MDK rejects a stale revision, persists the acknowledgment, and resumes setup.
The acknowledgment survives KeyPackage publication failure, task interruption,
and restart. Rechecking an earlier prerequisite, changing discovery sources,
approving another repair, explicitly retrying `SingleDevice`, or signing in again
after signing out a completed account invalidates it and requires a fresh notice.
Retries preserve optional steps the user skipped unless that skipped step is the
explicit retry target. Older checkpoints refresh their derived retry hints on
read, and package records without a `usable` field default to `false`.

Detection reads verified kind-30443 records through the validated relay routes
without starting an account worker. It compares the newest record per slot with
the local stable slot and durably owned private packages, including retained
rotation material. `other_packages` retains signed foreign-slot evidence even
when the payload is malformed or expired. `usable` describes package validity;
the reference and expiration are optional when validation cannot extract them.
The publication timestamp comes from the verified event. No recency cutoff
excludes a foreign slot:
republication retains the original event timestamp, so it is not last-active time.
No public device identifier is introduced, and continuing never deletes another
installation's packages.

`discovery_complete` describes only the bounded queries to the selected sources;
it is false for failed, malformed, future-dated, or potentially truncated results.
Positive evidence can accompany incomplete discovery. `Unknown` means discovery
was inconclusive; `NoneFound` means none were found on those sources. Neither is
an assurance that multi-device use is safe. Both still require the general notice.
Completed pre-notice checkpoints remain ready; incomplete checkpoints acquire
the notice before KeyPackage publication when upgraded.

Snapshots are complete states, not deltas. A slow subscriber may miss
intermediate states but receives the latest persisted state. Interrupting an
async check can leave a step `Checking`; `run_onboarding` resumes it. Once a repair is approved,
a retry resumes that repair before other checks. It cannot be cancelled as if
nothing had been published: a relay may already have accepted it. Signed bytes
are retained before the first send and replayed unchanged on retry.

Discovery reads require a completed relay query. Failed/partial empty discovery
is distinct from absence and never offers automatic replacement. A valid record
from a partially successful lookup may pass while retaining `DiscoveryIncomplete`
and source failures in its findings; a passed step is not necessarily warning-free.
Off-filter records are ignored. Single-device discovery remains incomplete if
any selected source fails, even when another source returns an empty result. Fresh signed
records remain available for inspection even when their contents are malformed;
a newer malformed record does not silently fall back to an older valid one.
Repairs re-fetch the source before signing and reject a changed record. Nostr
has no conditional replace operation, so simultaneous edits after this check
remain subject to its normal replaceable-event ordering.

Relay checks include syntax, local safety/retirement policy, read/write roles,
and bounded queries through the relevant routes. Inbox queries filter for the
account's recipient tag and use an isolated account-bound signer. They retain no
inbox payloads. Read permission and KeyPackage publication are checked separately;
these checks do not guarantee future availability or every relay's acceptance of
future third-party inbox messages. Incomplete workflows recheck reachability
older than five minutes. Completed onboarding is retained and reruns when a
signed-out account enters the identity-only flow again.

The existing `login` and generated-account APIs remain compatible. Apps must
adopt the new identity-only APIs and screen to enable this experience. Legacy
accounts without an onboarding checkpoint are not retroactively blocked. Active
legacy accounts and accounts with unfinished legacy setup are not silently
enrolled: finish or resume their existing setup first. Signed-out legacy accounts
without pending setup can explicitly opt in. Completed checkpoints defer to normal
setup/recovery readiness. Corrupt or newer-version checkpoints gate only their own
account; they must be restored or opened with a compatible runtime, not silently
discarded because they may contain approved publication intent. C
consumers have equivalent methods and subscriptions; external-signer entry
points retain the C API's existing callback-vtable limitation.

## Live timeline updates

`TimelineMessagesSubscription::next()` returns the complete bounded window on
every update. Its conversion cache avoids reparsing unchanged rows, but those
rows still get cloned and serialized across FFI. `next_update()` returns raw
projection deltas, or a replacement `Page` after a refresh. These methods consume
the same stream; use only one per subscription. Delta consumers must maintain
ordering, removals, and window limits themselves; raw projections do not report
which rows the runtime evicted from its bounded window.

Projection `messages` and upsert `changes` retain their existing wire format.
When corresponding source records are identical, conversion now parses Markdown
and resolves media once, then clones the converted record for the second field.
Different records and removals retain independent conversion.

Run the conversion and wire-serialization benchmark with:

```sh
cargo test -p marmot-uniffi --release --lib bench_live_timeline_updates -- --ignored --nocapture
```

It compares cached full pages, current deltas, and the original independent
conversion of both delta fields. Each window has 25, 100, or 500 rows and one
edited Markdown message per update. Results include source cloning, conversion,
and UniFFI serialization: p50/p95 over 100 samples after 10 warm-up iterations,
plus serialized byte counts. They exclude storage, runtime window application,
FFI scheduling, and Swift/Kotlin decoding and rendering.

## Selected chat-list presentation

`openPresentedChatList(accountRef, includeArchived)` returns an account-bound subscription.
Take `snapshot()` once (generation plus sequence zero), then consume `next()` as complete replacement snapshots.
Each row contains the existing chat-list fields and MDK's selected title/avatar; hosts render the typed fallback text
with their own localization and load the selected avatar descriptor without a roster/profile lookup.
`presentedChatList` and `presentedChatListRow` provide the same local contract for one-shot and creation/rebind paths.

First use can await bounded local preparation. `ChatPresentationNotReady` means preparation did not advance and may be
retried after maintenance; it is not an empty list or missing group. Storage errors remain errors. Ready reads do no
network fetching or repair writes. Selected values survive offline reopen; avatar bytes still use the existing loaders.

Order updates by the handle's generation and sequence. `presentationVersion` only versions selected presentation:
an unread, pin, archive or mute update can have the same presentation revision. Drop the old handle when changing
accounts; cancellation preserves a pending refresh, and shutdown ends the stream. Account-store replacement requires
opening a new handle. Do not log rows or avatar material, including generated host-language record stringification.
Existing chat-list APIs remain available during client migration. Android/iOS adoption is a separate delivery step.

## Bounded chat screens

C4 adds live Chats/Unread/Archived/Left windows and independent account attention.
See the [native handoff contract](../../docs/marmot-architecture/further-context/chat-projections-native.md)
for paging, sequence handling, cancellation, C ownership, and compatibility.

## Prepared conversation windows

The additive C5 screen API combines history, header/capabilities, visible identities,
read state and revisioned draft descriptors. See the [native conversation contract](CONVERSATION-WINDOW.md)
for opening, paging, cancellation, timeout, ownership and draft migration.

## Apple privacy resources

Apple exporters use raw static-library slices and publish a matching privacy manifest for the consuming Swift target. See the
[privacy audit and adoption guide](apple-privacy/README.md) for declarations,
archive validation, host integration changes, and unresolved release questions.

## Group reporting

Swift/Kotlin expose `report_message`, `dismiss_reports`, `content_reports`,
`report_dismissals`, and `reported_message`; the C ABI mirrors these operations.
`ReportReasonFfi` supplies the NIP-56 categories. Timeline records carry
`has_reports`. Individual report records carry reporter, target author, category,
explanation and `dismissed`; each admin label carries its own event ID, admin,
explanation and timestamp. No aggregate queue, count, status, revision argument,
or winning review decision is imposed on hosts.

Pages are capped at 100 and cursors are exclusive. C callers deep-free returned
pages with `marmot_content_report_page_free` or `marmot_report_dismissal_page_free`.
`reported_message` uses the ordinary timeline record and its free function.
Use existing projection subscriptions to refresh client review views.

## Durable avatar access

Chat rows and conversation header/identity records now include `avatarAsset` metadata. For visible content, batch its
opaque `target` values into `requestAvatarAssets`, then pass returned `reference` values to `readAvatarAssets`. Both
accept at most 16 items; byte reads additionally require a 1-byte to 16-MiB aggregate budget. A `deferred` result means
that complete image did not fit the remaining budget. Ready/stale images can render offline; decode and render on the
host, caching decoded images by reference plus content revision. Screen subscriptions update metadata when acquisition
completes. `clearAvatarCache` clears durable bytes and demand; later visible requests can acquire again.

Use matching regenerated Swift/Kotlin and native libraries. Keep host persistent caches until migration and device
validation are complete. See [the avatar contract](../../docs/marmot-architecture/further-context/avatar-cache-storage.md)
for source/account fencing, result states and lifecycle rules.
