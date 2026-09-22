# marmot-uniffi

UniFFI bindings for the Marmot app runtime.

Host-controlled automatic downloads use the [host-managed attachment contract](ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104), including Android WorkManager migration.

## Integration guide and API reference

This is the current integration entry point for Swift/iOS, Swift/macOS and Kotlin/Android.
The stateless `verifyPublicNostrEventJson` helper verifies public events through
MDK's Nostr/libsecp256k1 stack without constructing an account or supplying a
secret key. It checks both the canonical event ID and signature. A host must
still enforce its own allowed authors, kinds, tags, and input-size limits.
Malformed input and invalid signatures return `false`; it does not authenticate
an MLS group message or replace MDK's relay ingestion checks.
The [C guide](../marmot-c/README.md) adds ABI ownership and blocking-call rules for C and raw FFI hosts.
Read the documentation at the tag matching your binaries; `master` can describe unreleased APIs.

| Document | Use it for |
| --- | --- |
| [Complete method reference](API-REFERENCE.md) | Every exported constructor, runtime method, object method, free function and host callback, with signatures, purpose, source and API-selection guidance. |
| [0.10.2 integration guide](../../docs/integration/0.10.2.md) | Detailed upgrade from 0.10.1: required changes, changed defaults, optional adoption, examples and acceptance checks. |
| [Release integration index](../../docs/integration/README.md) | Find the companion guide for your upgrade; read intervening guides when skipping versions. |
| [Distribution](DISTRIBUTION.md) | Exact artifact layout, platform setup, checksums, Apple resources and source/binary pairing. |
| [Chat lists](../../docs/marmot-architecture/further-context/chat-projections-native.md) | Bounded list windows, account attention, navigation and sequence handling. |
| [Chat-list rows](CHAT-LIST-ROWS.md) | Selected previews, per-message expiry handling, live draft updates and row-action availability. |
| [Conversation windows](CONVERSATION-WINDOW.md) | Initial unread/latest positioning, live snapshots, paging, drafts and cancellation. |
| [Durable local sends](LOCAL-SENDS.md) | 0.10.4 early acceptance, exact optimistic-bubble correlation and retry semantics. |
| [Polls](POLLS.md) | Encrypted NIP-88 creation, replacement votes, bounded validation and deterministic timeline results. |
| [Attachment history](ATTACHMENT-HISTORY.md) / [attachment access](ATTACHMENT-ACCESS.md) | Media discovery, local bytes, acquisition, progress, policy and ownership. |

### What MDK owns and what the host owns

MDK owns account storage, cryptographic state, relay work, durable chat presentation,
message interpretation, read state, drafts, avatar bytes and retained attachment acquisition.
A screen projection is a coherent local view, not a request to fetch every profile or
message individually. Background work updates those projections as new information arrives.

The host owns navigation, localization, accessibility, layout, visible pixel anchors,
image/audio/video decoding, temporary exports, and OS scheduling/notification delivery.
Keep bounded decoded/display caches; do not assume an MDK byte cache is an image decoder
or that starting a runtime grants indefinite background execution on iOS or Android.
A successful send or publication is not proof that another person received or read it.

One runtime can serve several accounts. Each account-device identity has its own encrypted
database; every account-scoped handle/result must stay with the account that created it.
`groupIdHex` identifies opaque MLS group bytes (commonly 16 bytes), not a 32-byte Nostr
routing ID. Use canonical member/account references from MDK. Treat opaque cursor, revision,
asset and stream handles as their documented types, never as parseable persistent identifiers.

### Choose the right level of API

These are recommendations for new chat clients, **not Rust deprecation annotations or
scheduled removals**. Compatibility methods remain callable. Lower-level methods remain
supported for custom clients and non-chat uses; they are not obsolete merely because a
screen API exists. The method reference marks explicit alternatives individually.

| Use case | Recommended starting point | Existing alternative and when to use it |
| --- | --- | --- |
| Runtime construction | `newWithConfiguration` with `MarmotOptions` | `new` for defaults; specialized constructors remain compatibility conveniences. Preserve secret store and cursor policy when migrating. |
| Main Chats/Unread/Archived/Left screens | `openChatListWindow` | `presentedChatList` / `openPresentedChatList` for a full selected list; `chatList` / `subscribeChatList` for raw rows and custom filters. Do not filter a loaded page to implement full-account search. |
| One chat row | `presentedChatListRow` | `chatListRow` when raw fields are specifically required. Avoid account-wide reads for one row. |
| Account badges | `subscribeAccountAttention` | `accountUnreadSummary` remains a one-shot lower-level unread query, not a substitute for the prepared attention contract. |
| Conversation screen | `openConversationWindow` | `timelineMessages` / `subscribeTimelineMessages` for a custom timeline; `messages` / `subscribeMessages` for raw stored messages. |
| Composer | `selectedMessageDraft`, revision-conditional save/clear/attachment reads, `sendMessageDraft` | Unconditional `messageDraft` / `saveMessageDraft` / `deleteMessageDraft` for older single-owner flows; new concurrent composers should use revisions. `sendText` and other direct send methods remain supported. |
| Visible avatars | `requestAvatarAssets` then `readAvatarAssets` using screen metadata | `downloadProfileImage` / `downloadGroupBlossomImage` for explicit low-level downloads; new screens should use MDK's durable cache. |
| Media library | `attachmentHistoryPage` / `attachmentHistoryVersion` | `listMedia` is the older accepted-only listing; it omits rejected source slots and lacks the new cursor/version contract. |
| Display received media | `attachmentLocalAssets` then `readAttachmentAsset`, plus transfer observation/controls | `downloadMedia` is a supported one-shot network download returning full transient bytes. It is not a retained-cache read. |
| KeyPackage settings | `localAccountKeyPackages`, then `refreshAccountKeyPackages` | `accountKeyPackages` for the existing network-oriented inventory; `accountKeyPackageRelayEvents` remains useful for observed publication history. |
| Interactive imported-account onboarding | `beginOnboarding` / `beginExternalSignerOnboarding`, workflow snapshots and revision/epoch-aware approvals | `login` / `loginExternalSigner` remain compatible direct flows; they do not implement the interactive repair/notice UI for you. |
| Group administration | Detailed mutation methods where available, plus `groupManagementState` | Shorter mutation methods remain supported; use detailed results when the UI needs operation outcomes. |

### Feature map

All methods, including less common management/diagnostic operations, are listed in the
[complete reference](API-REFERENCE.md). These are the responsibilities of the main API families:

| Family | Integration boundary |
| --- | --- |
| Accounts and onboarding | Identity creation/import, setup readiness, local sign-in/out, wipe/export and external signers. Keep local removal, leaving groups, remote publication and wiping credentials distinct; inspect returned cleanup/send outcomes. Interactive onboarding is a persisted approval workflow, not a series of unconditional setters. |
| Directory and profiles | Canonical member-reference parsing, safe names, cached identities, profile/relay refresh and user search. Cached reads and explicit network refresh are separate. Use prepared identity references on chat screens instead of per-row lookups. |
| Groups and administration | Creation, staged/prepared images, invitations, membership/admin changes, retention, archive/leave/disband, recovery, quarantine and maintenance. Use current capabilities; a displayed roster is not authorization. Queued operations and uncertain publication require result-aware UI. |
| Messages, edits, reactions and polls | Send/reply/edit/custom events, reaction changes, encrypted NIP-88 polls, deletion and edit history. Render effective prepared content and viewer reaction/poll state; use raw history only when the feature needs it. |
| Moderation and blocking | Typed reports, individual dismissals, deletion-masked report targets and live block lists. Reports are not deletion evidence; the host designs moderation queue UI from the provided records. |
| Screens, read state and drafts | Prepared bounded lists/conversations, account attention, read markers, manual unread, pins, mutes and revisioned composers. MDK owns persistent projection state; the host owns viewport/layout. |
| Media and avatars | Sending/uploading media is separate from discovery, receiving, retained-byte access and decoding. Use original source slots and current opaque references; preserve rejected attachment positions. |
| Notifications and push | Notification preferences, native registration, bounded wake/catch-up and notification subscriptions. The host owns OS tokens, permission prompts, background budgets and notification presentation. |
| Relays and maintenance | Relay safety/classification, account/user relay lists, health, connectivity restoration, KeyPackage rotation and periodic group updates. Loopback development policy is explicit; connectivity recovery is not permission to reset user settings. |
| Agent streams | Start/watch live text previews or use a publisher handle to append then finish a durable transcript. Preview transport and durable message delivery have different outcomes; ephemeral handles do not provide restart persistence. |
| Diagnostics | Fixed performance milestones/snapshots, consent-gated product events, relay telemetry, audit recording/files/uploads. Keep each configuration and consent boundary explicit; do not dump secrets or DTOs into logs. |

### Runtime lifecycle, threads and errors

1. Install matching generated sources, native libraries and platform resources. Android must
   initialize `MarmotAndroid` before construction; Apple wrappers must carry the privacy resource.
2. Construct with the intended root, relay policy, cursor persistence and secret store. For White
   Noise publications, supply `clientName: "whitenoise"` in every foreground/background runtime.
   A frozen notification-extension cursor must remain frozen when adding options.
3. Use local reads for initial UI where their contracts allow it. Start the runtime for live
   account workers, relay synchronization and acquisition. Local data and send readiness are
   distinct: render a conversation's available history while honoring its composer capabilities.
   If one account worker fails to start, another ready account remains usable. A failed account
   is retried on a later trigger after bounded in-memory backoff; repeated commands during the
   delay report unavailability without reopening it. The runtime's aggregate start/reconcile
   result still reports the partial failure.
4. Keep synchronous storage reads off the UI thread. Async Swift/Kotlin calls may suspend;
   C methods are blocking unless documented otherwise. Host signer/secret-store callbacks may
   run concurrently on worker threads and must be thread-safe.
5. Bind one receive loop to each subscription. On account/view change discard late results from
   the old handle, cancel waiting tasks and release handles. Some handles have explicit `cancel`;
   consult the reference rather than assuming all handles share that method.
6. Before terminal suspension or transfer of root ownership, await `shutdownAndClose()`.
   It closes storage and releases locks even if host references remain. Reads on the closed
   runtime fail; reconstruct a runtime and its handles on foreground. `shutdown()` only stops
   work and does not by itself provide the terminal storage/root-release contract.

`RuntimeBusy` is contention for the exclusive root lease, not an empty account set. Handle
storage/closed/stopping/not-ready errors separately from successful empty results. On a timeout
or task cancellation, a durable mutation may already be queued; refresh authoritative state
before retrying. Do not translate every error into an empty list, restart the entire runtime on
every subscription update, or delete lock/database files to recover ownership.

### Screen snapshots, paging and ownership

Prepared list/conversation updates are complete replacements for their bounded window.
Apply generation/sequence ordering; do not append a replacement as if it were a page delta.
Pass current navigation tokens and preserve the visible row's pixel offset in the host.
The unread/latest anchor chooses content to load; the host still performs scrolling after layout.
Mark messages read when actually visible, not simply because an API returned them.

Legacy `nextUpdate` methods have different delta semantics; never mix them with `next` on the
same handle. Attachment-history cursors/versions have their own restart rules. Recreate opaque
runtime-scoped objects after reconstruction. Swift uses ARC; Kotlin hosts close disposable
UniFFI handles after cancelling/joining consumers. C hosts use only the matching deep-free and
never free handles during concurrent use. Returned plaintext and copies made by host decoders
remain the host's responsibility, including removal of downstream copies after local deletion.

### Localization, privacy and diagnostics

`record_host_performance` accepts 28 shared host stages for runtime/UI initialization,
accounts, lists, profiles, timelines, message sending/search, media and preferences.
For example, `MessageSend` measures host task execution, `ConversationSearch` finds
conversations containing matching messages, and `MediaApply` installs prepared
media in the UI; it does not publish to a relay. See the
[operation definitions](../marmot-app/src/app_telemetry.rs)
for boundaries. Record only stages your client can observe. Nested stages overlap
and must not be summed. Ten `Linux*` stages retain vault startup/storage,
post-presentation/idle-loop and catch-all worker measurements.

Shared stages appear in `AppPerformanceSnapshotFfi` as `host_*` fields. The ten
Linux-specific distributions remain available through Rust snapshots and OTLP.
All 38 stages export unlabeled `app_host_*_duration_ms` histograms and
`app_host_*_samples` counters through opt-in OTLP, including early/error returns,
without success/failure series. Snapshot outcomes still reflect the supplied outcome.
Regenerate Swift/Kotlin bindings and pair them with the matching native library.

Use typed presentation, capability, deletion and group-system fields rather than parsing English
strings or guessing from membership counts. Clients localize fallback labels and system wording.
Preserve unknown variants/provenance as neutral presentation rather than inventing an actor.
Configure consent-gated analytics, audit uploads and relay telemetry deliberately; endpoint URLs
are not credentials. Never log message bodies, asset references, keys, account/group identifiers,
raw DTO stringification or relay URLs as performance labels. Use bounded performance operations
and aggregate snapshots; keep secrets out of diagnostics and host callback errors.

### Compatibility and documentation maintenance

Generated source, DTOs, enums, errors, headers and native code form one versioned contract.
An additive Rust method does not imply that an old generated binding can call a new library;
C record layouts are especially sensitive. Database upgrades are separate from source-level API
compatibility, and rolling back only the library can be unsupported.

The reference's names, signatures and source-line links are checked with `just binding-docs-gate`.
Use `just binding-docs-update` (or `python3 scripts/check_binding_docs.py --write`) to refresh
mechanical metadata while preserving authored prose. New exports receive scaffold entries that
fail validation until their guidance is completed; removed/duplicate entries require explicit
editorial cleanup. Review prose, selection guidance and affected feature contracts after changes:
the gate cannot tell whether those descriptions still match runtime behavior.
Every release from 0.10.2 has concise release notes and a separate detailed integration guide;
see [the release checklist](../../release.md#release-documentation).

## Building local bindings

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
Await `shutdownAndClose()` before suspension or root handoff; it terminally closes
storage and releases the lease without waiting for every host reference to disappear.
Reconstruct the runtime and its handles for the next foreground session.

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

## Build phases

The no-argument build scripts still build complete local bundles. Release CI
uses separate phases to parallelize compilation across runners:

| Script | Phase | Work |
| --- | --- | --- |
| `xcframework.sh` | `generate` | Host library and generated Swift/headers in `build/ios/swift`; no device builds |
| `xcframework.sh` | `native <target>` | One `aarch64-apple-ios` or `aarch64-apple-ios-sim` native build |
| `xcframework.sh` | `assemble` | Assemble existing native slices and `build/ios/swift` into the usual iOS output |
| `xcframework-macos.sh` | `native` | One `aarch64-apple-darwin` build with the macOS deployment flags |
| `xcframework-macos.sh` | `assemble` | Assemble the native slice with shared Swift/headers placed in `build/macos/swift` |
| `kotlin-bindings.sh` | `generate` | Host library, generated Kotlin and Android support files; no NDK required |
| `kotlin-bindings.sh` | `native` | JNI libraries for `ANDROID_ABIS`; no host library or binding generation |

Run independent phases in separate checkouts/runners. Multiple Cargo processes
sharing one target directory contend on its lock; separate phases do not make
concurrent invocations in one checkout safe. All inputs must have matching source,
builder, toolchain, profile and features. CI transfers inputs only within the same
workflow run. Apple assembly checks required files before replacing an existing
bundle and never compiles Rust. Both Apple scripts honor `CARGO_TARGET_DIR`.
See the [release guide](../../release.md#parallel-builds-and-build-only-rehearsals)
for the build-only benchmark workflow and cache-warming procedure.

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
The two 64-bit Android links pass `-Wl,-z,max-page-size=16384` and
`-Wl,-z,common-page-size=16384` as extra flags on the final library `cargo rustc`
invocation. That appends the policy after Cargo's selected rustflags instead of
replacing `build.rustflags` or target rustflags. The 32-bit ABIs stay on the NDK's default
page size, and the supported ABI set is unchanged. Google Play's 16 KB check
reads ELF `PT_LOAD` alignment; aligning the app bundle ZIP does not change
those segments. Each published Android archive includes `android-elf.json`
with the SHA-256, ELF class, machine, and observed load alignments of all
four `libmarmot_uniffi.so` files. `manifest.json` keeps its existing ordered
`contents` list and records `elf_validation: android-elf.json`. Exact-head
candidate packages carry the same report next to their provenance manifest.
A later release publishes the new artifact; this check does not by itself
select a version or prove an app's Play Console result.

Standard MarmotKit release builds use the workspace `[profile.release]` together with
`marmotkit-release-profile.env`: `lto=thin`, `codegen-units=1`, `opt-level=3`,
`debug=0`, `panic=unwind`, and `strip=none`. Android target invocations override only
`CARGO_PROFILE_RELEASE_STRIP=symbols`. Apple target invocations add
`-C embed-bitcode=no` and sanitize leftover `__LLVM` / `__bitcode` sections
before packaging so shipped archives stay native; that is not a symbol strip.
Sanitization requires the active Rust toolchain's `llvm-tools-preview` component
(included by `rust-toolchain.toml`) and Xcode's `libtool`. It rebuilds symbol indexes
and validates a temporary output before replacing the original archive.
Those builder-owned settings are not a user-facing escape hatch; measurement
scripts may override LTO and codegen units on direct Cargo commands for a
controlled baseline comparison.
These are configured profile values, not proof that Cargo applies LTO to every
output: the mixed `rlib`/`cdylib`/`staticlib` binding target can suppress LTO.
The measured reduction belongs to the combined profile, not to thin LTO alone.
Apple measurement rows record pre-sanitization Cargo archive bytes and hashes,
not final packaged-archive or linked application sizes. Native-only archive
validation and consumer linking are separate packaging checks.
Changing crate types to enable effective LTO also requires revisiting the
incompatible `embed-bitcode=no` flag and revalidating native Apple artifacts.

The automatic `MarmotKit Release Profile` workflow is an exact-head packaging
check, not a comparison benchmark. It builds Kotlin/Swift generation and every
Android or Apple native target once in parallel, transfers those inputs only
within the current workflow run, verifies their source, builder, toolchain,
profile, feature and run provenance, then assembles and validates the Android,
iOS and macOS candidate packages. Pull requests restore the trusted release
cache read-only; only runs using the workflow from `master` may update it. A
weekly scheduled exact-head run on `master` provides drift detection and
refreshes those trusted cache seeds; it intentionally executes the complete
packaging matrix.

Baseline-versus-candidate measurements are intentionally manual. Run the
`MarmotKit Release Profile Measurements` workflow from `master` with the full
lowercase SHA that needs fresh evidence:

```sh
gh workflow run bindings-profile-measurement.yml \
  --ref master \
  -f source_sha="$(git rev-parse HEAD)"
```

Changes to the release profile, Rust toolchain or measurement method must run it
and link the completed evidence before merge; also run it whenever release or
review evidence is requested. The selected SHA must already be fetchable from
GitHub. The non-publishing run fails closed unless checkout
matches it exactly and uploads separate Linux/Android/CPU and Apple reports,
hashes, raw Criterion output and build logs. A failed or incomplete surface
keeps the final comparison check red.

```sh
# Inexpensive regressions, including provenance JSON and archive bitcode checks:
python3 crates/marmot-uniffi/test-release-profile.py

# On macOS: real archive reconstruction, embedded-bitcode removal and linking:
python3 crates/marmot-uniffi/test-native-archive.py

# Controlled host/Android/Apple/CPU comparison. Missing platforms are recorded as
# unavailable, never as zero. Isolated target directories keep the two variants
# from overwriting each other. `--cpu` fails if a benchmark invocation fails or
# only stale Criterion estimates remain:
python3 crates/marmot-uniffi/measure-release-profile.py \
  --source-sha "$(git rev-parse HEAD)" \
  --builder-sha "$(git rev-parse HEAD)" \
  --host --cpu \
  --output release-profile-measurements.json \
  --markdown release-profile-measurements.md
```

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
   a proposal. Recommended relays append missing defaults to the observed list,
   preserving every original relay tag, including private-network, `ws://` and `wss://` onion,
   retired, and unparseable entries. Dial policy filters connections, not published
   declarations. Both onion schemes require a Tor transport and are excluded from direct dialing.
   Defaults are deduplicated against raw tags, including unknown roles.
   If every default already has a read-only or unknown role, the general-relay step
   offers explicit editing instead of recommending an append that cannot add a write route.
   Relay findings are advisory once a usable outbox/inbox route is
   confirmed. Proposals require a policy-allowed write route (or inbox route);
   reachability is checked after publication. Explicit relay selections replace
   the list and require every selected endpoint to pass dial policy. Approval
   requires every configured discovery source to complete; failures from additional
   user-declared sources are tolerated only when the previous record is found.
   This bounded check cannot rule out newer records on unreachable or unqueried sources.
   A missing discovery result is not global proof of absence: hosts must
   not automatically approve publication for imported identities.
   Profile fields left unset preserve their current values; an
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

Ordinary checkpoints start at version 3, with supported version 1/2 upgrades.
Version 3 is a semantic barrier: old version 2 code rejects approved cancellation
and cannot safely restart it. Recovery checkpoints use version 4 because a
version 3 reader cannot validate epoch-scoped approvals. Completed recovery
leaves a version 4 cancellation tombstone even before a new begin, so older
readers fail closed. Preparing an additive relay proposal upgrades its checkpoint
to version 5, with or without a recovery epoch. This prevents older readers from
resuming an approved, unsigned proposal as a destructive replacement.
Downgrading once either format is used is unsupported; use a build that supports
the checkpoint version. Do not relabel versions or delete checkpoints to
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
network fetching or repair writes. Selected values survive offline reopen; visible avatar bytes should use
`requestAvatarAssets` / `readAvatarAssets` as described below.

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

## Bounded attachment history

Use the asynchronous attachment history page/version methods for canonical media-library
discovery. See [the C8-B native handoff](ATTACHMENT-HISTORY.md) for filtering, refresh,
removal and cursor ownership. `list_media` remains a compatibility API.

## KeyPackage client preference and publication label

Invitation discovery temporarily prefers `whitenoise`, then untagged/other clients,
then `amethyst`. Names are trimmed and matched case-insensitively, exactly (not by
substring). These are advisory labels, never proof of a particular application.
Only valid packages compatible with the proposed/existing group qualify. Within a
tier, the existing recency order applies. Amethyst remains selectable when no
higher-priority compatible package is available. A replacement in a publication
slot supersedes the old package before ranking; one package per account is selected.
This temporary selection policy applies to all hosts of this runtime; only the
publication label is host-configurable. Compatibility alone cannot identify a
client that publishes usable packages but does not process Welcomes.

Client ranking and slot supersession also apply to directory lookup (including
`wn-cli key-package`) and composition prewarm, without target-group requirements. A
malformed current publication never revives an older package in the same slot.
If no usable slot remains, prewarm reports failure while retaining successfully
discovered routes for other members. Its success must not imply readiness based
on superseded material. Bounded batch results are not exhaustive, so rejected
candidates still permit a per-account fallback fetch. A lower-priority batch
winner during create/invite also triggers that fetch to look for a preferred slot omitted by a relay's
batch limit, even if it returned fewer records than requested: relays may impose
lower caps. Already observed replacements remain authoritative during the refetch.
This adds a per-author request for each lower-priority batch winner. A White Noise
winner already has the highest tier in a newest-first prefix, so it skips that
request. Both paths remain bounded discovery: neither guarantees completeness
when a relay omits newer events instead of returning a newest-first prefix.
If that supplementary fetch fails, a still-valid, compatible package from the
current batch remains usable; previously cached packages are never substituted.
Prewarm skips preference-only refetches because it only checks existence.
Prewarm checks discovery readiness only; it has no proposed group configuration
and does not guarantee capability compatibility. Final creation/invitation checks
the actual group's requirements. Device-aware delivery in
[MDK #1696](https://github.com/marmot-protocol/mdk/issues/1696) is the intended
replacement for this temporary client ranking.

`MarmotOptions` combines `relayPolicy`, `cursorPersistence`, `clientName`, and
`secretStore` in `Marmot.newWithConfiguration`. Each field is optional in generated
Swift/Kotlin: omitted policies mean public-only endpoints and an advancing cursor;
an omitted label stays untagged and omitted storage uses the platform keychain.
Existing constructors keep their signatures and delegate to this same configuration
path. Use the options constructor when combining a label with a custom relay policy.
C hosts use `marmot_client_new_with_configuration` and a `MarmotClientOptions`
struct; zero initialization selects the same defaults. Use the matching header
and library for that struct's layout.

```swift
let options = MarmotOptions(clientName: "whitenoise")
let marmot = try Marmot.newWithConfiguration(
    rootPath: rootPath, relayUrls: relayUrls, options: options
)
```

Native construction/default checks: `./crates/marmot-uniffi/options-smoke.sh swift`
and `MDK_KOTLIN_CLASSPATH=<JNA:Android:annotations:coroutines jars>
./crates/marmot-uniffi/options-smoke.sh kotlin`.

Host applications opt into public tagging at construction. Existing constructors
remain untagged. Swift hosts can use:

```swift
let marmot = try Marmot.newWithClientName(
    rootPath: rootPath,
    relayUrls: relayUrls,
    clientName: "whitenoise",
    cursorPersistence: .advance,
    secretStore: nil
)
```

Kotlin exposes `Marmot.newWithClientName` with the same arguments; C exposes
`marmot_client_new_with_client_name`. Rust hosts set
`MarmotAppConfig::with_key_package_client_name(Some("whitenoise".into()))`.
Supply the name on every host runtime construction, including background and
notification-extension entry points (which retain their frozen cursor policy).
Absent or whitespace-only names omit the tag. New initial publications and normal
rotations carry the configured label. Existing events are not republished, and
already-signed pending publications retry with their original tags even if the
configuration changes. No workspace/binding version bump is part of this change.

## Local attachment access

Use `attachmentLocalAssets` to locate verified retained bytes for visible source
slots, then `readAttachmentAsset` for bounded local chunks without network work.
See [the native attachment handoff](ATTACHMENT-ACCESS.md) for unavailable/EOF semantics,
source revalidation, host buffer ownership and integration guidance. Acquisition
now defaults on with bounded per-account policy. Native progress snapshots/subscriptions
and durable cancellation, retry, remove and download-again controls use the same source slots.
