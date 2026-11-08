# marmot-uniffi

MarmotKit: UniFFI bindings for the Marmot app runtime (`marmot-app`), generated as Swift for iOS/macOS and Kotlin for
Android from one Rust API. This README is the entry point for app developers integrating MDK: what MDK owns, which
API to choose, the contracts behind each feature family, and how to build bindings locally. C and other raw-FFI hosts
should also read the [C ABI guide](../marmot-c/README.md), which adds ownership and blocking-call rules.

Read the documentation at the tag matching your binaries; `master` can describe unreleased APIs.

## Contents

- [Integration guide and API reference](#integration-guide-and-api-reference): documentation map, ownership, API
  selection, lifecycle, snapshots, diagnostics and compatibility
- Runtime setup: [runtime options and client label](#runtime-options-and-client-label),
  [experimental device-group test builds](#experimental-device-group-test-builds),
  [exclusive root ownership](#exclusive-root-ownership), [threading model](#threading-model),
  [service endpoint defaults](#service-endpoint-defaults)
- Accounts and identity: [interactive account onboarding](#interactive-account-onboarding),
  [identity references and profiles](#identity-references-and-profiles),
  [KeyPackage inventory](#keypackage-inventory), [KeyPackage selection](#keypackage-selection),
  [invitation lookup outcomes](#invitation-lookup-outcomes),
  [public Nostr event verification](#public-nostr-event-verification),
  [public event previews](#public-event-previews)
- Screens: [selected chat-list presentation](#selected-chat-list-presentation),
  [bounded chat screens](#bounded-chat-screens), [prepared conversation windows](#prepared-conversation-windows),
  [live timeline updates](#live-timeline-updates), [durable avatar access](#durable-avatar-access)
- Messages and moderation: [deletion provenance and custom events](#deletion-provenance-and-custom-events),
  [group-system previews](#group-system-previews),
  [device-local membership events](#device-local-membership-events), [members are accounts](#members-are-accounts),
  [undelivered Welcomes](#undelivered-welcomes),
  [turning on account devices](#turning-on-account-devices),
  [backup recovery and background conditions](#backup-recovery-and-background-conditions),
  [group reporting](#group-reporting),
  [moderation reports to the operator](#moderation-reports-to-the-operator),
  [history may be incomplete notices](#history-may-be-incomplete-notices)
- Media: [file-backed media upload](#file-backed-media-upload),
  [account attachment history](#account-attachment-history),
  [bounded attachment history](#bounded-attachment-history), [local attachment access](#local-attachment-access)
- Audit logs: [audit v5 recording and delivery](#audit-v5-recording-and-delivery),
  [legacy audit v4 upload](#legacy-audit-v4-upload)
- Building and packaging: [building local bindings](#building-local-bindings), [build phases](#build-phases),
  [Kotlin / Android](#kotlin--android), [release profile](#release-profile),
  [Apple privacy resources](#apple-privacy-resources)

## Integration guide and API reference

This is the current integration entry point for Swift/iOS, Swift/macOS and Kotlin/Android.

| Document | Use it for |
| --- | --- |
| [Complete method reference](API-REFERENCE.md) | Every exported constructor, runtime method, object method, free function and host callback, with signatures, purpose, source and API-selection guidance. |
| [Release integration index](../../docs/integration/README.md) | Per-release upgrade guides: required changes, changed defaults, optional adoption, examples and acceptance checks. Read every intervening guide when skipping versions. |
| [Changelog](CHANGELOG.md) | Binding-level changes per release, including unreleased work on `master`. |
| [Distribution](DISTRIBUTION.md) | Exact artifact layout, platform setup, checksums, Apple resources and source/binary pairing. |
| [Chat lists](../../docs/marmot-architecture/further-context/chat-projections-native.md) | Bounded list windows, account attention, navigation and sequence handling. |
| [Chat-list rows](CHAT-LIST-ROWS.md) | Selected previews, per-message expiry handling, live draft updates and row-action availability. |
| [Conversation windows](CONVERSATION-WINDOW.md) | Initial unread/latest positioning, live snapshots, paging, drafts and cancellation. |
| [Durable local sends](LOCAL-SENDS.md) | Early local acceptance, exact optimistic-bubble correlation, captured-media draft consumption and durable edits of pending local sends. |
| [Polls](POLLS.md) | Encrypted NIP-88 creation, replacement votes, bounded validation and deterministic timeline results. |
| [Attachment history](ATTACHMENT-HISTORY.md) / [attachment access](ATTACHMENT-ACCESS.md) | Media discovery, local bytes, atomic interactive promotion, genuine outgoing retention, progress, policy and ownership, including [host-managed automatic downloads](ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104) and Android WorkManager migration. |

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
| Runtime construction | `newWithConfiguration` with `MarmotOptions` | `new` with only a deployment; specialized constructors remain compatibility conveniences. Preserve secret store and cursor policy when migrating. |
| Main Chats/Unread/Archived/Left screens | `openChatListWindow` | `presentedChatList` / `openPresentedChatList` for a full selected list; `chatList` / `subscribeChatList` for raw rows and custom filters. Do not filter a loaded page to implement full-account search. |
| One chat row | `presentedChatListRow` | `chatListRow` when raw fields are specifically required. Avoid account-wide reads for one row. |
| Account badges | `subscribeAccountAttention` | `accountUnreadSummary` remains a one-shot lower-level unread query, not a substitute for the prepared attention contract. |
| Conversation screen | `openConversationWindow` | `timelineMessages` / `subscribeTimelineMessages` for a custom timeline; `messages` / `subscribeMessages` for raw stored messages. |
| Reaction details | `messageReactions` for complete effective participants | Window references contain bounded previews only. See [complete reaction details](CONVERSATION-WINDOW.md#complete-reaction-details). |
| Custom reaction artwork | `reactionAttachment` using the reaction's `reactionMessageIdHex`, then ordinary attachment acquisition/local reads | Resolves one reaction's matching encrypted artwork without a group-wide media scan. See [reaction artwork](ATTACHMENT-HISTORY.md#reaction-artwork). |
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
| Groups and administration | Creation, staged/prepared images, invitations, membership/admin changes, retention, archive/leave/disband, recovery, quarantine and maintenance. Use current capabilities; a displayed roster is not authorization. Queued operations and uncertain publication require result-aware UI. "History may be incomplete" notices report parked recovery; see [History may be incomplete notices](#history-may-be-incomplete-notices). |
| Messages, edits, reactions and polls | Send/reply/edit/custom events, reaction changes, encrypted NIP-88 polls, deletion and edit history. Render effective prepared content and viewer reaction/poll state; use raw history only when the feature needs it. Every client must render and answer polls, because peers can send them. |
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
   run concurrently on worker threads and must be thread-safe. See
   [threading model](#threading-model) for which threads run MDK work.
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

`EventTooLarge { artifact, sizeClass }` reports a size refusal of one serialized event by every requested relay on
the observed attempt. The artifact is Commit, Welcome, ApplicationMessage or Other; size classes are coarse diagnostic
buckets from under 64 KiB through over 4 MiB, not relay limits. Do not infer this error from generic relay text, a
timeout, or one refusal among mixed outcomes. Frozen native fanouts retain their strong proof: no accepted,
outstanding or ambiguously exposed targets in their retained history, and complete matching typed refusals.

A legacy Welcome's first attempt visible to its coarse bookkeeping can also carry this explanation. A crash before
finish bookkeeping, or expiry of an older attempt record, can hide earlier exposure. Thus a Welcome `EventTooLarge`
does **not** prove that the recipient never received it or that delivery is terminal: keep native retries, pending
work and confirmed state. The error has no frozen-versus-legacy discriminator; hosts must use this limited Welcome
meaning. Once the retained legacy record shows a prior attempt, its cause stays Unknown/generic rather than being
reconstructed. Unknown relay formats and KeyPackage errors carrying only a message remain generic; direct signed
helpers may also remain generic. An explicit retry can return this error; a confirmed create/invite instead exposes
the later Welcome failure through its pending query/notice without undoing the Add. No retirement or retry policy
is added.

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
Native startup investigation can explicitly call `set_startup_diagnostics_enabled(true)` before the first account query, then read `startup_diagnostics_snapshot()` while a call remains unfinished. The snapshot uses independent bounded memory and fixed phases, including key lookup, database-open waiting and migration numbers; it contains no paths, account identifiers or error text. Keep normal builds disabled, bound host serialization separately, and revoke capture with `false` when it is no longer needed. Neither method changes upload consent or database state. See the [API reference](API-REFERENCE.md).


`record_host_performance` accepts 28 shared host stages for runtime/UI initialization,
accounts, lists, profiles, timelines, sending/search, media and preferences, plus
nine Linux-specific vault/startup and event-loop stages. `MessageSend` covers host
send task execution, including attachment work. `ConversationSearch` finds
conversations containing matching messages. `MediaApply` installs prepared media
in the UI; this is UI resource application, not network publication.

All stages are readable by their `host_*` operation name in the existing
`AppPerformanceSnapshotFfi.runtime_operations` array, including the Linux stages.
They use the runtime registry's `app_runtime_host_*` OTLP series with the same
started/completed counters, five outcomes, histogram and live gauges. Hosts report
the actual outcome; merely leaving a scope does not establish success. These
completed-duration reports have no live observation, so their live gauges are zero.
Hosts should record every stage they can observe, and only those. Nested stages overlap and
must not be summed. See the [operation definitions](../marmot-observability/src/app_telemetry.rs) and
[metric catalog](../../docs/marmot-architecture/telemetry.md#registered-host-stage-metrics).

Use typed presentation, capability, deletion and group-system fields rather than parsing English
strings or guessing from membership counts. Clients localize fallback labels and system wording.
Preserve unknown variants/provenance as neutral presentation rather than inventing an actor.
Configure consent-gated analytics, audit uploads and relay telemetry deliberately; endpoint URLs
are not credentials. Never log message bodies, asset references, keys, account/group identifiers,
raw DTO stringification or relay URLs as performance labels. Use bounded performance operations
and aggregate snapshots; keep secrets out of diagnostics and host callback errors.

### Markdown rendering

Render the typed Markdown tokens on message, timeline and reply-preview records.
`parseMarkdown` returns the same AST for draft previews and custom renderers.
`MarkdownInlineFfi.Timestamp` carries signed `unixSeconds` (Swift `Int64`, Kotlin
`Long`) and a `MarkdownTimestampStyleFfi`, with no formatted text. Timestamp syntax
is `<t:UNIX_SECONDS>` or `<t:UNIX_SECONDS:STYLE>`; the parser resolves an omitted
style to `ShortDateTime`. Invalid timestamp syntax remains literal text.

| Style token | Enum variant | Display |
| --- | --- | --- |
| `t` | `ShortTime` | Time without seconds |
| `T` | `LongTime` | Time including seconds |
| `d` | `ShortDate` | Short date |
| `D` | `LongDate` | Long date |
| `f` (default) | `ShortDateTime` | Long date and time without seconds |
| `F` | `LongDateTime` | Weekday, long date and time without seconds |
| `s` | `CompactDateTime` | Short date and time without seconds |
| `S` | `CompactDateTimeSeconds` | Short date and time including seconds |
| `R` | `Relative` | Time relative to the current clock |

Use native date/time formatters with the device's current locale and timezone at
render time, including its date order and 12/24-hour preference. The parser and
bindings do not own a clock, timezone, formatter or refresh task. Refresh displayed
timestamps when locale, timezone or system clock changes and when the app resumes;
visible `Relative` nodes also need time-driven refresh even if the message tokens
are unchanged. A host may provide a localized absolute-time tooltip or accessibility
description. Keep the timestamp and typed style in display caches rather than
persisting formatted strings. The native renderer is supplied by the host app,
not this crate.

### Compatibility

Generated source, DTOs, enums, errors, headers and native code form one versioned contract.
An additive Rust method, record field or enum case does not imply that an old generated binding
can call or decode a new library: regenerate Swift/Kotlin bindings from the native library you ship
and update both together. For example, older generated sources cannot render the `MarkdownBlockFfi`
`Details` variant (bounded `<details>` / `<summary>` blocks) or record newer host-performance stages.
C record layouts are especially sensitive; C consumers rebuild against the matching header and library.
Database upgrades are separate from source-level API compatibility, and rolling back only the
library can be unsupported.

The reference's names, signatures and source-line links are checked against source with
`just binding-docs-gate`; prose and runtime behavior are reviewed by hand. Every release from
0.10.2 has concise release notes and a separate detailed integration guide; see
[the release checklist](../../release.md#release-documentation).

## Runtime options and client label

`MarmotOptions` combines `relayPolicy`, `cursorPersistence`, `clientName`, `devicePlatform`, `secretStore` and
`attachmentAcquisitionMode` with the required [`deployment`](#deployment) in `Marmot.newWithConfiguration`.
Every other field is optional in generated Swift/Kotlin: omitted policies mean public-only endpoints and an advancing cursor;
an omitted label stays untagged, omitted storage uses the platform keychain, and an omitted
acquisition mode keeps native automatic acquisition (see
[host-managed acquisition](ATTACHMENT-ACCESS.md#host-managed-automatic-acquisition-0104)).
Existing constructors take the deployment as their last argument and delegate to this
same configuration path. Use the options constructor when combining a label with a
custom relay policy.
C hosts use `marmot_client_new_with_configuration` and a `MarmotClientOptions`
struct; zero initialization selects the same defaults. Use the matching header
and library for that struct's layout.

```swift
let options = MarmotOptions(clientName: "whitenoise", deployment: marmotDeploymentWhiteNoise())
let marmot = try Marmot.newWithConfiguration(
    rootPath: rootPath, relayUrls: relayUrls, options: options
)
```

Host applications opt into public KeyPackage tagging at construction. Existing constructors
remain untagged. `newWithClientName` is the older single-purpose constructor:

```swift
let marmot = try Marmot.newWithClientName(
    rootPath: rootPath,
    relayUrls: relayUrls,
    clientName: "whitenoise",
    cursorPersistence: .advance,
    secretStore: nil,
    deployment: marmotDeploymentWhiteNoise()
)
```

Kotlin exposes `Marmot.newWithClientName` with the same arguments; C exposes
`marmot_client_new_with_client_name`. Rust hosts set
`MarmotAppConfig::with_key_package_client_name(Some("whitenoise".into()))`.
Supply the name on every host runtime construction, including background and
notification-extension entry points (which retain their frozen cursor policy).
Absent, whitespace-only and over-long names (more than 64 bytes of UTF-8 once
trimmed) omit the tag; MDK never truncates one. New initial publications and normal
rotations carry the configured label. Existing events are not republished, and
already-signed pending publications retry with their original tags even if the
configuration changes.

Native construction/default checks: `./crates/marmot-uniffi/options-smoke.sh swift`
and `MDK_KOTLIN_CLASSPATH=<JNA:Android:annotations:coroutines jars>
./crates/marmot-uniffi/options-smoke.sh kotlin`.

### Deployment

Every constructor requires a `MarmotDeploymentFfi`: `MarmotOptions.deployment` has no default, and the other
constructors take it as their last argument. It holds the services a deployment's users rely on: the
recovery-operated relays, discovery indexers, new-group media servers, group- and profile-image servers, Open
Ranking, the moderation label namespace, and the keychain service used when no `secretStore` is given. Start from `marmotDeploymentWhiteNoise()` or `marmotDeploymentNeutral()` and change what
differs. White Noise apps pass `marmotDeploymentWhiteNoise()` in every entry point, including background and
notification-extension runtimes. Never change `keychainService` for an existing install: secrets stored under the old
name are stranded.

Nothing an unset value configures falls back to White Noise's services. With no `newGroupMediaEndpoints`, new groups
carry no encrypted-media component and stay text-only. With no group-image server, setting or fetching an encrypted
group image fails; with no profile-image server, `uploadProfileImage` needs an explicit server. No recovery relays
means every route's history needs all its relays to certify, no discovery indexers means onboarding searches the
discovery relays the host passes plus the account's declared relays, no Open Ranking turns that directory-search tier off, and no moderation label namespace leaves reporting
unconfigured. The neutral keychain service
is `org.marmot-protocol.mdk`.

```swift
let options = MarmotOptions(clientName: "whitenoise", deployment: marmotDeploymentWhiteNoise())
let marmot = try Marmot.newWithConfiguration(
    rootPath: rootPath, relayUrls: relayUrls, options: options
)
```

## Exclusive root ownership

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

Exclude each account directory under `rootPath`, including its `media/` and `handoff/`
folders, from iCloud and Android auto-backup. Attachment files are encrypted with
device-bound keys, so a restored copy cannot be read, and `handoff/` holds plaintext
copies lent to OS surfaces.

## Threading model

MarmotKit runs MDK on a Tokio runtime it owns, not on the threads that call it.

- **Async methods** run their work as a task on that runtime. The Swift task or Kotlin coroutine
  awaiting the call only waits for the task to finish, so awaiting from the main actor or
  `Dispatchers.Main` does not run MDK work on the UI thread. Cancelling a Kotlin coroutine frees
  the call, which aborts the task at its next suspension point; `shutdownAndClose()` and
  `signOutAndWipe()` keep running regardless. Generated Swift waits for the call to finish even when its `Task` is
  cancelled.
- **Subscription receives** (`next()`, `nextUpdate()`) are the exception: they wait on the calling
  thread, with the runtime entered, because a receive that ran ahead on the runtime could consume
  an update that a cancelled caller never collects. They only wait and convert; the work that
  produces updates runs on the runtime.
- **Synchronous methods and constructors** run on the calling thread. Some are SQLCipher reads;
  keep them off the UI thread. Constructors enter MarmotKit's runtime, so background tasks they
  start run there too.
- **One runtime per process**, created by the first constructor and shared by every `Marmot`
  object. If it cannot start, construction throws `MarmotKitError.Runtime` rather than falling
  back. It has half as many worker threads as the device has CPUs, at least 2 and at most 4,
  plus Tokio's blocking pool for storage and file work, whose threads start on demand and exit
  when idle. All are named `marmotkit-rt` in crash reports and profilers. `shutdownAndClose()`
  stops MDK's work and releases its files; the idle threads remain for the next `Marmot`.
- **What runs in parallel:** account workers, the relay plane, subscription forwarders, timers
  and the work behind concurrent host calls are separate tasks spread over the worker threads.
  Each account's worker still handles its own commands one at a time, in order, so a slow
  operation delays that account's later worker-routed calls but not other accounts.
- **Host callbacks** (`SecretStore`, `ExternalAccountSignerFfi`) can be invoked from runtime
  threads or the calling thread, possibly concurrently. Implementations must be thread-safe and
  must not wait for the main thread.

The C bindings block the calling thread on a runtime owned by each client; see
[`marmot-c`](../marmot-c/README.md). The [app runtime threading
model](../../docs/marmot-architecture/overview/marmot-app-runtime.md#threading-model) compares
every binding.

## Service endpoint defaults

`marmotkit-endpoints.env` sets the public build-time defaults consumed by Marmot's compiled endpoint config:

- `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT`
- `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT`
- `MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT` (optional full Aptabase events URL; no default)

These are route URLs only. Host apps still supply audit and telemetry bearer tokens and analytics app keys at
runtime. Set any of these environment variables before invoking a build script to override the default for staging
or local testing.

Public profile-image uploads use the deployment's `profileImageEndpoint`
(`https://blossom.primal.net` in White Noise's), or an explicit Blossom server
passed to `uploadProfileImage`. With neither, the upload fails. Peers' avatars
always load from the URL in their own profile.

## Interactive account onboarding

Imported identities can use the durable preflight API instead of `login`:

1. Call `begin_onboarding(nsec, options)` or
   `begin_external_signer_onboarding(public_key, signer, options)`. Supply the
   same `default_relays` (and optional `inbox_relays`) as new-account creation
   and a separate set of trusted `discovery_relays`. These methods return a
   persisted account and snapshot before fetching or publishing Nostr records.
2. Display the snapshot steps in their returned order (profile, follows, general
   relays, inbox relays, sign-in chat/history notice (`SingleDevice`), KeyPackage). Use step identities,
   not enum discriminants, as positions. Subscribe with `subscribe_onboarding`, read its initial
   `snapshot`, and drive `next` concurrently with `run_onboarding`.
3. Localize the typed status, findings, and actions. A healthy account advances
   automatically until the notice acknowledgment. `NeedsInput` offers a repair or, for profile/follows, an
   explicit `continue_onboarding_without`. Empty follow lists are valid.
4. `propose_onboarding_relay_repair` previews the smallest safe change to a
   general or inbox relay declaration, preserving the original ordered tags,
   duplicate/custom entries, direction markers, and content. NIP-65 read/write
   markers are interpreted case-insensitively; their spelling and trailing
   extension fields remain unchanged in the preview and published event. Show its typed
   before/after diff and repair mode. `ManualReview` cannot be approved; prefill
   a manual editor from the original tags or offer a separately labeled reset.
   No proposal signs or publishes until explicit approval. The older
   `propose_onboarding_recommended_relays`, `propose_onboarding_relays`,
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
   reachability is checked after publication. Explicit relay selections edit known
   endpoint roles, preserving retained tag occurrences and unrelated fields in a
   typed preview, and require every selected endpoint to pass dial policy. Approval
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

Findings carry typed `context`, `purpose`, `outcome`, `declared_capability`,
`actions`, and `observed_revision` alongside `issue` and `endpoint`. Render
each finding separately, even when endpoints match. Use its actions as the
authoritative subset applicable to that finding; an empty list offers no
finding-specific action. The step's `actions` remain the full set, including
single-device consent and KeyPackage setup actions outside relay diagnostics.
`InspectionCompleted` with `DirectoryQuery` success records only a successful
directory inspection, not relay write support or event publication. Timeouts,
incomplete discovery, and unreachable queries leave the outcome unknown.
Retained findings keep their original observed revision and step `checked_at`;
interpret revisions only within the snapshot's account and recovery epoch.
Observations outside relay diagnostics may have unknown context/purpose/outcome
and no finding actions. Legacy checkpoints also have no observed revision;
rechecking supplies a fresh revision without upgrading retained evidence.

### Explicit recovery and checkpoint compatibility

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
resuming an approved, unsigned proposal as a destructive replacement. Preparing
an exact lossless relay repair upgrades the checkpoint to version 6, preserving
that version through approval, signing and completion. Version 3/4/5 readers
reject it rather than discard the typed preview and publish replacement tags.
Explicit relay edits return the same typed before/after preview. Retained
endpoint roles keep their original tag occurrences, order and extension fields,
even when selected with equivalent URL spelling; unrelated tags and content remain unchanged. An unchanged selection returns
`ManualReview` without an approval action. These manual previews use checkpoint
version 7 because version 6 readers can only revalidate automatic minimal repairs.
No binding signature changes are required. Downgrading once any of these formats
is used is unsupported; use a build that supports
the checkpoint version. Do not relabel versions or delete checkpoints to
force a downgrade. Restore/upgrade to a supporting build, or explicitly recover
unsupported evidence with this API.

### Single-device notice

The historical `SingleDevice` step still pauses before initial KeyPackage publication.
It explains what signing in alone restores, rather than declaring all multi-device
use unsupported. Suggested localized copy:

**Chats on this device**

> Signing in alone does not restore your existing chats or messages. If you use another
> device, keep its app and data until you've checked your chats here.

The snapshot's `single_device_notice` adds advisory evidence. For
`OtherInstallationPossible`, explain: "Other sign-in records were found. They may
belong to another installation or an earlier one." For `Unknown`: "Other sign-ins
could not be checked." `NoneFound` needs no extra warning and does not prove there
are no other installations. Reinstallation or cleared local state can produce the
same evidence; do not claim to have identified a physical device or a particular app.

`MultiDeviceUnsupported` remains a legacy issue value for checkpoint and binding
compatibility; current checks and resumed projections omit it. Render the notice
from its step, DTO and actions instead of using that historical identifier as a
capability claim. Existing apps need to adopt the updated localization against a
published, immutable binding artifact; the MDK update cannot replace installed UI
strings. Discovery, consent and publication policy stay in MDK.

Device-group linking remains disabled in normal released builds. Do not add a
working Link action to this notice or promise automatic chat/history restoration.
Acknowledging it does not approve a sign-in, link devices, or replace sign-in and
code-comparison prompts.

Offer **Cancel** and **Continue** (the existing `ContinueAnyway` action). For Cancel, invalidate the current UI
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

For Continue, call `acknowledge_onboarding_single_device(account_ref, snapshot.revision)`.
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

### Snapshots, discovery and relay checks

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

### Adoption and legacy accounts

The existing `login` and generated-account APIs remain compatible. Apps must
adopt the identity-only APIs and screen to enable this experience. Legacy
accounts without an onboarding checkpoint are not retroactively blocked. Active
legacy accounts and accounts with unfinished legacy setup are not silently
enrolled: finish or resume their existing setup first. Signed-out legacy accounts
without pending setup can explicitly opt in. Completed checkpoints defer to normal
setup/recovery readiness. Corrupt or newer-version checkpoints gate only their own
account; they must be restored or opened with a compatible runtime, not silently
discarded because they may contain approved publication intent. C
consumers have equivalent methods and subscriptions, except the external-signer
entry points, which have no C callback interface yet.

## Identity references and profiles

New generated identities publish kind `10002`, kind `10050`, and kind `0` to
their account relays and send separate best-effort copies to the built-in public
directory indexers. Later relay-list and profile edits through MarmotKit do the
same. The indexers are never inserted into the advertised relay lists or used
for KeyPackages, contact lists, or messaging. Acknowledgement from an account
relay establishes setup success; indexer copies are scheduled after bootstrap
confirmation, before initial KeyPackage publication, and an outage is reported
only as an aggregate warning. Shutdown or account removal cancels pending copies.
Existing identities are not automatically republished to the indexers and need a
client-initiated backfill of their current lists and profile.

`accountIdHex` / `normalizeMemberRef` accept `nprofile` and
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
fallback runs; FFI normalization rejects that form.

Decode a scanned reference first, then pass the canonical lowercase hex account id to
`defaultProfilePseudonym` so the shared text-hash seed is preserved. Passing uppercase hex
or an undecoded `npub` silently produces a different name, not an error. `randomProfilePseudonym`
replaces client-owned random-roll wordlists; it is cosmetic, may collide, and does not create
an account.

`userProfile` returns the cached kind:0 projection. `about` from a fetched
profile keeps normalized LF line breaks; `name`, `displayName`, `picture`,
`banner`, `nip05`, and `lud16` stay single-line. Tab and other controls are
removed on ingest. `publishUserProfile` caches the submitted local value
without reparsing it, so a same-instance publish/read does not show incoming
sanitization. Read another account through `refreshProfile`, then
`userProfile` or `cachedIdentityProjections`. A bio already stored without
line breaks stays until a newer event replaces it.

## KeyPackage inventory

`accountKeyPackages` lists the current KeyPackage winner per addressable slot
plus local-only rows. `accountKeyPackageRelayEvents` is the additive observed
history for that same fetch window: current and superseded kind-30443 events,
with `isCurrent` set only among those observed valid events. Hosts can pass a
superseded `eventIdHex` and its `sourceRelays` to the existing delete API.
This does not change the Published-list filter (`relay == true`).

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

## KeyPackage selection

Creating a group or inviting adds every device of each recipient account, and the group shows the account as one
member with its `deviceCount`. MDK reads the account's KeyPackages and KeyPackage deletion requests from relays, then
adds every valid, compatible package published in the last 30 days, at most 20 per account; with none that recent, it
adds the single best valid one. Each publication slot (`d` tag) contributes at most one package: the slot's newest
publication supersedes older ones even when it is invalid or deleted, so an older package never comes back. A package
a deletion request covers, by slot address or by event id, is skipped. Packages not marked last-resort rank first,
then the most recently published, then the lower KeyPackageRef. Packages sharing a leaf signature key (one device
publishing in several slots) count once. The `client` tag never affects selection; it is only a publication label
(see [runtime options](#runtime-options-and-client-label)).

Directory lookup (including `wn-cli key-package`) returns the best package of the same selection. Composition prewarm
checks existence from a batched read. Create and invite read each account on its own, because a read bounded across
accounts cannot prove that it saw every slot. If that read fails, valid, compatible packages from the batch remain
usable; previously cached packages are never substituted. Prewarm has no proposed group configuration, so it does not
guarantee capability compatibility; creation and invitation check the actual group's requirements.

## Invitation lookup outcomes

Creating or inviting looks up each recipient's relay lists and KeyPackage. The
first recipient that cannot be used ends the call, in request order:

- `MissingKeyPackage { account, reason }`: the lookup completed and found nothing
  invitable. `reason` is `NotFound`, or `ObsoleteOnly` when the recipient has only
  outdated KeyPackages and must update their app.
- `DirectoryLookupIncomplete { account }`: the lookup for `account` ran out of time
  or relay coverage, so nothing is known to be missing. Offer retry.
  `fetch_latest_key_package_for_account_id` and relay-list lookups report the same
  outcome.
- `MissingMemberInboxRoute { account }`: the recipient has no usable inbox relay.

## Public Nostr event verification

The stateless `verifyPublicNostrEventJson` helper verifies public events through
MDK's Nostr/libsecp256k1 stack without constructing an account or supplying a
secret key. It checks both the canonical event ID and signature. A host must
still enforce its own allowed authors, kinds, tags, and input-size limits.
Malformed input and invalid signatures return `false`; it does not authenticate
an MLS group message or replace MDK's relay ingestion checks.

## Public event previews

Event cards for `nostr:` references in message content read from an
account-scoped cache, so a reopened chat renders prior previews in its first
frame, offline included. Call `cachedPublicEventPreviews` (at most 16
references, network-free) before layout, then `resolvePublicEventPreview` for
each reference shown; it touches the network only for missing or stale rows.
MDK fetches from safe relay hints and the configured directory relays, stores
only verified events that match the reference, keeps the newest `naddr`
version, and turns an author's NIP-09 deletion into a `Deleted` row. Event JSON is the signed
event; shape its content for display on the host. Author names and avatars
come from `cachedIdentityProjections`. See
[the method reference](API-REFERENCE.md#marmotcached_public_event_previews).

## Selected chat-list presentation

`openPresentedChatList(accountRef, includeArchived)` returns an account-bound subscription.
Take `snapshot()` once (generation plus sequence zero), then consume `next()` as complete replacement snapshots.
Each row contains the existing chat-list fields and MDK's selected title/avatar; hosts render the typed fallback text
with their own localization and load the selected avatar descriptor without a roster/profile lookup.
`presentedChatList` and `presentedChatListRow` provide the same local contract for one-shot and creation/rebind paths.

First use can await bounded local preparation. `ChatPresentationNotReady` means preparation did not advance and may be
retried after maintenance; it is not an empty list or missing group. Storage errors remain errors. Ready reads do no
network fetching or repair writes. Selected values survive offline reopen; visible avatar bytes should use
`requestAvatarAssets` / `readAvatarAssets` as described in [durable avatar access](#durable-avatar-access).

Order updates by the handle's generation and sequence. `presentationVersion` only versions selected presentation:
an unread, pin, archive or mute update can have the same presentation revision. Drop the old handle when changing
accounts; cancellation preserves a pending refresh, and shutdown ends the stream. Account-store replacement requires
opening a new handle. Do not log rows or avatar material, including generated host-language record stringification.
Existing chat-list APIs remain available.

## Bounded chat screens

`openChatListWindow` provides live Chats/Unread/Archived/Left windows, and `subscribeAccountAttention` provides
independent account attention. See the [native handoff contract](../../docs/marmot-architecture/further-context/chat-projections-native.md)
for paging, sequence handling, cancellation, C ownership, and compatibility.

## Prepared conversation windows

`openConversationWindow` combines history, header/capabilities, visible identities,
read state and revisioned draft descriptors. See the [native conversation contract](CONVERSATION-WINDOW.md)
for opening, paging, cancellation, timeout, ownership and draft migration.

## Live timeline updates

`TimelineMessagesSubscription::next()` returns the complete bounded window on
every update. Its conversion cache avoids reparsing unchanged rows, but those
rows still get cloned and serialized across FFI. `next_update()` returns raw
projection deltas, or a replacement `Page` after a refresh. These methods consume
the same stream; use only one per subscription. Delta consumers must maintain
ordering, removals, and window limits themselves; raw projections do not report
which rows the runtime evicted from its bounded window.

Projection `messages` and upsert `changes` retain their existing wire format.
When corresponding source records are identical, conversion parses Markdown
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

## Durable avatar access

Chat rows and conversation header/identity records include `avatarAsset` metadata. For visible content, batch its
opaque `target` values into `requestAvatarAssets`, then pass returned `reference` values to `readAvatarAssets`. Both
accept at most 16 items; byte reads additionally require a 1-byte to 16-MiB aggregate budget. A `deferred` result means
that complete image did not fit the remaining budget. Ready/stale images can render offline; decode and render on the
host, caching decoded images by reference plus content revision. Screen subscriptions update metadata when acquisition
completes. `clearAvatarCache` clears durable bytes and demand; later visible requests can acquire again.

Keep host persistent caches until migration and device validation are complete. See
[the avatar contract](../../docs/marmot-architecture/further-context/avatar-cache-storage.md)
for source/account fencing, result states and lifecycle rules.

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
migration or deletion index is needed. Older MDK binaries reject the upgraded database schema;
do not roll back only the library. This is a binding layout change, not an MLS/wire-format change.

Custom events retain their numeric `kind` and verbatim `plaintext` content. Conversation windows
also carry their ordered `tags`, so clients can render app-defined event types without fetching
raw events. Deleted rows expose no raw tags in timeline reads, moderation reads, or conversation windows.
MDK-owned kinds continue to use prepared fields and references there. Custom-event tag changes invalidate
the conversion cache. Custom events do not change chat-list activity or notification policy.
`sendCustomEvent` refuses every kind MDK owns, the device-group kinds 457, 458, 459, 460, 461, 473, 475 and 476 included. Those
are read only in the account's own device group, so a chat never shows one, as a row, a message or a notification.


## Device-local membership events

The group-event firehose distinguishes account-level timeline activity from
`LocalGroupCopyTerminated`, `LocalGroupCopyRestored`, and
`GroupMemberLeavesRemoved`. MDK applies their membership, pending-send and
notification effects before host delivery; these events create no system row.
Use them to refresh presentation, and handle the new variants when regenerating
Swift/Kotlin bindings. Retained-history engine rollback does not automatically
recover a local copy that has applied its own removal.

## Queued sends the group refuses

A send made while the group settles reports `AcceptedPending`, and MDK sends it
once the group settles. If the settled group refuses it (the user stopped being
an admin meanwhile, or the change no longer applies), MDK drops it and emits
`GroupEventKindFfi::QueuedIntentRefused { intent_id_hex, intent_kind, reason }`
for that group. Nothing retries it: tell the user, who may try again. `reason`
is a stable tag such as `not_group_admin`.

## Undelivered Welcomes

An Add can already be confirmed while its Welcome remains unacknowledged. Subscribe before creating or
inviting, then use `pending_welcome_deliveries(account_ref)` to read the current repair handles. The
`WelcomeDeliveryPending` event and each handle carry optional `size_class`: a coarse serialized-event size explaining
the observed all-target refusal. It does not estimate any relay's configured limit or prove non-delivery; earlier
legacy exposure can be hidden by a crash or expired bookkeeping. The same [limited Welcome meaning](#runtime-lifecycle-threads-and-errors)
applies to a typed retry error. `None` means Unknown, including old records, lost diagnostic writes and unrecognized
future annotations; it is evidence of neither delivery nor non-delivery.

The event remains once per process/Welcome. Later cause changes are obtained from the query, not another event.
A later coarse legacy retry may replace a specific displayed cause with Unknown while the same debt persists.
MDK continues its existing retry behavior; this diagnosis neither removes the member nor adds another leaf,
rolls back the confirmed Add, or declares the obligation terminal. Hosts can distinguish a known size refusal
from an unexplained delivery problem without receiving relay details or another account's device information.

The event gains a field and the pending query returns a new record. The account database adds one nullable
annotation to each existing repair row;
older native builds supporting only schema 0176 cannot reopen the migrated database. There is no wire change or
additional diagnostic network traffic.

## Members are accounts

An account can have several devices in one group, each its own MLS leaf. Member
rows, rosters, member-id pages and conversation snapshots list each account once,
and `member_count`, admin counts, last-admin checks and direct-chat detection count
accounts: a 1:1 chat stays a 1:1 whatever devices either person uses. A member row's
`device_count` is how many of that account's devices are in the group; nothing else
about another account's devices reaches the bindings. A group-system row marks only
an account's first device joining or its last device leaving.

## Turning on account devices

A group can require `marmot.group.account-devices.v1`, after which a member's own devices
may add and remove each other there without an admin. A new group requires it on its
own when every founding device supports it. An existing group gets it only through
`enable_account_devices(account_ref, group_id_hex)`: one admin Commit, sent only when
the user asks, which no member can ever undo. MDK never turns it on by itself.

Before offering the action, call `account_devices_activation(account_ref, group_id_hex)`.
Offer it only on `Eligible`. Otherwise say why: `NotAdmin`, `AlreadyEnabled`,
`LegacyGroup`, `MembersNeedUpdate` (some device in the group runs a client without
support; it becomes eligible as those clients update and refresh their leaves),
`DevicesNeedReplacement` (some device's leaf carries data under the component's id
that another client wrote; an update does not clear it, so that device has to replace
its leaf or leave and be added again) or `DeviceLimitExceeded`. The answer is about the
whole group and never names which members or devices hold it back; a non-admin only
ever learns `NotAdmin`. It is advisory: `enable_account_devices` checks again and fails
with `MarmotKitError::AccountDevicesActivationRefused` and the same reason. When the
group is still settling incoming changes, the call checks the current state, then
waits for the group to settle and checks once more before committing. If that second
check refuses, the activation is dropped rather than retried, so read
`account_devices_activation` again to show the outcome.

## Group-system previews

`ChatListMessagePreviewFfi.groupSystem` and timeline `groupSystem` carry
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
client-localized rendering and layout. No client-owned reaction map is required.

## Group reporting

Swift/Kotlin expose `report_message`, `dismiss_reports`, `content_reports`,
`report_dismissals`, and `reported_message`; the C ABI mirrors these operations.
`ReportReasonFfi` supplies the NIP-56 categories. Timeline records carry
`has_reports`. Individual report records carry reporter, target author, category,
explanation and `dismissed`; each admin label carries its own event ID, admin,
explanation and timestamp. No aggregate queue, count, status, revision argument,
or winning review decision is imposed on hosts.

Pages are capped at 100 and cursors are exclusive. `reported_message` uses the ordinary
timeline record. Use existing projection subscriptions to refresh client review views.

## Moderation reports to the operator

`submit_moderation_report` privately reports an account to the deployment's
moderation team, in addition to in-group reporting. Group reporting is unchanged
and remains the primary path. The report is a NIP-56 kind-1984 rumor, sealed by
the account key and gift-wrapped per NIP-59 to the configured reports key. It
carries only the reported key, the report type from `ReportReasonFfi`, the
`ModerationReportOriginFfi` label and the trimmed explanation (at most 1,000
characters). It never carries message or group identifiers. "Block and Report"
sends `BlockAndReport` with `Other` unless the user chose a reason, and still calls
`block_user` separately.

Set `MarmotOptions.moderation_report_config` per build flavor, or call
`configure_moderation_reporting` to see why a destination was rejected. Show the
report-to-operator action only when `moderation_reporting_available()` is true;
otherwise the call fails with `ModerationReportingNotConfigured`.
`ModerationReportOutcomeFfi.accept_disposition` uses the send-summary
vocabulary. Treat `AcceptedPending` and `CompletionUnknown` as submitted, because
`catch_up_accounts` retries them, and never resubmit them. A repeat within 10
minutes returns the same `report_id`. Each account may send 20 reports per hour
(`ModerationReportRateLimited`). Sign-out and wipe delete the account's queued
reports. The C ABI mirrors these calls. See the
[wire format](../../docs/marmot-architecture/moderation-reports.md).

## Experimental device-group test builds

Ordinary constructors keep device groups disabled, including when the native library has the capability compiled in.
For a controlled host test build, compile `dev-device-groups` and open with
`Marmot.newWithExperimentalDeviceGroups(rootPath:relayUrls:options:)` (Swift) or
`Marmot.newWithExperimentalDeviceGroups(rootPath, relayUrls, options)` (Kotlin). This uses the same `MarmotOptions`
and required deployment as `newWithConfiguration`; relay policy, secret storage, attachment mode, cursor behavior,
client name and platform retain their usual meanings. A library without this feature returns
`experimental_device_groups_unavailable` before opening the root or acquiring a secret store. Use this constructor in
**every** foreground/background opener of the experimental root, a notification service extension or background
worker included. An ordinary constructor does not open an account that holds or is joining a device group: its
session fails with `MarmotKitError.Runtime` `experimental_device_groups_required` (and `start` reports it) before
anything of that account is read, sent or subscribed, so its device-group messages and unfinished device-group commits
wait for an experimental opener. Other accounts open as usual. This is an opt-in test build, not a release default.
Production settlement, retry and recovery timing remains unchanged; never enable `test-policy-overrides` in a host
artifact.

Build matching native libraries and generated bindings from the same source with the explicit flag:

```sh
./crates/marmot-uniffi/xcframework.sh --dev-device-groups
./crates/marmot-uniffi/xcframework-macos.sh --dev-device-groups
./crates/marmot-uniffi/kotlin-bindings.sh --dev-device-groups
```

Outputs go to `crates/marmot-uniffi/output-dev-device-groups/` (iOS at the root, macOS in `macos/`, Android
in `android/`). Cargo outputs use an `dev-device-groups/` child of the selected target directory; Apple
scratch uses `build/dev-device-groups/<platform>/`. The flag precedes any phase, for example
`xcframework.sh --dev-device-groups generate`; use it for every phase and transfer only matching inputs.
Ordinary invocations keep their usual outputs and remain incapable. These commands do not publish artifacts or
change release automation. Copy the matching native library, generated source and platform resources together;
source support alone does not establish a platform artifact or device test result.

For a native generated-language constructor check, `options-smoke.sh swift` (or `kotlin`) checks the unavailable
ordinary build; pass `--dev-device-groups` after the language to check an explicitly capable native library.
These local host checks do not package or validate iOS/Android device artifacts.

## Linked devices

Experimental updated clients also share invitation decisions through MDK for one authenticated admission generation
and its inherited sibling Adds. Older unidentified invitations remain local-only; a separate external Add batch or
fork can prompt again. Accept never joins/rejoins or resets explicit archive intent. Decline requests each matching
local leaf's existing Leave; later acceptance cannot cancel already-requested Leave. A decline does not reach a copy
this device already deleted locally. Private KeyPackage requests follow the ordinary stock rules. A zero-publication
`CompletionUnknown` is pending work, not proof every device departed. Keep rendering the returned invitation and
membership state. Explicit user Leave, including declining an invitation, records the same current-generation Decline
before departure publication when this device trusts a device group; archive, local deletion, sign-out and removal do
not create that choice. Unknown admissions or absent trust keep departure leaf-only. A held maximum version skips the new choice, allowing ordinary
Leave without replacing the retained winner. Invitation decisions use the existing host APIs. Ordinary constructors keep device groups disabled;
controlled host test builds use the explicit constructor described above. Custom experimental peers must update together before using
V2 sibling Welcomes; there is no capability negotiation or mixed-old-receiver guarantee.

User Leave automatically demotes a nonlast active admin account before SelfRemove. The last active admin account is
refused on all its devices before any new choice or departure publication. `can_leave` includes eligible admin Leave;
`requires_self_demote_before_leave` remains in the DTO and is false because core performs that step. The coarse
chat-list Leave action opens the authoritative command and need not imply last-admin eligibility. Sign-out stays
leaf-only and does not demote the account. A recorded Decline remains if a later eligibility check refuses departure;
a committed demotion remains if the following Leave fails. Already admitted native work retains its ordinary retry
owner. A SelfRemove applied without readable sibling attribution establishes no new automatic-Add hold, and later
repair does not promise to recover that attribution retroactively.

A local chat copy that has applied its own removal stays terminal: later branch changes do not resume convergence
on that copy. Rejoining requires a fresh valid Welcome that replaces its cryptographic state; an invitation alone is
not a guarantee of recovery. The remaining members do not promise to recommit every removal forever. An admin's
account-removal intent has at most two reissues, targeting members still in the selected membership. The rebuilt
commit must pass the author's current admin-authority check when it is sent; otherwise the queued send is refused
and retired. Device-removal cleanup has its own current-roster and remembered-key conditions. An eligible chat admin
can remove a stale member account with `remove_members`, which removes every leaf of that account, including its
active devices; it is not a per-device cleanup control. Removing a linked device is a separate device-group action.
Automatic inactivity removal is not available yet. Keep showing the selected membership and removal outcome rather
than assuming every branch has permanently removed a leaf.

At the maximum decision version, an opposite invitation choice is refused and the held winner remains; ordinary User
Leave still proceeds without writing another version. Retained invitation generations have no expiry or count cap:
a malicious currently linked device can inflate stored decisions and broadcast pages.

`linked_devices(account_ref)` returns this account's own devices as `LinkedDeviceFfi` records, read from the roster of
the device group this device trusts, for a Devices screen:

- This device comes first (`is_this_device`), then the rest by `linked_at`. Every entry is this account's own device.
- `slot_id_hex` is the device's KeyPackage slot, the handle later device actions take. `label`, `client` and
  `platform` are empty until set; `linked_by_slot_id_hex` is `None` for the device that founded the group.
- Each device writes its own `client` and `platform`: its `clientName` and `devicePlatform` options (a short name
  such as `iOS`), trimmed, and empty when blank or over 64 bytes. It writes them with its next KeyPackage
  announcement in the device group, so they appear after its next maintenance pass.
- `last_active_at` is when a heartbeat last showed a sibling running, in Unix seconds. Each running device sends one
  in the device group at most once an hour; each is dated when it was created or, if earlier, when this device read
  it. It is `None` for this device and for a sibling none of whose heartbeats has counted yet.
- `inactive` is this device's own judgement, for showing the user: 30 days have passed since a sibling's last activity
  or since this device first found it in the roster, whichever is later. It is never set for this device. `status`
  `Inactive` is the roster's own mark.
- The account's devices mark and remove inactive devices themselves. A device counts time only while it is caught up
  with its device group, and restarts every count after more than 24 hours without being caught up. About 30 days
  after a sibling was last heard from, a caught-up device marks it `Inactive`: show "Remove" and "Keep" for a device
  whose `status` is `Inactive` and whose `keep_while_inactive` is off. About 90 days after, a device still marked
  `Inactive` without **Keep while inactive** is removed as by `remove_linked_device`, except that its KeyPackage slot
  is left on the relays. A marked device that is running clears its own mark. A device catches up only about 30 days
  back: one that comes back later can't, and is removed at 90 days like one that never came back
  (`device_group_stalled` below).
- The list is empty until this device trusts a device group (a single-device account has none), and in ordinary opens
  without explicit experimental device-group intent.
- The device group's own events never reach hosts. Re-read on `MarmotEventFfi::LinkedDevicesChanged`, which carries no
  device or group identities. It also fires once each time the account's worker opens or reconnects, so it may fire
  with no visible change.

Chat history from another device: each imported `TimelineMessageRecordFfi` names its source in `imported_from`, and
`chat_history_imports(account_ref)` lists each held chat's history as `Receiving` (`retrying` once an attempt to get its
bundle failed) or `Imported`. The list is empty and the event silent in ordinary opens without explicit experimental
device-group intent. Draw "Imported from <device>" where rows change from imported to live, and say "another device" for an empty
`device_label`. Re-read the list on `MarmotEventFfi::ChatHistoryImportsChanged`, which fires whenever its answer
changes, a source device's rename or removal included; re-read rows on `LinkedDevicesChanged` for their new names.

`rename_linked_device(account_ref, slot_id_hex, label)` renames any of the account's devices, this one included, with
one roster commit in the device group:

- Only the label changes. It is at most 64 bytes of UTF-8; an empty label clears it.
- It is refused with nothing sent (`DeviceGroupRefused`) in ordinary opens, for a label that is too long, without a
  device group, for a slot the roster doesn't list, and while the device group has an earlier change of this device's
  in flight (`device_group_busy`). Retry that last one later; a commit then could build on a roster that is about to
  change.
- A rename whose commit loses a fork is made again on a later maintenance pass, unless another rename or settings edit of that device
  won; that one stands. Show the label `linked_devices` returns after `LinkedDevicesChanged`, not the one the user typed.

`update_linked_device_settings(account_ref, slot_id_hex, add_to_all_chats, bring_history, keep_while_inactive)`
changes any linked device's supplied settings, this device included. Each setting is optional: omitted values come
from the current roster on the account worker, so changing one toggle does not restore another from a stale screen.
A patch that still matches after earlier-edit recovery sends no new edit. Enabling **Add to all my chats** permits
eligible direct post-link Adds while that flow is still adding, and gap filling under its conditions; turning it off
does not leave joined chats. The approving device's direct post-link pass sends no gap-fill claim (kind 458). With
three or more devices, it can race another sibling's gap filling and cause extra Add attempts, private-KeyPackage
consumption, or Commits and convergence passes; selected-parent presence checks and ordinary branch selection still
apply. **Bring chat history** applies to future sibling Adds and transfers still owed; enabling
it does not backfill chats already joined or recreate a transfer discarded while it was off. **Keep while inactive**
stops automatic removal of an `Inactive` device; it does not stop the mark, explicit removal or sign-out.

Automatic chat Adds can wait for compatible private KeyPackages. Packages can satisfy stock time checks while
lacking a required chat capability; when they cover ordinary stock need, that mismatch alone sends no new request.
An issuer's ordinary upkeep stops counting packages that no longer advertise its current capabilities and can hand
over compatible replacements. Fresh supply can also follow older stock being used by other chats or passing its
lifetime midpoint, or a stock request needed for another reason. Repeat requests for an unchanged unmet need
keep their hourly throttle; an increased need can make a request due at the next upkeep. Progress depends on the
issuer and device group being available, with no fast or guaranteed discovery deadline for this wait.

On the editing device, new automatic Adds and history transfers wait for a differing local setting intention to
settle. Existing history debt keeps its original expiry; once ready, a history setting that is off discards that debt.
This does not recall deliveries already handed off or change what another device sends before it learns the edit.

A rename and a settings change share one recovery record. Before accepting another edit of that device, the runtime
tries the existing recovery of an earlier lost edit and re-reads the roster. Retry `device_group_busy` only while it
remains unsettled. A successful no-op never leaves an opposite lost intention to apply later. A competing user edit
of that device wins as a whole, even if it changed a different toggle. Once an edit is retired because another edit
stands or the device leaves the roster, a later branch that removes that rival does not restore the retired local
choice. To apply it again, edit the device once it is listed in the selected roster. Refresh the displayed label and flags on
`LinkedDevicesChanged`. These commands remain behind the device-group development gate.

### Explicit local device-group reset before fresh pairing

`DeviceLinkSnapshotFfi.device_group_stalled` says this device can no longer catch up with its device group: automatic
recovery gave up on a change it missed, or its copy is unrecoverable. It cannot see or clear an `Inactive` mark, and
its siblings remove it about 90 days after they last heard from it. Offer the reset below, then fresh pairing. Re-read
on `DeviceLinkChanged`, which fires when it changes.

In an experimental device-group build, offer `reset_device_group_for_repair(account_ref)` only after the user chooses
to discard this device's local hidden device-group copy. It keeps account credentials, the stable device slot and
ordinary chats, history, drafts and settings. It abandons old link-bound preparations; retained shared values and
security decisions can synchronize again under ordinary rules. It sends no removal and repairs no ordinary-chat
membership. It is separate from sign-out, account removal and a Move. An already unlinked
device cannot use it to bypass removal.

Reset acts on this device, not the other slot named by a sign-in row. Check both devices before choosing which local
copy to discard. If the approver still lists this slot, fresh admission can remain refused; removing that slot writes
removal evidence and is not a universal shortcut back in. If no other device retains the old group, a later first
link can create a different group: its discarded roster continuity is not restored. Independently retained local
backup/security records are kept.

The returned link snapshot has no trusted old copy to restore. Reset does not publish a new KeyPackage. Use the normal
`rotate_key_package(account_ref)` publication action, then start a fresh code-comparison flow and confirm on both
devices; the fresh Welcome can join the same group id under the existing exact sender/group/KeyPackage checks. Reset
alone does not guarantee admission: the approver may still list the slot or its old leaf, reject it, or be full.
Existing duplicate, removal, capacity and authentication rules still apply. Cancellation or failure after reset can
leave needs-link; a restart before confirmation can require a new exchange. A fresh link already confirmed retains
its existing durable Welcome-wait/restart rules. Retained chat data guarantees neither current membership nor missing
history backfill, and admitted work is not recalled.

Active pairing, an unfinished Move or unsettled native device-group work refuses with `device_group_busy`. Ordinary
settlement may unblock it, but no deadline is promised. No trusted copy returns `no_device_group`; the command never
creates a link or a new device slot. Rebuild matching native/generated bindings for the additive action and sign-in
field. Actual app display adoption is separate.

### Moving this device to another device group

In an experimental device-group build, start the same compared-code linking flow on a device that already trusts a
device group to move only that device. Keep showing the existing group while `DeviceLinkSnapshotFfi.moves` is
`WaitingForWelcome` or `Joining`. Joining the destination alone does not switch trust: `Made` requires this device's
first selected authenticated change there. Its trust then switches once, with ordinary full small-state synchronization
at unchanged versions. Chats and chat membership stay in place; the move does not promise delivery between the two
device groups. Released binding builds still provide no working linking entry.

At most one confirmed move link is kept, with its Welcome expectation while that Welcome is pending. After restart
another code comparison can begin, but if the earlier move is still pending at confirmation the new exchange ends
before this device sends its Confirm (`LinkFailed` locally, `CannotLink` on the answering device). The earlier link
and any still-live expectation stay unchanged; no second link approval or Add is made.

If this device moves while another device's link it approved is still pending, its old local prompt can end as failed
and its automatic chat additions can be skipped even if the other device joined. Finish that link before moving when
its completion and chat additions matter. Moving does not undo the other device's admitted membership.

Each move has an opaque `move_id`. `old_siblings` names recognized devices left in the old group; while
`question_suppressed` is true, offer to link that device here rather than treating its sign-in as unknown.
`dismiss_device_group_move_sibling(account_ref, move_id, slot_id_hex)` ends only that local recognition hint; it does
not remove or link a device. A later confirmed link or selected departure ends the hint too. Slots in
`overridden_rejection_slots` were already devices in the destination, so that destination entry took precedence over
an old rejection. Moves carry rejected slots with their original ages, never rejected KeyPackages.

`LinkedDeviceStatusFfi::Moved` is the old group's own status for a moving device; its cleanup leaves the device's
ordinary chats alone. Already admitted old-group traffic may finish through normal delivery rules before local old-group
storage is forgotten; there is no immediate-quiet deadline or cancellation promise. Several old siblings can race
cleanup, costing extra Commits and convergence passes under normal branch selection. A known failed link before Made
forgets only the destination and keeps old trust. An unrecoverable destination keeps that trust while ordinary repair
applies; it may stay pending indefinitely and need manual local recovery. While pending, this device cannot confirm
another move or answer new pairing Requests. Corrupt or unreadable local move facts can
fail progress/status reads and need manual local recovery or reset followed by a fresh compared-code link. Do not
infer an unlinked state or expect an unlink notification for those errors, and never reconstruct old trust.
Recognition hints suppress questions only on the mover. Old siblings can ask “Was this you?” after cleanup; the user
can dismiss that prompt. An old in-flight chat Add can leave a membership leaf whose Welcome no longer reaches this
device. Automatic gap filling may not replace that leaf; manual chat membership repair can be needed. Moving adds no
duplicate-leaf cleanup or recall of admitted Adds.

### This device unlinked

When another of the account's devices removes this one with `remove_linked_device`, the account stops on this device
once it reads the removal, and nothing more is sent from it (mdk#2628):

- `MarmotEventFfi::DeviceUnlinked { account_id_hex, account_label }` fires once, after the account is signed out. From
  then on the account's `AccountSummaryFfi` has `unlinked` and `signed_out` set, and both stay set.
- Show that this device was unlinked from the account, and stop showing its local history.
- Signing in to it, logging in to it or importing its key fails with `MarmotKitError::AccountUnlinked`. Offer `sign_out_and_wipe`, which skips leaving the
  account's chats and deleting its KeyPackage slot, since the other devices did both. Signing in again is then a new
  sign-in that links this device anew.

### Signing out with linked devices

`sign_out_and_wipe` signs out through the account's other devices when this device has a linked device that is not
signing out too (mdk#2628):

- It first records in the device group that it is leaving and waits for that to settle, which can take about 30
  seconds; show progress. It then leaves only the chats no other device can take it out of, deletes its KeyPackage
  slot and wipes. The other devices remove it from the device group and from the rest.
- `WipeOutcomeFfi.groups_left_to_siblings` counts the chats it left to the other devices; `groups_left` counts those it
  left itself.
- When it can't ask them in time, it tries to leave every chat itself, reporting any it can't in
  `group_leave_failures`, and sets `siblings_not_reached`. Tell the user their other devices couldn't be asked, and
  that those devices may still list this one until the user removes it from one of them.
- The other devices list it with `LinkedDeviceStatusFfi::Leaving` until they remove it, then drop it.

Signing out is device-only and does not submit an account-wide Leave decision or automatically demote the account.
An active-admin account cannot self-remove, even with another admin present, so this device's leaf can remain in an
admin chat. A separate admin-policy change affects the account on all its devices. Before the account can leave the
chat entirely, another account must be an active admin; an eligible sibling can still remove this device while the
account remains an admin. This limit also applies without linked devices.

Sibling assistance requires a trusted device group with another Active or Inactive device and this device's own
roster entry already carrying its tag signature key. Removal also needs a chat that supports same-account device
removal and the required tagged leaves;
`groups_left_to_siblings` is a handoff, not a completed-removal receipt. `groups_left` counts successful local leave
calls, not confirmed membership removal. The call still attempts local account deletion after remote leave
failures. Show the chats in `group_leave_failures` and check `local_cleanup.completed` independently; local cleanup
completion does not establish that this device left every chat.

### Overdue KeyPackage refresh

While this device trusts a device group, it announces each KeyPackage in its own roster entry before publishing it, so
a device group that can't take that Commit holds the refresh back. `key_package_refresh_overdue(account_ref)` is true
once the KeyPackage this device would publish is still unannounced and its slot's newest publication is a week old.
Inviters stop treating the device as fresh at 30 days, so tell the user. A routine refresh never shows, and neither
does one that is announced but failing at the relays. Re-read on `MarmotEventFfi::KeyPackageRefreshOverdueChanged`,
which carries no device or group identities and also fires once each time the account's worker opens or reconnects.
It is false in ordinary opens without explicit experimental device-group intent.

## Unrecognized sign-ins

`unrecognized_sign_ins(account_ref)` returns sign-ins of this account that this device does not recognize as
`UnrecognizedSignInFfi` records, for a "Was this you?" prompt:

- Each is a fresh, valid KeyPackage of the account in a slot that neither this device nor its device group's roster
  knows. The earliest to appear comes first.
- `before_this_device` means this device's first check found it, so it was signed in before this device: ask whether
  the user still has it, with `last_seen_at`. For any other, ask whether it was them, with `client` and
  `appeared_at`. `client` is display only.
- `state` is `Prompt`, `NotNow`, or `LinkedElsewhere`/`RejectedElsewhere` when another device answered while the
  prompt waited here. `linked_by_slot_id_hex` names the linking device for `LinkedElsewhere`.
- `previously_linked_here` adds context only when this device retains a made approval for that slot in its current
  trusted group but its settled selected roster no longer lists it. Offer “A slot previously linked here is missing
  from this device's current device list. Open both devices to check the link.” It does not authenticate the current
  publication or prove permanent loss. Known local removal/rejection or matching retained departure evidence suppresses
  the context, conservatively including older departures of the same slot/key. Incomplete records, expired evidence,
  slot reuse and discovery also bound it. False means no affirmative local context, not “never linked.” Keep existing Not now/dismiss behavior; silence/decryption failure is not a reset
  signal. The user can explicitly choose [local reset](#explicit-local-device-group-reset-before-fresh-pairing).
- `answer_sign_in(account_ref, slot_id_hex, response)` takes `NotNow`, `Reject` or `Dismiss`. `Reject` drops the sign-in
  from this device's list and records its slot as rejected in the device group's roster; with no device group yet, it
  waits on this device. On another device, a new sign-in whose prompt still waits there turns `RejectedElsewhere` and
  stays until `Dismiss`; one put off with `NotNow`, or found before that device, leaves its list. `Dismiss` only ends a
  prompt another device answered. Linking one is device pairing's.
- The account checks at open, every six hours, and soon after one of its KeyPackages arrives live.
  `check_sign_ins(account_ref)` checks now and returns the list after the check.
- Re-read on `MarmotEventFfi::UnrecognizedSignInsChanged`, which carries no slots. It also fires once each time the
  account's worker opens or reconnects, so it may fire with no visible change.
- The list is empty in ordinary opens without explicit experimental device-group intent.
- `start_fresh(account_ref)` is "No, start fresh" when the user no longer has the devices the first check found: every
  sign-in from before this device is answered `NotNow`, now and when one is listed later. It rejects nothing and
  raises no compromise warning, so one of those devices can still link this one. It is refused before the first check
  (`sign_ins_unchecked`) and once this device trusts a device group (`device_group_exists`). `started_fresh` says
  whether the device did so and still has no device group: say that only chats it is invited to from now on are here.
  Re-read it after `start_fresh` and on `LinkedDevicesChanged`.

## Compromise warning

`compromise_warning(account_ref)` returns the account's open compromise warning on this device as
`CompromiseWarningItemFfi` records, the earliest gathered first. An empty list means no warning is open:

- Each item means someone holding the account's signing key, or a session with its remote signer, published where the
  account's devices did not. `RejectedSignIn` is a sign-in answered This wasn't me, on this device or another;
  `ForeignOwnSlotKeyPackage` is a KeyPackage this device found in its own slot that it did not make, with its
  `key_package_ref_hex`. Only the device that found it warns of it, and it has replaced it. `slot_id_hex` and
  `occurred_at` say where and when.
- Later releases add reasons. Show one the app does not know as a generic one.
- The warning gathers this device's rejections and those in its device group's roster, so a rejection made on another
  device warns here too. Rejections already in the first roster this device trusts count as seen: the user saw them on
  the devices that were there. A rejected sign-in leaves the warning once its slot is linked as a device.
- `dismiss_compromise_warning(account_ref)` marks everything the warning gathers as seen, on this device only. It stays
  closed until a new rejection arrives, and a rejection that branch selection drops and brings back stays seen.
- The app writes the wording, and never says the account's devices stopped them.
- Re-read on `MarmotEventFfi::CompromiseWarningChanged`, which carries no slots. It also fires once each time the
  account's worker opens, so it may fire with no visible change.
- The list is empty in ordinary opens without explicit experimental device-group intent.

## Linking a new device

Linking a new device of the account shows the same seven emoji on both devices, and each user confirms. Every call
returns a `DeviceLinkSnapshotFfi`, and every call requires the explicit experimental build and constructor described above:

- The new device calls `start_device_link(account_ref)` and shows `new_device`: `WaitingForAnswer` (ask the user to
  open the app on a device already signed in), then `Comparing` with the code. Offer "They match"
  (`confirm_device_link_match`) and cancel (`cancel_device_link`). It then shows `WaitingForOtherDevice`, `Joining`,
  and `Linked`, or `Ended` with a reason.
- A device already signed in shows each entry in `prompts`. `Comparing` shows the code; offer a label field, "Add to
  all my chats" and "Bring chat history" (both on by default), Link device (`link_device`) and Not now
  (`decline_device_link`). After Link device it shows `Linking` until the new device's first change in the device group
  arrives, then `Linked`; with none within an hour, the device is removed again and both sides show `LinkFailed`.
  Other states say why Link isn't offered, or `AddedElsewhere`: "<device_label> was added by <added_by_label>".
- Each emoji carries an English `description` for screen readers. Users compare the pictures, not the descriptions.
- `device_link_snapshot(account_ref)` reads linking without changing it. Re-read on `MarmotEventFfi::DeviceLinkChanged`,
  which carries no device, session or group identities. It also fires once each time the account's worker opens or
  reconnects. Live comparison sessions are lost then; admitted moves resume from durable progress. Inspect `moves`
  rather than assuming an interrupted comparison undid an admitted move.

## Backup recovery and background conditions

Backup setup and manual restore require `devDeviceGroups`, which is off by default, and a build with experimental
device-group support. MDK owns backup selection, due work, download limits, import validation and membership checks;
the host supplies platform facts, renders status and obtains recovery words from the user.

Use `beginRecoveryWords(accountRef)` to generate 12 new words for backup setup. Display them once, then ask for the
words at the two returned **1-based** `confirmPositions`, in order, and pass those answers to `confirmRecoveryWords`.
`cancelRecoveryWords` forgets the pending setup; `backupSettings` reads selected account settings.
`turnOffBackups` disables future account backups without deleting existing archives. A busy or failed confirmation
keeps the core setup available for another try. Read settings again rather than treating a submitted choice as settled.

Report `setRuntimeBackupBackgroundConditions(wifi, charging)` once per runtime, before workers exist and on
changes. Background writer work requires **both Wi-Fi and charging**. Reports survive account-worker restarts; a new
runtime starts closed. An admitted pass settles after false, while later passes wait. The account-shaped
`setBackupBackgroundConditions` remains a compatibility wrapper that validates the active account before reporting
the same runtime-wide facts and never starts its worker. Manual restore is independent.

An OS background task can await `runDueBackupPass(accountRef)`: it joins the current pass or tries ordinary due
admission once. The admission wait includes other queued work and startup catch-up. `NotStarted` admits nothing;
`FinishedAttempt` means the pass's serialized settlement attempt and
credit release ended. It is not a publication-success receipt, forced backup, future-due wait or whole-runtime idle
barrier. Cancelling this caller detaches its wait; worker stop/replacement returns `TransportClosed`. The host
bounds its OS execution opportunity, since a queued caller's wait has no additional timeout, and supplies fresh facts
to each new runtime. Disabled device-group support returns
`NotStarted` without starting a worker; the fact-report method itself is local and available.

`beginBackupRestore(accountRef, words)` starts one manual history-only operation per account and returns its status.
Old words remain usable independently of the current backup key; restore never enables backups or changes that key.
Only chats whose current selected MLS tree contains this device's own leaf can receive history. Unknown chats retain
private availability metadata, without creating or joining a chat. After a real join, `backupHistoryAvailability`
returns words-again hints for that current chat. Archived preferences and invitation decisions are not applied.

Use `backupRestoreStatus` or `watchBackupRestore` for aggregate progress. A watch offers its initial snapshot once and
then `next` updates; closing it does **not** cancel work. `Complete` means eligible work settled, not that all history
was found or that a backup pointer existed. `Partial` retains committed history; `Unavailable` can require a later
manual retry. Availability revisions wake the same watch; read the current chat's hints again. Operation tokens are
opaque, ephemeral, account-scoped strings: return the exact token to `cancelBackupRestore`. A stale valid token returns
false and cannot cancel a newer operation; malformed tokens are rejected. Cancellation and shutdown release owned
secrets and leave committed history intact. Retry explicitly with the words again; there is no durable secret-backed resume.

Timeline pages and prepared conversation rows expose `historyImportProvenance`: `Device` carries a device slot,
`Backup` carries an archive identity. Render backup rows as restored from backup, never as an unnamed device. The
archive identity does not prove original writer, historical authorship or historical membership. The legacy
`importedFrom` field remains sibling-only; its absence alone does not identify live rows.

Never persist, log or include recovery words in diagnostics. Clear host-owned input and displayed copies promptly.
MDK guards its owned queued phrases and confirmation answers and zeroizes managed secret buffers on release; generated
Swift/Kotlin strings, caller copies and upstream parser/hash/compiler scratch are outside that guarantee. Dropping a
managed string does not promise erasure. Do not log whole DTOs even when a particular Rust Debug implementation redacts them.

## History may be incomplete notices

Automatic recovery stops retrying an obligation after a fixed budget of attempts that
recover and certify nothing. Each such parked occurrence is a notice the user should see
as "history may be incomplete":

- `history_notices(account_ref)` returns `HistoryNoticeFfi` records, oldest first: an
  opaque `notice_id`, a `HistoryNoticeCauseFfi` for the host's wording, `group_id_hex`
  for a group-scoped occurrence (an epoch gap) or `None` when the account as a whole is
  affected (delivery or notification loss, incremental or explicit history), and an
  optional `parked_at_ms`. It reads local durable state and never touches the network.
- `group_recovery_status` sets `history_may_be_incomplete` and lists the group's own
  `history_notice_ids`. Show a banner in that conversation; account-wide notices belong
  in an account-level surface instead.
- `MarmotEventFfi::HistoryNoticesChanged` fires when a notice appears (recovery parked),
  disappears (new evidence re-armed recovery, or it was dismissed), or is replaced. Re-read
  the list; a group whose own notices changed also receives `GroupStateUpdated`.
- `dismiss_history_notice(account_ref, notice_id)` records the user's decision durably,
  as its own outcome and never as recovered history. It returns `false` for a stale id;
  re-read and show the current notices. After a delivery-loss dismissal the transport
  cursor can advance again once no loss recovery remains pending.

Do not dismiss on the user's behalf, and do not persist `notice_id` as a group or
account identity: it changes whenever recovery re-arms. A dismissed occurrence never
comes back, but genuinely new evidence can raise a new notice: new loss, a higher missing
epoch, a later startup's incremental comparison, or a new explicit repair. Explicit
full-history repair remains available and can still complete parked history that its
comparison of the retained window certifies. Notices carry no relay, message or key identities; keep them out of
analytics. C callers: see the [C guide](../marmot-c/README.md#history-may-be-incomplete-notices).

`account_recovery_status(account_ref)` returns `AccountRecoveryStatusFfi`: the groups whose
history is still being fetched (`catching_up_group_ids_hex`), whether the inbox's is
(`inbox_catching_up`), and every notice as `history_notices` lists them. Show the first two
as "catching up" and re-read on `MarmotEventFfi::RecoveryStatusChanged`. The recovery
runner supplies those fields. Current epoch-gap exhaustion emits `EpochGap`; coverage-ledger
parks emit `HistoryNoticeCauseFfi::UnprovenHistory` without attributing the original reason
history was owed. Other cause labels preserve compatibility; keep exhaustive switches.

Durably and natively `Unrecoverable` copies start authenticated automatic rejoin in the existing account workers.
Hosts use the existing Repair action to rearm an eligible parked episode; restarting alone does not reset its budget.
A reachable eligible admin and eventual delivery are required. Usable forks still need explicit replacement
consent, and pruned epoch secrets are not restored. See the
[automatic rejoin contract](../../docs/marmot-architecture/invitation-recovery.md#automatic-rejoin-of-an-unrecoverable-copy).

While unresolved epoch-gap recovery covers a group's current local epoch, the group may
have moved past this device. Group changes (invite, remove, admin changes, profile, image,
retention, disbanding and app components) then fail with `MarmotKitError::GroupCatchingUp`:
a change committed from a stale epoch can split the group for everyone. Messages and
leaving are not affected.

The check is advisory, because the evidence behind it cannot be authenticated. Ask the
user, for example: "This chat may be out of date on this device. Changing the group now
could split it for everyone. Wait for it to sync, or continue anyway?" To continue, call
`acknowledge_group_catching_up(account_ref, group_id_hex)` and retry the change. The
acknowledgement admits one change attempt at the device's current epoch, is consumed even
if that attempt fails, and is not persisted. Use the
strongest wording for invites: a member invited onto a branch that later loses is left
with a Welcome that no longer works. Without an acknowledgement, the check lifts once
recovery catches the group up or the device moves past that epoch. Dismissing the group's
history notice does not lift it. Scheduled self-updates wait up to a day for the group to
catch up, then proceed.

A group change counts as published once one group relay accepts it, and MDK keeps
retrying the other group relays with the same event. Until they accept it, members who
read only those relays cannot follow the group. Once a change has been owed to a relay for
two minutes (a healthy slower relay is retried after 30 seconds), group changes fail with
`MarmotKitError::GroupCommitUndelivered` (mdk#2255). `group_commit_delivery(account_ref,
group_id_hex)` returns the oldest change still owed to a relay, with the relays owing it and
`since` (when the first relay accepted it), or `None`. It is reported immediately, so a host
can show "not delivered to every relay yet" before the user tries a change; a `Some` result
alone does not mean the next change fails. No event announces delivery completing, so poll
while showing it. This check is advisory too, because groups
often list a relay that is gone for good: once the user accepts that members on those
relays may not follow, call `acknowledge_group_commit_undelivered(account_ref,
group_id_hex)` and retry. Like the catching-up acknowledgement, it admits one change
attempt and is not persisted. A change can need both acknowledgements; each survives the
other check refusing the attempt. Scheduled self-updates wait up to an hour for delivery,
then proceed.

## File-backed media upload

Use `uploadMediaFiles` for private regular-file inputs instead of sending a
whole-file byte array across the binding. `uploadMediaFilesWithClientToken`
preserves durable local-send admission; probe `localSendStatus` after an unknown
outcome before another upload. Keep the host source valid until return, use one
`MediaFileTransferControlFfi` per operation, and explicitly cancel it rather than
only dropping the host's wait. Every source is copied into the account's
encrypted media store before PUT, and the ciphertext streams from that copy
without being written to disk. A source the disk cannot hold beyond the
attachment policy's disk reserve fails with `StorageFull` before anything is
uploaded; ask the user to free space. The counter is monotonic processed bytes
(copy, digest pass, then transfer), not a percentage.

Uploads return `MediaAttachmentReferenceFfi.sourceEpochIdentity`, a local branch
identity that must be preserved unchanged when saving a reference or passing it
to `sendMediaAttachments`, `sendTaggedMedia`, or `reactWithMedia`. A send requires
both the upload epoch and that exact branch to remain current. A branch change
can invalidate an upload even when the epoch number stays the same. References
received from peers or saved before this field existed have no upload identity:
re-upload their retained bytes before sending them. Downloads of those references
remain supported. This identity is local metadata and is never included in
`imeta` or shared with peers.

Cancellation observed before message admission starts prevents publication.
Admission is not interruptible once started, including while durable acceptance
is pending. File-backed uploads have no fixed worker-response timeout;
per-endpoint network deadlines still apply.

`maxFileMediaCiphertextBytes` includes a 16-byte AEAD tag for each attachment in
the batch. This is a finite implementation bound, not a claimed server maximum.
Uploads try policy endpoints in order; ordinary rejection or invalid descriptors
fall through, while signer denial and cancellation stop the operation. An
explicit endpoint override intentionally selects only that endpoint. Receiver
acquisition streams large bodies into private files, resumes protected ciphertext
where valid, and authenticates before publishing bounded readable local assets.
The stored copy becomes the sender's local attachment once the message is
confirmed, with no retention budget. Preview limits and the legacy byte-array
API bounds are not increased.

See [the upload reference](API-REFERENCE.md#marmotupload_media_files) and
[local-send ownership](LOCAL-SENDS.md). C hosts use the
[file-backed C inputs and control](../marmot-c/README.md#file-backed-media-upload).

## Bounded attachment history

Use the asynchronous attachment history page/version methods for canonical media-library
discovery. See [the native handoff](ATTACHMENT-HISTORY.md) for filtering, refresh,
removal and cursor ownership. `list_media` remains a compatibility API.
Custom reaction artwork uses the bounded `reactionAttachment` lookup with the
reaction event ID, followed by the same acquisition and local-read path as chat
attachments; see [reaction artwork](ATTACHMENT-HISTORY.md#reaction-artwork).

## Local attachment access

Use `attachmentLocalAssets` to locate verified retained bytes for visible source
slots, then `readAttachmentAsset` for bounded local chunks without network work.
See [the native attachment handoff](ATTACHMENT-ACCESS.md) for unavailable/EOF semantics,
source revalidation, host buffer ownership and integration guidance. For an OS surface
that needs a real file (package installer, share sheet, "open with", Quick Look), use
`openAttachmentHandoff` and release its lease when done; see
[handoff leases](ATTACHMENT-ACCESS.md#handoff-leases). A Manage storage screen reads
usage and largest-first listings, removes attachments in bulk and sets the opt-in
"Keep media" window; see
[Manage storage](ATTACHMENT-ACCESS.md#manage-storage). Acquisition
defaults on with bounded per-account policy. Native progress snapshots/subscriptions
and durable cancellation, retry, remove and download-again controls use the same source slots.

## Audit v5 recording and delivery

v5 replaces v4 as the audit format. `AuditLogSettingsFfi.enabled` remains the recording opt-in.
Account sessions and the live runtime write only `marmot-forensics-audit/v5` to
`audit-<engine_id>-v5.jsonl`; no new v4 files are written, and existing v4 files remain on disk.
Hosts that record audit logs must configure v5 delivery, or new evidence never leaves the
device. Deploy a receiver that accepts every v5 event kind first.

To deliver v5, supply a dedicated OTLP `/v1/logs` destination and bearer token
with `set_audit_otlp_config_v5(AuditOtlpConfigV5Ffi)`. The configuration is held in memory, so
apply it on every launch; the returned record omits the token. Set `enabled: false` to remove delivery configuration.
An exact loopback endpoint requires `allow_loopback_dev: true`; public endpoints require HTTPS.
The host then calls `post_audit_log_tracker_update_v5()`, in place of
`post_audit_log_tracker_update()`, for an immediate pass; the existing
audit tracker also uses this configuration on its activity triggers with the usual batching,
retry, and shutdown behavior. The v5 result reports accepted batches, pending accounts, blocked
accounts, and idle accounts separately from legacy v4 uploads. No host should infer receiver
acceptance from an empty v4 `uploaded` list. The v4 whole-file Goggles endpoint never receives
v5 records.

## Legacy audit v4 upload

The v4 whole-file route only drains v4 files written before 0.11.0; keep its configuration until
they are gone, and do not build new v4 infrastructure. Whole-file uploads accept only
`marmot-forensics-audit/v4`; older local files are never migrated or sent.
App construction automatically removes recognized v1-v3 forensic files and rotated segments after acquiring the
root lease, including files in failed account-wipe remnants, even with recording disabled. V4 files and the separate
key-reveal log are preserved; failures are nonfatal and retried on the next open. No additional Swift/Kotlin cleanup
call is needed.

Use `AuditLogTrackerConfigV4Ffi` with `AuditLogUploadSourceV4Ffi.hardwareModel` in place of the old source record
and its `deviceLabel`. The versioned config type changes the setter ABI checksum so old generated bindings cannot
silently reinterpret a device label as a hardware model.
Populate this field from system model information (e.g. `iPhone17,3` or `Pixel 9a`), never from a device name,
hostname or serial number. Omit it if unavailable. Platform and app version are unchanged.
Uploads of leftover v4 files still need a v4-compatible Goggles endpoint; new evidence goes to v5.

Native metadata lift/lower checks: `./crates/marmot-uniffi/audit-v4-smoke.sh swift` and
`MDK_KOTLIN_CLASSPATH=<JNA:Android:annotations:coroutines jars> ./crates/marmot-uniffi/audit-v4-smoke.sh kotlin`.
These regenerate host bindings and execute DTO round trips; platform package builds remain separate.

## Building local bindings

The Rust API in `src/` is the source of truth for both generated Swift and generated Kotlin. Platform scripts only
package that shared surface:

- `./crates/marmot-uniffi/xcframework.sh` builds `output/MarmotKit.xcframework` plus `output/MarmotKit.swift` and
  `output/PrivacyInfo.xcprivacy` for iOS.
- `./crates/marmot-uniffi/xcframework-macos.sh` builds `output/macos/MarmotKit.xcframework` plus
  `output/macos/MarmotKit.swift` and `output/macos/PrivacyInfo.xcprivacy` for macOS on Apple Silicon
  (`aarch64-apple-darwin`). Its output directory is separate from the iOS one so building both in one workspace
  cannot clobber either artifact.
- `./crates/marmot-uniffi/kotlin-bindings.sh` builds `output/android/kotlin/dev/ipf/marmotkit/marmot_uniffi.kt` plus
  Android `jniLibs` shared libraries.

The generated Swift file is platform-independent: `output/MarmotKit.swift` and `output/macos/MarmotKit.swift` are the
same UniFFI surface, and releases publish it once. The Kotlin binding is generated from the same host library metadata,
so it exposes the same `Marmot` object, subscription objects, records, enums, and error variants.

No generated Swift or Kotlin files are committed here; the output directories are ignored because generated bindings
and packaged native libraries are derived artifacts. Regenerate them from this crate before vendoring into an app
repository. For published artifacts, exact release and snapshot URLs, checksums, provenance and generated-source
synchronization rules, see [`DISTRIBUTION.md`](DISTRIBUTION.md).

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
for the build-only benchmark workflow.

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

Build all Android ABIs, or a subset:

```sh
./crates/marmot-uniffi/kotlin-bindings.sh
ANDROID_ABIS="arm64-v8a x86_64" ./crates/marmot-uniffi/kotlin-bindings.sh
```

Generated Kotlin uses package `dev.ipf.marmotkit`, loads `libmarmot_uniffi.so`, and requires the normal
UniFFI Kotlin runtime dependencies used by the generated file: JNA, Kotlin coroutines, and AndroidX annotations.

The script keeps the host library's UniFFI metadata intact while stripping debug and static symbol sections from each
packaged Android JNI library. The two 64-bit ABIs (`arm64-v8a`, `x86_64`) are linked with 16 KB ELF `PT_LOAD`
alignment for Google Play's 16 KB page-size check; the 32-bit ABIs stay on the NDK's default page size. Aligning the
app bundle ZIP does not change those segments. Each published Android archive includes an `android-elf.json` report of
the packaged libraries' hashes and observed load alignments; see [DISTRIBUTION.md](DISTRIBUTION.md#android). That
report does not by itself prove an app's Play Console result.

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

## Release profile

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
The latest recorded comparison is in [release-profile-measurements.md](release-profile-measurements.md).

The automatic `MarmotKit Release Profile` workflow (`bindings-profile.yml`) is an exact-head packaging
check, not a comparison benchmark. It builds Kotlin/Swift generation and every
Android or Apple native target once in parallel, transfers those inputs only
within the current workflow run, verifies their source, builder, toolchain,
profile, feature and run provenance, then assembles and validates the Android,
iOS and macOS candidate packages. Full packaging is opt-in on pull requests:
`ci:android` selects Kotlin generation and all four Android ABIs, `ci:apple`
selects the Apple inputs and packages, and `ci:full` selects both platforms.
After adding a packaging label, re-run all candidate-workflow jobs or push a
new commit; the workflow reads the current labels. Ordinary PRs retain Rust compilation/API and
packaging-contract checks without building complete candidate bundles.
Android target compilation, NDK checks and native linking are deferred unless
explicitly selected, including for changes to the UniFFI crate.
Matching `master` pushes always build the complete matrix and open an issue
when it fails; later pushes do not cancel running or queued candidate builds.
Candidate builds use no Cargo cache, so
every run compiles from a clean target directory.
The workflow has no schedule of its own. The
[nightly release](../../release.md#nightly-builds) builds and validates the
same Android and Apple packages from `master`, but only on nights it does not
skip: it skips when master has no new green commit or is not on an
`X.Y.Z-dev` version, and when releases or snapshots keep the macOS runners busy
for three hours. It does not run `test-native-archive.py`; matching `master`
pushes do.

Baseline-versus-candidate measurements are intentionally manual. Run the
`MarmotKit Release Profile Measurements` workflow from `master` with the full
lowercase SHA that needs fresh evidence (it must already be fetchable from GitHub):

```sh
gh workflow run bindings-profile-measurement.yml \
  --ref master \
  -f source_sha="$(git rev-parse HEAD)"
```

The non-publishing run fails closed unless checkout matches the SHA exactly, and uploads separate
Linux/Android/CPU and Apple reports, hashes, raw Criterion output and build logs. A failed or incomplete
surface keeps the final comparison check red. Local equivalents:

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

## Apple privacy resources

Apple exporters use raw static-library slices and publish a matching privacy manifest for the consuming Swift target.
See the [privacy audit and adoption guide](apple-privacy/README.md) for declarations, archive validation, host
integration changes, and unresolved release questions.

## Account attachment history

`account_attachment_history_page` reads bounded indexed attachment candidates across one local account. Original album slots retain source identity and shared-parser metadata; group/sender selections and inclusive dates bind the cursor. Empty filtered pages may still continue, and destructive source changes require replacing loaded rows; additions offer a separate head refresh. Reads perform no acquisition or decryption. See [Account attachment history](ACCOUNT-ATTACHMENT-HISTORY.md) for integration and bounds.
