# Local attachment bytes (C8-D1)

Use `attachment_local_assets` / `attachmentLocalAssets` for up to 64 original source
slots **in one group**, then `read_attachment_asset` / `readAttachmentAsset` for
bounded local bytes. These methods are additive; existing `download_media` retains
its behavior. Regenerate Swift/Kotlin sources and use the matching native libraries.

## Lookup

Build `AttachmentLocalTargetFfi` from the original timeline/history entry's
`message_id_hex`, `source_message_id_hex` and original `attachment_index` (including
rejected positions in albums). Do not use a reply row's identity for its target media.
Use attachment-history discovery when the original source identity is unavailable.

The result preserves target order, including duplicates. Each `AttachmentLocalAssetFfi`
has an optional opaque `reference` and `byte_count` of verified plaintext. A missing
reference means no readable retained bytes, including missing/in-flight/removed/expired
or obsolete sources; it is **not** a download failure, progress event or request to fetch.
An available empty file has a non-null reference and a zero byte count.

The call loads no payload bytes and starts no download or engine worker. Automatic
acquisition defaults on in `NativeAutomatic` mode when the account runtime is running.
`HostManaged` starts denied until the host grants permission. Use the C8-D2 controls below
to observe transfers, remove local files, or change the durable per-account policy.
Local access is useful only when MDK has acquired/published the bytes. Coordinate client
adoption of those controls with the binding release (C9); publishing an MDK release alone
does not add that UI to a client. For host network/type policy, use the [host-managed contract](#host-managed-automatic-acquisition-0104) below.
The durable `automatic` flag remains an additional override; toggling it cancels active
automatic leases while preserving partials, explicit requests and retained files.

## Read and lifetime

Read by opaque reference and offset, with `limit` from 1 through 1,048,576 bytes. Each
`AttachmentLocalBytesFfi` contains `available` plus `bytes`. `available=true` with empty
bytes is EOF (offset at/beyond the end), including a zero-byte attachment. When available,
advance the offset by bytes actually returned. `available=false` means discard any
partially assembled result and refresh metadata. Never join chunks from different references.

References contain no URLs or decryption keys. Do not inspect or persist them. Reacquire
metadata after runtime reconstruction. Each read validates account/store identity and
current source visibility/expiry. Deletion, explicit removal and source replacement can
invalidate a reference between chunks. Leaving a group preserves retained history access.
Calls after shutdown fail rather than reopening databases. Hosts own decoding, layout,
plaintext buffer/export lifetime and removal of any downstream copies. Only the transient
Rust storage-read buffer is zeroized; MDK does not wipe plaintext copies delivered through
native bindings, including buffers released by the C free function.

```swift
let targets = [AttachmentLocalTargetFfi(
    messageIdHex: messageId, sourceMessageIdHex: sourceId, attachmentIndex: index)]
let assets = try await marmot.attachmentLocalAssets(
    accountRef: account, groupIdHex: group, targets: targets)
if let reference = assets[0].reference {
    let chunk = try await marmot.readAttachmentAsset(
        accountRef: account, reference: reference, offset: 0, limit: 65536)
    // Consume only when chunk.available. Read further chunks as needed.
}
```

```kotlin
val targets = listOf(AttachmentLocalTargetFfi(messageId, sourceId, index))
val assets = marmot.attachmentLocalAssets(account, group, targets)
assets[0].reference?.let { reference ->
    val chunk = marmot.readAttachmentAsset(account, reference, 0uL, 65536u)
    // Consume only when chunk.available. Read further chunks as needed.
}
```

C consumers use `marmot_attachment_local_assets` and `marmot_read_attachment_asset` off
the UI thread. Targets and strings are borrowed for the call. Returned list references
are owned by the list; copy a reference before freeing that list if it is needed later.
Deep-free results with `marmot_attachment_local_asset_list_free` and
`marmot_attachment_local_bytes_free`; both accept NULL. No pointers to database buffers
or filesystem paths cross the ABI.

Progress and controls are described below. C9 owns released-artifact integration and real-device measurements.

## Transfer progress and controls (C8-D2)

`attachmentTransferSnapshot` and `subscribeAttachmentTransfers` accept the same bounded
original-slot targets as local access. `next()` returns an initial snapshot then complete
replacements in target order (maximum four per second). `cancel()` stops observation only;
call it to wake pending receivers, then drop/destroy the subscription when its screen leaves. Recreate it when the visible target set
changes. C provides blocking `next` with a timeout; call off the UI thread. A timeout does not
consume an update. Close/error/runtime shutdown ends observation. No transfer is requested by lookup.

Use state to distinguish unavailable source, not requested, queued, paused, downloading,
verification, retry scheduled, failed, policy blocked, cancelled, removed and ready. `received`
and optional `total` count ciphertext bytes, including a compatible resumed prefix. Never merge
counters across `attempt` generations: claim resets counters before HTTP starts, and later body restarts or locator fallback reset them again.
Ready alone means complete cryptographic verification and local publication. Continue using
local-asset lookup/ranged reads to obtain plaintext; always revalidate availability.

The opaque reference in a transfer entry supports `controlAttachment` with Cancel, Retry or
Remove. Cancel survives restart, retains valid partial ciphertext for its existing 24-hour expiry,
and does nothing to already-ready bytes. Retry is explicit and can run with automatic work disabled.
Remove discards local bytes and suppresses reacquisition. `downloadAttachmentAgain` accepts an
exact current source slot, clears suppression/cancellation and queues explicit work atomically.
Obsolete references return false; obsolete/unavailable slots return no reference. Pending invites
cannot download attachments before acceptance. These commands persist intent without waiting for
network readiness; acquisition needs an active, non-frozen account runtime.

`attachmentDownloadPolicy` / `setAttachmentDownloadPolicy` read/write a durable per-account
policy. In `NativeAutomatic` mode automatic acquisition defaults on: 2 GiB retained quota, 256 MiB free-disk reserve plus
SQLite/WAL headroom, 64 MiB automatic ciphertext ceiling, one runtime-wide acquisition at a time.
Explicit queued downloads use the existing 512 MiB hard limit and 15-minute transfer deadline.
Initial disk/quota admission reserves the automatic cap (64 MiB by default), then checkpoint
and publication checks enforce actual capacity. Automatic transfers have a two-minute deadline.
Policy requires retained quota at least equal to the automatic cap. Resource pressure appears
as `RetryScheduled` with a retry time; an intentionally high disk reserve can pause work.
Disable stops active automatic work and pauses automatic queues; explicit work and cached files
remain. Re-enable preserves individual cancellations/removals. No automatic retained-byte eviction.
Raising the cap readmits size-policy failures with remaining retry budget, never cryptographic failures. The legacy
`downloadMedia` API remains compatible and returns transient complete bytes.

Regenerate Swift/Kotlin bindings and C headers with the matching library. Release/client adoption,
large-file chunk overhead and device measurements remain C9 work; retain host caches until validated.

Idle transfer subscriptions use a 30-second fallback, shortened to the next known retention
expiry. Controls and presentation notifications wake them promptly; active rows retain a
one-second fallback. Cross-writer changes without notifications can take up to 30 seconds
while idle. Local-byte reads always revalidate visibility and expiry immediately.

## Host-managed automatic acquisition (0.10.4)

Android hosts with a network/type preference matrix should construct MDK with
`MarmotOptions.attachment_acquisition_mode = HostManaged` **before startup**.
The default remains `NativeAutomatic` for existing consumers. Host-managed mode
never turns projection discovery into automatic demand. Both modes use the same
SQLite jobs, source history, quotas, local reads and explicit controls. The new
retry budgets and terminal retention-failure behavior apply only to jobs opted in
through `requestAutomaticAttachment` or claimed as automatic work by a HostManaged worker (including
restored persisted jobs). Pure explicit requests are not opted in. Existing native jobs keep
their retry behavior; opting a job in is durable even if runtime mode later changes.

Host-managed automatic permission starts denied for every account on each runtime
construction, including newly created/imported accounts. Sign-out/removal also
invalidates approval and pending callbacks; signing back into retained storage needs
fresh approval. Permission updates while signed out are rejected. It is an additional gate;
`AttachmentDownloadPolicy.automatic=false` still denies automatic work. Explicit
user downloads remain eligible, and frozen runtimes still perform no acquisition.
Do not use `automatic=false` as a substitute for selecting host-managed mode.

For every network or preference change:

1. Call `beginAttachmentPermissionUpdate(account)` before asynchronous policy
   evaluation. It revokes existing approval and pauses automatic network work,
   returning a fresh runtime/account/store-scoped generation.
2. Evaluate the host's current network and media preferences. Call
   `setAttachmentAutomaticPermission(account, generation, permission)` once with
   booleans for images, videos, audio and files (Documents, including APKs).
   `false` means the generation is stale, already consumed, or belongs to another
   runtime/account. Never obtain a fresh generation from an old callback to bypass
   that result. To revoke without enabling anything, step 1 alone is sufficient.
3. Call `requestAutomaticAttachment(account, group, target)` for eligible demand.
   Both foreground callers and restored workers may safely repeat this call.

Use an ordered host policy coordinator: process the revocation step in event order,
then perform asynchronous evaluation with that event's captured generation. Do not
persist generations or Wi-Fi approval. Re-evaluate after runtime reconstruction.
Permission and automatic-request APIs require HostManaged mode; calling them in
NativeAutomatic returns `AttachmentModeRequired`. Beginning approval for a signed-out
account returns `AttachmentAccountSignedOut`. Neither is a media-corruption error.
MDK checks the shared parser's MIME category, source and policy during admission and
before HTTP attempts, including transport retry, redirects and locator fallback.
Revocation cancels active work; bytes already in flight cannot be retracted.
Reapproval cannot revive a network transfer from the old generation. A verified
body may still finish its receipt and local publication after network permission is
revoked. Explicit cancellation/removal, expiry and source replacement still fence
publication. Paused jobs have no retry timer; approval readmits existing demand
without resetting its retry deadline or discarding its resumable ciphertext.

`AutomaticAttachmentRequestFfi` returns `newly_queued` and an authoritative transfer
`status`. `newly_queued=false` is normal for repeated requests. Existing jobs retain
cancellation, retry deadlines, progress, budgets and their opaque reference.

| State | Automatic request behavior |
| --- | --- |
| Not previously requested and allowed | Queues one job; `newly_queued=true`. |
| PolicyBlocked / Paused | No network permission; re-evaluate host/durable policy. |
| Queued / downloading / RetryScheduled | Returns existing work without restarting it. |
| Ready | Uses retained verified local bytes. |
| PreviouslyAcquiredUnavailable | Previously published bytes are gone; no automatic reacquisition. |
| CompletedUnretained | A verified body could not be published, or the process stopped after recording its receipt; no automatic reacquisition. |
| RetryExhausted | The durable acquisition or network budget is spent; no automatic retry. |
| Failed / Cancelled / Removed | Preserves terminal state or suppression. |
| Unavailable | Source is obsolete, hidden, expired, rejected or otherwise unusable. |

For host-managed demand, the lifetime budget is **four acquisition attempts and
at most 64 network attempts per source/request cycle**. The network ceiling is a
separate bound: transport retries, redirects, range restarts, failed DNS/host setup
and fallback each spend one. A transient 503 retry therefore does not by itself
consume a whole acquisition attempt. A claim that fails before networking still
spends an acquisition attempt. Permission/policy interruptions refund the interrupted
claim exactly once, preserve backoff and retain ciphertext; actual network attempts
are never refunded. Thus four network changes cannot spend the acquisition budget,
while pathological reconnection loops remain bounded by actual network activity.

Checkpoint progress, recomposition, repeated demand and process restart never
replenish these budgets. A deliberate explicit Retry/download-again starts a new
bounded cycle when not already fetching. Explicit retries of an opted-in job bypass
automatic permission, not its budget. A completed verified body has one receipt owner
before publication; insufficient retention capacity or publication failure is terminal
for opted-in jobs. The free-disk check runs before the receipt; a transient shortage
there schedules a bounded retry without recording successful acquisition. Resource pressure
before fetching can defer admission without
spending an attempt. If receipt storage fails, the persisted budgets still bound
subsequent fetches. A size-policy failure remains `PolicyBlocked` even if the budget
is exhausted; raising the size cap does not replenish that budget, so explicit retry
may also be needed.

Source identity is the account store incarnation, group, original message and imeta
index, authoritative source-event ID, epoch, exact slot descriptor and parsed
plaintext digest. Rebuilding a projection with the same source preserves history.
A changed authoritative event/epoch/descriptor (including a locator change) is a
replacement source with a new job identity. Explicit removal suppresses the original
message slot across replacement until a deliberate download-again. Ordinary loss
of retained bytes preserves acquisition history and does not create removal intent.
Source expiry/deletion or store reset ends that history. Migration preserves existing
jobs and their backoff deadlines without deriving budgets from the old claim/backoff
counter. New budgets start at zero and native jobs are not opted in by migration.
Acquisitions made outside MDK's durable store cannot be reconstructed.

### Android migration

Route both foreground automatic callers and restored WorkManager jobs to this API.
WorkManager may wake/start MDK and observe durable acquisition, but must not download
independently or run a second network retry loop. Migrate/cancel legacy queued jobs
that invoke `downloadMedia` or `downloadAttachmentAgain` automatically.

Read through `attachmentLocalAssets` / `readAttachmentAsset`. A local read miss,
presentation-cache eviction, or conversation reload must never silently fall back
to legacy `downloadMedia`. Render an explicit download action for terminal unavailable
states; only a deliberate user action may invoke Retry/download-again.

Regenerate Kotlin/Swift bindings and pair them with the matching native library.
C adds three corresponding `marmot_*` functions and the acquisition-mode field on
`MarmotClientOptions` (0 NativeAutomatic, 1 HostManaged). Recompile with the matching
header/library; returned automatic-request records use
`marmot_automatic_attachment_request_free`, and generation strings use
`marmot_string_free`. C permission inputs are borrowed boolean integers.
