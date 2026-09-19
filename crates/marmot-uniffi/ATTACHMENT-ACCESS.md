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
acquisition defaults on when the account runtime is running; use the C8-D2 controls below
to observe transfers, remove local files, or change the durable per-account policy.
Local access is useful only when MDK has acquired/published the bytes. Coordinate client
adoption of those controls with the binding release (C9); publishing an MDK release alone
does not add that UI to a client. Hosts needing a network-specific policy can set
`automatic=false` before starting the runtime; toggling this flag cancels active automatic
leases while preserving partials, explicit requests and retained files.

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
policy. Automatic acquisition defaults on: 2 GiB retained quota, 256 MiB free-disk reserve plus
SQLite/WAL headroom, 64 MiB automatic ciphertext ceiling, one runtime-wide acquisition at a time.
Explicit queued downloads use the existing 512 MiB hard limit and 15-minute transfer deadline.
Initial disk/quota admission reserves the automatic cap (64 MiB by default), then checkpoint
and publication checks enforce actual capacity. Automatic transfers have a two-minute deadline.
Policy requires retained quota at least equal to the automatic cap. Resource pressure appears
as `RetryScheduled` with a retry time; an intentionally high disk reserve can pause work.
Disable stops active automatic work and pauses automatic queues; explicit work and cached files
remain. Re-enable preserves individual cancellations/removals. No automatic retained-byte eviction.
Raising the cap readmits size-policy failures, never cryptographic failures. The legacy
`downloadMedia` API remains compatible and returns transient complete bytes.

Regenerate Swift/Kotlin bindings and C headers with the matching library. Release/client adoption,
large-file chunk overhead and device measurements remain C9 work; retain host caches until validated.

Idle transfer subscriptions use a 30-second fallback, shortened to the next known retention
expiry. Controls and presentation notifications wake them promptly; active rows retain a
one-second fallback. Cross-writer changes without notifications can take up to 30 seconds
while idle. Local-byte reads always revalidate visibility and expiry immediately.
