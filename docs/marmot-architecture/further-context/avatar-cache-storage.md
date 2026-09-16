---
title: "Avatar cache storage foundation"
created: 2026-09-16
updated: 2026-09-16
status: implementation
---

# Avatar cache storage foundation

C7-A of [#1554](https://github.com/marmot-protocol/mdk/issues/1554) adds protected local bytes to the existing
account SQLCipher store. [The Rust API](../../../crates/storage-sqlite/src/avatar_cache.rs) documents source
references, publication preconditions, status and removal. C7-B still owns download validation, coalescing,
retry intent and source maintenance; C7-C owns screen/native integration. Keep existing client caches until
that replacement is integrated and verified.

## Bounds and eviction

| Resource | Initial bound / policy |
| --- | --- |
| Encoded bytes | 128 MiB per account; at most 10 MiB per image |
| Owner mappings | 2,048, including missing entries |
| Image dimensions | Each dimension in `1..=4096`; formats PNG/JPEG/GIF/WebP |
| Recency | Durable sequence, updated by byte reads and binds; metadata status does not touch LRU |
| Timed freshness | Optional Unix-seconds deadline; stale bytes remain usable for the same source |

These are initial implementation defaults, not measured device optima. Eviction removes a mapping and its bytes,
fencing late completions with the old reference. Sharing across views uses the same owner; no cross-owner blob
sharing is introduced. Eviction must not itself requeue downloads: later acquisition must wait for fresh demand
or an applicable source update, avoiding refill/eviction loops. Retained attachments must not use this policy.

## Storage work and integrity

Local reads never await an engine, worker, relay or HTTP request. They are blocking database operations and must
be dispatched off the UI thread. Recency lives in a separate narrow table so widening its SQLite integer encoding
cannot rewrite image overflow pages. Unchanged source binds skip blob writes and usage aggregation; changed binds
and publications account over at most 2,048 rows. Checked counters fail rather than wrap.

The file-backed `avatar_recency_counter_widening_does_not_rewrite_blob_pages` regression first reproduced
21,572,352 WAL bytes for three reads of a 10 MiB image. With separate recency, three reads plus three unchanged
binds wrote 78,312 bytes on the development host. The test checks a bounded 256 KiB ceiling, not that exact count.
SQL-work coverage also bounds reads, unchanged binds and publication at capacity. Neither result measures mobile
first-frame latency. File allocation/reuse, total storage pressure and foreground lock latency still need device evidence.

`AvatarImage::new` enforces storage bounds only. Acquisition must authenticate encrypted data and validate fetched
image format/MIME/dimensions before publication. The stored checksum detects logical payload/record mismatches;
it is not a replacement for SQLCipher page authentication or image validation. Byte reads currently hash up to
10 MiB while holding the account connection; C7-B must measure this cost with realistic image sizes before native
adoption. Read-time bounds protect the allocation/typed decoding boundary even though valid writes satisfy schema checks.

Account references retain explicit store-epoch scoping, consistent with other projection handles. Production does
not rotate `chat_presentation_meta.store_epoch` in place: account recreation gets a fresh store, and explicit cache
clear removes all mappings. The epoch-update trigger is a defensive database invariant, exercised directly by a test,
not an additional runtime reset mechanism. Existing terminal close, encrypted WAL and account-removal policies apply.

## C7-B/C integration constraints

`bind_avatar_source`, `publish_avatar` and `read_avatar` own transactions. Do not call them inside an existing
`with_transaction`/read snapshot. If source binding is composed with presentation writes, first adapt it to the
existing nestable transaction helper and add rollback coverage for the combined operation. Reference/status reads
remain metadata-only; the new methods alone do not observe group/profile changes.

The app must publish changes after committed source replacement, acquisition, corruption repair or eviction, and
fence stale completions against current authority. Bind/read APIs do not create durable download demand. Native
references and decoded-image caches must include content revision, not only the source reference. C7-C provides
bounded/batched visible-byte access and snapshot/update recovery; it must not embed every avatar in screen payloads.
