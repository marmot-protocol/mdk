# Per-chat attachment and recovery health

`attachment_management_snapshot` returns a bounded local health frame for one chat. `group_id_hex` is required and names an opaque MLS group ID. The frame includes only that group's transfer state and qualified parked recovery notices. Account-wide loss notices remain on the existing history-notice surface. A failed file does not establish failed synchronization, membership removal, missing epochs or corrupt state. `automatic_recovery_failed` comes from the existing durable qualified-recovery flag; `None` means the group is unavailable. Read errors remain errors and close observations; `available=false` supplies no recovery assertion or attachment references.

Health reads perform no relay fetch, demand registration, decryption, retry, read acknowledgment or notice dismissal. Existing native parsers provide file metadata and preserve rejected outcomes. Clients compose Android scheduler and platform constraints separately.

## Bounded pages and totals

`managed_attachment_page` seeks the group's partial acquisition index, visiting at most `limit + 1` non-ready job candidates, with `limit` in `1..=50`. SQLite rowid is the index's implicit ordering key; no global intent counter or acquisition-policy change is introduced. Source, permission, expiry, origin and state filters are applied inside this bound. Empty filtered pages can continue: exhaustion is established only when `next_cursor` is absent. Cursors bind the account incarnation, chat/query and existing attachment privacy version. Pages observe live state; they do not freeze an immutable selection. Request a new head to include new work, and discard the cursor after an error, privacy/source change, account reconstruction or shutdown.

Counts independently visit at most 1024 non-ready job candidates from that chat. Retained Ready history is excluded before both count and page budgets. Missing retained bytes rejoin the work index. `counts.complete=false` means every count is a lower bound; show “at least” or a partial indicator. Hidden, stale, unaccepted and expired sources do not count. Sparse visible candidates can produce partial totals. The count read streams one materialized indexed candidate query; page work is proportional to the capped candidate count. Neither scans historical plaintext. Acquisition descriptors are bounded by the existing 16 KiB limit; at most 50 details and 50 notices keep a frame below 1 MiB plus fixed record overhead.

The existing `attempt`, `received`, optional `total`, `retry_at` and transfer-state fields remain authoritative. Unknown totals stay absent. Opaque transport errors do not establish a network or integrity cause. Queued work, a policy pause and a cancelled request do not create persistent recovery warnings. Cancelled jobs have unknown original request origin and are excluded from Automatic/Explicit filters. Runtime reads apply the existing automatic-download policy, frozen-cursor setting and host-managed category permissions. Permission revocation changes the replacement generation; it does not confirm that a network connection has stopped.

## Existing per-item actions

`StorageBlocked` jobs appear in the attention page and count. They are parked for insufficient disk space, not active transfers or scheduled network retries, and have no retry timer. Show a storage prompt and the existing per-item Retry action; readmission remains owned by the acquisition worker.

Each observed transfer status carries its existing opaque attachment reference. Use `control_attachment` to retry or cancel an eligible item. The established account/store/source checks and retry budgets continue to apply; the health projection adds no actuation API or bulk cancellation. A read with unavailable evidence offers no reference. Cancellation is separate from removal and cache cleanup, and preserves Ready bytes. History notice dismissal uses the existing revision-fenced `dismiss_history_notice` operation and does not mean that history was recovered.

## Observation and privacy

`subscribe_attachment_management` emits a revalidated initial head and coalesced replacement heads, at most 4 Hz. Existing acquisition, runtime and presentation broadcasts invalidate it; retention uses a one-shot expiry deadline. There is no idle timer or diagnostic polling loop. Continued pages remain explicit reads. A timed-out or cancelled next call retains its pending invalidation. Events and resets from other accounts do not end the observation. Closing or dropping the feed stops observation without cancelling transfers or accepting notices. Runtime shutdown and account incarnation/reset changes fence publication. External writers use existing update signals or an explicit new read; the feed does not watch database files.

Authorized frames carry source identities for navigation to the user's own messages. Debug output and opaque references are redacted. `redacted_diagnostics` is a fixed aggregate JSON summary below 4096 bytes, excluding identifiers, names, captions, URLs, timestamps, references and keys. Sharing requires an explicit client action; there is no automatic upload.

## Binding ownership

Swift/Kotlin records require a nonempty group and carry opaque continuation/version objects plus existing transfer references. C query strings are borrowed; a NULL group is rejected. Input enum discriminants are checked `uint32_t`, using the generated view/origin constants. Required output pointers are validated before reads. Every returned page or snapshot is one independently owned deep-free root. Embedded cursors, versions and transfer references are borrowed until that root is freed. Clone an embedded handle through its existing clone function to retain independent ownership, and free only that clone directly. Use matching generated bindings, headers and libraries. Blocking C calls belong off the UI thread; close/free subscriptions before their client and never free a handle during an active call.

Android screens, background/platform diagnostics and SDK release/client adoption remain separate. The account attachment library supplies the privacy-version dependency. No workspace version is changed.
