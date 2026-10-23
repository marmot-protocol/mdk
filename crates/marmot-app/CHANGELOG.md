# Changelog

## Unreleased

## 0.14.0 - 2026-10-23

### Breaking changes

- App databases are keyed with raw SQLCipher keys (mdk#1791). The HKDF
  derivation and the `.salt` sidecars are unchanged, but on first open each
  existing passphrase-keyed database (`session.sqlite`, the directory cache
  `app-cache.sqlite3` and a legacy `app.sqlite3`, for local and
  external-signer accounts) is rekeyed once: `PRAGMA rekey` rewrites every
  page under a durable `<db>.raw-key-migrating` marker, and an interrupted
  rekey recovers on the next open. Later opens skip SQLCipher's
  256,000-iteration passphrase KDF. Older binaries cannot open a rekeyed
  database; downgrade is unsupported. Keep the salt sidecars and secret-store
  credentials; `docs/marmot-architecture/storage-format-v2.md` documents
  offline opens and the key-only offline rekey.
- Hosts must exclude the account directory, including `media/`, from cloud and
  device backups (iCloud, Android auto-backup). Its keys are device-bound, so
  a restored database, salt or media file could not be read anyway.
- `AttachmentTransferState` adds `CleanedBySetting` (mdk#2314 step 10).
  Update exhaustive matches.

- `RetentionSweepStatus::DeferredScanExhausted` is removed (mdk#2425): the
  retention sweep no longer pages wall-clock history, so there is no page
  cap to exhaust. Remove exhaustive handling of the variant.
- Deployment services move onto `MarmotDeployment`, carried as
  `MarmotAppConfig::deployment` (host-configuration brief, PR 1). It holds the
  recovery-operated relays, discovery indexers, new-group media servers,
  group- and profile-image servers, Open Ranking, the KeyPackage client
  preference, the moderation label namespace and the keychain service name.
  `MarmotDeployment::white_noise()` holds White Noise's values, unchanged;
  `MarmotDeployment::neutral()` configures none.
  `MarmotAppConfig::recovery_operated_relays` and the `MarmotServiceEndpoints`
  fields `encrypted_media_blob_endpoints`, `profile_image_blob_endpoint`,
  `open_ranking_search_endpoint` and `open_ranking_profile_relays` are gone;
  set them on the deployment with `MarmotAppConfig::with_deployment`.
  `with_recovery_operated_relays` and `with_open_ranking_provider` still work.
  `default_directory_discovery_relays()`, `DEFAULT_BLOSSOM_SERVER_URL(S)` and
  `MODERATION_REPORT_LABEL_NAMESPACE` are removed: use
  `MarmotApp::discovery_indexer_relays()` or the preset's fields. A
  moderation report destination is now refused when the deployment sets no
  label namespace. `with_service_endpoints` now sets only the collector
  routes, so passing `..Default::default()` no longer turns Open Ranking off;
  call `with_open_ranking_provider(None, Vec::new())` to turn search off.
- `MarmotAppConfig::default()` and `MarmotDeployment::default()` are now
  neutral (host-configuration brief, PR 3). A host that relied on the default
  for White Noise's services must start from `MarmotAppConfig::white_noise()`
  or pass `MarmotDeployment::white_noise()` to `with_deployment`, or it loses
  them, including its keychain service. Unset values no longer fall back to
  White Noise's servers: with no `new_group_media_endpoints` a new group
  carries no encrypted-media component and stays text-only, and with no
  `group_image_endpoint` setting or fetching an encrypted group image returns
  `AppError::BlobStore`, as does a profile-image upload with neither an
  explicit server nor `profile_image_endpoint`. The build-time
  `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS` override is gone; set the list on
  the deployment. `marmot_account::DEFAULT_KEYCHAIN_SERVICE_NAME` and
  `AccountHome::open_with_default_keychain` are removed: call
  `open_with_keychain` with the deployment's `keychain_service`.
- `MarmotApp`'s 16 directory methods (user and cached search, directory
  entries and refreshes, profile, follow-list and relay-list fetches, member
  KeyPackage resolution and prewarming) move to `MarmotApp::directory()`, a
  `Directory` from the new `nostr-directory` crate (directory brief, PRs 4-7).
  marmot-app re-exports `Directory` and `DirectoryError`. Directory methods
  return `DirectoryError`; `?` or `AppError::from` converts it to the same
  `AppError` variant, message and `privacy_safe_kind` as before.
  `MarmotAppRuntime` methods are unchanged.
- `AppError` adds six variants; update exhaustive matches:
  `GroupCatchingUp` and `GroupCommitUndelivered` (see Fixed),
  `InvalidEditTarget`, `FollowListTooLarge` (mdk#2268),
  `InvalidPublicEventReferences` (see Added) and
  `DirectoryLookupIncomplete(account)` (mdk#2302). Invite member resolution,
  directory KeyPackage lookup and relay-list lookup return
  `DirectoryLookupIncomplete` instead of `RelayDirectory` when time or relay
  coverage ran out, so nothing is known to be missing. When the invite
  deadline passes, members already decided keep their outcome, members still
  unfinished report `DirectoryLookupIncomplete`, and the call returns the first
  unusable member's error in request order. Retry it.
- `AppError::MissingKeyPackage` is now
  `{ account, reason: MissingKeyPackageReason }`. `ObsoleteOnly` means a
  completed lookup found only legacy-profile KeyPackages, so the recipient
  must update and publish a current one; `NotFound` keeps the previous
  meaning.
- Sends stage every attachment body in the account's media store before the
  first upload (mdk#2314 step 3). A body the disk cannot hold beyond the
  attachment policy's disk reserve fails with
  `AppError::Storage(StorageError::Capacity)` before anything is uploaded or
  published, instead of sending without a local copy. A full upload table
  (256 uploads awaiting publication) or a failed binding after the upload
  also fails the send, which publishes nothing.
- `AttachmentTransferState` adds `StorageBlocked`: free disk cannot cover the
  publication reserve for the body. Update exhaustive matches; the job keeps
  its checkpoint and readmits once space frees or on explicit Retry.

- Rust recovery models add `RecoveryCause::SubscriptionReplay`,
  `RecoveryPredicate::ReplayAdmission`, `RecoveryScopeCheckpoint::replay_admitted`
  and `RecoveryReplayPlacement`. Native checkpoints require separate account-wide
  placement before completion; scoped source facts can persist earlier.
  Native input admission is separate from history certification and loss acknowledgment.
  The C and UniFFI surfaces are unchanged.
- Rust ingestion borrows its transport input:
  `Engine::ingest_with_audit_context` takes `&TransportMessage`,
  `AccountDeviceSession::ingest_delivery` takes `&TransportDelivery`, and so
  do marmot-account's `AccountDeviceRuntime::ingest_delivery` and
  `ingest_delivery_with_observer`. `ReplayIngress` and `ReplayBatch` retain
  native frames until ordered admission acknowledges them. C and UniFFI calls
  are unchanged.
- Group (kind 445) event signatures are verified once, at the relay
  adapter's ingest boundary; group peeling no longer verifies Schnorr
  signatures (mdk#1799). A Rust host that builds `TransportMessage`s from
  `NostrTransportEvent` DTOs itself must authenticate their source or call
  `to_verified_nostr_event` before ingesting them.

### Changed

- Avatars and group images are stored as encrypted media-store cache files
  (mdk#2314 step 9). A fetched image is published on the blocking pool;
  identical images share one file, and a disk without room for the file
  retries the fetch later. Reads take file-backed images from the store; a
  missing or corrupt file is cleared and fetched again for every chat that
  shows it. The maintenance tick moves images still held in the account
  database into files in small batches, smallest first, without changing
  what viewers see. An identical file already on disk is read back in full
  and then reused at no space cost. When the disk cannot take a new file, or
  free space cannot be measured, the move waits for the next tick; like the
  attachment move it deletes nothing to make room. Compaction's live-size
  log waits until no avatar image remains in the database.

- Downloaded attachment bodies are retained as encrypted files in the account's
  `media/` directory (the `media-store` crate) instead of SQLCipher rows
  (mdk#2314). Identical content is stored once and attached without downloading
  again. `read_attachment_asset` reads either layout unchanged; bodies earlier
  releases kept in the database move into the store in the background (see
  Added).
- Sent attachment bodies are kept as encrypted media store files owned by
  their upload, and the wire ciphertext streams from that file in two passes
  (digest, then each PUT): no plaintext snapshot, ciphertext temp file or
  SQLCipher copy is written, and no retained-byte budget or 4x disk rule
  applies. The account worker promotes each upload into the sent message's
  slots once the message is confirmed; an upload whose file was lost is
  dropped so the message downloads its own media. Uploads staged in the
  database by earlier releases keep their previous promotion until they
  expire.
- The retained-byte budget (`retained_bytes_per_account`) no longer gates
  downloads, so a full budget cannot leave downloads waiting in `RetryScheduled`.
  Free disk is the only limit: a full disk parks the job as `StorageBlocked`.
- Download checkpoints keep their ciphertext in append-only `.wire` files in
  the account's `media/` directory instead of SQLCipher rows (mdk#2314).
  Checkpoints saved by an older build are discarded on upgrade.
- Downloads need the configured disk reserve plus twice the body (its
  ciphertext and its stored file) instead of four times; bytes already
  checkpointed count once. Large explicit downloads streamed to a file write
  their ciphertext straight into the `.wire` checkpoint (or, without a strong
  validator, one private staging file) and publication decrypts it straight
  into the encrypted store file, so no plaintext copy is written to disk. A
  checkpoint write the disk cannot take, or a full disk while publishing a
  body, parks the job as `StorageBlocked` for what its retry still writes,
  never on a retry timer.
- Publication, hashing and encryption of downloaded bodies run on the blocking
  pool for in-memory bodies too, never on the account worker.
- Approving an onboarding relay repair needs a completed freshness query from
  every onboarding source, including the relays named in the account's signed
  relay declaration, not only the discovery relays and public indexers. A
  source that times out blocks the replacement even when another source
  returns a record, since it may hold a newer one (mdk#2417).
- The directory's tracing targets name their modules:
  `nostr_directory::search`, `nostr_directory::sync` and
  `nostr_directory::cache`, and in marmot-app
  `marmot_app::directory_resources`, `marmot_app::user_blocks` and
  `marmot_app::profile_publication`; identity publication at the crate root
  logs as `marmot_app`. They replace `marmot_app::directory`; update log
  filters that named it.

### Added

- Opt-in relay telemetry exports `relay_account_activations_full`,
  `relay_account_activations_degraded` and `relay_account_activations_failed`,
  and `relay_group_syncs_full`, `relay_group_syncs_degraded` and
  `relay_group_syncs_failed`: device-wide, unlabeled counts of account
  activations and group syncs whose REQs reached every relay, succeeded while
  some relay owed or refused one, or failed (mdk#1951).
  `RelayTelemetryRollup` gains the matching fields; struct literals need them
  or `..Default::default()`.
- Opt-in "Keep media" (mdk#2314 step 10):
  `MarmotAppRuntime::attachment_keep_media` and `set_attachment_keep_media`
  (`AttachmentKeepMedia`: Forever by default, one year, six months, 30 days).
  Setting a window removes every retained attachment already past it before
  returning, with the count; the account worker then applies it at start and
  hourly, for at most 250 ms per maintenance tick, ahead of the legacy body
  move. Removed attachments read `CleanedBySetting` and can be downloaded
  again, which keeps them for the whole window from that request. Automatic
  downloads skip attachments already past the window, and the sweep drops
  unfinished automatic downloads that fell past it. Forever removes nothing.

- The account database returns freed space to the filesystem (mdk#2314 step
  6). Once a quarter of it is free pages, the volume has room for two copies
  of the live data and that data is at most 64 MiB (the copy is built in
  memory, and its final write-back cannot be interrupted, so the cap bounds
  how long a suspend's close can wait), the account worker compacts it once;
  a rolled-back attempt is retried. Attachment bodies moved out by the
  migration are free pages, not live data. An account still over the cap
  once nothing is left to move is logged once per process with its live
  size as a coarse bucket;
  `attachment_storage_usage().migration` reads `Compacting` meanwhile, from a
  snapshot taken just before, and attachment observers wake when it starts
  and ends. Afterwards each maintenance tick and each bulk removal returns
  freed pages, so moving legacy bodies out keeps disk use flat.

- `MarmotAppConfig::white_noise()` is the default configuration with White Noise's deployment. The CLI, `wn-agent`, the conformance simulator, the dev/test constructors and the tests name it explicitly, so they keep White Noise's behaviour now that `MarmotAppConfig::default()` is neutral (host-configuration brief, PRs 2 and 3). The CLI's default keychain service comes from `MarmotDeployment::white_noise()`; the name is unchanged.

- Legacy attachment bodies move into the encrypted media store in the
  background (mdk#2314 step 6): one small batch per maintenance tick, after
  readiness, on the blocking pool. On a tight disk the move takes what fits,
  then pauses until space frees; `attachment_storage_usage().migration`
  reports `NotNeeded`, `Running { remaining_bytes }`,
  `Paused { needed_bytes }` or `Complete`, and attachment observers wake when
  it pauses, resumes or finishes. Nothing is deleted to make room. A legacy
  body that fails its digest is dropped and its attachment shows as
  previously acquired and unavailable, with download-again allowed. Database
  pages freed by the move return to the filesystem through compaction
  (below).

- Manage storage (mdk#2314 step 5): `attachment_storage_usage`,
  `attachment_storage_by_chat`, `largest_retained_attachments`,
  `remove_chat_attachments` and `remove_attachments_older_than` on
  `MarmotAppRuntime`, across both body layouts. Removal is explicit `Remove`
  (shown as removed, download-again allowed), and the media files it
  releases are unlinked before the call returns, so file-backed space frees
  at once. Explicit `Remove` through `control_attachment` now unlinks its
  released file at once too, instead of at the next media sweep.

- `MarmotAppRuntime::open_attachment_handoff` and `release_attachment_handoff`
  (mdk#2314 step 4): a private plaintext copy of a retained attachment, under
  `<account>/handoff/<lease>/<name>`, lent to an OS surface that needs a real
  file (package installer, share sheet, "open with", Quick Look). The copy is
  named after the attachment, deleted on release, with the account, or when
  the account worker next starts in a new process, and refused with the
  storage-full error when the disk cannot hold it.

- `MarmotAppRuntime::cached_public_event_previews` and `resolve_public_event_preview` keep verified public Nostr events referenced from message content in the account's directory cache (mdk#1547). The cache adds directory-cache migration 2; an older build refuses the upgraded cache. `AppError` adds `InvalidPublicEventReferences` for batches over 16 references.

- Account-wide local attachment pages expose bounded typed metadata, group/sender/date selection, continuation cursors and retention deadlines. Reads start no acquisition or relay activity.

- `MarmotAppRuntime::submit_prepared_media_snapshot` admits the captured ordinary-media payload with a stable token and consumes only its unchanged captured draft in the same transaction. Newer or cleared drafts cannot replace the payload or block admission.

- `MarmotAppRuntime::acknowledge_group_catching_up` records that the user accepts the fork risk of changing a group that is still catching up, so the next group change at the current epoch proceeds.

- `MarmotAppRuntime::group_commit_delivery` returns the relays still owed the group's last change (`GroupCommitDelivery`), and `acknowledge_group_commit_undelivered` lets the next group change through after `GroupCommitUndelivered`.

### Fixed

- Sends, media preparation and group changes continue when the pre-send group
  subscription refresh fails, for example because a group's relays are
  unreachable (mdk#2562). A token send no longer turns `Rejected` moments after
  admission: publishing carries its own relays, and the refresh stays armed for
  the worker's retry. Convergence retries still require the refresh, and an
  inactive account still fails it, so its messages keep taking the
  inactive-account queue.
- `ctutils` 0.4.5 fixes non-constant-time mask generation and `u128`
  comparisons (RUSTSEC-2026-0385).
- `shutdown_and_close` and `close_storage` now close every connection that
  can hold a lock in the Marmot root before releasing the root lease,
  including each account engine's own `session.sqlite` connection and opens
  still in flight. Before, only the app's cached connections closed, so the
  lease could be released while a worker still held the database: the state
  behind iOS `0xdead10cc` kills, and a Notification Service Extension could
  take the lease while the engine was still writing. Each resource registers
  a `storage_sqlite::DatabaseCloser` when it opens, and the app opens the
  engine's connection itself and hands it to the session
  (`SessionConfig::with_storage`).
- Opening a database the process already holds open, such as a second
  connection to `session.sqlite`, no longer drops the live connection's POSIX
  locks. That let another process, such as the iOS Notification Service
  Extension, take the database exclusively and checkpoint, truncate or
  reinitialise its `-wal`/`-shm` under it (mdk#2351).
- A hydration-quarantined group no longer stops every conversation from
  receiving (mdk#2318). The worker reads no delivery while an effects batch is
  retained, and a strict read of the quarantined group failed that batch on
  every retry while sends kept publishing. Its events are now projected
  best-effort, a failure naming a quarantined group defers only that group's
  events (recovery re-derives its projection), and a locally deleted,
  quarantined group stays subscribed on its stored route. A head batch that
  keeps failing is logged after four retries and at each doubling.
- An inbound group event is rebuilt and verified once, not once per relay
  copy: relay timing is recorded from authenticated event ids and a retained
  ciphertext body is reused, while each replay source keeps its own claim
  (mdk#1799). Subscription relays are released after their last owner, so an
  account whose relay set rotates no longer accumulates relay connections for
  the process lifetime (mdk#1040).
- History recovery no longer lets stalled routes spend every pass before
  healthy peers are searched. Routes run in bounded concurrent slots that
  refill as each finishes, the complete pending plan is kept so skipped and
  refused work stays retryable, negentropy work on a shared relay connection
  is bounded per relay, and coverage debt is kept when retention makes an old
  window unsearchable.
- Bounded reconciliation keeps moving. A pass that ended in refusals at a full
  deferred queue now saves its replay cursor once every comparison event has
  had its ingest attempt, so the next pass fetches past the refused prefix
  instead of the same events; refused ids stay fetchable and still withhold
  the certificate. Each route pass ends at the caller's deadline, so events
  the relay already returned are kept instead of cancelled with the pass. A
  relay gets 5 s for its first NIP-77 reply and 20 s for the pass, instead of
  500 ms and 2 s, and once one relay has compared, the ones still pending at
  half the remaining pass time count as route timeouts.
- A generated identity's setup no longer advertises the app's configured
  relays first. While its setup journal was open, the KeyPackage lane
  published any missing relay lists (kinds 10002 and 10050) built from the
  app's relays alongside the lists the user chose, and where the bootstrap
  batch never landed those stayed the account's write and inbox relays. An
  open setup journal now owns the account's relay lists until they are
  projected.
- Pending-Welcome queries reconcile delivery obligations in one state-filtered
  scan per live group (mdk#1798). Outstanding-only recovery reads `Sent` rows;
  completed and canceled invites remain tracked for repair-index cleanup.

- `follow_user` and `unfollow_user` edit the account's current kind-3
  contact list in place (mdk#2268). A follow appends one `p` tag and an
  unfollow removes that account's `p` tags; petnames, relay hints, other tags
  and the content are republished unchanged. Before, every edit rebuilt the
  list from bare `p` tags, dropping that metadata. When the list has 2,048
  follows or more, the most MDK reads from one list, both refuse with
  `AppError::FollowListTooLarge` and publish nothing; before, they
  republished the list cut to its first 2,048 follows.
  `MarmotAppRuntime::update_account_follow_list` and
  `MarmotApp::update_account_follow_list` run the same edit against chosen
  relays.

- An epoch-gap recovery pass now fetches the route's newest events in the
  comparison window (256 events and 4 MiB per relay, inside the pass deadline)
  from each relay its comparison did not vouch for. A commit first accepted
  long after it was wrapped keeps its wrap-time `created_at`, below every
  subscriber's live `since`, so a relay that could not compare never returned
  it and the member stayed at the old epoch (mdk#2256). These events are
  admitted like comparison events but never certify the route or move its
  replay cursor. `publish_outcome` audit rows gain `event_age_secs`.
- Epoch-gap fallback searches older raw pages when a relay cannot compare,
  instead of repeatedly fetching only its newest 256 events (mdk#2257).
  Bounded advisory hints resume across pass cuts. Held-only traversal does
  not reset backoff or the durable park count, including after reopening.

- Offline catch-up stages each group's complete range before MLS processing and
  pages every route of a clamped reply backwards (#2375, #2381). Without a
  durable cursor it requests retained history, not the recent live tail, even
  when the relay refuses NIP-77. The account recovery owner preserves unresolved
  original windows across cancellation and reopen. All native group input,
  including live tails and local publication fanout, bypasses live-queue/spill alternation; retained spill
  rows join the ordered range before decryption. Current waiting peers fence
  release, and replacement requests establish their own boundaries. Unservable
  original ranges raise the existing history notice instead of silently blocking
  the cursor; terminal group removal retires obsolete native scopes. Native
  backend errors remain visible and automatic retries back off. Native-fed live
  messages run the same receive recovery and inbound projection measurement as
  ordinary deliveries. A live cursor-check failure preserves already-durable
  delivery counts. Committed native and comparison chunks publish during startup
  and follow-up drains, rather than waiting for the whole batch to settle.
  Direct catch-up failures retain already-committed native outputs in their
  completed prefix. Native ingests contribute to the existing drain delivery
  counts, including eventless deferred input.
  Native input wakes `next_event` for pending convergence or epoch backfill
  even when no visible event was produced.
  Native turns batch optional reconciliation-inventory writes at the existing
  four-frame boundary. Engine/app persistence, seen receipts and frame ACKs
  remain per delivery; structural input keeps immediate inventory bookkeeping.
  Route refresh skips convergence and epoch reads when no prior route can retire.
  Recovered Welcomes publish `GroupJoined` before live-subscription I/O and
  retain their grant-owned post-join history work in both streamed chunks and
  final comparison results.
  Epoch-gap page hints wait for every routed delivery to be retained or
  definitively rejected, including comparison/window duplicates.
  A recovered canonical context rearms ready retained ciphertext so deferred
  messages retry without another relay delivery or manual convergence retry.
  Already-held copies adopt durable spill ownership before
  source replacement, without copying the ciphertext. Empty or silent peers do not
  create notification loss. Sender-ratchet tolerance remains 100; timestamp/id
  ordering does not establish sender-generation order within a single second.

- `control_attachment` Remove opens the account's media store before the
  removal commits, so a store that cannot open (for example while storage
  closes) fails the call before anything is removed instead of reporting an
  error for a removal that already happened.

- The retention sweep no longer prunes a message the unread projection still
  counts unread (mdk#2425). The sweep used to compare only wall-clock
  `timeline_at` against the read marker, so it deleted a received message
  that shared the marker's second with a higher id, or one that arrived in a
  later epoch while the sender's clock ran behind the marker. Storage now
  answers the sweep with the projection's own cursor comparison over the rows
  whose pinned expiry has passed, the same rows the prune deletes; the page
  scan, its 20-page cap and the per-page classifier are gone.
- A device woken mostly by notifications now detects that it is stuck behind
  its group. Notification wakes (`CursorPersistence::Frozen`) retain
  undecryptable traffic without tracking stalls, and the main app later sees
  that traffic only as duplicates, so epoch-gap recovery armed only by chance.
  The next `Advance` open now rebuilds the evidence from the retained deferred
  rows, with the same filters live detection applies (mdk#2257).
- `edit_message` refuses with `AppError::InvalidEditTarget`, publishing nothing, unless the target is an available chat message this account sent. Before, the CLI, bindings and connector could publish an edit of another account's message, a reaction, or a deleted message to the whole group, report it as sent, and have every recipient ignore it. Queued local edits apply the same rule at admission. The check is fail-fast against this device's view when the edit is requested, not a guarantee: recipients stay authoritative, and a delete that lands afterwards still yields an ignored edit. A target whose own publish failed and is awaiting retry stays editable.
- Accounts in many groups no longer fill a relay connection's REQ limit (mdk#2266).
  Live group subscriptions go out in batches of up to 50 routes per REQ instead of
  one REQ per group, so a 1,000-group account holds about 21 REQs per relay where
  it used to hit strfry's 200 at about 200 groups. Groups past the limit are no longer
  refused, and history recovery's fetches on that connection find room unless an
  account's routes split across many relay sets or floors.

- Inviting or looking up an account that has published only legacy-profile KeyPackages
  (including MDK 0.8 publications) returns `MissingKeyPackage` with reason `ObsoleteOnly`
  instead of `InvalidKeyPackageEvent` (mdk#1975). Legacy packages are still never selected,
  never hide a current package's rejection. A lookup that ran out of time or relay
  coverage reports `DirectoryLookupIncomplete`; `RelayDirectory` remains for a fetch
  that failed.
- Group changes fail with `AppError::GroupCatchingUp` while unresolved epoch-gap recovery (pending, parked or with its notice dismissed) covers the group's current local epoch. Before, a device that knew the group had moved on could still commit from its stale epoch and fork the group (mdk#2258). The check is advisory: after the user accepts the risk, `acknowledge_group_catching_up` lets the change through. Due self-updates wait up to 24 hours for the gap to close. Messages and leave are not affected.
- One unreachable relay no longer fails an account's transport activation or
  group sync (mdk#1951). Once a relay had failed two connection attempts, the
  relay client refused new subscriptions to it, and when that was a route's
  only relay the whole activation rolled back, taking the inbox and every
  healthy group offline. The client now keeps such a relay's subscription and
  sends it when the relay reconnects. `NostrAdapterMetrics` gains
  `activations_full`, `activations_degraded`, `activations_failed`,
  `group_syncs_full`, `group_syncs_degraded` and `group_syncs_failed`; struct
  literals need the fields or `..Default::default()`.
- A group subscription sync re-sends only the batched subscriptions of the
  relay sets its change touches. Joining or leaving one group used to re-send
  every batch on every relay, briefly doubling each relay's subscriptions, and
  a relay that refused its new subscription failed the whole sync. Now each
  changed relay set commits on its own; one that fails keeps its live
  subscriptions, and the next sync retries only that set.
- A failed or cancelled transport activation no longer leaves untracked REQs
  live on the relay. They used to stay open until disconnect, be re-sent on
  every reconnect, and use up the relay's per-connection subscription limit
  until the account's own subscriptions were refused (#2262).
- A live replay that a relay cut short at its default page (500 events on
  strfry) no longer counts as complete coverage. The relay's stored history is
  paged backwards before its end-of-stored-events counts, so older events in
  the replay window are no longer skipped (#2263).
- An explicit attachment download the device lacks room to publish no longer
  retries forever. The download's disk need (disk reserve plus twice the body:
  its ciphertext and its stored file, less what is already checkpointed) is
  checked as soon as a response declares the size, as a body grows, and
  before the completed-body receipt, counting only the bytes the attempt
  itself still has to write.
  A shortage, or a database that reports it is full while publishing, parks
  the job as `AttachmentTransferState::StorageBlocked` with its ciphertext
  checkpoint instead of scheduling a timer, recording the free space it needs
  in the worker's own frame. The worker readmits it once free space exceeds
  that by 4 MiB and admission would pass; a job that parks again waits out its
  park streak (15 s doubling to an hour), and explicit Retry readmits at once.
  With a strong validator the in-memory sink publishes a checkpointed body
  without another request and the file sink re-requests at most its unsaved
  tail; without one both start over. A full database records at least the free
  space seen at the refusal plus the body and withdraws the completed-body
  receipt. If even the park write fails, the error is returned and the lease
  recovers the job. Parked checkpoints are kept for at most seven days after
  the latest park. Explicit bodies between the transfer limit and 512 MiB take
  the file sink, which follows the same rule (#2239).
- Receiving an attachment no longer holds several copies of it in native
  memory. The body buffer is reserved once from the declared length (an
  undeclared length grows geometrically to half the transfer limit and then
  once to the limit, so the buffer never exceeds the limit and the copy while
  it grows holds at most 1.5 times it; a failed reservation is a transient
  failure, not an abort), decrypted in place, and explicit downloads above the
  automatic transfer limit stream through the existing private file sink.
  Publication writes the body to the encrypted media store, never to a SQLite
  value (see Changed). Integrity checks, resume and retention behavior are
  unchanged (#2241).
- Self-update maintenance commits now publish through the same durable frozen fanout as every other commit. They still confirm on the first relay acknowledgement, and the app's fanout retry schedule keeps retrying every group relay that missed them. Self-updates staged before upgrading finish on their legacy record, which no longer stops retrying when its post-confirmation marker write fails.
- Every publish pass, including secondary retries after a commit confirmed, writes `publish_attempt` and `publish_outcome` audit rows with the endpoints attempted, accepted and failed in that pass.
- A relay still pending when a multi-relay signed publish meets quorum is now reported as `publish acknowledgement unknown` instead of being dropped from the outcome.
- Group changes fail with `AppError::GroupCommitUndelivered` once the group's last confirmed change has been owed to a group relay for two minutes. Before, a device could keep building on a change that members reading only the other relays never received (mdk#2255). The check is advisory: after the user accepts the risk, `acknowledge_group_commit_undelivered` lets one change through. Both advisory checks are evaluated together, so a change refused by both can be acknowledged past each in turn. Due self-updates wait up to an hour for delivery. Messages and leave are not affected.
- History recovery now records why each relay failed. The v5
  `recovery_attempt_finished` row lists each failed relay once, as a hashed
  endpoint reference, with a failure class: NEG-ERR and its reason's category,
  strfry's negentropy-cap NOTICE, a first-reply or pass timeout, a relay outside
  the pool or not usable, the comparison limit, a refused or unexpected fetch,
  withheld events, the pass's own budget, or a local error. `relays_failed`
  and `relays_incomplete` now count distinct relays; before, they were summed
  per compared route and could exceed `relays_required` (#2265).

### Maintenance

- Removed the 41 Delete/wiring tests identified in #2413 across the Rust crates
  and Hermes/OpenClaw integrations. Runtime behavior and public contracts are unchanged.

## 0.13.0 - 2026-10-12

### Breaking changes

- External-signer accounts move their device-local SQLCipher key from the
  plaintext `.external-sqlcipher-secret` file into the configured `SecretStore`
  (`.external-sqlcipher/<account label>`) on first open, then scrub and remove the
  file. Older binaries cannot open these databases; downgrade is unsupported.
  Opening a database with neither credential fails instead of generating a key.

- `PresentedChatRow` adds `draft_version: Option<ChatListDraftVersion>`; struct
  literals must set it. `MessageDraftRevision::includes_chat_list_version`
  compares the two. An identical-text draft save now advances the revision.

- `GroupEvent` adds `LocalGroupCopyTerminated`, `LocalGroupCopyRestored` and
  `GroupMemberLeavesRemoved`; update exhaustive matches. See Fixed for their
  semantics.

- `AppError` adds `ModerationReportingNotConfigured`, `InvalidModerationReportConfig`,
  `InvalidReportedPublicKey`, `CannotReportSelf` and `ModerationReportRateLimited`;
  update exhaustive matches. `MarmotAppConfig` adds `moderation_report_config`;
  struct literals that do not use `..Default::default()` must set it.

- Attachment history adds `AttachmentRole` and the required `AttachmentEntry.role`
  field. Update Rust struct literals; gallery consumers can exclude `InlineEmoji`
  without changing original slots, parser verdicts or acquisition references.
  See [the attachment-history handoff](../marmot-uniffi/ATTACHMENT-HISTORY.md).

- `RelaySyncSnapshot` adds `refusals: Vec<RelayRefusalStats>`. Struct literals
  must set it (`Vec::new()` keeps the old meaning); serialized snapshots omit it
  when empty and older ones still deserialize.

### Added

- `MarmotApp::set_startup_diagnostics_enabled` and `startup_diagnostics_snapshot`
  (`NativeStartupSnapshot`, `NativeStartupStage`, `NativeStartupOutcome`,
  `NativeStartupObservation`) report opt-in, in-memory account, store and
  key-opening phases, migration progress and async completion, with bounded
  history and drop counters. Snapshotting does not query storage or the keystore,
  and ordinary construction keeps capture disabled.

- Relay refusals of live subscriptions are no longer dropped silently (#2247).
  When a relay answers an inbox, group or maintenance REQ with `CLOSED`, the
  account's v5 audit records a `subscription_refused` row: per relay (hashed)
  and route kind, the reason category, whether the relay client kept the REQ
  for a later AUTH or dropped it, and how often. `RelaySyncSnapshot.refusals`
  (and `wn relay-stats`) counts refusals by opaque relay index, route kind,
  category and disposition. `RelayRefusalStats`, `SubscriptionRouteKind` and
  `SubscriptionRefusalDisposition` are re-exported.

- Opt-in SOCKS5 routing. Set `WN_SOCKS5_PROXY` (a numeric `ip:port`) and,
  optionally, both `WN_SOCKS5_USERNAME` and `WN_SOCKS5_PASSWORD` before the
  runtime starts. Relay publishing, account receive and history pools,
  directory reads, moderation reports, Blossom media, Open Ranking and
  collector/audit uploads then connect through the proxy. Relay hostnames
  resolve at the proxy; HTTP still sends the locally validated IP. The policy
  is read once per process, ignores `ALL_PROXY`/`NO_PROXY`, and never falls
  back to a direct connection. With all three variables unset, routing is
  unchanged. See [SOCKS5 routing](README.md#socks5-routing).
  - `MarmotApp::try_with_relays_and_account_home_and_config` now fails with an
    `InvalidInput` I/O error when the `WN_SOCKS5_*` settings are invalid
    (partial credentials, a hostname or a zero port). The infallible dev
    constructors open, but every relay and HTTP connection is refused.
  - `MarmotAppRuntime` agent preview publishing and watching return an
    `Unsupported` I/O error while SOCKS5 is on, because the proxy cannot carry
    QUIC.

- `MarmotAppRuntime::submit_moderation_report` privately reports an account to
  the deployment's moderation team. It sends a NIP-56 kind-1984 rumor, sealed by
  the account key and gift-wrapped per NIP-59 (through the shared Welcome wrap
  path) to the configured reports key, and publishes only to the configured
  relays without account AUTH. This is additive: `report_message`,
  `content_reports` and `dismiss_reports` are unchanged. Reports never carry
  message, group or relay identifiers. Signed wraps are staged before publishing,
  retried after `catch_up_accounts` and purged on sign-out and wipe. Repeats
  within 10 minutes return the existing outcome, and each account may send 20
  reports per hour. The new
  `moderation_reporting_available`, `retry_pending_moderation_reports` and
  `MarmotApp::set_moderation_report_config` complete the surface. See
  `docs/marmot-architecture/moderation-reports.md`.

- Opt-in relay telemetry exports `relay_reconciliation_attempts` and
  `relay_reconciliation_order_unproven_passes`: device-wide, unlabeled counts
  of NIP-77 history-repair passes, and of group passes that returned nothing
  because no time order covered the missing history (#2086). Repeated, those
  passes end in a "history may be incomplete" notice.
  `NostrAdapterMetrics` gains `reconciliation_order_unproven_passes` and
  `NostrReconciliationSummary` gains `order_unproven`; struct literals need
  the field or `..Default::default()`.

- `MarmotAppRuntime::create_identity_local_ready_with_initial_profile` makes a
  caller-selected profile the first public kind-0 of a generated account, so
  contacts never see the key-derived default name. A setup resumed past
  its first local step ignores the profile and returns what its bootstrap
  publishes.
- `AccountManager::propose_onboarding_relay_repair` previews exact ordered
  tags, content and minimal relay changes without signing or publishing.
  Approval retains the existing revision and source-event checks; typed
  previews require checkpoint version 6.

- `MarmotAppRuntime::message_reactions` returns complete local reaction details for one exact
  account/group/message, with one effective entry per sender/emoji and no
  conversation-preview cap. Missing, hidden, deleted, invalidated and
  retention-pruned targets return no participants; blocked reactors are excluded.
  The read performs no network work or conversation-history scan.
- `MarmotAppRuntime::upload_media_files` and
  `upload_media_files_with_client_token` upload file-backed attachments
  (`MediaFileUploadRequest`, `MediaFileTransferControl`) without whole-file
  byte arrays: sources are snapshotted and encrypted into owner-only files
  under the account's `media-staging/` before the first PUT, with the existing
  wire format, ordered server fallback on identical ciphertext and the
  existing publication and local-send admission. Optional retention streams
  into SQLCipher through `stage_attachment_upload_files` and stays bounded by
  the file-backed 900 MiB ceiling while preserving the account quota.
  Explicit large acquisitions use private file sinks, bounded authenticated
  decryption and ciphertext Range checkpoints. Legacy arrays retain their
  smaller limits. Cancellation observed before admission starts publishes
  nothing; admission itself is not interruptible. File uploads wait for their
  size-bounded endpoint attempts without the legacy 16-minute response timeout.
  File uploads require the server descriptor's `sha256` and `size`. (#2175)

### Changed

- Polls can be created in direct conversations as well as groups. Renaming or
  reclassifying a conversation does not disable an existing open poll.

- A sync drain stops waiting once every relay has answered its history REQs,
  counting a relay that refused one for good as answered, instead of running
  to `SDK_FIRST_SYNC_WAIT` / `SDK_DRAIN_WAIT`. A refusal is not evidence of
  served history, so live cursor promotion and incremental activation reuse
  still require end-of-stored-events from every relay.

- `relay.damus.io` is no longer on the retired-relay denylist; the relay is
  still operating. `retired_relay_hosts()` now returns only
  `relay.nostr.band`. Members whose kind-10050 inbox list names only
  `relay.damus.io` can be invited again.

### Fixed

- Invites recover a member's KeyPackage from up to eight discovery relays when
  their advertised outboxes have no usable one, checking signed deletions and
  newer slot replacements before using it. Lookup stays within the existing
  50-second deadline and incomplete coverage stays retryable (#2200).
- Durably accepted sends no longer wait behind startup recovery, automatic push
  gossip, a pending retry deadline or an older publication's secondary-relay
  retry once required acknowledgements and MLS confirmation complete.

- Catch-up downloads a large group backlog oldest first. When more history
  is missing than one comparison pass fetches, the pass narrows to the oldest
  part that fits, so commits no longer arrive ahead of older messages and move
  a member's epoch past messages it can then never read (#2086).
- Catch-up downloads missed group history in far fewer round trips. Each
  comparison pass now fetches up to 256 events (1 MiB), across all relays, in
  batched requests instead of 16 one-at-a-time requests, so a backlog of a few hundred
  messages arrives in a couple of passes instead of dozens. A long drip gave
  commits time to move a member's epoch past older messages it had not
  downloaded yet (#2086).
- Profile, follow-list and relay-list saves still return on the first relay
  acknowledgement, but relays the quorum cancelled now receive the identical
  signed record in a bounded background send. Previously those relays kept
  serving the older version, such as a generated signup name (#2216).

- Explicit onboarding relay edits now preview and publish the selected endpoint
  changes without rebuilding untouched tags: mixed NIP-65 roles, duplicate
  occurrences, tag extensions, unrelated tags and event content survive, including
  when a host supplies an equivalent URL spelling. No-op selections cannot publish. Approval revalidates the exact preview and current
  endpoint policy; restart retries the same persisted signed event. Manual edit
  checkpoints use version 7, which older readers reject; no database migration
  or binding signature change is required. Follow-up to #1979.


- File acquisition enforces disk reserve with or without resumable validators,
  saves interrupted ciphertext tails, retries a rejected resumed representation
  from zero without consuming redirect hops, and discards responses exceeding
  their advertised total. Completed files keep progress in ciphertext units.
  Cancelled file upload completion releases staging even when `send` is false.
- Lossless relay repairs accept case-insensitive NIP-65 read/write markers,
  matching relay-list inspection while preserving their original spelling
  and extension fields through approval and publication.

- Commands and maintenance retain committed activity before subscription waits.
  Manual and scheduled convergence keep subscriber updates owned through route,
  checkpoint, notification and invitation waits, including cancellation.
- Maintenance deadline write failures preserve committed effects. Quiet ticks
  and reopen repair missing deadlines and partial completion without another
  MLS commit or reuse of terminal obligation IDs. Deadline collision repair
  keeps the 24–36-day period; ordinary epoch activity does not postpone an
  overdue periodic rotation.
- Test-only conformance progress distinguishes bounded confirmation replay
  through unchanged opaque rows from a stalled convergence drain.

- Historical canonical replay clears stale removal metadata when the selected
  local MLS leaf remains active, without emitting a false restoration event.
  Activity from commits preceding a disband survives a later terminal-cleanup
  failure. Confirmation replay retries share the normal background row and time
  budget and resume beyond an unchanged deferred prefix. An admitted slice makes
  progress even when storage preparation consumes its wall-time allowance.
- Quiet projection repair releases the accepted delivery's cursor pin. Resumed
  chat and poll publications wake recipients after source revival and checkpoint;
  projection or checkpoint failures retain that session's notification obligation.
  Sent wake ownership lasts through partial fanout acceptance and acknowledgement
  retry, preventing duplicate wakes from resumed publications or direct-send cleanup.

- Identical same-actor fork activity retains its reaction target when a fresh
  canonical commit replaces a withdrawn origin; adoption and revival are atomic.
  Canonical removal and membership cleanup commit together; their native events
  survive later candidate-cleanup failures. Retained-history restoration resumes
  enrolled periodic maintenance without reusing failed work IDs.
- Projection retry retains bookkeeping and failed-message updates as well as
  native events. Live receive keeps the owning client until projection and its
  checkpoint finish. Outbound sends reconcile retained route changes and retry
  failed subscription rebuilds. Comparison admission/checkpoint failures preserve
  repaired subscriber updates.
  A second local deletion discards obsolete retained projections. Terminal groups
  that never reached app projection do not stall later batches. Queues remain
  session-local; this does not claim crash-durable activity replay.

- The HPKE dependency now uses `libcrux-kem` 0.0.10, fixing malformed hybrid-key
  and short-seed panics (RUSTSEC-2026-0330 and RUSTSEC-2026-0331). A documented
  compatibility patch preserves the existing HPKE and OpenMLS versions.

- Group-activity reaction targets retain each accepted commit's authenticated
  actor, source-state delta and fork-withdrawal origin. Authors and recipients
  use the same activity derivation. Account membership rows describe first-leaf
  arrival and last-leaf departure; sibling-only changes create no misleading
  account invitation or departure. Display-component decoding no longer blocks
  otherwise valid legacy MLS evolution. Valid profile repairs retain rename
  activity with an unknown previous name; unreadable resulting components
  produce no invented display values.
  Device-local termination/restoration effects drive participation and pending-send
  cleanup independently of timeline activity. Push cleanup follows actual leaf
  transitions, preserves surviving destinations and clears tombstones only for
  departed accounts. Restoration preserves archive choices and outstanding leave
  intent; reopen repairs terminal projections from durable removal markers.
  Manual convergence retries observe the same native effects as scheduled
  convergence, including reportless membership changes and leaf-token cleanup.
  Group commands and maintenance also observe native membership decisions
  produced while settling retained commits. Secondary projection or route-refresh
  failures preserve the canonical publish result. Failed projection batches
  retain their source identity/time in a session queue; later delivery, drain and
  convergence observations cannot overtake them. Successful-prefix subscriber
  updates survive a later write failure, including an older blocked batch.
  Retries resume completed native and activity-row phases instead of repeating
  old termination cleanup over newer sends. Repaired updates precede newer
  deltas and are returned once by quiet direct-client sync and event reads;
  cancelled drain checkpoints, receive waits and explicit-sync recovery waits
  retain progress and pending notifications. Completed pending-send cleanup retains its exact storage update
  across chat-list conversion failures; message and Welcome notifications wait
  for acknowledgement completion, and retries re-stage removed acknowledgements.
  Push gossip never enters partial host-message summaries. Route rebuilds and
  failed hydration token sweeps use bounded worker retries; one group's failed
  sweep does not block other groups or route refresh. These retry queues are not durable.
  Local termination preserves peer push records and tombstones. Late gossip
  cannot re-add an absent account/leaf pair; hydrated open reconciles missed leaf
  cleanup without treating unreadable groups as empty rosters.
  A pass ending in disband retains preceding commits' activity before the terminal
  row, without emitting the closing commit's incidental member removals.
  Drained and retried batches retain committed activity even when an unrelated
  publication fails. Publish confirmation commits retained anchors and native
  membership cleanup before consuming its retry handle, preserving author
  activity after transient storage failures. Inbound replay failure after confirmed
  publication retains a session retry without changing the publish result.
  Replay-only work remains visible to the convergence scheduler after its
  one-shot notification is consumed, respecting terminal, unrecoverable and
  pending-publication gates and the worker's existing error backoff.
  Eviction realization commits its
  marker, roster and queued-work cleanup together before emitting events.
  Forgetting a group removes its queued projection work without blocking other
  groups. Manual and scheduled retries preserve finalized subscriber updates
  when later route, retention or checkpoint work fails. Maintenance reconciles
  the final canonical local leaf when a batch terminates and then restores a copy,
  without reviving previously failed obligations.
  Rust consumers must handle the three new non-timeline `GroupEvent` variants.
  Existing row IDs and correctly attributed stored rows remain unchanged;
  no account reset or destructive history migration is required.

- When a member lookup does not complete and the member's known inbox relay
  list has no usable relays, the invite now fails with "known member inbox
  relay list has no usable relays and its refresh did not complete" instead
  of "relay-list absence was not authoritatively established". The error is
  still retryable. A completed lookup still returns
  `AppError::MissingMemberInboxRoute`.

- A sent message the engine queued while the group was converging is no longer
  marked failed when an unrelated publish in the same batch fails, and a sent
  row already marked failed revives once a relay accepts its fanout. Before,
  other members received the message while the sender's row stayed failed
  forever, and a sender's poll showed no projection.

## 0.12.0 - 2026-10-02

### Added

- `MarmotAppRuntime::group_app_component` and `update_app_component` read and
  admin-update optional application-owned MLS group components (ids at or
  above `0xf000`). Invalid ids, required components and oversized state fail
  with `AppError::InvalidAppComponent`. (#1929)
- `MarmotAppRuntime::request_explicit_attachment` joins or promotes attachment
  demand to explicit priority without resetting retry budgets, backoff or
  active deadlines. (#2142)

- Hosts can declare a separate kind-10050 inbox relay list.
  `AccountSetupRequest::inbox_relays`, `AccountRelayListBootstrap::inbox_relays`
  (`with_inbox_relays`) and `OnboardingOptions::inbox_relays` set it for
  generated-account bootstrap, missing-list publication on import or login,
  and onboarding's recommended inbox relays. Empty keeps the previous
  behavior: `default_relays` declare both the NIP-65 and the inbox list.
  Persisted setup contexts and onboarding checkpoints without the field resume
  unchanged.
- `MarmotAppRuntime::poll_votes` pages each voter's effective poll selection
  (`PollVotePage` of `PollVote`) with the same rules as the timeline poll
  tally. (#2091)
- `MarmotAppRuntime::send_tagged_text`, `send_tagged_media`, and
  `react_with_media` add application tags (for example NIP-30 `emoji`) to a
  kind-9 chat, a media chat, or a kind-7 reaction; the reaction emits its
  attachments as `imeta`. `MediaUploadRequest::message_tags` does the same for
  a sent upload. Tags are capped at 64 rows and 16 KiB of values, and `imeta`
  rows are rejected.
- `ConversationReaction::reaction_message_id_hex` names the earliest active
  kind-7 carrying that emoji, so a NIP-30 reaction's image can be resolved.
- Account-worker startup is observable stage by stage. Six runtime
  operations, `account_startup_spawned`, `_open_queued`, `_account_state`,
  `_session_open`, `_client_restore` and `_ready_handoff`, record one span
  per stage a starting worker enters. A span stays in flight while the stage
  runs, even after its worker was aborted, and ends as a timeout if the
  ready-wait expired in that stage. An expired ready-wait now fails with
  `account worker startup timed out at <stage>`; hosts that matched the old
  message exactly should match its prefix. (#1911, #2098)

### Changed

- A durable chat mute suppresses ordinary notification traffic but still emits
  a typed direct mention of the receiving account. Sender blocks still suppress
  those mentions. Hosts using notification subscriptions apply their own
  permission, channel, and foreground policy to emitted updates.
  (marmot-protocol/whitenoise-android#2984)
- A successful outgoing upload stages a private local copy before the message
  is published. Once the send is confirmed, the staged bytes gain owners and
  are promoted to retained attachment bytes, so the sender reopens the file
  without reacquisition. Staging is best-effort and bounded; its failure never
  blocks the send. (#2142)

### Fixed

- v5 audit rows keep the engine's `pre_membership_event`,
  `app_payload_retention_expired`, `peel_failed_no_snapshot` and
  `quarantined_group_input_deferred` message reasons instead of writing them
  as `unclassified`. Older v5 rows with an `unclassified` reason stay
  ambiguous (#2120).
- Import and external-signer onboarding now searches the built-in public
  indexers alongside the host's discovery relays when checking an identity's
  profile, follows, and kind-10002/10050 relay lists. Previously a host that
  passed only its own messaging relays could see an existing identity's lists
  as missing and be offered (or automatically approve) a defaults-only
  replacement. A missing list is now concluded, and a repair approved, only
  when every searched relay, indexers included, answers. Indexers are dialed
  on top of the 16-relay inspection cap, so they neither displace the host's
  or the account's declared relays nor get dropped themselves. Repairs still
  publish only to the host's discovery relays and the account's declared
  relays, not to the indexers. A host-selected set from
  `set_onboarding_discovery_relays` is used as given, without indexers, so an
  unreachable indexer can be bypassed. Loopback (development) routes are
  unchanged, and the KeyPackage device check keeps its existing sources.
- A route change, such as creating or leaving a group, no longer resets
  history recovery for every route. Routes whose own window and required
  relays are unchanged keep their certificates and quiet streak; only changed
  and new routes are compared again. Before, each new DM restarted recovery
  over every route, so on accounts with many chats it rarely finished
  (#2110).
- History recovery no longer retries forever when a required relay never
  answers while another required relay answers. After six such comparisons
  for an unchanged goal and required relays, the route counts toward parking
  with the existing "history may be incomplete" notice. Offline passes and
  routes skipped or timed out by the local deadline spend no parking budget
  (#2110).
- Creating a group no longer rebuilds the whole routing table. It installs only
  the invitees' inbox routes, which the Welcome publish needs; `add_group`
  already installs the new group's routes. The rebuild took about 13 ms per
  create at 1000 chats, most of it a quadratic pass over deleted-group routes
  (#2110).
- Host catch-up (`catch_up_accounts`) and the catch-up after creating or
  changing a group no longer run a recovery job while holding the account
  worker. They drain live input and return; the worker's paced recovery job
  serves any history debt. Sends, conversation opens and new DMs no longer
  wait behind recovery, which grew with the number of chats (#2110). New
  `just bench-create-direct-message` measures DM creation latency with 300
  and 1000 existing chats.
- The post-join maintenance sweep no longer decodes every transport fanout
  once per group, which made it quadratic in the number of chats.
- Messages are no longer withdrawn as undecryptable by a convergence pass that selected
  no branch, such as the pass that settles the device's own disband. That pass never tried
  them against the group's state; they now wait for a pass that selects a branch, or for
  the engine to try them against its live state.
- A recovery comparison no longer fails when a group route, window or relay changes after
  the comparison was requested, for example when a Welcome is admitted during startup.
  Such a grant used to fail on every attempt until the next request. Each pass now compares
  the recorded incremental-history debt rather than the live routing snapshot, so it
  queries exactly the relays its settlement certifies. (#2100)
- Attachments from a message whose epoch the group had already left no longer spin in
  `RetryScheduled` forever. The receiver cached only the current epoch's encrypted-media
  key, so a media message surfaced after a commit (common for agent sends) had no key.
  The engine now captures the key for the message's source epoch while it authenticates
  the message and carries it on `GroupEvent::MessageReceived::encrypted_media_secret`,
  so projection caches it even when the same convergence pass advanced more than five
  epochs and pruned that epoch's retained state. A media message that arrives late, after
  the receiver left its epoch, gets the key from that epoch's retained state before the
  pass merges further commits. Events without a carried key fall back to the engine's
  retained epoch state (newest five epochs), and that fallback no longer gives up when
  the live export fails.
- Missing-key attachment deferrals back off and fail after about eight minutes instead of
  repeating every 15 seconds forever, and a blob that every Blossom server reports as
  404/410 fails without retrying. Retry and download-again derive a missing source-epoch
  key from the engine's retained epoch state, so they recover attachments projected before
  that key was cached.

## 0.11.0 - 2026-09-29

### Changed

- A recovery scope whose route no comparison backend could compare is no longer counted as
  a quiet pass. No relay answered it, so it spends none of the three-pass parking budget and
  is recorded as unserved; incremental history still waits for a capability change.

- Generated accounts can copy signed kind 10002, kind 10050, and kind 0 records
  to separate public indexers after bootstrap confirmation. Relay-list and
  profile edits also schedule indexer copies after account-relay acknowledgement;
  indexer latency does not delay account readiness or edit returns. Pending
  copies are cancelled on runtime shutdown or account removal.
- Account recovery completes loss of unknown scope on NIP-77 comparison certificates. A
  scope certifies when every required relay finished an untruncated comparison over a
  window that covers the scope's whole goal and every difference was admitted. A queue-loss
  goal starts at the earliest wire `created_at` among the deliveries it lost. A goal with no
  known lower bound never certifies. Cold-start and incremental history compare the
  retained 30-day inventory window. An epoch gap also completes once its group's local
  epoch passes the stalled one. A relay whose compared set fills the request limit counts
  as truncated and cannot certify. (#2068)
- A recovery obligation parks once every route it still cannot certify has been compared
  three times in a row for its goal with its required relays answering, and nothing was
  admitted or certified. It then waits for new evidence or explicit repair. A comparison whose
  required relay failed or timed out does not count; one that answered but could not fetch a
  claimed event, or whose events were not durably admitted, does. New evidence, or durable
  admission on a route, starts that route's count over. (#2068)
- Recovery compares off the account worker. The worker then admits what the
  comparison fetched a few events per turn, between commands and live input, and never
  through the live delivery queue. Recovery reuses the live subscriptions instead of
  re-subscribing, so it no longer replays history the account already holds. The separate
  online epoch-gap job is removed. (#2068)
- The inline recovery executor is gone; every cause and caller runs the one comparison
  job. A post-join maintenance boundary installs only its own REQ and completes on that
  REQ's end of stored events. Known-event demand and routes with more than four relays are
  compared off the worker too. Explicit catch-up, `sync()` and a directly owned client's
  `next_event()` drain the live queue, then run one job in place, and no longer re-activate
  transport or re-issue live REQs once the session is active; a route change still
  refreshes them. `repair_full_history` compares every route over the retained-inventory
  window in one pass inside its 60-second budget and installs no unfloored replay, so it
  no longer fetches history older than the retained window. Full history has no lower
  bound, so the repair never reports complete. When every route's window certified it
  returns `BelowRetentionWindow` and closes its request. The owner's automatic passes over
  a pending explicit request keep each route's certified window, off the parking streak,
  and close it once every route is certified: no explicit-history debt is left
  to park into a "history may be incomplete" notice, and nothing is recorded as coverage.
  Otherwise it returns `CoverageUnproven`, `Cancelled` or `Deadline`, and the debt stays
  open for the owner's ordinary retries. The comparison gets the first 50 seconds; routes
  that finished by then are admitted in the last 10, stopping at a turn boundary if the
  budget runs out; that budget starts once the repair holds its process credit. A certified
  window wins over the clock: `Deadline` means admission ran out, or the cutoff cut a
  route and left the window uncertified. Only cancellation discards what a pass already
  fetched.
- Account recovery certifies a route on its operated relays only.
  `MarmotAppConfig::recovery_operated_relays` names them and defaults to
  `wss://relay.eu.whitenoise.chat` and `wss://relay.us.whitenoise.chat`. A route that lists
  none of them still certifies on all of the relays recovery can dial; a retired, unsafe or
  over-cap relay is never required. The route's other relays are still
  compared and their events admitted, but their failures never withhold completion or
  schedule a retry. Changing the operated set rebuilds pending recovery scopes. (#2068)

- A full account delivery queue now spills deliveries into the account database instead of
  dropping them. The worker admits spilled deliveries through the ordinary ingest path,
  alternating them with live ones, and removes each row once ingest has seen it. Deliveries
  the account had already seen are not stored. A delivery still becomes queue loss when the
  router's hand-off is full (4,096 deliveries or 4 MiB), when it would exceed the durable
  spill limits (8,192 rows or 16 MiB per account), when its spill write keeps failing, when
  its row cannot be decoded, or when it is still unadmitted after 8 retries.
  `RelayPlaneHealth` reports `account_delivery_spilled` and
  `account_delivery_spill_already_seen`. (#1947)
- A live delivery now promotes the persisted transport cursor with its own checkpoint, once
  every account subscription has replayed its stored history and no loss is pending. An
  account that has never persisted a cursor waits for its first drain checkpoint. Only a
  drain checkpoint or settled loss used to, so a restart re-downloaded everything the
  account had received live since its last drain: on the #2069 scorecard, a full pass of the
  account's history on each relay. No checkpoint passes a delivery that a restart would then
  no longer fetch while it is queued, or taken and not yet ingested durably. That includes
  the checkpoint a catch-up drain or startup receive runs when an older delivery fails to
  ingest after newest-first replay remembered a newer cursor, which used to persist a cursor
  a restart no longer fetched the failed delivery from. A delivery goes to the durable spill
  instead of the queue when it arrives while a checkpoint saves and falls below the floor
  that checkpoint commits, or when only a live promotion put it below the floor. It becomes
  queue loss bounded by its `created_at` when the spill cannot take it;
  `account_delivery_spilled` counts it. (#2069)

### Fixed

- Account setup readiness, setup resume and onboarding reads no longer fail with a JSON
  parse error (`expected value at line 1 column 1`) when they race a setup-phase or
  onboarding-checkpoint update. Each atomic replacement of those owner-only files used to
  zero the previous file afterwards, so a reader that had already opened it could read
  zeros. Only local signing-key files are still zeroed, and their reader now re-reads
  instead of parsing a replaced key file.

- Keep conversation-window commands usable across content-only replacements
  and report a stale window when an older visible-anchor quote names a row
  dropped by a background replacement. (#2052)

- Keep chat-list-window commands usable across content-only replacements, so
  paging no longer livelocks on `StaleWindow` while other chats' previews,
  badges or order keep changing. An older visible-anchor quote naming a row a
  background replacement dropped reports a stale window.

- Keep an account's delivery route open when its relay notification consumer lags. A lag
  used to close the route and send the account worker through reconnect. The reopened
  session replayed the backlog from the loss-fenced cursor, which overflowed again, so large
  accounts looped in reconnect backoff and commands failed with `transport_closed`. The
  consumer now resumes on the same receiver and the worker keeps serving commands. It
  records the loss durably, bounded below by the lowest `since` among every REQ the
  account's SDK context issued, live or closed, or unbounded when any of them had no
  `since`, and recovers it by comparison. `RelayPlaneHealth` still counts each lag in
  `notification_forwarder_lag_incidents`, `notification_forwarder_lagged_notifications`
  and `notification_forwarder_restarts`. Only an unexpected consumer exit
  (`notification_forwarder_unexpected_exits`) still closes delivery and reconnects. (#2070)

- Hand a pending loss signal to an account's next delivery route when the worker drops its
  queue with the control record still in it. The record died with the queue, but the plane
  still counted it as queued, so the loss generation could never clear and the transport
  cursor stayed fenced for the rest of the process. (#2070)

- Publish and rotate KeyPackages without a full-history resubscription. Both used to
  activate transport with no `since`, which replayed every held event on every inbox and
  group route and left a notification lag during that replay unbounded. They now reuse the
  live activation or rebuild it from the transport cursor, like reconnect. (#2070)

- Floor the post-join maintenance REQ and retained-route REQs, so a notification lag while
  one is live charges a bounded loss. The maintenance REQ used to request the group's full
  history, and a retained route was backfilled in full on every activation. Either made
  the loss unbounded, which parks as "history may be incomplete" and keeps the transport
  cursor fenced. Maintenance is now floored at the creation of the Welcome that installed
  the copy, never the local join, so a member that was offline still sees the commits
  made between that Welcome and its join. A retained route is floored at the moment the
  device saw it replaced, and from no later than the account cursor. A retained route
  stored before this release has no such moment, so the first account load after the
  upgrade records one and keeps it: earlier sessions fetched its older traffic, and the
  comparison covers the rest. Both floors sit fifteen minutes below their anchor
  (`HISTORY_FLOOR_CLOCK_SKEW_ALLOWANCE`) to absorb clock skew. The routing table now keeps
  each group's current route first. It used to sort a group's routes by id after a route
  change, so the adapter could resume a retained route from the cursor and backfill the
  current one in full. A locally deleted group no longer lists its current route twice.
  A hidden group's route replaced while it was hidden keeps a full backfill until the
  group is restored. (#2070)
- Recover end-of-stored-events (EOSE) that a relay notification lag lost. A lost EOSE left
  its subscription's replay coverage incomplete for good: the next activation
  re-subscribed instead of reusing the live one, live cursor promotion stayed off, quiet
  drains waited out their full first wait, and post-join maintenance did not observe its
  boundary. A lag still marks no EOSE complete,
  since it cannot tell a lost one from one still coming. Once the receiver has gone 30
  seconds without another lag, each REQ issued before the lag that has not reported EOSE on
  a relay is repaired there. When the SDK recorded that relay's EOSE, the lag lost only the
  notification, and the EOSE is recorded with no network traffic. Otherwise the REQ's CLOSE
  and the REQ again, unchanged and under its own id, are queued together or not at all, and
  the relay replays from the same `since` before a fresh EOSE; the relay never sees a
  repeated live id, and the SDK keeps the REQ it restores on reconnect. A relay whose
  re-issue went out is not re-issued again, but later repairs still read the SDK's record,
  so a fresh EOSE that a later lag lost still completes; one that got nothing is repaired
  again after the settle window. The notification-loss floor does not move. `NostrRelayClient` gains
  `reissue_subscription` and `subscription_eose_received`, unsupported by default, and `NostrTransportAdapter` gains
  `reissue_subscriptions_awaiting_eose`. The `nostr-sdk` fork pin moves to
  `a9c7a6423d104c603de6ea8244265ea17f0f9d89` for `Relay::batch_msg` and
  `Relay::subscription_received_eose`. (#2070)

- Preserve normalized line breaks in ingested kind:0 `about` text while still removing
  unsafe controls from every known profile string. Previously flattened cached bios stay
  until a newer event replaces them. (#1973)

- Count account-scoped relay publishes on the shared device-wide publish counters.
  `relay_publish_attempts` was previously always zero in production. Success now
  requires the acknowledgement threshold, and publishes dropped in flight (such as
  endpoints abandoned after quorum) count under the new `publish_cancellations` /
  `relay_publish_cancellations` series rather than as failures. (#1950)
- Judge epoch-backfill overflow retry backoff by the durable delay. A loaded runner
  can spend more than a second after that reservation is written, which previously
  failed a test that still required nearly the full cooldown to be remaining.

### Changed

- Restrict the account-local overflow marker writer to durable loss evidence. The account
  mutation path imports that evidence into recovery demand; runtime dispatch consolidation
  remains separate integration work. (#1946)

### Breaking changes

- `FullHistoryRepairIncompleteReason` gains `BelowRetentionWindow`
  (`full_history_below_retention_window`): an explicit repair certified every route's
  retained window, but history below that window was never searched, and the request
  closed without leaving debt or a notice. Exhaustive Rust
  matches must handle it; bindings see only the existing error code.
- Remove `MarmotAppConfig::dev_epoch_backfill_eose_wait_ms` and
  `dev_epoch_backfill_execution_quantum_ms` with their `with_*` builders. Recovery no
  longer drains toward an end-of-stored-events budget, so neither had an effect. The
  bindings and CLI never exposed them.
- Remove `RecoveryExecutorMode` and `MarmotAppConfig::recovery_executor_mode`. The
  conservative mode ran one recovery obligation per grant as a same-schema rollback
  switch. The bindings and CLI never exposed it, and recovery now has one execution
  path. Rust callers that set the field should delete it. (#2068)
- `HostPerformanceOperation` and `RuntimePerformanceOperation` gain 28 shared and
  nine Linux-specific host stages. Downstream exhaustive Rust matches must handle
  the new variants. The snapshot struct layout is unchanged; stages appear in
  `runtime_operations`.
- `MarmotAppEvent` gains `HistoryNoticesChanged { account_id_hex, account_label }`, and
  `GroupRecoveryStatus` gains `history_may_be_incomplete` and `history_notice_ids` (both
  serde-defaulted). Exhaustive Rust matches and struct literals must handle them. (#2068)
- `AppPriorNostrRoute` gains `replaced_at` (serde-defaulted), when the device saw the route
  replaced as its group's current route. Struct literals must set it. (#2070)

### Added

- Record account recovery in the opt-in v5 audit log. The recovery owner writes
  `recovery_need_changed` when loss or demand is charged to an obligation (with its cause,
  goal bound and newly charged count), when a parked obligation's notice is shown or
  dismissed, and when a parked obligation closes; `recovery_attempt_started` and
  `recovery_attempt_finished` for every reserved attempt (obligations, endpoints, budgets,
  compared and certified routes, events retrieved, duplicate, rejected, retained and
  refused, relay counts, and a `progressed` / `quiet` / `unserved` / `deadline` /
  `cancelled` / `superseded` / `failed` outcome); and `recovery_obligation_reassessed`, its
  verdict on each obligation it settled (including an explicit request closed below the
  retained window) and whether another attempt may follow. The
  transport cursor writes `transport_cursor_advanced` for drain checkpoints, settled loss
  and retired notices, and for a live promotion only when it moves the cursor past the
  rebuild lookback, with spill and queue-loss placement counts. Each lag-lost end-of-stored-events repair
  pass writes `subscription_eose_repaired` with its relay counts (awaiting, completed without
  traffic, re-issued, re-issued earlier, failed) and whether a follow-up was scheduled. Rows carry enums, counts
  and hashed references only, and are written only when a v5 recorder is installed.

- Route reviewed host stages through the existing runtime telemetry registry,
  including its fixed metric names and all five outcomes in snapshots and OTLP.
- Surface parked recovery as "history may be incomplete". `MarmotAppRuntime::history_notices`
  lists each parked occurrence as a `HistoryNotice` (opaque `notice_id`, `HistoryNoticeCause`,
  optional group, parking time); a group's own occurrences also appear in
  `GroupRecoveryStatus`. `dismiss_history_notice` runs on the account worker and durably retires
  exactly that occurrence as its own outcome, never as coverage, returning false for a stale id.
  Retiring the last pending loss obligation releases the transport-cursor fence without recording
  a recovery success, and a late observation of retired loss releases it too instead of
  re-raising it. A dismissed incremental-history notice stays dismissed: later startups still
  compare, but parking again on the same routes and required relays raises no new notice.
  `HistoryNoticesChanged` announces parking, un-parking and dismissal; a group whose own notices
  changed also gets `GroupStateUpdated`. (#2068)

## 0.10.4 - 2026-09-20

### Fixed

- Keep pure explicit downloads outside automatic budgets and defer transient disk pressure before the verified-body receipt. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Preserve verified publication across network revocation, refund interrupted acquisition claims, park denied demand without polling, and avoid permission locks around network polling. Native retries remain unchanged. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Make locally accepted pending rows visible to conversation-window navigation before relay publication completes and
  avoid unused attachment plaintext hydration during draft saves. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))

- Apply execution-based exponential backoff to repeated epoch-backfill overflow failures. ([#1949](https://github.com/marmot-protocol/mdk/pull/1949))

### Breaking changes

- `MarmotAppConfig` adds `attachment_acquisition_mode`; full struct literals must set it or use `Default`. Handle the new terminal `AttachmentTransferState` and configuration/account `AppError` variants in exhaustive matches. `AttachmentTransferStatus` carries source MIME metadata for automatic policy observation. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Add host-managed automatic attachment demand with denied startup and generation-fenced per-account media permission. Bound network retries and stop automatic reacquisition after retention failure. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Add durable token-correlated local send admission and restart recovery without changing existing send-method
  completion semantics. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))
