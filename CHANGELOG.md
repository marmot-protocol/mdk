# Changelog

Unreleased entries wait as fragment files in `changelog.d/` until a release folds them in here.

## 0.19.0 - 2026-11-22

See the [release notes](docs/release/0.19.0.md) and the [0.18.0 → 0.19.0 upgrade guide](docs/integration/0.19.0.md).

### Breaking changes

- The account database advances from schema 216 to 218. Upgrade every process that opens it, including extensions.
- Draft input saves keep omitted attachments. Send an explicit removal for an attachment the user deletes.
- The retired QUIC live preview of agent text is removed (marmot-protocol/marmot#513). The `transport-quic-stream`,
  `transport-quic-broker` (`marmot-quic-broker`) and `agent-stream-compose` crates, the broker Docker image and its
  GHCR workflow are gone, and so are the agent stream APIs in `marmot-app`, UniFFI and the C bindings and `wn stream`.
  The per-crate changelogs list each removed surface. Groups that already require
  `marmot.group.agent-text-stream.quic.v1` (`0x8006`) keep working: clients still advertise and validate it.
- `wn-agent` and the Hermes and OpenClaw plugins no longer send live agent text previews over QUIC; every reply is one
  durable message. The `agent-control` v2 stream operations (`stream_begin`, `stream_append`, `stream_status`,
  `stream_progress`, `stream_finish`, `stream_finalize`, `stream_cancel`), their `stream_begun` and
  `stream_finalized` responses and the `stream_update` event are removed; `send_final` is the reply path.
  `wn-agent` drops `--insecure-local-broker` and the bootstrap `--quic-candidate(s)` flags and the `quic_candidates`
  bootstrap output, and still accepts `--no-quic` as a hidden no-op for older installers. The Hermes and OpenClaw
  installers drop `--enable-streaming` and `--quic-candidate`; OpenClaw still accepts and ignores the
  `quicCandidates`, `streaming` and `blockStreaming` keys older installers wrote, and the Hermes gateway configure
  helper drops `--streaming`, `--transport` and `--configure-global-streaming` and keeps Marmot streaming off.

### Added

- Thread views can send NIP-22 messages from Rust, MarmotKit and C. Timelines expose the thread root and parent,
  and thread messages count toward chat activity, mentions and notifications.
- Rust hosts can submit tagged text, replies, edits and custom events with a token that survives restart.

### Changed

- `wn-agent` passes NIP-22 thread messages (kind 1111 with a parent) to the agent like chat: as inbound messages whose
  reply target is the parent, with their edits and deletes, live and on replay.

### Fixed

- Update `url` to 2.5.9 for RUSTSEC-2026-0592 (#3601).
- Linked devices resend invitation answers promptly after losing a device-group fork. A sign-out held by device
  removal also stops retrying maintenance every 15 seconds.
- `wn-agent` no longer passes a message's original text and attachments to the agent when it was deleted before the
  agent caught up after a lag, including while earlier catch-up messages were still being written; the agent receives
  only the deletion.

## 0.18.0 - 2026-11-20

### Breaking changes

- Multi-device ships. Every build includes device groups and every MarmotKit,
  Marmot C and WN Agent runtime opens with them on: device linking, the
  linked-device list, sign-in review, history transfer, backups and admin
  step-down on Leave work without a special build or constructor, and a
  runtime with them on advertises the device-roster component. The `dev-device-groups` and
  `unreleased-device-pairing` Cargo features and the `--dev-device-groups`
  build flags are gone. `MarmotAppConfig::dev_device_groups` is renamed
  `device_groups` and defaults to true; `wn` and `wnd` honor
  `WN_DEVICE_GROUPS=0`. Ship the new library in every process that opens a
  root, extensions included (#3476, #3519).
- A sibling Welcome that forwards how the adding device holds a chat is
  version 3, which devices older than this release refuse (#3564).
- MarmotKit adds `MarmotKitError.GroupCommitPending`, `NoUsableRelay` and
  `ReactionNotFound`, `GroupEventKindFfi.GroupChangeNotDelivered` and
  `OnboardingActionFfi.RemoveUnusableRelays`; exhaustive switches must add
  them. `AppMessageRecordFfi.invalidated`, `OnboardingDevicePackageFfi.client`
  and `OnboardingRelayTagChangeFfi.removal_reason` are new fields without
  defaults. C adds statuses 131 to 133 and changes the layout of seven
  records. See the crate changelogs.
- Account databases migrate from schema 207 to 216 (0208 to 0216), the shared
  database from 4 to 5 (0005) and the per-account directory cache from 2 to 3,
  on first open. Older binaries refuse the upgraded databases; downgrade is
  unsupported.
- C hosts: `MarmotSelectedMessageDraftAttachment` and
  `MarmotAttachmentStorageUsage` gain fields for file-backed draft attachments
  (#3431), so their layouts changed: rebuild with the matching header and
  library. Rust hosts using `storage-sqlite` directly pass
  `StoredMessageDraftAttachmentInput`s to `save_message_draft_if_revision`.
  See the crate changelogs.

### Added

- Device-link status reports how many chats remain on each device
  (`chat_progress`) (#3543).
- `attachment_removals` (Rust, UniFFI, C) exposes durable, bounded removal
  identities for host derivative caches (#3495).
- Raw message records carry `invalidated` for rows kept only as invalidated
  tombstones (#3463).
- `start_direct_conversation_with_options` founds a direct chat with a
  disappearing-message duration in its founding state (#3432).
- NIP-22 comments (kind 1111) project as editable replies with their parent,
  media and author edits; account migration 0208 repairs retained ones
  (#3435).
- Onboarding lets users fix a relay or inbox list whose check was
  inconclusive (#3445), suggests removing declared relays that cannot serve
  their role (#3453), names the app another installation's package reports
  (#3447), and keeps a single-device acknowledgment across a long pause
  (#3444).
- The v5 audit records every invite on the sender, not only a new group's
  founding Welcomes. An invite into an existing group records
  `welcome_prepared` naming the exact KeyPackage its Welcome answers, every
  pass over the Welcome's relays records `welcome_publish_started` and
  `welcome_publish_finished` (first sends, startup retries, redeliveries and
  background retries, each with its own attempt id), and the generic publish
  rows of Welcomes name their group. Two new group-scoped kinds say how big a
  Welcome is (`welcome_event_size`) and why one will never be sent
  (`welcome_withdrawn`: withdrawn, its commit superseded, expired, or refused
  as too large with the oversized size class). A receiver must accept the new
  kinds before it gets these rows; one that rejects them loses only them, so
  repin and deploy the White Noise audit receiver before shipping. The rows
  are best-effort evidence, and a missing row proves nothing: a Welcome whose
  KeyPackage had no transport source has no `welcome_prepared`, a pass cut
  off by a worker stop may have no finished row, and a Welcome that settles
  while no process watches it has no `welcome_withdrawn`.
- A group send none of whose relays MDK may send to, such as relays at
  private-network addresses, fails as a typed no-usable-relay error, not a
  generic publish failure: `AppError::NoUsableRelay`,
  `MarmotKitError.NoUsableRelay`, `MARMOT_STATUS_NO_USABLE_RELAY` (133) and
  the CLI's `no_usable_relay` code. Nothing was sent, and a retry fails the
  same way while the group's relays stay the same (#3305).
- Rust, UniFFI, and C expose bounded availability for the selected account's direct follows (#1996).
  `follow_availability_page` reads the persisted projection without network I/O;
  `refresh_follow_availability` checks at most 100 follows and reports partial progress.
  Availability records usable KeyPackage state and freshness, not which app an account installed.
- MarmotKit and C bindings expose emoji-scoped reaction removal and a typed
  `ReactionNotFound` outcome for local no-match results. Target-wide removal
  remains available (#1963).
- The v5 audit records a pending commit going stuck, confirming without a
  relay's `OK`, or being given up (#3460). The new `pending_commit_changed` row
  says `stuck` once, at the commit's first read-back past the ten-minute bound;
  `read_back_confirmed` or `echo_confirmed` when a read or the account's own
  echo confirmed it; or `given_up` when it reached no relay and rolled back. It
  names the group and the commit by hashed references, as the commit's publish
  rows do, with seconds since the first send attempt. A receiver must accept
  the new kind before it gets these rows; one that rejects the kind loses only
  them.
- Group changes MDK gives up after their call returned are recorded until the
  user has seen them (#2332). A direct group change that answered
  `CompletionUnknown`, or a queued one that answered `AcceptedPending`, gets a
  durable record when MDK later rolls its commit back: no relay received it
  (`not_delivered`), it fits none of the group's relays (`event_too_large`), or
  every relay refused it (`refused`). Read them with
  `group_changes_not_delivered` (Rust, UniFFI, C, `wn groups
  changes-not-delivered`) and clear one with `acknowledge_change_not_delivered`.
  A direct change is also announced by the new `GroupChangeNotDelivered` group
  event; a queued one by `QueuedIntentRefused`, as before. Handle the new event
  kind and read the records on start: the events only notify. A record names
  the change by its group, commit id, kind and time only. A change staged before
  this release and given up after it is not recorded. Account migration 0210
  adds the table.
- `group_pending_commit` (Rust, UniFFI, C, `wn groups pending-commit`) reads
  the group's own commit that has not confirmed yet (#2332): `Sending` for its
  first ten minutes and while no relay may hold it, `Stuck` once some relay may
  hold it and none has acknowledged it, which MDK never gives up. It names the
  change the commit carries, when its first attempt started, and the relays
  that may hold it, are still owed it, or gave a final answer. Poll it while
  showing a stuck change.
- Usage diagnostics show where interactive onboarding stops (#3440). MDK
  itself records a new `mdk_onboarding_summary` aggregate each time an
  onboarding attempt saves a step in a blocking status. A row carries the step,
  the status, the primary and per-source issue classes, the finding context and
  a bucketed count of failing sources. It never carries an endpoint or an
  identity. Each attempt counts a distinct step, status and issue once, and only
  under usage-and-diagnostics consent. The catalogue change gives the registry
  a new revision, so users who opted in are asked to accept the expanded scope
  again. Hosts need no new calls.
- Keep composer-draft attachments up to the encrypted-media blob limit as
  files (#3431). `stage_message_draft_attachment_file` (Rust, UniFFI, C) copies
  a host file into the account's encrypted media store and adds it to the
  draft; the draft owns the copy across text-only saves and restarts, and
  saving, clearing or sending the draft releases it. Selected drafts mark such
  attachments `file_backed`; keep them through edits with
  `save_message_draft_inputs_if_revision`'s `Retained` inputs, read them with
  `read_message_draft_attachment` (1 MiB chunks) or
  `open_message_draft_attachment_handoff`, and upload them with
  `upload_message_draft_attachments`, whose references carry the staged
  bodies' descriptors and digests, before `send_message_draft`. No full-size
  buffer crosses the binding after staging. Storage usage reports the staged
  bytes as `draft_bytes`. `message_draft_attachment_if_revision` refuses a
  file-backed attachment (it still reads inline ones), and the legacy
  whole-draft read refuses a draft that holds one.

### Changed

- Idle accounts no longer wake every 15 seconds (#3258, #3361, #3568). Session
  maintenance, device pairing, the device-group passes, recovery, post-join
  work, attachments, avatars and the other maintenance jobs run when an event
  wakes them and at the deadline their data gives, and an idle maintenance
  tick takes no writer transaction (#3487). Deadlines a week or more out ride
  the hourly heartbeat's run, so they can be up to an hour late.
- WN Agent accounts run with device groups on, through the runtime's new
  default; the connector has no switch for them.
- Runtime shutdown gives Welcome waves still publishing up to 2 s before it
  cancels them, so a Welcome a create or invite just started is usually sent
  before exit (#3488). `shutdown_and_close` still closes storage first: a wave
  that settles after the close leaves its Welcome owed, and the next start
  sends it again.
- Destructive sign-out reports queued member leaves in its leave failures
  instead of counting them as left (#3539).
- A group change made while the group's own commit is pending fails with the
  new `GroupCommitPending` (Rust `AppError`, UniFFI `MarmotKitError`, C
  `MARMOT_STATUS_GROUP_COMMIT_PENDING`, CLI `group_commit_pending`) instead of
  the engine's untyped refusal (#2332). It is checked before `GroupCatchingUp`
  and `GroupCommitUndelivered`, and no acknowledgement releases it: retry once
  the commit confirms. A member's leave and invite decline fail the same way.
  Disbanding and an admin's leave are still accepted, and messages are accepted
  but wait in the queue until the commit resolves.
- `send_message_draft` (Rust, UniFFI, C) and captured-media admission match
  prepared media to the draft's attachments after the normalization an upload
  applies (#3431): a V1 upload's trimmed file name and either version's
  canonical media type now match the draft's own strings, so a correct upload
  of a draft attachment named `" clip.mp4 "` or typed `Video/MP4` sends.

### Fixed

- An invitation answered on one linked device shows as answered on the other
  within seconds instead of about a minute (#3568).
- When a device is linked to an account with two or more devices, the
  approver adds it to its chats while active and the other devices wait, so
  they no longer both add it and fork chats (#3562).
- A newly linked device no longer reads pre-join history as an epoch gap,
  which offered a needless Reset Device List and held its chats back (#3552).
- A device the user linked and then removed no longer comes back as a new
  sign-in, nor as "Rejected on another of your devices" (#3508, #3482).
- A fresh account no longer fails KeyPackage rotation or reports
  `RecoveryRequired` because an early read created its database (#3483,
  #3509).
- A refused Welcome delivery no longer drops a later delivery of the same
  Welcome as a duplicate (#3520).
- Background history fetches without a live tail, and epoch-gap visits, end
  instead of polling relays continuously, and recovery status is announced
  per route (#3541, #3548).
- The OpenClaw plugin declares its tools and ships a Doctor contract, so it
  installs and updates on OpenClaw 2026.10.10 and later (#3518).
- Emoji discovery applies its 60-set limit after deduplicating (#3494).
- A newly linked device gets each chat as the device that adds it holds it
  (#3546). A chat confirmed there from before invitation generations arrives
  confirmed instead of as an invitation from the account itself; one with an
  invitation generation settles through its shared decision, and can show as
  pending until that decision arrives (#3556). An unanswered invitation arrives
  pending from its real inviter.
  The sibling Welcome that carries this is a new version 3, which linked
  devices must both run to read.

- A relay the host-safety rule refuses no longer reads as one a send may have
  reached, or hides that a send is too large (#3305). A Welcome whose inbox
  relays it refuses, on the first attempt or a later retry, no longer counts
  toward maintenance's ambiguous-exposure total. A commit or message that every
  other group relay refused for size fails as `EventTooLarge`, as it would
  without the refused relay.
- Stop queued detached Welcomes from starting relay publication after their
  native origin loses (#3493). Parked recovery keeps its exact retry for
  canonical re-adoption; terminal loss retires it. Already-started relay I/O
  still completes.
- Continue group history recovery across partial MLS epoch advances. Retained
  unreadable messages can arm the next recovery request after local replay
  settles, without reopening the account or waiting for fresh traffic.
- Stop a retried emoji-set install from deleting emoji the user already has
  (#3464). Reinstalling the installed version keeps each image whose download
  fails, and the result's `skipped` list names only entries left without an
  image.
- Find sticker packs an imported account's relay list does not lead to.
  Sticker pack reads (discovery and installed-pack refresh in
  `sync_sticker_packs`, `fetch_sticker_pack`, `install_sticker_pack`, and
  resolving a received sticker) now query the runtime's configured relays as
  well as the account's NIP-65 relays. Packs are published to few relays, so an
  account whose relay list came from another client saw an empty pack browser
  and default-pack installs failed with `StickerNotFound`. The newest version
  of a pack among the relays that answered wins; a read that misses a relay
  can keep an older version until a later read reaches it. The installed list (kind 10031) and other
  sticker publications still go only to the account's own relays. Emoji set
  reads (`sync_emoji_sets`, `fetch_emoji_set` and the sets `user_emoji_list`
  points to) use the same relays; the account's own emoji list (kind 10030) is
  still read from its relays only. A pack's share link now names only relays
  that served the version MDK kept, never relays that were merely queried or
  hold only an older version.
- Stop onboarding's relay checks from failing healthy relays (#3439). A relay
  that closes a query with its NIP-01 `auth-required:` reason behind an
  `ERROR: ` wrapper is reported as needing authentication, not as restricting
  access, and an account that can sign authenticates to it and asks again
  instead of failing the check. A check now waits up to 8 seconds, not 3, for
  a relay to finish answering, so a slow gift-wrap inbox query on a mobile
  network no longer times out. Other relay reads keep their 3-second wait.
- Confirm a group change that stayed pending after an unclear relay answer
  once the account's own group subscription receives that exact change from
  one of the group's relays (#2332). The relay holds it, whatever it answered
  the publish, so the change confirms instead of waiting out its retries; the
  relay counts as having accepted it even after it refused a later attempt.
  A copy under another event id, or from a relay outside the group's list,
  confirms nothing.
- Confirm a group change that is still pending ten minutes after its first
  send by asking its relays for it (#2332). From then on, each retry of a
  relay that may hold the change first reads that exact change back from it,
  and a relay that returns it confirms the change. The read never signs in as
  the account, sends one request per relay, at most eight per account per relay an hour, and feeds
  nothing into message handling. Any other answer changes nothing: the relay
  is resent to as before, and nothing rolls back because a read found nothing.
- Give up a group change that reached no relay (#2332). Ten minutes after its
  first send, a pending change that no relay accepted and none may hold, with
  relays still unreached, rolls back once the device shows it is online: a
  relay refused a send made since then, or a relay answered a read of the
  change, asked at most once an hour. The unreached relays are given up, and a
  queued change is announced as `QueuedIntentRefused` with reason
  `not_delivered`. A change any relay may hold still never rolls back,
  including one stored before this release recorded that exposure, and an
  offline device keeps the change pending.
- Retire a queued group change when its commit resolves after a restart
  (#2332). The commit's stored send now names the queued change it came from,
  so a confirmation, a size refusal or giving the commit up retires that change
  instead of leaving it queued to be prepared and sent again. A change whose
  commit was stored by an earlier release is prepared once more after such a
  rollback, and its new commit carries the link.
- Prepare a queued message once across retries and restarts (#2332). A
  message sent while a group change was pending waits in the queue, and it
  was prepared and sent a second time, as a new message, when its first send
  reached no relay and a retry later did, or when the app restarted before
  its send resolved. Its stored send now names the queued message, which
  retires when the send resolves, so a retry or a restart no longer prepares
  it again; relays can still receive the same event more than once while the
  send resolves. A message whose send was stored by an earlier release can
  still be prepared once more after a restart.

## 0.17.0 - 2026-11-15

### Security

- Bump `quinn-proto` to 0.11.19 and `quinn-udp` to 0.5.16, past
  RUSTSEC-2026-0523, RUSTSEC-2026-0524 and RUSTSEC-2026-0538 (#3394). Every
  shipped artifact links them through the QUIC preview transport.
- Stop fresh undecryptable envelopes from forcing repeated history
  reconstruction (#2492, #3406). Live ingest re-derived the retained exporter
  contexts for every envelope that missed the live key, so anyone able to post
  correctly signed envelopes to a group's route could make the receiver
  rebuild past group state once per envelope. Live ingest now reuses the
  contexts that deferred sweeps and publish replay already cache, on storage
  that reports a past-peel-context generation (SQLite does; a custom provider
  keeping the default `None` still rebuilds per envelope), and each envelope
  is decoded once per ingest.

### Breaking changes

- Remove the legacy v4 whole-file audit upload. Its only receiver, the
  retired Goggles service, no longer exists; v5 OTLP delivery is now the only
  remote audit path. The manual file upload, the v4 tracker pass, the default
  tracker endpoint (`MARMOT_AUDIT_LOG_TRACKER_ENDPOINT`) and the upload
  checkpoint are gone, and startup cleanup deletes the orphaned
  `audit-upload-checkpoint.json`. The tracker config setter is replaced by a
  source-only `set_audit_log_source` across Rust, UniFFI and C, and the v5
  tracker result drops its v4 fields. Local v4 files stay listable and
  deletable until retention expires them (#3390).
- Return optional create/invite operation results with ordered per-account
  resolution outcomes across Rust, C, UniFFI, and CLI (#1813, #3375).
  Available accounts proceed in one MLS operation; unavailable accounts are
  reported individually. A nonempty roster with no available account creates
  no group or commit. Prepared-image retries retain the original report across
  restart. Stable agent-control v2 creation and invitation remain atomic:
  WN Agent still fails the request when any requested member is unavailable.
- The app performance snapshot drops `account_group_read_snapshot` (UniFFI
  `accountGroupReadSnapshot`) (#3421). Group reads answer from the published
  read state, so the startup group-read snapshot it timed no longer exists. The
  C struct's layout changed.
- A download the worker cannot start for lack of free disk now parks as
  `StorageBlocked` instead of retrying every 15 seconds as `RetryScheduled`,
  and is readmitted only while free space funds it (#3414, #3419).
- Account databases migrate from schema 201 to 207 (migrations 0202 to 0207:
  sticker-pack relay hints, prepared-image member reports, deleted failed
  sends, storage-readmitted downloads, committed rosters and commit
  refusals). Older binaries
  refuse the upgraded database; downgrade is unsupported.
- Rust hosts: a custom `TransportPeeler` takes a `PreparedGroupMessage` in
  `peel_group_message` (#3406); `GroupStorage::put_group` is replaced by
  `put_group_with_roster` and `put_group_keeping_roster`, and
  `StorageProvider` requires `CommittedRosterStorage` (#3420). See the crate
  changelogs.

### Added

- Discard a failed own send locally with `discard_failed_send` (Rust, UniFFI,
  C) instead of publishing a group delete for a message nobody received. A
  failed send the user deletes now leaves the timeline instead of staying as a
  "deleted" row that still reports failure (#3392).
- Add tagged poll and sticker sends in the runtime, UniFFI, and C bindings.
  Reply, thread, and effect context reaches peers; polls project reply links
  and previews. Existing send signatures and C ABI remain unchanged (#3408,
  #3427).
- Build a canonical Sonar sticker-pack share link offline with
  `sticker_pack_share_link` (Rust, UniFFI, C), carrying up to eight retained
  relay hints (#3283, #3373).
- Message Markdown recognizes a bare `note1`, `nevent1` or `naddr1`
  reference with a valid bech32 checksum as a `NostrUri` token, so a copied
  note id can render as an event card. Invalid checksums stay plain text
  (#3058, #3372).
- The v5 forensic audit log records what the recovery runner does for each
  group: `recovery_runner_fetched`, `recovery_runner_raced` and
  `recovery_runner_changed` (mdk#2660, #3399). The White Noise audit receiver
  accepts the new kinds.
- Record `read_state_publish` runtime telemetry: the count and duration of
  each new version of an account's published read state (mdk#3273).
- Add `durably_owned_key_packages_with_validity` to the engine, session and
  account runtime: the owned KeyPackage list with the one clock reading its
  lifetimes are judged at, the next lifetime bound ahead (a listed bundle's
  `not_after` or a not-yet-valid bundle's `not_before`), whether a stored
  bundle was skipped as undecodable, and whether a lifetime check disagreed
  with that reading. A caller may keep the list only while no write reaches
  the account database, the clock stays between that reading and the next
  bound, and the read skipped no undecodable bundle and saw no disagreement
  (mdk#3273).
- The engine keeps each group's committed roster, written in the same
  transaction as every membership change (mdk#3273, #3420).
- Add a deterministic native-host MarmotKit test recipe and Swift XCTest
  smoke against a local MockRelay (mdk#2947, #3376).

### Changed

- A group relay that refuses a confirmed own change for good (too large, or
  any other final answer) now warns until the user acknowledges it, across
  restarts (mdk#2333, #3426). Group commit delivery lists `refused_relays`
  with a cause, a refusal makes group changes fail with
  `GroupCommitUndelivered` at once, and acknowledging dismisses the group's
  refusals for good. A relay's size answer after an attempt that may have
  reached it now ends its retries once the change is confirmed.
- Account and group reads answer from the read state the account worker
  publishes at each quiescent point, on the caller's task, instead of waiting
  in the worker's queue behind a send, catch-up or convergence pass (mdk#3273,
  #3315, #3415, #3421). This covers quarantined groups, KeyPackage status and
  the owned list, maintenance policy and status, commit delivery, backup
  restore status and watch, group members and member-id pages, group MLS
  state, roster and conversation snapshots, and group app components.
- No more "history may be incomplete" notices from the coverage ledger
  (mdk#3308, #3379). Users see a notice only when MDK has evidence that
  messages are missing or after a rejoin. A broken recovery unit instead
  probes quietly an hour after it breaks, then on an interval that doubles to
  a day. Units broken before the upgrade probe right after it. If that probe
  fails, a unit that broke for lack of progress usually waits a day, because
  it keeps its earlier retry step, and one that broke on a relay refusal or in
  the coverage-ledger conversion waits an hour, then doubles up to a day.
  `UnprovenHistory` stays in the enums but is no longer emitted.
- Attachment downloads run four at a time across a runtime's accounts instead
  of one, and a host's request for an on-screen attachment moves it ahead of
  background backlog (#3417).
- The White Noise deployment drops `https://cdn.hzrd149.com` from new groups'
  media endpoints: it now refuses uploads from unlisted pubkeys. Existing
  groups keep their signed endpoint list until an admin replaces it (#3417).

### Fixed

- Stop a large group change from staying pending for good at a relay whose
  event limit is unknown (#2332, #3396). A commit over 64 KiB is no longer sent
  to such a relay, whose socket would close on the oversized frame and leave
  the commit possibly seen: it is refused before sending, and a commit every
  relay refuses rolls back as too large. A relay the device cannot connect to
  holds the commit for a retry instead of refusing it. A pending commit now
  counts as possibly seen at a relay that received it and answered
  `rate-limited:` or `auth-required:`, so a later refusal there no longer
  rolls back a commit members may have.
- The same rule covers every send, not only commits (#2332, #3396). A message
  a relay answered `rate-limited:` or `auth-required:` and then refused
  (`invalid:`, `blocked:`) no longer fails: it stays pending and keeps
  retrying, and while no relay has accepted it, later sends in its group wait
  behind it, as they already do behind a send that timed out. Such an answer
  still retries after 5 seconds, as before.
- Archive, forget and delete an external-signer account's chat through its
  running account worker, as for a local-signing account (#3318, #3393). These
  wrote storage directly while the worker kept its own copy of the account:
  its next save of the chat's record, for example after another member renamed
  the chat, unarchived it again, and after a forget or delete it kept
  answering for the removed group. An account that runs no worker still writes
  storage directly, now with worker starts held off until the write is done.
- A foreground send no longer waits behind a scheduled retry to an optional
  relay that withholds its acknowledgement (#3234, #3368). Secondary retries
  already yielded to durable admissions; they now yield to queued direct
  sends too.
- `NotificationUpdate.is_dm` follows the chat-list conversation kind for
  messages, group-state notices and invitations, including pending DM
  Welcomes (mdk#2773, #3357).
- Outgoing attachment promotion resumes when a running batch finishes after
  an attachment pass skipped it, without waiting for the maintenance tick
  (mdk#3366, mdk#3378, #3374, #3380).
- Create and invite abort on directory fetch-resource failures instead of
  reporting recipients as `Incomplete` in a successful result (#1813).
- An inbox relay that refuses NIP-77 comparison no longer brings back a
  "history may be incomplete" notice about a second after every dismissal
  (mdk#3308), and history the 30-day retention window passed before the
  runner proved it no longer raises a notice that busy groups flashed about
  once a second.
- Fail `durably_owned_key_packages` with the storage error when proving a
  stored bundle fails to read (I/O, busy, closed), instead of returning a
  partial list that reports this device's own KeyPackages as not owned.
  Bundles whose stored value does not decode are still skipped. Storage
  backends classify OpenMLS storage errors through the new
  `StorageProvider::mls_storage_failure` (mdk#3273).
- A contained rewind window on a storage provider without atomic group
  savepoints writes one snapshot, not two, so a crash no longer quarantines
  the group on the next open (mdk#3278, #3412). SQLite is unchanged.
- Every engine OpenMLS load goes through one gate that refuses a group whose
  rewind restore failed (#3280, #3395). No current entry path reached that
  state; the gate stops the next one that would.
- Timeline withdrawals report the trigger of the event that changed each row:
  a withdrawn delete of an edit reports an edit and reply-preview change, not
  a reaction, and batch withdrawals no longer attribute every row to the
  batch's first event (mdk#2843, mdk#3377, #3401, #3407).
- One-shot `wn` commands shut their runtime down before exiting, so a
  co-hosted account's recovery sweep cut by the exit no longer delays that
  account's next messages by 30 seconds (#3381).

## 0.16.0 - 2026-11-12

### Security

- Keep Hermes inbound attachment staging private from creation: use a `0700`
  directory and exclusively created `0600` files instead of copying source
  permissions and tightening them afterward. Tighten existing staging
  directories before copying new attachments (#2477).
- Move OpenMLS from the `erskingardner/openmls` fork to upstream `main`, which
  carries the fixes released in OpenMLS 0.9.1 and 0.9.2. A Welcome, GroupInfo,
  Proposal or Commit with deeply nested extensions could abort the process
  (GHSA-gc79-23g3-8g52), and a rejected private message could advance its
  sender's ratchet and block that sender's later messages (GHSA-p276-g3f3-wwgh).
  Stored groups load unchanged, and members on either build interoperate.

### Fixed

- Keep a chat receiving new messages after its account's live subscriptions
  are rebuilt (#3333). A relay's end-of-stored-events reply that arrived after
  the account had accepted the new subscriptions held the group's live
  messages until the recovery runner answered it, but only a new subscription
  generation woke the runner. The chat stopped receiving messages until
  unrelated activity woke recovery, and on an idle account nothing did.
- Joining a group while stored history is still replaying no longer records
  account-wide history loss and a needless re-sync (#3342). History that the
  new subscription asks for again is now owed to it, and loss is recorded only
  if that history does not arrive.
- Re-drive a pending leave that a rival branch blocked (#3345). When a
  convergence pass applied a branch that undid a leaving admin's step-down, or
  left the account the chat's last admin, the leave was neither staged again
  nor reported blocked until unrelated traffic arrived, so sign-out could wait
  out its full 30 s leave deadline.
- Stop waking the account worker every 10 ms for a chat the account was
  removed from (#3330). When two members committed the same removal from one
  epoch, the leftover rival kept the removed chat scheduled for convergence for
  the life of the process, wasting CPU and battery.
- A delayed generated-account setup handoff at startup or in the foreground no
  longer creates a replacement account after the original is wiped or removed
  (#3290). The handoff is bound to the original account and stops if it is
  gone; sign-out and wipe wait for foreground setup before withdrawing its
  KeyPackage, and a new create leaves signed-out and unlinked accounts alone.
- Forward Swift task cancellation to MDK's cancellable subscription receives
  (#2760). MarmotKit's Swift asset now ships `nextCancellable()` for presented
  chat lists, chat-list windows, account attention, conversation windows and
  block lists; UniFFI's generated `next()` keeps waiting after its Swift task
  is cancelled. Remove a host-owned copy of these adapters when taking the new
  asset, or Swift rejects the duplicate methods.
- Write Hermes `config.yaml`, its backup, and temporary files with mode `0600`
  during gateway configuration, regardless of the process umask. Existing
  group and other access is removed (#2481).
- Preserve explicit reply targets on standalone app and Hermes media sends,
  including durable uploads and ordered batches with or without captions.
  Validate and normalize reply ids before upload or admission, keep composer
  drafts unchanged, and reject idempotency keys reused for different reply
  targets (#859).
- Update the pinned Nostr SDK fork so a manual relay reconnect dials at once
  (#3269). A connect issued right after a disconnect could find the relay
  marked disconnected by the old connection's teardown and wait out the 5 s
  retry interval, so a reconnect could miss its 5 s bound and fail with a
  reconnect observation timeout.
- Resume v5 audit delivery of a file a receiver's `409` blocked under 0.15.0
  (#3300). 0.15.0 blocked such a file for good as partial acceptance; loading
  the cursor now clears that block as it does a 0.15.0 rejection, including a
  cursor already rewritten as version 2, resends the file's pending range, and
  retries a later `409`. Before, the file stayed blocked until age expiry
  deleted it.
- Report each relay's answer to a publish under the spelling the group or
  inbox list gave it (#3305). A relay spelled with an upper-case host or an
  explicit default port read as possibly exposed whatever it answered, so a
  group whose only relay was spelled that way never confirmed or rolled back a
  commit.
- Fetch independent directory queries up to four at a time, so KeyPackage and
  deletion reads overlap their relay waits while retaining separate event limits
  (#1813).
- Reuse notification settings, chat mutes, group records, and directory users
  across live subscription events (#1800). Track settings, mute, and group
  changes at the shared storage boundary, including engine-side forgets across
  connections. Honor timed mute expiry and skip non-notifying kinds before
  storage reads or blocking-task dispatch.
- Keep a group commit pending when a crash interrupted its send and the relay
  then refuses the retry (#2332). The interrupted send may have reached the
  relay, so a later refusal no longer rolls back a commit that members may
  have applied.
- An account that is offline or has no relays no longer repeats the full replay
  synchronization on every 15 s maintenance tick (#3238). The pass ran five
  writer transactions and woke the recovery runner each time with nothing new to
  record. It now runs once per inactive transport generation and again on
  activation.
- Quarantine a group whose read of past group state could not restore its live
  state, instead of leaving it live on that past state for the session and
  validating it as live at the next open (#3272). The group reports the new
  hydration-quarantine reason `RewindRestoreFailed`; a retry or re-join does not
  clear it, and its input is retained. The next account open tries to restore
  the live state and replays the input only if that succeeds; otherwise the
  group is quarantined again for the same reason. Opening an account now
  handles every group's interrupted rewind before ingest or a Welcome join can
  read it.
- Report each relay the host-safety rule refuses (a private or loopback
  address, a plaintext `ws://` URL, or a URL that does not parse) as never
  contacted (#3276). A commit that every other group relay refused was retried
  against it with backoff and never rolled back; it now rolls back. A Welcome
  whose recipient's inbox list includes such a relay goes to the list's other
  relays instead of failing whole. Audit records the refusal as
  `publish_attempt_failed_before_exposure`.
- Unstick a group whose deferred-peel backlog is full (#3297). Catch-up held
  the whole group behind a history event the engine could neither open nor
  store, which also held the group's live messages and the account's sync
  cursor; that event is now let go of and the rest of the group admitted. A
  quarantined group stays held. The per-group deferred-peel caps rise from
  2,048 rows and 16 MiB to 8,192 rows and 64 MiB, the account cap from 64 MiB
  to 256 MiB, and the recovery runner's account breaker from 720 to 7,200
  quanta an hour, so a first catch-up of many groups no longer pauses it.
- Keep delivering v5 audit records however many segments a device retains
  (#3300). The delivery cursor kept about 320 bytes per retained file under a 1
  MiB cap and discovery held every segment open, so at about 3,250 segments
  every pass failed before any request. Idle sealed segments are now compact
  cursor rows matched from metadata; an over-limit cursor sheds the oldest with
  a `CursorOverflow` gap. Version 1 cursors upgrade on load.
- Stop retrying v5 audit delivery silently forever (#3300). A `400`, `413` or
  `422` now halves the batch and retries the halves, and only a record the
  receiver still rejects alone is skipped, with a `ReceiverRejected` gap; `409`
  is retried instead of blocking the file for good; `401`, `403`, `404` or
  another unexpected response pauses automatic delivery until the configuration
  changes or the host runs a manual tracker update. Each attempt's outcome is
  persisted and readable.
- Record only the outcome row for a relay replay that ingest ignores as a
  duplicate or own echo (#3300). Each such message wrote about 6 KB of audit
  rows; one replay storm filled 2.4 GB of v5 segments in a week.
- Record an `ExpiredUndelivered` gap when retention deletes an audit file that
  still held undelivered data (#3300). The loss surfaced only later, as a
  generic `MissingSource` gap.
- Record a relay's size refusal in audit v5 as `relay_rejected_invalid` again
  (mdk#2334). Since 0.15.0 it was written as `unclassified`. A relay MDK did not
  send to because the event is over its known limit is recorded as
  `publish_attempt_failed_before_exposure`.
- Retire a queued group change whose commit every group relay refuses for size
  (mdk#2334). The drain rolled it back and staged it again on every pass; it is
  now dropped once and announced as `QueuedIntentRefused` with reason
  `event_too_large`.
- Stop resending an account event that is over a relay's advertised message
  limit (mdk#2334). Such a relay closed the socket, which read as a possible
  exposure, and the event was resent three times; it is no longer sent there.

### Added

- Share NIP-46 remote signer sessions across Rust, UniFFI, and C, with
  account-secret-store persistence, startup restoration, versioned permission
  approval, relay-ready pairing offers, and request-scoped cancellation (#828).
  Sign-out and wipe erase communication keys; host NIP-55 callbacks and local
  signing accounts keep their existing APIs.
  Freeing a C handle preserves the runtime-owned signer. Logout detaches the
  revoked signer after credential erasure; storage failures retain stopped,
  retryable cleanup ownership. Setup rollback restores prior callbacks and
  grant records while initial-provisioning retries retain their paired credentials.
  Native login/register adoption is runtime-owned across all bindings: caller drop
  stops waiting without cancelling admitted work. Pairing is a separate bounded,
  caller-cancellable connect call; login requires an already-verified Ready session
  and rejects other states without connecting or creating an account. Unbound pairing
  never mutates an account. Explicit session cancel/disconnect/logout interrupts
  adoption, and shutdown interrupts and settles owned work before returning.
  Adoption keeps its admission generation through binding, network waits, and
  rollback. Reconnect cannot revive retired work; rollback cannot cancel a newer generation.
  Completed accounts rebind without reopening setup; failed Native adoption restores
  prior local callbacks, records, and activation without retracting published
  KeyPackages. Legacy host login behavior and explicit sign-out cleanup are unchanged.
  Post-commit journal cleanup failures do not revoke a ready account.
  Explicit pairing can repair metadata-only interrupted credential writes.
  Local removal reports account disappearance after cancellation instead of a vault failure.
  Account deletion serializes session resume through credential erasure and removal.
  Sign-out and wipe wait for foreground setup and keep signer resume behind
  their existing account fence through credential removal.
  Unsupported relay negotiation accepts `method not found` without hiding other errors.

## 0.15.0 - 2026-11-09

### Added

- Add host-driven automatic rejoin for eligible Unrecoverable group copies,
  with bounded retries and Rust status and explicit-retry APIs. Accepted
  recovery controls are durably retained before their inbox source is
  acknowledged. Live retries preserve the handshake; quarantined coordinators
  retain publication debt without scheduling more work.

### Security

- Verify live directory events independently at MDK's relay forwarding and
  directory ingestion boundaries before forwarding or persisting profiles,
  follow edges, relay lists, or KeyPackages (mdk#2521). Reject unsigned,
  tampered, and invalidly signed records even when a producer claims prior
  verification.
- Update the pinned Nostr SDK fork to reject tampered event content and invalid
  signatures even when the event ID is in its verification cache. This ports
  upstream nostrdevkit/nostr commits `0e08c3062186fbc6665161769037873e0a981cd5`
  and `a991ff004975deaf1ef5279969ba1c6a85f79203` (#1508).
