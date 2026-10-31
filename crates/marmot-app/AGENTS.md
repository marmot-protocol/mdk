# AGENTS.md - crates/marmot-app

Multi-account app runtime bridge (`MarmotApp`, `MarmotAppRuntime`) beneath `wn`, `marmot-uniffi`, and `marmot-c`. For
the human overview and host-facing API contracts (storage tiers, KeyPackage inventory, directory search, app-owned
components, full-history repair, notices, blocking, moderation) see [`README.md`](README.md); do not restate them here.

Implement shared behavior here, following [MDK's host boundary](../../docs/marmot-architecture/overview/app-core-boundary.md#host-app-boundary).

## Scope and module rules

- Own the app-facing runtime that ties `AccountHome`, SQLCipher session storage, Nostr peeling, and Nostr transport
  adapter support together.
- Keep runtime orchestration, managed account workers, subscriptions, and live agent stream watches in the `src/runtime/`
  module instead of regrowing `src/lib.rs`. The module splits along these seams: `mod.rs` (the `MarmotAppRuntime`
  orchestration core — construction/start/shutdown, shared services, lifecycle, module wiring and re-exports),
  `account_worker.rs` (the per-account worker: command enum, worker loop, reconnect backoff, runtime-event publishers),
  `subscriptions.rs` (the `Runtime*Subscription` handles and the materialized-timeline window), `commands.rs` (the
  `AccountManager` command-RPC wrappers that send a worker command and await its oneshot reply), `agent_stream_watch.rs`
  (agent-text-stream discovery and the brokered-QUIC watch machinery), `onboarding.rs` and `onboarding/` (durable
  preflight, cancellation, and advisory installation detection), `audit_tracker.rs` (the forensic audit-log tracker
  upload worker), `audit_otlp_delivery.rs` (the explicit one-account v5 OTLP attempt), `event_routing.rs` (pure
  `MarmotAppEvent` classification/routing helpers), `avatar.rs` (local identity-avatar demand and bounded maintenance),
  `avatar_access.rs` (bounded local native batches), `attachment_history.rs` (bounded local attachment discovery and
  shared-parser presentation), `attachment_access.rs` (read-only source-slot availability and verified local byte
  ranges), and `account_worker/attachments.rs` (durable attachment demand admission, fair background transfer capacity
  and publication into the account's media store). Other runtime modules are listed in the Code map below. Keep `mod.rs` re-exporting the
  moved public types so `crate::runtime::Item` and the `marmot_app::...` paths stay stable.
- Keep app-client commands and query methods in the `src/client/` module; the crate root should construct clients but
  not absorb their behavior again. The `AppClient` inherent impl is split across the module along these seams: `mod.rs`
  (the `AppClient` struct plus the broadly-shared command/query API — key-package, group lifecycle, message/media/agent
  send commands, and the lifecycle helpers and encrypted-media helpers they share), `sync.rs` (transport sync: `sync`,
  `next_event`, `sync_sdk_relay`, `ingest_delivery`, `sync_runtime_groups`, the relay-echo/transport-cursor helpers, and
  the cursor unit tests; `sync/full_history_tests.rs` covers explicit repair), `projection.rs`
  (timeline/group projection accessors, the `*_for_group` component reads, the
  kind-1210 group-system row synthesis, and the local-send projection helpers), `receipts.rs` (the synchronized
  transport receipt view, release-journal consumption, and seen-index maintenance), `push.rs` (push-token registration
  and gossip, with announces and join windows in `push/announce.rs`, repair replies in `push/repair.rs`, and
  notification-trigger publishing),
  `retention.rs` (the engine-owned retention sweep policy, the
  storage-answered expiry/unread scan, per-group outcome orchestration, and decision tests), `chat_history.rs` (a
  chat's history exported as sealed bundles and a sibling's bundle imported, never for a device group), `history_notices.rs` ("history may be incomplete"
  notices, their worker-owned dismissal and the notice-change baseline; the public DTOs and opaque id codec live
  in the crate-root `src/history_notices.rs`), and `audit.rs` (audit-context construction, the local/observed
  `human_action` recorders, and the `ObservedHumanActionAudit` descriptor). Private items referenced across these files
  are widened to `pub(crate)`; `pub` items keep stable `marmot_app::...` paths via the crate-root re-export.
  Steady-state sync passes must not rescan full retained state (no full `MlsGroup::load` sweeps, no full
  account-projection loads; cheap per-group probes are acceptable): the encrypted-media epoch-secret warm pass
  skips authoritative (`MlsGroup::load`) component re-checks at an unchanged group epoch
  (`encrypted_media_not_required_epochs`, mdk#1380), and the sync checkpoint skips its second
  `refresh_group_routes` when the drained prefix carried zero deliveries and clean routes.
- Keep app-defined custom events on the `AppMessageIntent::Custom` path in `src/messages/intents.rs`: kind, tags, and
  content pass through verbatim, and kinds MDK owns (`is_reserved_app_event_kind`: chat, reaction, edit, delete,
  agent, group system, push token, and the device-group kinds `is_device_group_kind` lists) are rejected with `AppError::InvalidAppMessagePayload` so apps cannot forge
  protocol-owned events. Custom kinds project as standalone timeline rows under
  `TimelineUpdateTrigger::CustomEvent` (never folding onto a target message like reactions/deletes) and are queryable
  by kind through `AppMessageQuery::kinds`.
- Never project the account's device group (mdk#2628 item 3.1, `src/client/device_group.rs`). A group is one when
  `device_groups` records it or the engine says it requires the device roster (`is_device_group`). Every seam that
  could re-project a group absent from the projection checks that first and keeps only its route:
  `suppress_local_deleted_group_event` (both event loops), `refresh_group`, `reconcile_live_engine_groups` and
  `refresh_routing`. Every host surface built from engine or recovery state rather than the projection filters with
  `host_may_see_group`, which fails closed: quarantine, history notices and their changes, epoch-stall escalations,
  deferred events, recovery-status and superseded-change updates, convergence park notices, and Welcome redelivery. A
  new such surface filters too. Trust is separate from hiding. Act on a device group's roster only once `device_groups`
  says `created` or `linked`. Never judge a joined Welcome: the engine decides which Welcome joins, before the join
  (mdk#2628 D28, D30). `record_confirmed_device_link` refuses a group this device already holds, writes the
  `awaiting_welcome` row, then records the engine's `DeviceGroupWelcomeExpectation` (group, the existing device's leaf
  signature key, the confirmed `KeyPackageRef`, `WELCOME_WAIT_SECS`), deleting the row if that fails. Withdrawing a
  link and ending a wait (`withdraw_confirmed_device_link`, `end_welcome_waits` on every record and reconcile) delete
  the expectation before the row, so once either returns no Welcome under the link joins. A row a crash or failure
  leaves without its expectation admits nothing, and `end_welcome_waits` drops it at once rather than at the wait's
  end. Decide from the engine's durable group record (`stored_group`), never the live group a deferred open has not
  hydrated, and settle trust in one place (`settle_held_device_group`: the live join and the restart reconcile). A held
  device group with an `awaiting_welcome` row joined in time, whatever the row's age. A held device group with no row
  stays `untrusted`, and a group under a row that does not require the roster drops the row; neither arises through the
  engine. A routing rebuild skips a device group a deferred open has not hydrated; the post-hydration reconcile installs
  its route. The founding roster lists only this device and its sign-in rejections, never the linked slot's; the
  founding Add takes the account's own device only through the confirmed `KeyPackageRef` and sets its entry, as a later
  link does (D41). Confirmed links come from device pairing; the `test-policy-overrides` hooks
  (`dev_create_device_group`, `dev_record_confirmed_device_link`, `dev_withdraw_confirmed_device_link`) stay for tests.
- Read the device roster only through `trusted_device_roster` (the trusted group's decoded roster, or none). Hosts see
  it only as `linked_devices`, this account's own devices; its errors never name the group. The device group's events
  stay hidden, so every hidden device-group event and every change of trust sets `linked_devices_changed`, which the
  worker's account-level and applied-summary seams drain into one payload-free `LinkedDevicesChanged`. Every client
  opens with it set: a client dropped before a drain (a reconnect attempt whose transport fails) takes its change with
  it, and its replacement cannot see that change. Startup and reconnect settle trust with no command after them, so a
  new seam that settles trust must reach one of those two.
- Name the device group to tag from (mdk#2628 3.1d) with `sync_device_tag_group`, which picks the same group the
  announcement does. Naming hydrates it, so never name it at a deferred open's end: the post-hydration reconcile
  does, as do settling a join, creating a group, maintenance and every KeyPackage publication. Name it before reading
  whether the current KeyPackage still serves (`key_package_republish_falls_back`), since an untagged one is stale once
  this device tags. The founder's founding entry carries its own tag signature key; every other device sets its own
  in maintenance or, before a host KeyPackage publication, through `set_device_tag_key`, once per call, since the
  runtime stages no KeyPackage while the key is due.
- The overdue-refresh warning (`key_package_refresh_overdue`) asks the runtime's announcement gate, never a copy of
  the roster. The client recomputes it after each maintenance pass; a change sets
  `key_package_refresh_overdue_changed`, which the same two seams drain into one payload-free
  `KeyPackageRefreshOverdueChanged`. It opens set, for the same reason as `linked_devices_changed`.
- Write a device entry of the roster only through the runtime's `edit_device_roster_entry` (renaming, announcements).
  It refuses while the device group has anything of this device's in flight; surface that as `device_group_busy`.
  The engine stages a `ReplaceDeviceEntry` only while the entry is still the one the edit read, so a whole-entry
  replacement never undoes a change that lands in between. A rename (`client/device_renames.rs`) writes a fresh rename
  id next to the label and is kept on disk before its commit is sent. Maintenance reads only the rename id the winning
  roster holds (D37): one the rename wrote means applied, one its renames replaced means lost with nothing renamed
  since (made again with a fresh id), any other means another rename stands. Never infer a rename's fate from labels
  or commit ids. Every entry is created with a fresh rename id (`fresh_rename_id`: the creator's founding entry, the
  founding Add's and every later link's), so a kept id shows up again only when a fork brings back an earlier state.
  Rejected slots (3.2's sign-in rejections, below) are written by the runtime's `reject_device_slots` instead, never as
  device entries.
- New sign-ins (`src/client/sign_ins.rs`, mdk#2628 3.2) count only what `read_account_key_package_slots` keeps under the
  inviter's rules; a live KeyPackage from the directory subscription, or a Welcome delivery the engine finds
  `NotAddressedToThisDevice` (`ingest_delivery` in `src/client/sync.rs`; also a sibling's delivery of a Welcome this
  device already joined), only brings a check forward (`SignInNudges`):
  a KeyPackage is addressable, so the one a Welcome names is served only as its slot's newest publication. The
  first check's baseline, every slot id its read returned whether or not it counted, never a publication time, separates
  devices that were here first from new sign-ins. Only a complete read changes whether a listed sign-in is still signed
  in, and a slot holding a valid publication that is merely stale (`current_slots`) stays signed in. A read of the
  configured directory relays, when the account lists none, is never complete. Rejections are recorded locally first,
  then committed to the trusted roster through the runtime's rejected-slot write (`reject_device_slots`), behind the
  gate the runtime's own roster updates wait behind; a device with no device group keeps them until
  `create_device_group` founds the roster with them or it trusts a group it joined. A rejection is committed only while
  the roster has no entry for the slot, and never replaces one; a slot the roster holds as a device ends it, since the
  user confirmed that link. A rejection stays pending until the roster shows it. A sign-in this device dismissed is
  listed again once the roster has no entry for its slot. Every device-group event and every superseded roster update
  rechecks every rejection (`recheck_sign_in_rejections`): it ends at once a rejection of a slot the roster now holds as
  a device, so a link that branch selection drops before the next pass asks again rather than restoring `not_me`, and
  re-arms the rest. A rejection settled from another device's commit is lost when that commit loses convergence, and
  only a device that made the rejection restores it. A slot is its `d` as published, compared as bytes; one the roster
  cannot name is rejected on this device only. A rejection names the slot alone (`rejected_slot`), and a rejected
  KeyPackage never makes another slot rejected: the account key can copy any KeyPackage, a real device's included, into
  a slot the user rejects. Rejected KeyPackages are Scene 8's (3.7). A roster device's KeyPackage matches its slot when
  the trusted roster announces it now or the engine recorded it from a roster state applied in the last 30 days
  (`announced_key_packages`, D31 item 7); only this classification reads that record. Hosts read the list as
  `unrecognized_sign_ins`. A check or answer that changes it, and every roster change (`note_device_roster_changed`),
  sets `unrecognized_sign_ins_changed`, drained at the device-group seams into one payload-free
  `UnrecognizedSignInsChanged`; every client opens with it set.
  Start fresh (D54, `start_fresh`) answers every before-this-device sign-in Not now, including baseline slots listed
  later (storage writes them as `not_now` while `started_fresh_at` is set); it never rejects and never warns.
- The own-slot check (mdk#2628 3.4, `src/client/sign_ins.rs`) rides 3.2's read: `read_account_key_package_slots` also
  reads this device's slot by `d` from every relay (`OwnSlotRead`), keeping each relay's current publication there by
  NIP-01's rule, valid or not. One whose event id is none of this device's current, pending or retained events is
  foreign (`OwnSlotForeign`); an older event of its own is a lagging relay, which fanout retry owns. `check_sign_ins`
  hands foreign ones to `replace_foreign_slot_publications`, which publishes a newer KeyPackage or, for one dated past
  the skew window, asks the relays to delete it by id (D63). It also hands over each relay whose own read finished and
  returned nothing in the slot (`OwnSlotRead::empty`), named as the lifecycle's publication targets name it, to
  `refill_emptied_slot`, which publishes a new KeyPackage when one accepted the current publication, while this
  device's trusted roster, if it has one, lists it as a device (`listed_as_device`). A failed or unfinished read never
  shows a relay empty. An incomplete own-slot read is retried within the hour.
- The compromise warning (`src/client/compromise_warning.rs`, mdk#2628 3.7a, D53) is storage's
  (`account_compromise_warning_items`): every `not_me` slot and rejected KeyPackage in the trusted roster, plus this
  device's own rejected sign-ins, gathered with insert-or-ignore so a seen mark survives branch selection dropping and
  restoring an item. Never gather `removed` slots. Gathering is lazy: a roster change (`note_device_roster_changed`)
  or a Reject answer sets `compromise_warning_gather_due`, and the next host read or publication seam gathers once.
  The first roster this device trusts from a device group goes in seen (D68: the user saw those on the devices that
  were there); its own rejections still warn. Storage takes that roster in the same transaction that makes the group
  trusted, so every trust site goes through `AppClient::trust_device_group` (storage refuses any other move into a
  trusted state): Creating to Created passes no roster rejections (a founding roster holds only the founder's), and
  AwaitingWelcome to Linked passes the roster the engine holds. Only a group trusted before migration 0148 takes its
  first gather instead. Dismiss is per
  device. An unseen rejected sign-in that neither this device nor the roster holds leaves the warning (a link ended
  it, or a branch dropped it); a seen one stays seen. Keep `CompromiseWarningReason` exhaustive so each binding maps a new reason
  explicitly; the stored reason is text with no CHECK, and an unknown one is skipped on read.
- Send and read messages between this account's devices through `src/client/device_group/messages.rs`: one
  `send_device_group_message` (`false` means it reached no relay), one dispatch by kind in `observe_device_group_event`
  (add a feature's kinds there), and one sender read, `ensure_sent_by`, from the sending leaf's device tag (mdk#2628
  D33). A message from an earlier epoch is read from that epoch's retained anchor, so one older than the retained
  anchors has no readable sender. List every kind sent only in a device group in `is_device_group_kind` (457, 459, 460,
  461, 462, 475, 476), the one list: `observe_event` drops one received in any other group before the host summary and
  the stored projection, the notification preview refuses it, and the custom path rejects it as reserved. The engine
  withdraws a message by message id alone (an own send's transport id, a received message's content id), so a kind
  whose withdrawal a feature acts on is listed in `withdrawal_handled` and dispatched in
  `device_group_message_withdrawn`. Each such message is recorded with its kind in `device_group_messages` when sent
  (before the send; its message id is filled in from whichever drain's effects publish it, in
  `retain_effect_projection`) and when read. Records go after a week or past 4,096, so a feature also acts on a
  withdrawn message with no record, which may be of any kind.
- Hand private KeyPackages only inside the trusted device group (mdk#2628 item 3.4b, `src/client/private_key_packages.rs`).
  Read a request (459) or hand-off (460) only from that group, addressed to this device's slot, from another slot its
  roster lists, sent by a leaf whose device tag reads as that slot's, and keep a hand-off only if every KeyPackage is
  this account's, single-use, unexpired and tagged as that slot's (mdk#2628 D33, through 3.1d's tag reader; never a
  second one). Never publish one, and never fall back to a public KeyPackage when none is held. A KeyPackage this
  device has used is never kept again if a sibling hands it over again (mdk#2628 D42).
  Stash a sibling Welcome (461, mdk#2628 3.5b) only after a hand-off's checks, a relay list of one to 16 relay URLs
  distinct once parsed, and a KeyPackage this device issued to its sender; join from the stash (migration 0160) in
  the maintenance pass, never in the synchronous dispatch, only while its carrier is still `Processed`, and drain the
  joins' events as a confirmed rejoin does. A refused or withdrawn 461 is dropped; one whose checks could not be read,
  or admitted but not stashed, fails the event's projection, which is retried. One into a chat still held active is
  held, never a rejoin offer (D72): its row keeps the chat's id, and a pass joins it, with no consent asked, only once
  that copy reads removed or unrecoverable. A held row goes only when its carrier is withdrawn, its KeyPackage is used
  or expired, the chat is forgotten or disbanded, or a full stash makes room for a new Welcome. A forget refuses only
  the carriers dated before it, so the same Welcome sent again afterwards joins, whether or not a pass held it first.
  Every call that can store or retire a rejoin offer (ingest, the retry, a confirmation, a decline) tells the host
  which chats' offers changed.
  Upkeep runs in the maintenance pass and serves siblings before asking for this device's own. Issue, hand over and
  ask for nothing until this device's own leaf reads as its slot: siblings would refuse it, and what it issued would
  be untagged.
- Heartbeats (mdk#2628 item 3.6, D35) live in `src/client/device_heartbeats.rs`. Send one only from the trusted
  device group, once this device's own leaf reads as its slot, at most once an hour. Record the sent time only once the
  send returns that it went out (published, unresolved or queued), and leave the record alone when it reached no one
  or failed, so a crash mid-send costs at most one extra heartbeat, never an hour's silence. Count one only when the sending leaf's tag reads as a
  sibling in the tree this device holds when it reads it (one from an earlier epoch counts for no device), never read
  its content, and date it `min(created_at, now)`. Judge `inactive` locally for the Devices screen; never write the
  roster's `inactive` status from it.
- Keep device pairing (mdk#2628 item 3.3b) in `src/client/device_pairing.rs` (host DTOs) and
  `src/client/device_pairing/live.rs` (behind `unreleased-device-pairing`, and inert unless
  `MarmotAppConfig::dev_device_groups` is set). The Welcome peeler opens each gift wrap to the account once and hands
  pairing rumors to the `PairingInbox`; the engine still sees them refused. Pairing secrets (the code, keys and session
  ids) live only in the in-memory `marmot-pairing` sessions: never persist them, and never log them, a slot or a label.
  A device adds a sibling only after both users confirmed the code and the new device's confirmation verified, through
  exactly the confirmed `KeyPackageRef`: a first link creates the device group, a later one sends one
  `SendIntent::LinkDevice` commit, sent through `runtime.send_with_audit_context` so the runtime releases its Welcome
  only once the commit is confirmed (never split the Welcome off for app delivery). On both paths the prompt stays
  `Linking` after the commit: `decide_device_links` is the one gate for every link in `device_links`, prompt or not
  (D40). A link is `Linked` once the new device's first commit, which sets its roster entry's `tag_signature_key` to
  the leaf key the link added (`leaf_signature_key_hex`), is on the selected branch: the device group is `Stable` with
  no pending convergence input. It fails when its group was never made, when the quiet roster has not listed it as
  this device's link for a whole settlement window (`MarmotApp::settlement_quiescence_ms`, in milliseconds, whose
  override only test-policy builds read), or when that commit is still absent `LINK_DEADLINE_SECS` after the entry's
  `linked_at`. A decided link never changes, and a link whose approval still waits to be retried is not decided. A
  failed link ends its prompt as `LinkFailed` with a `CannotLink` cancel. Its Welcome, found by the `KeyPackageRef`
  recorded before the commit (`welcomes_for_key_package`), is withdrawn before the failure is recorded. While the
  Welcome's deadline may be ahead (before `linked_at` plus `WELCOME_WAIT_SECS`), a failure is recorded only once that
  withdrawal succeeds: until then the link stays pending and the next drive decides it again. From then on the runtime
  refuses the Welcome, so the failure is recorded and the removal does not wait for the withdrawal. Never rely on a Welcome id written after the commit, which a crash can lose. Welcome publishers (startup
  recovery, a maintenance pass, a fanout retry) run before the gate and whether or not device groups are on, so the
  gate never guards delivery: both link paths pass the new device's wait end (`Approval::wait_ends`) to the engine as
  the Welcome's `deliver_until`, and the runtime's publish check refuses it from then on. While the roster
  lists the device as this device's link, it also removes its entry, and its leaf if the engine's tree still has one, in
  one `SendIntent::UnlinkDevice` commit; never decide the leaf from the stored member list, which a staged removal has
  already changed. A withdrawal that fails never holds the removal back. A link refused as
  `LinkDeviceUnsettled` made no commit, even while another commit resolves. Publish an undelivered Welcome again every
  few seconds until the new device's Welcome wait ends; neither its publication nor its delivery decides a link.
  `drive_unpublished_welcome_delivery` returns a `#[must_use]` `WelcomeDelivery`; chat creation goes on either way, as
  the Welcome stays owed. Prompt ids are random, so an id a host kept from before a reopen names no prompt. The engine
  refuses a link or an unlink with `LinkDeviceUnsettled` rather than queue it; retry a link on each drive until a
  minute before the new device's Welcome wait ends, counted from when the new device sent its confirmation, never
  attempt it after that, and cancel it as `LinkFailed`. The existing device's confirmation names `own_signature_key`,
  its leaf key in the device group, and the new device records it with the link (`record_confirmed_device_link`).
  Ending the new device's wait (cancel, a withdrawn link, timeout) withdraws the engine's expectation first and keeps
  the wait until that succeeds, retrying on each drive. Record each link in `device_links` before its commit, so a
  crash cannot lose it. The new device records a `device_group_joins` row before it trusts the group it joined, nudges
  its first commit there (`set_device_tag_key`) on each drive rather than waiting for maintenance, and drops the row
  once that commit landed. Removed from the device group, it forgets its copy (`forget_group_local`); removed before
  its first commit landed, it shows `Ended { LinkFailed }`. A later link's Welcome into that group is a first join,
  held by the engine to the link rather than to the forget's date. A new device never starts a link by a KeyPackage it
  already joined by (`last_consumed_key_package_ref`): the link binds its Welcome by KeyPackage alone, so a used one
  would also admit the Welcome that installed the forgotten copy. The start waits for the replacement's publication
  (`key_package_not_published`). Each drive ends by comparing linking as hosts read it with
  `DevicePairing::last_view` and sets `device_link_changed` when it differs; the client opens with that flag set, and
  the same two seams as `linked_devices_changed` drain it into `DeviceLinkChanged`.
- Small state (`src/small_state.rs` and `src/client/small_state.rs`, mdk#2628 4.3) keeps each chat's read position,
  pin, mute and archive the same on the account's devices, from the first maintenance pass after this device trusts a
  device group. A pass is one storage transaction (`sync_small_state`): a local state that differs from what this
  device last observed is its user's change, so no setter needs a hook and leaving a chat is never a change. Archives
  go through the worker's in-memory account state (`apply_sibling_archives`, one save, mdk#178) and, like pins and
  mutes from siblings, record no product outcome. Each chat a pass changes gets one chat-list update through `pending_projection_updates`. The merge rule's tie-break
  (`tie_break`), its placement of a new pin (`new_pin_index`) and the broadcast schedule (`broadcast_due`) are each one
  function; change them nowhere else. Recovery is a broadcast of every held item, with no stopping condition and
  nothing tracked per sibling: at start, daily, when the device-group tip passes the app-payload window since the last
  one, and an hour after the last when a sibling asked. Each maintenance pass then sends what is owed: updates split
  to fit 32,768 bytes, each page's items marked sent only after it went out (a duplicate is harmless, a loss is not),
  and a broadcast request when owed. Updates and requests are read from any member of the trusted device group, never
  through `ensure_sent_by`. A withdrawn update owes every held item again, whoever sent it, and a withdrawn broadcast
  request owes a new one; a withdrawn message with no record in the trusted device group owes both. A winning pin for
  an archived chat waits, unobserved, until the chat is unarchived.
- Keep outbound Welcomes on the engine's Welcome rows (mdk#2628 3.5a). The invite slot of
  `drive_unpublished_welcome_delivery` holds only Welcome ids, published through the runtime's
  `deliver_owed_welcomes_with_audit_context`; the founding slot keeps the create's `SessionEffects`, because a legacy
  create's `GroupCreated` work rides them. Note a Welcome a publish could not deliver in one place,
  `note_welcome_delivery_failures`, called from `remember_published_reports` (every seam that applies runtime
  effects) and from the device-link send; never write a pending Welcome row or queue `WelcomeDeliveryPending` from a
  drive. It announces each Welcome once per process (`announced_welcome_failures`) and leaves a failure without a
  group (the startup retry's) to `reconcile_pending_welcome_delivery_index`. The worker's projection drain
  (`publish_client_pending_projection_updates`) broadcasts the queued events, so every worker seam does.
  `note_welcome_delivery_failures` and that reconcile are the pending table's only writers; never write a row before a
  commit is exposed, since the engine stages an invite's Welcomes with its commit.
- Keep group DTOs, component projections, and group event projection helpers in `src/groups.rs`.
  `AppCreateGroupOptions::relays` overrides founding group routing only; validate through `RelaySafetyPolicy`
  before member resolution or group mutation, and preserve app-configured relays when omitted.
- Keep encrypted-media DTOs, exporter labels, and Blossom upload/download helpers in the `src/media/` module
  (`blossom.rs`, `crypto.rs`, `group_image.rs`, `host_safety.rs`, `avatar.rs` for downloaded avatar admission).
  `media/attachment_resume.rs` adapts attempt-fenced checkpoints (metadata rows in storage, ciphertext in the media
  store's `.wire` files) to the shared safe HTTP path, and admits disk use through `media_store::DiskPolicy` built
  from the configured reserve. Checkpoint reads, writes and clears go through the media store's checkpoint API with
  the job's `AttachmentCheckpoint` target; never open or truncate a wire file here. Every download disk check uses
  `DiskPolicy::download_need` (worker admission, readmission and the attempt's checks share `capacity`);
  keep Range validation, protected partials and complete-body authentication separate from native progress/access.
  `media/file_transfer.rs` owns the download side's `DownloadedFileBody` (ciphertext in the job's `.wire` checkpoint,
  held open by the store's `CheckpointReader`, or one `media-staging/` file without a validator; authenticated into a
  discard sink before the receipt and decrypted by `DecryptingReader` straight into the store publish; never write a
  plaintext file for a download) and the `MediaFileTransferControl` cancellation/progress handle.
- `runtime/attachment_storage.rs` is Manage storage (mdk#2314 step 5): usage and largest-first listings across both
  body layouts, and bulk removal that is exactly explicit `Remove`. Every removal path (bulk or `control_attachment`)
  unlinks the media files its transaction released through `unlink_released` before returning; never leave that to the
  sweep. The opt-in "Keep media" setting (mdk#2314 step 10) reuses that removal, recorded as cleaned by the setting:
  its setter sweeps to completion before returning, and the worker's maintenance batch sweeps at start and hourly for
  at most `KEEP_MEDIA_SWEEP_BUDGET`, before the legacy move. Automatic demand goes through
  `request_automatic_acquisition` (which skips slots past the window); explicit requests never do.
- `media/legacy_migration.rs` moves legacy database bodies into the media store (mdk#2314 step 6): one bounded batch per
  maintenance tick, started by the account worker on the blocking pool after readiness. Each body is admitted with
  `DiskPolicy::migration_need`, published, then its rows dropped; the smallest body that does not fit pauses the move
  (reported as `Paused { needed_bytes }`, never by deleting anything), and a body that fails its digest or is malformed
  as stored is dropped so its slot shows as unavailable with download-again allowed. The per-account
  `LegacyMigrationProgress` lives in `MarmotApp` and is dropped with the account's media store.
- `media/avatar_files.rs` keeps avatar and group-image bodies in the media store's cache category (mdk#2314 step 9),
  always on the blocking pool: a fetched image is admitted with `DiskPolicy::cache_need` and published with its
  attempt settled in the same commit (no room retries the fetch later); reads take file-backed images from the store
  and report a missing or corrupt file so every owner sharing it refetches; and the maintenance tick moves images
  still held in the database into files after the attachment batch, smallest first. An identical ready file is
  attached at no space cost (the move verifies it first, since its commit drops the database copy). When the next
  image needs a new file the disk cannot take, or free space cannot be measured, the batch stops and the next tick
  tries again; never delete an owner to make room.
- `media/storage_compaction.rs` returns the account database's freed pages to the filesystem (mdk#2314 step 6) on the
  blocking pool: the one-time compaction runs only through `compaction_gate` (a quarter of the file free, the reserve
  plus two live copies free on the volume, and a live database of at most 64 MiB: the `VACUUM` copy is built in
  memory, and its final write-back cannot be interrupted, so the cap bounds how long a close can wait for it; an
  account over the cap with no legacy bodies left is logged once per process, as a power-of-two MiB bucket), at most once per worker ownership (a rolled-back one is retried, at most three times), never while a
  migration batch runs. The maintenance task (never awaited) checks the gates every tick and only flags a due
  compaction; the account worker awaits it from its maintenance tick only when flagged, so a tick with nothing due
  costs the worker nothing and none of its synchronous storage calls park an async thread on the held connection, and
  `Compacting` is served from a usage snapshot so hosts never wait on it. Afterwards `reclaim` runs after every
  migration batch and bulk removal, settling any WAL truncate the storage records as owed; the first pass of each
  worker ownership truncates once on an incremental database, since a truncate owed when a process ended is recorded
  nowhere. `close_storage` calls `begin_close` on every database before closing media stores:
  a sweep blocked behind a compacting connection holds its store's sweep lock until the VACUUM, which polls the close latch, stops.
- `media/handoff.rs` owns handoff leases (mdk#2314 step 4): the only plaintext attachment files MDK writes, decrypted from a
  retained body (either layout) into `<account>/handoff/<lease>/<name>` for an OS surface that needs a real file.
  Register a lease before its directory exists, delete only on explicit release or by `wipe_stale` (worker start,
  sparing this process's live leases and never following a symlink), and never sync, rename or lock these files.
- `media/outgoing.rs` owns the send path on the media store (mdk#2314 step 3): `SendStaging` admits each body with
  `DiskPolicy::send_need` (a shortfall is `StorageError::Capacity`, which bindings surface as `StorageFull`), reserves
  an `outgoing_attachment_uploads` row and stages the body as that row's file before the first PUT; `upload_staged`
  hashes the wire ciphertext in one pass over the staged file and streams it again per server attempt with
  `EncryptingReader` (never write ciphertext or a plaintext snapshot to disk); `OutgoingUploads` releases every upload
  of a failed or dropped send (rows, then files). The worker's `promote_uploads` pass promotes owned uploads of
  confirmed messages and drops uploads whose file was lost. Keep chunks at 64 KiB and never build a whole-file `Vec`.
- Downloaded attachment bodies are retained in the account's encrypted media store (`media-store` crate,
  `MarmotApp::account_media_store`, one per account; mdk#2314). Callers pass the database handle they already hold, so
  creating a store never opens a database; creation is admitted under the storage lifecycle guard like an open. Every media store call (publish, reuse check, reads,
  sweep) runs on the blocking pool, never inline on an account worker or other async task: file I/O, hashing and AEAD
  would stall every account under UniFFI's single runtime thread. The database authorizes and locates each read
  (`retained_attachment_read`) before the store reads the file. Media stores close through `close_registry.rs`, the
  closure registry `close_storage` runs; register any other runtime-owned closeable handle there too.
- Never discard the shared `imeta` parser's verdict in a projection (mdk#1787). `parse_media_attachment` returns a
  typed `MediaAttachmentRejection` whose `kind` is judged version-first so it does not depend on field order, and
  `media_attachment_outcomes_from_tags` / `media_attachment_outcomes_from_media_json` yield ordered per-attachment
  outcomes indexed by position among the message's `imeta` tags. Bindings surface `Rejected` entries in place; tracing
  logs only aggregate counts and kinds. Keep the three download error classes distinct: `MediaAttachmentRejected`
  (structural), `MediaUnfetchable` (valid reference, no locator fetchable under group/client policy, nothing dialed),
  and `MediaDownloadFailed` (transport, integrity, or decryption after a locator was selected).
- Keep the mechanical `storage_sqlite` `Stored*` <-> app-DTO mapper free functions (account state, groups, components,
  messages, app events, push registrations, telemetry/audit settings) in `src/conversions.rs`. They hold no `MarmotApp`
  state.
- Keep the forensic audit-log feature in `src/audit_log.rs`: the `AuditLog*` DTOs, salted-hash identity derivation,
  the per-account upload checkpoint file (`audit-upload-checkpoint.json`), and the `MarmotApp` methods for audit
  settings, recorder open/build, file enumeration, path validation/resolution/removal, and upload. Audit-log unit tests
  live in its own `#[cfg(test)] mod tests`.
- The v4 upload's HTTP half is `marmot-observability`'s `src/audit_upload.rs`: snapshot capture, the checkpoint record,
  endpoint validation with its retired-host check, the per-attempt pinned request and the response handling. It opens
  no files:
  `audit_log.rs` validates and opens each audit file and reads and writes the checkpoint file, then hands it the open
  file or the record. It returns `AuditUploadError`; `From<AuditUploadError> for AppError` in `src/error.rs` restores
  the variant, message and `privacy_safe_kind` the upload reported before it had its own type, and
  `error::audit_upload_error_tests` covers every failure.
- Keep the bounded live v5 Welcome capture in `src/client/audit_v5_probe.rs`. It records actual retained founding
  preparation, receipt/peel, app join/checkpoint, and bounded stored-group snapshots through the installed recorder;
  tests retain an in-memory probe for focused product-boundary assertions. Do not infer ACKs, recipient joins, or
  durable writes from another boundary. See `tests/audit-v5-welcome-probe.md` for historical subset measurements.
- Keep the v5-only recovery-owner and transport-cursor audit rows in `src/client/audit_recovery.rs`
  (`recovery_need_changed`, `recovery_attempt_started`, `recovery_attempt_finished`,
  `recovery_obligation_reassessed`, `transport_cursor_advanced`). Record at owner seams only: loss import through
  `synchronize_recovery_loss` (never call the storage import directly from client code), the shared execution
  bracket (`begin_recovery_execution` / `finish_recovery_execution`, which the comparison job uses), settlement after
  the checkpoint commits, the notice publication seam and dismissal, and cursor commits after their save succeeds.
  Never add a row per scheduler evaluation, per live ingest, or on the router path; the router only counts
  placements. Rows are best effort: an audit-only read that fails skips the row, never the recovery step. The
  account owner's native input goal uses cause `subscription_replay` in those existing rows, without loss
  charges or history certificates. `subscription_eose_repaired` remains historical decoding only. The publication seam drains the
  adapter's queued subscription refusals (`take_subscription_refusals`) into one `subscription_refused` row. Scenario
  tests live in
  `src/client/audit_recovery/scenario_tests.rs` and `sync/comparison_job.rs`.
- Keep the coverage-ledger recorder in `src/client/recovery_coverage.rs` (mdk#2660 phase 2, shadow mode). It records
  at owner seams only: loss imports (`record_recovery_loss_imports`, goals only and only for loss that named no
  routes: storage un-covers the ledger inside the import transaction, and inside each receipt release), history
  requests (`record_recovery_request`), native
  synchronization (`synchronize_native_replay`) and settlement (`settle_recovery_grant`). A grant reads the ledger's
  un-cover mark when it is selected (`AttemptGrant::coverage_mark`); its certificates are recorded through
  `record_recovery_coverage_since`, which leaves out whatever was un-covered after that. Its writes are best effort
  and nothing schedules, retries or fences on the ledger; do not read it from recovery decisions until phase 4
  replaces the obligations. A live boundary proves only what its relay's count does, once per generation: from the
  second after the oldest event counted (never before the REQ's `since`) through the second before the count's
  `requested_at`. An empty count proves nothing, and no NIP-11 limit is read: the relay pool drops some frames
  uncounted, so a count cannot show a reply was not cut, and relays are assumed to cut newest first. Read the
  un-cover mark before each look at the adapter and write through `record_recovery_coverage_since`; a generation that
  loss imported since the last look may have reached never proves again (`LiveCoverage`), and the log is read again
  after the look so loss imported during it gives no tail; the adapter is looked at again after the write, and a
  generation it no longer reports streaming with the same count gives none either. Past the request an open,
  healthy REQ vouches only provisionally: `LiveTails`, held in memory and never written to the ledger, because nothing
  proves when an open REQ stopped delivering. A tail starts at the count's `live_from`, which for a REQ the relay pool
  sent again is its EOSE, never the request stamp, and stands only while the adapter reports the count streaming
  (`ReplayEndpointView::streaming`: the relay client still names the connection its serial started on); a count
  that is not streaming is recorded as ended. A tail can outlive its REQ by the time the adapter takes to process
  notifications already queued for that relay, an accepted limit: a forwarder that falls behind records loss, which
  breaks it, and a tail never reaches the ledger. Read tails at every debt read; they lapse without an event. A route whose group's live frames
  the adapter's fence holds gets no live boundary until they are released, while its tail stands. Debt that drives work reads the ledger only up to
  `LiveTails::owed_until`, refreshed by `AppClient::live_tails`; without it an idle connected account owes its own
  live frames. Storage keeps a released receipt's second out of every live boundary, and a tail starts past the
  newest one on its route; only a fetch proof covers it, on its own relay. Live-boundary tests live in
  `recovery_coverage/live_boundary_tests.rs`. `coverage_shadow_report`
  is the test-visible comparison with pending obligations; a scope holds proof only as completion would count it once
  loss invalidates by route (its predicate at the current route, inventory and obligation revisions; newer loss voids
  it only where storage's `recovery_loss_reach_after` says loss imported after the scope's loss revision, retired or
  not, reached its route inside its window; a scope that would hold but whose newer loss was since acknowledged is not
  comparable, because acknowledgment deletes where it reached). A loss obligation's scope on a route its own loss
  (`recovery_loss_reach`) never reached there is not comparable, and loss goals are restored only on reached routes,
  from their reach. A scope whose floor is unknown or older than the
  retained window is owed from the retention floor. Before it prunes, it passes the current routes and
  their required relays, so what they still owe below the floor is parked as each route's remainder; the prune settles
  every route there, so restoring a pending loss's goal below it each report parks nothing twice. Standing goals
  (startup history, epoch gaps) start at `standing_floor`: a group copy's Welcome time less the allowance, never below
  the window. That time is only a hint: never use it to retire, un-cover or drop debt. It logs aggregate counts only.
  Known disagreements
  are listed in `docs/marmot-architecture/further-context/account-recovery.md#coverage-ledger-shadow-mode`.
- Keep the recovery runner in `src/client/recovery_runner.rs` and its `admission`, `select`, `quantum`, `compare`,
  `recheck`, `policy`, `tails` and `host` modules (mdk#2660 phase 4). It runs only behind the internal
  `runner_owns_debt` gate (`RECOVERY_RUNNER_OWNS_DEBT` in `lib.rs`, off; proofs turn it on with the hidden
  `MarmotApp::with_recovery_runner_owning_debt`), never a host setting or cargo feature, until the switch-over flips it.
  With the gate off nothing constructs it and the comparison owner keeps every behavior. `host` is its only seat:
  the account worker spawns it with the worker, serves one of its turns each pass of its loop (as comparison
  admission gets one) and waits for the next in one select arm, and stops it on the client at every exit that still
  holds one (`SpawnedRunner::stop`), so a preempted quantum settles there but nothing is ingested on the way out.
  Whoever lets go of a runner, by a stop, an abort or a dropped in-place pass, refunds the attempts it began and never
  settled as `Unanswered` (`OpenAttempts`), through storage that is still open, and a settle whose write failed stays
  open for that refund. `shutdown_and_close` refunds only if storage is still open as the runner stops; otherwise,
  and after a crash, the charge stays until it ages out of the hour. A
  directly owned client from `MarmotApp::client()` runs one pass in place from `sync()` and from `next_event()`'s
  loss branch. The worker never awaits a pass, the network or a credit. The host routes a fetched event through the
  adapter's installed subscriptions, which trail the routes a debt turn reads: a valid event that routes nowhere yet
  stops its slice uncovered as a local failure (`SinkStop::Unrouted`), and only an invalid one is dropped. Wake it
  through `AppTransportRouting`'s sender at the chokepoint that changes debt or routes (loss import, goal widening,
  route replacement, a released receipt, a dismissal, a group lifecycle effect), never per call site; it re-reads
  the ledger on every wake. Every ledger and retry-state write happens in a worker turn; the
  credit wait, caps read and sweep run off the worker, and nothing read before the credit wait is planned on. Live
  tails are a query read fresh in each turn, never stored. A quantum's outcome comes from `quantum::classify` alone (the plan's outcome table): newly
  covered seconds settle `Advanced` before any relay verdict, a local write failure outranks both, and a deadline
  reached right after a `rate-limited:` reply settles `RateLimited`. Every event byte a required relay sends is
  charged to the account's rolling hour, cut and discarded replies included; best-effort relays are never charged.
  A quantum cut by its deadline, shutdown or the pass deadline interrupts its request in flight rather than dropping
  it, so the reply it was reading is charged too (`SweepRelay::interrupt`); an interrupted request is no answer and
  never clears a rate limit.
  A comparison or re-check quantum settles through the same table: its end maps to a sweep end (`compare::verdict`).
  A re-check settles the relay and the account budget but never its unit's retry state, records pass progress only
  under the pass revision it began on (a request that makes the pass due mid-quantum wins), and never un-covers; it
  runs only when no debt unit is eligible, on required relays whose recorded caps show NIP-77. Storage makes a relay's
  re-checks due in the same write that ends a cooldown longer than an hour; do not split that into a second write.
  Admission releases a group's staged events oldest first below its admission frontier, never past an event the
  engine kept no trace of. Nothing is swept, compared or re-checked for a group admission cannot drain (held, or
  admission waiting after local failures), and a re-check gets no frontier exemption from backpressure. Only capture debt below a non-empty live count fences; the fence is a query
  (`live_fences`) over each unit's durable capture ranges, and the runner reads live counts through its own
  `LiveCount`, never the coverage recorder's facts. `recovery_runner_live_counts` maps the admitted counts into it
  with the adapter's fence ticket and held routes; `fence_live_frames` answers with that ticket. Nothing calls
  them or `enable_live_fences` before the switch-over. Logs carry aggregates only.
  An Unrecoverable group's routes are suspended (`RunnerRoute.unrecoverable`, read from the engine's group record
  each debt turn): never scheduled, charged, broken or noticed, left out of admission so what they staged is given
  back as an unlisted route's is, and with the gate on the comparison owner drops their
  epoch-gap obligations from its grant fence (`suspended_epoch_gaps`); gate off, it fetches them as before. A
  retained route's ceiling (`retained_route_goal_until`) caps every debt and re-check read through
  `DebtTurn::owed_until`/`checked_until`; never store it. Route-gone retirement runs only in the runner's debt turn
  (`settle_recovery_route_changes`), from drops `replace_group_routes` records once a runner tracks them; a full
  `replace` records only inbox drops, and a group left with no route is forgotten, not retired. A relay the routes
  carry again reopens only its `RouteGone` spans; do not re-arm units on a route add. Reconnects come from the relay
  pool's connection generations (`NostrSdkRelayClient::relay_connections`), diffed at each step, and an unknown caps
  read (`None`) is never evidence. Window hints come from the live conversation captures
  (`open_conversation_groups`). The breaker's pauses and late findings are process counters
  (`recovery_runner_counts`) carried only by the v5 `recovery_runner_paused` row, written through the turn's audit
  sink (`WorkerTurn::audit`).
- The configured audit OTLP/HTTP sender is `marmot-observability`'s `src/audit_otlp_sender.rs`, which hosts name as
  `marmot_app::audit_otlp_sender`. It accepts an owned local-delivery batch,
  checks the prepared destination, preserves each original v5 JSON body inside the restricted OTLP JSON envelope,
  and maps only complete, partial, and retryable receiver outcomes to local finish actions. Blocked and unknown
  outcomes retain the prepared range. Runtime tracker/manual triggers and additive native bindings configure it;
  there is no default v5 destination.
- Keep process-local audit export admission in `src/audit_export_lifecycle.rs`: one active attempt per account, short
  local admission under `storage_lifecycle`, and cancellation on consent, deletion, account removal, destination change,
  or close. Never hold local guards across HTTP or wait for HTTP before releasing the root lease on terminal close.
- Record new opt-in sessions into distinct v5 files and deliver strictly validated v5 JSONL through OTLP. Historical
  v4 files retain their separate v4-only Goggles whole-file path. Never migrate or send v1-v3
  or key-reveal files. Reject removed/unknown fields and duplicate keys before HTTP; cache ineligible file verdicts
  by size and mtime without retry cooldowns. On exclusive-root startup, `audit_log/legacy_cleanup.rs` deletes
  reserved v1-v3 filenames and their segments from `accounts/` and failed-wipe `.wipe-tombstones/` remnants
  without reading payloads, even when recording is disabled. Match the frozen 32-lowercase-hex legacy engine ID,
  not the current audit ID width; pin the live layout through AccountHome-backed tests.
  Keep this after lease acquisition and before exposing the app; never traverse symlinks or delete v4/future
  filenames, names outside the reserved legacy forms, or the separate key-reveal log. Unexpected containers
  and other cleanup errors are reported with aggregate counts, are nonfatal, and retry on next open.
  Account/device names are forbidden in rows and headers; hardware model is system-sourced, never a label.
- Keep audit uploads incremental (mdk#1181). An audit file whose size and mtime still match its checkpoint entry is
  never re-read or re-posted; only the growing active file re-transfers, bounded by the recorder's segment threshold.
  Checkpoint only complete immutable upload snapshots after successful upload.
  Defer an unfinished trailing JSONL row and preserve it for a later upload; an HTTP length limit alone is insufficient.
  Automatic triggers use a fixed 30-second window and the size-1 coalescing queue in `runtime/audit_tracker.rs`.
  Later triggers cannot postpone that window or shorten a failure cooldown. Manual upload APIs remain immediate.
  Incomplete snapshots wait for the next trigger. Automatic failures retry after 60 seconds, doubling up to five
  minutes; authentication failures wait at least five minutes, and Retry-After can extend the delay up to five minutes.
  Stop automatic passes on endpoint-wide failures
  (authentication, rate limits, server/transport failures); file-specific failures and oversized files must not block
  the files behind them.
  Treat a `413` with no `Retry-After` as the endpoint's verdict on that file (RFC 9110 15.5.14 has a server send the
  header when the refusal is temporary): acknowledge it as too-large so it is reported once and never re-posted. Unlike
  the local ceiling this verdict is escapable: it is keyed on the file's size and mtime, deleting the sidecar clears it,
  and a manual per-file upload never consults it. A `413` carrying any `Retry-After`, parseable or not, is a cooldown
  and retries like any other rejection.
  Shutdown cancels pending or in-flight automatic work; unacknowledged files remain on disk.
  Tests may shorten the window per runtime via `test-policy-overrides`; paused-clock tests pin the production default.
  `audit_log/retention.rs` owns the fixed 30-day local forensic retention policy, independently of uploads and consent.
  Sweep metadata on exclusive-root startup and hourly across accounts and failed-wipe remnants, independent of
  account workers. Use a size-one candidate queue and per-file storage admission. Retire through local delivery before
  unlinking; drain directory-local cursor work, cancel only a prepared attempt owning that inode and block new
  reservations for that directory. Other uploads must remain valid; never globally fence orphan/tombstone cleanup;
  never rewrite rows or unlink the actual live inode. Serialize the weak registry with writer creation and let the
  recorder recheck metadata and protect its canonical/actual backing paths under its own lock.
- Keep the upload checkpoint's cost proportional to the account's *live* audit files, not to its history. `retain_present`
  prunes entries for files that are gone, so the sidecar is O(live `audit-*.jsonl` files). Retention deletes expired
  segments, and each tracker run stats every file and
  rewrites the whole sidecar. Do not add a per-upload or per-line entry, and do not treat the sidecar as durable state:
  losing it costs one repeat transfer per file and nothing else.
- A file above `AUDIT_LOG_UPLOAD_MAX_BYTES` has no app-level transfer path. `post_audit_log_file` enforces the same
  ceiling, so the tracker's skip is the whole story: the file stays on disk for manual handling. Do not document an
  escape hatch that does not exist, and do not widen the ceiling to invent one.
- Keep SQLCipher key derivation, per-database salt persistence, legacy-key migration/recovery, and the in-process
  v2-open probe-verdict cache (mdk#1439) in `src/sqlcipher.rs`. The verdict cache is advisory only: a durable
  migration marker or a missing verdict always re-runs the recovery probe, so the mdk#568 crash windows keep their
  self-heal. Key presentation and the passphrase KDF work factor follow the decision record in
  `docs/marmot-architecture/storage-format-v2.md`.
- The user directory is the [`nostr-directory`](../nostr-directory/AGENTS.md) crate; `src/lib.rs` re-exports its
  types at their `marmot_app::...` paths. This crate keeps the resources the directory reaches through traits:
  `src/directory_resources.rs` implements `DirectoryResources` and `DirectoryObserver` over the per-account cache
  lifecycle, label-based account resolution and product analytics, and builds the service with `directory()`;
  `src/user_blocks.rs` implements `BlockListSink`; publishing the account's own profile and follow list is
  `src/profile_publication.rs`. `directory()` builds a fresh service on each call with `DirectoryConfig` read from the
  app's configuration; anything the directory keeps between calls lives in `directory_state`, never in `directory()`.
- Classify a lower-stack error by what it is, never by its wrapper (mdk#2602). Ask `AppError::as_engine_error`, or
  `AccountError::as_engine_error` / `SessionError::as_engine_error` below it; do not match `AppError::Session(..)`
  or `AppError::Account(..)` paths. `From<SessionError>` and `From<AccountError>` recognise the external-signer
  sentinel by text, as `From<TransportAdapterError>` does, so build `AppError` from them with `?` or `From`, never
  with the variant constructor. `src/error_kind_table.rs` lists every wrapping the lower stack produces with each
  host's answer. This crate checks the sync class, privacy kind and wipe reason; `marmot-uniffi`, `marmot-c` and
  `wn-cli` check their own columns over the same rows. A new wrapping or host classifier adds rows or a column.
- Callers reach the directory through `app.directory()`, whose methods return `DirectoryError`; `MarmotApp` has no
  directory delegates. `From<DirectoryError> for AppError` in `src/error.rs` restores the variant, message and
  `privacy_safe_kind` the directory reported before it had its own type, so app paths that return `AppError` convert
  with `?`; `error::directory_error_tests` covers every variant. The CLI, agent connector and bindings convert
  `DirectoryError` through `AppError` too, so their error codes don't depend on which layer failed.
- Directory tests that need a real `MarmotApp` or runtime live in `src/directory_tests/`, one module per directory
  file; tests that need only the directory live in `nostr-directory`. They reach directory internals through its
  `test-support` feature (enabled here as a dev-dependency only): gated root re-exports and `_for_test` wrappers. The
  account's own KeyPackage inventory, record merge and publish-endpoint selection stay in
  `src/key_package_records.rs`, and the group-id helpers in `src/ids.rs`; both re-export only the directory helpers
  the app's own code uses.
- Keep the crate root focused on app construction, shared state, storage/projector wiring, account relay-list helpers,
  and public re-exports.
- Never publish an account relay list from the cache alone. `ensure_local_account_relay_lists`, which every KeyPackage
  publish, setup publish and rotation runs first, leaves an open generated setup's lists to that setup (mdk#2359);
  otherwise it adopts the published lists through `resolve_account_relay_list_status_for_account_id` and publishes only
  a kind a complete read proved absent (mdk#2550).
- Keep CLI/TUI presentation out of this crate.
- Keep the Nostr user directory app-facing and pubkey-keyed. It may cache local-account links, profile metadata, follow
  lists, relay lists, and KeyPackages. Web-of-trust search may traverse the live follow graph, but traversal is bounded
  by construction: a capped search radius, a per-radius candidate cap, a per-radius fetch timeout, batched
  author-scoped fetches, and a per-search lifecycle — traversal runs only while a search
  subscription is live and stops as soon as its consumer drops. There is no background or open-ended crawl.
- Keep web-of-trust search results un-promoted. Strangers discovered by search are never written to `directory_users`
  and must never reach `directory_sync_plan` or live per-author subscriptions (mdk#418); cache them only in the
  un-promoted `directory_search_graph_users` tier, which directory sync never reads.
- Keep runtime directory subscriptions chunked and privacy-safe. Subscription identifiers must not embed raw pubkeys.
- Treat Marmot kind `30443` KeyPackages as cached last-resort packages. Normal publish should reuse the cached valid
  package and stable replaceable d-tag; expired or policy-invalid packages rotate to a fresh package ref.
- Incoming welcomes may auto-join MLS state, but app projections must preserve local confirmation state. Pending invites
  should stay visible until accepted, and decline should leave the group before archiving the local projection.
- Keep protocol engine behavior in `cgka-engine` and session ownership in `marmot-session`.
- Name no `cgka_engine` item in production code. `cgka-engine` is only a dev-dependency here, so the library build
  rejects one; engine types come through `marmot-session`'s re-exports. The crate root re-exports the lower stack's error
  types (`AccountError`, `SessionError`) and identity-proof signer types, so hosts reach them through `marmot_app`
  (mdk#2602).
- Every recovery cause and caller runs the one comparison job in `src/client/sync/comparison_job.rs`; there is
  no inline executor. Runtime catch-ups (`SyncMode::Drain`) only drain the live queue and never run a job, so
  they cross a worker-owned job (mdk#2110); `sync()` drains, then runs one job in place; nothing
  re-subscribes to recover history, and only startup, a frozen wake or an unactivated client installs live
  subscriptions. Its epoch-gap window (`fetch_epoch_gap_window`, mdk#2256/#2257) pages backwards from relays that
  failed without answering comparison, using raw counts/timestamps before SDK filtering and bounded advisory hints.
  Admit only completed oldest pages; cuts and saturated seconds release no newer suffix. Held-only traversal never
  resets pacing or durable parking, even after hint eviction or client reconstruction. Keep original comparison
  stability and SQL fences. Never fetch ahead of older comparison backlog, and admit the route's
  comparison and window events together oldest first. Window events (`PendingSource::Window`) must not touch the
  route's certificate, replay cursor or admission verdict. Explicit full-history repair runs the job in place: one comparison pass over every route of its
  grant inside the repair budget. It never reports complete: history below the retained window is unsearched
  (`BelowRetentionWindow` when the window certified), so never certify explicit history from a window; that
  result closes the request (`close_explicit_history_request`, revision-checked) instead of leaving debt that parks
  into a notice; an explicit scope whose window certified reports `RecoveryPassProgress::WindowCertified`, never
  `Quiet`, and the checkpoint that finds every scope certified closes the request from any pass,
  while `CoverageUnproven`, `Cancelled` and `Deadline` keep it open. Keep
  the budget split: the network pass ends at `FullHistoryRepairControl::network_deadline` and returns its finished
  routes for admission; only cancellation aborts the request at the poll; `stopped` ends admission at a turn
  boundary, keeping the admitted prefix; and
  preserve generation-checked overflow marker clearing. The account worker can serve committed snapshot reads
  while repair waits; mutations retain FIFO order, and repair waits while a worker-owned job
  is in flight. Client continuation tests live in `src/client/sync/full_history_tests.rs`; worker
  cancellation/read-order tests stay in `src/runtime/account_worker.rs`. See the README for the
  automatic-recovery and send-fairness limits.
- A dismissed "history may be incomplete" notice is the one user-authorized ending for parked recovery debt
  besides qualified completion. Record it only through `retire_parked_recovery_obligation` (its own outcome,
  never coverage) and release the delivery-loss fence through `release_retired_delivery_loss`, which keeps the
  fence while any loss obligation is pending, clears the plane only against the exact observed generation, and
  never counts a recovery success. Notice ids are opaque and must not be logged.
- Keep an account's delivery route open when its relay notification consumer lags: charge the lag as notification
  loss with the REQ floors its SDK context reported at the lag (per route when known; record them through
  `record_account_recovery_loss_routed`), and enqueue the generation's control record. Only an
  unexpected consumer exit closes the route and sends the worker through reconnect (mdk#2070). The worker persists
  notification loss before waiting for its control record.
- AccountRecoveryOwner owns the SubscriptionReplay goal, original unresolved windows, retry and completion.
  Synchronize borrowed source observations at lifecycle, grant, checkpoint and worker-watch seams. Preserve
  unresolved floors across cancellation/reopen; an unfloored query must not become a recent tail. Capture only
  current sources authorized by the frozen selected grant, through the existing credited comparison job.
  Passive replay_admitted needs current-epoch full-range placement and no pending bytes/nondurable spill;
  it spends no retry credit and never qualifies history, maintenance, known-event or real loss predicates.
  Empty silence is not notification loss. No adapter/relay-plane quiet repair scheduler or alternate owner.
- Register `ReplayIngress` before activation, seeding durable group spill rows before native source release.
  Admit complete group batches through the owner's ordinary recovered-ingest path, sharing four actual
  ingests per turn with comparison input, never through live/spill alternation. Select the oldest known
  same-group frame across both sources; a pending native range fences that group, not independent groups.
  Borrow each frame until ACK; cancellation or loan revocation leaves the frame
  retained. Native batches keep holding the cursor, but acquired ranges spend no new network retry credit
  while draining. Keep retained spill receipt settlement and independent-group turns.
- Move `checkpointed_transport_timestamp` only through `AppClient::seal_transport_cursor`, never straight to
  `state.last_transport_timestamp`. The seal holds adapter admission stable through the router's placement lock,
  importing any discarded replay into the existing loss fence before deciding. It returns nothing while staged,
  releasing or not-yet-placed replay, loss, or a spill hand-off is pending, and caps the commit at the
  lowest delivery a restart still fetches that is queued or taken and not yet released, and raises the restart floor
  before the save, so the router spills a delivery that arrives during the save and falls below it; before the
  account's first settled floor that is every older delivery. A live ingest promotes with its own save only when
  the owner's completed/explicitly retired native goal matches the guarded source generation and the account
  has a settled floor, and leaves the floor raised. A drain
  checkpoint, settled loss or retired notice confirms what its seal reached with `settle_transport_cursor` once its save
  succeeds, which ends the spilling. Every failed save undoes its seal with `abandon_transport_cursor`. Keep every
  condition cursor safety relies on inside the seal: anything read before an `.await` or a save is stale by the time
  that save commits. See `docs/marmot-architecture/further-context/account-recovery.md` section 6.
- With no durable transport cursor, activation requests retained history rather than inventing a recent-tail floor.
  A trusted cursor keeps its configured rewind, bounded by unresolved original native windows. All-relay EOSE
  remains separate from the owner's limited native admission; a silent peer alone must not prevent a seal once
  available replay is placed and the matching native goal is completed or explicitly retired.
- Every path that takes a delivery from the account queue calls `release_account_delivery` once its ingest returns
  `Ok`, or when it skips the delivery as already held, and before the save that follows. Never release on an ingest
  error: the key must keep capping the checkpoint that failure runs, because newest-first replay has usually remembered
  a newer cursor. A new consumer of the queue that forgets to release holds the cursor back until the queue generation
  ends; one that releases early lets a failed ingest's checkpoint pass the delivery.
- Keep Nostr group routing sourced from `marmot.transport.nostr.routing.v1` component bytes; relay filtering may affect
  connections, but must not rewrite signed routing state. Relay endpoints pass through the `RelaySafetyPolicy`
  host-safety chokepoint (`transport-nostr`'s `src/safety.rs`), and agent-stream broker candidates through
  `src/runtime/agent_stream_watch.rs`, before any connect; both follow the one dial discipline in
  `docs/marmot-architecture/overview/dial-safety.md` (validate + pin, trust from config, loopback only under an explicit
  dev flag). Do not add an outbound relay/broker path that bypasses them.
- Floor every history REQ at an anchor, less `HISTORY_FLOOR_CLOCK_SKEW_ALLOWANCE` (`history_floor`, ledger A14): the
  post-join maintenance REQ at the Welcome that installed the copy (`Group::local_copy_welcome_created_at`, never the
  local join time, which an offline member reaches long after the Welcome), and a retained route at the moment
  `refresh_from_group` saw it replaced (`AppPriorNostrRoute::replaced_at`). A retained route stored before switch times
  were kept is stamped by the first `load_state` that finds it, and the stamp is persisted at once
  (`stamp_unrecorded_prior_route_switches`) so later launches never move its floor forward. Keep each group's current
  route first in the routing table (`replace_group_routes` preserves the caller's order; a new lead is a change): the
  adapter reads the lead as the route that resumes from the cursor. A locally deleted group lists its current route
  first too, never its frontier copy. See `docs/marmot-architecture/further-context/account-recovery.md` section 5.
- Keep the post-join history fetch's lifetime apart from the PostJoin obligation's phase (mdk#2626).
  `advance_post_join_maintenance_subscriptions` keeps a group's session while its fetch is owed, whatever phase commits
  moved the obligation to, and ends the fetch only through `settle_post_join_history_fetch`: `Fetched` needs the
  session's qualified boundary, open native ingress and the adapter's placement verdict for that subscription, and
  the deadline expires only a session whose boundary has not qualified. While a fetch is owed, its session is
  requested and retained under the fetch's job alone; an early-phase obligation (a re-armed one, or an earlier copy's
  after a replacement Welcome) keeps the session alive but never picks its job. A session installed for another fetch
  id (an earlier copy), or whose demand is gone before its boundary qualified, never ends the current one. The fetch never moves the obligation, so self-update timing stays the
  obligation's own.
- Keep `MarmotAppRuntime::shutdown_and_close` the one terminal teardown for hosts whose process can be suspended: it
  closes admission, closes every SQLite database and releases the root runtime lease first, then gives graceful worker
  cleanup a bounded budget. The terminal operation must outlive cancellation of its caller. `shutdown` alone does not
  release file locks. Register every resource that can hold a lock in the root with `root_closers` while holding
  `begin_storage_open` admission (the engine's own `session.sqlite` connection included); `close_storage` closes that
  registry, not the handle caches. Closing is terminal — do not add a path that transparently reopens a database
  afterwards, and put shutdown checks at engine-step boundaries (never inside a step, where a snapshot guard may be
  live). See `docs/marmot-architecture/overview/local-artifact-safety.md`.
- Broadcast a projection update only after the write that produced it commits: build it inside the write's
  transaction and publish it from the worker at one of two points. Received and other summarized updates go out
  through the operation's summary once the operation returns. A local send publishes its own projection earlier,
  from the in-command `on_local_projection` callback, right after its record call has committed. A host may close
  storage the moment it shows an update. `tests/group_activity_reactions.rs` closes right after a live
  reaction and reads the store before any runtime starts (mdk#2345). Tests that wait on a live timeline must match the
  exact expected state: a timeline also carries its own account's changes, so "any reaction" can match a stale one.
- Keep legacy message-format promotion after account readiness and bounded to
  one small transaction per steady-state maintenance tick. Log aggregate
  progress only, retry transient contention, and halt durable decode failures
  without disabling legacy reads.
- Keep local test relay code in tests; production app runtime should talk to Nostr relay URLs through the adapter.
- Do not print or log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key
  material.
- Keep the relay-telemetry export path in the relay plane (`transport-nostr`, rollup in its `src/telemetry.rs`) and
  `marmot-observability`'s `relay_telemetry_export.rs` (exporter, including the `RelayTelemetryExporter::new`
  constructor). It is
  opt-in and off by default: `RelayTelemetryExporter::new` is the single construction gate, relay-identity
  resolution requires it (through the plane's `RelayExportGate`, which the export config implements), and export
  points carry only a `relay` label. Keep the OTLP wire encoding and HTTP push behind
  the `otlp-export` feature; keep the privacy-critical mapping (`build_export_batch`) and the opt-in gate in the default
  build. Keep per-attempt collector DNS validation and pinning in `marmot-observability`'s `collector_host_safety.rs`: validate
  every address, pin reqwest, disable redirects/system proxies, and retain TLS verification. It builds every collector
  client through the `http_builder` that both `MarmotApp` constructors hand in (`hand_in_http_builder`); before that
  it builds none, so nothing dials, tests included: a test that dials hands in a builder itself. Endpoint parsers and the exporters' resolved config live in `marmot-observability`'s `export_config.rs`;
  `config.rs` keeps the settings that resolve against `MarmotServiceEndpoints`. Explicit SOCKS5 routing
  must send the validated IP rather than delegate HTTP DNS to the proxy. Build every relay client with
  `network_proxy::nostr_builder()` (in `transport-nostr`, its own `nostr_builder()`, which calls the same adapter
  builder; that crate's `clippy.toml` holds the same ban) and every HTTP client through `network_proxy::http_builder()`; `clippy.toml` rejects
  direct `nostr_sdk`/`reqwest` constructors. Allow that lint only where a fresh reqwest builder goes straight into
  `http_builder()` or in local test fixtures. Only exact `localhost` or a
  loopback IP literal is a local-test endpoint, and all its addresses must be loopback. The default build includes this
  helper so forensic audit uploads share it; do not feature-gate the module or introduce a second uploader. Relay
  NIP-11 fetches (`relay_caps.rs`) pin through its `pin_with` too, after the relay gate (`RelaySafetyPolicy`). See
  `docs/marmot-architecture/relay-observability.md`, `audit-logging.md`, and `overview/dial-safety.md`.
- The diagnostics exporters live in [`marmot-observability`](../marmot-observability/AGENTS.md) (mdk#2627). Its
  surface is its crate root; its other modules are private. This crate records through `Observer`'s views
  (`ProductRecorder`, `PerformanceRecorder`, `ProductOperation`), runs the collectors through
  `marmot_observability::wiring`, names everything else at the crate root, and re-exports what hosts name at their
  `marmot_app::` paths: the `product_analytics` and `audit_otlp_sender` modules, and the other types by name from the
  crate root. Hosts can name `ProductAnalytics`, `AppPerformanceTelemetry`, `ProductObservation`, `DiagnosticsPermit`
  and `AuditOtlpSender`, so do not give them new `pub` methods; add the method to a view or to `wiring`. An operation
  recorded as one product outcome runs its body through `ProductRecorder::observed` and an outcome rule
  (`success_or_failure`, `confirmed_or_failure`, `send_outcome` or its own); do not write an `_unobserved` twin beside
  it.
- Diagnostics tests that need a `MarmotApp`, its runtime or the network-proxy policy live in `src/observability_tests/`,
  one module per crate file. They reach the crate as the rest of this crate does, plus the fixtures its root
  re-exports and its `_for_test` hooks, which `marmot-observability`'s `test-support` feature (enabled here as a
  dev-dependency only) builds.

## Code map (modules not covered above)

- Crate root `src/`: `config.rs` (`MarmotAppConfig`, collector endpoints, attachment acquisition policy),
  `deployment.rs` (`MarmotDeployment`: the deployment services, with `neutral()` and the White Noise preset; the one
  place White Noise's values are defined), `error.rs`,
  `close_registry.rs` (terminal-close closures for runtime-owned handles outside the storage caches),
  `ids.rs` (group-id and admin-key helpers; it wraps the npub/nprofile/account-ref helpers in `nostr-directory`'s `ids.rs`), `drafts.rs` (encrypted per-account composer drafts),
  `chat_presentation.rs` + `chat_presentation/` (shared selected-chat presentation policy and maintenance),
  `conversation_presentation/` (C5 header, capability, and window selectors; they never subscribe, acknowledge
  reads, or fetch media), `local_submissions.rs` + `local_submissions/` (durable device-local send admission and host
  correlation; no relay I/O),
  `user_blocks.rs` (block policy and NIP-51 sync), `moderation_reports.rs` (private NIP-59-wrapped NIP-56 reports
  to the deployment operator: config validation, staged outbox, retry, purge; tests in
  `moderation_reports/tests.rs`), `history_notices.rs` (public notice DTOs and opaque id codec),
  `history_bundle.rs` (the history bundle's encoding, filling in chat order and sealing; tests in
  `history_bundle/tests.rs`), `notifications.rs` (push platform, triggers, settings), `external_signer.rs` (`ExternalAccountSigner` and the
  internal `AccountSigner`), `nostr_secret.rs` (secret-key shape classification shared with CLI/UniFFI),
  `nostr_verification.rs` (stateless public-event verification), `relay_caps.rs` (each relay's NIP-11
  `max_limit` and NIP-77 support for the history sweep, cached per relay; unknown caps on any failure), `profile_pseudonyms.rs` (cosmetic display names; not a
  security primitive), `publisher_sequences.rs` (QUIC preview publisher lifecycle state), `agent_streams.rs` (agent
  stream watch DTOs and manager), `root_runtime_lease.rs` (cross-process exclusive root lease), `usage_diagnostics.rs`
  (`MarmotApp`'s usage-diagnostics consent persistence and the headless-host analytics configuration; it reaches the
  product collector only through `marmot_observability::wiring`, consent lock before state lock), `projection.rs` (legacy account
  projection import), `messages/` (`AppMessageIntent` and custom-event intents), `local_open_test_gate.rs` and
  `test_support.rs` (test-only gates/helpers).
- `src/runtime/`: `worker_startup.rs` (per-account startup admission and retry backoff),
  `account_worker/recovery_credits.rs` (process-wide recovery credit pool), `conversation_window.rs`, `chat_list_window.rs`,
  `presentation.rs`, `presented_chat_list.rs`, `account_attention.rs` (presentation windows and account-switcher
  attention), `user_blocks.rs`, `moderation.rs` (reports, admin labels and operator moderation reports),
  `local_submissions.rs`,
  `agent_publisher.rs` (host-driven agent publishing), `attachment_controls.rs`, `attachment_permission.rs`
  (runtime-only network approval; never restore it from disk).
- `src/client/`: `recovery.rs` (recovery grant authorization), `recovery_coverage.rs` (the shadow coverage-ledger
  recorder and its comparison with pending obligations, mdk#2660), `recovery_runner.rs` (the per-account recovery
  runner behind the internal `runner_owns_debt` gate, mdk#2660; `recovery_runner/host.rs` seats it on the worker or
  a direct client), `invite_recovery.rs` (durable invitation recovery),
  `epoch_stall.rs` (epoch-gap backfill detection), `delivery_spill.rs` (worker side of the durable delivery spill),
  `audit_v5_app_update.rs` (bounded app-boundary audit rows), `sync/comparison_job.rs` (the one recovery comparison
  job).
- The shared relay plane is the [`transport-nostr`](../transport-nostr/AGENTS.md) crate; name its items as
  `transport_nostr::`.
- `src/sqlcipher/open_lock.rs`: in-process same-file open exclusion (the root lease covers cross-process).
- Integration tests in `tests/` (with `tests/support/` and `tests/fixtures/`); media benchmarks in `benches/` (require
  `media-benchmarks`); `examples/usage_diagnostics_staging/`.

## Features

- `test-policy-overrides`: test-only convergence timing/rewind overrides. Never enable in app artifacts.
- `otlp-export`: OTLP protobuf encoding and HTTP push for relay telemetry (the privacy mapping stays in the default
  build); forwards to `marmot-observability/otlp-export`.
- `product-analytics-export`: product analytics export path; forwards to `marmot-observability/product-analytics-export`.
- `media-benchmarks`: internal surface for the media transport benchmarks.
- `test-support`: exposes `error_kind_table` to the host crates' tests and turns on `marmot-observability/test-support`
  (the diagnostics test fixtures and hooks). Enable it only as a dev-dependency.

## Verification

```sh
cargo test -p marmot-app
# Accelerated recovery/retry scenarios (also enabled by workspace CI):
cargo test -p marmot-app --features test-policy-overrides
# Opt-in OTLP exporter wire encoding and push (heavy deps behind a feature):
cargo test -p marmot-app --features otlp-export
```

Tests that require shortened production policy intervals must use
`#[cfg(feature = "test-policy-overrides")]`; normal test builds deliberately
ignore those configuration overrides.

Async tests in `src/` and `tests/` default to `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`, the flavor
every production binding uses; a test that needs more workers sets its own `worker_threads`. Composed whole-app
`#[test]`s run through `run_composed_app_runtime_test`, which builds the same two-worker runtime with every thread on an
8 MiB stack; a test that builds its own runtime uses `Builder::new_multi_thread()` with `worker_threads(2)` and gives
every thread its stack (`thread_stack_size`). Only a test that needs one thread stays off it:
`#[tokio::test(start_paused = true)]` for a clock paused from the start (Tokio allows that only on the current-thread
runtime), otherwise `flavor = "current_thread"`, `run_composed_app_runtime_test_on_one_thread`, or
`Builder::new_current_thread()` with a `//` comment on the line above saying why.
When a multi-thread test waits for an effect, wait for the state it expects rather than the next event: other
tasks run between your steps, and window subscriptions keep only the latest snapshot. `Notify::notify_waiters` reaches
only waiters already registered, so a fixture signal either uses `notify_one`'s permit or the waiter `enable()`s its
`notified()` before announcing it waits.
