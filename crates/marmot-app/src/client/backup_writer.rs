//! Writing backups (mdk#2628 item 4.4b, D71, D79).
//!
//! The device the roster's account entry names the backup writer, or a
//! device with no device group under the key it keeps, writes the account's
//! backup once a day: an archive (`backup_archive.rs`) on the deployment's
//! Blossom servers, listed in the account's backup pointer under the
//! recovery key. A pass runs from maintenance, once due, on the media lane:
//!
//! 1. [`AppClient::prepare_backup_pass`], on the worker, reads the key and
//!    the writer, forgets the ledger under any other key, and abandons a run
//!    that stopped before its head.
//! 2. [`BackupPass::run`], off the worker, fetches the pointer from a relay
//!    that answers in full and deletes condemned blobs whose backup it does
//!    not list. While this device writes, it publishes again a run no relay
//!    accepted yet, or, once the newest listed backup is a day old, uploads a
//!    new one, each blob recorded in the ledger before its upload. It builds
//!    the pointer that lists the run, by retention, and condemns the blobs
//!    of the backups that pointer drops.
//! 3. [`AppClient::finish_backup_pass`], on the worker, checks that this
//!    device still writes under the same key, then signs and publishes the
//!    pointer. A backup counts only once a relay accepts its pointer. Until
//!    one does, later passes publish it again for a day, then abandon it.
//!
//! A condemned blob is deleted only while the pointer fetched in that pass
//! lists no backup it belongs to, and no sooner than an hour after it was
//! condemned; deletes are tried for a week. A run abandoned or cut short
//! has its blobs condemned the same way. Backups under other words, or
//! turned off, are never deleted.
//!
//! A device that does not write takes over at once when the writer has left
//! the roster or is leaving, and once the writer has listed nothing for a
//! week since this device first saw it named for this key. It commits
//! itself as writer over the entry it read, through the roster's
//! compare-and-set, so concurrent takeovers settle on one. Nothing secret is
//! stored: the archive key lives only in the pass.

use std::collections::BTreeSet;
use std::sync::Arc;

use bytes::Bytes;
use cgka_traits::app_components::{AccountEntryV1, DeviceSlotId, DeviceStatusV1};
use cgka_traits::{GroupId, MemberId, TransportEndpoint};
use marmot_session::DeviceRosterEdit;
use sha2::{Digest, Sha256};
use storage_sqlite::{BackupRunHead, BackupSchedule, SqliteAccountStorage};
use transport_nostr::DirectoryEventQuery;
use transport_nostr_peeler::{MarmotNostrSigner, NostrTransportEvent};

use super::AppClient;
use super::chat_history::{ExportedBundle, export_history, newest_bundles_start};
use crate::backup_archive::{
    ArchiveKey, BACKUP_ID_LEN, BackupHead, BackupIndex, BackupPointer, BlobLocator, IndexBlob,
    ListedBackup, MAX_BACKUP_HEAD_BYTES, PointerEntry, backup_address, new_backup_id, retain,
    seal_backup_bundle, seal_backup_small_state,
};
use crate::history_bundle::{ChatPosition, HISTORY_BUNDLE_MAX_PLAINTEXT, is_chat_hex};
use crate::history_delivery::{MAX_BLOSSOM_BUNDLES, blossom_server_for_endpoint};
use crate::media::{
    BlossomHttpTransport, delete_blossom_blob, fetch_history_blob, upload_blossom_blob,
};
use crate::{AppError, MarmotApp, QuorumCancelledDelivery, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::backup_writer";
/// The kind of the backup pointer: NIP-78 application data.
pub(crate) const KIND_BACKUP_POINTER: u64 = 30078;
/// A backup is due once the newest one listed is this old, in seconds.
const BACKUP_INTERVAL_SECS: u64 = 24 * 60 * 60;
/// A device takes over a writer that listed nothing for this long.
const TAKEOVER_AFTER_SECS: u64 = 7 * 24 * 60 * 60;
/// How long a backup whose pointer no relay accepted is published again.
const REPUBLISH_FOR_SECS: u64 = 24 * 60 * 60;
/// How long a condemned blob waits before its first delete, so it outlives
/// the pass that condemned it.
const DELETE_AFTER_SECS: u64 = 60 * 60;
/// The longest wait between deletes of one blob.
const MAX_DELETE_WAIT_SECS: u64 = 24 * 60 * 60;
/// How long a condemned blob's deletes are tried.
const DELETE_FOR_SECS: u64 = 7 * 24 * 60 * 60;
/// The first wait after a failed pass; each further failure doubles it, up
/// to [`MAX_PASS_RETRY_SECS`].
const PASS_RETRY_SECS: u64 = 60;
const MAX_PASS_RETRY_SECS: u64 = 60 * 60;
/// How many versions of the pointer a fetch reads. A relay keeps one; room
/// for a relay that keeps old versions to still answer in full.
const POINTER_FETCH_LIMIT: usize = 10;

fn pass_retry_at(now: u64, failed_passes: u64) -> u64 {
    now.saturating_add((PASS_RETRY_SECS << failed_passes.min(6)).min(MAX_PASS_RETRY_SECS))
}

fn delete_retry_at(now: u64, attempts: u64) -> u64 {
    now.saturating_add((DELETE_AFTER_SECS << attempts.min(5)).min(MAX_DELETE_WAIT_SECS))
}

fn backup_error(reason: &'static str) -> AppError {
    AppError::DeviceGroupRefused(reason)
}

/// The account's recovery key, and whether this device writes under it.
struct BackupRole {
    key: Vec<u8>,
    writes: bool,
}

/// A backup pass, prepared on the account worker by
/// [`AppClient::prepare_backup_pass`]. Running it fetches the pointer,
/// deletes, and writes off the worker; [`AppClient::finish_backup_pass`]
/// publishes the pointer it built.
pub(crate) struct BackupPass {
    app: MarmotApp,
    account_id_hex: String,
    storage: SqliteAccountStorage,
    key: Vec<u8>,
    /// What this device writes, while it is the writer and the deployment
    /// has a Blossom server.
    write: Option<BackupWrite>,
    started_at: u64,
    servers: Vec<String>,
    signer: Arc<dyn MarmotNostrSigner>,
    transport: BlossomHttpTransport,
    endpoints: Vec<TransportEndpoint>,
    allow_loopback_http: bool,
}

struct BackupWrite {
    writer: DeviceSlotId,
    chats: Vec<GroupId>,
}

/// What a [`BackupPass`] found and built, or why it stopped.
pub(crate) struct BackupPassOutcome {
    key: Vec<u8>,
    result: Result<PassReport, AppError>,
}

struct PassReport {
    /// When the newest backup the fetched pointer lists was written.
    newest: Option<u64>,
    /// The pointer to publish.
    pointer: Option<PendingPointer>,
}

/// A pointer listing run `run`, ready to sign.
struct PendingPointer {
    run: [u8; BACKUP_ID_LEN],
    written_at: u64,
    content: String,
    /// When the pointer it replaces was made, which it must postdate.
    replaces: u64,
}

impl BackupPass {
    pub(crate) async fn run(self) -> BackupPassOutcome {
        let result = self.pass().await;
        BackupPassOutcome {
            key: self.key,
            result,
        }
    }

    async fn pass(&self) -> Result<PassReport, AppError> {
        let (listed, replaces) = self.fetch_pointer().await?;
        self.delete_condemned(&listed).await;
        let newest = listed.first().map(|entry| entry.written_at);
        let Some(write) = &self.write else {
            return Ok(PassReport {
                newest,
                pointer: None,
            });
        };
        let storage = self.storage.app_storage();
        let now = unix_now_seconds();
        // A run the pointer lists counts already; one past its day is
        // abandoned, and the newest left is published again.
        let mut pending = None;
        for run in storage.backup_runs()? {
            let Some(head) = run.head else {
                continue;
            };
            if listed
                .iter()
                .any(|entry| entry.id == hex::encode(run.backup_id))
            {
                storage.finish_backup_run(&run.backup_id)?;
            } else if head.publish_until <= now {
                storage.abandon_backup_run(&run.backup_id, now, now + DELETE_AFTER_SECS)?;
            } else {
                let locator = BlobLocator {
                    sha256: head.sha256,
                    size: head.size,
                    server: head.server,
                };
                let entry = PointerEntry::new(&run.backup_id, run.written_at, locator);
                if let Some(older) = pending.replace((run.backup_id, entry)) {
                    storage.abandon_backup_run(&older.0, now, now + DELETE_AFTER_SECS)?;
                }
            }
        }
        let (entry, index) = match pending {
            Some((_, entry)) => (entry, None),
            None if newest.is_some_and(|at| now < at.saturating_add(BACKUP_INTERVAL_SECS)) => {
                return Ok(PassReport {
                    newest,
                    pointer: None,
                });
            }
            None => {
                let (entry, index) = self.write_backup(write, now).await?;
                (entry, Some(index))
            }
        };
        let pointer = self.listing(listed, replaces, entry, index, now).await?;
        Ok(PassReport {
            newest,
            pointer: Some(pointer),
        })
    }

    /// The backups the account's pointer under this key lists, newest first,
    /// and when that pointer was made: none, and zero, when no relay holds
    /// one. Refused unless a relay answered in full, since a pointer built
    /// from no answer would drop every backup, and when the newest pointer
    /// does not open.
    async fn fetch_pointer(&self) -> Result<(Vec<PointerEntry>, u64), AppError> {
        let address = backup_address(&self.key);
        let query = DirectoryEventQuery::address(
            KIND_BACKUP_POINTER,
            &self.account_id_hex,
            address.clone(),
            POINTER_FETCH_LIMIT,
        );
        let outcome = self
            .app
            .relay_plane
            .fetch_directory_events_with_completion(self.endpoints.clone(), vec![query])
            .await
            .map_err(|_| backup_error("backup_pointer_unavailable"))?;
        if outcome.complete_endpoints.is_empty() {
            return Err(backup_error("backup_pointer_unavailable"));
        }
        // Of two versions, the newer stands; on a tie, the lower id (NIP-01).
        let newest = outcome
            .records
            .into_iter()
            .map(|record| record.event)
            .filter(|event| {
                event.kind == KIND_BACKUP_POINTER
                    && event.pubkey == self.account_id_hex
                    && event.tag_values("d").contains(&address.as_str())
            })
            .max_by(|a, b| a.created_at.cmp(&b.created_at).then(b.id.cmp(&a.id)));
        let Some(event) = newest else {
            return Ok((Vec::new(), 0));
        };
        let backups = BackupPointer::open(&event.content, &self.key)?.backups;
        Ok((backups, event.created_at))
    }

    /// Delete each condemned blob whose delete is due, unless `listed`
    /// names its backup: then it is the pointer's again, and forgotten. A
    /// failed delete waits longer each time and is given up after a week.
    async fn delete_condemned(&self, listed: &[PointerEntry]) {
        let storage = self.storage.app_storage();
        let Ok(due) = storage.due_condemned_backup_blobs(&self.key, self.started_at) else {
            return;
        };
        let listed = listed
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut failed = 0_usize;
        for blob in due {
            let deleted = if listed.contains(hex::encode(blob.backup_id).as_str()) {
                true
            } else {
                delete_blossom_blob(
                    &blob.server,
                    &blob.sha256,
                    self.signer.as_ref(),
                    &self.transport,
                )
                .await
                .is_ok()
            };
            let now = unix_now_seconds();
            let settled = if deleted || now >= blob.condemned_at.saturating_add(DELETE_FOR_SECS) {
                storage.forget_condemned_backup_blob(&blob.sha256, &blob.server)
            } else {
                failed += 1;
                storage.defer_condemned_backup_blob(
                    &blob.sha256,
                    &blob.server,
                    delete_retry_at(now, blob.attempts),
                )
            };
            if settled.is_err() {
                break;
            }
        }
        if failed > 0 {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "delete_condemned",
                failed,
                "condemned backup blobs not deleted; retrying later"
            );
        }
    }

    /// Write a new backup at `now`: each chat's newest bundles, then the
    /// small state, then the head. Each blob is recorded in the run before
    /// it is uploaded, and the head's place once it is.
    async fn write_backup(
        &self,
        write: &BackupWrite,
        now: u64,
    ) -> Result<(PointerEntry, BackupIndex), AppError> {
        let storage = self.storage.app_storage();
        let id = new_backup_id();
        let archive_key = ArchiveKey::generate();
        storage.begin_backup_run(&id, &self.key, now)?;
        let mut index = BackupIndex::new(now, &write.writer);
        for chat in &write.chats {
            let mut after = self.newest_bundles_start(chat).await?;
            for _ in 0..MAX_BLOSSOM_BUNDLES {
                let Some(bundle) = self.export(chat, after.take()).await? else {
                    break;
                };
                let sealed = seal_backup_bundle(&archive_key, index.next_blob_number()?, &bundle)?;
                let server = self
                    .upload(&id, sealed.ciphertext.clone(), &sealed.sha256)
                    .await?;
                index.push_blob(chat.as_slice(), IndexBlob::new(&bundle, &sealed, server))?;
                after = Some(bundle.to);
            }
        }
        let items = {
            let storage = self.storage.app_storage();
            tokio::task::spawn_blocking(move || storage.small_state_items())
                .await
                .map_err(|_| AppError::BlockingTask("backup export failed".into()))??
        };
        if !items.is_empty() {
            let sealed = seal_backup_small_state(&archive_key, &items)?;
            let server = self
                .upload(&id, sealed.ciphertext.clone(), &sealed.sha256)
                .await?;
            index.small_state = Some(BlobLocator::new(&sealed, server));
        }
        let head = BackupHead::seal(id, &archive_key, &self.key, &index)?.encode();
        let sha256: [u8; 32] = Sha256::digest(&head).into();
        let size = head.len() as u64;
        let server = self.upload(&id, head, &sha256).await?;
        storage.record_backup_run_head(
            &id,
            &BackupRunHead {
                sha256: hex::encode(sha256),
                size,
                server: server.clone(),
                publish_until: now.saturating_add(REPUBLISH_FOR_SECS),
            },
        )?;
        let locator = BlobLocator {
            sha256: hex::encode(sha256),
            size,
            server,
        };
        Ok((PointerEntry::new(&id, now, locator), index))
    }

    /// Upload one blob of run `id` to the first server that takes it,
    /// recording it on each server before trying that server.
    async fn upload(
        &self,
        id: &[u8; BACKUP_ID_LEN],
        blob: Vec<u8>,
        sha256: &[u8; 32],
    ) -> Result<String, AppError> {
        let storage = self.storage.app_storage();
        let hash = hex::encode(sha256);
        let blob = Bytes::from(blob);
        let mut last = backup_error("backup_no_blossom");
        for server in &self.servers {
            storage.record_backup_run_blob(id, &hash, server)?;
            match upload_blossom_blob(
                server,
                blob.clone(),
                &hash,
                self.signer.as_ref(),
                &self.transport,
            )
            .await
            {
                Ok(_) => return Ok(server.clone()),
                Err(AppError::ExternalSignerRejected) => {
                    return Err(AppError::ExternalSignerRejected);
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    async fn newest_bundles_start(&self, chat: &GroupId) -> Result<Option<ChatPosition>, AppError> {
        let (storage, chat) = (self.storage.clone(), chat.clone());
        let allow_loopback_http = self.allow_loopback_http;
        tokio::task::spawn_blocking(move || {
            newest_bundles_start(
                &storage,
                &chat,
                &hex::encode(chat.as_slice()),
                HISTORY_BUNDLE_MAX_PLAINTEXT,
                MAX_BLOSSOM_BUNDLES,
                allow_loopback_http,
            )
        })
        .await
        .map_err(|_| AppError::BlockingTask("backup export failed".into()))?
    }

    async fn export(
        &self,
        chat: &GroupId,
        after: Option<ChatPosition>,
    ) -> Result<Option<crate::history_bundle::HistoryBundle>, AppError> {
        let (storage, chat) = (self.storage.clone(), chat.clone());
        let allow_loopback_http = self.allow_loopback_http;
        tokio::task::spawn_blocking(move || {
            Ok(export_history(
                &storage,
                &chat,
                &hex::encode(chat.as_slice()),
                after.as_ref(),
                HISTORY_BUNDLE_MAX_PLAINTEXT,
                allow_loopback_http,
            )?
            .map(|ExportedBundle { bundle, .. }| bundle))
        })
        .await
        .map_err(|_| AppError::BlockingTask("backup export failed".into()))?
    }

    /// The pointer listing `own` among `listed`, by retention at `now`, to
    /// replace the one made at `replaces`. The blobs of each backup it drops are condemned first: if the pointer
    /// never lands, the fetched one still lists them, and no delete touches
    /// a listed backup's blobs.
    async fn listing(
        &self,
        listed: Vec<PointerEntry>,
        replaces: u64,
        own: PointerEntry,
        own_index: Option<BackupIndex>,
        now: u64,
    ) -> Result<PendingPointer, AppError> {
        let mut backups = Vec::with_capacity(listed.len() + 1);
        for entry in listed.into_iter().filter(|entry| entry.id != own.id) {
            let index = self.read_index(&entry).await;
            backups.push(ListedBackup { entry, index });
        }
        let index = match own_index {
            Some(index) => Some(index),
            None => self.read_index(&own).await,
        };
        backups.push(ListedBackup {
            entry: own.clone(),
            index,
        });
        let (kept, dropped) = retain(backups, now);
        let storage = self.storage.app_storage();
        for backup in &dropped {
            let mut id = [0_u8; BACKUP_ID_LEN];
            hex::decode_to_slice(&backup.entry.id, &mut id)
                .map_err(|_| backup_error("backup_format"))?;
            let blobs = backup
                .locators()
                .into_iter()
                .map(|locator| (locator.sha256, locator.server))
                .collect::<Vec<_>>();
            storage.condemn_backup_blobs(&self.key, &id, &blobs, now, now + DELETE_AFTER_SECS)?;
        }
        let content = BackupPointer::new(kept.into_iter().map(|backup| backup.entry).collect())
            .seal(&self.key)?;
        let mut run = [0_u8; BACKUP_ID_LEN];
        hex::decode_to_slice(&own.id, &mut run).map_err(|_| backup_error("backup_format"))?;
        Ok(PendingPointer {
            run,
            written_at: own.written_at,
            content,
            replaces,
        })
    }

    /// The index of the backup `entry` lists, read from its head with the
    /// public half; none when the head cannot be fetched, is another
    /// backup's or does not open.
    async fn read_index(&self, entry: &PointerEntry) -> Option<BackupIndex> {
        let mut hash = [0_u8; 32];
        hex::decode_to_slice(&entry.head.sha256, &mut hash).ok()?;
        let bytes = fetch_history_blob(
            &entry.head.server,
            &hash,
            MAX_BACKUP_HEAD_BYTES as u64,
            &self.transport,
        )
        .await
        .ok()?;
        let head = BackupHead::decode(&bytes).ok()?;
        if hex::encode(head.id) != entry.id {
            return None;
        }
        head.open_index(&self.key).ok()
    }
}

impl MarmotApp {
    /// The relays the account's backup pointer goes to and is read from:
    /// its NIP-65 write relays, else the directory's.
    fn backup_pointer_endpoints(&self, account_id_hex: &str) -> Vec<TransportEndpoint> {
        self.outbox_endpoints(
            account_id_hex,
            self.directory().directory_source_relays(&[]),
        )
    }
}

impl AppClient {
    /// The account's recovery key and whether this device writes under it:
    /// the trusted roster's account entry, or with no device group the key
    /// this device keeps. None while backups are off.
    fn backup_role(&mut self) -> Result<Option<BackupRole>, AppError> {
        let Some((_, roster)) = self.trusted_device_roster()? else {
            let kept = self
                .app
                .account_storage(&self.state.label)?
                .app_storage()
                .kept_recovery_key()?;
            return Ok(kept.map(|key| BackupRole { key, writes: true }));
        };
        let Some(key) = roster.account.recovery_public_key else {
            return Ok(None);
        };
        Ok(Some(BackupRole {
            key,
            writes: roster.account.backup_writer == Some(self.own_slot()?),
        }))
    }

    /// The chats this device holds, never a device group, nor a chat whose
    /// MLS group id no bundle can name.
    fn backup_chats(&self) -> Result<Vec<GroupId>, AppError> {
        let mut chats = Vec::new();
        for group in &self.state.groups {
            if !is_chat_hex(&group.group_id_hex) {
                continue;
            }
            let Ok(bytes) = hex::decode(&group.group_id_hex) else {
                continue;
            };
            let chat = GroupId::new(bytes);
            if !self.is_device_group(&chat)? {
                chats.push(chat);
            }
        }
        Ok(chats)
    }

    /// The deployment's Blossom servers, in its order.
    fn backup_servers(&self) -> Vec<String> {
        let allow_loopback = self.app.allow_loopback_blob_endpoints();
        self.app
            .deployment()
            .new_group_media_endpoints
            .iter()
            .filter_map(|endpoint| blossom_server_for_endpoint(endpoint))
            .filter(|server| allow_loopback || !crate::media::is_loopback_http_endpoint(server))
            .fold(Vec::new(), |mut servers, server| {
                if !servers.contains(&server) {
                    servers.push(server);
                }
                servers
            })
    }

    /// The backup pass due now, ready to run off the worker. None while
    /// backups are off, device groups are, or nothing is due: no pass
    /// before its scheduled time unless a condemned blob's delete is due. A
    /// pass that cannot be prepared waits as a failed one does.
    pub(crate) fn prepare_backup_pass(&mut self) -> Result<Option<BackupPass>, AppError> {
        if self.runtime.maintenance_is_paused() || !self.app.device_groups_enabled() {
            return Ok(None);
        }
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        let schedule = storage.backup_schedule()?;
        let prepared = self.prepare_due_backup_pass(account.clone(), schedule);
        if prepared.is_err() {
            let now = unix_now_seconds();
            storage.schedule_backup_pass(BackupSchedule {
                next_pass_at: pass_retry_at(now, schedule.failed_passes),
                failed_passes: schedule.failed_passes.saturating_add(1),
            })?;
        }
        prepared
    }

    fn prepare_due_backup_pass(
        &mut self,
        account: SqliteAccountStorage,
        schedule: BackupSchedule,
    ) -> Result<Option<BackupPass>, AppError> {
        let storage = account.app_storage();
        let role = self.backup_role()?;
        storage.forget_backups_except(role.as_ref().map(|role| role.key.as_slice()))?;
        let Some(role) = role else {
            return Ok(None);
        };
        let now = unix_now_seconds();
        let deletes_due = storage
            .next_condemned_backup_try(&role.key)?
            .is_some_and(|at| at <= now);
        if schedule.next_pass_at > now && !deletes_due {
            return Ok(None);
        }
        // No pass is running, so a run without its head stopped short.
        for run in storage.backup_runs()? {
            if run.head.is_none() {
                storage.abandon_backup_run(&run.backup_id, now, now + DELETE_AFTER_SECS)?;
            }
        }
        let summary = self.app.account_home().account(&self.state.label)?;
        let signer = self.app.account_signer_for_summary(&summary)?;
        let servers = self.backup_servers();
        let write = if !role.writes {
            None
        } else if servers.is_empty() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "prepare_backup_pass",
                "no Blossom server for backups; none written"
            );
            None
        } else if marmot_session::seal_to_recovery_key(&role.key, &[], &[]).is_none() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "prepare_backup_pass",
                "recovery key seals nothing; no backup written"
            );
            None
        } else {
            Some(BackupWrite {
                writer: self.own_slot()?,
                chats: self.backup_chats()?,
            })
        };
        Ok(Some(BackupPass {
            app: self.app.clone(),
            endpoints: self.app.backup_pointer_endpoints(&summary.account_id_hex),
            account_id_hex: summary.account_id_hex,
            storage: account,
            key: role.key,
            write,
            started_at: now,
            servers,
            signer: signer.as_nostr_signer(),
            transport: self.blossom_http_transport.clone(),
            allow_loopback_http: self.app.allow_loopback_blob_endpoints(),
        }))
    }

    /// Publish the pointer a pass built, while this device still writes
    /// under its key, and schedule the next pass. A pass that failed, or
    /// whose pointer no relay accepted, waits longer each time; its run is
    /// published again by the next pass.
    pub(crate) async fn finish_backup_pass(&mut self, outcome: BackupPassOutcome) {
        let BackupPassOutcome { key, result } = outcome;
        let settled = match result {
            Ok(report) => self.settle_backup_pass(&key, report).await,
            Err(error) => Err(error),
        };
        let Ok(storage) = self.app.account_storage(&self.state.label) else {
            return;
        };
        let storage = storage.app_storage();
        let schedule = match settled {
            Ok(next_pass_at) => BackupSchedule {
                next_pass_at,
                failed_passes: 0,
            },
            Err(error) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "finish_backup_pass",
                    error_kind = error.privacy_safe_kind(),
                    "backup pass did not settle; retrying later"
                );
                let failed_passes = storage
                    .backup_schedule()
                    .map(|schedule| schedule.failed_passes)
                    .unwrap_or_default();
                BackupSchedule {
                    next_pass_at: pass_retry_at(unix_now_seconds(), failed_passes),
                    failed_passes: failed_passes.saturating_add(1),
                }
            }
        };
        let _ = storage.schedule_backup_pass(schedule);
    }

    /// Publish `report`'s pointer, or decide on a takeover; when the next
    /// pass is due.
    async fn settle_backup_pass(
        &mut self,
        key: &[u8],
        report: PassReport,
    ) -> Result<u64, AppError> {
        let now = unix_now_seconds();
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let role = self.backup_role()?.filter(|role| role.key == key);
        if let Some(pointer) = report.pointer {
            // New words, backups turned off or another writer since the
            // pass began: the pointer never goes out.
            if !role.as_ref().is_some_and(|role| role.writes) {
                storage.abandon_backup_run(&pointer.run, now, now + DELETE_AFTER_SECS)?;
                return Ok(now);
            }
            if !self
                .publish_backup_pointer(key, pointer.content, pointer.replaces)
                .await?
            {
                return Err(backup_error("backup_pointer_refused"));
            }
            storage.finish_backup_run(&pointer.run)?;
            return Ok(pointer.written_at.saturating_add(BACKUP_INTERVAL_SECS));
        }
        if role.as_ref().is_some_and(|role| role.writes) {
            return Ok(report
                .newest
                .map_or(now, |at| at.saturating_add(BACKUP_INTERVAL_SECS))
                .max(now.saturating_add(PASS_RETRY_SECS)));
        }
        if role.is_some() {
            self.take_over_a_quiet_writer(key, report.newest, now)
                .await?;
        }
        Ok(now.saturating_add(BACKUP_INTERVAL_SECS))
    }

    /// Sign the pointer with `content`, later than the one it `replaces`
    /// (NIP-01 keeps the newer), and publish it to the account's relays.
    /// Whether a relay accepted it; the others get it later.
    async fn publish_backup_pointer(
        &self,
        key: &[u8],
        content: String,
        replaces: u64,
    ) -> Result<bool, AppError> {
        let summary = self.app.account_home().account(&self.state.label)?;
        let signer = self
            .app
            .account_signer_for_summary(&summary)?
            .as_nostr_signer();
        let endpoints = self.app.backup_pointer_endpoints(&summary.account_id_hex);
        let event = self
            .app
            .sign_replaceable_identity_event(
                &self.state.label,
                signer.clone(),
                &NostrTransportEvent::new_unsigned_at(
                    summary.account_id_hex.clone(),
                    KIND_BACKUP_POINTER,
                    vec![vec!["d".to_owned(), backup_address(key)]],
                    content,
                    unix_now_seconds().max(replaces.saturating_add(1)),
                ),
            )
            .await?;
        let relay_client = self
            .app
            .relay_client_for_account_id(&summary.account_id_hex, signer);
        let Ok(outcome) = relay_client.publish_event(&endpoints, &event, 1).await else {
            return Ok(false);
        };
        let accepted = !outcome.accepted.is_empty();
        let mut completion = QuorumCancelledDelivery::new(
            relay_client,
            MemberId::new(hex::decode(&summary.account_id_hex)?),
        );
        completion.add(&event, &endpoints, &outcome);
        self.app.spawn_quorum_cancelled_delivery(completion);
        Ok(accepted)
    }

    /// Take over writing when the roster's writer under `key` listed
    /// nothing, by the newest backup listed at `newest`, for a week since
    /// this device first saw it named.
    async fn take_over_a_quiet_writer(
        &mut self,
        key: &[u8],
        newest: Option<u64>,
        now: u64,
    ) -> Result<(), AppError> {
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let entry = roster.account;
        let (Some(read_key), Some(writer)) = (&entry.recovery_public_key, entry.backup_writer)
        else {
            return Ok(());
        };
        if read_key != key || writer == self.own_slot()? {
            return Ok(());
        }
        let seen = self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .note_backup_writer(key, &writer, now)?;
        if now
            >= newest
                .unwrap_or(0)
                .max(seen)
                .saturating_add(TAKEOVER_AFTER_SECS)
        {
            self.take_over_backups(&group_id, entry).await?;
        }
        Ok(())
    }

    /// Take over writing the account's backups at once when the roster's
    /// writer has left the roster or is leaving, and note the writer it
    /// names, for the quiet-writer check a pass makes.
    pub(crate) async fn drive_backup_takeover(&mut self) {
        if let Err(error) = self.take_over_from_a_gone_writer().await {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drive_backup_takeover",
                error_kind = error.privacy_safe_kind(),
                "backup takeover not settled; retrying later"
            );
        }
    }

    async fn take_over_from_a_gone_writer(&mut self) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(());
        }
        let Some((group_id, roster)) = self.trusted_device_roster()? else {
            return Ok(());
        };
        let entry = roster.account.clone();
        let Some(key) = &entry.recovery_public_key else {
            return Ok(());
        };
        let writer = entry.backup_writer;
        if writer == Some(self.own_slot()?) {
            return Ok(());
        }
        if let Some(writer) = writer {
            self.app
                .account_storage(&self.state.label)?
                .app_storage()
                .note_backup_writer(key, &writer, unix_now_seconds())?;
        }
        let gone = writer.is_none_or(|writer| {
            roster
                .devices
                .get(&writer)
                .is_none_or(|device| device.status == DeviceStatusV1::Leaving)
        });
        if gone {
            self.take_over_backups(&group_id, entry).await?;
        }
        Ok(())
    }

    /// Commit this device as the backup writer over `read`, the account
    /// entry it read. Nothing goes out while the device group cannot take a
    /// commit from this device, or once the entry changed: of concurrent
    /// takeovers, the roster's compare-and-set keeps one.
    async fn take_over_backups(
        &mut self,
        group_id: &GroupId,
        read: AccountEntryV1,
    ) -> Result<(), AppError> {
        let held = self.epoch_gap_held_groups()?;
        if !self.runtime.device_group_takes_commit(group_id, &held)? {
            return Ok(());
        }
        let own = self.own_slot()?;
        let edit = self
            .runtime
            .edit_roster_account_entry(group_id, &held, |entry| {
                if *entry == read {
                    entry.backup_writer = Some(own);
                }
            })
            .await?;
        if let DeviceRosterEdit::Committed(effects) = edit
            && let Err(error) = self
                .observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                .await
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "take_over_backups",
                error_kind = error.privacy_safe_kind(),
                "backup takeover not confirmed; the runtime retries it"
            );
        }
        Ok(())
    }

    /// Run every due backup pass in place, as the account worker does off
    /// it. Test support only.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn drive_backup_pass(&mut self) {
        if let Ok(Some(pass)) = self.prepare_backup_pass() {
            let outcome = pass.run().await;
            self.finish_backup_pass(outcome).await;
        }
    }
}
