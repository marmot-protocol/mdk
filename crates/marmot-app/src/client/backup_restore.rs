//! Manual history-only backup restore (mdk#2628 4.4c, D49/D71/D93).
//! Archive metadata never creates membership. Secrets belong to one ephemeral
//! operation; every content fetch/application checks the current own leaf.

use crate::AppError;
use bip39::{Language, Mnemonic};
use std::fmt;
use zeroize::Zeroizing;

/// Recovery words supplied for one manual restore. Ownership moves into MDK;
/// no Debug output or persistent operation record contains the words.
pub struct BackupRestoreWords(Zeroizing<String>);

impl BackupRestoreWords {
    pub fn new(words: String) -> Self {
        Self(Zeroizing::new(words))
    }
}

impl fmt::Debug for BackupRestoreWords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupRestoreWords").finish_non_exhaustive()
    }
}

/// An ephemeral operation identity, valid only within the current worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupRestoreId(pub(crate) [u8; 16]);

impl BackupRestoreId {
    /// Opaque host token for this ephemeral operation. It is not a recovery
    /// key, membership proof, or persistent resume cursor.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Decode the exact token returned by MDK. A syntactically valid stale
    /// token still cannot cancel another operation; the worker checks its id.
    pub fn from_hex(token: &str) -> Option<Self> {
        if token.len() != 32
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        Some(Self(hex::decode(token).ok()?.try_into().ok()?))
    }
}

/// No secret, event content, writer attribution or network endpoint is exposed
/// in restore progress. Completed prefix counts remain after cancellation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackupRestoreStatus {
    pub operation: Option<BackupRestoreId>,
    pub phase: BackupRestorePhase,
    pub imported_bundles: u64,
    pub imported_events: u64,
    pub failed_archives: u64,
    pub failed_bundles: u64,
    pub skipped_bundles: u64,
    /// Also changes when a real membership change may affect catalog hints.
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackupRestorePhase {
    #[default]
    Idle,
    Discovering,
    Restoring,
    Complete,
    Partial,
    Unavailable,
    Cancelled,
}

/// A backup may hold history for this currently joined chat. Public-key
/// identity distinguishes old words without retaining those words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupHistoryAvailability {
    pub recovery_public_key: [u8; 32],
    pub newest_written_at: u64,
    pub backups: u32,
}

/// Payload-free progress/availability wakeups from the owning account worker.
/// This handle owns no database lease, words or archive key.
pub struct BackupRestoreWatch {
    pub(crate) receiver: tokio::sync::watch::Receiver<BackupRestoreStatus>,
}

impl BackupRestoreWatch {
    pub fn snapshot(&self) -> BackupRestoreStatus {
        self.receiver.borrow().clone()
    }

    pub async fn changed(&mut self) -> Result<BackupRestoreStatus, AppError> {
        self.receiver
            .changed()
            .await
            .map_err(|_| AppError::TransportClosed)?;
        Ok(self.receiver.borrow_and_update().clone())
    }
}

fn restore_error(reason: &'static str) -> AppError {
    AppError::DeviceGroupRefused(reason)
}

fn recovery_entropy(words: BackupRestoreWords) -> Result<Zeroizing<[u8; 16]>, AppError> {
    // Bound the normalized copy by the actual English dictionary rather than
    // accepting an arbitrarily long host-provided token. Our owned phrase,
    // Mnemonic (bip39's zeroize feature) and returned entropy buffers zeroize.
    // bip39 2.2.2's internal parse/hash scratch and compiler/register copies
    // are outside that best-effort guarantee; do not promise blanket erasure.
    let max_word = Language::English
        .word_list()
        .iter()
        .map(|word| word.len())
        .max()
        .unwrap_or(0);
    let mut normalized = Zeroizing::new(String::with_capacity(max_word * 12 + 11));
    let mut count = 0;
    for word in words.0.split_whitespace() {
        count += 1;
        if count > 12
            || word.len() > max_word
            || !word.bytes().all(|byte| byte.is_ascii_alphabetic())
        {
            return Err(restore_error("backup_recovery_words"));
        }
        if count > 1 {
            normalized.push(' ');
        }
        for byte in word.bytes() {
            normalized.push(char::from(byte.to_ascii_lowercase()));
        }
    }
    if count != 12 {
        return Err(restore_error("backup_recovery_words"));
    }
    let mnemonic = Zeroizing::new(
        Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|_| restore_error("backup_recovery_words"))?,
    );
    // Twelve validated words encode exactly sixteen entropy bytes. Guard the
    // returned array directly rather than to_entropy's extra plain-array/Vec
    // copy, and keep only the fixed-size recovery-key input.
    let entropy = Zeroizing::new(mnemonic.to_entropy_array().0);
    let mut fixed = Zeroizing::new([0; 16]);
    fixed.copy_from_slice(&entropy[..16]);
    Ok(fixed)
}

use super::AppClient;
use crate::MarmotRelayPlane;
use crate::backup_archive::{
    ArchiveKey, BackupHead, BackupIndex, BlobLocator, IndexBlob, IndexChat, PointerEntry,
    open_backup_bundle,
};
use crate::history_bundle::HistoryBundle;
use crate::media::{BlossomHttpTransport, fetch_history_blob};
use cgka_traits::{GroupId, TransportEndpoint};
use std::collections::{BTreeMap, HashSet, VecDeque};
use storage_sqlite::{BackupHistorySource, BackupRestoreArchive, HistoryImportProvenance};
use tokio::sync::watch;

const TARGET: &str = "marmot_app::client::backup_restore";

fn completed_phase(status: &BackupRestoreStatus, discovery_complete: bool) -> BackupRestorePhase {
    if !discovery_complete
        || status.failed_archives > 0
        || status.failed_bundles > 0
        || status.skipped_bundles > 0
    {
        BackupRestorePhase::Partial
    } else {
        BackupRestorePhase::Complete
    }
}

pub(crate) struct BackupRestore {
    status: BackupRestoreStatus,
    updates: watch::Sender<BackupRestoreStatus>,
    job: Option<RestoreJob>,
    pub(super) availability_changed: bool,
}

impl Default for BackupRestore {
    fn default() -> Self {
        let status = BackupRestoreStatus::default();
        let (updates, _) = watch::channel(status.clone());
        Self {
            status,
            updates,
            job: None,
            availability_changed: false,
        }
    }
}

impl BackupRestore {
    /// Whether a restore was requested and waits for a dispatch slot
    /// (mdk#2923).
    pub(crate) fn waiting(&self) -> bool {
        self.job.is_some()
    }

    fn publish(&mut self) {
        self.status.revision = self.status.revision.wrapping_add(1);
        self.updates.send_replace(self.status.clone());
    }
}

// Intentionally no Debug/Clone: only one operation owns words' entropy and
// the archive key. Dropping its sender cancels any media future in flight.
struct RestoreJob {
    id: BackupRestoreId,
    entropy: Zeroizing<[u8; 16]>,
    public_key: [u8; 32],
    discovering: bool,
    discovery_complete: bool,
    pending: VecDeque<PointerEntry>,
    current: Option<RestoreArchive>,
    cancellation: watch::Sender<()>,
}

struct RestoreArchive {
    source: BackupHistorySource,
    key: Option<ArchiveKey>,
    blobs: VecDeque<RestoreBlob>,
}

struct RestoreBlob {
    number: u32,
    chat: GroupId,
    chat_hex: String,
    blob: IndexBlob,
}

/// Number before filtering: a later eligible chat never becomes blob zero.
fn plan_blobs(index: &BackupIndex, members: &HashSet<GroupId>, now: u64) -> VecDeque<RestoreBlob> {
    index
        .blobs()
        .filter_map(|(number, chat, blob)| {
            let group = GroupId::new(hex::decode(&chat.chat).ok()?);
            (members.contains(&group) && blob.expires.is_none_or(|at| at > now)).then(|| {
                RestoreBlob {
                    number,
                    chat: group,
                    chat_hex: chat.chat.clone(),
                    blob: blob.clone(),
                }
            })
        })
        .collect()
}

pub(crate) struct BackupRestoreWork {
    id: BackupRestoreId,
    cancellation: watch::Receiver<()>,
    transport: BlossomHttpTransport,
    kind: RestoreWorkKind,
}

enum RestoreWorkKind {
    Discover {
        plane: MarmotRelayPlane,
        endpoints: Vec<TransportEndpoint>,
        account: String,
        key: [u8; 32],
    },
    Head {
        entry: PointerEntry,
        key: [u8; 32],
    },
    Blob {
        item: RestoreBlob,
        key: ArchiveKey,
    },
}

pub(crate) struct BackupRestoreOutcome {
    id: BackupRestoreId,
    kind: RestoreDone,
}

enum RestoreDone {
    Discover(Result<super::backup_writer::BackupPointerDiscovery, AppError>),
    Head {
        entry: PointerEntry,
        result: Result<OpenedHead, AppError>,
    },
    Blob {
        item: RestoreBlob,
        key: Option<ArchiveKey>,
        result: Result<HistoryBundle, AppError>,
    },
    Cancelled,
}

struct OpenedHead {
    index: BackupIndex,
    context: Vec<u8>,
    sealed_key: Vec<u8>,
}

async fn read_locator(
    locator: &BlobLocator,
    transport: &BlossomHttpTransport,
) -> Result<Vec<u8>, AppError> {
    let hash: [u8; 32] = hex::decode(&locator.sha256)?
        .try_into()
        .map_err(|_| restore_error("backup_format"))?;
    let bytes = fetch_history_blob(&locator.server, &hash, locator.size, transport).await?;
    if bytes.len() as u64 != locator.size {
        return Err(restore_error("backup_blob_size"));
    }
    Ok(bytes)
}

impl BackupRestoreWork {
    /// One media credit covers the network, bounded decode and queued result.
    /// A cancelled job/worker drops the HTTP future and its ephemeral key;
    /// blocking crypto holds no account/database lease and is size-bounded.
    pub(crate) async fn run(mut self) -> BackupRestoreOutcome {
        let id = self.id;
        let kind = tokio::select! {
            biased;
            _=self.cancellation.changed()=>RestoreDone::Cancelled,
            done=Self::run_kind(self.kind,self.transport)=>done,
        };
        BackupRestoreOutcome { id, kind }
    }

    async fn run_kind(kind: RestoreWorkKind, transport: BlossomHttpTransport) -> RestoreDone {
        match kind {
            RestoreWorkKind::Discover {
                plane,
                endpoints,
                account,
                key,
            } => RestoreDone::Discover(
                super::backup_writer::read_backup_pointer_discovery(
                    &plane, &endpoints, &account, &key,
                )
                .await,
            ),
            RestoreWorkKind::Head { entry, key } => {
                let result = match read_locator(&entry.head, &transport).await {
                    Err(error) => Err(error),
                    Ok(bytes) => {
                        let expected = entry.clone();
                        tokio::task::spawn_blocking(move || {
                            let head = BackupHead::decode(&bytes)?;
                            if hex::encode(head.id) != expected.id {
                                return Err(restore_error("backup_head_id"));
                            }
                            let index = head.open_index(&key)?;
                            if index.written_at != expected.written_at {
                                return Err(restore_error("backup_written_at"));
                            }
                            let (context, sealed) = head.sealed_archive_key();
                            Ok(OpenedHead {
                                index,
                                context,
                                sealed_key: sealed.to_vec(),
                            })
                        })
                        .await
                        .map_err(|_| AppError::BlockingTask("backup head task failed".into()))
                        .and_then(|result| result)
                    }
                };
                RestoreDone::Head { entry, result }
            }
            RestoreWorkKind::Blob { item, key } => {
                let ciphertext = match read_locator(&item.blob.locator(), &transport).await {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return RestoreDone::Blob {
                            item,
                            key: Some(key),
                            result: Err(error),
                        };
                    }
                };
                // Only this blob's tiny index entry is copied, never a whole
                // chat's blob vector for each selected blob.
                let chat = IndexChat {
                    chat: item.chat_hex.clone(),
                    blobs: Vec::new(),
                };
                let blob = item.blob.clone();
                let number = item.number;
                match tokio::task::spawn_blocking(move || {
                    let result = open_backup_bundle(&key, number, &chat, &blob, &ciphertext);
                    (key, result)
                })
                .await
                {
                    Ok((key, result)) => RestoreDone::Blob {
                        item,
                        key: Some(key),
                        result,
                    },
                    Err(_) => RestoreDone::Blob {
                        item,
                        key: None,
                        result: Err(AppError::BlockingTask("backup blob task failed".into())),
                    },
                }
            }
        }
    }
}

impl AppClient {
    pub(crate) fn begin_backup_restore(
        &mut self,
        words: BackupRestoreWords,
    ) -> Result<BackupRestoreStatus, AppError> {
        if !self.app.device_groups_enabled() {
            return Err(restore_error("roster_unsupported"));
        }
        if self.backup_restore.job.is_some() {
            return Err(restore_error("backup_restore_busy"));
        }
        let entropy = recovery_entropy(words)?;
        let public_key: [u8; 32] = self
            .runtime
            .recovery_public_key(&entropy)?
            .try_into()
            .map_err(|_| restore_error("backup_recovery_key"))?;
        let id = BackupRestoreId(crate::backup_archive::new_backup_id());
        let (cancellation, _) = watch::channel(());
        self.backup_restore.job = Some(RestoreJob {
            id,
            entropy,
            public_key,
            discovering: true,
            discovery_complete: false,
            pending: VecDeque::new(),
            current: None,
            cancellation,
        });
        let revision = self.backup_restore.status.revision;
        self.backup_restore.status = BackupRestoreStatus {
            operation: Some(id),
            phase: BackupRestorePhase::Discovering,
            revision,
            ..Default::default()
        };
        self.backup_restore.publish();
        Ok(self.backup_restore.status.clone())
    }

    pub(crate) fn cancel_backup_restore(&mut self, id: BackupRestoreId) -> bool {
        if !self
            .backup_restore
            .job
            .as_ref()
            .is_some_and(|job| job.id == id)
        {
            return false;
        }
        self.backup_restore.job = None;
        self.backup_restore.status.phase = BackupRestorePhase::Cancelled;
        self.backup_restore.publish();
        true
    }

    pub(crate) fn backup_restore_status(&self) -> BackupRestoreStatus {
        self.backup_restore.status.clone()
    }

    pub(crate) fn watch_backup_restore(&self) -> BackupRestoreWatch {
        BackupRestoreWatch {
            receiver: self.backup_restore.updates.subscribe(),
        }
    }

    /// No account projection or other device's account membership proves this
    /// device is in the selected tree. A failed read is never permission.
    fn restore_chat_is_member(&mut self, chat: &GroupId) -> bool {
        let hex = hex::encode(chat.as_slice());
        if !self
            .state
            .groups
            .iter()
            .any(|group| group.group_id_hex == hex)
            || self.skips_quarantined_group_reads(chat)
            || self.is_device_group(chat).ok() != Some(false)
        {
            return false;
        }
        // Catalog ids alone never create a native group. Hydrate only a
        // known held, nonterminal ordinary chat through the existing owner.
        let Ok(Some(stored)) = self.stored_group(chat) else {
            return false;
        };
        if stored.removed
            || stored.disbanded.is_some()
            || stored.unrecoverable
            || self.runtime.ensure_group_hydrated(chat).is_err()
        {
            return false;
        }
        let Ok(record) = self.runtime.group_record(chat) else {
            return false;
        };
        if record.removed || record.disbanded.is_some() || record.unrecoverable {
            return false;
        }
        // OpenMLS retains an own-leaf index even on an inactive removed
        // copy. Match this device's MLS signature key in the selected member
        // set instead of treating that index or account membership as proof.
        let own = self.runtime.own_signature_key();
        self.runtime
            .members(chat)
            .is_ok_and(|members| members.iter().any(|member| member.credential == own))
    }

    pub(crate) fn backup_history_availability(
        &mut self,
        chat: &GroupId,
    ) -> Result<Vec<BackupHistoryAvailability>, AppError> {
        if !self.app.device_groups_enabled() || !self.restore_chat_is_member(chat) {
            return Ok(Vec::new());
        }
        let mut by_key = BTreeMap::<[u8; 32], BackupHistoryAvailability>::new();
        for archive in self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .backup_restore_archives_for_chat(chat)?
        {
            let found = by_key.entry(archive.source.recovery_public_key).or_insert(
                BackupHistoryAvailability {
                    recovery_public_key: archive.source.recovery_public_key,
                    newest_written_at: 0,
                    backups: 0,
                },
            );
            found.newest_written_at = found.newest_written_at.max(archive.source.written_at);
            found.backups = found.backups.saturating_add(1);
        }
        Ok(by_key.into_values().collect())
    }

    /// Complete content-id provenance for a held ordinary chat. Unlike the
    /// legacy sibling-only timeline field, this identifies backup imports.
    pub(crate) fn history_import_provenance(
        &self,
        chat: &GroupId,
        event_id: &str,
    ) -> Result<Option<storage_sqlite::HistoryImportProvenance>, AppError> {
        let group = self.history_chat(chat)?;
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .app_event_import_provenance(&group, event_id)?)
    }

    /// Flush after the worker's projection boundary, including real joins.
    /// No retained-chat/MLS scan occurs just to publish a wakeup.
    pub(crate) fn publish_backup_restore_availability(&mut self) {
        if self.backup_restore.availability_changed {
            self.backup_restore.availability_changed = false;
            self.backup_restore.publish();
        }
    }

    pub(crate) fn prepare_backup_restore(&mut self) -> Result<Option<BackupRestoreWork>, AppError> {
        let result = self.try_prepare_backup_restore();
        if result.is_err() {
            self.backup_restore.job = None;
            self.backup_restore.status.phase = BackupRestorePhase::Unavailable;
            self.backup_restore.publish();
        }
        result
    }

    fn try_prepare_backup_restore(&mut self) -> Result<Option<BackupRestoreWork>, AppError> {
        let Some(mut job) = self.backup_restore.job.take() else {
            return Ok(None);
        };
        let kind = if job.discovering {
            let account = self.app.account_home().account(&self.state.label)?;
            job.discovering = false;
            Some(RestoreWorkKind::Discover {
                plane: self.app.relay_plane.clone(),
                endpoints: self.app.backup_pointer_endpoints(&account.account_id_hex),
                account: account.account_id_hex,
                key: job.public_key,
            })
        } else {
            loop {
                if let Some(current) = job.current.as_mut() {
                    if let Some(item) = current.blobs.pop_front() {
                        if !self.restore_chat_is_member(&item.chat) {
                            self.backup_restore.status.skipped_bundles =
                                self.backup_restore.status.skipped_bundles.saturating_add(1);
                            continue;
                        }
                        let Some(key) = current.key.take() else {
                            return Err(restore_error("backup_restore_key"));
                        };
                        break Some(RestoreWorkKind::Blob { item, key });
                    }
                    job.current = None;
                }
                match job.pending.pop_front() {
                    Some(entry) => {
                        break Some(RestoreWorkKind::Head {
                            entry,
                            key: job.public_key,
                        });
                    }
                    None => break None,
                }
            }
        };
        let Some(kind) = kind else {
            self.backup_restore.status.phase =
                completed_phase(&self.backup_restore.status, job.discovery_complete);
            self.backup_restore.publish();
            return Ok(None);
        };
        let work = BackupRestoreWork {
            id: job.id,
            cancellation: job.cancellation.subscribe(),
            transport: self.blossom_http_transport.clone(),
            kind,
        };
        self.backup_restore.job = Some(job);
        Ok(Some(work))
    }

    pub(crate) fn finish_backup_restore(&mut self, outcome: BackupRestoreOutcome) {
        if !self
            .backup_restore
            .job
            .as_ref()
            .is_some_and(|job| job.id == outcome.id)
        {
            return;
        }
        let mut job = self
            .backup_restore
            .job
            .take()
            .expect("matching restore job");
        match outcome.kind {
            RestoreDone::Discover(Ok(discovery)) => {
                // A partial empty view cannot prove absence. Keep the private
                // catalog and release the ephemeral secrets for manual retry.
                if !discovery.complete && discovery.created_at.is_none() {
                    self.backup_restore.status.phase = BackupRestorePhase::Unavailable;
                    self.backup_restore.publish();
                    return;
                }
                job.discovery_complete = discovery.complete;
                let entries = discovery.entries;
                let listed = entries
                    .iter()
                    .map(|entry| {
                        hex::decode(&entry.id)
                            .ok()
                            .and_then(|bytes| bytes.try_into().ok())
                    })
                    .collect::<Option<Vec<[u8; 16]>>>();
                let result = listed
                    .ok_or_else(|| restore_error("backup_format"))
                    .and_then(|listed| {
                        if !discovery.complete {
                            return Ok(());
                        }
                        self.app
                            .account_storage(&self.state.label)?
                            .app_storage()
                            .retain_backup_restore_archives(&job.public_key, &listed)
                            .map_err(AppError::from)
                    });
                if let Err(error) = result {
                    self.restore_failure(&error);
                    self.backup_restore.status.phase = BackupRestorePhase::Unavailable;
                    self.backup_restore.publish();
                    return;
                }
                job.pending = entries.into();
                self.backup_restore.status.phase = BackupRestorePhase::Restoring;
            }
            RestoreDone::Discover(Err(error)) => {
                self.restore_failure(&error);
                self.backup_restore.status.phase = BackupRestorePhase::Unavailable;
                self.backup_restore.publish();
                return;
            }
            RestoreDone::Head { entry, result } => {
                let result = result.and_then(|head| self.accept_restore_head(&job, &entry, head));
                match result {
                    Ok(current) => job.current = current,
                    Err(error) => {
                        self.restore_failure(&error);
                        self.backup_restore.status.failed_archives =
                            self.backup_restore.status.failed_archives.saturating_add(1);
                    }
                }
            }
            RestoreDone::Blob { item, key, result } => {
                if let Some(current) = job.current.as_mut() {
                    current.key = key;
                }
                let result = if self.restore_chat_is_member(&item.chat) {
                    result.and_then(|bundle| {
                        let source = job
                            .current
                            .as_ref()
                            .ok_or_else(|| restore_error("backup_restore_key"))?
                            .source
                            .clone();
                        self.import_plaintext_history_bundle(
                            &item.chat,
                            &HistoryImportProvenance::Backup(source),
                            bundle,
                        )
                    })
                } else {
                    self.backup_restore.status.skipped_bundles =
                        self.backup_restore.status.skipped_bundles.saturating_add(1);
                    self.resume_or_finish_backup_restore(job);
                    return;
                };
                match result {
                    Ok((count, update)) => {
                        self.backup_restore.status.imported_bundles = self
                            .backup_restore
                            .status
                            .imported_bundles
                            .saturating_add(1);
                        self.backup_restore.status.imported_events = self
                            .backup_restore
                            .status
                            .imported_events
                            .saturating_add(count as u64);
                        if let Some(update) = update {
                            self.pending_projection_updates.push(update);
                        }
                    }
                    Err(error) => {
                        self.restore_failure(&error);
                        self.backup_restore.status.failed_bundles =
                            self.backup_restore.status.failed_bundles.saturating_add(1);
                    }
                }
                if job
                    .current
                    .as_ref()
                    .is_some_and(|current| current.key.is_none())
                {
                    job.current = None;
                }
            }
            RestoreDone::Cancelled => return,
        }
        self.resume_or_finish_backup_restore(job);
    }

    fn resume_or_finish_backup_restore(&mut self, job: RestoreJob) {
        if !job.discovering
            && job.pending.is_empty()
            && job
                .current
                .as_ref()
                .is_none_or(|current| current.blobs.is_empty())
        {
            // All content is settled: do not retain secrets until another
            // media credit happens to become available for prepare(None).
            self.backup_restore.status.phase =
                completed_phase(&self.backup_restore.status, job.discovery_complete);
            drop(job);
        } else {
            self.backup_restore.job = Some(job);
        }
        self.backup_restore.publish();
    }

    fn accept_restore_head(
        &mut self,
        job: &RestoreJob,
        entry: &PointerEntry,
        head: OpenedHead,
    ) -> Result<Option<RestoreArchive>, AppError> {
        let source = BackupHistorySource {
            recovery_public_key: job.public_key,
            backup_id: hex::decode(&entry.id)?
                .try_into()
                .map_err(|_| restore_error("backup_format"))?,
            head_sha256: hex::decode(&entry.head.sha256)?
                .try_into()
                .map_err(|_| restore_error("backup_format"))?,
            written_at: head.index.written_at,
        };
        let chats = head
            .index
            .chats
            .iter()
            .map(|chat| hex::decode(&chat.chat).map(GroupId::new))
            .collect::<Result<Vec<_>, _>>()?;
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .put_backup_restore_archive(
                &BackupRestoreArchive {
                    source: source.clone(),
                    head_server: entry.head.server.clone(),
                    head_size: entry.head.size,
                },
                &chats,
            )?;
        self.backup_restore.availability_changed = true;
        let now = crate::unix_now_seconds();
        let mut members = HashSet::new();
        for (chat, entry) in chats.into_iter().zip(&head.index.chats) {
            if self.restore_chat_is_member(&chat) {
                members.insert(chat);
            } else if self
                .state
                .groups
                .iter()
                .any(|group| group.group_id_hex == entry.chat)
            {
                // Unknown catalog-only chats are outside this history-only
                // operation. A held candidate we cannot read/admit is a skip,
                // never a silently successful empty restore.
                let skipped = entry
                    .blobs
                    .iter()
                    .filter(|blob| blob.expires.is_none_or(|at| at > now))
                    .count();
                self.backup_restore.status.skipped_bundles = self
                    .backup_restore
                    .status
                    .skipped_bundles
                    .saturating_add(skipped as u64);
            }
        }
        let blobs = plan_blobs(&head.index, &members, now);
        if blobs.is_empty() {
            return Ok(None);
        }
        let opened = self
            .runtime
            .open_with_recovery_key(&job.entropy, &head.context, &head.sealed_key)?
            .map(Zeroizing::new)
            .ok_or_else(|| restore_error("backup_archive_key"))?;
        let key =
            ArchiveKey::from_opened(&opened).ok_or_else(|| restore_error("backup_archive_key"))?;
        Ok(Some(RestoreArchive {
            source,
            key: Some(key),
            blobs,
        }))
    }

    fn restore_failure(&self, error: &AppError) {
        tracing::warn!(
            target: TARGET,
            method = "backup_restore",
            error_kind = error.privacy_safe_kind(),
            "backup restore step failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_archive::{IndexBlob, seal_backup_bundle};
    use crate::history_bundle::{BundledEvent, ChatPosition};
    use cgka_traits::MarmotAppEvent;

    #[test]
    fn restore_operation_tokens_have_an_exact_bounded_host_codec() {
        let token = "ab".repeat(16);
        assert_eq!(BackupRestoreId([0xab; 16]).to_hex(), token);
        assert_eq!(
            BackupRestoreId::from_hex(&token),
            Some(BackupRestoreId([0xab; 16]))
        );
        for invalid in [
            String::new(),
            "ab".repeat(15),
            "ab".repeat(17),
            "AB".repeat(16),
            "zz".repeat(16),
            format!(" {token}"),
        ] {
            assert_eq!(BackupRestoreId::from_hex(&invalid), None);
        }
    }

    #[test]
    fn recovery_input_is_redacted_and_only_twelve_checksum_valid_english_words_open() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let input = BackupRestoreWords::new(words.to_uppercase());
        let debug = format!("{input:?}");
        assert!(!debug.to_lowercase().contains("abandon"));
        assert_eq!(*recovery_entropy(input).unwrap(), [0; 16]);
        assert_eq!(
            *recovery_entropy(BackupRestoreWords::new(
                "  LEGAL\twinner thank year wave sausage worth useful legal winner thank YELLOW\n"
                    .into()
            ))
            .unwrap(),
            [0x7f; 16],
            "the published nonzero 128-bit vector keeps the input case/whitespace contract"
        );
        for bad in [
            "abandon".repeat(12),
            words.replace("about", "abandon"),
            words
                .split_whitespace()
                .take(11)
                .collect::<Vec<_>>()
                .join(" "),
            words.replace("about", "notaword"),
            words.replace("about", "ábout"),
            format!("{words} about"),
        ] {
            assert!(matches!(
                recovery_entropy(BackupRestoreWords::new(bad)),
                Err(AppError::DeviceGroupRefused("backup_recovery_words"))
            ));
        }
    }

    /// The restore planner, not crypto itself, owns filtering. A genuine
    /// two-chat archive makes renumbering the eligible second chat fail AEAD.
    #[test]
    fn filtering_restore_chats_preserves_the_global_blob_number() {
        let key = ArchiveKey::generate();
        let mut index = BackupIndex::new(50, &[7; 32]);
        let chats = [GroupId::new(vec![1; 16]), GroupId::new(vec![2; 16])];
        let mut ciphertexts = Vec::new();
        for (number, chat) in chats.iter().enumerate() {
            let event = MarmotAppEvent::new(
                "aa".repeat(32),
                10,
                9,
                Vec::new(),
                format!("history {number}"),
            );
            let position = ChatPosition::of(&event, 0);
            let mut bundle = HistoryBundle::new(chat.as_slice(), position.clone(), position);
            bundle.events.push(BundledEvent {
                event,
                epoch: 0,
                retention: None,
                grant: None,
                keys: None,
            });
            let sealed = seal_backup_bundle(&key, number as u32, &bundle).unwrap();
            index
                .push_blob(
                    chat.as_slice(),
                    IndexBlob::new(&bundle, &sealed, "https://blossom.example".into()),
                )
                .unwrap();
            ciphertexts.push(sealed.ciphertext);
        }
        let selected_membership = plan_blobs(&index, &HashSet::from([chats[1].clone()]), 0);
        assert_eq!(selected_membership.len(), 1);
        assert_eq!(selected_membership[0].number, 1);
        index.chats[0].blobs[0].expires = Some(50);
        let mut selected = plan_blobs(&index, &HashSet::from(chats.clone()), 50);
        assert_eq!(selected.len(), 1, "an all-expired blob is not fetched");
        let item = selected.pop_front().unwrap();
        let opened = open_backup_bundle(
            &key,
            item.number,
            &IndexChat {
                chat: item.chat_hex,
                blobs: Vec::new(),
            },
            &item.blob,
            &ciphertexts[1],
        )
        .unwrap();
        assert_eq!(opened.events[0].event.content, "history 1");
    }
}
