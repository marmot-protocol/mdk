//! Bounded per-chat health reads over the authoritative acquisition store.
use super::*;
use crate::{AccountAttachmentVersion, AttachmentHistoryEntry};

/// Runtime-effective policy for presentation; never persisted as new job authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentManagementPermission {
    pub automatic: bool,
    pub categories: [bool; 4],
}
fn apply_permission(
    status: &mut AttachmentTransferStatus,
    permission: AttachmentManagementPermission,
) {
    if active(status.state)
        && status.automatic_media_type.as_ref().is_some_and(|mime| {
            !permission.categories[AttachmentPermissionCategory::from_media_type(mime) as usize]
        })
    {
        status.state = AttachmentTransferState::Paused;
        status.retry_at = None;
    }
}

pub const ATTACHMENT_MANAGEMENT_PAGE_LIMIT: usize = 50;
pub const ATTACHMENT_MANAGEMENT_COUNT_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttachmentJobView {
    #[default]
    All,
    Active,
    NeedsAttention,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttachmentJobOrigin {
    #[default]
    Any,
    Automatic,
    Explicit,
}
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AttachmentJobQuery {
    pub group_id_hex: String,
    pub view: AttachmentJobView,
    pub origin: AttachmentJobOrigin,
}
impl AttachmentJobQuery {
    fn canonical(&self) -> StorageResult<Self> {
        let mut q = self.clone();
        if q.group_id_hex.is_empty()
            || q.group_id_hex.len() > 512
            || hex::decode(&q.group_id_hex).is_err()
        {
            return Err(invalid("invalid attachment health group"));
        }
        q.group_id_hex.make_ascii_lowercase();
        Ok(q)
    }
    fn accepts(&self, explicit: bool, state: AttachmentTransferState) -> bool {
        if state == AttachmentTransferState::Cancelled && self.origin != AttachmentJobOrigin::Any {
            return false;
        }
        (match self.origin {
            AttachmentJobOrigin::Any => true,
            AttachmentJobOrigin::Automatic => !explicit,
            AttachmentJobOrigin::Explicit => explicit,
        }) && match self.view {
            AttachmentJobView::All => true,
            AttachmentJobView::Active => active(state),
            AttachmentJobView::NeedsAttention => attention(state),
        }
    }
}
fn active(s: AttachmentTransferState) -> bool {
    matches!(
        s,
        AttachmentTransferState::Queued
            | AttachmentTransferState::Downloading
            | AttachmentTransferState::VerifyingCiphertext
            | AttachmentTransferState::Decrypting
            | AttachmentTransferState::VerifyingPlaintext
            | AttachmentTransferState::RetryScheduled
    )
}
fn attention(s: AttachmentTransferState) -> bool {
    matches!(
        s,
        AttachmentTransferState::Failed
            | AttachmentTransferState::RetryExhausted
            | AttachmentTransferState::PreviouslyAcquiredUnavailable
            | AttachmentTransferState::CompletedUnretained
    )
}
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentJobCursor {
    identity: Vec<u8>,
    query: AttachmentJobQuery,
    history: AccountAttachmentVersion,
    cutoff: i64,
    before: i64,
}
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentJobEntry {
    pub group_id_hex: String,
    pub source: AttachmentHistoryEntry,
    pub explicit: bool,
    pub status: AttachmentTransferStatus,
}
#[derive(Clone, Debug)]
pub struct AttachmentJobPage {
    pub entries: Vec<AttachmentJobEntry>,
    pub next_cursor: Option<AttachmentJobCursor>,
    pub history_version: AccountAttachmentVersion,
    pub observed_at: u64,
    pub next_expiry: Option<u64>,
}
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct AttachmentJobCounts {
    pub active: u32,
    pub needs_attention: u32,
    pub paused: u32,
    pub cancelled: u32,
    pub policy_blocked: u32,
    pub other: u32,
    /// False means these are lower bounds from at most1024 current job candidates.
    pub complete: bool,
}
macro_rules! private_formatter {
    ($($ty:ty),* $(,)?)=>{$(impl std::fmt::Debug for $ty {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct(stringify!($ty)).finish_non_exhaustive()}})*};
}
private_formatter!(AttachmentJobQuery, AttachmentJobCursor, AttachmentJobEntry,);

fn history(s: &SqliteAccountStorage, now: u64) -> StorageResult<AccountAttachmentVersion> {
    s.account_attachment_history_version_at(now)
        .map_err(|e| match e {
            crate::AccountAttachmentHistoryError::Storage(e) => e,
            _ => invalid("attachment management history unavailable"),
        })
}
fn current_row(conn: &Connection, group: &str) -> StorageResult<i64> {
    Ok(conn
        .query_row_cached(
            "SELECT rowid FROM attachment_acquisition INDEXED BY attachment_management_group_work
         WHERE group_id_hex=?1 AND management_ready=0 ORDER BY rowid DESC LIMIT 1",
            [group],
            |r| r.get(0),
        )
        .optional()
        .storage()?
        .unwrap_or(0))
}
/// The group partial index stores rowid as its implicit tie-breaker.
type Candidate = (i64, Vec<u8>, String, String, String, u32, bool);
fn candidates(
    conn: &Connection,
    group: &str,
    low: i64,
    high: i64,
    limit: usize,
) -> StorageResult<Vec<Candidate>> {
    conn.prepare_cached(
        "SELECT rowid,token,group_id_hex,message_id_hex,source_message_id_hex,attachment_index,explicit_request
         FROM attachment_acquisition INDEXED BY attachment_management_group_work
         WHERE group_id_hex=?4 AND management_ready=0 AND rowid>?1 AND rowid<=?2
         ORDER BY rowid DESC LIMIT ?3"
    ).storage()?.query_map(params![low,high,limit as i64,group], |r| {
        Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))
    }).storage()?.collect::<Result<Vec<_>,_>>().storage()
}

impl SqliteAccountStorage {
    /// Indexed live candidate paging, at most50 candidates plus lookahead. Empty filtered pages can continue.
    /// Cursors are process-local and privacy-fenced; state remains live and a head refresh shows newer work.
    pub fn attachment_jobs_page(
        &self,
        query: &AttachmentJobQuery,
        limit: usize,
        cursor: Option<&AttachmentJobCursor>,
        now: u64,
        permission: AttachmentManagementPermission,
    ) -> StorageResult<AttachmentJobPage> {
        if !(1..=ATTACHMENT_MANAGEMENT_PAGE_LIMIT).contains(&limit) {
            return Err(invalid("invalid attachment management limit"));
        }
        let query = query.canonical()?;
        self.connection.with_read_snapshot(|| {
            let h = history(self, now)?;
            let conn = self.lock()?;
            let identity = epoch(&conn)?;
            let (cutoff, before) = if let Some(c) = cursor {
                if c.identity != identity || c.query != query {
                    return Err(invalid("attachment management cursor mismatch"));
                }
                if h.requires_restart_since(&c.history) {
                    return Err(invalid("attachment management restart required"));
                }
                (c.cutoff, c.before)
            } else {
                let cutoff = current_row(&conn, &query.group_id_hex)?;
                (cutoff, cutoff.saturating_add(1))
            };
            let rows = candidates(
                &conn,
                &query.group_id_hex,
                0,
                cutoff.min(before - 1),
                limit + 1,
            )?;
            drop(conn);
            let more = rows.len() > limit;
            let mut entries = Vec::new();
            let mut last = before;
            let mut next_expiry = h.next_expiry;
            for (sequence, token, g, m, source, index, explicit) in rows.into_iter().take(limit) {
                last = sequence;
                let Some(entry) = self.attachment_control_entry(&g, &m, &source, index, now)?
                else {
                    continue;
                };
                let conn = self.lock()?;
                let Some(mut status) = super::controls::transfer_status(
                    &conn,
                    &identity,
                    &g,
                    (&m, &source, index),
                    now,
                    permission.automatic,
                    &mut next_expiry,
                )?
                else {
                    continue;
                };
                drop(conn);
                apply_permission(&mut status, permission);
                if status.reference.as_ref().is_none_or(|r| r.token != token)
                    || !query.accepts(explicit, status.state)
                {
                    continue;
                }
                entries.push(AttachmentJobEntry {
                    group_id_hex: g,
                    source: entry,
                    explicit,
                    status,
                });
            }
            Ok(AttachmentJobPage {
                entries,
                next_cursor: more.then(|| AttachmentJobCursor {
                    identity,
                    query,
                    history: h.clone(),
                    cutoff,
                    before: last,
                }),
                history_version: h,
                observed_at: now,
                next_expiry,
            })
        })
    }
    /// Bounded non-ready counts. Retained completed downloads are history, not unhealthy work.
    pub fn attachment_job_counts(
        &self,
        group: &str,
        now: u64,
        permission: AttachmentManagementPermission,
    ) -> StorageResult<AttachmentJobCounts> {
        let q = AttachmentJobQuery {
            group_id_hex: group.to_owned(),
            ..Default::default()
        }
        .canonical()?;
        self.connection.with_read_snapshot(|| {
            let conn = self.lock()?;
            let identity = epoch(&conn)?;
            // The materialized index seek fixes candidate work before privacy/source
            // joins. Stream rows rather than preparing four statements per candidate.
            let sql = format!("WITH candidates AS MATERIALIZED (
                SELECT * FROM attachment_acquisition INDEXED BY attachment_management_group_work
                WHERE management_ready=0 AND group_id_hex=?3 ORDER BY rowid DESC LIMIT ?1)
                SELECT {},CASE WHEN length(CAST(h.slot_json AS BLOB))<=16384 THEN h.slot_json ELSE '[]' END AS management_slot,
                h.visible=1 AND length(CAST(h.slot_json AS BLOB))<=16384 AND h.source_message_id_hex=q.source_message_id_hex
                AND h.source_epoch=q.source_epoch AND h.slot_json=q.slot_json
                AND g.pending_confirmation=0 AND a.message_id_hex IS NOT NULL AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?2) AS source_visible
                FROM candidates q
                LEFT JOIN attachment_history h ON h.group_id_hex=q.group_id_hex AND h.message_id_hex=q.message_id_hex AND h.attachment_index=q.attachment_index
                LEFT JOIN app_events a ON a.group_id_hex=q.group_id_hex AND a.message_id_hex=q.message_id_hex
                LEFT JOIN account_groups g ON g.group_id_hex=q.group_id_hex", super::controls::TRANSFER_STATUS_COLUMNS);
            let mut values = vec![rusqlite::types::Value::Integer((ATTACHMENT_MANAGEMENT_COUNT_LIMIT+1) as i64), rusqlite::types::Value::Integer(u64_to_i64(now)?)];
            values.push(q.group_id_hex.clone().into());
            let mut statement = conn.prepare_cached(&sql).storage()?;
            let mut rows = statement.query(rusqlite::params_from_iter(values)).storage()?;
            let mut visited = 0;
            let mut counts = AttachmentJobCounts { complete: true, ..Default::default() };
            while let Some(row) = rows.next().storage()? {
                visited += 1;
                if visited > ATTACHMENT_MANAGEMENT_COUNT_LIMIT { counts.complete=false; break; }
                if !row.get::<_,Option<bool>>("source_visible").storage()?.unwrap_or(false) { continue; }
                let slot: String = row.get("management_slot").storage()?;
                let mut status = super::controls::transfer_status_row(row, &identity, permission.automatic, &slot).storage()?;
                apply_permission(&mut status, permission);
                if active(status.state) { counts.active+=1; }
                else if attention(status.state) { counts.needs_attention+=1; }
                else { match status.state {
                    AttachmentTransferState::Paused => counts.paused+=1,
                    AttachmentTransferState::Cancelled => counts.cancelled+=1,
                    AttachmentTransferState::PolicyBlocked => counts.policy_blocked+=1,
                    _ => counts.other+=1,
                }}
            }
            Ok(counts)
        })
    }
}

/// Opaque replacement-frame generation; unrelated accounts never compare equal.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentManagementVersion {
    identity: Vec<u8>,
    history: AccountAttachmentVersion,
    query: AttachmentJobQuery,
    permission: AttachmentManagementPermission,
    available: bool,
    automatic_recovery_failed: Option<bool>,
    notices: Vec<([u8; 16], u64)>,
    notices_complete: bool,
    counts: AttachmentJobCounts,
    entries: Vec<AttachmentJobEntry>,
    next_cursor: Option<AttachmentJobCursor>,
    next_expiry: Option<u64>,
}
impl AttachmentManagementVersion {
    pub fn same_as(&self, other: &Self) -> bool {
        self == other
    }
    pub fn same_account(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}
private_formatter!(AttachmentManagementVersion);
pub struct AttachmentManagementFrame {
    pub available: bool,
    pub automatic_recovery_failed: Option<bool>,
    pub notices: Vec<crate::ParkedRecoveryObligation>,
    pub notices_complete: bool,
    pub counts: AttachmentJobCounts,
    pub page: AttachmentJobPage,
    pub version: AttachmentManagementVersion,
}
impl SqliteAccountStorage {
    /// One local snapshot; group-specific notices and account-wide notices remain separate.
    pub fn attachment_management_frame(
        &self,
        query: &AttachmentJobQuery,
        now: u64,
        permission: AttachmentManagementPermission,
    ) -> StorageResult<AttachmentManagementFrame> {
        let q = query.canonical()?;
        self.connection.with_read_snapshot(|| {
            let conn=self.lock()?;
            let available = conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM account_groups WHERE group_id_hex=?1 AND pending_confirmation=0)",
                [&q.group_id_hex], |r| r.get(0),
            ).storage()?;
            let identity=epoch(&conn)?;
            drop(conn);
            let group = hex::decode(&q.group_id_hex).map_err(|_|invalid("invalid health group"))?;
            let failure = if available { Some(self.automatic_recovery_failed(&cgka_traits::GroupId::new(group.clone()))?) } else { None };
            let (notices,notices_complete) = if available { self.bounded_parked_recovery_notices(Some(&group),50)? } else { (Vec::new(),true) };
            let counts = if available { self.attachment_job_counts(&q.group_id_hex,now,permission)? } else { AttachmentJobCounts::default() };
            let page=self.attachment_jobs_page(&q,50,None,now,permission)?;
            let version = AttachmentManagementVersion {
                identity,
                history: page.history_version.clone(),
                query: q,
                permission,
                available,
                automatic_recovery_failed: failure,
                notices: notices.iter().map(|n| (n.ticket.id, n.ticket.revision)).collect(),
                notices_complete,
                counts: counts.clone(),
                entries: page.entries.clone(),
                next_cursor: page.next_cursor.clone(),
                next_expiry: page.next_expiry,
            };
            Ok(AttachmentManagementFrame{available,automatic_recovery_failed:failure,notices,notices_complete,counts,page,version})
        })
    }
}
