//! Source-bound, bounded management over the authoritative acquisition store.
use super::*;
use crate::{AccountAttachmentVersion, AttachmentHistoryEntry};

pub const ATTACHMENT_MANAGEMENT_PAGE_LIMIT: usize = 50;
pub const ATTACHMENT_MANAGEMENT_COUNT_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttachmentJobView {
    #[default]
    All,
    Active,
    NeedsAttention,
    Ready,
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
    pub group_id_hex: Option<String>,
    pub view: AttachmentJobView,
    pub origin: AttachmentJobOrigin,
}
impl AttachmentJobQuery {
    fn canonical(&self) -> StorageResult<Self> {
        let mut q = self.clone();
        if let Some(g) = &mut q.group_id_hex {
            if g.is_empty() || g.len() > 512 || hex::decode(&*g).is_err() {
                return Err(invalid("invalid attachment management group"));
            }
            g.make_ascii_lowercase();
        }
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
            AttachmentJobView::Ready => state == AttachmentTransferState::Ready,
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
/// Stable observed categories; an opaque transport error is never diagnosed as a network cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentFailureCategory {
    None,
    UnclassifiedFailure,
    RetryExhausted,
    RetainedBytesUnavailable,
    CompletedWithoutRetention,
    PolicyBlocked,
}
impl AttachmentFailureCategory {
    pub fn from_state(s: AttachmentTransferState) -> Self {
        match s {
            AttachmentTransferState::Failed => Self::UnclassifiedFailure,
            AttachmentTransferState::RetryExhausted => Self::RetryExhausted,
            AttachmentTransferState::PreviouslyAcquiredUnavailable => {
                Self::RetainedBytesUnavailable
            }
            AttachmentTransferState::CompletedUnretained => Self::CompletedWithoutRetention,
            AttachmentTransferState::PolicyBlocked => Self::PolicyBlocked,
            _ => Self::None,
        }
    }
}
#[derive(Clone)]
pub struct AttachmentJobCursor {
    identity: Vec<u8>,
    query: AttachmentJobQuery,
    history: AccountAttachmentVersion,
    cutoff: i64,
    before: i64,
}
#[derive(Clone)]
pub struct AttachmentJobActionToken {
    reference: AttachmentAssetRef,
    sequence: i64,
}
#[derive(Clone)]
pub struct AttachmentJobEntry {
    pub group_id_hex: String,
    pub source: AttachmentHistoryEntry,
    pub explicit: bool,
    /// Cancellation clears old explicit intent in the authoritative store.
    pub origin_known: bool,
    pub status: AttachmentTransferStatus,
    pub action: AttachmentJobActionToken,
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
    pub ready: u32,
    pub paused: u32,
    pub cancelled: u32,
    pub policy_blocked: u32,
    pub other: u32,
    /// False means these are lower bounds from at most1024 current job candidates.
    pub complete: bool,
}
#[derive(Clone)]
pub struct AttachmentCancellationCursor {
    identity: Vec<u8>,
    group: Option<String>,
    automatic_only: bool,
    cutoff: i64,
    after: i64,
}
#[derive(Clone, Debug)]
pub struct AttachmentCancellationBatch {
    pub visited: u32,
    pub requested: u32,
    pub preserved: u32,
    pub next_cursor: Option<AttachmentCancellationCursor>,
}
macro_rules! private_formatter {
    ($($ty:ty),*)=>{$(impl std::fmt::Debug for $ty {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct(stringify!($ty)).finish_non_exhaustive()}})*};
}
private_formatter!(
    AttachmentJobQuery,
    AttachmentJobCursor,
    AttachmentJobActionToken,
    AttachmentJobEntry,
    AttachmentCancellationCursor
);

fn history(s: &SqliteAccountStorage) -> StorageResult<AccountAttachmentVersion> {
    s.account_attachment_history_version().map_err(|e| match e {
        crate::AccountAttachmentHistoryError::Storage(e) => e,
        _ => invalid("attachment management history unavailable"),
    })
}
fn current_sequence(conn: &Connection) -> StorageResult<i64> {
    conn.query_row(
        "SELECT value FROM attachment_management_sequence WHERE id=1",
        [],
        |r| r.get(0),
    )
    .storage()
}
/// Index seek visits limit+1 job candidates before source, visibility and UI filtering.
type Candidate = (i64, Vec<u8>, String, String, String, u32, bool);
fn candidates(
    conn: &Connection,
    group: Option<&str>,
    low: i64,
    high: i64,
    descending: bool,
    limit: usize,
) -> StorageResult<Vec<Candidate>> {
    let index = if group.is_some() {
        "attachment_management_group_sequence"
    } else {
        "attachment_management_sequence_index"
    };
    let filter = if group.is_some() {
        " AND group_id_hex=?4"
    } else {
        ""
    };
    let order = if descending { "DESC" } else { "ASC" };
    let sql = format!(
        "SELECT management_sequence,token,group_id_hex,message_id_hex,source_message_id_hex,attachment_index,explicit_request FROM attachment_acquisition INDEXED BY {index} WHERE management_sequence>?1 AND management_sequence<=?2{filter} ORDER BY management_sequence {order} LIMIT ?3"
    );
    let mut values = vec![
        rusqlite::types::Value::Integer(low),
        rusqlite::types::Value::Integer(high),
        rusqlite::types::Value::Integer(limit as i64),
    ];
    if let Some(g) = group {
        values.push(g.to_owned().into());
    }
    conn.prepare(&sql)
        .storage()?
        .query_map(rusqlite::params_from_iter(values), |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

impl SqliteAccountStorage {
    /// Indexed live candidate paging, at most50 candidates plus lookahead. Empty filtered pages can continue.
    /// Cursors are process-local and privacy-fenced; new intents are offered by a head refresh.
    pub fn attachment_jobs_page(
        &self,
        query: &AttachmentJobQuery,
        limit: usize,
        cursor: Option<&AttachmentJobCursor>,
        now: u64,
        automatic: bool,
    ) -> StorageResult<AttachmentJobPage> {
        if !(1..=ATTACHMENT_MANAGEMENT_PAGE_LIMIT).contains(&limit) {
            return Err(invalid("invalid attachment management limit"));
        }
        let query = query.canonical()?;
        self.connection.with_read_snapshot(|| {
            let h = history(self)?;
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
                let cutoff = current_sequence(&conn)?;
                (cutoff, cutoff.saturating_add(1))
            };
            let rows = candidates(
                &conn,
                query.group_id_hex.as_deref(),
                0,
                cutoff.min(before - 1),
                true,
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
                let Some(status) = super::controls::transfer_status(
                    &conn,
                    &identity,
                    &g,
                    (&m, &source, index),
                    now,
                    automatic,
                    &mut next_expiry,
                )?
                else {
                    continue;
                };
                drop(conn);
                if status.reference.as_ref().is_none_or(|r| r.token != token)
                    || !query.accepts(explicit, status.state)
                {
                    continue;
                }
                entries.push(AttachmentJobEntry {
                    group_id_hex: g,
                    source: entry,
                    explicit,
                    origin_known: status.state != AttachmentTransferState::Cancelled,
                    status,
                    action: AttachmentJobActionToken {
                        reference: AttachmentAssetRef {
                            store_epoch: identity.clone(),
                            token,
                        },
                        sequence,
                    },
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
    /// Bounded current counts. `complete=false` explicitly reports lower bounds, never an exact total.
    pub fn attachment_job_counts(
        &self,
        group: Option<&str>,
        now: u64,
        automatic: bool,
    ) -> StorageResult<AttachmentJobCounts> {
        let q = AttachmentJobQuery {
            group_id_hex: group.map(str::to_owned),
            ..Default::default()
        }
        .canonical()?;
        self.connection.with_read_snapshot(|| {
            let conn=self.lock()?;let identity=epoch(&conn)?;
            let rows=candidates(&conn,q.group_id_hex.as_deref(),0,current_sequence(&conn)?,true,ATTACHMENT_MANAGEMENT_COUNT_LIMIT+1)?;
            let mut counts=AttachmentJobCounts{complete:rows.len()<=ATTACHMENT_MANAGEMENT_COUNT_LIMIT,..Default::default()};
            for (_,token,g,m,s,i,_) in rows.into_iter().take(ATTACHMENT_MANAGEMENT_COUNT_LIMIT) {
                // Membership eligibility is checked before the canonical source/expiry state read.
                let eligible:bool=conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM attachment_acquisition q WHERE token=?1 AND {ACCEPTED})"),[&token],|r|r.get(0)).storage()?;
                if !eligible {continue;}
                // Reuse the canonical state mapping; source/expiry privacy is checked before classification.
                if let Some(status)=super::controls::transfer_status(&conn,&identity,&g,(&m,&s,i),now,automatic,&mut None)? {
                    if status.reference.as_ref().is_none_or(|r|r.token!=token){continue;}
                    if active(status.state){counts.active+=1;}else if attention(status.state){counts.needs_attention+=1;}else{match status.state {AttachmentTransferState::Ready=>counts.ready+=1,AttachmentTransferState::Paused=>counts.paused+=1,AttachmentTransferState::Cancelled=>counts.cancelled+=1,AttachmentTransferState::PolicyBlocked=>counts.policy_blocked+=1,_=>counts.other+=1}}
                }
            }
            Ok(counts)
        })
    }
    /// Read-only capture of old intent membership. Later inserts, explicit promotions and retries are excluded.
    pub fn begin_attachment_cancellation(
        &self,
        group: Option<&str>,
        automatic_only: bool,
    ) -> StorageResult<AttachmentCancellationCursor> {
        let q = AttachmentJobQuery {
            group_id_hex: group.map(str::to_owned),
            ..Default::default()
        }
        .canonical()?;
        let conn = self.lock()?;
        Ok(AttachmentCancellationCursor {
            identity: epoch(&conn)?,
            group: q.group_id_hex,
            automatic_only,
            cutoff: current_sequence(&conn)?,
            after: 0,
        })
    }
    /// At most64 candidates, durable cancellation before worker signalling. Ready bytes and newer intent survive.
    /// Counts acknowledge requests, never connection termination. Replaying a batch is safe for newer user intent.
    pub fn cancel_attachment_batch(
        &self,
        cursor: &AttachmentCancellationCursor,
        now: u64,
    ) -> StorageResult<AttachmentCancellationBatch> {
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            if epoch(&conn)?!=cursor.identity{return Err(invalid("attachment cancellation account mismatch"));}
            let rows=candidates(&conn,cursor.group.as_deref(),cursor.after,cursor.cutoff,false,65)?;
            let more=rows.len()>64;let mut next=cursor.clone();let mut visited=0;let mut requested=0;
            for (seq,token,_,_,_,_,_) in rows.into_iter().take(64) {
                visited+=1;next.after=seq;
                requested+=conn.execute(&format!("UPDATE attachment_acquisition AS q SET cancelled=1,state=4,due=NULL,attempt=NULL,explicit_request=0 WHERE token=?1 AND management_sequence=?2 AND state<>3 AND cancelled=0 AND (?3=0 OR explicit_request=0) AND {SOURCE_MATCH} AND {ACCEPTED} AND (expires_at IS NULL OR expires_at>?4)"),params![token,seq,cursor.automatic_only,u64_to_i64(now)?]).storage()? as u32;
            }
            Ok(AttachmentCancellationBatch{visited,requested,preserved:visited-requested,next_cursor:more.then_some(next)})
        })
    }
    /// Reject stale intent/action generations before invoking the existing cancel/retry engine.
    pub fn control_managed_attachment(
        &self,
        token: &AttachmentJobActionToken,
        retry: bool,
        now: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            if !matches_store(&conn,&token.reference)?{return Ok(false);}
            let current:bool=conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM attachment_acquisition q WHERE token=?1 AND management_sequence=?2 AND {SOURCE_MATCH} AND {ACCEPTED} AND (expires_at IS NULL OR expires_at>?3))"),params![token.reference.token,token.sequence,u64_to_i64(now)?],|r|r.get(0)).storage()?;drop(conn);
            if !current{return Ok(false);}
            if retry{self.explicitly_retry_attachment(&token.reference,now)}else{self.cancel_attachment_acquisition(&token.reference)}
        })
    }
}

/// Opaque replacement-frame generation; unrelated accounts never compare equal.
#[derive(Clone)]
pub struct AttachmentManagementVersion {
    identity: Vec<u8>,
    revision: i64,
    history: AccountAttachmentVersion,
    health_fence: [u8; 32],
}
impl AttachmentManagementVersion {
    pub fn same_as(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.revision == other.revision
            && self.history == other.history
            && self.health_fence == other.health_fence
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
        automatic: bool,
    ) -> StorageResult<AttachmentManagementFrame> {
        let q = query.canonical()?;
        self.connection.with_read_snapshot(|| {
            let conn=self.lock()?;
            let available=if let Some(g)=q.group_id_hex.as_deref(){conn.query_row("SELECT EXISTS(SELECT 1 FROM account_groups WHERE group_id_hex=?1 AND pending_confirmation=0)",[g],|r|r.get(0)).storage()?}else{true};
            let identity=epoch(&conn)?;
            let revision=conn.query_row("SELECT revision FROM attachment_management_sequence WHERE id=1",[],|r|r.get(0)).storage()?;
            drop(conn);
            let group=q.group_id_hex.as_deref().map(hex::decode).transpose().map_err(|_|invalid("invalid management group"))?;
            let failure=if available{group.as_ref().map(|g|self.automatic_recovery_failed(&cgka_traits::GroupId::new(g.clone()))).transpose()?}else{None};
            let (notices,notices_complete)=if available{self.bounded_parked_recovery_notices(group.as_deref(),50)?}else{(Vec::new(),true)};
            let mut hash=Sha256::new();hash.update([u8::from(available),u8::from(failure.unwrap_or(false)),u8::from(notices_complete)]);
            hash.update([u8::from(failure.is_some()),q.view as u8,q.origin as u8]);
            match q.group_id_hex.as_deref(){
                Some(g)=>{hash.update([1]);hash.update((g.len() as u64).to_be_bytes());hash.update(g.as_bytes());},
                None=>hash.update([0]),
            }
            for n in &notices {hash.update(n.ticket.id);hash.update(n.ticket.revision.to_be_bytes());}
            let counts=if available{self.attachment_job_counts(q.group_id_hex.as_deref(),now,automatic)?}else{AttachmentJobCounts::default()};
            let page=self.attachment_jobs_page(&q,50,None,now,automatic)?;
            let version=AttachmentManagementVersion{identity,revision,history:page.history_version.clone(),health_fence:hash.finalize().into()};
            Ok(AttachmentManagementFrame{available,automatic_recovery_failed:failure,notices,notices_complete,counts,page,version})
        })
    }
}

/// Intent advances independently of wall clocks, progress and SQLite rowid reuse.
pub(super) fn advance_intent(conn: &Connection, token: &[u8]) -> StorageResult<()> {
    conn.execute(
        "UPDATE attachment_management_sequence SET value=value+1 WHERE id=1",
        [],
    )
    .storage()?;
    conn.execute("UPDATE attachment_acquisition SET management_sequence=(SELECT value FROM attachment_management_sequence WHERE id=1) WHERE token=?1",[token]).storage()?;
    Ok(())
}
