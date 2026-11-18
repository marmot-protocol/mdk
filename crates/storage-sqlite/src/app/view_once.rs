use crate::{SqliteAppStorage, SqliteResultExt, StoredAppEvent, u64_to_i64};
use cgka_traits::{
    MarmotAppEvent,
    app_event::{AppMessageRetentionDecision, ViewOncePolicy},
    storage::StorageResult,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViewOnceState {
    Unopened,
    Consumed,
    Expired,
    Sent,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredViewOncePresentation {
    pub state: ViewOnceState,
    pub unopened_expires_at: u64,
}

#[derive(PartialEq, Eq)]
pub enum ViewOnceClaim {
    Claimed {
        imeta_tag: Vec<String>,
        source_epoch: u64,
        expires_at: u64,
    },
    Consumed,
    Expired,
    Unavailable,
}
impl std::fmt::Debug for ViewOnceClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Claimed { .. } => "Claimed",
            Self::Consumed => "Consumed",
            Self::Expired => "Expired",
            Self::Unavailable => "Unavailable",
        })
    }
}

pub(crate) fn is_view_once(tags: &[Vec<String>]) -> bool {
    tags.iter().any(|tag| {
        tag.first().is_some_and(|name| name == "view-once")
            || (tag.first().is_some_and(|name| name == "imeta")
                && tag
                    .iter()
                    .skip(1)
                    .any(|field| field.starts_with("v encrypted-media-view-once")))
    })
}

pub(crate) fn placeholder_tags(expires_at: Option<u64>) -> Vec<Vec<String>> {
    match expires_at.filter(|expires_at| *expires_at > 0) {
        Some(expires_at) => vec![vec![
            "view-once".into(),
            cgka_traits::app_components::VIEW_ONCE_MARKER_VERSION.into(),
            expires_at.to_string(),
        ]],
        None => vec![vec!["view-once".into()]],
    }
}

fn bounded_visual_descriptor(tags: &[Vec<String>]) -> bool {
    let bytes = tags.iter().try_fold(0usize, |sum, tag| {
        tag.iter().try_fold(sum.checked_add(2)?, |sum, field| {
            sum.checked_add(field.len())?.checked_add(3)
        })
    });
    if bytes.is_none_or(|bytes| bytes > 16_384) {
        return false;
    }
    let Some(imeta) = tags
        .iter()
        .find(|t| t.first().is_some_and(|v| v == "imeta"))
    else {
        return false;
    };
    let mut mime = imeta.iter().filter_map(|field| field.strip_prefix("m "));
    let Some(kind) = mime.next() else {
        return false;
    };
    mime.next().is_none()
        && (kind.starts_with("image/") || kind.starts_with("video/"))
        && kind.split_once('/').is_some_and(|(_, subtype)| {
            !subtype.is_empty()
                && subtype
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        })
}

fn validated_profile(event: &StoredAppEvent) -> Option<ViewOncePolicy> {
    if !bounded_visual_descriptor(&event.tags) {
        return None;
    }
    let inner = MarmotAppEvent::new(
        event.sender.clone(),
        event.recorded_at,
        event.kind,
        event.tags.clone(),
        event.plaintext.clone(),
    );
    if inner.id != event.message_id_hex {
        return None;
    }
    inner.view_once_policy().ok().flatten()
}

// No foreign keys: history deletion and projection recreation must never reset a claim.
pub(crate) fn record_tx(
    conn: &Connection,
    event: &StoredAppEvent,
    retention: Option<AppMessageRetentionDecision>,
) -> StorageResult<bool> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='view_once_consumption')",
            [],
            |r| r.get(0),
        )
        .storage()?;
    if !exists {
        return Ok(false);
    }
    let old: Option<(i64,bool)> = conn.query_row("SELECT state,eligible FROM view_once_consumption WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=0", params![event.group_id_hex,event.message_id_hex], |r|Ok((r.get(0)?,r.get(1)?))).optional().storage()?;
    if let Some((state, eligible)) = old {
        let now = advance_clock(conn, event.received_at)?;
        if state == 0
            && !eligible
            && let Some(policy) = retention.and_then(|decision| decision.view_once)
            && let Some(epoch) = event.source_epoch
            && validated_profile(event) == Some(policy)
        {
            // Complete missing authentication only for the original source, without restarting its cap.
            conn.execute("UPDATE view_once_consumption SET eligible=1,source_epoch=coalesce(source_epoch,?4),source_message_id_hex=coalesce(source_message_id_hex,?5) WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=0 AND state=0 AND eligible=0 AND revoked=0 AND policy_expires_at=?3 AND (source_epoch IS NULL OR source_epoch=?4) AND (source_message_id_hex IS NULL OR source_message_id_hex IS ?5) AND sender=?6 AND expires_at>?7",params![event.group_id_hex,event.message_id_hex,u64_to_i64(policy.unopened_expires_at)?,u64_to_i64(epoch)?,event.source_message_id_hex,event.sender,now]).storage()?;
        }
        let state:i64=conn.query_row("SELECT state FROM view_once_consumption WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=0",params![event.group_id_hex,event.message_id_hex],|r|r.get(0)).storage()?;
        return Ok(state != 0 || !is_view_once(&event.tags));
    }
    if !is_view_once(&event.tags) {
        return Ok(false);
    }
    let policy = validated_profile(event);
    let valid = policy.is_some();
    let eligible = valid
        && event.source_epoch.is_some()
        && policy == retention.and_then(|decision| decision.view_once);
    let deadline = policy.map(|p| p.unopened_expires_at).unwrap_or(0);
    let expiry_clock = crate::i64_to_u64(advance_clock(conn, event.received_at)?)?;
    let receipt_cap = event
        .received_at
        .checked_add(cgka_traits::app_components::VIEW_ONCE_MAX_LIFETIME_SECONDS)
        .ok_or_else(|| {
            cgka_traits::storage::StorageError::Serialization(
                "view-once receipt deadline overflow".into(),
            )
        })?;
    let expires_at = retention
        .and_then(|decision| decision.expires_at)
        .map_or(deadline, |retention| retention.min(deadline))
        .min(receipt_cap);
    let state = if !valid {
        3
    } else if expires_at <= expiry_clock {
        2
    } else {
        0
    };
    conn.execute("INSERT INTO view_once_consumption(group_id_hex,message_id_hex,attachment_index,state,expires_at,source_epoch,source_message_id_hex,sender,policy_expires_at,eligible) VALUES(?1,?2,0,?3,?4,?5,?6,?7,?8,?9)", params![event.group_id_hex,event.message_id_hex,state,u64_to_i64(expires_at)?,event.source_epoch.map(u64_to_i64).transpose()?,event.source_message_id_hex,event.sender,u64_to_i64(deadline)?,eligible]).storage()?;
    Ok(state != 0)
}

pub(crate) fn finalize_tx(
    conn: &Connection,
    group: &str,
    message: &str,
    retention: AppMessageRetentionDecision,
) -> StorageResult<()> {
    if presentation_tx(conn, group, message)?.is_none() {
        return Ok(());
    }
    let deadline = retention
        .view_once
        .map(|policy| u64_to_i64(policy.unopened_expires_at))
        .transpose()?;
    conn.execute("UPDATE view_once_consumption SET eligible=CASE WHEN policy_expires_at=?3 THEN 1 ELSE 0 END WHERE group_id_hex=?1 AND message_id_hex=?2 AND state IN(0,2) AND eligible=0 AND source_epoch IS NOT NULL AND EXISTS(SELECT 1 FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2 AND direction='sent')",params![group,message,deadline]).storage()?;
    Ok(())
}

pub(crate) fn cap_retention_tx(conn: &Connection, group: &str, message: &str) -> StorageResult<()> {
    if presentation_tx(conn, group, message)?.is_none() {
        return Ok(());
    }
    conn.execute("UPDATE app_events SET retention_expires_at=(SELECT expires_at FROM view_once_consumption WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=0) WHERE group_id_hex=?1 AND message_id_hex=?2 AND (retention_expires_at IS NULL OR retention_expires_at>(SELECT expires_at FROM view_once_consumption WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=0))",params![group,message]).storage()?;
    Ok(())
}

pub(crate) fn expire_tx(conn: &Connection, now: u64) -> StorageResult<()> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='view_once_clock')",
            [],
            |r| r.get(0),
        )
        .storage()?;
    if exists {
        advance_clock(conn, now)?;
    }
    Ok(())
}

fn advance_clock(conn: &Connection, now: u64) -> StorageResult<i64> {
    conn.execute(
        "UPDATE view_once_clock SET high_water=?1 WHERE id=1 AND high_water<?1",
        [u64_to_i64(now)?],
    )
    .storage()?;
    let now = conn
        .query_row(
            "SELECT high_water FROM view_once_clock WHERE id=1",
            [],
            |r| r.get::<_, i64>(0),
        )
        .storage()?;
    conn.execute("UPDATE app_events SET plaintext='',tags_json=(SELECT json_array(json_array('view-once',?2,CAST(expires_at AS TEXT))) FROM view_once_consumption v WHERE v.group_id_hex=app_events.group_id_hex AND v.message_id_hex=app_events.message_id_hex AND v.attachment_index=0) WHERE (group_id_hex,message_id_hex) IN (SELECT group_id_hex,message_id_hex FROM view_once_consumption WHERE state=0 AND expires_at<=?1)",params![now,cgka_traits::app_components::VIEW_ONCE_MARKER_VERSION]).storage()?;
    conn.execute(
        "UPDATE view_once_consumption SET state=2 WHERE state=0 AND expires_at<=?1",
        [now],
    )
    .storage()?;
    Ok(now)
}

pub(crate) fn presentation_tx(
    conn: &Connection,
    group: &str,
    message: &str,
) -> StorageResult<Option<StoredViewOncePresentation>> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='view_once_consumption')",
            [],
            |r| r.get(0),
        )
        .storage()?;
    if !exists {
        return Ok(None);
    }
    let presentation = conn.query_row("SELECT v.state,v.expires_at,coalesce(a.direction='sent' AND (v.eligible=1 OR a.source_epoch IS NULL),0) FROM view_once_consumption v LEFT JOIN app_events a USING(group_id_hex,message_id_hex) WHERE v.group_id_hex=?1 AND v.message_id_hex=?2 AND v.attachment_index=0", params![group,message], |r| {
        let state:i64=r.get(0)?;
        let sender_ready:bool=r.get(2)?;
        Ok(StoredViewOncePresentation { state: match state { 1=>ViewOnceState::Consumed,2=>ViewOnceState::Expired,0 if sender_ready=>ViewOnceState::Sent,0=>ViewOnceState::Unopened,_=>ViewOnceState::Unavailable },unopened_expires_at:r.get::<_,i64>(1)? as u64 })
    }).optional().storage()?;
    let Some(mut presentation) = presentation else {
        return Ok(None);
    };
    if presentation.state == ViewOnceState::Unopened {
        let now = conn
            .query_row(
                "SELECT high_water FROM view_once_clock WHERE id=1",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if !source_valid(conn, group, message, 0, now)? {
            presentation.state = ViewOnceState::Unavailable;
        }
    }
    Ok(Some(presentation))
}

fn source_valid(
    conn: &Connection,
    group: &str,
    message: &str,
    index: u32,
    now: i64,
) -> StorageResult<bool> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM view_once_consumption v JOIN app_events a USING(group_id_hex,message_id_hex) JOIN message_timeline t USING(group_id_hex,message_id_hex) JOIN account_groups g USING(group_id_hex) WHERE v.group_id_hex=?1 AND v.message_id_hex=?2 AND v.attachment_index=?3 AND v.eligible=1 AND v.revoked=0 AND v.expires_at>?4 AND a.source_epoch=v.source_epoch AND a.source_message_id_hex IS v.source_message_id_hex AND a.sender=v.sender AND a.kind=9 AND a.invalidated=0 AND a.direction='received' AND t.deleted=0 AND t.invalidation_status IS NULL AND g.pending_confirmation=0 AND g.self_membership='member' AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?4))",params![group,message,index,now],|r|r.get(0)).storage()
}

fn opening_metadata(
    conn: &Connection,
    group: &str,
    message: &str,
    index: u32,
    own_pubkey_hex: &str,
    now: i64,
) -> StorageResult<Option<(Vec<String>, u64, u64)>> {
    if own_pubkey_hex.len() != 64
        || !own_pubkey_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !source_valid(conn, group, message, index, now)?
    {
        return Ok(None);
    }
    let row: Option<(String,String,i64,i64,String,i64,i64)> = conn.query_row(
        "SELECT a.tags_json,a.plaintext,a.recorded_at,v.policy_expires_at,v.sender,v.source_epoch,v.expires_at FROM app_events a JOIN view_once_consumption v USING(group_id_hex,message_id_hex) WHERE a.group_id_hex=?1 AND a.message_id_hex=?2 AND v.attachment_index=?3 AND v.state=0",
        params![group,message,index], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    ).optional().storage()?;
    let Some((tags, content, created, deadline, sender, epoch, expires)) = row else {
        return Ok(None);
    };
    if sender.eq_ignore_ascii_case(own_pubkey_hex) {
        return Ok(None);
    }
    let tags: Vec<Vec<String>> = serde_json::from_str(&tags).unwrap_or_default();
    let inner = MarmotAppEvent::new(sender, created as u64, 9, tags.clone(), content);
    if inner.id != message
        || !bounded_visual_descriptor(&tags)
        || inner
            .view_once_policy()
            .ok()
            .flatten()
            .is_none_or(|policy| policy.unopened_expires_at != deadline as u64)
    {
        return Ok(None);
    }
    let Some(imeta) = tags
        .into_iter()
        .find(|tag| tag.first().is_some_and(|name| name == "imeta"))
    else {
        return Ok(None);
    };
    Ok(Some((
        imeta,
        crate::i64_to_u64(epoch)?,
        crate::i64_to_u64(expires)?,
    )))
}

impl SqliteAppStorage {
    pub fn view_once_metadata(
        &self,
        group: &str,
        message: &str,
        index: u32,
        own_pubkey_hex: &str,
        now: u64,
    ) -> StorageResult<Option<(Vec<String>, u64, u64)>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let now = advance_clock(&conn, now)?;
            opening_metadata(&conn, group, message, index, own_pubkey_hex, now)
        })
    }

    pub fn view_once_state(
        &self,
        group: &str,
        message: &str,
        index: u32,
        now: u64,
    ) -> StorageResult<ViewOnceState> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            advance_clock(&conn, now)?;
            if index != 0 {
                return Ok(ViewOnceState::Unavailable);
            }
            Ok(presentation_tx(&conn, group, message)?
                .map_or(ViewOnceState::Unavailable, |p| p.state))
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim_view_once(
        &self,
        allowed_mime: &[&str],
        group: &str,
        message: &str,
        index: u32,
        own_pubkey_hex: &str,
        now: u64,
    ) -> StorageResult<ViewOnceClaim> {
        if own_pubkey_hex.len() != 64 || !own_pubkey_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(ViewOnceClaim::Unavailable);
        }
        if !self.lock()?.is_autocommit() {
            return Err(cgka_traits::storage::StorageError::Backend(
                "view-once claim requires independent transaction".into(),
            ));
        }
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            let now=advance_clock(&conn,now)?;
            let row:Option<(i64,String)>=conn.query_row("SELECT state,sender FROM view_once_consumption WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3",params![group,message,index],|r|Ok((r.get(0)?,r.get(1)?))).optional().storage()?;
            let Some((state,sender))=row else {return Ok(ViewOnceClaim::Unavailable)};
            if sender.eq_ignore_ascii_case(own_pubkey_hex) {return Ok(ViewOnceClaim::Unavailable);}
            match state {1=>return Ok(ViewOnceClaim::Consumed),2=>return Ok(ViewOnceClaim::Expired),0=>{},_=>return Ok(ViewOnceClaim::Unavailable)}
            let Some((imeta,epoch,expires))=opening_metadata(&conn,group,message,index,own_pubkey_hex,now)? else {return Ok(ViewOnceClaim::Unavailable)};
            if !imeta.iter().filter_map(|field|field.strip_prefix("m ")).any(|mime|allowed_mime.contains(&mime)) {return Ok(ViewOnceClaim::Unavailable);}
            let changed=conn.execute("UPDATE view_once_consumption SET state=1 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3 AND state=0",params![group,message,index]).storage()?;
            if changed!=1 {return Ok(ViewOnceClaim::Consumed);}
            conn.execute("UPDATE app_events SET plaintext='',tags_json=(SELECT json_array(json_array('view-once',?3,CAST(expires_at AS TEXT))) FROM view_once_consumption v WHERE v.group_id_hex=?1 AND v.message_id_hex=?2 AND v.attachment_index=0) WHERE group_id_hex=?1 AND message_id_hex=?2",params![group,message,cgka_traits::app_components::VIEW_ONCE_MARKER_VERSION]).storage()?;
            Ok(ViewOnceClaim::Claimed {imeta_tag:imeta,source_epoch:epoch,expires_at:expires})
        })
    }

    pub fn view_once_access_valid(
        &self,
        group: &str,
        message: &str,
        index: u32,
        now: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            let now=advance_clock(&conn,now)?;
            let consumed:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM view_once_consumption WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3 AND state=1)",params![group,message,index],|r|r.get(0)).storage()?;
            Ok(consumed && source_valid(&conn,group,message,index,now)?)
        })
    }
}

#[cfg(test)]
mod tests;
