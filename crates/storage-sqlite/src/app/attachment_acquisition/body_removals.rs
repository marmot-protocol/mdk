use super::*;

/// Historical loss of a local body or its source authorization. This never
/// grants access to bytes; retained-attachment reads check current authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentBodyRemovalState {
    CleanedBySetting,
    Removed,
    CompletedUnretained,
    Unavailable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentBodyRemoval {
    pub group_id_hex: String,
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub attachment_index: u32,
    pub state: AttachmentBodyRemovalState,
}

impl std::fmt::Debug for AttachmentBodyRemoval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentBodyRemoval")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentBodyRemovalPage {
    pub removals: Vec<AttachmentBodyRemoval>,
    pub next_cursor: String,
    pub reset_required: bool,
    pub has_more: bool,
}

impl std::fmt::Debug for AttachmentBodyRemovalPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentBodyRemovalPage")
            .field("removal_count", &self.removals.len())
            .field("reset_required", &self.reset_required)
            .field("has_more", &self.has_more)
            .finish_non_exhaustive()
    }
}

fn parse_cursor(cursor: &str) -> Option<([u8; 16], i64)> {
    if cursor.len() > 64 {
        return None;
    }
    let mut parts = cursor.split(':');
    if parts.next()? != "1" {
        return None;
    }
    let mut epoch = [0; 16];
    hex::decode_to_slice(parts.next()?, &mut epoch).ok()?;
    let sequence = parts.next()?.parse::<i64>().ok()?;
    (sequence >= 0 && parts.next().is_none()).then_some((epoch, sequence))
}

impl SqliteAppStorage {
    /// Read 1–256 historical removals after an opaque, durable account-store
    /// cursor. The journal retains at most 4,096 records. An absent, unknown,
    /// reset-store or trimmed cursor returns a fresh high-water cursor with
    /// `reset_required=true` and no records. Capture that cursor before
    /// reconciling derivative caches, then persist it after reconciliation.
    /// Expiry is reported when cleanup removes the acquisition, not at its
    /// exact deadline. This query neither starts work nor authorizes local reads.
    pub fn attachment_removals(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> StorageResult<AttachmentBodyRemovalPage> {
        if !(1..=256).contains(&limit) {
            return Err(invalid("invalid attachment body removal page limit"));
        }
        // Hold one read snapshot even when another process writes this store.
        self.connection.with_transaction_mode(true, || {
            let conn = self.lock()?;
            let (epoch, high_water, floor): (Vec<u8>, i64, i64) = conn.query_row(
                "SELECT p.store_epoch,m.high_water,
                    coalesce((SELECT sequence FROM attachment_body_removals ORDER BY sequence LIMIT 1),m.high_water+1)
                 FROM chat_presentation_meta p JOIN attachment_body_removal_meta m ON m.id=p.id WHERE p.id=1",
                [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            ).storage()?;
            let sequence = cursor.and_then(parse_cursor).and_then(|(store, sequence)| {
                (store.as_slice() == epoch.as_slice() && sequence >= floor - 1 && sequence <= high_water).then_some(sequence)
            });
            let Some(sequence) = sequence else {
                return Ok(AttachmentBodyRemovalPage {
                    removals: Vec::new(),
                    next_cursor: format!("1:{}:{high_water}", hex::encode(&epoch)),
                    reset_required: true,
                    has_more: false,
                });
            };
            let mut statement = conn.prepare(
                "SELECT sequence,group_id_hex,message_id_hex,source_message_id_hex,attachment_index,state
                 FROM attachment_body_removals WHERE sequence>?1 ORDER BY sequence LIMIT ?2",
            ).storage()?;
            let mut rows = statement.query(params![sequence, limit as i64 + 1]).storage()?;
            let mut removals = Vec::new();
            let mut next_sequence = sequence;
            let mut has_more = false;
            while let Some(row) = rows.next().storage()? {
                if removals.len() == limit {
                    has_more = true;
                    break;
                }
                next_sequence = row.get(0).storage()?;
                let state = match row.get::<_, i64>(5).storage()? {
                    0 => AttachmentBodyRemovalState::CleanedBySetting,
                    1 => AttachmentBodyRemovalState::Removed,
                    2 => AttachmentBodyRemovalState::CompletedUnretained,
                    3 => AttachmentBodyRemovalState::Unavailable,
                    _ => return Err(StorageError::Corruption("invalid attachment body removal state".into())),
                };
                removals.push(AttachmentBodyRemoval {
                    group_id_hex: row.get(1).storage()?,
                    message_id_hex: row.get(2).storage()?,
                    source_message_id_hex: row.get(3).storage()?,
                    attachment_index: row.get(4).storage()?,
                    state,
                });
            }
            Ok(AttachmentBodyRemovalPage {
                removals,
                next_cursor: format!("1:{}:{next_sequence}", hex::encode(epoch)),
                reset_required: false,
                has_more,
            })
        })
    }
}
