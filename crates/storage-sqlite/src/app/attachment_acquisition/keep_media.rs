//! The opt-in "Keep media" setting (mdk#2314 step 10): retained attachments
//! older than the account's window are removed as explicit `Remove` does,
//! but recorded as cleaned by the setting, so hosts can tell the two apart.
//! Download-again works for both.
//!
//! Age is the later of the message's received time and the last explicit
//! request for the body (`keep_from`): something the user asked for is kept
//! for the whole window from that request. Forever, the default, removes
//! nothing.
use super::storage_usage::RemovalReason;
use super::*;

const DAY_SECONDS: u64 = 24 * 60 * 60;

/// How long retained attachments are kept, per account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttachmentKeepMedia {
    /// Nothing is removed automatically.
    #[default]
    Forever,
    OneYear,
    SixMonths,
    ThirtyDays,
}

impl AttachmentKeepMedia {
    /// The window in days, as stored; `None` for Forever.
    pub fn days(self) -> Option<u64> {
        match self {
            Self::Forever => None,
            Self::OneYear => Some(365),
            Self::SixMonths => Some(183),
            Self::ThirtyDays => Some(30),
        }
    }

    fn from_days(days: Option<i64>) -> StorageResult<Self> {
        match days {
            None => Ok(Self::Forever),
            Some(365) => Ok(Self::OneYear),
            Some(183) => Ok(Self::SixMonths),
            Some(30) => Ok(Self::ThirtyDays),
            Some(_) => Err(invalid("invalid stored keep media setting")),
        }
    }

    /// Attachments aged before this (Unix seconds) are past the window at
    /// `now`; `None` for Forever.
    pub fn cutoff(self, now: u64) -> Option<u64> {
        self.days()
            .map(|days| now.saturating_sub(days.saturating_mul(DAY_SECONDS)))
    }
}

/// The SQL age of retained attachment `q`: the later of its message's
/// received time and its last explicit request.
const AGE: &str = "max(coalesce(q.keep_from,0),(SELECT h.received_at FROM attachment_history h
    WHERE h.group_id_hex=q.group_id_hex AND h.message_id_hex=q.message_id_hex
      AND h.attachment_index=q.attachment_index))";

fn keep_media_in(conn: &Connection) -> StorageResult<AttachmentKeepMedia> {
    let days = conn
        .query_row(
            "SELECT keep_days FROM attachment_keep_media WHERE id=1",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()
        .storage()?
        .flatten();
    AttachmentKeepMedia::from_days(days)
}

/// When automatic demand meets a slot that has no acquisition yet and whose
/// message was received before the window, records it as cleaned by the
/// setting instead of fetching a body the next sweep would delete. True when
/// it did; the caller then reports the demand as suppressed.
pub(super) fn suppress_past_window(
    conn: &Connection,
    group: &str,
    message: &str,
    index: u32,
    now: u64,
) -> StorageResult<bool> {
    let Some(cutoff) = keep_media_in(conn)?.cutoff(now) else {
        return Ok(false);
    };
    let cutoff = i64::try_from(cutoff).unwrap_or(i64::MAX);
    Ok(conn
        .execute(
            "INSERT INTO attachment_removal_suppression(group_id_hex,message_id_hex,attachment_index,reason)
             SELECT h.group_id_hex,h.message_id_hex,h.attachment_index,?5 FROM attachment_history h
             JOIN app_events a USING(group_id_hex,message_id_hex)
             WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.attachment_index=?3
               AND h.visible=1 AND h.received_at<?4
               AND NOT EXISTS(SELECT 1 FROM attachment_acquisition q
                   WHERE q.group_id_hex=h.group_id_hex AND q.message_id_hex=h.message_id_hex
                     AND q.attachment_index=h.attachment_index)
             ON CONFLICT DO NOTHING",
            params![group, message, index, cutoff, RemovalReason::BySetting as i64],
        )
        .storage()?
        == 1)
}

impl SqliteAppStorage {
    /// The account's "Keep media" setting; Forever when never set.
    pub fn attachment_keep_media(&self) -> StorageResult<AttachmentKeepMedia> {
        keep_media_in(&*self.lock()?)
    }

    /// Persists the setting. It removes nothing itself: run
    /// [`Self::clean_attachments_past_keep_window`] afterwards.
    pub fn set_attachment_keep_media(&self, keep: AttachmentKeepMedia) -> StorageResult<()> {
        let days = keep.days().map(|days| days as i64);
        self.lock()?
            .execute(
                "INSERT INTO attachment_keep_media(id,keep_days) VALUES(1,?1)
                 ON CONFLICT(id) DO UPDATE SET keep_days=excluded.keep_days",
                [days],
            )
            .storage()?;
        Ok(())
    }

    /// [`Self::request_attachment_acquisition`] for automatic demand: a slot
    /// with no acquisition yet whose message is already past the "Keep media"
    /// window is recorded as cleaned by the setting and reported as
    /// suppressed instead. Explicit requests never go through this gate.
    pub fn request_automatic_acquisition(
        &self,
        group: &str,
        selected: &crate::AttachmentHistoryEntry,
        plaintext_digest: [u8; 32],
        now: u64,
    ) -> StorageResult<AttachmentDemand> {
        let index = u32::try_from(selected.attachment_index)
            .map_err(|_| invalid("invalid attachment index"))?;
        self.connection.with_transaction(|| {
            if suppress_past_window(&*self.lock()?, group, &selected.message_id_hex, index, now)? {
                return Ok(AttachmentDemand::Suppressed);
            }
            self.request_attachment_acquisition(group, selected, plaintext_digest, now)
        })
    }

    /// Removes up to [`ATTACHMENT_REMOVAL_BATCH`] attachments past the "Keep
    /// media" window, as explicit `Remove` does but recorded as cleaned by
    /// the setting, in one transaction: retained ones, and unfinished
    /// automatic downloads the user never requested. Nothing under Forever.
    /// Unlink the returned files, then call again while `more`.
    pub fn clean_attachments_past_keep_window(&self, now: u64) -> StorageResult<AttachmentRemoval> {
        if self.attachment_keep_media()? == AttachmentKeepMedia::Forever {
            return Ok(AttachmentRemoval::default());
        }
        // Retained attachments, and automatic downloads the user never asked
        // for that have not finished: those were demanded before the window
        // reached them, and would otherwise fetch a body only to remove it.
        // The window is read again inside the removal transaction, so a
        // concurrent change to Forever removes nothing more.
        self.remove_batch(
            now,
            &format!(
                "({} OR (q.state<>3 AND q.explicit_request=0 AND q.keep_from IS NULL))
                 AND {AGE}<?1-(SELECT keep_days FROM attachment_keep_media WHERE id=1)*{DAY_SECONDS}",
                super::storage_usage::retained("?1")
            ),
            &[],
            RemovalReason::BySetting,
        )
    }
}
