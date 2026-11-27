//! Post-link chat progress. The account worker serializes reports for its own
//! links. A receiver only accepts pages addressed to its current roster entry.
use crate::base::connection::{CachedSql, canonical_group_id_hex};
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

/// One complete scan, bound to the KeyPackageRef of the approved link.
#[derive(Clone, PartialEq, Eq)]
pub struct LinkChatReport {
    pub slot: String,
    pub link_ref: String,
    pub digest: Vec<u8>,
    pub total: u32,
    pub remaining: u32,
    pub expires_at: u64,
}

/// An authenticated page of the inventory addressed to this device.
pub struct LinkChatPage<'a> {
    pub link_ref: &'a str,
    pub revision: u32,
    pub page: u32,
    pub total: u32,
    pub expires_at: u64,
    pub tokens: &'a [u8],
    pub message_id: &'a [u8],
}

/// Pages retained for one incoming link, in ascending page order.
#[derive(Debug, PartialEq, Eq)]
pub struct ReceivedLinkChatReport {
    pub revision: u32,
    pub total: u32,
    pub available_pages: u32,
}

impl SqliteAppStorage {
    /// Avoid hydrating a device group on a snapshot read before any report exists.
    pub fn has_link_chat_progress(&self, now: u64) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM link_chat_reports WHERE expires_at>?1)
                 OR EXISTS(SELECT 1 FROM link_chat_report_pages WHERE expires_at>?1)",
                [u64_to_i64(now)?],
                |row| row.get(0),
            )
            .storage()
    }

    /// Save the sender's scan before attempting its publication. A change to
    /// remaining alone keeps the inventory revision so no pages need resending.
    pub fn save_link_chat_report(
        &self,
        group: &str,
        report: &LinkChatReport,
    ) -> StorageResult<u32> {
        let group = canonical_group_id_hex(group);
        self.lock()?.query_row_cached(
            "INSERT INTO link_chat_reports(group_id,slot,link_ref,digest,revision,total,remaining,expires_at)
             VALUES(?1,?2,?3,?4,1,?5,?6,?7) ON CONFLICT(group_id,slot) DO UPDATE SET
             revision=CASE WHEN link_ref!=excluded.link_ref THEN 1
                           ELSE revision+(digest!=excluded.digest) END,
             link_ref=excluded.link_ref,digest=excluded.digest,total=excluded.total,
             remaining=excluded.remaining,expires_at=excluded.expires_at RETURNING revision",
            params![
                group.as_ref(), report.slot, report.link_ref, report.digest, report.total,
                report.remaining, u64_to_i64(report.expires_at)?
            ],
            |row| row.get(0),
        ).storage()
    }

    /// Active reports made by this device.
    pub fn link_chat_reports(&self, group: &str, now: u64) -> StorageResult<Vec<LinkChatReport>> {
        let group = canonical_group_id_hex(group);
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT slot,link_ref,digest,total,remaining,expires_at FROM link_chat_reports
             WHERE group_id=?1 AND expires_at>?2 ORDER BY slot",
            )
            .storage()?;
        stmt.query_map(params![group.as_ref(), u64_to_i64(now)?], |r| {
            let expiry: i64 = r.get(5)?;
            Ok(LinkChatReport {
                slot: r.get(0)?,
                link_ref: r.get(1)?,
                digest: r.get(2)?,
                total: r.get(3)?,
                remaining: r.get(4)?,
                expires_at: expiry
                    .try_into()
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, expiry))?,
            })
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
    }

    /// Replace an older inventory atomically, preserving other pages from the
    /// same revision. Delivery can be duplicated or reordered across restart.
    pub fn receive_link_chat_page(
        &self,
        group: &str,
        page: &LinkChatPage<'_>,
    ) -> StorageResult<()> {
        let group = canonical_group_id_hex(group);
        let group = group.as_ref();
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let previous: Option<(String, u32, u32, i64)> = conn.query_row_cached(
                "SELECT link_ref,revision,total,expires_at FROM link_chat_report_pages WHERE group_id=?1 LIMIT 1",
                [group], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).optional().storage()?;
            if let Some((link, revision, total, expiry)) = previous {
                let same_link = link == page.link_ref;
                let same_revision = same_link && revision == page.revision;
                if same_link && revision > page.revision {
                    return Ok(());
                }
                if same_revision && (total != page.total || i64_to_u64(expiry)? != page.expires_at) {
                    return Ok(());
                }
                if !same_revision {
                    conn.execute_cached(
                        "DELETE FROM link_chat_report_pages WHERE group_id=?1", [group],
                    ).storage()?;
                }
            }
            conn.execute_cached(
                "INSERT INTO link_chat_report_pages(group_id,link_ref,revision,page,total,expires_at,tokens,message_id)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(group_id,page) DO UPDATE SET
                 tokens=excluded.tokens,message_id=excluded.message_id
                 WHERE tokens=excluded.tokens",
                 params![
                     group, page.link_ref, page.revision, page.page, page.total,
                     u64_to_i64(page.expires_at)?, page.tokens, page.message_id
                 ],
            ).storage()?;
            Ok(())
        })
    }

    /// Check the current generation and page coverage without reading any token blobs.
    pub fn received_link_chat_report(
        &self,
        group: &str,
        link: &str,
        now: u64,
    ) -> StorageResult<Option<ReceivedLinkChatReport>> {
        let group = canonical_group_id_hex(group);
        self.lock()?
            .query_row_cached(
                "SELECT revision,total,COUNT(message_id) FROM link_chat_report_pages
             WHERE group_id=?1 AND link_ref=?2 AND expires_at>?3 GROUP BY revision,total",
                params![group.as_ref(), link, u64_to_i64(now)?],
                |row| {
                    Ok(ReceivedLinkChatReport {
                        revision: row.get(0)?,
                        total: row.get(1)?,
                        available_pages: row.get(2)?,
                    })
                },
            )
            .optional()
            .storage()
    }

    /// Read selected pages of precisely the revision requested. Withdrawal
    /// preserves the immutable token bytes, so same-revision repair cannot
    /// change what an already assembled report means.
    pub fn received_link_chat_tokens(
        &self,
        group: &str,
        link: &str,
        revision: u32,
    ) -> StorageResult<Vec<u8>> {
        let group = canonical_group_id_hex(group);
        let conn = self.lock()?;
        let mut stmt=conn.prepare_cached(
            "SELECT tokens FROM link_chat_report_pages
             WHERE group_id=?1 AND link_ref=?2 AND revision=?3 AND message_id IS NOT NULL ORDER BY page"
        ).storage()?;
        let mut rows = stmt
            .query(params![group.as_ref(), link, revision])
            .storage()?;
        let mut tokens = Vec::new();
        while let Some(row) = rows.next().storage()? {
            tokens.extend(row.get::<_, Vec<u8>>(0).storage()?);
        }
        Ok(tokens)
    }

    /// Invalidate a withdrawn observation without accepting a stale revision.
    /// Returns whether the carrier belonged to a currently selected incoming page.
    pub fn withdraw_link_chat_page(&self, group: &str, message: &[u8]) -> StorageResult<bool> {
        let group = canonical_group_id_hex(group);
        let changed = self.lock()?
            .execute_cached(
                "UPDATE link_chat_report_pages SET message_id=NULL WHERE group_id=?1 AND message_id=?2",
                params![group.as_ref(), message],
            )
            .storage()?;
        Ok(changed != 0)
    }

    /// Bound retained link inventories to the direct post-link window.
    pub fn prune_link_chat_progress(&self, now: u64) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "DELETE FROM link_chat_reports WHERE expires_at<=?1",
                [u64_to_i64(now)?],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM link_chat_report_pages WHERE expires_at<=?1",
                [u64_to_i64(now)?],
            )
            .storage()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    #[test]
    fn reordered_withdrawn_and_replayed_pages_preserve_the_latest_inventory() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let page =
            |revision, page, tokens: &'static [u8], message_id: &'static [u8]| LinkChatPage {
                link_ref: "link",
                revision,
                page,
                total: 2,
                expires_at: 100,
                tokens,
                message_id,
            };
        let receive = |page| store.receive_link_chat_page("group", &page).unwrap();
        let inventory = || {
            store
                .received_link_chat_report("group", "link", 10)
                .unwrap()
                .map(|report| {
                    (
                        report.total,
                        store
                            .received_link_chat_tokens("group", "link", report.revision)
                            .unwrap(),
                    )
                })
        };
        receive(page(1, 0, b"a", b"old"));
        receive(page(2, 1, b"c", b"second"));
        receive(page(1, 0, b"a", b"old"));
        assert_eq!(inventory(), Some((2, b"c".to_vec())));
        receive(page(2, 0, b"b", b"first"));
        receive(page(2, 1, b"c", b"repeated"));
        store.withdraw_link_chat_page("group", b"second").unwrap();
        assert_eq!(inventory(), Some((2, b"bc".to_vec())));
        store.withdraw_link_chat_page("group", b"first").unwrap();
        assert_eq!(inventory(), Some((2, b"c".to_vec())));
        receive(page(2, 0, b"b", b"repair"));
        assert_eq!(inventory(), Some((2, b"bc".to_vec())));
        store.prune_link_chat_progress(100).unwrap();
        assert_eq!(inventory(), None);
    }
}
