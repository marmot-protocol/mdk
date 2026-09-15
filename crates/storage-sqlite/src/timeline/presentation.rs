//! Captured, immutable system provenance for one bounded conversation page.
use super::*;

const MAX_CONVERSATION_SYSTEM_BYTES: usize = 16 * 1024;

/// Owns the existing page, without a second transcript copy. Private fields
/// bind provenance to the exact immutable rows and account store that were
/// checked. M4 can capture this inside its account transaction and enrich it
/// from directory caches after releasing that transaction.
#[derive(Clone)]
pub struct ConversationPresentationPage {
    page: TimelinePage,
    store_epoch: Vec<u8>,
    system_rows: Vec<bool>,
}
impl ConversationPresentationPage {
    pub fn page(&self) -> &TimelinePage {
        &self.page
    }
    pub fn store_epoch(&self) -> &[u8] {
        &self.store_epoch
    }
    /// A borrowed payload, not a second string or a caller-supplied assertion.
    /// Branch invalidation remains on the retained timeline row.
    pub fn authenticated_system_content(&self, index: usize) -> Option<&str> {
        self.system_rows
            .get(index)
            .copied()
            .filter(|v| *v)
            .and_then(|_| self.page.messages.get(index))
            .map(|m| m.plaintext.as_str())
    }
}
impl SqliteAccountStorage {
    /// Batch-check synthesized direction, absent inner source, commit
    /// attribution, exact payload and epoch using one bounded VALUES join.
    /// No roster/history scan, no row-by-row locks and no payload copies.
    /// The caller's transaction, if any, remains caller-owned.
    pub fn conversation_presentation_page(
        &self,
        page: TimelinePage,
    ) -> StorageResult<ConversationPresentationPage> {
        if page.messages.len() > MAX_TIMELINE_LIMIT {
            return Err(StorageError::Serialization(
                "conversation page limit exceeded".into(),
            ));
        }
        if let Some(first) = page.messages.first()
            && page
                .messages
                .iter()
                .any(|m| m.group_id_hex != first.group_id_hex)
        {
            return Err(StorageError::Serialization(
                "conversation page group mismatch".into(),
            ));
        }
        let mut system_rows = vec![false; page.messages.len()];
        let conn = self.lock()?;
        let store_epoch = conn
            .query_row_cached(
                "SELECT store_epoch FROM chat_presentation_meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .storage()?;
        let eligible = page
            .messages
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                m.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
                    && m.direction == "system"
                    && m.source_message_id_hex.is_none()
                    && m.plaintext.len() <= MAX_CONVERSATION_SYSTEM_BYTES
            })
            .map(|(index, m)| Ok((index, m, optional_u64_to_i64(m.source_epoch)?)))
            .collect::<StorageResult<Vec<_>>>()?;
        if let Some((_, first, _)) = eligible.first() {
            // 2 fixed parameters + 3 per eligible row <= 602, below the shared
            // SQLite parameter budget. All interpolated values are local indices.
            let values = eligible
                .iter()
                .enumerate()
                .map(|(slot, (index, _, _))| {
                    format!(
                        "({index}, ?{}, ?{}, ?{})",
                        3 + slot * 3,
                        4 + slot * 3,
                        5 + slot * 3
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "WITH requested(idx, message_id, plaintext, epoch) AS (VALUES {values})
                SELECT requested.idx FROM requested JOIN app_events a
                  ON a.group_id_hex = ?1 AND a.message_id_hex = requested.message_id
                WHERE a.kind = ?2 AND a.direction = 'system' AND a.source_message_id_hex IS NULL
                  AND a.origin_commit_id IS NOT NULL AND length(a.origin_commit_id) > 0
                  AND a.plaintext = requested.plaintext AND a.source_epoch IS requested.epoch"
            );
            let kind = MARMOT_APP_EVENT_KIND_GROUP_SYSTEM as i64;
            let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![&first.group_id_hex, &kind];
            for (_, message, epoch) in &eligible {
                parameters.extend([
                    &message.message_id_hex as &dyn rusqlite::ToSql,
                    &message.plaintext,
                    epoch,
                ]);
            }
            let mut statement = conn.prepare(&sql).storage()?;
            for index in statement
                .query_map(params_from_iter(parameters), |r| r.get::<_, u32>(0))
                .storage()?
            {
                system_rows[index.storage()? as usize] = true;
            }
        }
        drop(eligible);
        Ok(ConversationPresentationPage {
            page,
            store_epoch,
            system_rows,
        })
    }
}
