//! Keyed provenance reads for the conversation presentation layer.
use super::*;

/// Maximum structured system payload read by the display parser. Oversized or
/// legacy rows without origin evidence remain ordinary text in narrow APIs.
pub const MAX_CONVERSATION_SYSTEM_BYTES: usize = 16 * 1024;

impl SqliteAccountStorage {
    /// Return only locally synthesized, commit-attributed system content for
    /// this exact retained timeline row. Member-authored kind-1210 JSON is not
    /// evidence of a group transition. This does not claim the commit remains
    /// canonical: callers must preserve the timeline's invalidation status.
    ///
    /// Matching the visible payload and source epoch prevents a stale page from
    /// borrowing evidence from a replacement row. No full history or roster is
    /// loaded. M4 should call this within its account read snapshot.
    pub fn conversation_system_event_content(
        &self,
        message: &TimelineMessageRecord,
    ) -> StorageResult<Option<String>> {
        if message.kind != MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
            || message.plaintext.len() > MAX_CONVERSATION_SYSTEM_BYTES
        {
            return Ok(None);
        }
        self.lock()?
            .query_row_cached(
                "SELECT plaintext FROM app_events
             WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND kind = ?3
               AND direction = 'system' AND source_message_id_hex IS NULL
               AND origin_commit_id IS NOT NULL AND length(origin_commit_id) > 0
               AND plaintext = ?4 AND source_epoch IS ?5
               AND length(CAST(plaintext AS BLOB)) <= ?6",
                params![
                    message.group_id_hex,
                    message.message_id_hex,
                    MARMOT_APP_EVENT_KIND_GROUP_SYSTEM as i64,
                    message.plaintext,
                    optional_u64_to_i64(message.source_epoch)?,
                    MAX_CONVERSATION_SYSTEM_BYTES as i64
                ],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }
}
