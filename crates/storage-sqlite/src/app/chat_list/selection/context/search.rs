//! Transient raw search metadata from the existing row projection. This is not
//! a rendered preview, and no attachment metadata escapes app preparation.
use super::*;
#[derive(Clone, PartialEq, Eq)]
pub struct SelectionSearchPreviewInput {
    pub routing_component_hex: Option<String>,
    pub message_id_hex: Option<String>,
    pub plaintext: String,
    pub kind: u64,
    pub deleted: bool,
    pub media_json: Option<String>,
    pub group_system: Option<crate::GroupSystemEventProjection>,
}
impl std::fmt::Debug for SelectionSearchPreviewInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionSearchPreviewInput")
            .finish_non_exhaustive()
    }
}
pub(super) fn search_preview_tx(
    conn: &Connection,
    id: &str,
    component_id: u16,
    remaining: &mut usize,
) -> Result<SelectionSearchPreviewInput, ContextError> {
    const SOURCE: &str = "FROM visible_chat_list_rows row LEFT JOIN account_group_app_components routing ON routing.group_id_hex=row.group_id_hex AND routing.component_id=?2 WHERE row.group_id_hex=?1";
    const VISIBLE: &str = "row.last_message_id_hex IS NOT NULL AND COALESCE(row.last_message_sender IN (SELECT public_key FROM user_blocks),0)=0";
    let sizes_sql = format!(
        "SELECT CASE WHEN {VISIBLE} THEN COALESCE(length(CAST(row.last_message_id_hex AS BLOB)),0) ELSE 0 END, COALESCE(length(CAST(routing.component_data_hex AS BLOB)),0), CASE WHEN {VISIBLE} THEN COALESCE(length(CAST(row.last_message_preview AS BLOB)),0) ELSE 0 END, CASE WHEN {VISIBLE} THEN COALESCE(length(CAST(row.last_message_media_json AS BLOB)),0) ELSE 0 END {SOURCE}"
    );
    let total = conn
        .query_row_cached(&sizes_sql, params![id, component_id], |row| {
            let mut total = 0usize;
            for column in 0..4 {
                let size: i64 = row.get(column)?;
                total = total
                    .checked_add(
                        usize::try_from(size)
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, size))?,
                    )
                    .ok_or(rusqlite::Error::IntegralValueOutOfRange(column, size))?;
            }
            Ok(total)
        })
        .storage()?;
    if total > *remaining {
        return Err(ContextError::ResourceExhausted);
    }
    let sql = format!(
        "SELECT routing.component_data_hex, CASE WHEN {VISIBLE} THEN row.last_message_id_hex ELSE NULL END, CASE WHEN {VISIBLE} THEN row.last_message_preview ELSE '' END, CASE WHEN {VISIBLE} THEN row.last_message_kind ELSE 0 END, CASE WHEN {VISIBLE} THEN row.last_message_deleted ELSE 0 END, CASE WHEN {VISIBLE} THEN row.last_message_media_json ELSE NULL END, CASE WHEN ({VISIBLE}) AND row.last_message_kind=1210 THEN EXISTS (SELECT 1 FROM app_events AS system_source WHERE system_source.group_id_hex=row.group_id_hex AND system_source.message_id_hex=row.last_message_id_hex AND {} AND system_source.plaintext=row.last_message_preview AND system_source.recorded_at=row.last_message_timeline_at) ELSE 0 END {SOURCE}",
        crate::app::group_system::authenticated_system_source_sql!("system_source")
    );
    let input = conn
        .query_row_cached(&sql, params![id, component_id], |row| {
            let plaintext = row.get::<_, Option<String>>(2)?.unwrap_or_default();
            let kind = row
                .get::<_, Option<i64>>(3)?
                .and_then(|n| n.try_into().ok())
                .unwrap_or_default();
            let deleted = row.get(4)?;
            let group_system = crate::app::group_system::projected_group_system(
                kind,
                &plaintext,
                row.get(6)?,
                deleted,
            );
            Ok(SelectionSearchPreviewInput {
                routing_component_hex: row.get(0)?,
                message_id_hex: row.get(1)?,
                plaintext,
                kind,
                deleted,
                media_json: row.get(5)?,
                group_system,
            })
        })
        .storage()?;
    *remaining -= total;
    Ok(input)
}
