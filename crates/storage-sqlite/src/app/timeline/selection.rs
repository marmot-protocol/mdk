//! Borrowed thin message inputs in the caller's existing read transaction.
//! Both native callbacks are synchronous and cannot retain SQLite row references.
use super::*;

/// Raw inputs for the existing host message-search predicate. No attachment
/// bytes, reply/reaction objects, profile lookups or rendered snippets.
pub struct SelectionMessageInput<'a> {
    pub group_id_hex: &'a str,
    pub message_id_hex: &'a str,
    pub sender: &'a str,
    pub plaintext: &'a str,
    pub media_json: Option<&'a str>,
    pub source_epoch: Option<u64>,
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
    pub retention_seconds: Option<u64>,
    pub retention_expires_at: Option<u64>,
}
impl std::fmt::Debug for SelectionMessageInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionMessageInput")
            .finish_non_exhaustive()
    }
}
impl SqliteAppStorage {
    /// Visits the complete visible account corpus under one snapshot. Native
    /// candidate/kind/deletion admission precedes text copying. A length-only
    /// query budgets source bytes before a keyed needed-input read; raw media
    /// counts conservatively even when its parser later drops fields. SQL LIKE
    /// work and SQLite steps retain the existing nonpreemptible behavior.
    /// Errors fail the whole capture, never a successful prefix.
    pub fn visit_selection_messages(
        &self,
        search: Option<&str>,
        mut source_text_budget: usize,
        cancelled: &impl Fn() -> bool,
        include_message: &impl Fn(&str, u64, bool) -> bool,
        visit: &mut impl FnMut(&SelectionMessageInput<'_>) -> Result<(), crate::ContextError>,
    ) -> Result<(), crate::ContextError> {
        self.connection.with_deferred_read(|conn|{
            let query=TimelineMessageQuery{group_id_hex:None,search:search.map(str::to_owned),pagination:TimelinePagination::default()};
            let pagination=ValidatedPagination{direction:CursorDirection::None,cursor_at:None,cursor_message_id_hex:None,cursor_order:None,inclusive:false,limit:usize::MAX-1};
            let (sql,values)=timeline_query_sql_projection(&query,&pagination,false,true,
                "timeline.group_id_hex,timeline.message_id_hex,timeline.kind,timeline.deleted,length(CAST(timeline.sender AS BLOB)),length(CAST(timeline.plaintext AS BLOB)),COALESCE(length(CAST(timeline.media_json AS BLOB)),0)")?;
            let mut statement=conn.prepare_cached(&sql).storage()?;
            let mut rows=statement.query(params_from_iter(values.iter())).storage()?;
            let mut inputs=conn.prepare_cached("SELECT timeline.sender,timeline.plaintext,timeline.media_json,timeline.source_epoch,timeline.timeline_at,source.retention_seconds,source.retention_expires_at FROM visible_message_timeline timeline LEFT JOIN app_events source ON source.group_id_hex=timeline.group_id_hex AND source.message_id_hex=timeline.message_id_hex WHERE timeline.group_id_hex=?1 AND timeline.message_id_hex=?2").storage()?;
            loop {
                if cancelled(){return Err(crate::ChatListSelectionError::Cancelled.into());}
                let Some(row)=rows.next().storage()? else{return Ok(());};
                let group=row.get_ref(0).storage()?.as_str().map_err(|_|StorageError::Serialization("invalid selection search identity".into()))?;
                let id=row.get_ref(1).storage()?.as_str().map_err(|_|StorageError::Serialization("invalid selection search identity".into()))?;
                let kind=row.get::<_,i64>(2).storage()?.try_into().unwrap_or_default();
                let deleted=row.get(3).storage()?;
                if !include_message(group,kind,deleted){continue;}
                let mut size=id.len();
                for column in 4..7 {
                    let bytes=row.get::<_,i64>(column).storage()?;
                    size=size.checked_add(usize::try_from(bytes).map_err(|_|crate::ContextError::ResourceExhausted)?).ok_or(crate::ContextError::ResourceExhausted)?;
                }
                source_text_budget=source_text_budget.checked_sub(size).ok_or(crate::ContextError::ResourceExhausted)?;
                if cancelled(){return Err(crate::ChatListSelectionError::Cancelled.into());}
                let mut values=inputs.query(params![group,id]).storage()?;
                let input=values.next().storage()?.ok_or(StorageError::NotFound)?;
                let text=|column|->StorageResult<&str>{input.get_ref(column).storage()?.as_str().map_err(|_|StorageError::Serialization("invalid selection search text".into()))};
                let media_json=match input.get_ref(2).storage()? {rusqlite::types::ValueRef::Null=>None,value=>Some(value.as_str().map_err(|_|StorageError::Serialization("invalid selection search media".into()))?)};
                let optional=|column|->StorageResult<Option<u64>>{Ok(input.get::<_,Option<i64>>(column).storage()?.and_then(|value|value.try_into().ok()))};
                visit(&SelectionMessageInput{group_id_hex:group,message_id_hex:id,sender:text(0)?,plaintext:text(1)?,media_json,source_epoch:optional(3)?,kind,timeline_at:input.get::<_,i64>(4).storage()?.try_into().unwrap_or_default(),deleted,retention_seconds:optional(5)?,retention_expires_at:optional(6)?})?;
            }
        })
    }
}
