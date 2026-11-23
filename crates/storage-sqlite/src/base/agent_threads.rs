//! SQL access to MDK's agent-thread rule, so a query applies it exactly as
//! the alert path does in Rust.

use rusqlite::functions::FunctionFlags;
use rusqlite::types::ValueRef;

/// `marmot_agent_thread_words(kind, tags_json, sender)`: whether a stored
/// message is an agent's own words in a thread under one of its agent items
/// (`cgka_traits::is_agent_own_thread_comment`, marmot-agents D-122). Always 0
/// or 1: tags that do not decode read as none, and then the message is not.
pub(crate) fn register_agent_thread_functions(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.create_scalar_function(
        "marmot_agent_thread_words",
        3,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |ctx| {
            let (
                ValueRef::Integer(kind),
                ValueRef::Text(tags) | ValueRef::Blob(tags),
                ValueRef::Text(sender),
            ) = (ctx.get_raw(0), ctx.get_raw(1), ctx.get_raw(2))
            else {
                return Ok(false);
            };
            let (Ok(kind), Ok(sender)) = (u64::try_from(kind), std::str::from_utf8(sender)) else {
                return Ok(false);
            };
            // Only a thread message can be one; skip decoding every chat's tags.
            if kind != cgka_traits::NIP22_COMMENT_KIND {
                return Ok(false);
            }
            let tags = serde_json::from_slice::<Vec<Vec<String>>>(tags).unwrap_or_default();
            Ok(cgka_traits::is_agent_own_thread_comment(
                kind, &tags, sender,
            ))
        },
    )
}
