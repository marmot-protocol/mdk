//! # storage-sqlite
//!
//! SQLCipher-backed SQLite implementation of the Marmot storage aggregate.
//! The backend stores Marmot metadata and custom OpenMLS storage rows in the
//! same database so group snapshot and rollback can be atomic across both
//! layers.

mod account_projection;
mod chat_list;
mod codec;
mod connection;
mod encrypted_media_secrets;
mod migrations;
mod openmls_storage;
mod shared;
mod storage;
mod timeline;

pub use account_projection::{
    AccountGroupPushToken, AccountNotificationSettings, AccountPushRegistration,
    AccountStoredPushRegistration, StoredAccountGroup, StoredAccountGroupComponent,
    StoredAccountState, StoredAppMessageQuery, StoredAppMessageRecord,
};
pub use chat_list::{
    AccountUnreadTotal, ChatListAvatar, ChatListMessagePreview, ChatListQuery, ChatListRow,
};
#[allow(deprecated)]
pub use connection::SqliteStorage;
pub use connection::{
    SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, SqliteJournalMode,
    SqliteStorageOptions, SqliteSynchronous, open_hardened_sqlcipher,
};
pub use openmls_storage::SqliteOpenMlsStorageError;
pub use shared::{
    PublicDirectoryUserRecord, SqliteSharedStorage, StoredAuditLogSettings,
    StoredRelayTelemetrySettings,
};
pub use timeline::{
    MAX_TIMELINE_LIMIT, StoredAppEvent, TimelineMessageChange, TimelineMessageQuery,
    TimelineMessageRecord, TimelineMessageTarget, TimelinePage, TimelinePagination,
    TimelineProjectionUpdate, TimelineReactionSummary, TimelineRemoveReason, TimelineReplyPreview,
    TimelineUpdateTrigger, TimelineUserReaction,
};

pub(crate) use codec::{
    SqliteResultExt, bool_i64, created_at_to_i64, deserialize, epoch_to_i64, message_state_to_i64,
    optional_u64_to_i64, serialize, tags_from_json, u64_to_i64, unix_now_ms, unix_now_seconds,
    unix_now_seconds_i64, usize_to_i64,
};
