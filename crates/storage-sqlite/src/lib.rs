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
pub use chat_list::{ChatListAvatar, ChatListMessagePreview, ChatListQuery, ChatListRow};
#[allow(deprecated)]
pub use connection::SqliteStorage;
pub use connection::{
    SqlCipherKey, SqliteAccountStorage, SqliteJournalMode, SqliteStorageOptions, SqliteSynchronous,
};
pub use openmls_storage::SqliteOpenMlsStorageError;
pub use shared::{PublicDirectoryUserRecord, SqliteSharedStorage};
pub use timeline::{
    StoredAppEvent, TimelineMessageChange, TimelineMessageQuery, TimelineMessageRecord,
    TimelinePage, TimelinePagination, TimelineProjectionUpdate, TimelineReactionSummary,
    TimelineRemoveReason, TimelineReplyPreview, TimelineUpdateTrigger, TimelineUserReaction,
};

pub(crate) use codec::{
    SqliteResultExt, created_at_to_i64, deserialize, epoch_to_i64, message_state_to_i64, serialize,
};
