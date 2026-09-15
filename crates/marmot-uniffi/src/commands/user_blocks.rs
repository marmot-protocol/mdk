//! Account-private user blocking and its revisioned subscription.
use crate::{Marmot, MarmotKitError};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

#[derive(Clone, uniffi::Record)]
pub struct BlockedUserFfi {
    pub public_key: String,
    pub is_private: bool,
    pub created_at_ms: i64,
}
impl From<marmot_app::BlockedUser> for BlockedUserFfi {
    fn from(value: marmot_app::BlockedUser) -> Self {
        Self {
            public_key: value.public_key,
            is_private: value.is_private,
            created_at_ms: value.created_at_ms,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct BlockListSnapshotFfi {
    pub revision: u64,
    pub users: Vec<BlockedUserFfi>,
}
impl From<marmot_app::BlockListSnapshot> for BlockListSnapshotFfi {
    fn from(value: marmot_app::BlockListSnapshot) -> Self {
        Self {
            revision: value.revision,
            users: value.users.into_iter().map(Into::into).collect(),
        }
    }
}
#[derive(uniffi::Object)]
pub struct BlockListSubscription {
    snapshot: StdMutex<Option<BlockListSnapshotFfi>>,
    inner: Mutex<marmot_app::RuntimeBlockListSubscription>,
}
#[uniffi::export(async_runtime = "tokio")]
impl BlockListSubscription {
    pub fn snapshot(&self) -> Option<BlockListSnapshotFfi> {
        self.snapshot.lock().ok()?.take()
    }
    pub async fn next(&self) -> Option<BlockListSnapshotFfi> {
        self.inner.lock().await.recv().await.map(Into::into)
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    pub async fn block_user(
        &self,
        account_ref: String,
        user_account_id_hex: String,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .block_user(&account_ref, &user_account_id_hex)
            .await?)
    }
    pub async fn unblock_user(
        &self,
        account_ref: String,
        user_account_id_hex: String,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .unblock_user(&account_ref, &user_account_id_hex)
            .await?)
    }
    pub fn get_blocked_users(
        &self,
        account_ref: String,
    ) -> Result<Vec<BlockedUserFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .get_blocked_users(&account_ref)?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    pub fn is_user_blocked(
        &self,
        account_ref: String,
        user_account_id_hex: String,
    ) -> Result<bool, MarmotKitError> {
        Ok(self
            .runtime
            .is_user_blocked(&account_ref, &user_account_id_hex)?)
    }
    pub fn subscribe_blocked_users(
        &self,
        account_ref: String,
    ) -> Result<Arc<BlockListSubscription>, MarmotKitError> {
        let inner = self.runtime.subscribe_blocked_users(&account_ref)?;
        Ok(Arc::new(BlockListSubscription {
            snapshot: StdMutex::new(Some(inner.snapshot.clone().into())),
            inner: Mutex::new(inner),
        }))
    }
}
