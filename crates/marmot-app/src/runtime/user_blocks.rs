use super::{MarmotAppRuntime, wait_for_runtime_shutdown};
use crate::{AppError, BlockListSnapshot, BlockedUser, MarmotApp};
use tokio::sync::watch;

pub struct RuntimeBlockListSubscription {
    pub snapshot: BlockListSnapshot,
    app: MarmotApp,
    label: String,
    revision: u64,
    changes: watch::Receiver<u64>,
    stopping: watch::Receiver<bool>,
}
impl RuntimeBlockListSubscription {
    pub async fn recv(&mut self) -> Option<BlockListSnapshot> {
        loop {
            tokio::select! {
                _ = wait_for_runtime_shutdown(&mut self.stopping) => return None,
                result = self.changes.changed() => { if result.is_err() { return None; } }
            }
            let snapshot = self
                .app
                .account_storage(&self.label)
                .ok()?
                .block_list_snapshot()
                .ok()?;
            if snapshot.revision != self.revision {
                self.revision = snapshot.revision;
                return Some(snapshot);
            }
        }
    }
}
impl MarmotAppRuntime {
    pub async fn block_user(
        &self,
        account_ref: &str,
        user_account_id_hex: &str,
    ) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_user_blocked(&account.label, user_account_id_hex, true)
            .await
    }
    pub async fn unblock_user(
        &self,
        account_ref: &str,
        user_account_id_hex: &str,
    ) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .set_user_blocked(&account.label, user_account_id_hex, false)
            .await
    }
    pub fn get_blocked_users(&self, account_ref: &str) -> Result<Vec<BlockedUser>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        Ok(self
            .accounts
            .app
            .account_storage(&account.label)?
            .block_list_snapshot()?
            .users)
    }
    pub fn is_user_blocked(
        &self,
        account_ref: &str,
        user_account_id_hex: &str,
    ) -> Result<bool, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let key = crate::parse_account_id_hex(user_account_id_hex)?;
        Ok(self
            .accounts
            .app
            .account_storage(&account.label)?
            .is_user_blocked(&key)?)
    }
    pub fn subscribe_blocked_users(
        &self,
        account_ref: &str,
    ) -> Result<RuntimeBlockListSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        let changes = app.block_list_updates.subscribe();
        let snapshot = app.account_storage(&account.label)?.block_list_snapshot()?;
        Ok(RuntimeBlockListSubscription {
            revision: snapshot.revision,
            snapshot,
            label: account.label,
            app,
            changes,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }
}
