//! Private synchronous composition. No worker command, FFI or selection handle.
use super::AppClient;
use crate::AppError;
#[cfg(test)]
use crate::smart_folder::{CompiledNativeFolder, SmartFolderError, SmartFolderPredicate};
use cgka_traits::EngineError;
use std::collections::HashSet;
#[cfg(test)]
use storage_sqlite::ChatListView;
use storage_sqlite::{ContextCaptureError, PeerInputs};

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeFolderCaptureError {
    #[cfg(test)]
    #[error("native folder rule is unsupported or invalid: {0:?}")]
    Rule(SmartFolderError),
    #[error(transparent)]
    Capture(#[from] ContextCaptureError<EngineError>),
    #[error(transparent)]
    App(#[from] AppError),
    #[error(transparent)]
    Storage(#[from] cgka_traits::StorageError),
}
impl AppClient {
    /// Explicit native view only. This private prerequisite does not admit a
    /// whole Android folder or authorize a future action from captured IDs.
    #[cfg(test)]
    pub(crate) fn capture_native_folder_context(
        &self,
        view: ChatListView,
        predicate: &SmartFolderPredicate,
        capture_now_ms: i64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Vec<String>, NativeFolderCaptureError> {
        let compiled =
            CompiledNativeFolder::new(predicate).map_err(NativeFolderCaptureError::Rule)?;
        self.with_selection_snapshot(cancelled, |store, check, peer| {
            let members = compiled.keys.as_ref().map(|keys| (keys, peer));
            let ids = store
                .app_storage()
                .capture_chat_list_context_ids_with_members(
                    view,
                    compiled.request,
                    capture_now_ms,
                    cancelled,
                    members,
                    &mut |group| check(group),
                    &mut |context| compiled.matches(context),
                )?;
            Ok(ids)
        })
    }
    /// One actual session snapshot with the already-cached presentation owner
    /// and persisted epoch checked again after outer SQL teardown.
    #[cfg(test)]
    pub(super) fn with_selection_snapshot<T>(
        &self,
        cancelled: &impl Fn() -> bool,
        capture: impl FnOnce(
            &storage_sqlite::SqliteAccountStorage,
            &dyn Fn(&cgka_traits::GroupId) -> Result<(), EngineError>,
            PeerInputs<'_>,
        ) -> Result<T, NativeFolderCaptureError>,
    ) -> Result<T, NativeFolderCaptureError> {
        self.with_selection_snapshot_bound(cancelled, capture)
            .map(|(value, _, _)| value)
    }
    pub(super) fn with_selection_snapshot_bound<T>(
        &self,
        cancelled: &impl Fn() -> bool,
        capture: impl FnOnce(
            &storage_sqlite::SqliteAccountStorage,
            &dyn Fn(&cgka_traits::GroupId) -> Result<(), EngineError>,
            PeerInputs<'_>,
        ) -> Result<T, NativeFolderCaptureError>,
    ) -> Result<(T, storage_sqlite::SqliteAccountStorage, Vec<u8>), NativeFolderCaptureError> {
        self.app.ensure_storage_open("native selection")?;
        // The engine intentionally owns a distinct connection. Freeze only the
        // already-cached presentation owner; never lazily reopen it here.
        let owner_storage = self
            .app
            .account_storages
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&self.state.label)
            .cloned()
            .ok_or(AppError::RuntimeStopping)?;
        let owner_epoch = owner_storage
            .app_storage()
            .chat_presentation_version()?
            .store_epoch;
        let session = self.runtime.session();
        let active: [u8; 32] = session.self_id().as_slice().try_into().map_err(|_| {
            cgka_traits::StorageError::Serialization(
                "invalid native selection active identity".into(),
            )
        })?;
        let account = self
            .app
            .account_home()
            .account(&self.state.label)
            .map_err(AppError::from)?;
        if account.account_id_hex != hex::encode(active) {
            return Err(AppError::from(marmot_account::AccountHomeError::AccountIdMismatch).into());
        }
        let check_owner = || -> Result<(), AppError> {
            self.app.ensure_storage_open("native selection")?;
            if cancelled()
                || owner_storage.is_closed()
                || !self
                    .app
                    .account_storage_is_current(&self.state.label, &owner_storage)
            {
                return Err(AppError::RuntimeStopping);
            }
            if self
                .app
                .account_home()
                .account(&self.state.label)?
                .account_id_hex
                != account.account_id_hex
            {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            Ok(())
        };
        check_owner()?;
        // Freeze the same local-profile key presence used by members(); names
        // and directory storage never enter the held SQL callback.
        let local: HashSet<[u8; 32]> = self
            .app
            .profiles_by_id()?
            .keys()
            .filter_map(|key| {
                let mut id = [0; 32];
                hex::decode_to_slice(key, &mut id).ok().map(|()| id)
            })
            .collect();
        check_owner()?;
        let ids =
            session.with_members_read_snapshot::<_, NativeFolderCaptureError>(|store, check| {
                if store.app_storage().chat_presentation_version()?.store_epoch != owner_epoch {
                    return Err(AppError::RuntimeStopping.into());
                }
                capture(
                    store,
                    check,
                    PeerInputs {
                        active: Some(active),
                        local_profile_ids: &local,
                    },
                )
            })?;
        // Recheck only after query-only restoration and outer transaction teardown.
        // The cached owner witness is distinct from the exact session SQL store.
        check_owner()?;
        Ok((ids, owner_storage, owner_epoch))
    }
}

#[cfg(test)]
mod tests;
