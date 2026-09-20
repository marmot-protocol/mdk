//! Runtime-only, store-incarnation-scoped permission. Never restore network
//! approval from disk or infer it from durable demand.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use cgka_traits::GroupId;
use storage_sqlite::AttachmentTransferStatus;

use super::{AttachmentCategory, AttachmentLocalTarget, MarmotAppRuntime};
use crate::{AppError, AttachmentAcquisitionMode, CursorPersistence};

/// Runtime-only host approval by media category; false denies network acquisition.
/// Approval is meaningful only with the current account/store generation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttachmentAutomaticPermission {
    /// Permit image attachments.
    pub images: bool,
    /// Permit video attachments.
    pub videos: bool,
    /// Permit audio attachments.
    pub audio: bool,
    /// Permit documents and other MIME types, including APKs.
    pub files: bool,
}
impl AttachmentAutomaticPermission {
    fn allows(self, category: AttachmentCategory) -> bool {
        match category {
            AttachmentCategory::Image => self.images,
            AttachmentCategory::Video => self.videos,
            AttachmentCategory::Audio => self.audio,
            AttachmentCategory::File => self.files,
            AttachmentCategory::Rejected => false,
        }
    }
}

/// Status is authoritative at the transaction boundary; None means obsolete or
/// unavailable source. Queued does not promise network readiness.
#[derive(Debug, Clone)]
pub struct AutomaticAttachmentRequest {
    pub status: Option<AttachmentTransferStatus>,
    pub newly_queued: bool,
}

#[derive(Clone, Default)]
pub(super) struct Permissions(Arc<Mutex<HashMap<Vec<u8>, Permission>>>);
struct Permission {
    account_id: String,
    generation: String,
    applied: bool,
    categories: AttachmentAutomaticPermission,
}

/// An in-flight transfer is tied to one approval, not just the latest bool.
#[derive(Clone)]
pub(crate) struct PermissionLease {
    permissions: Permissions,
    store: Vec<u8>,
    generation: String,
    category: AttachmentCategory,
}
impl PermissionLease {
    /// Check the captured approval immediately before polling network work.
    /// No permission lock is held while external futures execute.
    pub(crate) fn allowed(&self) -> bool {
        self.permissions
            .lock()
            .get(&self.store)
            .is_some_and(|p| p.generation == self.generation && p.categories.allows(self.category))
    }
}
impl Permissions {
    /// A poisoned update revokes all approvals once; a fresh host generation can
    /// recover. Never silently disable the runtime for its remaining lifetime.
    fn lock(&self) -> MutexGuard<'_, HashMap<Vec<u8>, Permission>> {
        match self.0.lock() {
            Ok(map) => map,
            Err(poisoned) => {
                let mut map = poisoned.into_inner();
                map.clear();
                self.0.clear_poison();
                map
            }
        }
    }

    /// Category mask for indexed readmission of parked demand, never new demand.
    pub(super) fn categories(&self, store: &[u8]) -> [bool; 4] {
        self.lock().get(store).map_or([false; 4], |p| {
            [
                p.categories.images,
                p.categories.videos,
                p.categories.audio,
                p.categories.files,
            ]
        })
    }

    /// Shared category decision used by demand, observation and work admission.
    pub(super) fn allows(&self, store: &[u8], media_type: &str) -> bool {
        Self::allows_locked(&self.lock(), store, media_type)
    }

    fn allows_locked(map: &HashMap<Vec<u8>, Permission>, store: &[u8], media_type: &str) -> bool {
        map.get(store).is_some_and(|p| {
            p.categories
                .allows(super::attachment_history::category(media_type))
        })
    }

    pub(super) fn forget_account(&self, account_id: &str) {
        self.lock().retain(|_, p| p.account_id != account_id);
    }

    pub(super) fn lease(&self, store: &[u8], media_type: &str) -> Option<PermissionLease> {
        let map = self.lock();
        let p = map.get(store)?;
        let category = super::attachment_history::category(media_type);
        p.categories.allows(category).then(|| PermissionLease {
            permissions: self.clone(),
            store: store.to_vec(),
            generation: p.generation.clone(),
            category,
        })
    }
}

impl MarmotAppRuntime {
    fn ensure_host_managed_attachments(&self) -> Result<(), AppError> {
        if self.accounts.app.config.attachment_acquisition_mode
            != AttachmentAcquisitionMode::HostManaged
        {
            return Err(AppError::AttachmentModeRequired);
        }
        Ok(())
    }

    /// Revoke current automatic permission and issue a single-use generation.
    /// Call on each network/policy change BEFORE asynchronous policy evaluation;
    /// callbacks must only apply the generation captured for that evaluation.
    pub async fn begin_attachment_permission_update(
        &self,
        account_ref: &str,
    ) -> Result<String, AppError> {
        self.ensure_host_managed_attachments()?;
        let permissions = self.shared.attachment_permissions.clone();
        let app = self.accounts.app.clone();
        let account_reference = account_ref.to_owned();
        let generation = hex::encode(rand::random::<[u8; 32]>());
        let result = self
            .attachment_read(account_ref, move |storage, _| {
                let store = storage.attachment_store_identity()?;
                let mut map = permissions.lock();
                let account = app.account_home().account(&account_reference)?;
                if account.signed_out {
                    return Err(AppError::AttachmentAccountSignedOut);
                }
                map.insert(
                    store,
                    Permission {
                        account_id: account.account_id_hex,
                        generation: generation.clone(),
                        applied: false,
                        categories: AttachmentAutomaticPermission::default(),
                    },
                );
                storage.pause_automatic_attachments(crate::unix_now_seconds())?;
                Ok(generation)
            })
            .await?;
        self.wake_attachment_work();
        Ok(result)
    }

    /// Apply only the current, unused runtime/account generation. Stale callbacks
    /// return false. An empty permission remains denied. Never persists approval.
    pub async fn set_attachment_automatic_permission(
        &self,
        account_ref: &str,
        generation: String,
        categories: AttachmentAutomaticPermission,
    ) -> Result<bool, AppError> {
        let permissions = self.shared.attachment_permissions.clone();
        self.ensure_host_managed_attachments()?;
        let app = self.accounts.app.clone();
        let account_reference = account_ref.to_owned();
        let applied = self
            .attachment_read(account_ref, move |storage, _| {
                let store = storage.attachment_store_identity()?;
                let mut map = permissions.lock();
                if app.account_home().account(&account_reference)?.signed_out {
                    return Ok(false);
                }
                let Some(p) = map.get_mut(&store) else {
                    return Ok(false);
                };
                if p.applied || p.generation != generation {
                    return Ok(false);
                }
                p.categories = categories;
                p.applied = true;
                Ok(true)
            })
            .await?;
        if applied {
            self.wake_attachment_work();
        }
        Ok(applied)
    }

    /// Idempotent automatic demand. Never clears suppression, resets backoff or
    /// retry budgets, or reacquires a source whose bytes have been lost.
    pub async fn request_automatic_attachment(
        &self,
        account_ref: &str,
        group: &GroupId,
        mut target: AttachmentLocalTarget,
    ) -> Result<AutomaticAttachmentRequest, AppError> {
        self.ensure_host_managed_attachments()?;
        super::attachment_access::validate_targets(std::slice::from_mut(&mut target))?;
        let group = hex::encode(group.as_slice());
        let permissions = self.shared.attachment_permissions.clone();
        let config = self.accounts.app.config.clone();
        let result = self
            .attachment_read(account_ref, move |storage, loopback| {
                let now = crate::unix_now_seconds();
                let unavailable = || AutomaticAttachmentRequest {
                    status: None,
                    newly_queued: false,
                };
                let Some(entry) = storage.attachment_control_entry(
                    &group,
                    &target.message_id_hex,
                    &target.source_message_id_hex,
                    target.attachment_index,
                    now,
                )?
                else {
                    return Ok(unavailable());
                };
                let Some(epoch) = entry.source_epoch else {
                    return Ok(unavailable());
                };
                let Ok(tag) = serde_json::from_value::<Vec<String>>(entry.slot.clone()) else {
                    return Ok(unavailable());
                };
                let Ok(reference) = crate::parse_media_attachment(&tag, Some(epoch), loopback)
                else {
                    return Ok(unavailable());
                };
                let digest = crate::media::media_hash_from_reference(&reference)?;
                let identity = storage.attachment_store_identity()?;
                // Serialize admission with revocation; never hold this lock over asynchronous IO.
                let map = permissions.lock();
                let allowed = config.cursor_persistence != CursorPersistence::Frozen
                    && (config.attachment_acquisition_mode
                        == AttachmentAcquisitionMode::NativeAutomatic
                        || Permissions::allows_locked(&map, &identity, &reference.media_type));
                let (status, newly_queued) = storage.request_automatic_attachment(
                    &group,
                    &entry,
                    digest,
                    now,
                    (
                        &super::attachment_controls::default_policy(&config),
                        allowed,
                    ),
                )?;
                Ok(AutomaticAttachmentRequest {
                    status,
                    newly_queued,
                })
            })
            .await?;
        if result.newly_queued {
            self.wake_attachment_work();
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_permission_poison_revokes_once_and_accepts_fresh_approval() {
        let permissions = Permissions::default();
        let make = |generation: &str| Permission {
            account_id: "test".to_owned(),
            generation: generation.to_owned(),
            applied: true,
            categories: AttachmentAutomaticPermission {
                files: true,
                ..Default::default()
            },
        };
        permissions.lock().insert(vec![1], make("old"));
        let old = permissions.lease(&[1], "application/octet-stream").unwrap();
        let _ = std::panic::catch_unwind(|| {
            let _guard = permissions.0.lock().unwrap();
            panic!("injected permission update failure");
        });
        assert!(!old.allowed());
        permissions.lock().insert(vec![1], make("fresh"));
        assert!(!old.allowed());
        assert!(
            permissions
                .lease(&[1], "application/octet-stream")
                .unwrap()
                .allowed()
        );
    }

    #[test]
    fn automatic_permission_uses_shared_mime_categories() {
        let files = AttachmentAutomaticPermission {
            files: true,
            ..Default::default()
        };
        for (mime, expected) in [
            ("application/vnd.android.package-archive", true),
            ("application/octet-stream", true),
            ("image/png", false),
            ("VIDEO/mp4", false),
            ("audio/ogg", false),
        ] {
            assert_eq!(
                files.allows(super::super::attachment_history::category(mime)),
                expected
            );
        }
        assert!(!files.allows(AttachmentCategory::Rejected));
    }
}
