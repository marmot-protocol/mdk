//! Local source selection for explicitly requested identities; no roster crawl.
use crate::{AppError, MarmotApp};
use storage_sqlite::{AvatarAssetRef, ChatPresentationInput, SelectedAvatar};

impl MarmotApp {
    /// Record visible identity-avatar demand using cached local metadata. Returns
    /// immediately without engine/relay/HTTP work. C7-C adds native batch access.
    pub fn request_identity_avatar(
        &self,
        label: &str,
        group: &str,
        member: &str,
    ) -> Result<Option<AvatarAssetRef>, AppError> {
        let member = crate::chat_presentation::canonical_identity(member)
            .ok_or_else(|| AppError::InvalidEncryptedMedia("invalid avatar identity".into()))?;
        let account = self.account_home().account(label)?;
        let storage = self.account_storage(label)?;
        let input = storage.chat_presentation_input(group)?.ok_or_else(|| {
            AppError::InvalidEncryptedMedia("avatar conversation unavailable".into())
        })?;
        let (selected, version) =
            selected_identity(self, &input, &account.account_id_hex, &member)?;
        let reference =
            storage.request_identity_avatar_acquisition(group, &member, &selected, &version)?;
        self.presentation_signals.wake();
        Ok(reference)
    }
}

fn selected_identity(
    app: &MarmotApp,
    input: &ChatPresentationInput,
    account: &str,
    member: &str,
) -> Result<(SelectedAvatar, storage_sqlite::ChatPresentationVersion), AppError> {
    let record = app.shared_storage()?.directory_presentation(member)?;
    let profile = record
        .profile_json
        .map(|json| serde_json::from_str::<crate::UserProfileMetadata>(&json))
        .transpose()
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid avatar profile".into()))?;
    let key = |kind, parts: &[&str]| {
        crate::chat_presentation::presentation_cache_key(input, account, member, kind, parts)
    };
    Ok((
        match profile
            .and_then(|p| p.picture)
            .and_then(|url| crate::chat_presentation::safe_image_url(&url))
        {
            Some(url) => SelectedAvatar::RemoteImage {
                cache_key: key("peer-url", &[&url]),
                url,
            },
            None => SelectedAvatar::Placeholder {
                stable_seed: key("person", &[]),
                source: crate::PresentationSource::PeerFallback,
            },
        },
        record.version,
    ))
}

#[derive(Default)]
pub(super) struct IdentityAvatarMaintenance {
    after: String,
}
impl IdentityAvatarMaintenance {
    pub(super) fn run(&mut self, client: &crate::AppClient, account: &str) -> Result<(), AppError> {
        let storage = client.app.account_storage(&client.state.label)?;
        let identities = storage.requested_avatar_identities_after(&self.after)?;
        self.after = if identities.len() == 64 {
            identities.last().unwrap().owner.clone()
        } else {
            String::new()
        };
        let mut failure = None;
        for identity in &identities {
            let result = (|| -> Result<(), AppError> {
                if let Some(input) = storage.chat_presentation_input(&identity.group)? {
                    let (selected, version) =
                        selected_identity(&client.app, &input, account, &identity.member)?;
                    storage.maintain_identity_avatar_acquisition(identity, &selected, &version)?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                failure = Some(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_account::AccountHome;
    use std::sync::Arc;
    use storage_sqlite::PublicDirectoryUserRecord;

    #[tokio::test]
    async fn requested_identity_avatar_tracks_later_profile_without_an_open_window() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = hex::encode(
            client
                .create_group("Avatar test", &[])
                .await
                .unwrap()
                .as_slice(),
        );
        let member = "bb".repeat(32);
        assert!(
            app.request_identity_avatar("alice", &group, &member)
                .unwrap()
                .is_none()
        );
        let storage = app.account_storage("alice").unwrap();
        let owner = storage.requested_avatar_identities_after("").unwrap()[0]
            .owner
            .clone();
        app.shared_storage()
            .unwrap()
            .put_public_directory_user(&PublicDirectoryUserRecord {
                account_id_hex: member.clone(),
                npub: "fixture".into(),
                profile_json: Some(
                    serde_json::to_string(&crate::UserProfileMetadata {
                        picture: Some("https://example.com/avatar.png".into()),
                        ..Default::default()
                    })
                    .unwrap(),
                ),
                relay_lists_json: "{}".into(),
                key_package_json: None,
                event_id_hex: None,
                event_kind: None,
                event_created_at: None,
                follows: vec![],
            })
            .unwrap();
        IdentityAvatarMaintenance::default()
            .run(&client, &account.account_id_hex)
            .unwrap();
        let reference = storage.avatar_reference(&owner).unwrap().unwrap();
        assert_eq!(
            storage
                .claim_avatar_acquisition(0)
                .unwrap()
                .unwrap()
                .reference,
            reference
        );
        // Removal during the shared-profile preparation gap must not recreate demand.
        storage.remove_avatar_source(&reference).unwrap();
        IdentityAvatarMaintenance::default()
            .run(&client, &account.account_id_hex)
            .unwrap();
        assert!(storage.avatar_reference(&owner).unwrap().is_none());
    }
}
