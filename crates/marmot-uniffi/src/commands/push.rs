//! Native-push registration and group push-debug commands.

use crate::Marmot;
use crate::conversions::{
    GroupPushDebugInfoFfi, PushPlatformFfi, PushRegistrationFfi, PushRegistrationShareOutcomeFfi,
    PushRegistrationSyncResultFfi, group_id_from_hex,
};
use crate::errors::MarmotKitError;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    pub fn push_registration(
        &self,
        account_ref: String,
    ) -> Result<Option<PushRegistrationFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .push_registration(&account_ref)?
            .map(Into::into))
    }

    pub async fn upsert_push_registration(
        &self,
        account_ref: String,
        platform: PushPlatformFfi,
        raw_token: String,
        server_pubkey_hex: String,
        relay_hint: Option<String>,
    ) -> Result<PushRegistrationSyncResultFfi, MarmotKitError> {
        let raw_token = zeroize::Zeroizing::new(raw_token);
        Ok(self
            .runtime
            .upsert_push_registration(
                &account_ref,
                platform.into(),
                &raw_token,
                &server_pubkey_hex,
                relay_hint,
            )
            .await?
            .into())
    }

    pub async fn clear_push_registration(
        &self,
        account_ref: String,
    ) -> Result<PushRegistrationShareOutcomeFfi, MarmotKitError> {
        Ok(self
            .runtime
            .clear_push_registration(&account_ref)
            .await?
            .into())
    }

    pub async fn group_push_debug_info(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupPushDebugInfoFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .group_push_debug_info(&account_ref, &group_id)
            .await?
            .into())
    }
}
