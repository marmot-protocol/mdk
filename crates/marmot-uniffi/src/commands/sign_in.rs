//! Sign-ins of this account that this device does not recognize.

use crate::Marmot;
use crate::conversions::{SignInResponseFfi, UnrecognizedSignInFfi};
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Sign-ins of this account that this device does not recognize, the
    /// earliest to appear first. For one that is `before_this_device`, ask
    /// whether the user still has it; for any other, ask whether it was them.
    /// Always empty in release builds until the roster's spec lands. Refresh
    /// on `UnrecognizedSignInsChanged`.
    pub async fn unrecognized_sign_ins(
        &self,
        account_ref: String,
    ) -> Result<Vec<UnrecognizedSignInFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .unrecognized_sign_ins(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Answer the unrecognized sign-in in `slot_id_hex`. `Reject` records it
    /// in the device group's roster, now or once that is possible. `Dismiss`
    /// only ends a prompt another device already answered.
    pub async fn answer_sign_in(
        &self,
        account_ref: String,
        slot_id_hex: String,
        response: SignInResponseFfi,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .answer_sign_in(&account_ref, &slot_id_hex, response.into())
            .await?)
    }

    /// Check the account's KeyPackage slots for new sign-ins now and return
    /// the list after the check. A read that reached no relay fails.
    pub async fn check_sign_ins(
        &self,
        account_ref: String,
    ) -> Result<Vec<UnrecognizedSignInFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .check_sign_ins(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Start this device without the devices its first check found ("No,
    /// start fresh"): each sign-in from before this device is answered Not
    /// now, now and when one is listed later. It rejects nothing and raises
    /// no warning, so one of those devices can still link this one. Fails
    /// before the first check and once this device trusts a device group.
    pub async fn start_fresh(&self, account_ref: String) -> Result<(), MarmotKitError> {
        Ok(self.runtime.start_fresh(&account_ref).await?)
    }

    /// Whether this device started fresh and still has no device group, so
    /// the app can say that only chats it is invited to from now on are here.
    /// Always false in release builds until the roster's spec lands.
    pub async fn started_fresh(&self, account_ref: String) -> Result<bool, MarmotKitError> {
        Ok(self.runtime.started_fresh(&account_ref).await?)
    }
}
