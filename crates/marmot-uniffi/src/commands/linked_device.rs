//! This account's own devices, from its device group's roster, and whether
//! this device's KeyPackage refresh is held back by its device group.

use crate::Marmot;
use crate::conversions::LinkedDeviceFfi;
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// This account's own devices, from the roster of the device group this
    /// device trusts: this device first, then by when each was linked. Empty
    /// until this device trusts a device group, and always empty in release
    /// builds until the roster's spec lands. Refresh on `LinkedDevicesChanged`.
    pub async fn linked_devices(
        &self,
        account_ref: String,
    ) -> Result<Vec<LinkedDeviceFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .linked_devices(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Whether this device's KeyPackage refresh is overdue because its
    /// device group can't take the announcement that must come first. While
    /// it is, warn the user: after 30 days inviters stop treating this device
    /// as fresh. Always false until this device trusts a device group, and in
    /// release builds until the device group's spec lands. Refresh on
    /// `KeyPackageRefreshOverdueChanged`.
    pub async fn key_package_refresh_overdue(
        &self,
        account_ref: String,
    ) -> Result<bool, MarmotKitError> {
        Ok(self
            .runtime
            .key_package_refresh_overdue(&account_ref)
            .await?)
    }
}
