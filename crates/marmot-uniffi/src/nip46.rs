use std::sync::Arc;

use marmot_app::{Nip46Error, Nip46Permissions, Nip46Session, Nip46State, Nip46Status};
use zeroize::Zeroizing;

use crate::{Marmot, MarmotKitError, conversions::AccountSummaryFfi, endpoints};

/// Privacy-safe remote signer failures, independent of host callback errors.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum Nip46ErrorFfi {
    #[error("invalid NIP-46 configuration or protocol response")]
    Invalid,
    #[error("invalid proxy configuration")]
    ProxyConfig,
    #[error("remote signer unavailable")]
    Unavailable,
    #[error("remote signer request publication failed")]
    RelayPublish,
    #[error("remote signer rejected the request")]
    Rejected,
    #[error("remote signer identity or signed event mismatch")]
    Mismatch,
    #[error("remote signer request timed out")]
    Timeout,
    #[error("remote signer request cancelled")]
    Cancelled,
    #[error("remote signer session logged out")]
    LoggedOut,
    #[error("remote signer does not support the method")]
    Unsupported,
    #[error("remote signer permissions require approval")]
    PermissionApprovalRequired,
    #[error("remote signer credential storage failed")]
    Storage,
    #[error("remote signer is busy")]
    Busy,
    #[error("remote signer disconnected")]
    Disconnected,
    #[error("remote signer request not found")]
    RequestNotFound,
}

impl From<Nip46Error> for Nip46ErrorFfi {
    fn from(error: Nip46Error) -> Self {
        match error {
            Nip46Error::Invalid => Self::Invalid,
            Nip46Error::ProxyConfig => Self::ProxyConfig,
            Nip46Error::Unavailable => Self::Unavailable,
            Nip46Error::RelayPublish => Self::RelayPublish,
            Nip46Error::Rejected => Self::Rejected,
            Nip46Error::Mismatch => Self::Mismatch,
            Nip46Error::Timeout => Self::Timeout,
            Nip46Error::Cancelled => Self::Cancelled,
            Nip46Error::LoggedOut => Self::LoggedOut,
            Nip46Error::Unsupported => Self::Unsupported,
            Nip46Error::PermissionApprovalRequired => Self::PermissionApprovalRequired,
            Nip46Error::Storage => Self::Storage,
            Nip46Error::Busy => Self::Busy,
            Nip46Error::Disconnected => Self::Disconnected,
            Nip46Error::RequestNotFound => Self::RequestNotFound,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Nip46StateFfi {
    Unavailable,
    PermissionApproval,
    Connecting,
    Ready,
    Approval,
    Disconnected,
    Cancelled,
    LoggedOut,
    Reconnecting,
    Listening,
}

impl From<Nip46State> for Nip46StateFfi {
    fn from(state: Nip46State) -> Self {
        match state {
            Nip46State::Unavailable => Self::Unavailable,
            Nip46State::PermissionApproval => Self::PermissionApproval,
            Nip46State::Connecting => Self::Connecting,
            Nip46State::Ready => Self::Ready,
            Nip46State::Approval => Self::Approval,
            Nip46State::Disconnected => Self::Disconnected,
            Nip46State::Cancelled => Self::Cancelled,
            Nip46State::LoggedOut => Self::LoggedOut,
            Nip46State::Reconnecting => Self::Reconnecting,
            Nip46State::Listening => Self::Listening,
        }
    }
}

/// Permission snapshot shown to the user before granting signer access.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Nip46PermissionsFfi {
    pub version: u32,
    pub grants: Vec<String>,
}

impl From<Nip46Permissions> for Nip46PermissionsFfi {
    fn from(permissions: Nip46Permissions) -> Self {
        Self {
            version: permissions.version,
            grants: permissions.grants,
        }
    }
}

/// Snapshot without keys, pairing URIs, or signer request payloads.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Nip46StatusFfi {
    pub state: Nip46StateFfi,
    pub last_error: Option<Nip46ErrorFfi>,
    pub auth_url: Option<String>,
    pub request_id: Option<String>,
    pub generation: u64,
}

impl From<Nip46Status> for Nip46StatusFfi {
    fn from(status: Nip46Status) -> Self {
        Self {
            state: status.state.into(),
            last_error: status.last_error.map(Into::into),
            auth_url: status.auth_url,
            request_id: status.request_id,
            generation: status.generation,
        }
    }
}

/// MDK-owned remote signer. No foreign signer callbacks are retained.
#[derive(uniffi::Object)]
pub struct Nip46SessionFfi {
    inner: Nip46Session,
}

impl Nip46SessionFfi {
    fn new(inner: Nip46Session) -> Arc<Self> {
        Arc::new(Self { inner })
    }

    fn check_owner(&self, owner: &Marmot) -> Result<(), MarmotKitError> {
        if self.inner.belongs_to(&owner.app) {
            Ok(())
        } else {
            Err(MarmotKitError::ExternalSignerMismatch)
        }
    }
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Nip46SessionFfi {
    /// Return the currently required grants without approving them.
    pub fn permissions(&self) -> Nip46PermissionsFfi {
        Nip46Session::permissions().into()
    }

    /// Record the exact version and grants presented for user review.
    pub fn review_permissions(&self) -> Nip46PermissionsFfi {
        self.inner.review_permissions().into()
    }

    /// Approve only the exact snapshot returned by review_permissions.
    #[marmot_uniffi_macros::survives_cancellation]
    pub async fn approve_permissions(
        &self,
        version: u32,
        grants: Vec<String>,
    ) -> Result<(), Nip46ErrorFfi> {
        let session = self.inner.clone();
        tokio::task::spawn_blocking(move || session.approve_permissions(version, grants))
            .await
            .map_err(|_| Nip46ErrorFfi::Unavailable)?
            .map_err(Into::into)
    }

    /// Pair or reconnect and verify the pinned account identity.
    pub async fn connect(&self) -> Result<String, Nip46ErrorFfi> {
        self.inner.connect_async().await.map_err(Into::into)
    }

    /// Start listening before displaying a client-initiated pairing URI.
    pub async fn pairing_offer(&self) -> Result<String, Nip46ErrorFfi> {
        self.inner.pairing_offer().await.map_err(Into::into)
    }

    /// Return the credential-bearing pairing URI after permission approval.
    pub fn uri(&self) -> Result<String, Nip46ErrorFfi> {
        self.inner.uri().map_err(Into::into)
    }

    /// Export secret credentials for an optional encrypted-vault backup.
    pub fn export(&self) -> Result<String, Nip46ErrorFfi> {
        self.inner.export().map_err(Into::into)
    }

    /// Read typed local status without network access.
    pub fn status(&self) -> Nip46StatusFfi {
        self.inner.status().into()
    }

    /// Read the compatibility JSON status without network access.
    pub fn state_json(&self) -> Result<String, Nip46ErrorFfi> {
        self.inner.state_json().map_err(Into::into)
    }

    /// Check the remote signer through the shared transport.
    pub async fn ping(&self) -> Result<(), Nip46ErrorFfi> {
        self.inner.ping_async().await.map_err(Into::into)
    }

    /// Interrupt transport work while permitting a later explicit reconnect.
    pub fn disconnect(&self) {
        self.inner.disconnect();
    }

    /// Cancel one matching request without cancelling another session or request.
    pub fn cancel_request(&self, request_id: String) -> Result<(), Nip46ErrorFfi> {
        self.inner.cancel_request(&request_id).map_err(Into::into)
    }

    /// Acknowledge one matching authentication challenge; the RPC still awaits its response.
    pub fn complete_auth(&self, request_id: String) -> Result<(), Nip46ErrorFfi> {
        self.inner.complete_auth(&request_id).map_err(Into::into)
    }

    /// Permanently cancel this session and interrupt pending work.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Attempt bounded remote logout and erase local communication credentials.
    #[marmot_uniffi_macros::survives_cancellation]
    pub async fn logout(&self) -> Result<(), Nip46ErrorFfi> {
        let session = self.inner.clone();
        tokio::task::spawn_blocking(move || session.logout())
            .await
            .map_err(|_| Nip46ErrorFfi::Unavailable)?
            .map_err(Into::into)
    }
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Create an offline session; review and approve permissions before pairing.
    pub fn nip46_new(&self, config_json: String) -> Result<Arc<Nip46SessionFfi>, MarmotKitError> {
        let config_json = Zeroizing::new(config_json);
        let session = self.runtime.nip46_new(&config_json)?;
        Ok(Nip46SessionFfi::new(session))
    }

    /// Log in with an MDK session and persist its credentials in the configured secret store.
    pub async fn nip46_login(
        &self,
        session: Arc<Nip46SessionFfi>,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
        inbox_relays: Vec<String>,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        session.check_owner(self)?;
        let account = self
            .runtime
            .nip46_login(
                session.inner.clone(),
                endpoints(&default_relays),
                endpoints(&bootstrap_relays),
                endpoints(&inbox_relays),
            )
            .await?;
        Ok(AccountSummaryFfi {
            label: account.label,
            account_id_hex: account.account_id_hex,
            local_signing: account.local_signing,
            external_signing: account.external_signing,
            signed_out: account.signed_out,
            running: true,
            unlinked: account.unlinked,
        })
    }

    /// Attach an imported session to its existing account and persist verified credentials.
    pub async fn nip46_register(
        &self,
        account_ref: String,
        session: Arc<Nip46SessionFfi>,
    ) -> Result<(), MarmotKitError> {
        session.check_owner(self)?;
        self.runtime
            .nip46_register(&account_ref, session.inner.clone())
            .await?;
        Ok(())
    }

    /// Restore an account's MDK-owned session without a host descriptor or signer callback.
    pub async fn nip46_resume(
        &self,
        account_ref: String,
    ) -> Result<Arc<Nip46SessionFfi>, MarmotKitError> {
        let session = self.runtime.nip46_resume(&account_ref).await?;
        Ok(Nip46SessionFfi::new(session))
    }

    /// Remove the account-scoped signer credentials and detach the shared session.
    pub async fn nip46_remove(&self, account_ref: String) -> Result<(), MarmotKitError> {
        self.runtime.nip46_remove(&account_ref).await?;
        Ok(())
    }
}
