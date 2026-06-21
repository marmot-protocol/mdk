//! Account lifecycle, identity, relay-list, key-package, and profile commands.

use marmot_app::{AccountSetupRequest, UserProfileMetadata};

use crate::conversions::{AccountSummaryFfi, UserProfileMetadataFfi};
use crate::errors::MarmotKitError;
use crate::{Marmot, conversions, endpoints};

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    // -----------------------------------------------------------------------
    // Accounts
    // -----------------------------------------------------------------------

    /// All accounts known to the runtime, in stable order. `running` is
    /// `false` for accounts that haven't been brought up by the current
    /// process yet.
    pub fn list_accounts(&self) -> Result<Vec<AccountSummaryFfi>, MarmotKitError> {
        let managed = self.runtime.accounts().managed_accounts()?;
        Ok(managed
            .into_iter()
            .map(|m| AccountSummaryFfi {
                label: m.label,
                account_id_hex: m.account_id_hex,
                local_signing: m.local_signing,
                signed_out: m.signed_out,
                running: m.running,
            })
            .collect())
    }

    /// Per-account unread aggregate for the account-switcher badge
    /// (darkmatter#461). Each entry's `unread_count` is read from that
    /// account's materialized chat-list projection, so this does not require
    /// switching into, or loading a full session/timeline for, any account —
    /// non-active (not-`running`) accounts are reported too. Only
    /// local-signing accounts are included, matching `list_accounts`.
    pub fn account_unread_summary(
        &self,
    ) -> Result<Vec<conversions::AccountUnreadFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .account_unread_summary()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Remove a local-signing account from this device.
    pub async fn remove_account(&self, account_ref: String) -> Result<(), MarmotKitError> {
        self.runtime.accounts().remove_account(&account_ref).await?;
        Ok(())
    }

    /// Destructive sign-out: leave every active MLS group (best-effort), delete
    /// the account's relay-published KeyPackages, then wipe all local state for
    /// this account (MLS state DB, cached media/secrets, SQL account row, and
    /// the secret-store nsec). After this returns the account ref is no longer
    /// valid for any further FFI call. The returned `WipeOutcomeFfi` reports
    /// each stage independently so the app can show progress and a
    /// partial-failure sheet (darkmatter#478).
    pub async fn sign_out_and_wipe(
        &self,
        account_ref: String,
    ) -> Result<conversions::WipeOutcomeFfi, MarmotKitError> {
        Ok(self.runtime.sign_out_and_wipe(&account_ref).await?.into())
    }

    /// Non-destructive sign-out: deactivate the account on this device and,
    /// when `delete_key_packages` is `true` (the default behavior in the UI),
    /// publish kind:5 deletions for its relay-published KeyPackages so
    /// strangers cannot gift-wrap a Welcome into a new group while it is signed
    /// out.
    ///
    /// Unlike [`sign_out_and_wipe`](Self::sign_out_and_wipe) /
    /// [`remove_account`](Self::remove_account), this keeps ALL local state on
    /// device — the SQLCipher session database (MLS state + projections), cached
    /// media/secrets, the SQL account record, and the secret-store nsec — so the
    /// same identity can be signed back in from the account picker with its
    /// groups, message history, and drafts intact. The account ref stays valid
    /// after this returns. The returned `SignOutOutcomeFfi` surfaces per-relay
    /// KeyPackage cleanup failures so the app can show a "will retry on next
    /// sign-in" hint (darkmatter#477).
    pub async fn sign_out(
        &self,
        account_ref: String,
        delete_key_packages: bool,
    ) -> Result<conversions::SignOutOutcomeFfi, MarmotKitError> {
        let options = marmot_app::SignOutOptions {
            delete_key_packages,
        };
        Ok(self.runtime.sign_out(&account_ref, options).await?.into())
    }

    /// Create a brand-new Nostr identity, store its secret in the platform
    /// keychain, and publish initial relay lists + key package.
    pub async fn create_identity(
        &self,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        let request = AccountSetupRequest {
            identity: None,
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let result = self.runtime.create_identity(request).await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            signed_out: result.account.signed_out,
            running: true,
        })
    }

    /// Log in with an existing identity. `identity` can be an `nsec` (private
    /// key) for a local-signing account, or an `npub` to track a public
    /// identity without local signing.
    pub async fn login(
        &self,
        identity: String,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        let request = AccountSetupRequest {
            identity: None,
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let result = self.runtime.login(identity, request).await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            signed_out: result.account.signed_out,
            running: true,
        })
    }

    /// Re-activate a non-destructively signed-out local account. This clears
    /// the durable signed-out marker and starts the account worker again; relay
    /// list/key-package repair can still be driven by the existing publish
    /// commands after sign-in.
    pub async fn sign_in_account(
        &self,
        account_ref: String,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        let account = self.runtime.sign_in_account(&account_ref).await?;
        Ok(AccountSummaryFfi {
            label: account.label,
            account_id_hex: account.account_id_hex,
            local_signing: account.local_signing,
            signed_out: account.signed_out,
            running: account.running,
        })
    }

    /// Publish (or re-publish) the NIP-65 and inbox relay lists for
    /// `account_ref`. Idempotent — safe to call on every launch.
    pub async fn publish_relay_lists(
        &self,
        account_ref: String,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<(), MarmotKitError> {
        let bootstrap = marmot_app::AccountRelayListBootstrap::new(
            endpoints(&default_relays),
            endpoints(&bootstrap_relays),
        );
        self.app
            .publish_account_relay_lists(&account_ref, bootstrap)
            .await?;
        Ok(())
    }

    pub fn account_nip65_relays(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError> {
        Ok(self.runtime.account_nip65_relays(&account_ref)?)
    }

    pub fn account_inbox_relays(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError> {
        Ok(self.runtime.account_inbox_relays(&account_ref)?)
    }

    /// List the local and relay-discovered Marmot KeyPackage publications for
    /// `account_ref`.
    pub async fn account_key_packages(
        &self,
        account_ref: String,
        bootstrap_relays: Vec<String>,
    ) -> Result<Vec<conversions::AccountKeyPackageFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .account_key_packages(&account_ref, endpoints(&bootstrap_relays))
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Publish a new fresh KeyPackage for `account_ref`.
    pub async fn publish_new_key_package(
        &self,
        account_ref: String,
    ) -> Result<u64, MarmotKitError> {
        Ok(self.runtime.publish_new_key_package(&account_ref).await? as u64)
    }

    /// Re-publish the latest cached KeyPackage when possible, otherwise
    /// publish a fresh one.
    pub async fn republish_key_package(&self, account_ref: String) -> Result<u64, MarmotKitError> {
        Ok(self.runtime.publish_key_package(&account_ref).await? as u64)
    }

    /// Publish a NIP-09 deletion for a KeyPackage event.
    pub async fn delete_account_key_package(
        &self,
        account_ref: String,
        event_id_hex: String,
        relays: Vec<String>,
    ) -> Result<u64, MarmotKitError> {
        Ok(self
            .runtime
            .delete_key_package(&account_ref, &event_id_hex, endpoints(&relays))
            .await? as u64)
    }

    pub async fn set_account_nip65_relays(
        &self,
        account_ref: String,
        relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError> {
        let status = self
            .runtime
            .set_account_nip65_relays(
                &account_ref,
                endpoints(&relays),
                endpoints(&bootstrap_relays),
            )
            .await?;
        Ok(status.into())
    }

    pub async fn set_account_inbox_relays(
        &self,
        account_ref: String,
        relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError> {
        let status = self
            .runtime
            .set_account_inbox_relays(
                &account_ref,
                endpoints(&relays),
                endpoints(&bootstrap_relays),
            )
            .await?;
        Ok(status.into())
    }

    /// Export the active account's raw private key in canonical `nsec1...`
    /// bech32 form for an in-app key-backup display (darkmatter#543).
    ///
    /// SENSITIVE: revealing the raw key is logged to the per-account audit log
    /// and permanently marks the account's NIP-49 KEY_SECURITY_BYTE as 0x00
    /// ("handled insecurely"). The returned string is computed on demand and is
    /// never cached by the engine; the caller should display it transiently and
    /// drop it. Refuses unknown / public-only / cross-account refs via the
    /// existing keystore validation.
    pub fn reveal_nsec(&self, account_ref: String) -> Result<String, MarmotKitError> {
        Ok(self
            .runtime
            .reveal_nsec(&account_ref, "marmot_uniffi::Marmot::reveal_nsec")?)
    }

    /// Publish the Nostr kind:0 metadata for `account_ref`. The returned
    /// metadata is what marmot-app actually published (any server-applied
    /// defaults are reflected here).
    pub async fn publish_user_profile(
        &self,
        account_ref: String,
        profile: UserProfileMetadataFfi,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<UserProfileMetadataFfi, MarmotKitError> {
        let bootstrap = marmot_app::AccountRelayListBootstrap::new(
            endpoints(&default_relays),
            endpoints(&bootstrap_relays),
        );
        let pushed = self
            .runtime
            .publish_user_profile(&account_ref, UserProfileMetadata::from(profile), bootstrap)
            .await?;
        Ok(pushed.into())
    }
}
