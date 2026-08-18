//! Account lifecycle, identity, relay-list, key-package, and profile commands.

use cgka_traits::TransportEndpoint;
use marmot_app::{AccountSetupRequest, UserProfileMetadata, default_directory_discovery_relays};
use zeroize::Zeroizing;

use crate::conversions::{AccountSummaryFfi, UserProfileMetadataFfi, normalize_member_ref_ffi};
use crate::errors::MarmotKitError;
use crate::external_signer::{ExternalAccountSignerAdapter, ExternalAccountSignerFfi};
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
                external_signing: m.external_signing,
                signed_out: m.signed_out,
                running: m.running,
            })
            .collect())
    }

    /// Per-account unread aggregate for the account-switcher and application
    /// badge (mdk#461, mdk#1460). Each entry is read from that account's
    /// materialized chat-list projection, so this does not require switching
    /// into, or loading a full session/timeline for, any account — non-active
    /// (not-`running`) accounts are reported too. Sign-capable local and
    /// external-signer accounts are included, matching `list_accounts`.
    /// `attention_only_conversations` covers pending invitations and
    /// manual-only unread rows without overlapping unread-message totals.
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
    /// partial-failure sheet (mdk#478).
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
    /// KeyPackage cleanup failures. These are the final best-effort results for
    /// this call; the runtime does not persist a remote-deletion retry queue
    /// (mdk#477).
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
    /// keychain, and publish initial relay lists, an empty follow list, and a
    /// key package.
    pub async fn create_identity(
        &self,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        let request = AccountSetupRequest {
            identity: None,
            import_nsec: None,
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            discovery_relays: ffi_discovery_relays(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let result = self.runtime.create_identity(request).await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            external_signing: result.account.external_signing,
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
        let (public_identity, import_nsec) = if marmot_app::is_nostr_secret(&identity) {
            (None, Some(Zeroizing::new(identity)))
        } else {
            (Some(identity), None)
        };
        let request = AccountSetupRequest {
            identity: public_identity,
            import_nsec,
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            discovery_relays: ffi_discovery_relays(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let result = self.runtime.create_or_import_account(request).await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            external_signing: result.account.external_signing,
            signed_out: result.account.signed_out,
            running: true,
        })
    }

    /// Remove only the legacy ambiguous partial-account shape so a subsequent
    /// `login` with the same nsec can recreate it. The acknowledgement is
    /// required because old local state cannot prove that no KeyPackage was
    /// exposed before its stable slot was lost.
    pub async fn reset_incomplete_account_setup(
        &self,
        nsec: String,
        acknowledge_possible_key_package_orphan: bool,
    ) -> Result<(), MarmotKitError> {
        let nsec = Zeroizing::new(nsec);
        self.runtime
            .reset_incomplete_account_setup(nsec.as_str(), acknowledge_possible_key_package_orphan)
            .await?;
        Ok(())
    }

    /// Consent-gated one-call recovery for installations stranded before MDK
    /// had durable account-setup journals. This validates the same nsec,
    /// removes only the recognized ambiguous partial shape, preserves an
    /// existing account-id Keychain credential, and immediately retries login.
    pub async fn login_recovering_incomplete_setup(
        &self,
        nsec: String,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
        acknowledge_possible_key_package_orphan: bool,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        if !marmot_app::is_nostr_secret(&nsec) {
            return Err(MarmotKitError::InvalidIdentity {
                details: "incomplete setup recovery requires an nsec".into(),
            });
        }
        let request = AccountSetupRequest {
            identity: None,
            import_nsec: Some(Zeroizing::new(nsec)),
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            discovery_relays: ffi_discovery_relays(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let result = self
            .runtime
            .recover_incomplete_account_setup(request, acknowledge_possible_key_package_orphan)
            .await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            external_signing: result.account.external_signing,
            signed_out: result.account.signed_out,
            running: true,
        })
    }

    /// Log in with an external account signer such as Amber/NIP-55.
    ///
    /// MDK stores only the account public key and device-local database
    /// encryption material. All Nostr signing/decryption and MLS
    /// account-identity proof signing are routed through `signer`; apps must
    /// call this again after process restart before the external account can
    /// publish, decrypt welcomes, or start its worker.
    pub async fn login_external_signer(
        &self,
        public_key: String,
        signer: std::sync::Arc<dyn ExternalAccountSignerFfi>,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        let request = AccountSetupRequest {
            identity: None,
            import_nsec: None,
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            discovery_relays: ffi_discovery_relays(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let signer = ExternalAccountSignerAdapter::new(signer);
        let result = self
            .runtime
            .login_external_signer(public_key, signer, request)
            .await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            external_signing: result.account.external_signing,
            signed_out: result.account.signed_out,
            running: true,
        })
    }

    /// Re-register an external signer for an already-known external account.
    ///
    /// This is the restore path after app/process restart. It does not create a
    /// new account; it only installs the signer callback so runtime work can
    /// resume for the account.
    pub async fn register_external_signer(
        &self,
        account_ref: String,
        signer: std::sync::Arc<dyn ExternalAccountSignerFfi>,
    ) -> Result<(), MarmotKitError> {
        self.runtime
            .register_external_signer(&account_ref, ExternalAccountSignerAdapter::new(signer))
            .await?;
        Ok(())
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
            external_signing: account.external_signing,
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

    // -----------------------------------------------------------------------
    // Follows
    // -----------------------------------------------------------------------

    /// Return the complete locally cached kind-3 follow list for `account_ref`
    /// as canonical lowercase public-key hex strings.
    ///
    /// This is a synchronous, network-free read intended for profile screens
    /// and bulk membership checks. Follow/unfollow and directory refreshes
    /// update the cache before returning.
    pub fn account_follows(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError> {
        Ok(self.runtime.account_follows(&account_ref)?)
    }

    /// Return whether `account_ref` currently follows `user_ref`, using the
    /// same local cache as [`Self::account_follows`]. `user_ref` accepts npub,
    /// hex, `nostr:npub…`, and Marmot profile links.
    pub fn is_following(
        &self,
        account_ref: String,
        user_ref: String,
    ) -> Result<bool, MarmotKitError> {
        let user = normalize_member_ref_ffi(&user_ref)?;
        Ok(self
            .runtime
            .is_following(&account_ref, &user.account_id_hex)?)
    }

    /// Follow `user_ref` while preserving every other entry in the account's
    /// current kind-3 contact list. Returns the complete updated list.
    ///
    /// This fetches the current replaceable event from the account's known
    /// outbox/default relays before publishing. If no current event can be
    /// established, it returns `FollowListUnavailable` rather than risking a
    /// destructive replacement.
    pub async fn follow_user(
        &self,
        account_ref: String,
        user_ref: String,
    ) -> Result<Vec<String>, MarmotKitError> {
        let user = normalize_member_ref_ffi(&user_ref)?;
        Ok(self
            .runtime
            .follow_user(&account_ref, &user.account_id_hex)
            .await?)
    }

    /// Unfollow `user_ref` while preserving every other entry in the account's
    /// current kind-3 contact list. Returns the complete updated list.
    pub async fn unfollow_user(
        &self,
        account_ref: String,
        user_ref: String,
    ) -> Result<Vec<String>, MarmotKitError> {
        let user = normalize_member_ref_ffi(&user_ref)?;
        Ok(self
            .runtime
            .unfollow_user(&account_ref, &user.account_id_hex)
            .await?)
    }

    /// Export the active account's raw private key in canonical `nsec1...`
    /// bech32 form for an in-app key-backup display (mdk#543).
    ///
    /// SENSITIVE: revealing the raw key is logged to the per-account audit log
    /// and permanently marks the account's NIP-49 KEY_SECURITY_BYTE as 0x00
    /// ("handled insecurely"). The returned string is computed on demand and is
    /// never cached by the engine. The Rust runtime keeps the nsec in
    /// `Zeroizing<String>` until this UniFFI return boundary. UniFFI can lower
    /// only a plain `String`, so the final clone here is the intentional point
    /// where Rust's zeroizing guarantee stops; the caller should display the
    /// host-owned string transiently and drop it. Refuses unknown / public-only
    /// / cross-account refs via the existing keystore validation.
    pub fn reveal_nsec(&self, account_ref: String) -> Result<String, MarmotKitError> {
        let nsec = self
            .runtime
            .reveal_nsec(&account_ref, "marmot_uniffi::Marmot::reveal_nsec")?;
        Ok(nsec.to_string())
    }

    /// Export the active account's private key as a password-encrypted NIP-49
    /// `ncryptsec1...` bech32 backup string (mdk#544).
    ///
    /// SENSITIVE: the passphrase is accepted as an owned FFI string and zeroed
    /// on return by the Rust boundary. This cannot wipe the caller's original
    /// host-language string, which remains a separate host-side responsibility
    /// and should be kept transient. The encrypted export is logged to the
    /// per-account audit log, but unlike `reveal_nsec` it does not downgrade the
    /// account's NIP-49 KEY_SECURITY_BYTE because raw plaintext key material is
    /// not returned to the host app.
    pub fn export_encrypted_secret_key(
        &self,
        account_ref: String,
        passphrase: String,
    ) -> Result<String, MarmotKitError> {
        let passphrase = zeroize::Zeroizing::new(passphrase);
        Ok(self.runtime.export_encrypted_secret_key(
            &account_ref,
            passphrase.as_str(),
            "marmot_uniffi::Marmot::export_encrypted_secret_key",
        )?)
    }

    /// Publish Nostr kind:0 metadata with explicit caller-supplied relay
    /// overrides. Most app clients should use
    /// [`publish_user_profile_using_account_relays`](Self::publish_user_profile_using_account_relays)
    /// so relay selection remains owned by MDK. This override remains for
    /// diagnostics, tests, and specialized clients.
    ///
    /// The returned metadata is what marmot-app actually published (including
    /// preserved unknown fields and any merge defaults).
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

    /// Publish Nostr kind:0 metadata using one coherent snapshot of the
    /// selected account's MDK-owned relay configuration.
    ///
    /// Published NIP-65 write relays are preferred. When that list is empty,
    /// remembered bootstrap relays are used; when bootstrap relays are absent,
    /// the account's default/publish list is the fallback. Invalid, unsafe, and
    /// retired endpoints are removed by the relay safety policy before any
    /// network work starts. No preceding [`account_relay_lists`](Self::account_relay_lists)
    /// call is needed.
    pub async fn publish_user_profile_using_account_relays(
        &self,
        account_ref: String,
        profile: UserProfileMetadataFfi,
    ) -> Result<UserProfileMetadataFfi, MarmotKitError> {
        let pushed = self
            .runtime
            .publish_user_profile_using_account_relays(
                &account_ref,
                UserProfileMetadata::from(profile),
            )
            .await?;
        Ok(pushed.into())
    }

    /// Upload a public raster profile image to Blossom with the account's
    /// signer. The returned HTTPS URL can be published as kind:0 `picture`.
    pub async fn upload_profile_image(
        &self,
        account_ref: String,
        data: Vec<u8>,
        media_type: String,
        blossom_server: Option<String>,
    ) -> Result<String, MarmotKitError> {
        Ok(self
            .runtime
            .upload_profile_image(&account_ref, data, &media_type, blossom_server.as_deref())
            .await?)
    }

    /// Fetch one untrusted kind:0 profile `picture` URL with MDK dial-safe
    /// HTTPS policy, address pinning, and bounded streaming.
    pub async fn download_profile_image(
        &self,
        url: String,
        max_bytes: u64,
    ) -> Result<Vec<u8>, MarmotKitError> {
        Ok(marmot_app::download_profile_image(url, max_bytes).await?)
    }
}

fn ffi_discovery_relays(bootstrap_relays: &[String]) -> Vec<TransportEndpoint> {
    let mut relays = endpoints(bootstrap_relays);
    for relay in default_directory_discovery_relays() {
        if !relays.contains(&relay) {
            relays.push(relay);
        }
    }
    relays
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use marmot_account::AccountHome;
    use marmot_app::{AccountRelayListBootstrap, MarmotApp, npub_for_account_id};
    use nostr_relay_builder::MockRelay;

    use super::*;

    #[test]
    fn account_unread_summary_reports_zero_attention_for_idle_local_account() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = AccountHome::open(root.path());
        let account = home.create_account("alice").expect("create alice");
        let app = MarmotApp::with_relay(root.path(), "wss://relay.invalid.test");
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };

        let summary = kit
            .account_unread_summary()
            .expect("unread summary without starting a session");
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].account_id_hex, account.account_id_hex);
        assert_eq!(summary[0].unread_count, 0);
        assert_eq!(summary[0].unread_conversations, 0);
        assert_eq!(summary[0].attention_only_conversations, 0);
        assert!(!summary[0].has_unread);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn follow_bindings_preserve_the_list_and_refresh_fast_reads() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let home = AccountHome::open(root.path());
        let alice = home.create_account("alice").expect("create alice");
        let bob = home.create_account("bob").expect("create bob");
        let carol = home.create_account("carol").expect("create carol");
        let app = MarmotApp::with_relay(root.path(), relay_url.clone());
        let endpoint = TransportEndpoint(relay_url);
        let bootstrap =
            AccountRelayListBootstrap::new(vec![endpoint.clone()], vec![endpoint.clone()]);
        app.publish_account_follow_list(&alice.label, &[bob.account_id_hex.as_str()], bootstrap)
            .await
            .expect("seed follow list");

        // Kind-3 is replaceable at second granularity. Keep each update in a
        // distinct timestamp so this test exercises deterministic relay state
        // rather than the event-id tie-breaker.
        tokio::time::sleep(Duration::from_millis(1_050)).await;

        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let bob_npub = npub_for_account_id(&bob.account_id_hex).expect("bob npub");
        let carol_npub = npub_for_account_id(&carol.account_id_hex).expect("carol npub");

        let followed = kit
            .follow_user(alice.label.clone(), carol_npub)
            .await
            .expect("follow carol");
        let mut expected_follows = vec![bob.account_id_hex.clone(), carol.account_id_hex.clone()];
        expected_follows.sort();
        assert_eq!(followed, expected_follows);
        assert_eq!(
            kit.account_follows(alice.label.clone())
                .expect("cached follows"),
            followed
        );
        assert!(
            kit.is_following(alice.label.clone(), bob_npub.clone())
                .expect("bob membership")
        );
        assert!(
            kit.is_following(alice.label.clone(), carol.account_id_hex.clone())
                .expect("carol membership")
        );

        tokio::time::sleep(Duration::from_millis(1_050)).await;

        let remaining = kit
            .unfollow_user(alice.label.clone(), bob_npub)
            .await
            .expect("unfollow bob");
        assert_eq!(remaining, vec![carol.account_id_hex.clone()]);
        assert_eq!(
            kit.account_follows(alice.label.clone())
                .expect("updated cached follows"),
            remaining
        );
        assert!(
            !kit.is_following(alice.label, bob.account_id_hex)
                .expect("removed membership")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn follow_binding_refuses_to_replace_an_unknown_list() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let home = AccountHome::open(root.path());
        let alice = home.create_account("alice").expect("create alice");
        let bob = home.create_account("bob").expect("create bob");
        let app = MarmotApp::with_relay(root.path(), relay_url);
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };

        let error = kit
            .follow_user(alice.label, bob.account_id_hex)
            .await
            .expect_err("missing current kind-3 must not be treated as empty");
        assert!(matches!(error, MarmotKitError::FollowListUnavailable));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn account_owned_profile_publish_binding_needs_no_relay_arguments() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let app = MarmotApp::with_relays(root.path(), vec![relay_url.clone()]);
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let endpoint = TransportEndpoint(relay_url);
        let account = kit
            .runtime
            .create_identity(marmot_app::AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..marmot_app::AccountSetupRequest::default()
            })
            .await
            .expect("create identity");

        let published = kit
            .publish_user_profile_using_account_relays(
                account.account.account_id_hex,
                UserProfileMetadataFfi {
                    display_name: Some("Account Owned".to_owned()),
                    ..UserProfileMetadataFfi::default()
                },
            )
            .await
            .expect("publish without a host relay-list read");

        assert_eq!(published.display_name.as_deref(), Some("Account Owned"));
    }
}
