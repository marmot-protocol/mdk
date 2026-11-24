use super::*;

fn random_owner_id() -> AccountHomeResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        AccountHomeError::SecretStore(format!(
            "cannot create credential ownership identity: {error}"
        ))
    })?;
    Ok(hex::encode(bytes))
}

fn validate_owner_id(id: &str) -> AccountHomeResult<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AccountHomeError::SecretStore(
            "invalid credential ownership identity".into(),
        ));
    }
    Ok(())
}

pub(super) fn credential_index(kind: SecretCredentialKind) -> usize {
    match kind {
        SecretCredentialKind::Signing => 0,
        SecretCredentialKind::ExternalDatabase => 1,
        SecretCredentialKind::Nip46Session => 2,
    }
}

pub(super) fn missing_secret(error: &AccountHomeError) -> bool {
    matches!(error, AccountHomeError::SecretNotFound(_))
        || matches!(error, AccountHomeError::Io(error) if error.kind() == std::io::ErrorKind::NotFound)
}

impl AccountHome {
    fn wipe_namespace(&self) -> AccountHomeResult<[u8; 32]> {
        if let Some(namespace) = self.vault_namespace.get() {
            return Ok(*namespace);
        }
        let namespace = self.secret_store.cleanup_namespace()?;
        let namespace = Sha256::digest(namespace.as_bytes()).into();
        let _ = self.vault_namespace.set(namespace);
        Ok(namespace)
    }

    fn canonical_root(&self) -> AccountHomeResult<PathBuf> {
        let root = self.root.canonicalize()?;
        if self
            .home_id
            .get()
            .is_some_and(|(target, _)| target != &root)
        {
            return Err(AccountHomeError::SecretStore(
                "cached account home target changed; reopen its original canonical root".into(),
            ));
        }
        Ok(root)
    }

    pub(super) fn home_identity(&self, readonly: bool) -> AccountHomeResult<&str> {
        let root = self.canonical_root()?;
        if let Some((_, id)) = self.home_id.get() {
            return Ok(id);
        }
        let path_hash = hex::encode(crate::location::root_hash(&root, &self.ios_options)?);
        let path = self.root.join(HOME_IDENTITY_FILE);
        let identity: HomeIdentity = if readonly {
            read_immutable_json_bounded(&path, MAX_WIPE_CLEANUP_BYTES)?
        } else {
            read_private_json_bounded(&path, MAX_WIPE_CLEANUP_BYTES)?
        };
        if identity.path_hash != path_hash {
            return Err(AccountHomeError::SecretStore("account ownership belongs to another canonical root; create a fresh home and reimport instead of copying a live home".into()));
        }
        validate_owner_id(&identity.id)?;
        let _ = self.home_id.set((root, identity.id));
        Ok(self
            .home_id
            .get()
            .expect("home identity initialized")
            .1
            .as_str())
    }

    fn initialize_home_identity(&self) -> AccountHomeResult<()> {
        let path = self.root.join(HOME_IDENTITY_FILE);
        if self.home_id.get().is_some() || path.try_exists()? {
            self.home_identity(false)?;
            return Ok(());
        }
        let root = self.canonical_root()?;
        let identity = HomeIdentity {
            id: random_owner_id()?,
            path_hash: hex::encode(crate::location::root_hash(&root, &self.ios_options)?),
        };
        write_private_json(&self.root, &path, &identity)?;
        let _ = self.home_id.set((root, identity.id));
        Ok(())
    }

    fn credential_home(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
    ) -> AccountHomeResult<String> {
        let home = self.home_identity(false)?;
        if kind == SecretCredentialKind::Signing {
            return Ok(home.to_owned());
        }
        let mut hash = Sha256::new();
        hash.update(home.as_bytes());
        hash.update(account.account_id_hex.as_bytes());
        Ok(hex::encode(hash.finalize()))
    }

    pub(super) fn credential_manifest(
        &self,
        label: &str,
    ) -> AccountHomeResult<Option<CredentialManifest>> {
        match read_private_json_bounded(
            self.account_dir(label)
                .join(CREDENTIAL_OWNERS_FILE)
                .as_path(),
            MAX_WIPE_CLEANUP_BYTES,
        ) {
            Ok(manifest) => Ok(Some(manifest)),
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn manifest_or_legacy(
        &self,
        account: &AccountSummary,
    ) -> AccountHomeResult<CredentialManifest> {
        let manifest = match self.credential_manifest(&account.label)? {
            Some(manifest) => manifest,
            None => {
                let legacy = self.account_record_path(&account.label).try_exists()?;
                CredentialManifest {
                    account: account.clone(),
                    legacy,
                    generated_named_creation: false,
                    nip46_admission: if legacy {
                        Nip46Admission::LegacyAllowed
                    } else {
                        Nip46Admission::ManagedOnly
                    },
                    nip46_retirement_pending: false,
                    nip46_legacy_cleanup_pending: false,
                    credentials: Default::default(),
                }
            }
        };
        manifest.validate_identity(account)?;
        Ok(manifest)
    }

    pub(super) fn write_credential_manifest(
        &self,
        label: &str,
        manifest: &CredentialManifest,
    ) -> AccountHomeResult<()> {
        write_private_json(
            &self.root,
            self.account_dir(label).join(CREDENTIAL_OWNERS_FILE),
            manifest,
        )
    }

    pub(super) fn check_credential(
        &self,
        account: &AccountSummary,
        credential: &OwnedCredential,
    ) -> AccountHomeResult<()> {
        if credential.namespace != self.wipe_namespace()? {
            return Err(AccountHomeError::SecretStore(
                "credential belongs to another vault; reopen with its originating store".into(),
            ));
        }
        if credential.home_id != self.credential_home(account, credential.kind)? {
            return Err(AccountHomeError::SecretStore(
                "credential ownership belongs to another home or account identity".into(),
            ));
        }
        validate_owner_id(&credential.owner_id)
    }

    pub(super) fn acquire_credential(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        let manifest = self.manifest_or_legacy(account)?;
        self.acquire_prepared_credential(account, kind, mode, proposed, manifest)
    }

    pub(super) fn acquire_prepared_credential(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
        mut manifest: CredentialManifest,
    ) -> AccountHomeResult<AcquiredSecret> {
        let namespace = self.wipe_namespace()?;
        if manifest
            .credentials
            .iter()
            .flatten()
            .any(|credential| credential.namespace != namespace)
        {
            return Err(AccountHomeError::SecretStore(
                "account credentials belong to another vault".into(),
            ));
        }
        let index = credential_index(kind);
        let plaintext_migration = kind == SecretCredentialKind::ExternalDatabase
            && mode == SecretClaimMode::MigrateLegacy
            && proposed.is_some();
        if let Some(credential) = &mut manifest.credentials[index]
            && kind != SecretCredentialKind::Nip46Session
            && credential.origin.is_none()
            && proposed.is_some()
            && credential.claim_mode != mode
            && !plaintext_migration
            && mode != SecretClaimMode::AdoptOnly
        {
            credential.claim_mode = mode;
            self.write_credential_manifest(&account.label, &manifest)?;
        }
        if manifest.credentials[index].is_none() {
            if kind == SecretCredentialKind::Nip46Session
                && manifest.nip46_admission == Nip46Admission::ManagedOnly
                && mode == SecretClaimMode::MigrateLegacy
            {
                return Err(AccountHomeError::SecretStore(
                    "legacy NIP-46 admission is closed".into(),
                ));
            }
            self.initialize_home_identity()?;
            let target = match kind {
                SecretCredentialKind::Signing => account.clone(),
                SecretCredentialKind::ExternalDatabase => external_database_credential(account),
                SecretCredentialKind::Nip46Session => {
                    synthetic_credential(account, NIP46_CREDENTIAL_PREFIX)
                }
            };
            manifest.credentials[index] = Some(OwnedCredential {
                namespace,
                home_id: self.credential_home(account, kind)?,
                owner_id: random_owner_id()?,
                account: target,
                kind,
                claim_mode: mode,
                origin: None,
            });
            self.write_credential_manifest(&account.label, &manifest)?;
        }
        let credential = manifest.credentials[index]
            .as_ref()
            .expect("credential prepared");
        self.check_credential(account, credential)?;
        // The plaintext file remains the migration intent until a successful
        // comparison and acquisition. Older owners may predate that mode.
        let request_mode = if plaintext_migration {
            mode
        } else {
            credential.claim_mode
        };
        let acquired =
            self.secret_store
                .acquire_secret(credential.request(), request_mode, proposed)?;
        if (kind == SecretCredentialKind::Signing
            && acquired.keys.public_key().to_hex() != account.account_id_hex)
            || proposed.is_some_and(|keys| keys.secret_key() != acquired.keys.secret_key())
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        match credential.origin {
            Some(origin) if origin != acquired.origin => {
                return Err(AccountHomeError::SecretStore(
                    "credential acquisition origin changed across a retry".into(),
                ));
            }
            Some(_) => {}
            None => {
                manifest.credentials[index]
                    .as_mut()
                    .expect("credential prepared")
                    .origin = Some(acquired.origin);
                self.write_credential_manifest(&account.label, &manifest)?;
            }
        }
        Ok(acquired)
    }

    pub(super) fn read_credential(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
        readonly: bool,
    ) -> AccountHomeResult<Option<nostr::prelude::Keys>> {
        let path = self
            .account_dir(&account.label)
            .join(CREDENTIAL_OWNERS_FILE);
        let manifest = if readonly {
            read_immutable_json_bounded(&path, MAX_WIPE_CLEANUP_BYTES)
        } else {
            read_private_json_bounded(&path, MAX_WIPE_CLEANUP_BYTES)
        };
        let manifest: CredentialManifest = match manifest {
            Ok(manifest) => manifest,
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        manifest.validate_identity(account)?;
        if let Some(credential) = &manifest.credentials[credential_index(kind)] {
            if readonly {
                self.home_identity(true)?;
            }
            self.check_credential(account, credential)?;
            if credential.origin.is_some() {
                let keys = self.secret_store.load_secret(credential.request())?;
                if kind == SecretCredentialKind::Signing
                    && keys.public_key().to_hex() != account.account_id_hex
                {
                    return Err(AccountHomeError::AccountIdMismatch);
                }
                return Ok(Some(keys));
            }
        }
        Ok(None)
    }

    pub(super) fn load_credential(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        if let Some(keys) = self.read_credential(account, kind, false)? {
            return Ok(keys);
        }
        let manifest = self.credential_manifest(&account.label)?;
        let legacy = manifest.as_ref().is_none_or(|manifest| {
            manifest.legacy
                && (kind != SecretCredentialKind::Nip46Session
                    || manifest.nip46_admission == Nip46Admission::LegacyAllowed)
        });
        if kind == SecretCredentialKind::Nip46Session
            && !legacy
            && manifest
                .as_ref()
                .is_none_or(|manifest| manifest.credentials[credential_index(kind)].is_none())
        {
            return Err(AccountHomeError::SecretNotFound(account.label.clone()));
        }
        let mode = if legacy {
            SecretClaimMode::MigrateLegacy
        } else {
            SecretClaimMode::AdoptOnly
        };
        Ok(self.acquire_credential(account, kind, mode, None)?.keys)
    }

    pub(super) fn renew_credential(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        if kind == SecretCredentialKind::Signing
            && proposed.is_some_and(|keys| keys.public_key().to_hex() != account.account_id_hex)
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        let mut manifest = self.credential_manifest(&account.label)?.ok_or_else(|| {
            AccountHomeError::SecretStore("credential ownership manifest is missing".into())
        })?;
        let index = credential_index(kind);
        if manifest.credentials[index]
            .as_ref()
            .is_some_and(|credential| credential.origin.is_some())
        {
            self.retire_claim(account, kind, &mut manifest)?;
        }
        self.acquire_credential(account, kind, SecretClaimMode::CreateOrAdopt, proposed)
    }

    pub(super) fn retire_claim(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
        manifest: &mut CredentialManifest,
    ) -> AccountHomeResult<()> {
        let index = credential_index(kind);
        if let Some(credential) = &manifest.credentials[index] {
            self.check_credential(account, credential)?;
            let outcome = self
                .secret_store
                .release_secret(credential.request(), SecretReleaseMode::DeleteIfUnowned)?;
            if kind == SecretCredentialKind::Nip46Session
                && outcome == SecretReleaseOutcome::PendingLegacy
            {
                manifest.nip46_legacy_cleanup_pending = true;
            }
            manifest.credentials[index] = None;
            self.write_credential_manifest(&account.label, manifest)?;
        }
        Ok(())
    }

    pub(super) fn build_wipe_cleanup(
        &self,
        account: &AccountSummary,
        manifest: &CredentialManifest,
        signing: SigningKeyRemoval,
    ) -> AccountHomeResult<WipeCleanup> {
        manifest.validate_identity(account)?;
        let mut cleanup = WipeCleanup {
            account: Some(account.clone()),
            ..WipeCleanup::default()
        };
        for kind in [
            SecretCredentialKind::Signing,
            SecretCredentialKind::ExternalDatabase,
            SecretCredentialKind::Nip46Session,
        ] {
            let index = credential_index(kind);
            if let Some(credential) = &manifest.credentials[index] {
                self.check_credential(account, credential)?;
                let mode = if kind == SecretCredentialKind::Signing
                    && matches!(signing, SigningKeyRemoval::Preserve)
                {
                    SecretReleaseMode::Preserve
                } else {
                    SecretReleaseMode::DeleteIfUnowned
                };
                cleanup.credentials[index] = Some(CleanupCredential {
                    credential: credential.clone(),
                    mode,
                });
            }
            let target = match kind {
                SecretCredentialKind::Signing if manifest.legacy && account.local_signing => {
                    Some(account.clone())
                }
                SecretCredentialKind::ExternalDatabase
                    if manifest.legacy
                        && (account.external_signing || manifest.account.external_signing) =>
                {
                    Some(external_database_credential(account))
                }
                SecretCredentialKind::Nip46Session
                    if !account.local_signing
                        && (manifest.nip46_legacy_cleanup_pending
                            || (manifest.legacy
                                && (account.external_signing
                                    || manifest.account.external_signing
                                    || manifest.nip46_admission
                                        == Nip46Admission::ManagedOnly))) =>
                {
                    Some(synthetic_credential(account, NIP46_CREDENTIAL_PREFIX))
                }
                _ => None,
            };
            if let Some(account) = target {
                let local_tombstone_home =
                    if kind == SecretCredentialKind::Signing && self.local_file_store {
                        self.initialize_home_identity()?;
                        Some(self.home_identity(false)?.to_owned())
                    } else {
                        None
                    };
                cleanup.legacy[index] = Some(LegacyCredential {
                    account,
                    kind,
                    local_tombstone_home,
                });
            }
        }
        Ok(cleanup)
    }

    pub(super) fn abort_prepared_account(
        &self,
        label: &str,
        directory: &Path,
        manifest: &CredentialManifest,
    ) -> AccountHomeResult<()> {
        validate_account_label(label)?;
        if manifest.account.label != label {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        let signing = match &manifest.credentials[credential_index(SecretCredentialKind::Signing)] {
            Some(credential) if credential.claim_mode != SecretClaimMode::CreateOnly => {
                SigningKeyRemoval::Preserve
            }
            _ => SigningKeyRemoval::Delete,
        };
        let account = &manifest.account;
        let cleanup = self.build_wipe_cleanup(account, manifest, signing)?;
        write_private_json(&self.root, directory.join(WIPE_CLEANUP_FILE), &cleanup)?;
        if let Some(tombstone) = self.move_account_dir_to_tombstone(label, directory)? {
            self.finish_wipe_cleanup(&tombstone, Some(cleanup));
        }
        Ok(())
    }

    pub(super) fn cleanup_abandoned_admissions(&self) -> AccountHomeResult<()> {
        let entries = match fs::read_dir(self.accounts_dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut failure = None;
        for entry in entries {
            let result = (|| -> AccountHomeResult<()> {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    return Ok(());
                }
                let Some(label) = entry.file_name().to_str().map(str::to_owned) else {
                    return Ok(());
                };
                let directory = entry.path();
                if directory.join(ACCOUNT_RECORD_FILE).try_exists()?
                    || directory.join(ACCOUNT_SETUP_STATE_FILE).try_exists()?
                {
                    return Ok(());
                }
                if let Some(manifest) = self.credential_manifest(&label)? {
                    self.abort_prepared_account(&label, &directory, &manifest)?;
                }
                Ok(())
            })();
            if let Err(error) = result
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn read_guard(&self) -> AccountHomeResult<MutexGuard<'_, ()>> {
        let guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.home_id.get().is_some() {
            self.canonical_root()?;
        }
        Ok(guard)
    }

    pub(super) fn immutable_read<T>(
        &self,
        read: impl FnOnce() -> AccountHomeResult<CredentialRead<T>>,
    ) -> AccountHomeResult<CredentialRead<T>> {
        let _guard = self.read_guard()?;
        match read() {
            Err(AccountHomeError::Io(error))
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Ok(CredentialRead::Admission)
            }
            result => result,
        }
    }

    pub(super) fn mutation_guard(&self) -> AccountHomeResult<AccountMutationGuard<'_>> {
        let clone_guard = self.read_guard()?;
        #[cfg(any(unix, windows))]
        {
            let root = match self.canonical_root() {
                Ok(root) => root,
                Err(AccountHomeError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    crate::io::create_durable_private_dir(&self.root, &self.root)?;
                    self.canonical_root()?
                }
                Err(error) => return Err(error),
            };
            crate::io::create_durable_private_dir(&root, &root)?;
            let root_lease = fs_private::try_acquire_private_exclusive_file_lease(
                &root.join(ROOT_MUTATION_LOCK_FILE),
            )?;
            Ok(AccountMutationGuard {
                _root_lease: root_lease,
                _clone_guard: clone_guard,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            drop(clone_guard);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "account credential mutation requires a root file lease",
            )
            .into())
        }
    }

    pub(super) fn add_nonlocal_account(
        &self,
        public_key: &str,
        admission: NonlocalAdmission,
    ) -> AccountHomeResult<AccountSummary> {
        let (external_signing, setup_kind) = match admission {
            NonlocalAdmission::Public => (false, None),
            NonlocalAdmission::PublicSetup => (false, Some(AccountSetupKind::PublicIdentity)),
            NonlocalAdmission::External => (true, None),
            NonlocalAdmission::ExternalSetup => (true, Some(AccountSetupKind::ExternalSigner)),
        };
        let account_id_hex = Self::account_id_for_public_key(public_key)?;
        let _guard = self.mutation_guard()?;
        let has_record = self.account_record_path(&account_id_hex).try_exists()?;
        let (account, promoted) = if has_record {
            let mut account = self.account(&account_id_hex)?;
            if !external_signing || account.local_signing {
                return Err(AccountHomeError::AccountExists(account_id_hex));
            }
            let promoted = !account.external_signing;
            account.external_signing = true;
            (account, promoted)
        } else {
            (
                AccountSummary {
                    label: account_id_hex.clone(),
                    account_id_hex,
                    local_signing: false,
                    external_signing,
                    signed_out: false,
                    unlinked: false,
                },
                false,
            )
        };
        let manifest = self.credential_manifest(&account.label)?;
        if let Some(manifest) = &manifest {
            manifest.validate_identity(&account)?;
            if manifest.account.local_signing
                || (!has_record && manifest.account.external_signing != external_signing)
            {
                return Err(AccountHomeError::AccountExists(account.label));
            }
        }
        let mut journal = self.raw_account_setup_journal(&account.label)?;
        if let Some(journal) = &journal {
            let state = &journal.state;
            let promotion = journal.promotion_for(&account)?;
            let role_matches = match journal.admission_role {
                Some(role) => {
                    role == SetupAdmissionRole::of(&account)
                        || (promoted && role == SetupAdmissionRole::Public)
                }
                None => {
                    state.kind != AccountSetupKind::InteractiveIdentity
                        || has_record
                        || manifest.is_some()
                }
            };
            let public_transition = external_signing
                && setup_kind.is_some()
                && (promoted || promotion.is_some())
                && state.kind == AccountSetupKind::PublicIdentity;
            if !role_matches
                || (Some(state.kind) != setup_kind
                    && !(setup_kind.is_some()
                        && state.kind == AccountSetupKind::InteractiveIdentity)
                    && !public_transition)
            {
                return Err(AccountHomeError::AccountExists(account.label));
            }
        }
        let prior_public = if promoted {
            let mut public = account.clone();
            public.external_signing = false;
            if manifest
                .as_ref()
                .is_some_and(|manifest| manifest.nip46_retirement_pending)
            {
                self.resume_public_nip46_retirement(&public)?;
                journal = self.raw_account_setup_journal(&account.label)?;
            } else {
                self.remove_nip46_session_inner(&public, Nip46Removal::IncludingOrphaned)?;
            }
            Some(public)
        } else {
            None
        };
        if let Some(kind) = setup_kind
            && (journal.is_none() || promoted)
        {
            let prior_journal = journal.is_some();
            let mut journal = journal.unwrap_or_else(|| AccountSetupJournal {
                state: AccountSetupState {
                    account_id_hex: account.account_id_hex.clone(),
                    reused_account_id_credential: false,
                    kind,
                    phase: AccountSetupPhase::LocalStateCreated,
                },
                admission_role: None,
                promotion: None,
                created: Some(!has_record),
            });
            journal.admission_role = Some(SetupAdmissionRole::of(&account));
            if let Some(public) = prior_public {
                let prior_created = journal.created;
                journal.created = Some(false);
                journal.promotion.get_or_insert(PublicPromotion {
                    account: public,
                    prior_journal,
                    prior_created,
                });
            }
            self.write_account_setup_journal(&account.label, &journal)?;
        }
        if !has_record || promoted {
            self.write_account_record(&account)?;
        }
        Ok(account)
    }

    /// Journal a wipe and move the account out of the live catalog. The caller
    /// must hold the account mutation guard through the move.
    pub(super) fn remove_account_locked(
        &self,
        account_ref: &str,
        expected: Option<&AccountSummary>,
        removal: SigningKeyRemoval,
    ) -> AccountHomeResult<()> {
        let account = self.account(account_ref)?;
        if expected.is_some_and(|expected| expected != &account) {
            return Err(AccountHomeError::AccountExists(account.label));
        }
        let manifest = self.manifest_or_legacy(&account)?;
        let cleanup = self.build_wipe_cleanup(&account, &manifest, removal)?;
        let live_dir = self.account_dir(&account.label);
        write_private_json(&self.root, live_dir.join(WIPE_CLEANUP_FILE), &cleanup)?;
        if let Some(tombstone) = self.move_account_dir_to_tombstone(&account.label, &live_dir)? {
            self.finish_wipe_cleanup(&tombstone, Some(cleanup));
        }
        Ok(())
    }

    pub(super) fn resume_public_nip46_retirement(
        &self,
        account: &AccountSummary,
    ) -> AccountHomeResult<()> {
        validate_account_label(&account.label)?;
        let directory = self.account_dir(&account.label);
        let manifest = self.credential_manifest(&account.label)?;
        if manifest.as_ref().is_some_and(|manifest| {
            manifest.nip46_retirement_pending
                || manifest.credentials[credential_index(SecretCredentialKind::Nip46Session)]
                    .is_some()
                || (manifest.legacy
                    && manifest.account.external_signing
                    && manifest.nip46_admission == Nip46Admission::LegacyAllowed)
        }) || directory.join(NIP46_REMOVING_FILE).try_exists()?
            || directory.join(NIP46_SESSION_FILE).try_exists()?
        {
            crate::io::sync_directory(&directory)?;
            self.remove_nip46_session_inner(account, Nip46Removal::IncludingOrphaned)?;
        }
        Ok(())
    }

    /// Retry best-effort cleanup of committed wipes and public-role restorations.
    ///
    /// Failure to acquire the mutation lease or authorize this home is returned
    /// before accessing the vault. Individual cleanup failures remain pending.
    /// The caller must exclusively own the runtime root across processes and
    /// replay before allowing account mutations. Constructors do not replay.
    pub fn resume_wipe_cleanup(&self) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        if self.root.join(HOME_IDENTITY_FILE).try_exists()? {
            self.home_identity(false)?;
        }
        if self.secret_store.reconcile_cleanup().is_err() {
            tracing::warn!(target: TRACE_TARGET, method = "resume_wipe_cleanup", "vault-side retired receipt cleanup remains pending");
        }
        if self.cleanup_abandoned_admissions().is_err() {
            tracing::warn!(target: TRACE_TARGET, method = "resume_wipe_cleanup", "incomplete account admission cleanup remains pending");
        }
        match self.accounts() {
            Ok(accounts) => {
                for account in accounts.iter().filter(|account| !account.can_sign()) {
                    if self.resume_public_nip46_retirement(account).is_err() {
                        tracing::warn!(target: TRACE_TARGET, method = "resume_wipe_cleanup", "public account NIP-46 retirement remains pending");
                    }
                }
            }
            Err(_) => {
                tracing::warn!(target: TRACE_TARGET, method = "resume_wipe_cleanup", "public accounts could not be listed for NIP-46 retirement replay")
            }
        }
        let root = self.root.join(WIPE_TOMBSTONE_DIR);
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.is_dir() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            _ => {
                tracing::warn!(target: TRACE_TARGET, method = "resume_wipe_cleanup", "wipe cleanup container is not an accessible directory");
                return Ok(());
            }
        }
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(_) => {
                tracing::warn!(target: TRACE_TARGET, method = "resume_wipe_cleanup", "wipe cleanup container cannot be listed");
                return Ok(());
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let path = entry.path();
            let cleanup = read_private_json_bounded::<WipeCleanup>(
                &path.join(WIPE_CLEANUP_FILE),
                MAX_WIPE_CLEANUP_BYTES,
            )
            .ok();
            self.finish_wipe_cleanup(&path, cleanup);
        }
        Ok(())
    }

    pub(super) fn finish_wipe_cleanup(&self, tombstone: &Path, mut cleanup: Option<WipeCleanup>) {
        if crate::io::sync_directory(&self.root)
            .and_then(|()| match crate::io::sync_directory(&self.accounts_dir()) {
                // The root sync covers the absence of the former parent.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                result => result,
            })
            .and_then(|()| crate::io::sync_directory(&self.root.join(WIPE_TOMBSTONE_DIR)))
            .is_err()
        {
            tracing::warn!(target: TRACE_TARGET, method = "finish_wipe_cleanup", "wipe rename durability is uncertain; cleanup remains pending");
            return;
        }
        let scrubbed = |name| {
            let path = tombstone.join(name);
            scrub_and_remove_local_secret_file(&path).is_ok()
                && fs::symlink_metadata(&path)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        };
        let signing_scrubbed = scrubbed(ACCOUNT_SECRET_FILE);
        let database_scrubbed = scrubbed(EXTERNAL_SQLCIPHER_SECRET_FILE);
        let mut progress_saved = true;
        if let Some(cleanup) = &mut cleanup {
            let signing = credential_index(SecretCredentialKind::Signing);
            if signing_scrubbed
                && cleanup.legacy[signing].as_ref().is_some_and(|legacy| {
                    legacy.kind == SecretCredentialKind::Signing
                        && cleanup.account.as_ref() == Some(&legacy.account)
                        && legacy.local_tombstone_home.as_deref().is_some_and(|home| {
                            self.home_identity(false)
                                .is_ok_and(|current| current == home)
                        })
                })
                && crate::io::sync_directory(tombstone).is_ok()
            {
                cleanup.legacy[signing] = None;
                progress_saved =
                    write_private_json(&self.root, tombstone.join(WIPE_CLEANUP_FILE), cleanup)
                        .is_ok();
            }
            for index in 0..cleanup.credentials.len() {
                let Some(CleanupCredential { credential, mode }) = &cleanup.credentials[index]
                else {
                    continue;
                };
                if cleanup
                    .account
                    .as_ref()
                    .is_none_or(|account| self.check_credential(account, credential).is_err())
                {
                    continue;
                }
                if self
                    .secret_store
                    .release_secret(credential.request(), *mode)
                    .is_ok_and(|outcome| outcome == SecretReleaseOutcome::Released)
                {
                    cleanup.credentials[index] = None;
                    progress_saved &=
                        write_private_json(&self.root, tombstone.join(WIPE_CLEANUP_FILE), cleanup)
                            .is_ok();
                }
            }
        }
        let unknown = cleanup.is_none();
        let mut pending = !signing_scrubbed
            || !database_scrubbed
            || !progress_saved
            || cleanup.as_ref().is_none_or(|cleanup| {
                cleanup.credentials.iter().any(Option::is_some)
                    || cleanup.legacy.iter().any(Option::is_some)
            });
        match fs::read_dir(tombstone) {
            Ok(entries) => {
                for entry in entries {
                    let result = (|| -> std::io::Result<()> {
                        let entry = entry?;
                        let name = entry.file_name();
                        if name == WIPE_CLEANUP_FILE
                            || name == ACCOUNT_SECRET_FILE
                            || name == EXTERNAL_SQLCIPHER_SECRET_FILE
                            || (unknown
                                && (name == ACCOUNT_RECORD_FILE || name == CREDENTIAL_OWNERS_FILE))
                        {
                            return Ok(());
                        }
                        if entry.file_type()?.is_dir() {
                            fs::remove_dir_all(entry.path())
                        } else {
                            fs::remove_file(entry.path())
                        }
                    })();
                    if result.is_err() {
                        pending = true;
                    }
                }
            }
            Err(_) => pending = true,
        }
        if !pending
            && let Err(error) = fs::remove_file(tombstone.join(WIPE_CLEANUP_FILE))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            pending = true;
        }
        if fs::remove_dir(tombstone).is_err() {
            pending = true;
        }
        if pending {
            tracing::warn!(target: TRACE_TARGET, method = "finish_wipe_cleanup", "wipe committed; credential or file cleanup remains pending");
        }
    }

    pub(super) fn admit_external_database_secret(
        &self,
        account_ref: &str,
        mode: ExternalSecretMode,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        if !account.external_signing || account.local_signing {
            return Err(AccountHomeError::InvalidSecretKey);
        }
        let legacy_path = self
            .account_dir(&account.label)
            .join(EXTERNAL_SQLCIPHER_SECRET_FILE);
        let legacy = match read_secret_text(&legacy_path) {
            Ok(raw) => Some(nostr::prelude::Keys::new(
                nostr::prelude::SecretKey::from_hex(raw.trim())
                    .map_err(|_| AccountHomeError::InvalidSecretKey)?,
            )),
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                None
            }
            Err(error) => return Err(error),
        };
        let keys = if let Some(keys) = &legacy {
            self.acquire_credential(
                &account,
                SecretCredentialKind::ExternalDatabase,
                SecretClaimMode::MigrateLegacy,
                Some(keys),
            )?
            .keys
        } else {
            match self.load_credential(&account, SecretCredentialKind::ExternalDatabase) {
                Ok(keys) => keys,
                Err(error) if missing_secret(&error) && mode == ExternalSecretMode::Create => {
                    let keys = nostr::prelude::Keys::generate();
                    self.renew_credential(
                        &account,
                        SecretCredentialKind::ExternalDatabase,
                        Some(&keys),
                    )?
                    .keys
                }
                Err(error) => return Err(error),
            }
        };
        if legacy
            .as_ref()
            .is_some_and(|legacy| legacy.secret_key() != keys.secret_key())
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        if legacy.is_some() {
            scrub_and_remove_local_secret_file(&legacy_path)?;
        }
        Ok(keys)
    }
}
