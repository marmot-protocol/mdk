//! Persistent account home: local Nostr account records and signing credentials.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use std::fs;
use zeroize::Zeroizing;

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::io::{
    read_json, validate_account_label, write_json, write_secret_bytes, write_secret_json,
};
use crate::secret_store::{
    AccountSecretStore, KeychainSecretStore, LocalFileSecretStore,
    scrub_and_remove_local_secret_file,
};

const ACCOUNT_RECORD_FILE: &str = "account.json";
const ACCOUNT_SETUP_STATE_FILE: &str = ".account-setup.json";
const ACCOUNT_SETUP_CONTEXT_FILE: &str = ".account-setup-context.json";
/// Per-account NIP-49 KEY_SECURITY_BYTE status record. Records only a status
/// byte, never key material, so it is written with public file permissions.
const ACCOUNT_KEY_SECURITY_FILE: &str = "key-security.json";
pub(crate) const ACCOUNT_SECRET_FILE: &str = "secret.json";
pub const EXTERNAL_SQLCIPHER_SECRET_FILE: &str = ".external-sqlcipher-secret";
pub(crate) const LOCAL_FILE_SECRET_BACKEND: &str = "local-dev-file";
pub const DEFAULT_KEYCHAIN_SERVICE_NAME: &str = "com.marmot.whitenoise";
const TRACE_TARGET: &str = "marmot_account::home";
/// Subdirectory of the home root that holds account directories that have been
/// atomically renamed out of the live `accounts/` namespace by
/// [`AccountHome::remove_account`] and are pending best-effort deletion. It is
/// deliberately not under `accounts/` so account enumeration never observes a
/// tombstone as a live record.
const WIPE_TOMBSTONE_DIR: &str = ".wipe-tombstones";

/// Disambiguates concurrent tombstone names within a single process.
static TOMBSTONE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Persistent home for local Nostr account records and their signing
/// credentials.
///
/// `AccountHome` is **not safe for arbitrary concurrent mutation**.
/// Methods such as [`AccountHome::create_account`] and
/// [`AccountHome::import_account`] perform check-then-act sequences over
/// the filesystem and the secret store (e.g. checking
/// [`AccountSecretStore::has_secret_for_label`] /
/// [`AccountSecretStore::has_secret_for_account_id`] before writing a
/// credential). Two callers racing those methods can both observe the
/// pre-state and both proceed, which can produce duplicate writes. The
/// duplicate-key guard in `write_signing_account_for_label` is advisory,
/// not atomic; callers needing concurrent imports must serialize
/// mutations externally.
///
/// [`AccountHome::remove_account`] is the exception: it holds an internal
/// mutation lock across its shared-credential check and the matching
/// `remove_secret` call, so concurrent `remove_account` calls on twin
/// records sharing a credential cannot both skip deletion and orphan it.
#[derive(Clone)]
pub struct AccountHome {
    root: PathBuf,
    secret_store: Arc<dyn AccountSecretStore>,
    /// Serializes mutating operations whose check-then-act sequences would
    /// otherwise race against concurrent callers. Currently held by
    /// [`AccountHome::remove_account`] to make the
    /// `secret_shared_with_other_record` check and the matching
    /// `remove_secret` call atomic, so two concurrent removals on twin
    /// records cannot both observe the other as still present and skip
    /// deleting the shared credential.
    mutation_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    /// The account signs through a host-provided external signer instead of a
    /// local nsec. Public/tracked accounts keep both signing flags false.
    #[serde(default)]
    pub external_signing: bool,
    /// Durable local runtime state for reversible sign-out. A signed-out
    /// account keeps its local signing secret and account directory but must not
    /// be auto-started by runtime reconciliation until an explicit sign-in
    /// clears this flag.
    #[serde(default)]
    pub signed_out: bool,
}

/// Provenance for a strict Nostr private-key import used by account setup.
///
/// A live account record is never treated as idempotent by this flow. The
/// only reusable state is an exact account-id-keyed signing credential whose
/// filesystem account record is absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrAccountImport {
    account: AccountSummary,
    reused_account_id_credential: bool,
}

/// Durable provenance and progress for an account setup that has not committed.
///
/// This file is created with the account record and removed only after the app
/// runtime has completed setup. It makes task cancellation and process death
/// recoverable without treating the mere existence of `session.sqlite` as evidence
/// that a KeyPackage was previously published.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSetupState {
    pub account_id_hex: String,
    pub reused_account_id_credential: bool,
    #[serde(default)]
    pub kind: AccountSetupKind,
    pub phase: AccountSetupPhase,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountSetupKind {
    #[default]
    ImportedIdentity,
    GeneratedIdentity,
    PublicIdentity,
    ExternalSigner,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountSetupPhase {
    #[default]
    LocalStateCreated,
    /// The identity, app-visible profile, account database, stable KeyPackage
    /// slot, private KeyPackage material, and exact signed publication bytes
    /// are durable locally. Generated-account callers may return at this
    /// boundary; network publication remains journaled and resumable.
    LocalReady,
    /// Set before publishing the account's replaceable bootstrap records
    /// (relay lists and, for generated identities, the empty follow list and
    /// default profile). A retry may safely republish those records, but setup
    /// rollback must stop here because a relay may already have accepted one
    /// member of the batch.
    BootstrapPublicationStarted,
    /// Every required bootstrap record reached at least one relay and its
    /// local directory projection is durable.
    BootstrapPublicationConfirmed,
    /// Set before entering KeyPackage preparation/publication. If the task is
    /// cancelled after this point, the SQLCipher lifecycle is authoritative:
    /// exact signed bytes are persisted there before the first network send.
    KeyPackagePublicationStarted,
    KeyPackagePublicationConfirmed,
}

impl NostrAccountImport {
    pub fn account(&self) -> &AccountSummary {
        &self.account
    }
}

impl AccountSummary {
    pub fn can_sign(&self) -> bool {
        self.local_signing || self.external_signing
    }

    pub fn is_active_signing(&self) -> bool {
        self.can_sign() && !self.signed_out
    }

    pub fn is_active_local_signing(&self) -> bool {
        self.local_signing && !self.signed_out
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredKeySecurity {
    /// NIP-49 KEY_SECURITY_BYTE. 0x00 = weak/insecure (revealed/exported in
    /// raw form), 0x01 = not known to have been handled insecurely, 0x02 =
    /// unknown/untracked. We only ever transition toward 0x00.
    key_security_byte: u8,
}

impl AccountHome {
    pub fn open(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Self {
            secret_store: Arc::new(LocalFileSecretStore::new(&root)),
            root,
            mutation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn open_with_keychain(
        root: impl AsRef<Path>,
        service_name: impl Into<String>,
    ) -> AccountHomeResult<Self> {
        let secret_store = Arc::new(KeychainSecretStore::new(service_name)?);
        Ok(Self::open_with_secret_store(root, secret_store))
    }

    pub fn open_with_default_keychain(root: impl AsRef<Path>) -> AccountHomeResult<Self> {
        Self::open_with_keychain(root, DEFAULT_KEYCHAIN_SERVICE_NAME)
    }

    pub fn open_with_secret_store(
        root: impl AsRef<Path>,
        secret_store: Arc<dyn AccountSecretStore>,
    ) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            secret_store,
            mutation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn account_dir(&self, label: &str) -> PathBuf {
        self.accounts_dir().join(label)
    }

    pub fn create_account(&self, label: &str) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::Keys::generate();
        self.write_signing_account_for_label(label, &keys)
    }

    pub fn create_nostr_account(&self) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::Keys::generate();
        self.write_signing_account(&keys)
    }

    /// Create a generated identity with its setup journal durable before the
    /// account becomes visible. A restart can therefore resume the same
    /// identity instead of minting another one.
    pub fn create_nostr_account_for_setup(&self) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::Keys::generate();
        let account = AccountSummary {
            label: keys.public_key().to_hex(),
            account_id_hex: keys.public_key().to_hex(),
            local_signing: true,
            external_signing: false,
            signed_out: false,
        };
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        validate_account_label(&account.label)?;
        if self.account_record_path(&account.label).exists() {
            return Err(AccountHomeError::AccountExists(account.label));
        }
        self.begin_account_setup_with(
            &account,
            false,
            AccountSetupKind::GeneratedIdentity,
            AccountSetupPhase::LocalStateCreated,
        )?;
        if let Err(err) = self.secret_store.write_secret(&account, &keys) {
            let _ = self.secret_store.remove_secret(&account);
            let _ = fs::remove_dir_all(self.account_dir(&account.label));
            return Err(err);
        }
        if let Err(err) = self.write_account_record(&account) {
            let _ = self.secret_store.remove_secret(&account);
            let _ = fs::remove_dir_all(self.account_dir(&account.label));
            return Err(err);
        }
        Ok(account)
    }

    /// Recover the one generated setup that did not yet remove its journal.
    pub fn resumable_generated_account_setup(&self) -> AccountHomeResult<Option<AccountSummary>> {
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = self.accounts_dir();
        if !dir.exists() {
            return Ok(None);
        }
        let mut entries = fs::read_dir(&dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let Some(label) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(state) = self.raw_account_setup_state(&label)? else {
                continue;
            };
            if state.kind != AccountSetupKind::GeneratedIdentity {
                continue;
            }
            let account = AccountSummary {
                label: label.clone(),
                account_id_hex: state.account_id_hex,
                local_signing: true,
                external_signing: false,
                signed_out: false,
            };
            if account.label != account.account_id_hex {
                return Err(AccountHomeError::AccountIdMismatch);
            }
            if !self.account_record_path(&label).exists() {
                let has_secret = self.secret_store.has_secret_for_label(&label)?
                    || self
                        .secret_store
                        .has_secret_for_account_id(&account.account_id_hex)?;
                if !has_secret {
                    fs::remove_dir_all(self.account_dir(&label))?;
                    continue;
                }
                self.write_account_record(&account)?;
            }
            let keys = self.secret_store.load_secret(&account)?;
            if keys.public_key().to_hex() != account.account_id_hex {
                return Err(AccountHomeError::AccountIdMismatch);
            }
            return Ok(Some(account));
        }
        Ok(None)
    }

    pub fn import_account(
        &self,
        label: &str,
        secret_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account_for_label(label, &keys)
    }

    /// Import a local signing identity, reusing or repairing an exact match.
    ///
    /// This is intended for repeatable bootstrap flows. It never creates a
    /// second local-signing record for the same public key, and a retry can
    /// finish an import interrupted after the account record was persisted but
    /// before its secret was written.
    pub fn import_account_idempotent(
        &self,
        label: &str,
        secret_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        validate_account_label(label)?;

        let account_id_hex = keys.public_key().to_hex();
        if self.account_record_path(label).exists() {
            let account = self.account(label)?;
            if account.account_id_hex != account_id_hex || !account.local_signing {
                return Err(AccountHomeError::AccountExists(label.to_owned()));
            }
            return self.reuse_or_repair_signing_account(account, &keys);
        }

        if let Some(account) = self
            .accounts()?
            .into_iter()
            .find(|account| account.local_signing && account.account_id_hex == account_id_hex)
        {
            return self.reuse_or_repair_signing_account(account, &keys);
        }

        let account = AccountSummary {
            label: label.to_owned(),
            account_id_hex,
            local_signing: true,
            external_signing: false,
            signed_out: false,
        };

        // Recover a credential left behind by the old secret-first import
        // ordering (#822), or a same-label local-file secret whose record was
        // interrupted. Verify that it is the requested identity before making
        // the account visible again.
        if self.secret_store.has_secret_for_label(label)?
            || self
                .secret_store
                .has_secret_for_account_id(&account.account_id_hex)?
        {
            let stored_keys = self.secret_store.load_secret(&account)?;
            if stored_keys.public_key() != keys.public_key() {
                return Err(AccountHomeError::AccountIdMismatch);
            }
            self.write_account_record(&account)?;
            return Ok(account);
        }

        self.write_new_signing_account(&account, &keys)
    }

    pub fn import_nostr_account(&self, secret_key: &str) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account(&keys)
    }

    /// Import a Nostr private key for runtime account setup, resuming only an
    /// exact journaled setup or orphaned account-id-keyed credential.
    ///
    /// Committed account records remain duplicates and are rejected. This is
    /// narrower than [`Self::import_account_idempotent`]: it also exists for
    /// uninstall/reinstall recovery where an app's filesystem home was removed
    /// while its Keychain entry survived.
    pub fn import_nostr_account_idempotent(
        &self,
        secret_key: &str,
    ) -> AccountHomeResult<NostrAccountImport> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        let account_id_hex = keys.public_key().to_hex();
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        validate_account_label(&account_id_hex)?;

        if self.account_record_path(&account_id_hex).exists() {
            let account = self.account(&account_id_hex)?;
            let Some(setup) = self.account_setup_state(&account_id_hex)? else {
                return Err(AccountHomeError::AccountExists(account.label));
            };
            if !account.local_signing || setup.account_id_hex != account.account_id_hex {
                return Err(AccountHomeError::AccountExists(account_id_hex));
            }
            let stored_keys = self.secret_store.load_secret(&account)?;
            if stored_keys.public_key() != keys.public_key() {
                return Err(AccountHomeError::AccountIdMismatch);
            }
            return Ok(NostrAccountImport {
                account,
                reused_account_id_credential: setup.reused_account_id_credential,
            });
        }
        let account = AccountSummary {
            label: account_id_hex.clone(),
            account_id_hex,
            local_signing: true,
            external_signing: false,
            signed_out: false,
        };
        if let Some(setup) = self.raw_account_setup_state(&account.label)? {
            if setup.account_id_hex != account.account_id_hex
                || setup.kind != AccountSetupKind::ImportedIdentity
            {
                return Err(AccountHomeError::AccountExists(account.label));
            }
            match self.secret_store.load_secret(&account) {
                Ok(stored_keys) if stored_keys.public_key() == keys.public_key() => {}
                Ok(_) => return Err(AccountHomeError::AccountIdMismatch),
                Err(AccountHomeError::SecretNotFound(_)) => {
                    self.secret_store.write_secret(&account, &keys)?;
                }
                Err(AccountHomeError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                    self.secret_store.write_secret(&account, &keys)?;
                }
                Err(err) => return Err(err),
            }
            self.write_account_record(&account)?;
            return Ok(NostrAccountImport {
                account,
                reused_account_id_credential: setup.reused_account_id_credential,
            });
        }
        if self.secret_store.has_secret_for_label(&account.label)? {
            return Err(AccountHomeError::AccountExists(account.label));
        }
        if self.accounts()?.iter().any(|existing| {
            existing.local_signing && existing.account_id_hex == account.account_id_hex
        }) {
            return Err(AccountHomeError::AccountIdInUse(account.account_id_hex));
        }
        let reused_account_id_credential = self
            .secret_store
            .has_secret_for_account_id(&account.account_id_hex)?;
        let setup = AccountSetupState {
            account_id_hex: account.account_id_hex.clone(),
            reused_account_id_credential,
            kind: AccountSetupKind::ImportedIdentity,
            phase: AccountSetupPhase::LocalStateCreated,
        };
        self.write_account_setup_state(&account.label, &setup)?;
        if reused_account_id_credential {
            let stored_keys = self.secret_store.load_secret(&account)?;
            if stored_keys.public_key() != keys.public_key() {
                return Err(AccountHomeError::AccountIdMismatch);
            }
        } else {
            if let Err(err) = self.secret_store.write_secret(&account, &keys) {
                let _ = fs::remove_dir_all(self.account_dir(&account.label));
                return Err(err);
            }
        }
        if let Err(err) = self.write_account_record(&account) {
            if !reused_account_id_credential {
                let _ = self.secret_store.remove_secret(&account);
            }
            let _ = fs::remove_dir_all(self.account_dir(&account.label));
            return Err(err);
        }

        Ok(NostrAccountImport {
            account,
            reused_account_id_credential,
        })
    }

    /// Create the durable setup journal for a newly-created account.
    pub fn begin_account_setup(
        &self,
        account: &AccountSummary,
        reused_account_id_credential: bool,
    ) -> AccountHomeResult<AccountSetupState> {
        self.begin_account_setup_with(
            account,
            reused_account_id_credential,
            AccountSetupKind::ImportedIdentity,
            AccountSetupPhase::LocalStateCreated,
        )
    }

    pub fn begin_account_setup_with(
        &self,
        account: &AccountSummary,
        reused_account_id_credential: bool,
        kind: AccountSetupKind,
        phase: AccountSetupPhase,
    ) -> AccountHomeResult<AccountSetupState> {
        let state = AccountSetupState {
            account_id_hex: account.account_id_hex.clone(),
            reused_account_id_credential,
            kind,
            phase,
        };
        self.write_account_setup_state(&account.label, &state)?;
        Ok(state)
    }

    pub fn account_setup_state(
        &self,
        account_ref: &str,
    ) -> AccountHomeResult<Option<AccountSetupState>> {
        let account = self.account(account_ref)?;
        self.raw_account_setup_state(&account.label)
    }

    fn raw_account_setup_state(&self, label: &str) -> AccountHomeResult<Option<AccountSetupState>> {
        match read_json(self.account_setup_state_path(label)) {
            Ok(state) => Ok(Some(state)),
            Err(AccountHomeError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    pub fn set_account_setup_phase(
        &self,
        account_ref: &str,
        phase: AccountSetupPhase,
    ) -> AccountHomeResult<()> {
        let account = self.account(account_ref)?;
        let Some(mut state) = self.account_setup_state(&account.label)? else {
            return Err(AccountHomeError::AccountSetupStateMissing);
        };
        if state.account_id_hex != account.account_id_hex {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        state.phase = phase;
        write_secret_json(self.account_setup_state_path(&account.label), &state)
    }

    fn write_account_setup_state(
        &self,
        label: &str,
        state: &AccountSetupState,
    ) -> AccountHomeResult<()> {
        validate_account_label(label)?;
        write_secret_json(self.account_setup_state_path(label), state)
    }

    pub fn complete_account_setup(&self, account_ref: &str) -> AccountHomeResult<()> {
        let account = self.account(account_ref)?;
        for path in [
            self.account_setup_state_path(&account.label),
            self.account_setup_context_path(&account.label),
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    /// Store app-owned, opaque setup context alongside the account journal.
    /// The account layer does not interpret these bytes; it only provides the
    /// same private, atomic durability contract as the journal itself.
    pub fn set_account_setup_context(
        &self,
        account_ref: &str,
        bytes: &[u8],
    ) -> AccountHomeResult<()> {
        let account = self.account(account_ref)?;
        if self.raw_account_setup_state(&account.label)?.is_none() {
            return Err(AccountHomeError::AccountSetupStateMissing);
        }
        write_secret_bytes(self.account_setup_context_path(&account.label), bytes)
    }

    pub fn account_setup_context(&self, account_ref: &str) -> AccountHomeResult<Option<Vec<u8>>> {
        let account = self.account(account_ref)?;
        match fs::read(self.account_setup_context_path(&account.label)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Remove an explicitly-authorized legacy incomplete setup while retaining
    /// the matching account-id-keyed credential for the immediate retry.
    pub fn reset_incomplete_setup_preserving_credential(
        &self,
        account_ref: &str,
    ) -> AccountHomeResult<()> {
        let account = self.account(account_ref)?;
        let preserve = self
            .secret_store
            .has_secret_for_account_id(&account.account_id_hex)?;
        self.remove_account_inner(account_ref, Some(&account), preserve)
    }

    pub fn add_public_account(&self, public_key: &str) -> AccountHomeResult<AccountSummary> {
        let account_id_hex = Self::account_id_for_public_key(public_key)?;
        if self.account_record_path(&account_id_hex).exists() {
            return Err(AccountHomeError::AccountExists(account_id_hex));
        }
        let account = AccountSummary {
            label: account_id_hex.clone(),
            account_id_hex,
            local_signing: false,
            external_signing: false,
            signed_out: false,
        };
        self.write_account_record(&account)?;
        Ok(account)
    }

    pub fn add_external_signer_account(
        &self,
        public_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        let account_id_hex = Self::account_id_for_public_key(public_key)?;
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.account_record_path(&account_id_hex).exists() {
            let mut account = self.account(&account_id_hex)?;
            if account.local_signing {
                return Err(AccountHomeError::AccountExists(account_id_hex));
            }
            if !account.external_signing {
                account.external_signing = true;
                self.write_account_record(&account)?;
            }
            return Ok(account);
        }
        let account = AccountSummary {
            label: account_id_hex.clone(),
            account_id_hex,
            local_signing: false,
            external_signing: true,
            signed_out: false,
        };
        self.write_account_record(&account)?;
        Ok(account)
    }

    /// Undo the `external_signing` promotion that [`Self::add_external_signer_account`]
    /// applies to a pre-existing public/tracked account, so a failed external-signer
    /// setup restores that account to its prior tracked state instead of leaving it
    /// half-configured. A no-op for local accounts, and for accounts that were
    /// already external (nothing was promoted).
    pub fn revert_external_signer_upgrade(&self, account_ref: &str) -> AccountHomeResult<()> {
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut account = self.account(account_ref)?;
        if account.external_signing && !account.local_signing {
            account.external_signing = false;
            self.write_account_record(&account)?;
        }
        Ok(())
    }

    pub fn account_id_for_secret(secret_key: &str) -> AccountHomeResult<String> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        Ok(keys.public_key().to_hex())
    }

    pub fn account_id_for_public_key(public_key: &str) -> AccountHomeResult<String> {
        nostr::PublicKey::parse(public_key)
            .map(|pubkey| pubkey.to_hex())
            .map_err(|_| AccountHomeError::InvalidPublicKey)
    }

    pub fn account(&self, account_ref: &str) -> AccountHomeResult<AccountSummary> {
        if validate_account_label(account_ref).is_ok() {
            let path = self.account_record_path(account_ref);
            if path.exists() {
                return read_json(path);
            }
        }

        let account_id = Self::account_id_for_public_key(account_ref)
            .map_err(|_| AccountHomeError::UnknownAccount(account_ref.to_owned()))?;
        let path = self.account_record_path(&account_id);
        if !path.exists() {
            return Err(AccountHomeError::UnknownAccount(account_ref.to_owned()));
        }
        read_json(path)
    }

    pub fn accounts(&self) -> AccountHomeResult<Vec<AccountSummary>> {
        let dir = self.accounts_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut accounts = Vec::new();
        let mut skipped_unreadable_records = 0usize;
        for entry in fs::read_dir(dir)? {
            let path = entry?.path().join(ACCOUNT_RECORD_FILE);
            if path.exists() {
                match read_json(path) {
                    Ok(account) => accounts.push(account),
                    Err(_) => skipped_unreadable_records += 1,
                }
            }
        }
        if skipped_unreadable_records > 0 {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "accounts",
                skipped_account_records = skipped_unreadable_records,
                "skipped unreadable account records while listing accounts"
            );
        }
        accounts.sort_by(|a: &AccountSummary, b| a.account_id_hex.cmp(&b.account_id_hex));
        Ok(accounts)
    }

    /// Persist the reversible sign-out marker for a local-signing account.
    ///
    /// This deliberately does not touch the signing secret or account directory:
    /// it only controls whether runtimes should auto-start the account worker.
    pub fn set_account_signed_out(
        &self,
        account_ref: &str,
        signed_out: bool,
    ) -> AccountHomeResult<AccountSummary> {
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut account = self.account(account_ref)?;
        if !account.can_sign() {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
        }
        if account.signed_out == signed_out {
            return Ok(account);
        }
        account.signed_out = signed_out;
        self.write_account_record(&account)?;
        Ok(account)
    }

    /// Remove an account's entire local footprint: its on-disk account
    /// directory (the SQLCipher session database with MLS state + projections,
    /// cached media/source-epoch secrets, on-disk KeyPackage material, and the
    /// SQL account record) and its signing secret.
    ///
    /// # All-or-nothing local wipe
    ///
    /// The account directory is first **atomically renamed** out of the live
    /// `accounts/` namespace into a tombstone under [`WIPE_TOMBSTONE_DIR`]; only
    /// then are the secret and the tombstone bytes deleted. `fs::rename` within
    /// the same filesystem is atomic, so from the perspective of every live
    /// account read ([`AccountHome::account`], [`AccountHome::accounts`]) the
    /// account either still fully exists (rename not yet done) or is entirely
    /// gone (rename done) — there is no observable partial-MLS-DB state.
    ///
    /// This matters for destructive sign-out (`sign_out_and_wipe`): the issue
    /// invariant is that once the MLS-DB wipe starts it must complete, because a
    /// half-wiped MLS database is worse than either extreme. The rename is that
    /// commit point. If the rename itself fails, nothing has been touched and
    /// the error is safe to surface as "wipe did not start". If deleting the
    /// secret or the tombstone fails *after* the rename, the live account is
    /// already gone; the residual tombstone bytes are orphaned junk outside any
    /// live account, so the call still reports success rather than a forbidden
    /// partial-live state.
    pub fn remove_account(&self, account_ref: &str) -> AccountHomeResult<()> {
        self.remove_account_inner(account_ref, None, false)
    }

    /// Roll back a runtime setup import using the provenance captured when the
    /// account record was created.
    ///
    /// If the import recovered an account-id-keyed credential, the filesystem
    /// account state is removed while that pre-existing credential is retained.
    /// Newly created credentials are removed with the account as usual.
    pub fn rollback_nostr_account_import(
        &self,
        imported: &NostrAccountImport,
    ) -> AccountHomeResult<()> {
        self.remove_account_inner(
            &imported.account.label,
            Some(&imported.account),
            imported.reused_account_id_credential,
        )
    }

    fn remove_account_inner(
        &self,
        account_ref: &str,
        expected: Option<&AccountSummary>,
        preserve_account_id_credential: bool,
    ) -> AccountHomeResult<()> {
        // Hold the mutation lock across the shared-credential check and
        // the matching `remove_secret` call so two concurrent removals on
        // twin records cannot both observe the other as still present,
        // both skip deletion, and orphan the shared credential. The lock
        // also serializes the rename-to-tombstone commit point.
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let account = self.account(account_ref)?;
        if expected.is_some_and(|expected| expected != &account) {
            return Err(AccountHomeError::AccountExists(account.label));
        }
        if preserve_account_id_credential {
            if !self
                .secret_store
                .has_secret_for_account_id(&account.account_id_hex)?
            {
                return Err(AccountHomeError::SecretNotFound(
                    account.account_id_hex.clone(),
                ));
            }
            let stored_keys = self.secret_store.load_secret(&account)?;
            if stored_keys.public_key().to_hex() != account.account_id_hex {
                return Err(AccountHomeError::AccountIdMismatch);
            }
        }

        // Commit point: atomically move the live account directory into the
        // tombstone namespace. After this returns Ok the account is no longer a
        // live record and the MLS DB can never be observed half-wiped. A
        // missing directory is treated as already-removed (idempotent).
        let live_dir = self.account_dir(&account.label);
        let tombstone = self.move_account_dir_to_tombstone(&account.label, &live_dir)?;

        // Drop the signing secret unless a twin record still depends on a
        // shared (account-id-keyed) credential. For the local-file store the
        // secret lived inside the account directory we just renamed, so this is
        // a no-op (NotFound -> Ok); the tombstoned secret file is scrubbed below
        // before recursive directory deletion. For the keychain store the entry
        // is independent of the directory and is removed here.
        if !preserve_account_id_credential && !self.secret_shared_with_other_record(&account)? {
            self.secret_store.remove_secret(&account)?;
        }

        // For the local-file secret store, the signing secret moved into the
        // tombstone with the account directory before `remove_secret` ran. Scrub
        // that file explicitly before the recursive unlink so destructive wipe
        // does not devolve to `remove_dir_all` on plaintext key material.
        if let Some(tombstone) = tombstone.as_ref() {
            let secret_path = tombstone.join(ACCOUNT_SECRET_FILE);
            if scrub_and_remove_local_secret_file(&secret_path).is_err() {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "remove_account",
                    "failed to scrub tombstoned local signing secret before directory deletion"
                );
            }
            let external_secret_path = tombstone.join(EXTERNAL_SQLCIPHER_SECRET_FILE);
            if scrub_and_remove_local_secret_file(&external_secret_path).is_err() {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "remove_account",
                    "failed to scrub tombstoned external SQLCipher secret before directory deletion"
                );
            }
        }

        // Best-effort deletion of the tombstoned bytes. A failure here leaves
        // orphaned bytes outside the live `accounts/` namespace, never a
        // partially wiped *live* account, so the wipe is still considered
        // complete.
        if let Some(tombstone) = tombstone
            && let Err(err) = fs::remove_dir_all(&tombstone)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "remove_account",
                "failed to delete wiped account tombstone; bytes are orphaned but no live account remains"
            );
        }
        Ok(())
    }

    /// Atomically rename a live account directory into the tombstone namespace.
    ///
    /// Returns the tombstone path on success, or `None` if the live directory
    /// did not exist (already removed). On any other error the live directory
    /// is left untouched so the caller can report that the wipe never started.
    fn move_account_dir_to_tombstone(
        &self,
        label: &str,
        live_dir: &Path,
    ) -> AccountHomeResult<Option<PathBuf>> {
        if !live_dir.exists() {
            return Ok(None);
        }
        let tombstone_root = self.root.join(WIPE_TOMBSTONE_DIR);
        fs::create_dir_all(&tombstone_root)?;
        for _ in 0..32 {
            let attempt = TOMBSTONE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tombstone =
                tombstone_root.join(format!("{label}.{}.{attempt}", std::process::id()));
            match fs::rename(live_dir, &tombstone) {
                Ok(()) => return Ok(Some(tombstone)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate unique account wipe tombstone",
        )
        .into())
    }

    /// Account-id-keyed stores hold one credential per account id, so records
    /// with the same account id share a single credential. The shared
    /// credential must outlive this record while another signing record still
    /// depends on it.
    ///
    /// This helper is only safe when the caller already holds
    /// `AccountHome::mutation_lock`, which serializes the check against
    /// concurrent removals on twin records. See
    /// [`AccountHome::remove_account`].
    fn secret_shared_with_other_record(&self, account: &AccountSummary) -> AccountHomeResult<bool> {
        if !self
            .secret_store
            .has_secret_for_account_id(&account.account_id_hex)?
        {
            return Ok(false);
        }
        Ok(self.accounts()?.iter().any(|other| {
            other.local_signing
                && other.label != account.label
                && other.account_id_hex == account.account_id_hex
        }))
    }

    pub fn load_signing_keys(&self, account_ref: &str) -> AccountHomeResult<nostr::Keys> {
        let account = self.account(account_ref)?;
        if !account.local_signing {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
        }
        let keys = self.secret_store.load_secret(&account)?;
        if keys.public_key().to_hex() != account.account_id_hex {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        Ok(keys)
    }

    /// NIP-49 KEY_SECURITY_BYTE for `account_ref`. Defaults to 0x02
    /// (unknown/untracked) when no status has been persisted yet.
    pub fn key_security_byte(&self, account_ref: &str) -> AccountHomeResult<u8> {
        let account = self.account(account_ref)?;
        let path = self
            .account_dir(&account.label)
            .join(ACCOUNT_KEY_SECURITY_FILE);
        match read_json::<StoredKeySecurity>(&path) {
            Ok(stored) => Ok(stored.key_security_byte),
            Err(AccountHomeError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                Ok(0x02)
            }
            Err(err) => Err(err),
        }
    }

    /// Mark `account_ref`'s key as handled insecurely (NIP-49 KEY_SECURITY_BYTE
    /// 0x00). Idempotent and monotonic: once 0x00 it stays 0x00 across restarts.
    pub fn mark_key_handled_insecurely(&self, account_ref: &str) -> AccountHomeResult<()> {
        let account = self.account(account_ref)?;
        let path = self
            .account_dir(&account.label)
            .join(ACCOUNT_KEY_SECURITY_FILE);
        write_json(
            &path,
            &StoredKeySecurity {
                key_security_byte: 0x00,
            },
        )
    }

    /// Export `account_ref`'s raw private key in canonical `nsec1...` bech32
    /// form (NIP-19). Reading the raw key out is a NIP-49 "insecure handling"
    /// event, so this also flips the persisted KEY_SECURITY_BYTE to 0x00.
    ///
    /// The returned value is zeroized on drop for Rust callers. That guarantee
    /// stops once a caller clones or converts it into a plain `String`, including
    /// at the UniFFI boundary; unwrap it only there and keep the host-side string
    /// transient.
    pub fn reveal_nsec(&self, account_ref: &str) -> AccountHomeResult<Zeroizing<String>> {
        use nostr::ToBech32;
        let keys = self.load_signing_keys(account_ref)?;
        let nsec = Zeroizing::new(
            keys.secret_key()
                .to_bech32()
                .expect("nsec bech32 encode is infallible"),
        );
        // Persist the insecure-handling marker only after a successful encode.
        self.mark_key_handled_insecurely(account_ref)?;
        Ok(nsec)
    }

    /// Export `account_ref`'s private key as a password-encrypted NIP-49
    /// `ncryptsec1...` backup string using the fixed mobile-friendly log_n=18.
    ///
    /// This does not mark the key as handled insecurely: the raw secret never
    /// leaves the engine in plaintext, so the persisted KEY_SECURITY_BYTE is
    /// copied into the encrypted export as associated data and left unchanged.
    pub fn export_encrypted_secret_key(
        &self,
        account_ref: &str,
        passphrase: &str,
    ) -> AccountHomeResult<String> {
        if passphrase.is_empty() {
            return Err(AccountHomeError::EmptyPassphrase);
        }
        let account = self.account(account_ref)?;
        if !account.is_active_local_signing() {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
        }
        let key_security_byte = self.key_security_byte(&account.label)?;
        let keys = self.load_signing_keys(&account.label)?;
        crate::nip49_export::export_ncryptsec(keys.secret_key(), passphrase, key_security_byte)
    }

    fn write_signing_account(&self, keys: &nostr::Keys) -> AccountHomeResult<AccountSummary> {
        let label = keys.public_key().to_hex();
        self.write_signing_account_for_label(&label, keys)
    }

    fn write_signing_account_for_label(
        &self,
        label: &str,
        keys: &nostr::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        let label = label.to_owned();
        validate_account_label(&label)?;
        if self.account_record_path(&label).exists()
            || self.secret_store.has_secret_for_label(&label)?
        {
            return Err(AccountHomeError::AccountExists(label));
        }
        let account_id_hex = keys.public_key().to_hex();
        // NOTE: this check-then-write is advisory. Concurrent callers can
        // both observe an empty store and both proceed. See the `AccountHome`
        // type-level docs; callers needing concurrent imports must serialize
        // externally.
        if self
            .secret_store
            .has_secret_for_account_id(&account_id_hex)?
        {
            return Err(AccountHomeError::AccountIdInUse(account_id_hex));
        }
        let account = AccountSummary {
            label,
            account_id_hex,
            local_signing: true,
            external_signing: false,
            signed_out: false,
        };
        self.write_new_signing_account(&account, keys)
    }

    fn reuse_or_repair_signing_account(
        &self,
        mut account: AccountSummary,
        keys: &nostr::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        match self.secret_store.load_secret(&account) {
            Ok(stored_keys) => {
                if stored_keys.public_key() != keys.public_key() {
                    return Err(AccountHomeError::AccountIdMismatch);
                }
            }
            Err(AccountHomeError::SecretNotFound(_)) => {
                self.secret_store.write_secret(&account, keys)?;
            }
            Err(AccountHomeError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                self.secret_store.write_secret(&account, keys)?;
            }
            Err(err) => return Err(err),
        }
        if account.signed_out {
            account.signed_out = false;
            self.write_account_record(&account)?;
        }
        Ok(account)
    }

    fn write_new_signing_account(
        &self,
        account: &AccountSummary,
        keys: &nostr::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        // Record first so a crash cannot leave an invisible keychain credential
        // that permanently blocks re-import. A record without a secret is
        // visible/removable and `import_account_idempotent` repairs it on retry.
        self.write_account_record(account)?;
        if let Err(err) = self.secret_store.write_secret(account, keys) {
            let _ = fs::remove_file(self.account_record_path(&account.label));
            let _ = fs::remove_dir(self.account_dir(&account.label));
            return Err(err);
        }
        Ok(account.clone())
    }

    fn write_account_record(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        validate_account_label(&account.label)?;
        write_json(self.account_record_path(&account.label), account)
    }

    fn accounts_dir(&self) -> PathBuf {
        self.root.join("accounts")
    }

    fn account_record_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_RECORD_FILE)
    }

    fn account_setup_state_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_SETUP_STATE_FILE)
    }

    fn account_setup_context_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_SETUP_CONTEXT_FILE)
    }
}
