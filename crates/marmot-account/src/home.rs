//! Persistent account home: local Nostr account records and signing credentials.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use zeroize::Zeroizing;

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::io::{
    read_immutable_json, read_immutable_json_bounded, read_json, read_private_json,
    read_private_json_bounded, read_secret_text, validate_account_label, write_private_bytes,
    write_private_json,
};
use crate::secret_store::{
    AccountSecretStore, KeychainSecretStore, LocalFileSecretStore,
    scrub_and_remove_local_secret_file,
};
use crate::{
    AcquiredSecret, IosOptions, SecretClaimMode, SecretCredential, SecretCredentialKind,
    SecretOrigin, SecretReleaseMode, SecretReleaseOutcome,
};

const ACCOUNT_RECORD_FILE: &str = "account.json";
const EXTERNAL_DATABASE_CREDENTIAL_PREFIX: &str = ".external-sqlcipher/";
const NIP46_CREDENTIAL_PREFIX: &str = ".nip46-client/";
const NIP46_SESSION_FILE: &str = ".nip46-session.json";
const NIP46_REMOVING_FILE: &str = ".nip46-session-removing.json";
const MAX_NIP46_RECORD_BYTES: u64 = 128 * 1024;
const ACCOUNT_SETUP_STATE_FILE: &str = ".account-setup.json";
const ACCOUNT_SETUP_CONTEXT_FILE: &str = ".account-setup-context.json";
/// Per-account NIP-49 KEY_SECURITY_BYTE status record. Records only a status
/// byte, never key material, so it is written with public file permissions.
const ACCOUNT_KEY_SECURITY_FILE: &str = "key-security.json";
pub(crate) const ACCOUNT_SECRET_FILE: &str = "secret.json";
pub const EXTERNAL_SQLCIPHER_SECRET_FILE: &str = ".external-sqlcipher-secret";
pub(crate) const LOCAL_FILE_SECRET_BACKEND: &str = "local-dev-file";
const TRACE_TARGET: &str = "marmot_account::home";
/// Subdirectory of the home root that holds account directories that have been
/// atomically renamed out of the live `accounts/` namespace by
/// [`AccountHome::remove_account`] and are pending best-effort deletion. It is
/// deliberately not under `accounts/` so account enumeration never observes a
/// tombstone as a live record.
const WIPE_TOMBSTONE_DIR: &str = ".wipe-tombstones";
const WIPE_CLEANUP_FILE: &str = ".wipe-cleanup.json";
const CREDENTIAL_OWNERS_FILE: &str = ".credential-ownership.json";
const HOME_IDENTITY_FILE: &str = ".account-home-id.json";
const MAX_WIPE_CLEANUP_BYTES: u64 = 16 * 1024;
/// Stable root lease filename for account mutations. Never unlink while the root is in use.
pub const ROOT_MUTATION_LOCK_FILE: &str = ".account-mutation.lock";

enum SigningKeyRemoval {
    Delete,
    Preserve,
}

enum NonlocalAdmission {
    Public,
    PublicSetup,
    External,
    ExternalSetup,
}

#[derive(Default, Serialize, Deserialize)]
struct WipeCleanup {
    account: Option<AccountSummary>,
    credentials: [Option<CleanupCredential>; 3],
    legacy: [Option<LegacyCredential>; 3],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialManifest {
    account: AccountSummary,
    legacy: bool,
    // Clearing an owner must not reopen admission of retained raw keys.
    nip46_admission: Nip46Admission,
    credentials: [Option<OwnedCredential>; 3],
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Nip46Admission {
    LegacyAllowed,
    ManagedOnly,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedCredential {
    namespace: [u8; 32],
    home_id: String,
    owner_id: String,
    account: AccountSummary,
    kind: SecretCredentialKind,
    claim_mode: SecretClaimMode,
    origin: Option<SecretOrigin>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupCredential {
    credential: OwnedCredential,
    mode: SecretReleaseMode,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCredential {
    account: AccountSummary,
    kind: SecretCredentialKind,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HomeIdentity {
    id: String,
    path_hash: String,
}

impl OwnedCredential {
    fn request(&self) -> SecretCredential<'_> {
        SecretCredential {
            label: &self.account.label,
            account_id_hex: &self.account.account_id_hex,
            home_id: &self.home_id,
            owner_id: &self.owner_id,
            kind: self.kind,
        }
    }
}

/// Disambiguates concurrent tombstone names within a single process.
static TOMBSTONE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Persistent home for local Nostr account records and their signing
/// credentials.
///
/// Credential mutations serialize across clones and independently opened
/// handles to the same root. Independent mutations return an I/O
/// [`std::io::ErrorKind::WouldBlock`] error if another mutation holds the root
/// lease. Existing managed credentials can be read without that lease.
#[derive(Clone)]
pub struct AccountHome {
    root: PathBuf,
    secret_store: Arc<dyn AccountSecretStore>,
    ios_options: IosOptions,
    /// Serializes mutating operations whose check-then-act sequences would
    /// otherwise race against concurrent callers, including session credential
    /// writes/removals and the account wipe commit point.
    mutation_lock: Arc<Mutex<()>>,
    home_id: Arc<OnceLock<(PathBuf, String)>>,
    vault_namespace: Arc<OnceLock<[u8; 32]>>,
}

struct AccountMutationGuard<'a> {
    #[cfg(any(unix, windows))]
    _root_lease: fs_private::PrivateExclusiveFileLease,
    _clone_guard: MutexGuard<'a, ()>,
}

enum CredentialRead<T> {
    Ready(T),
    Admission,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    /// The account signs through an external signer instead of a
    /// local nsec. Public/tracked accounts keep both signing flags false.
    #[serde(default)]
    pub external_signing: bool,
    /// Durable local runtime state for reversible sign-out. A signed-out
    /// account keeps its local signing secret and account directory but must not
    /// be auto-started by runtime reconciliation until an explicit sign-in
    /// clears this flag.
    #[serde(default)]
    pub signed_out: bool,
    /// The account's device group removed this device after its link was
    /// made. An unlinked account is also signed out, and stays so: it can
    /// only be wiped, and coming back is a new link (mdk#2628 D67).
    #[serde(default)]
    pub unlinked: bool,
}

/// Nonsecret, versioned metadata for an account's remote-signing session.
/// The communication key is stored separately through [`AccountSecretStore`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Nip46SessionRecord {
    pub version: u32,
    pub user_public_key: String,
    pub remote_signer_public_key: String,
    pub client_public_key: String,
    pub relays: Vec<String>,
    pub name: String,
    pub permission_version: u32,
    pub permissions: Vec<String>,
}

/// Credential ownership observed atomically while storing a pairing.
#[derive(Debug)]
pub enum Nip46SessionWrite {
    /// This write created the communication credential.
    Created,
    /// Keep this record and its existing key if later account setup rolls back.
    /// An orphaned existing key retains the newly repaired public record.
    Existing(Nip46SessionRecord),
}

/// Whether cleanup knows that this account owns a NIP-46 credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nip46Removal {
    /// Generic external-account cleanup must not query an unrelated host vault.
    Recorded,
    /// Explicit NIP-46 removal also revokes a key whose metadata was lost.
    IncludingOrphaned,
}

fn invalid_nip46_record() -> AccountHomeError {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid NIP-46 session metadata",
    )
    .into()
}

impl Nip46SessionRecord {
    fn validate(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        if !account.external_signing || account.local_signing {
            return Err(AccountHomeError::InvalidSecretKey);
        }
        if self.version != 1
            || self.permission_version == 0
            || self.relays.is_empty()
            || self.relays.len() > 16
            || self.name.len() > 256
            || self.name.chars().any(char::is_control)
            || self.permissions.len() > 64
            || self.permissions.iter().any(|grant| {
                grant.is_empty()
                    || grant.len() > 256
                    || !grant.is_ascii()
                    || grant.bytes().any(|byte| byte.is_ascii_control())
            })
            || self.relays.iter().any(|relay| {
                relay.len() > 2048
                    || relay.chars().any(char::is_control)
                    || nostr::prelude::RelayUrl::parse(relay).is_err()
            })
        {
            return Err(invalid_nip46_record());
        }
        for public_key in [
            &self.user_public_key,
            &self.remote_signer_public_key,
            &self.client_public_key,
        ] {
            if public_key.len() != 64
                || !nostr::prelude::PublicKey::from_hex(public_key)
                    .is_ok_and(|key| key.to_hex() == *public_key)
            {
                return Err(AccountHomeError::InvalidPublicKey);
            }
        }
        if self.user_public_key != account.account_id_hex {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        Ok(())
    }
}

/// Whether a missing external device key may be created before any database exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalSecretMode {
    Existing,
    Create,
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
    /// Host-driven setup must remain gated until its app checkpoint completes.
    InteractiveIdentity,
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

fn external_database_credential(account: &AccountSummary) -> AccountSummary {
    synthetic_credential(account, EXTERNAL_DATABASE_CREDENTIAL_PREFIX)
}

fn synthetic_credential(account: &AccountSummary, prefix: &str) -> AccountSummary {
    use sha2::{Digest, Sha256};
    let label = format!("{prefix}{}", account.label);
    let account_id_hex = hex::encode(Sha256::digest(label.as_bytes()));
    AccountSummary {
        label,
        account_id_hex,
        local_signing: false,
        external_signing: false,
        signed_out: false,
        unlinked: false,
    }
}

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

fn credential_index(kind: SecretCredentialKind) -> usize {
    match kind {
        SecretCredentialKind::Signing => 0,
        SecretCredentialKind::ExternalDatabase => 1,
        SecretCredentialKind::Nip46Session => 2,
    }
}

fn missing_secret(error: &AccountHomeError) -> bool {
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

    fn home_identity(&self, readonly: bool) -> AccountHomeResult<&str> {
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
        write_private_json(&path, &identity)?;
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

    fn credential_manifest(&self, label: &str) -> AccountHomeResult<Option<CredentialManifest>> {
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

    fn manifest_or_legacy(
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
                    nip46_admission: if legacy {
                        Nip46Admission::LegacyAllowed
                    } else {
                        Nip46Admission::ManagedOnly
                    },
                    credentials: Default::default(),
                }
            }
        };
        if manifest.account.account_id_hex != account.account_id_hex
            || manifest.account.label != account.label
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        Ok(manifest)
    }

    fn write_credential_manifest(
        &self,
        label: &str,
        manifest: &CredentialManifest,
    ) -> AccountHomeResult<()> {
        write_private_json(
            self.account_dir(label).join(CREDENTIAL_OWNERS_FILE),
            manifest,
        )
    }

    fn check_credential(
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

    fn acquire_credential(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        let mut manifest = self.manifest_or_legacy(account)?;
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
        if let Some(credential) = &mut manifest.credentials[index]
            && kind != SecretCredentialKind::Nip46Session
            && credential.origin.is_none()
            && proposed.is_some()
            && credential.claim_mode != mode
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
        let acquired = self.secret_store.acquire_secret(
            credential.request(),
            credential.claim_mode,
            proposed,
        )?;
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

    fn read_credential(
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

    fn load_credential(
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

    fn renew_credential(
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

    fn retire_claim(
        &self,
        account: &AccountSummary,
        kind: SecretCredentialKind,
        manifest: &mut CredentialManifest,
    ) -> AccountHomeResult<()> {
        let index = credential_index(kind);
        if let Some(credential) = &manifest.credentials[index] {
            self.check_credential(account, credential)?;
            self.secret_store
                .release_secret(credential.request(), SecretReleaseMode::DeleteIfUnowned)?;
            manifest.credentials[index] = None;
            self.write_credential_manifest(&account.label, manifest)?;
        }
        Ok(())
    }

    fn build_wipe_cleanup(
        &self,
        account: &AccountSummary,
        manifest: &CredentialManifest,
        signing: SigningKeyRemoval,
    ) -> AccountHomeResult<WipeCleanup> {
        if manifest.account.account_id_hex != account.account_id_hex
            || manifest.account.label != account.label
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
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
            if !manifest.legacy {
                continue;
            }
            let target = match kind {
                SecretCredentialKind::Signing if account.local_signing => Some(account.clone()),
                SecretCredentialKind::ExternalDatabase if account.external_signing => {
                    Some(external_database_credential(account))
                }
                SecretCredentialKind::Nip46Session if !account.local_signing => (account
                    .external_signing
                    || manifest.account.external_signing
                    || manifest.nip46_admission == Nip46Admission::ManagedOnly)
                    .then(|| synthetic_credential(account, NIP46_CREDENTIAL_PREFIX)),
                _ => None,
            };
            if let Some(account) = target {
                cleanup.legacy[index] = Some(LegacyCredential { account, kind });
            }
        }
        Ok(cleanup)
    }

    fn abort_prepared_account(
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
        write_private_json(directory.join(WIPE_CLEANUP_FILE), &cleanup)?;
        if let Some(tombstone) = self.move_account_dir_to_tombstone(label, directory)? {
            self.finish_wipe_cleanup(&tombstone, Some(cleanup));
        }
        Ok(())
    }

    fn cleanup_abandoned_admissions(&self) -> AccountHomeResult<()> {
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

    fn immutable_read<T>(
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

    fn mutation_guard(&self) -> AccountHomeResult<AccountMutationGuard<'_>> {
        let clone_guard = self.read_guard()?;
        #[cfg(any(unix, windows))]
        {
            let root = match self.canonical_root() {
                Ok(root) => root,
                Err(AccountHomeError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    crate::io::create_durable_private_dir(&self.root)?;
                    self.canonical_root()?
                }
                Err(error) => return Err(error),
            };
            crate::io::create_durable_private_dir(&root)?;
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

    pub fn open(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        let secret_store = Arc::new(LocalFileSecretStore::new(root, IosOptions::default()));
        Self::open_with_secret_store(root, secret_store, IosOptions::default())
    }

    pub fn open_with_keychain(
        root: impl AsRef<Path>,
        service_name: impl Into<String>,
        ios_options: IosOptions,
    ) -> AccountHomeResult<Self> {
        let secret_store = Arc::new(KeychainSecretStore::new(service_name, &ios_options)?);
        Ok(Self::open_with_secret_store(
            root,
            secret_store,
            ios_options,
        ))
    }

    pub fn open_with_secret_store(
        root: impl AsRef<Path>,
        secret_store: Arc<dyn AccountSecretStore>,
        ios_options: IosOptions,
    ) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            secret_store,
            ios_options,
            mutation_lock: Arc::new(Mutex::new(())),
            home_id: Arc::new(OnceLock::new()),
            vault_namespace: Arc::new(OnceLock::new()),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn account_dir(&self, label: &str) -> PathBuf {
        self.accounts_dir().join(label)
    }

    pub fn create_account(&self, label: &str) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::prelude::Keys::generate();
        self.write_signing_account_for_label(label, &keys)
    }

    pub fn create_nostr_account(&self) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::prelude::Keys::generate();
        self.write_signing_account(&keys)
    }

    /// Create a generated identity with its setup journal durable before the
    /// account becomes visible. A restart can therefore resume the same
    /// identity instead of minting another one.
    pub fn create_nostr_account_for_setup(&self) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::prelude::Keys::generate();
        let account = AccountSummary {
            label: keys.public_key().to_hex(),
            account_id_hex: keys.public_key().to_hex(),
            local_signing: true,
            external_signing: false,
            signed_out: false,
            unlinked: false,
        };
        let _guard = self.mutation_guard()?;
        validate_account_label(&account.label)?;
        if self.account_record_path(&account.label).try_exists()?
            || self.raw_account_setup_state(&account.label)?.is_some()
            || self.secret_store.has_secret_for_label(&account.label)?
            || self
                .secret_store
                .has_secret_for_account_id(&account.account_id_hex)?
        {
            return Err(AccountHomeError::AccountExists(account.label));
        }
        let state = AccountSetupState {
            account_id_hex: account.account_id_hex.clone(),
            reused_account_id_credential: false,
            kind: AccountSetupKind::GeneratedIdentity,
            phase: AccountSetupPhase::LocalStateCreated,
        };
        self.write_account_setup_state(&account.label, &state)?;
        self.acquire_credential(
            &account,
            SecretCredentialKind::Signing,
            SecretClaimMode::CreateOnly,
            Some(&keys),
        )?;
        self.write_account_record(&account)?;
        Ok(account)
    }

    /// Recover an active generated setup that did not yet remove its journal.
    pub fn resumable_generated_account_setup(&self) -> AccountHomeResult<Option<AccountSummary>> {
        let _guard = self.mutation_guard()?;
        let dir = self.accounts_dir();
        if !dir.exists() {
            return Ok(None);
        }
        let mut entries = fs::read_dir(&dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if !entry.file_type()?.is_dir() {
                continue;
            }
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
                unlinked: false,
            };
            if account.label != account.account_id_hex {
                return Err(AccountHomeError::AccountIdMismatch);
            }
            let signing = SecretCredentialKind::Signing;
            if self.account_record_path(&label).try_exists()? {
                let recorded = self.account(&label)?;
                if recorded.signed_out || recorded.unlinked {
                    continue;
                }
                if recorded != account {
                    return Err(AccountHomeError::AccountIdMismatch);
                }
                self.load_credential(&account, signing)?;
                return Ok(Some(account));
            }
            let manifest = self.pending_signing_admission(&label, &account.account_id_hex)?;
            if let Some(manifest) = &manifest
                && let Some(claim) = &manifest.credentials[credential_index(signing)]
            {
                match self.load_credential(&account, signing) {
                    Ok(_) => {}
                    Err(AccountHomeError::SecretNotFound(_)) if claim.origin.is_none() => {
                        self.abort_prepared_account(&label, &entry.path(), manifest)?;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            } else if self.secret_store.has_secret_for_label(&label)?
                || self
                    .secret_store
                    .has_secret_for_account_id(&account.account_id_hex)?
            {
                self.load_credential(&account, signing)?;
            } else {
                if let Some(manifest) = &manifest {
                    self.abort_prepared_account(&label, &entry.path(), manifest)?;
                } else {
                    fs::remove_dir_all(entry.path())?;
                }
                continue;
            }
            self.write_account_record(&account)?;
            return Ok(Some(account));
        }
        Ok(None)
    }

    pub fn import_account(
        &self,
        label: &str,
        secret_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::prelude::Keys::parse(secret_key)
            .map_err(|_| AccountHomeError::InvalidSecretKey)?;
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
        let keys = nostr::prelude::Keys::parse(secret_key)
            .map_err(|_| AccountHomeError::InvalidSecretKey)?;
        let _guard = self.mutation_guard()?;
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
        let _ = self.pending_signing_admission(label, &account_id_hex)?;
        let account = AccountSummary {
            label: label.to_owned(),
            account_id_hex,
            local_signing: true,
            external_signing: false,
            signed_out: false,
            unlinked: false,
        };
        let mode = if self.secret_store.has_secret_for_label(label)?
            || self
                .secret_store
                .has_secret_for_account_id(&account.account_id_hex)?
        {
            SecretClaimMode::MigrateLegacy
        } else {
            SecretClaimMode::CreateOrAdopt
        };
        self.acquire_credential(&account, SecretCredentialKind::Signing, mode, Some(&keys))?;
        self.write_account_record(&account)?;
        Ok(account)
    }

    pub fn import_nostr_account(&self, secret_key: &str) -> AccountHomeResult<AccountSummary> {
        let keys = nostr::prelude::Keys::parse(secret_key)
            .map_err(|_| AccountHomeError::InvalidSecretKey)?;
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
        self.import_nostr_account_with_setup_kind(secret_key, AccountSetupKind::ImportedIdentity)
    }

    /// Persist the interactive setup provenance before making a new identity
    /// visible. A crash before the app writes its detailed checkpoint remains
    /// distinguishable from a completed or legacy account.
    pub fn import_nostr_account_for_onboarding(
        &self,
        secret_key: &str,
    ) -> AccountHomeResult<NostrAccountImport> {
        self.import_nostr_account_with_setup_kind(secret_key, AccountSetupKind::InteractiveIdentity)
    }

    fn import_nostr_account_with_setup_kind(
        &self,
        secret_key: &str,
        kind: AccountSetupKind,
    ) -> AccountHomeResult<NostrAccountImport> {
        let keys = nostr::prelude::Keys::parse(secret_key)
            .map_err(|_| AccountHomeError::InvalidSecretKey)?;
        let account_id_hex = keys.public_key().to_hex();
        let _guard = self.mutation_guard()?;
        validate_account_label(&account_id_hex)?;
        if self.account_record_path(&account_id_hex).try_exists()? {
            let account = self.account(&account_id_hex)?;
            let Some(setup) = self.account_setup_state(&account_id_hex)? else {
                return Err(AccountHomeError::AccountExists(account.label));
            };
            if !account.local_signing || setup.account_id_hex != account.account_id_hex {
                return Err(AccountHomeError::AccountExists(account_id_hex));
            }
            let stored = match self.load_credential(&account, SecretCredentialKind::Signing) {
                Ok(keys) => keys,
                Err(error) if missing_secret(&error) => {
                    self.renew_credential(&account, SecretCredentialKind::Signing, Some(&keys))?
                        .keys
                }
                Err(error) => return Err(error),
            };
            if stored.public_key() != keys.public_key() {
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
            unlinked: false,
        };
        let _ = self.pending_signing_admission(&account.label, &account.account_id_hex)?;
        if let Some(mut setup) = self.raw_account_setup_state(&account.label)? {
            if setup.account_id_hex != account.account_id_hex || setup.kind != kind {
                return Err(AccountHomeError::AccountExists(account.label));
            }
            let acquired = self.acquire_credential(
                &account,
                SecretCredentialKind::Signing,
                SecretClaimMode::MigrateLegacy,
                Some(&keys),
            )?;
            if acquired.origin == SecretOrigin::Existing
                && self
                    .secret_store
                    .has_secret_for_account_id(&account.account_id_hex)?
            {
                setup.reused_account_id_credential = true;
            }
            self.write_account_setup_state(&account.label, &setup)?;
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
        let reused = self
            .secret_store
            .has_secret_for_account_id(&account.account_id_hex)?;
        let mut setup = AccountSetupState {
            account_id_hex: account.account_id_hex.clone(),
            reused_account_id_credential: reused,
            kind,
            phase: AccountSetupPhase::LocalStateCreated,
        };
        self.write_account_setup_state(&account.label, &setup)?;
        let mode = if reused {
            SecretClaimMode::MigrateLegacy
        } else {
            SecretClaimMode::CreateOnly
        };
        let acquired =
            self.acquire_credential(&account, SecretCredentialKind::Signing, mode, Some(&keys))?;
        if acquired.origin == SecretOrigin::Existing
            && self
                .secret_store
                .has_secret_for_account_id(&account.account_id_hex)?
        {
            setup.reused_account_id_credential = true;
            self.write_account_setup_state(&account.label, &setup)?;
        }
        self.write_account_record(&account)?;
        Ok(NostrAccountImport {
            account,
            reused_account_id_credential: setup.reused_account_id_credential,
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
        let _guard = self.mutation_guard()?;
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
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        let Some(mut state) = self.account_setup_state(&account.label)? else {
            return Err(AccountHomeError::AccountSetupStateMissing);
        };
        if state.account_id_hex != account.account_id_hex {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        state.phase = phase;
        write_private_json(self.account_setup_state_path(&account.label), &state)
    }

    fn write_account_setup_state(
        &self,
        label: &str,
        state: &AccountSetupState,
    ) -> AccountHomeResult<()> {
        validate_account_label(label)?;
        write_private_json(self.account_setup_state_path(label), state)
    }

    pub fn complete_account_setup(&self, account_ref: &str) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
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
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        if self.raw_account_setup_state(&account.label)?.is_none() {
            return Err(AccountHomeError::AccountSetupStateMissing);
        }
        write_private_bytes(self.account_setup_context_path(&account.label), bytes)
    }

    pub fn account_setup_context(&self, account_ref: &str) -> AccountHomeResult<Option<Vec<u8>>> {
        let account = self.account(account_ref)?;
        match fs::read(self.account_setup_context_path(&account.label)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// App-owned onboarding checkpoint. Unlike setup context, this survives
    /// setup completion so a host can distinguish checked from legacy accounts.
    /// Bytes are private and atomically replaced; this layer assigns no meaning
    /// to their schema or to the onboarding policy.
    pub fn set_account_onboarding(&self, account_ref: &str, bytes: &[u8]) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        write_private_bytes(
            self.account_dir(&account.label).join("onboarding.json"),
            bytes,
        )
    }

    pub fn account_onboarding(&self, account_ref: &str) -> AccountHomeResult<Option<Vec<u8>>> {
        let account = self.account(account_ref)?;
        match fs::read(self.account_dir(&account.label).join("onboarding.json")) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Newest timestamp this device authored per replaceable record kind.
    /// Kinds are opaque to this layer; callers record a floor before signing
    /// so a later version is never authored behind one already published,
    /// even after a restart.
    pub fn replaceable_record_floors(
        &self,
        account_ref: &str,
    ) -> AccountHomeResult<BTreeMap<u64, u64>> {
        let account = self.account(account_ref)?;
        match read_json(self.replaceable_record_floors_path(&account.label)) {
            Ok(floors) => Ok(floors),
            Err(AccountHomeError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                Ok(BTreeMap::new())
            }
            Err(err) => Err(err),
        }
    }

    /// Raise one kind's floor to `created_at`; a lower value leaves it unchanged.
    /// The owner-only file is atomically replaced.
    pub fn advance_replaceable_record_floor(
        &self,
        account_ref: &str,
        kind: u64,
        created_at: u64,
    ) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        let mut floors = self.replaceable_record_floors(&account.label)?;
        let floor = floors.entry(kind).or_insert(0);
        if *floor >= created_at {
            return Ok(());
        }
        *floor = created_at;
        write_private_json(self.replaceable_record_floors_path(&account.label), &floors)
    }

    /// Retain the last cancelled checkpoint while removing its active gate.
    /// The caller must first durably sign out and retain any setup journal.
    /// A later cancellation replaces this evidence even if publication is uncertain.
    pub fn archive_account_onboarding(&self, account_ref: &str) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        if !account.signed_out {
            return Err(AccountHomeError::AccountExists(account.label));
        }
        let directory = self.account_dir(&account.label);
        match fs::rename(
            directory.join("onboarding.json"),
            directory.join("onboarding-cancelled.json"),
        ) {
            Ok(()) => {
                #[cfg(unix)]
                fs::File::open(directory)?.sync_all()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Private opaque recovery journal. The app owns its schema and retains the
    /// interrupted checkpoints here before clearing their active gates.
    pub fn set_account_onboarding_recovery(
        &self,
        account_ref: &str,
        bytes: &[u8],
    ) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        write_private_bytes(
            self.account_dir(&account.label)
                .join("onboarding-recovery.json"),
            bytes,
        )
    }

    pub fn account_onboarding_recovery(
        &self,
        account_ref: &str,
    ) -> AccountHomeResult<Option<Vec<u8>>> {
        let account = self.account(account_ref)?;
        match fs::read(
            self.account_dir(&account.label)
                .join("onboarding-recovery.json"),
        ) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Replace old gates with an app-supplied recovery tombstone. Write the
    /// active gate before atomically renaming it over the cancelled gate, so
    /// older readers always encounter a checkpoint they must validate.
    pub fn finish_recovered_account_onboarding(
        &self,
        account_ref: &str,
        tombstone: &[u8],
    ) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        if !account.signed_out || self.account_onboarding_recovery(&account.label)?.is_none() {
            return Err(AccountHomeError::AccountExists(account.label));
        }
        let directory = self.account_dir(&account.label);
        write_private_bytes(directory.join("onboarding.json"), tombstone)?;
        fs::rename(
            directory.join("onboarding.json"),
            directory.join("onboarding-cancelled.json"),
        )?;
        #[cfg(unix)]
        fs::File::open(directory)?.sync_all()?;
        Ok(())
    }

    /// Read the retained cancellation record for an explicit onboarding restart.
    pub fn cancelled_account_onboarding(
        &self,
        account_ref: &str,
    ) -> AccountHomeResult<Option<Vec<u8>>> {
        let account = self.account(account_ref)?;
        match fs::read(
            self.account_dir(&account.label)
                .join("onboarding-cancelled.json"),
        ) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove an explicitly-authorized legacy incomplete setup while retaining
    /// the matching account-id-keyed credential for the immediate retry.
    pub fn reset_incomplete_setup_preserving_credential(
        &self,
        account_ref: &str,
    ) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        let removal = if self
            .secret_store
            .has_secret_for_account_id(&account.account_id_hex)?
        {
            SigningKeyRemoval::Preserve
        } else {
            SigningKeyRemoval::Delete
        };
        self.remove_account_locked(account_ref, Some(&account), removal)
    }

    pub fn add_public_account(&self, public_key: &str) -> AccountHomeResult<AccountSummary> {
        self.add_nonlocal_account(public_key, NonlocalAdmission::Public)
    }

    /// Persist a public identity's setup journal before publishing its account record.
    /// Existing records remain duplicates; an interrupted journal is retained.
    pub fn add_public_account_for_setup(
        &self,
        public_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        self.add_nonlocal_account(public_key, NonlocalAdmission::PublicSetup)
    }

    pub fn add_external_signer_account(
        &self,
        public_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        self.add_nonlocal_account(public_key, NonlocalAdmission::External)
    }

    /// Persist setup before creating or promoting an external-signing account.
    /// A matching journal keeps its original provenance and progress.
    pub fn add_external_signer_for_setup(
        &self,
        public_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        self.add_nonlocal_account(public_key, NonlocalAdmission::ExternalSetup)
    }

    fn add_nonlocal_account(
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
        let (account, write_record) = if self.account_record_path(&account_id_hex).try_exists()? {
            let mut account = self.account(&account_id_hex)?;
            if !external_signing || account.local_signing {
                return Err(AccountHomeError::AccountExists(account_id_hex));
            }
            let promoted = !account.external_signing;
            if promoted {
                self.remove_nip46_session_inner(&account, Nip46Removal::IncludingOrphaned)?;
            }
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
                true,
            )
        };
        if let Some(kind) = setup_kind {
            if let Some(state) = self.raw_account_setup_state(&account.label)? {
                if state.account_id_hex != account.account_id_hex {
                    return Err(AccountHomeError::AccountIdMismatch);
                }
            } else {
                let state = AccountSetupState {
                    account_id_hex: account.account_id_hex.clone(),
                    reused_account_id_credential: false,
                    kind,
                    phase: AccountSetupPhase::LocalStateCreated,
                };
                self.write_account_setup_state(&account.label, &state)?;
            }
        }
        if write_record {
            self.write_account_record(&account)?;
        }
        Ok(account)
    }

    /// Undo the `external_signing` promotion that [`Self::add_external_signer_account`]
    /// applies to a pre-existing public/tracked account, so a failed external-signer
    /// setup restores that account to its prior tracked state instead of leaving it
    /// half-configured. Credential retirement follows the public-role commit;
    /// failures remain pending for retry before another promotion. Local accounts
    /// are unchanged. Callers must establish that this setup promoted the account.
    pub fn revert_external_signer_upgrade(&self, account_ref: &str) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let mut account = self.account(account_ref)?;
        if !account.external_signing || account.local_signing {
            return Ok(());
        }
        let mut manifest = self.manifest_or_legacy(&account)?;
        if self.root.join(HOME_IDENTITY_FILE).try_exists()? {
            self.home_identity(false)?;
        }
        for credential in manifest.credentials.iter().flatten() {
            self.check_credential(&account, credential)?;
        }
        if manifest.legacy && manifest.nip46_admission == Nip46Admission::LegacyAllowed {
            // A raw orphan may have no session file or managed owner. Record the
            // old role before committing so a crash cannot hide its cleanup scope.
            manifest.account.external_signing = true;
            self.write_credential_manifest(&account.label, &manifest)?;
        }
        account.external_signing = false;
        self.write_account_record(&account)?;
        if self
            .remove_nip46_session_inner(&account, Nip46Removal::IncludingOrphaned)
            .is_err()
        {
            tracing::warn!(target: TRACE_TARGET, method = "revert_external_signer_upgrade", "public role restored; NIP-46 credential retirement remains pending");
        }
        Ok(())
    }

    pub fn account_id_for_secret(secret_key: &str) -> AccountHomeResult<String> {
        let keys = nostr::prelude::Keys::parse(secret_key)
            .map_err(|_| AccountHomeError::InvalidSecretKey)?;
        Ok(keys.public_key().to_hex())
    }

    pub fn account_id_for_public_key(public_key: &str) -> AccountHomeResult<String> {
        nostr::prelude::PublicKey::parse(public_key)
            .map(|pubkey| pubkey.to_hex())
            .map_err(|_| AccountHomeError::InvalidPublicKey)
    }

    fn account_record_for_ref(&self, account_ref: &str) -> AccountHomeResult<PathBuf> {
        if validate_account_label(account_ref).is_ok() {
            let path = self.account_record_path(account_ref);
            if path.exists() {
                return Ok(path);
            }
        }

        let account_id = Self::account_id_for_public_key(account_ref)
            .map_err(|_| AccountHomeError::UnknownAccount(account_ref.to_owned()))?;
        let path = self.account_record_path(&account_id);
        if !path.exists() {
            return Err(AccountHomeError::UnknownAccount(account_ref.to_owned()));
        }
        Ok(path)
    }

    fn account_readonly(&self, account_ref: &str) -> AccountHomeResult<AccountSummary> {
        read_immutable_json(self.account_record_for_ref(account_ref)?)
    }

    pub fn account(&self, account_ref: &str) -> AccountHomeResult<AccountSummary> {
        read_private_json(self.account_record_for_ref(account_ref)?)
    }

    pub fn accounts(&self) -> AccountHomeResult<Vec<AccountSummary>> {
        self.read_accounts(false)
    }

    /// Load device-local database key material for an external account through
    /// the configured secret store. The synthetic credential is not an account
    /// signing key and never produces an account record. Host vault and default
    /// keychain stores keep it encrypted; the development file store retains its
    /// explicit file-backed policy. Existing plaintext keys are migrated before
    /// their legacy inode is scrubbed, preserving already-encrypted databases.
    /// Use `Create` only before the account's first database is created.
    pub fn external_database_secret(
        &self,
        account_ref: &str,
        mode: ExternalSecretMode,
    ) -> AccountHomeResult<Zeroizing<[u8; 32]>> {
        let existing = self.immutable_read(|| {
            if let Ok(account) = self.account_readonly(account_ref) {
                if !account.external_signing || account.local_signing {
                    return Err(AccountHomeError::InvalidSecretKey);
                }
                if !self
                    .account_dir(&account.label)
                    .join(EXTERNAL_SQLCIPHER_SECRET_FILE)
                    .try_exists()?
                {
                    match self.read_credential(
                        &account,
                        SecretCredentialKind::ExternalDatabase,
                        true,
                    ) {
                        Ok(Some(keys)) => return Ok(CredentialRead::Ready(keys)),
                        Ok(None) => {}
                        Err(error)
                            if missing_secret(&error) && mode == ExternalSecretMode::Create => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            Ok(CredentialRead::Admission)
        })?;
        let keys = match existing {
            CredentialRead::Ready(keys) => keys,
            CredentialRead::Admission => self.admit_external_database_secret(account_ref, mode)?,
        };
        let secret = keys
            .secret_key()
            .as_secret_bytes()
            .try_into()
            .map_err(|_| AccountHomeError::InvalidSecretKey)?;
        Ok(Zeroizing::new(secret))
    }

    fn admit_external_database_secret(
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
                SecretClaimMode::CreateOrAdopt,
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

    /// Store a verified remote-signing session without storing its key in metadata.
    /// A confirmed missing key permits explicit re-pairing after an interrupted store.
    /// Replacing an existing key requires explicit session removal first.
    pub fn store_nip46_session(
        &self,
        account_ref: &str,
        keys: &nostr::prelude::Keys,
        record: &Nip46SessionRecord,
    ) -> AccountHomeResult<Nip46SessionWrite> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        record.validate(&account)?;
        if record.client_public_key != keys.public_key().to_hex() {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        let directory = self.account_dir(&account.label);
        if directory.join(NIP46_REMOVING_FILE).try_exists()? {
            self.remove_nip46_session_inner(&account, Nip46Removal::IncludingOrphaned)?;
        }
        let previous = self.read_nip46_record(&account, false)?;
        let manifest = self.credential_manifest(&account.label)?;
        let restore_legacy = previous.is_some()
            && manifest.as_ref().is_none_or(|manifest| {
                manifest.legacy && manifest.nip46_admission == Nip46Admission::LegacyAllowed
            });
        let pending = manifest.as_ref().and_then(|manifest| {
            manifest.credentials[credential_index(SecretCredentialKind::Nip46Session)]
                .as_ref()
                .filter(|credential| credential.origin.is_none())
        });
        let stored = if let Some(credential) = pending {
            self.acquire_credential(
                &account,
                SecretCredentialKind::Nip46Session,
                credential.claim_mode,
                None,
            )
            .map(|acquired| Some(acquired.keys))
        } else if restore_legacy {
            self.load_credential(&account, SecretCredentialKind::Nip46Session)
                .map(Some)
        } else {
            self.read_credential(&account, SecretCredentialKind::Nip46Session, false)
        };
        let (existing, absent) = match stored {
            Ok(Some(stored)) => {
                if stored.secret_key() != keys.secret_key() {
                    return Err(AccountHomeError::AccountIdMismatch);
                }
                (true, false)
            }
            Ok(None) => (false, false),
            Err(AccountHomeError::SecretNotFound(_)) => (false, true),
            Err(error) => return Err(error),
        };
        if existing
            && previous.as_ref().is_some_and(|previous| {
                previous.client_public_key != record.client_public_key
                    || previous.remote_signer_public_key != record.remote_signer_public_key
            })
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        let mut manifest = self.manifest_or_legacy(&account)?;
        let index = credential_index(SecretCredentialKind::Nip46Session);
        let discard_absent = absent
            && manifest.credentials[index]
                .as_ref()
                .is_some_and(|credential| credential.origin.is_none());
        if manifest.nip46_admission != Nip46Admission::ManagedOnly || discard_absent {
            manifest.nip46_admission = Nip46Admission::ManagedOnly;
            if discard_absent {
                manifest.credentials[index] = None;
            }
            self.write_credential_manifest(&account.label, &manifest)?;
        }
        if !existing
            && manifest.credentials[index]
                .as_ref()
                .is_some_and(|credential| credential.origin.is_some())
        {
            self.retire_claim(&account, SecretCredentialKind::Nip46Session, &mut manifest)?;
        }
        write_private_json(directory.join(NIP46_SESSION_FILE), record)?;
        let acquired = self.acquire_credential(
            &account,
            SecretCredentialKind::Nip46Session,
            SecretClaimMode::CreateOrAdopt,
            Some(keys),
        )?;
        if existing || acquired.origin == SecretOrigin::Existing {
            return Ok(Nip46SessionWrite::Existing(
                previous.unwrap_or_else(|| record.clone()),
            ));
        }
        Ok(Nip46SessionWrite::Created)
    }

    /// Restore metadata and its separate communication key. Corruption is an error.
    pub fn load_nip46_session(
        &self,
        account_ref: &str,
    ) -> AccountHomeResult<Option<(nostr::prelude::Keys, Nip46SessionRecord)>> {
        let existing = self.immutable_read(|| {
            if let Ok(account) = self.account_readonly(account_ref) {
                let Some((account, record)) = self.nip46_session_record(account, true)? else {
                    return Ok(CredentialRead::Ready(None));
                };
                if let Some(keys) =
                    self.read_credential(&account, SecretCredentialKind::Nip46Session, true)?
                {
                    return Ok(CredentialRead::Ready(Some((keys, record))));
                }
            }
            Ok(CredentialRead::Admission)
        })?;
        let session = match existing {
            CredentialRead::Ready(session) => session,
            CredentialRead::Admission => {
                let _guard = self.mutation_guard()?;
                let Some((account, record)) =
                    self.nip46_session_record(self.account(account_ref)?, false)?
                else {
                    return Ok(None);
                };
                let keys = self.load_credential(&account, SecretCredentialKind::Nip46Session)?;
                Some((keys, record))
            }
        };
        let Some((keys, record)) = session else {
            return Ok(None);
        };
        if keys.public_key().to_hex() != record.client_public_key {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        Ok(Some((keys, record)))
    }

    fn nip46_session_record(
        &self,
        account: AccountSummary,
        readonly: bool,
    ) -> AccountHomeResult<Option<(AccountSummary, Nip46SessionRecord)>> {
        if !account.external_signing || account.local_signing {
            return Ok(None);
        }
        if self
            .account_dir(&account.label)
            .join(NIP46_REMOVING_FILE)
            .try_exists()?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "NIP-46 session removal is incomplete; retry removal",
            )
            .into());
        }
        let Some(record) = self.read_nip46_record(&account, readonly)? else {
            return Ok(None);
        };
        Ok(Some((account, record)))
    }

    /// Remove the session locally, without requiring the remote signer to respond.
    /// A failed secret-store deletion leaves a removal record for an explicit retry.
    /// Retained raw legacy material remains pending independently of local completion.
    pub fn remove_nip46_session(
        &self,
        account_ref: &str,
        removal: Nip46Removal,
    ) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        self.remove_nip46_session_inner(&account, removal)
    }

    fn read_nip46_record(
        &self,
        account: &AccountSummary,
        readonly: bool,
    ) -> AccountHomeResult<Option<Nip46SessionRecord>> {
        let path = self.account_dir(&account.label).join(NIP46_SESSION_FILE);
        let record = if readonly {
            read_immutable_json_bounded(&path, MAX_NIP46_RECORD_BYTES)
        } else {
            read_private_json_bounded(&path, MAX_NIP46_RECORD_BYTES)
        };
        let record: Nip46SessionRecord = match record {
            Ok(record) => record,
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        record.validate(account)?;
        Ok(Some(record))
    }

    fn remove_nip46_session_inner(
        &self,
        account: &AccountSummary,
        removal: Nip46Removal,
    ) -> AccountHomeResult<()> {
        let directory = self.account_dir(&account.label);
        let path = directory.join(NIP46_SESSION_FILE);
        let removing = directory.join(NIP46_REMOVING_FILE);
        let recorded = path.try_exists()? || removing.try_exists()?;
        let index = credential_index(SecretCredentialKind::Nip46Session);
        let mut manifest = self.manifest_or_legacy(account)?;
        if manifest.nip46_admission != Nip46Admission::ManagedOnly {
            manifest.nip46_admission = Nip46Admission::ManagedOnly;
            self.write_credential_manifest(&account.label, &manifest)?;
        }
        if !recorded && (removal == Nip46Removal::Recorded || manifest.credentials[index].is_none())
        {
            return Ok(());
        }
        match crate::io::rename_for_commit(&path, &removing) {
            Ok(()) => crate::io::sync_directory(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !removing.try_exists()? {
                    write_private_json(&removing, &())?;
                }
            }
            Err(error) => return Err(error.into()),
        }
        self.retire_claim(account, SecretCredentialKind::Nip46Session, &mut manifest)?;
        match fs::remove_file(removing) {
            Ok(()) => crate::io::sync_directory(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// List the complete account catalog or report a read error. Unlike `accounts`,
    /// this never hides an account whose record cannot be read or decoded.
    /// Metadata-probe errors also propagate: an inaccessible directory is not an
    /// empty catalog. This holds the shared mutation lock across enumeration to
    /// serialize with guarded mutations through this `AccountHome`.
    /// The legacy `accounts` method retains its unlocked, best-effort behavior.
    pub fn accounts_strict(&self) -> AccountHomeResult<Vec<AccountSummary>> {
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.read_accounts(true)
    }

    fn read_accounts(&self, strict: bool) -> AccountHomeResult<Vec<AccountSummary>> {
        let dir = self.accounts_dir();
        let exists = if strict {
            dir.try_exists()?
        } else {
            dir.exists()
        };
        if !exists {
            return Ok(Vec::new());
        }

        let mut accounts = Vec::new();
        let mut skipped_unreadable_records = 0usize;
        for entry in fs::read_dir(dir)? {
            let path = entry?.path().join(ACCOUNT_RECORD_FILE);
            let exists = if strict {
                path.try_exists()?
            } else {
                path.exists()
            };
            if exists {
                match read_private_json(path) {
                    Ok(account) => accounts.push(account),
                    Err(error) if strict => return Err(error),
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
        let _guard = self.mutation_guard()?;
        let mut account = self.account(account_ref)?;
        if !account.can_sign() {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
        }
        if !signed_out && account.unlinked {
            return Err(AccountHomeError::AccountUnlinked(account.label));
        }
        if account.signed_out == signed_out {
            return Ok(account);
        }
        account.signed_out = signed_out;
        self.write_account_record(&account)?;
        Ok(account)
    }

    /// Record that this device was unlinked from the account: signed out for
    /// good, in one record write. Signing in, or importing the account's key
    /// over this record, is refused from then on; only removing the account
    /// clears it.
    pub fn mark_account_unlinked(&self, account_ref: &str) -> AccountHomeResult<AccountSummary> {
        let _guard = self.mutation_guard()?;
        let mut account = self.account(account_ref)?;
        if account.unlinked && account.signed_out {
            return Ok(account);
        }
        account.unlinked = true;
        account.signed_out = true;
        self.write_account_record(&account)?;
        Ok(account)
    }

    /// Remove an account from the live catalog and clean up its payload and managed secrets.
    /// The payload includes its SQLCipher database, media, local KeyPackage material,
    /// and account record. Cleanup failures retain identifying deletion intent.
    ///
    /// # Commit boundary
    ///
    /// Resolve ownership and vault authorization before journaling cleanup and
    /// atomically renaming the directory into [`WIPE_TOMBSTONE_DIR`]. A failed
    /// rename leaves the account payload and credentials intact. Once renamed,
    /// the account is absent from [`AccountHome::account`] and [`AccountHome::accounts`].
    ///
    /// After that commit, ordinary credential or filesystem failures do not
    /// change success or skip the remaining secret-file scrubs and payload cleanup.
    /// Failed work retains a private record containing the label and account ID
    /// for [`AccountHome::resume_wipe_cleanup`]. Unproven raw legacy entries are
    /// not erased; their identifying intent may remain indefinitely. Replay
    /// releases original receipts, not credentials adopted by a new live account.
    pub fn remove_account(&self, account_ref: &str) -> AccountHomeResult<()> {
        self.remove_account_inner(account_ref, None, SigningKeyRemoval::Delete)
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
            if imported.reused_account_id_credential {
                SigningKeyRemoval::Preserve
            } else {
                SigningKeyRemoval::Delete
            },
        )
    }

    fn remove_account_inner(
        &self,
        account_ref: &str,
        expected: Option<&AccountSummary>,
        removal: SigningKeyRemoval,
    ) -> AccountHomeResult<()> {
        let _guard = self.mutation_guard()?;
        self.remove_account_locked(account_ref, expected, removal)
    }

    fn remove_account_locked(
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
        write_private_json(live_dir.join(WIPE_CLEANUP_FILE), &cleanup)?;
        if let Some(tombstone) = self.move_account_dir_to_tombstone(&account.label, &live_dir)? {
            self.finish_wipe_cleanup(&tombstone, Some(cleanup));
        }
        Ok(())
    }

    /// Retry best-effort cleanup of committed account wipes.
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

    fn finish_wipe_cleanup(&self, tombstone: &Path, mut cleanup: Option<WipeCleanup>) {
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
        let mut progress_saved = true;
        if let Some(cleanup) = &mut cleanup {
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
                    progress_saved =
                        write_private_json(tombstone.join(WIPE_CLEANUP_FILE), cleanup).is_ok();
                }
            }
        }
        let unknown = cleanup.is_none();
        let mut pending = !progress_saved
            || cleanup.as_ref().is_none_or(|cleanup| {
                cleanup.credentials.iter().any(Option::is_some)
                    || cleanup.legacy.iter().any(Option::is_some)
            });
        for name in [ACCOUNT_SECRET_FILE, EXTERNAL_SQLCIPHER_SECRET_FILE] {
            if scrub_and_remove_local_secret_file(&tombstone.join(name)).is_err() {
                pending = true;
            }
        }
        match fs::read_dir(tombstone) {
            Ok(entries) => {
                for entry in entries {
                    let result = (|| -> std::io::Result<()> {
                        let entry = entry?;
                        let name = entry.file_name();
                        if name == WIPE_CLEANUP_FILE
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
        if !live_dir.try_exists()? {
            return Ok(None);
        }
        let tombstone_root = self.root.join(WIPE_TOMBSTONE_DIR);
        fs_private::create_dir_all_private(&tombstone_root)?;
        crate::io::sync_directory(&self.root)?;
        for _ in 0..32 {
            let attempt = TOMBSTONE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tombstone =
                tombstone_root.join(format!("{label}.{}.{attempt}", std::process::id()));
            match crate::io::rename_for_commit(live_dir, &tombstone) {
                Ok(()) => return Ok(Some(tombstone)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate unique account wipe tombstone",
        )
        .into())
    }

    pub fn load_signing_keys(&self, account_ref: &str) -> AccountHomeResult<nostr::prelude::Keys> {
        if let CredentialRead::Ready(keys) = self.immutable_read(|| {
            if let Ok(account) = self.account_readonly(account_ref) {
                if !account.local_signing {
                    return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
                }
                if let Some(keys) =
                    self.read_credential(&account, SecretCredentialKind::Signing, true)?
                {
                    return Ok(CredentialRead::Ready(keys));
                }
            }
            Ok(CredentialRead::Admission)
        })? {
            return Ok(keys);
        }
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        if !account.local_signing {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex));
        }
        self.load_credential(&account, SecretCredentialKind::Signing)
    }

    /// NIP-49 KEY_SECURITY_BYTE for `account_ref`. Defaults to 0x02
    /// (unknown/untracked) when no status has been persisted yet.
    pub fn key_security_byte(&self, account_ref: &str) -> AccountHomeResult<u8> {
        let account = self.account(account_ref)?;
        let path = self
            .account_dir(&account.label)
            .join(ACCOUNT_KEY_SECURITY_FILE);
        match read_private_json::<StoredKeySecurity>(&path) {
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
        let _guard = self.mutation_guard()?;
        let account = self.account(account_ref)?;
        let path = self
            .account_dir(&account.label)
            .join(ACCOUNT_KEY_SECURITY_FILE);
        write_private_json(
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
        use nostr::nips::nip19::ToBech32;
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

    fn write_signing_account(
        &self,
        keys: &nostr::prelude::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        let label = keys.public_key().to_hex();
        self.write_signing_account_for_label(&label, keys)
    }

    fn write_signing_account_for_label(
        &self,
        label: &str,
        keys: &nostr::prelude::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        let _guard = self.mutation_guard()?;
        validate_account_label(label)?;
        if self.account_record_path(label).try_exists()? {
            return Err(AccountHomeError::AccountExists(label.to_owned()));
        }
        let account_id_hex = keys.public_key().to_hex();
        if let Some(manifest) = self.pending_signing_admission(label, &account_id_hex)? {
            let account = manifest.account;
            self.acquire_credential(
                &account,
                SecretCredentialKind::Signing,
                SecretClaimMode::CreateOnly,
                Some(keys),
            )?;
            self.write_account_record(&account)?;
            return Ok(account);
        }
        if self.secret_store.has_secret_for_label(label)? {
            return Err(AccountHomeError::AccountExists(label.to_owned()));
        }
        if self
            .secret_store
            .has_secret_for_account_id(&account_id_hex)?
        {
            return Err(AccountHomeError::AccountIdInUse(account_id_hex));
        }
        let account = AccountSummary {
            label: label.to_owned(),
            account_id_hex,
            local_signing: true,
            external_signing: false,
            signed_out: false,
            unlinked: false,
        };
        self.write_new_signing_account(&account, keys)
    }

    fn pending_signing_admission(
        &self,
        label: &str,
        account_id_hex: &str,
    ) -> AccountHomeResult<Option<CredentialManifest>> {
        let manifest = self.credential_manifest(label)?;
        if manifest.as_ref().is_some_and(|manifest| {
            manifest.account.account_id_hex != account_id_hex
                || manifest.account.label != label
                || !manifest.account.local_signing
                || manifest.account.external_signing
        }) {
            return Err(AccountHomeError::AccountExists(label.to_owned()));
        }
        Ok(manifest)
    }

    fn reuse_or_repair_signing_account(
        &self,
        mut account: AccountSummary,
        keys: &nostr::prelude::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        if account.unlinked {
            return Err(AccountHomeError::AccountUnlinked(account.label));
        }
        match self.load_credential(&account, SecretCredentialKind::Signing) {
            Ok(stored) if stored.public_key() == keys.public_key() => {}
            Ok(_) => return Err(AccountHomeError::AccountIdMismatch),
            Err(error) if missing_secret(&error) => {
                self.renew_credential(&account, SecretCredentialKind::Signing, Some(keys))?;
            }
            Err(error) => return Err(error),
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
        keys: &nostr::prelude::Keys,
    ) -> AccountHomeResult<AccountSummary> {
        self.acquire_credential(
            account,
            SecretCredentialKind::Signing,
            SecretClaimMode::CreateOnly,
            Some(keys),
        )?;
        self.write_account_record(account)?;
        Ok(account.clone())
    }

    fn write_account_record(&self, account: &AccountSummary) -> AccountHomeResult<()> {
        validate_account_label(&account.label)?;
        let path = self.account_record_path(&account.label);
        if path.try_exists()? {
            let existing: AccountSummary = read_private_json(&path)?;
            if existing.account_id_hex != account.account_id_hex {
                return Err(AccountHomeError::AccountIdMismatch);
            }
        } else if self.credential_manifest(&account.label)?.is_none() {
            self.write_credential_manifest(
                &account.label,
                &CredentialManifest {
                    account: account.clone(),
                    legacy: false,
                    nip46_admission: Nip46Admission::ManagedOnly,
                    credentials: Default::default(),
                },
            )?;
        }
        write_private_json(path, account)
    }

    fn accounts_dir(&self) -> PathBuf {
        self.root.join("accounts")
    }

    fn account_record_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_RECORD_FILE)
    }

    fn replaceable_record_floors_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join("replaceable-floors.json")
    }

    fn account_setup_state_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_SETUP_STATE_FILE)
    }

    fn account_setup_context_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(ACCOUNT_SETUP_CONTEXT_FILE)
    }
}
