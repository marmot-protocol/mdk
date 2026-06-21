//! Persistent account home: local Nostr account records and signing credentials.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use std::fs;

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::io::{read_json, validate_account_label, write_json};
use crate::secret_store::{AccountSecretStore, KeychainSecretStore, LocalFileSecretStore};

const ACCOUNT_RECORD_FILE: &str = "account.json";
/// Per-account NIP-49 KEY_SECURITY_BYTE status record. Records only a status
/// byte, never key material, so it is written with public file permissions.
const ACCOUNT_KEY_SECURITY_FILE: &str = "key-security.json";
pub(crate) const ACCOUNT_SECRET_FILE: &str = "secret.json";
pub(crate) const LOCAL_FILE_SECRET_BACKEND: &str = "local-dev-file";
pub const DEFAULT_KEYCHAIN_SERVICE_NAME: &str = "com.marmot.darkmatter";
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
    /// Durable local runtime state for reversible sign-out. A signed-out
    /// account keeps its local signing secret and account directory but must not
    /// be auto-started by runtime reconciliation until an explicit sign-in
    /// clears this flag.
    #[serde(default)]
    pub signed_out: bool,
}

impl AccountSummary {
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

    pub fn import_account(
        &self,
        label: &str,
        secret_key: &str,
    ) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account_for_label(label, &keys)
    }

    pub fn import_nostr_account(&self, secret_key: &str) -> AccountHomeResult<AccountSummary> {
        let keys =
            nostr::Keys::parse(secret_key).map_err(|_| AccountHomeError::InvalidSecretKey)?;
        self.write_signing_account(&keys)
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
            signed_out: false,
        };
        self.write_account_record(&account)?;
        Ok(account)
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
        if !account.local_signing {
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

        // Commit point: atomically move the live account directory into the
        // tombstone namespace. After this returns Ok the account is no longer a
        // live record and the MLS DB can never be observed half-wiped. A
        // missing directory is treated as already-removed (idempotent).
        let live_dir = self.account_dir(&account.label);
        let tombstone = self.move_account_dir_to_tombstone(&account.label, &live_dir)?;

        // Drop the signing secret unless a twin record still depends on a
        // shared (account-id-keyed) credential. For the local-file store the
        // secret lived inside the account directory we just renamed, so this is
        // a no-op (NotFound -> Ok); the bytes are destroyed with the tombstone
        // below. For the keychain store the entry is independent of the
        // directory and is removed here.
        if !self.secret_shared_with_other_record(&account)? {
            self.secret_store.remove_secret(&account)?;
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
    /// The returned String is the only place the bech32 form exists; it is
    /// neither cached nor logged. Caller should drop it promptly.
    pub fn reveal_nsec(&self, account_ref: &str) -> AccountHomeResult<String> {
        use nostr::ToBech32;
        let keys = self.load_signing_keys(account_ref)?;
        let nsec = keys
            .secret_key()
            .to_bech32()
            .expect("nsec bech32 encode is infallible");
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
            signed_out: false,
        };
        self.secret_store.write_secret(&account, keys)?;
        if let Err(err) = self.write_account_record(&account) {
            let _ = self.secret_store.remove_secret(&account);
            return Err(err);
        }
        Ok(account)
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
}
