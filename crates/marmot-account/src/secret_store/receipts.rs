//! Account secret stores and their owned credential receipts.

use std::ffi::OsStr;
use std::fs::File;
#[cfg(any(unix, windows))]
use std::io::Write;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IosOptions;
use crate::error::{AccountHomeError, AccountHomeResult};
use crate::home::{ACCOUNT_SECRET_FILE, LOCAL_FILE_SECRET_BACKEND};
use crate::io::record_directory::DirAccess;
use crate::io::{
    open_durable_private_dir, read_secret_json, read_secret_text_with, record_directory,
    remove_file_then_scrub, write_private_record, write_secret_record,
};
use crate::native_vault::NativeVault;
use crate::owned_vault::{self, Addressing, RecordKind, StoredSecretKeyHex, VaultStorage};
use crate::ownership::{
    AcquiredSecret, SecretClaimMode, SecretCredential, SecretCredentialKind, SecretReleaseMode,
    SecretReleaseOutcome,
};

/// Stable vault lease filename. Never unlink while the vault is in use.
pub const CREDENTIAL_STORE_LOCK_FILE: &str = ".credential-store.lock";
const VAULT_ID_FILE: &str = ".credential-store-id-v1";
const VAULT_NAMESPACE_PREFIX: &str = "local-file-vault-v1:";
const VAULT_ID_LEN: usize = 64;
const OWNED_SECRET_DIR: &str = ".owned-secrets-v1";
const RECORD_NAME_LEN: usize = 129;

fn record_directory_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Receipt => "receipts",
        RecordKind::Retirement => "retirements",
    }
}

#[derive(Serialize, Deserialize)]
struct StoredAccountSecret {
    #[serde(default = "stored_secret_version")]
    version: u32,
    #[serde(default = "stored_secret_backend")]
    backend: String,
    secret_key_hex: StoredSecretKeyHex,
}

pub trait AccountSecretStore: Send + Sync {
    /// Stable nonsecret identity of the actual vault, including its target scope.
    /// A store object must retain that target for its entire lifetime.
    fn cleanup_namespace(&self) -> AccountHomeResult<String>;
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool>;
    fn has_secret_for_account_id(&self, _account_id_hex: &str) -> AccountHomeResult<bool> {
        Ok(false)
    }
    /// Acquire a durable receipt before exposing its account. A retry retains
    /// the original material and origin; retired owner IDs are never reused.
    /// `SecretNotFound` guarantees no usable source and no committed or pending
    /// receipt for this owner. An uncertain lookup or write must return another
    /// error so the caller retains the same owner for recovery.
    fn acquire_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret>;
    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys>;
    /// Release only this receipt. Preserve survives removal of its account record.
    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome>;
    /// Retry retired receipts without deleting ambiguous legacy credentials.
    fn reconcile_cleanup(&self) -> AccountHomeResult<()>;
}

#[derive(Clone, Debug)]
pub struct LocalFileSecretStore {
    root: PathBuf,
    #[cfg(any(target_os = "ios", target_os = "android"))]
    ios_options: IosOptions,
    directory: Arc<OnceLock<FileVaultDirectory>>,
}

#[derive(Debug)]
struct FileVaultDirectory {
    path: PathBuf,
    handle: File,
    namespace: OnceLock<String>,
}

impl FileVaultDirectory {
    fn verify(&self) -> AccountHomeResult<&Path> {
        if !is_vault_directory(&self.handle, &self.path)? {
            return Err(AccountHomeError::SecretStore(
                "cached file vault directory changed; reopen its original target".into(),
            ));
        }
        Ok(&self.path)
    }

    fn open_records(&self, kind: RecordKind, access: DirAccess) -> io::Result<File> {
        let owned = record_directory::open_dir(&self.handle, OsStr::new(OWNED_SECRET_DIR), access)?;
        record_directory::open_dir(&owned, OsStr::new(record_directory_name(kind)), access)
    }

    fn create_records(&self, kind: RecordKind) -> io::Result<File> {
        let owned = record_directory::create_dir(&self.handle, OsStr::new(OWNED_SECRET_DIR))?;
        let records =
            record_directory::create_dir(&owned, OsStr::new(record_directory_name(kind)))?;
        // Re-sync existing edges too: an earlier attempt may have failed before syncing them.
        record_directory::sync(&records)?;
        record_directory::sync(&owned)?;
        record_directory::sync(&self.handle)?;
        Ok(records)
    }

    fn read_marker(&self) -> AccountHomeResult<Option<[u8; VAULT_ID_LEN]>> {
        let mut file = match record_directory::open_record(&self.handle, OsStr::new(VAULT_ID_FILE))
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let invalid = || AccountHomeError::SecretStore("invalid file vault identity marker".into());
        if !file.metadata()?.is_file() {
            return Err(invalid());
        }
        let mut marker = [0; VAULT_ID_LEN];
        if let Err(error) = file.read_exact(&mut marker) {
            return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
                invalid()
            } else {
                error.into()
            });
        }
        if file.read(&mut [0])? != 0 || !marker.iter().copied().all(is_lower_hex) {
            return Err(invalid());
        }
        Ok(Some(marker))
    }

    fn pin_namespace(&self, marker: &[u8; VAULT_ID_LEN]) -> AccountHomeResult<&str> {
        self.verify()?;
        let namespace = self.namespace.get_or_init(|| {
            let mut value = String::with_capacity(VAULT_NAMESPACE_PREFIX.len() + VAULT_ID_LEN);
            value.push_str(VAULT_NAMESPACE_PREFIX);
            value.push_str(std::str::from_utf8(marker).expect("validated lowercase hex marker"));
            value
        });
        if &namespace.as_bytes()[VAULT_NAMESPACE_PREFIX.len()..] != marker {
            return Err(marker_changed());
        }
        Ok(namespace)
    }

    fn existing_namespace(&self) -> AccountHomeResult<Option<&str>> {
        match self.read_marker()? {
            Some(marker) => {
                #[cfg(unix)]
                if self.namespace.get().is_none() {
                    // Initialization can publish a marker before a failed directory sync.
                    self.handle.sync_all()?;
                }
                self.pin_namespace(&marker).map(Some)
            }
            None if self.namespace.get().is_some() => Err(marker_changed()),
            None => Ok(None),
        }
    }

    fn initialize_namespace(&self) -> AccountHomeResult<&str> {
        if let Some(namespace) = self.existing_namespace()? {
            return Ok(namespace);
        }

        // Unpublished drafts wrote managed records without a marker. The old
        // pathname-derived namespace cannot verify which directory held them.
        match record_directory::open_dir(
            &self.handle,
            OsStr::new(OWNED_SECRET_DIR),
            DirAccess::Search,
        ) {
            Ok(_) => {
                return Err(AccountHomeError::SecretStore(
                    "file vault identity marker is missing over managed credential storage".into(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let mut random = [0; VAULT_ID_LEN / 2];
        getrandom::fill(&mut random).map_err(|_| {
            AccountHomeError::SecretStore("could not generate file vault identity".into())
        })?;
        let mut marker = [0; VAULT_ID_LEN];
        hex::encode_to_slice(random, &mut marker).expect("file vault marker length");
        self.verify()?;
        publish_vault_marker(&self.handle, &marker)?;
        if self.read_marker()? != Some(marker) {
            return Err(marker_changed());
        }
        self.pin_namespace(&marker)
    }
}

#[cfg(any(unix, windows))]
fn marker_temp_name(marker: &[u8; VAULT_ID_LEN]) -> String {
    format!(
        "{VAULT_ID_FILE}.tmp.{}",
        std::str::from_utf8(marker).expect("encoded marker")
    )
}

#[cfg(any(unix, windows))]
fn publish_vault_marker(parent: &File, marker: &[u8; VAULT_ID_LEN]) -> io::Result<()> {
    #[cfg(windows)]
    record_directory::require_ntfs(parent, false)?;

    let temporary = marker_temp_name(marker);
    let stage = OsStr::new(&temporary);
    let name = OsStr::new(VAULT_ID_FILE);
    let mut file = record_directory::create_stage(parent, stage)?;
    let published = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(marker)?;
        file.sync_all()?;
        #[cfg(unix)]
        let result = record_directory::link_new(parent, stage, name);
        #[cfg(windows)]
        let result = record_directory::publish_new(parent, &file, name);
        result
    })();
    // POSIX publishes a second link. Windows renames the staging file itself.
    let removed = if cfg!(unix) || published.is_err() {
        record_directory::discard_stage(parent, &file, stage)
    } else {
        Ok(())
    };
    published.and(removed).and(record_directory::sync(parent))
}

#[cfg(not(any(unix, windows)))]
fn publish_vault_marker(_parent: &File, _marker: &[u8; VAULT_ID_LEN]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file vault requires atomic marker publication",
    ))
}

fn marker_changed() -> AccountHomeError {
    AccountHomeError::SecretStore(
        "cached file vault identity marker changed; reopen its original target".into(),
    )
}

#[cfg(unix)]
fn is_vault_directory(handle: &std::fs::File, path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let held = handle.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    Ok(current.is_dir() && (held.dev(), held.ino()) == (current.dev(), current.ino()))
}

#[cfg(not(any(unix, windows)))]
fn is_vault_directory(_handle: &std::fs::File, _path: &Path) -> std::io::Result<bool> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "file vault requires stable directory identity",
    ))
}

#[cfg(windows)]
fn is_vault_directory(handle: &std::fs::File, path: &Path) -> std::io::Result<bool> {
    fn file_id(file: &std::fs::File) -> std::io::Result<(u64, [u8; 16])> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };

        let mut info = FILE_ID_INFO::default();
        // The output buffer and borrowed handle remain valid for the call.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&raw mut info).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok((info.VolumeSerialNumber, info.FileId.Identifier))
    }

    let current = record_directory::open_root(path)?;
    Ok(file_id(handle)? == file_id(&current)?)
}

struct FileVaultGuard {
    #[cfg(unix)]
    _lease: fs_private::PrivateExclusiveFileLease,
    #[cfg(windows)]
    _lease: File,
}

#[cfg(unix)]
fn acquire_vault_lease(dir: &File) -> io::Result<FileVaultGuard> {
    use std::os::fd::AsFd;

    let lease = fs_private::try_acquire_lease_at(dir.as_fd(), CREDENTIAL_STORE_LOCK_FILE.as_ref())?;
    Ok(FileVaultGuard { _lease: lease })
}

#[cfg(windows)]
fn acquire_vault_lease(dir: &File) -> io::Result<FileVaultGuard> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN_IF;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_DATA, FILE_WRITE_DATA, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let file = record_directory::open_child(
        dir,
        OsStr::new(CREDENTIAL_STORE_LOCK_FILE),
        false,
        FILE_READ_DATA | FILE_WRITE_DATA,
        FILE_OPEN_IF,
        0,
        record_directory::WINDOWS_SHARE,
    )?;
    let mut range = OVERLAPPED::default();
    // Lock the same whole-file range as fs-private. The synchronous handle and
    // zero-offset OVERLAPPED remain valid through the nonblocking call.
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut range,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        return Err(error);
    }
    Ok(FileVaultGuard { _lease: file })
}

#[cfg(not(any(unix, windows)))]
fn acquire_vault_lease(_dir: &File) -> io::Result<FileVaultGuard> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file vault requires an exclusive filesystem lease",
    ))
}

impl LocalFileSecretStore {
    pub fn new(root: impl AsRef<Path>, ios_options: IosOptions) -> Self {
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        let _ = ios_options;
        Self {
            root: root.as_ref().to_path_buf(),
            #[cfg(any(target_os = "ios", target_os = "android"))]
            ios_options,
            directory: Arc::new(OnceLock::new()),
        }
    }

    fn storage_directory(&self) -> AccountHomeResult<&FileVaultDirectory> {
        if let Some(directory) = self.directory.get() {
            directory.verify()?;
            return Ok(directory);
        }
        let (root, handle) = match self.root.canonicalize() {
            Ok(root) => {
                #[cfg(any(target_os = "ios", target_os = "android"))]
                crate::location::root_hash(&root, &self.ios_options)?;
                let handle = record_directory::open_root(&root)?;
                (root, handle)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                #[cfg(any(target_os = "ios", target_os = "android"))]
                {
                    let root = canonical_storage_candidate(&self.root)?;
                    crate::location::root_hash(&root, &self.ios_options)?;
                    let handle = open_durable_private_dir(&root, &root)?;
                    (root, handle)
                }
                #[cfg(not(any(target_os = "ios", target_os = "android")))]
                {
                    let handle = open_durable_private_dir(&self.root, &self.root)?;
                    (self.root.canonicalize()?, handle)
                }
            }
            Err(error) => return Err(error.into()),
        };
        // Authorize the location independently of the random marker identity.
        let selected = FileVaultDirectory {
            path: root,
            handle,
            namespace: OnceLock::new(),
        };
        let configured = self.root.canonicalize()?;
        let changed = || {
            AccountHomeError::SecretStore("file vault directory changed during selection".into())
        };
        if selected.path != configured {
            return Err(changed());
        }
        selected.verify()?;
        let directory = self.directory.get_or_init(|| selected);
        if directory.path != configured {
            return Err(changed());
        }
        directory.verify()?;
        Ok(directory)
    }

    fn storage_root(&self) -> AccountHomeResult<&Path> {
        Ok(&self.storage_directory()?.path)
    }

    fn secret_path(&self, label: &str) -> AccountHomeResult<PathBuf> {
        Ok(self
            .storage_root()?
            .join("accounts")
            .join(label)
            .join(ACCOUNT_SECRET_FILE))
    }

    #[cfg(test)]
    fn owned_path(&self, kind: RecordKind, name: &str) -> AccountHomeResult<PathBuf> {
        validate_record_name(name)?;
        Ok(self
            .storage_root()?
            .join(OWNED_SECRET_DIR)
            .join(record_directory_name(kind))
            .join(name))
    }

    fn lock_directory(directory: &FileVaultDirectory) -> AccountHomeResult<FileVaultGuard> {
        #[cfg(unix)]
        crate::io::tighten_private_directory(&directory.handle)?;
        let guard = acquire_vault_lease(&directory.handle)?;
        directory.verify()?;
        Ok(guard)
    }

    fn namespace(&self) -> AccountHomeResult<&str> {
        let directory = self.storage_directory()?;
        if let Some(namespace) = directory.existing_namespace()? {
            return Ok(namespace);
        }
        let _guard = Self::lock_directory(directory)?;
        directory.initialize_namespace()
    }

    fn store_guard(&self) -> AccountHomeResult<(FileVaultGuard, &str)> {
        let directory = self.storage_directory()?;
        let guard = Self::lock_directory(directory)?;
        Ok((guard, directory.initialize_namespace()?))
    }

    fn remove_receipts(&self, names: &[impl AsRef<str>]) -> AccountHomeResult<()> {
        if names.is_empty() {
            return Ok(());
        }
        for name in names {
            validate_record_name(name.as_ref())?;
        }
        let directory = self.storage_directory()?;
        let records = match directory.open_records(RecordKind::Receipt, DirAccess::Read) {
            Ok(records) => records,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        Ok(remove_receipt_records(&records, names)?)
    }

    fn legacy_keys(&self, label: &str) -> AccountHomeResult<Option<nostr::prelude::Keys>> {
        let secret: StoredAccountSecret = match read_secret_json(self.secret_path(label)?) {
            Ok(secret) => secret,
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if secret.backend != LOCAL_FILE_SECRET_BACKEND {
            return Err(AccountHomeError::UnsupportedSecretBackend(secret.backend));
        }
        nostr::prelude::Keys::parse(secret.secret_key_hex.as_str())
            .map(Some)
            .map_err(|_| AccountHomeError::InvalidSecretKey)
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn canonical_storage_candidate(path: &Path) -> io::Result<PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or(error)?;
            let parent = path.parent().filter(|part| !part.as_os_str().is_empty());
            Ok(canonical_storage_candidate(parent.unwrap_or_else(|| Path::new(".")))?.join(name))
        }
        Err(error) => Err(error),
    }
}

fn remove_receipt_records(records: &File, names: &[impl AsRef<str>]) -> io::Result<()> {
    let mut result = Ok(());
    for name in names {
        result = result.and(record_directory::remove_secret(
            records,
            OsStr::new(name.as_ref()),
        ));
    }
    let mut temporaries = Vec::new();
    result = result.and(record_directory::visit_entries(records, |name, _| {
        if let Some(target) = name.to_str().and_then(temporary_target)
            && names
                .binary_search_by(|name| name.as_ref().cmp(target))
                .is_ok()
        {
            temporaries.push(name.to_os_string());
        }
        Ok(())
    }));
    for temporary in temporaries {
        result = result.and(record_directory::remove_secret(records, &temporary));
    }
    result.and(record_directory::sync(records))
}

fn read_owned_record(records: &File, name: &OsStr) -> AccountHomeResult<Option<Zeroizing<String>>> {
    match read_secret_text_with(|| record_directory::open_record(records, name)) {
        Ok(value) => Ok(Some(value)),
        Err(AccountHomeError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_record_name(name: &str) -> AccountHomeResult<()> {
    if name.len() != RECORD_NAME_LEN
        || name.as_bytes()[64] != b'-'
        || !name
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 64 || is_lower_hex(byte))
    {
        return Err(AccountHomeError::SecretStore(
            "invalid owned credential record name".into(),
        ));
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

impl VaultStorage for LocalFileSecretStore {
    fn read(&self, kind: RecordKind, name: &str) -> AccountHomeResult<Option<Zeroizing<String>>> {
        validate_record_name(name)?;
        let directory = self.storage_directory()?;
        let value = match directory.open_records(kind, DirAccess::Search) {
            Ok(records) => read_owned_record(&records, OsStr::new(name)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        };
        directory.verify()?;
        value
    }

    fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()> {
        validate_record_name(name)?;
        let directory = self.storage_directory()?;
        let records = directory.create_records(kind)?;
        let name = OsStr::new(name);
        if matches!(kind, RecordKind::Receipt) {
            if let Some(existing) = read_owned_record(&records, name)? {
                if existing.as_str() == value {
                    return Ok(());
                }
                return Err(AccountHomeError::SecretStore(
                    "owned credential receipts are immutable".into(),
                ));
            }
            return write_secret_record(&records, name, value.as_bytes());
        }
        write_private_record(&records, name, value.as_bytes())
    }

    fn sync(&self, kind: RecordKind) -> AccountHomeResult<()> {
        Ok(record_directory::sync(
            &self
                .storage_directory()?
                .open_records(kind, DirAccess::Read)?,
        )?)
    }

    fn remove(&self, kind: RecordKind, name: &str) -> AccountHomeResult<()> {
        if matches!(kind, RecordKind::Retirement) {
            return Err(AccountHomeError::SecretStore(
                "credential retirement metadata must not be removed".into(),
            ));
        }
        self.remove_receipts(&[name])
    }

    fn remove_retired_receipts(&self, names: &[String]) -> AccountHomeResult<()> {
        self.remove_receipts(names)
    }

    fn names(&self, kind: RecordKind) -> AccountHomeResult<Vec<String>> {
        let directory = self.storage_directory()?;
        let records = match directory.open_records(kind, DirAccess::Read) {
            Ok(records) => records,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut names = Vec::new();
        record_directory::visit_entries(&records, |name, regular| -> AccountHomeResult<()> {
            if !regular {
                return Err(AccountHomeError::SecretStore(
                    "owned credential record must be a regular file".into(),
                ));
            }
            let name = name.to_str().ok_or_else(|| {
                AccountHomeError::SecretStore("invalid owned credential filename".into())
            })?;
            if let Some(target) = temporary_target(name) {
                validate_record_name(target)?;
            } else {
                validate_record_name(name)?;
                names.push(name.to_owned());
            }
            Ok(())
        })?;
        Ok(names)
    }
}

impl AccountSecretStore for LocalFileSecretStore {
    fn cleanup_namespace(&self) -> AccountHomeResult<String> {
        self.namespace().map(str::to_owned)
    }

    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        self.namespace()?;
        if self.legacy_keys(label)?.is_some() {
            return Ok(true);
        }
        owned_vault::has_managed(
            self,
            SecretCredential {
                label,
                account_id_hex: "",
                home_id: "",
                owner_id: "",
                kind: SecretCredentialKind::Signing,
            },
            Addressing::Label,
        )
    }

    fn acquire_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        let (_guard, namespace) = self.store_guard()?;
        owned_vault::acquire(self, credential, Addressing::Label, mode, proposed, || {
            Ok(self
                .legacy_keys(credential.label)?
                .map(|keys| (keys, Some(namespace.to_owned()))))
        })
    }

    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        self.namespace()?;
        owned_vault::load(self, credential, Addressing::Label)
    }

    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome> {
        let (_guard, namespace) = self.store_guard()?;
        owned_vault::release(
            self,
            credential,
            Addressing::Label,
            mode,
            || Ok(Some(namespace)),
            |legacy| self.legacy_keys(&legacy.label).map(|keys| keys.is_some()),
        )
    }

    fn reconcile_cleanup(&self) -> AccountHomeResult<()> {
        let _guard = self.store_guard()?;
        owned_vault::reconcile(self)
    }
}

/// Unlink and best-effort overwrite through the original handle. Copy-on-write
/// filesystems and SSD wear levelling prevent a physical-erasure guarantee.
pub(crate) fn scrub_and_remove_local_secret_file(path: &Path) -> AccountHomeResult<()> {
    Ok(remove_file_then_scrub(path)?)
}

#[derive(Clone, Debug)]
pub struct KeychainSecretStore {
    service_name: String,
    vault: Arc<NativeVault>,
}

impl KeychainSecretStore {
    pub fn new(
        service_name: impl Into<String>,
        ios_options: &IosOptions,
    ) -> AccountHomeResult<Self> {
        let service_name = service_name.into().trim().to_owned();
        if service_name.is_empty() {
            return Err(AccountHomeError::EmptySecretStoreService);
        }
        let vault = Arc::new(NativeVault::new(&service_name, ios_options)?);
        Ok(Self {
            service_name,
            vault,
        })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    fn legacy_keys(&self, account_id: &str) -> AccountHomeResult<Option<nostr::prelude::Keys>> {
        self.vault
            .legacy_secret(account_id)?
            .map(|value| {
                nostr::prelude::Keys::parse(value.as_str())
                    .map_err(|_| AccountHomeError::InvalidSecretKey)
            })
            .transpose()
    }
}

impl AccountSecretStore for KeychainSecretStore {
    fn cleanup_namespace(&self) -> AccountHomeResult<String> {
        Ok(self.vault.namespace().to_owned())
    }

    fn has_secret_for_label(&self, _label: &str) -> AccountHomeResult<bool> {
        Ok(false)
    }

    fn has_secret_for_account_id(&self, account_id_hex: &str) -> AccountHomeResult<bool> {
        if self.legacy_keys(account_id_hex)?.is_some() {
            return Ok(true);
        }
        self.vault.with_mutation(|storage| {
            owned_vault::has_managed(
                storage,
                SecretCredential {
                    label: "",
                    account_id_hex,
                    home_id: "",
                    owner_id: "",
                    kind: SecretCredentialKind::Signing,
                },
                Addressing::AccountId,
            )
        })
    }

    fn acquire_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        self.vault.with_mutation(|storage| {
            owned_vault::acquire(
                storage,
                credential,
                Addressing::AccountId,
                mode,
                proposed,
                || {
                    Ok(self
                        .legacy_keys(credential.account_id_hex)?
                        .map(|keys| (keys, self.vault.legacy_scope().map(str::to_owned))))
                },
            )
        })
    }

    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        self.vault
            .with_mutation(|storage| owned_vault::load(storage, credential, Addressing::AccountId))
    }

    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome> {
        self.vault.with_mutation(|storage| {
            owned_vault::release(
                storage,
                credential,
                Addressing::AccountId,
                mode,
                || Ok(self.vault.legacy_scope()),
                |legacy| {
                    self.legacy_keys(&legacy.account_id_hex)
                        .map(|keys| keys.is_some())
                },
            )
        })
    }

    fn reconcile_cleanup(&self) -> AccountHomeResult<()> {
        self.vault
            .with_mutation(|storage| owned_vault::reconcile(storage))
    }
}

fn temporary_target(name: &str) -> Option<&str> {
    let (target, suffix) = name.strip_prefix('.')?.split_once(".tmp.")?;
    let (pid, counter) = suffix.split_once('.')?;
    if pid.is_empty()
        || counter.is_empty()
        || !pid
            .bytes()
            .chain(counter.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(target)
}

fn stored_secret_version() -> u32 {
    1
}

fn stored_secret_backend() -> String {
    LOCAL_FILE_SECRET_BACKEND.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::overwrite_file_with_zeros;
    use std::fs;

    fn receipt_name(credential: SecretCredential<'_>) -> String {
        format!(
            "{}-{}",
            owned_vault::slot_name(credential, Addressing::Label),
            credential.owner_id
        )
    }

    #[test]
    #[cfg(unix)]
    fn namespace_distinguishes_vaults_and_pins_aliases() {
        use std::ffi::OsString;
        use std::os::unix::{ffi::OsStringExt, fs::symlink};

        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join(OsString::from_vec(b"vault-\xff".to_vec()));
        let second = dir.path().join(OsString::from_vec(b"vault-\xfe".to_vec()));
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        assert_eq!(first.to_string_lossy(), second.to_string_lossy());
        let alias = dir.path().join("vault-alias");
        symlink(&first, &alias).unwrap();
        let store = LocalFileSecretStore::new(&first, IosOptions::default());
        let guard = fs_private::try_acquire_private_exclusive_file_lease(
            &first.join(CREDENTIAL_STORE_LOCK_FILE),
        )
        .unwrap();
        assert!(
            matches!(store.cleanup_namespace(), Err(AccountHomeError::Io(error))
            if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(!first.join(VAULT_ID_FILE).exists());
        drop(guard);
        let namespace = store.cleanup_namespace().unwrap();
        let pinned = LocalFileSecretStore::new(&alias, IosOptions::default());
        assert_eq!(pinned.cleanup_namespace().unwrap(), namespace);
        assert_eq!(
            LocalFileSecretStore::new(&first, IosOptions::default())
                .cleanup_namespace()
                .unwrap(),
            namespace
        );
        assert_ne!(
            LocalFileSecretStore::new(&second, IosOptions::default())
                .cleanup_namespace()
                .unwrap(),
            namespace
        );
        fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        assert_eq!(pinned.cleanup_namespace().unwrap(), namespace);
        assert_ne!(
            LocalFileSecretStore::new(&alias, IosOptions::default())
                .cleanup_namespace()
                .unwrap(),
            namespace
        );
    }

    #[test]
    #[cfg(unix)]
    fn file_vault_writer_tightens_the_held_root_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        let namespace = store.cleanup_namespace().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let mode = || fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;

        let reopened = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        assert_eq!(reopened.cleanup_namespace().unwrap(), namespace);
        assert_eq!(mode(), 0o755);

        reopened.reconcile_cleanup().unwrap();
        assert_eq!(mode(), 0o700);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_vault_rejects_retarget() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("new-parent/vault");
        let moved = directory.path().join("original-vault");
        let store = LocalFileSecretStore::new(&root, IosOptions::default());
        let keys = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
        let account_id = keys.public_key().to_hex();
        let home = "11".repeat(32);
        let owner = "22".repeat(32);
        let credential = SecretCredential {
            label: "pinned",
            account_id_hex: &account_id,
            home_id: &home,
            owner_id: &owner,
            kind: SecretCredentialKind::Signing,
        };
        store
            .acquire_secret(credential, SecretClaimMode::CreateOnly, Some(&keys))
            .unwrap();
        let namespace = store.cleanup_namespace().unwrap();
        let held_directory = store.storage_directory().unwrap();
        let name = receipt_name(credential);
        let original = store.read(RecordKind::Receipt, &name).unwrap().unwrap();
        let clone = store.clone();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();

        assert!(
            matches!(store.cleanup_namespace(), Err(AccountHomeError::SecretStore(error))
            if error == "cached file vault directory changed; reopen its original target")
        );
        assert!(
            matches!(clone.load_secret(credential), Err(AccountHomeError::SecretStore(error))
            if error == "cached file vault directory changed; reopen its original target")
        );
        assert!(
            matches!(clone.release_secret(credential, SecretReleaseMode::DeleteIfUnowned),
            Err(AccountHomeError::SecretStore(error)) if error == "cached file vault directory changed; reopen its original target")
        );
        assert!(fs::read_dir(&root).unwrap().next().is_none());

        let replacement = LocalFileSecretStore::new(&root, IosOptions::default());
        let other_keys = nostr::prelude::Keys::parse(&"02".repeat(32)).unwrap();
        let other_account_id = other_keys.public_key().to_hex();
        replacement
            .acquire_secret(
                SecretCredential {
                    account_id_hex: &other_account_id,
                    ..credential
                },
                SecretClaimMode::CreateOnly,
                Some(&other_keys),
            )
            .unwrap();
        assert_ne!(replacement.cleanup_namespace().unwrap(), namespace);
        let other = replacement
            .read(RecordKind::Receipt, &name)
            .unwrap()
            .unwrap();
        assert_ne!(other.as_str(), original.as_str());

        // Move the pathname after obtaining the directory, but before opening the record.
        let records = held_directory
            .open_records(RecordKind::Receipt, DirAccess::Search)
            .unwrap();
        let pinned = read_owned_record(&records, OsStr::new(&name))
            .unwrap()
            .unwrap();
        assert_eq!(pinned.as_str(), original.as_str());
        drop(records);

        let reopened = LocalFileSecretStore::new(&moved, IosOptions::default());
        assert_eq!(reopened.cleanup_namespace().unwrap(), namespace);
        assert_eq!(
            reopened.load_secret(credential).unwrap().secret_key(),
            keys.secret_key()
        );
        drop((reopened, replacement));
        fs::remove_dir_all(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        assert_eq!(
            store.load_secret(credential).unwrap().secret_key(),
            keys.secret_key()
        );
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn marker_publication_never_retargets_or_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let moved = dir.path().join("moved");
        let pending = LocalFileSecretStore::new(&root, IosOptions::default());
        let held = pending.storage_directory().unwrap();
        fs::rename(&root, &moved).unwrap();
        let replacement = LocalFileSecretStore::new(&root, IosOptions::default());
        let (replacement_lease, namespace) = replacement.store_guard().unwrap();
        let marker_path = root.join(VAULT_ID_FILE);
        let replacement_id = fs::read(&marker_path).unwrap();

        // The original and replacement lock files remain distinct after the move.
        let _original_lease = acquire_vault_lease(&held.handle).unwrap();
        let original_id = [b'a'; VAULT_ID_LEN];
        publish_vault_marker(&held.handle, &original_id).unwrap();
        assert_eq!(fs::read(moved.join(VAULT_ID_FILE)).unwrap(), original_id);
        assert_eq!(fs::read(&marker_path).unwrap(), replacement_id);
        let error = publish_vault_marker(&held.handle, &[b'b'; VAULT_ID_LEN]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(held.read_marker().unwrap(), Some(original_id));
        assert_eq!(replacement.cleanup_namespace().unwrap(), namespace);
        drop(replacement_lease);
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn owned_record_io_stays_in_the_selected_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        let (_guard, _) = store.store_guard().unwrap();
        let name = format!("{}-{}", "a".repeat(64), "b".repeat(64));
        let path = store.owned_path(RecordKind::Receipt, &name).unwrap();
        let records_path = path.parent().unwrap();
        let held = store
            .storage_directory()
            .unwrap()
            .create_records(RecordKind::Receipt)
            .unwrap();
        let moved = dir.path().join("original-receipts");
        fs::rename(records_path, &moved).unwrap();
        fs::create_dir(records_path).unwrap();
        let stage = format!(".{name}.tmp.0.0");
        fs::write(&path, b"replacement record").unwrap();
        fs::write(records_path.join(&stage), b"replacement stage").unwrap();

        write_secret_record(&held, OsStr::new(&name), b"original record").unwrap();
        fs::write(moved.join(&stage), b"unpublished original record").unwrap();
        assert_eq!(fs::read(moved.join(&name)).unwrap(), b"original record");

        remove_receipt_records(&held, &[name]).unwrap();

        assert!(fs::read_dir(&moved).unwrap().next().is_none());
        assert_eq!(fs::read(&path).unwrap(), b"replacement record");
        assert_eq!(
            fs::read(records_path.join(stage)).unwrap(),
            b"replacement stage"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reconcile_refuses_symlinked_retired_receipts_and_stages() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let store = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        let keys = nostr::prelude::Keys::generate();
        let account_id = keys.public_key().to_hex();
        let credential = SecretCredential {
            label: "retired",
            account_id_hex: &account_id,
            home_id: &"11".repeat(32),
            owner_id: &"22".repeat(32),
            kind: SecretCredentialKind::Signing,
        };
        store
            .acquire_secret(credential, SecretClaimMode::CreateOnly, Some(&keys))
            .unwrap();
        store
            .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
            .unwrap();
        let name = receipt_name(credential);
        let receipt = store.owned_path(RecordKind::Receipt, &name).unwrap();
        let records = receipt.parent().unwrap();
        let stage = format!(".{name}.tmp.0.0");
        let external = dir.path().join("outside-receipts");
        fs::rename(records, &external).unwrap();
        let outside_receipt = external.join(&name);
        let outside_stage = external.join(&stage);
        fs::write(&outside_receipt, b"outside receipt").unwrap();
        fs::write(&outside_stage, b"outside stage").unwrap();
        let expects_refusal = || {
            assert!(
                matches!(store.reconcile_cleanup(), Err(AccountHomeError::Io(error))
                if error.raw_os_error() == Some(libc::ELOOP))
            );
        };

        symlink(&external, records).unwrap();
        expects_refusal();
        fs::remove_file(records).unwrap();

        fs::create_dir(records).unwrap();
        let staged_receipt = records.join(stage);
        for (link, target) in [
            (&receipt, &outside_receipt),
            (&staged_receipt, &outside_stage),
        ] {
            symlink(target, link).unwrap();
            expects_refusal();
            assert_eq!(fs::read_link(link).unwrap(), *target);
            fs::remove_file(link).unwrap();
        }
        assert_eq!(fs::read(&outside_receipt).unwrap(), b"outside receipt");
        assert_eq!(fs::read(&outside_stage).unwrap(), b"outside stage");
    }

    #[test]
    fn vault_refuses_unverifiable_identity_over_managed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        let keys = nostr::prelude::Keys::generate();
        let account_id = keys.public_key().to_hex();
        let credential = SecretCredential {
            label: "needs-identity",
            account_id_hex: &account_id,
            home_id: &"11".repeat(32),
            owner_id: &"22".repeat(32),
            kind: SecretCredentialKind::Signing,
        };
        store
            .acquire_secret(credential, SecretClaimMode::CreateOnly, Some(&keys))
            .unwrap();
        let path = store
            .owned_path(RecordKind::Receipt, &receipt_name(credential))
            .unwrap();
        let receipt = Zeroizing::new(fs::read(&path).unwrap());
        let marker = dir.path().join(VAULT_ID_FILE);
        let saved_identity = fs::read(&marker).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_file(&marker).unwrap();

        assert!(
            matches!(store.cleanup_namespace(), Err(AccountHomeError::SecretStore(error))
            if error == "cached file vault identity marker changed; reopen its original target")
        );
        let reopened = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        for result in [
            reopened.cleanup_namespace().map(|_| ()),
            reopened.load_secret(credential).map(|_| ()),
            reopened
                .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
                .map(|_| ()),
            reopened.reconcile_cleanup(),
        ] {
            assert!(matches!(result, Err(AccountHomeError::SecretStore(error))
                if error == "file vault identity marker is missing over managed credential storage"));
        }
        assert!(!marker.exists());

        let malformed = [b'g'; VAULT_ID_LEN];
        fs_private::write_private(&marker, &malformed).unwrap();
        assert!(
            matches!(reopened.cleanup_namespace(), Err(AccountHomeError::SecretStore(error))
            if error == "invalid file vault identity marker")
        );
        assert_eq!(fs::read(&marker).unwrap(), malformed);
        assert_eq!(fs::read(&path).unwrap().as_slice(), receipt.as_slice());

        fs_private::write_private(&marker, &saved_identity).unwrap();
        assert_eq!(
            reopened.load_secret(credential).unwrap().secret_key(),
            keys.secret_key()
        );
    }

    #[test]
    fn overwrite_file_with_zeros_replaces_all_bytes_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        let secret = "deadbeef".repeat(8);
        fs::write(&path, secret.as_bytes()).unwrap();
        let original_len = fs::metadata(&path).unwrap().len();
        assert!(original_len > 0);

        overwrite_file_with_zeros(&path).unwrap();

        // The file still exists with the same length, but every byte that held
        // the plaintext key has been overwritten with zero before any unlink.
        let scrubbed = fs::read(&path).unwrap();
        assert_eq!(scrubbed.len() as u64, original_len);
        assert!(scrubbed.iter().all(|byte| *byte == 0));
        assert!(!scrubbed.windows(4).any(|w| w == b"dead"));
    }

    #[test]
    fn scrub_and_remove_local_secret_file_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        fs::write(&path, b"00112233445566778899aabbccddeeff").unwrap();
        assert!(path.exists());

        scrub_and_remove_local_secret_file(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn scrub_and_remove_local_secret_file_is_ok_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(!path.exists());

        scrub_and_remove_local_secret_file(&path).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn scrub_and_remove_does_not_follow_a_secret_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let secret_path = dir.path().join("secret.json");
        fs::write(&target, b"must remain intact").unwrap();
        symlink(&target, &secret_path).unwrap();

        scrub_and_remove_local_secret_file(&secret_path).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"must remain intact");
        assert!(!secret_path.exists());
    }

    #[test]
    fn owned_file_release_scrubs() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        let keys = nostr::prelude::Keys::generate();
        let account_id = keys.public_key().to_hex();
        let home_id = "01".repeat(32);
        let owner_id = "02".repeat(32);
        let credential = SecretCredential {
            label: "scrub-me",
            account_id_hex: &account_id,
            home_id: &home_id,
            owner_id: &owner_id,
            kind: SecretCredentialKind::Signing,
        };
        store
            .acquire_secret(credential, SecretClaimMode::CreateOnly, Some(&keys))
            .unwrap();
        let name = receipt_name(credential);
        let path = store.owned_path(RecordKind::Receipt, &name).unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains(&keys.secret_key().to_secret_hex())
        );
        let temporary = path.parent().unwrap().join(format!(".{name}.tmp.0.0"));
        fs_private::write_private(&temporary, &fs::read(&path).unwrap()).unwrap();
        let writer = store.store_guard().unwrap();
        let independent = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        assert_eq!(
            independent.load_secret(credential).unwrap().secret_key(),
            keys.secret_key()
        );
        assert!(independent.has_secret_for_label(credential.label).unwrap());
        for mutation in [
            independent
                .acquire_secret(credential, SecretClaimMode::CreateOrAdopt, None)
                .map(|_| ()),
            independent
                .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
                .map(|_| ()),
            independent.reconcile_cleanup(),
        ] {
            assert!(matches!(mutation, Err(AccountHomeError::Io(error))
                if error.kind() == std::io::ErrorKind::WouldBlock));
        }
        drop(writer);
        #[cfg(unix)]
        let held = hold_secret(&path);
        #[cfg(unix)]
        let held_temporary = hold_secret(&temporary);
        assert_eq!(
            store
                .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
                .unwrap(),
            SecretReleaseOutcome::Released
        );
        assert!(!path.exists());
        assert!(!temporary.exists());
        #[cfg(unix)]
        {
            assert_scrubbed(held);
            assert_scrubbed(held_temporary);
        }
        assert_eq!(
            store
                .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
                .unwrap(),
            SecretReleaseOutcome::Released
        );
    }

    #[cfg(unix)]
    fn hold_secret(path: &Path) -> (File, u64) {
        let file = File::open(path).unwrap();
        let len = file.metadata().unwrap().len();
        assert!(len > 0);
        (file, len)
    }

    #[cfg(unix)]
    fn assert_scrubbed((mut file, len): (File, u64)) {
        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.len() as u64, len);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    #[cfg(unix)]
    fn reconcile_scrubs_only_terminal_owners_and_retries_failed_removal() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        let keys = nostr::prelude::Keys::generate();
        let account_id = keys.public_key().to_hex();
        let home_id = "11".repeat(32);
        let owners = ["22", "33", "44", "55"].map(|id| id.repeat(32));
        let credentials = owners.each_ref().map(|owner_id| SecretCredential {
            label: "sweep",
            account_id_hex: &account_id,
            home_id: &home_id,
            owner_id,
            kind: SecretCredentialKind::Signing,
        });
        let copies = std::array::from_fn::<_, 4, _>(|index| {
            let credential = credentials[index];
            let (mode, proposed) = if index == 0 {
                (SecretClaimMode::CreateOnly, Some(&keys))
            } else {
                (SecretClaimMode::AdoptOnly, None)
            };
            store.acquire_secret(credential, mode, proposed).unwrap();
            let name = receipt_name(credential);
            let path = store.owned_path(RecordKind::Receipt, &name).unwrap();
            let temp = path.with_file_name(format!(".{name}.tmp.1.1"));
            let contents = Zeroizing::new(fs::read(&path).unwrap());
            (path, temp, contents)
        });
        for credential in &credentials[..2] {
            assert_eq!(
                store
                    .release_secret(*credential, SecretReleaseMode::DeleteIfUnowned)
                    .unwrap(),
                SecretReleaseOutcome::Released
            );
        }
        assert_eq!(
            store
                .release_secret(credentials[2], SecretReleaseMode::Preserve)
                .unwrap(),
            SecretReleaseOutcome::Released
        );

        // Restore the receipt bytes a crash after terminal publication could leave behind.
        for (path, temp, contents) in &copies[..2] {
            fs_private::write_private(path, contents).unwrap();
            fs_private::write_private(temp, contents).unwrap();
        }
        for (_, temp, contents) in &copies[2..] {
            fs_private::write_private(temp, contents).unwrap();
        }
        let blocked = copies[0].1.with_extension("2");
        fs::create_dir(&blocked).unwrap();
        let held = [
            hold_secret(&copies[0].0),
            hold_secret(&copies[0].1),
            hold_secret(&copies[1].0),
            hold_secret(&copies[1].1),
        ];
        drop(store);
        let reopened = LocalFileSecretStore::new(dir.path(), IosOptions::default());
        assert!(
            matches!(reopened.reconcile_cleanup(), Err(AccountHomeError::Io(error))
            if error.kind() == io::ErrorKind::IsADirectory || error.raw_os_error() == Some(libc::EPERM))
        );
        for (path, temp, _) in &copies[..2] {
            assert!(!path.exists());
            assert!(!temp.exists());
        }
        for (path, temp, contents) in &copies[2..] {
            assert_eq!(fs::read(path).unwrap().as_slice(), contents.as_slice());
            assert_eq!(fs::read(temp).unwrap().as_slice(), contents.as_slice());
        }
        held.into_iter().for_each(assert_scrubbed);

        fs::remove_dir(&blocked).unwrap();
        fs_private::write_private(&blocked, &copies[0].2).unwrap();
        let held_retry = hold_secret(&blocked);
        reopened.reconcile_cleanup().unwrap();
        assert!(!blocked.exists());
        assert_scrubbed(held_retry);
    }
}
