//! Account secret stores and their owned credential receipts.

#[cfg(not(any(target_os = "ios", target_os = "android")))]
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IosOptions;
use crate::error::{AccountHomeError, AccountHomeResult};
use crate::home::{ACCOUNT_SECRET_FILE, LOCAL_FILE_SECRET_BACKEND};
use crate::io::{
    read_secret_json, read_secret_text, remove_file_then_scrub, sync_directory,
    write_private_bytes, write_secret_bytes,
};
use crate::native_vault::NativeVault;
use crate::owned_vault::{self, Addressing, RecordKind, StoredSecretKeyHex, VaultStorage};
use crate::ownership::{
    AcquiredSecret, SecretClaimMode, SecretCredential, SecretCredentialKind, SecretReleaseMode,
    SecretReleaseOutcome,
};

/// Stable vault lease filename. Never unlink while the vault is in use.
pub const CREDENTIAL_STORE_LOCK_FILE: &str = ".credential-store.lock";

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
    directory: Arc<OnceLock<FileVaultDirectory>>,
    #[cfg(any(target_os = "ios", target_os = "android"))]
    ios_options: IosOptions,
}

#[derive(Debug)]
struct FileVaultDirectory {
    path: PathBuf,
    handle: std::fs::File,
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

#[cfg(not(windows))]
fn open_vault_directory(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(windows)]
fn open_vault_directory(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
    };

    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
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

    let current = open_vault_directory(path)?;
    Ok(file_id(handle)? == file_id(&current)?)
}

struct FileVaultGuard {
    #[cfg(any(unix, windows))]
    _lease: fs_private::PrivateExclusiveFileLease,
}

impl LocalFileSecretStore {
    pub fn new(root: impl AsRef<Path>, _ios_options: IosOptions) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            directory: Arc::new(OnceLock::new()),
            #[cfg(any(target_os = "ios", target_os = "android"))]
            ios_options: _ios_options,
        }
    }

    fn storage_root(&self) -> AccountHomeResult<&Path> {
        if let Some(directory) = self.directory.get() {
            return directory.verify();
        }
        let root = match self.root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::io::create_durable_private_dir(&self.root)?;
                self.root.canonicalize()?
            }
            Err(error) => return Err(error.into()),
        };
        let handle = open_vault_directory(&root)?;
        if !handle.metadata()?.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "file vault root must be a directory",
            )
            .into());
        }
        let _ = self
            .directory
            .set(FileVaultDirectory { path: root, handle });
        self.directory
            .get()
            .expect("file vault target initialized")
            .verify()
    }

    fn secret_path(&self, label: &str) -> AccountHomeResult<PathBuf> {
        Ok(self
            .storage_root()?
            .join("accounts")
            .join(label)
            .join(ACCOUNT_SECRET_FILE))
    }

    fn owned_dir(&self, kind: RecordKind) -> AccountHomeResult<PathBuf> {
        Ok(self
            .storage_root()?
            .join(".owned-secrets-v1")
            .join(match kind {
                RecordKind::Receipt => "receipts",
                RecordKind::Retirement => "retirements",
            }))
    }

    fn owned_path(&self, kind: RecordKind, name: &str) -> AccountHomeResult<PathBuf> {
        if name.len() != 129
            || name.as_bytes()[64] != b'-'
            || !name.bytes().enumerate().all(|(index, byte)| {
                index == 64 || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            })
        {
            return Err(AccountHomeError::SecretStore(
                "invalid owned credential record name".into(),
            ));
        }
        Ok(self.owned_dir(kind)?.join(name))
    }

    fn store_guard(&self) -> AccountHomeResult<FileVaultGuard> {
        let root = self.storage_root()?;
        #[cfg(any(unix, windows))]
        {
            let guard = FileVaultGuard {
                _lease: fs_private::try_acquire_private_exclusive_file_lease(
                    &root.join(CREDENTIAL_STORE_LOCK_FILE),
                )?,
            };
            self.storage_root()?;
            Ok(guard)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = root;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "file vault requires an exclusive filesystem lease",
            )
            .into())
        }
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

impl VaultStorage for LocalFileSecretStore {
    fn read(&self, kind: RecordKind, name: &str) -> AccountHomeResult<Option<Zeroizing<String>>> {
        match read_secret_text(&self.owned_path(kind, name)?) {
            Ok(value) => Ok(Some(value)),
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()> {
        let path = self.owned_path(kind, name)?;
        crate::io::create_durable_private_dir(path.parent().expect("owned credential parent"))?;
        if matches!(kind, RecordKind::Receipt) {
            if let Some(existing) = self.read(kind, name)? {
                if existing.as_str() == value {
                    return self.sync(kind);
                }
                return Err(AccountHomeError::SecretStore(
                    "owned credential receipts are immutable".into(),
                ));
            }
            return write_secret_bytes(&path, value.as_bytes());
        }
        write_private_bytes(&path, value.as_bytes())
    }

    fn sync(&self, kind: RecordKind) -> AccountHomeResult<()> {
        Ok(sync_directory(&self.owned_dir(kind)?)?)
    }

    fn remove(&self, kind: RecordKind, name: &str) -> AccountHomeResult<()> {
        let path = self.owned_path(kind, name)?;
        if matches!(kind, RecordKind::Retirement) {
            return Err(AccountHomeError::SecretStore(
                "credential retirement metadata must not be removed".into(),
            ));
        }
        let mut failure = scrub_and_remove_local_secret_file(&path).err();
        let entries = match std::fs::read_dir(self.owned_dir(kind)?) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return failure.map_or(Ok(()), Err);
            }
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let result = (|| -> AccountHomeResult<()> {
                let entry = entry?;
                let file_name = entry.file_name();
                if file_name.to_str().and_then(temporary_target) == Some(name) {
                    scrub_and_remove_local_secret_file(&entry.path())?;
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

    fn names(&self, kind: RecordKind) -> AccountHomeResult<Vec<String>> {
        let entries = match std::fs::read_dir(self.owned_dir(kind)?) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(AccountHomeError::SecretStore(
                    "owned credential record must be a regular file".into(),
                ));
            }
            let name = entry.file_name().into_string().map_err(|_| {
                AccountHomeError::SecretStore("invalid owned credential filename".into())
            })?;
            if let Some(target) = temporary_target(&name) {
                self.owned_path(kind, target)?;
                continue;
            }
            self.owned_path(kind, &name)?;
            names.push(name);
        }
        Ok(names)
    }
}

impl AccountSecretStore for LocalFileSecretStore {
    fn cleanup_namespace(&self) -> AccountHomeResult<String> {
        let root = self.storage_root()?;
        let mut namespace = String::from("local-file-owned-v1:");
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            namespace.push_str(&hex::encode(crate::location::root_hash(
                root,
                &self.ios_options,
            )?));
        }
        #[cfg(all(unix, not(any(target_os = "ios", target_os = "android"))))]
        {
            use std::os::unix::ffi::OsStrExt;
            for byte in root.as_os_str().as_bytes() {
                write!(&mut namespace, "{byte:02x}").expect("writing to a String");
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            for unit in root.as_os_str().encode_wide() {
                write!(&mut namespace, "{unit:04x}").expect("writing to a String");
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "file vault needs stable native path encoding",
            )
            .into());
        }
        Ok(namespace)
    }

    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
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
        let _guard = self.store_guard()?;
        owned_vault::acquire(self, credential, Addressing::Label, mode, proposed, || {
            self.legacy_keys(credential.label)?
                .map(|keys| Ok((keys, Some(self.cleanup_namespace()?))))
                .transpose()
        })
    }

    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        owned_vault::load(self, credential, Addressing::Label)
    }

    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome> {
        let _guard = self.store_guard()?;
        owned_vault::release(
            self,
            credential,
            Addressing::Label,
            mode,
            || self.cleanup_namespace().map(Some),
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
        owned_vault::has_managed(
            self.vault.as_ref(),
            SecretCredential {
                label: "",
                account_id_hex,
                home_id: "",
                owner_id: "",
                kind: SecretCredentialKind::Signing,
            },
            Addressing::AccountId,
        )
    }

    fn acquire_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        owned_vault::acquire(
            self.vault.as_ref(),
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
    }

    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        owned_vault::load(self.vault.as_ref(), credential, Addressing::AccountId)
    }

    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome> {
        owned_vault::release(
            self.vault.as_ref(),
            credential,
            Addressing::AccountId,
            mode,
            || Ok(self.vault.legacy_scope()),
            |legacy| {
                self.legacy_keys(&legacy.account_id_hex)
                    .map(|keys| keys.is_some())
            },
        )
    }

    fn reconcile_cleanup(&self) -> AccountHomeResult<()> {
        owned_vault::reconcile(self.vault.as_ref())
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

    #[test]
    #[cfg(unix)]
    fn namespace_keeps_raw_paths() {
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
        let namespace = LocalFileSecretStore::new(&first, IosOptions::default())
            .cleanup_namespace()
            .unwrap();
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

    #[cfg(any(unix, windows))]
    #[test]
    fn file_vault_rejects_retarget() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
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

        fs::remove_dir(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        assert_eq!(
            store.load_secret(credential).unwrap().secret_key(),
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
        let name = format!(
            "{}-{owner_id}",
            owned_vault::slot_name(credential, Addressing::Label)
        );
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
        let mut held = fs::File::open(&path).unwrap();
        #[cfg(unix)]
        let mut held_temporary = fs::File::open(&temporary).unwrap();
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
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut held, &mut bytes).unwrap();
            assert!(bytes.iter().all(|byte| *byte == 0));
            bytes.clear();
            std::io::Read::read_to_end(&mut held_temporary, &mut bytes).unwrap();
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
        assert_eq!(
            store
                .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
                .unwrap(),
            SecretReleaseOutcome::Released
        );
    }
}
