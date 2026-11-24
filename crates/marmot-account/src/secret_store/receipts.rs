//! Account secret stores and their owned credential receipts.

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
use crate::io::{
    read_secret_json, read_secret_text_with, remove_file_then_scrub, sync_directory,
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

    fn open_record(&self, kind: RecordKind, name: &str) -> io::Result<File> {
        let owned = open_vault_child(&self.handle, OWNED_SECRET_DIR, true)?;
        let records = open_vault_child(&owned, record_directory_name(kind), true)?;
        open_vault_child(&records, name, false)
    }

    fn read_marker(&self) -> AccountHomeResult<Option<[u8; VAULT_ID_LEN]>> {
        let mut file = match open_vault_child(&self.handle, VAULT_ID_FILE, false) {
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
        match open_vault_child(&self.handle, OWNED_SECRET_DIR, true) {
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

#[cfg(unix)]
fn publish_vault_marker(parent: &File, marker: &[u8; VAULT_ID_LEN]) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;

    let temp = std::ffi::CString::new(marker_temp_name(marker)).expect("encoded marker filename");
    let leaf = std::ffi::CString::new(VAULT_ID_FILE).expect("marker filename");
    let directory = parent.as_raw_fd();
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // The directory and NUL-terminated filename outlive openat.
    let fd = unsafe {
        libc::openat(
            directory,
            temp.as_ptr(),
            flags,
            libc::c_uint::from(0o600u16),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // A successful openat owns this descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(marker)?;
        file.sync_all()?;
        // linkat publishes the synced inode without replacing an existing name.
        // Both names are live C strings relative to the same held directory.
        if unsafe { libc::linkat(directory, temp.as_ptr(), directory, leaf.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    // Remove only the staging name, even if publication failed.
    let removed = if unsafe { libc::unlinkat(directory, temp.as_ptr(), 0) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    };
    result.and(removed).and(parent.sync_all())
}

#[cfg(windows)]
fn publish_vault_marker(parent: &File, marker: &[u8; VAULT_ID_LEN]) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DISPOSITION_INFORMATION, FILE_RENAME_INFORMATION, FILE_WRITE_THROUGH,
        FileDispositionInformation, FileRenameInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_GENERIC_WRITE, GetVolumeInformationByHandleW,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut filesystem = [0u16; 32];
    // Only the filesystem-name output is requested; its buffer and the handle are live.
    if unsafe {
        GetVolumeInformationByHandleW(
            parent.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // NTFS applies write-through to rename metadata as well as file content.
    if !filesystem.starts_with(&[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0]) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable file vault markers require NTFS",
        ));
    }

    let temp = marker_temp_name(marker);
    let mut file = open_windows_vault_child(
        parent,
        &temp,
        false,
        FILE_GENERIC_WRITE | DELETE,
        FILE_CREATE,
        FILE_WRITE_THROUGH,
        0,
    )?;
    let mut status_block = IO_STATUS_BLOCK::default();
    if let Err(error) = file.write_all(marker).and_then(|()| file.sync_all()) {
        let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        // This handle still names staging, owns DELETE access, and closes after the call.
        unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status_block,
                (&raw const disposition).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
        };
        return Err(error);
    }
    // A simple name with a null RootDirectory is a same-directory rename.
    // The staging handle pins that directory even if its pathname moved.
    #[repr(C)]
    struct Rename {
        flags: u32,
        root: HANDLE,
        length: u32,
        name: [u16; VAULT_ID_FILE.len() + 4],
    }
    const NAME_BYTES: usize = VAULT_ID_FILE.len() * size_of::<u16>();
    const {
        assert!(
            std::mem::offset_of!(Rename, name)
                == std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
        );
        assert!(size_of::<Rename>() >= size_of::<FILE_RENAME_INFORMATION>() + NAME_BYTES);
    }
    let mut rename = Rename {
        flags: 0, // ReplaceIfExists = FALSE.
        root: null_mut(),
        length: NAME_BYTES as u32,
        name: [0; VAULT_ID_FILE.len() + 4],
    };
    for (unit, byte) in rename.name.iter_mut().zip(VAULT_ID_FILE.bytes()) {
        *unit = u16::from(byte);
    }
    // The rename buffer and synchronous, write-through handle remain valid for the call.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            (&raw const rename).cast(),
            size_of::<Rename>() as u32,
            FileRenameInformation,
        )
    };
    let result = check_nt_status(status);
    if matches!(&result, Err(error) if error.kind() == io::ErrorKind::AlreadyExists) {
        let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        // On a collision, the handle still names staging and closes after this call.
        unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status_block,
                (&raw const disposition).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
        };
    }
    result
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

#[cfg(unix)]
fn open_vault_directory(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_vault_directory(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file vault requires stable directory identity",
    ))
}

#[cfg(windows)]
fn open_vault_directory(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_TRAVERSE,
    };

    let file = File::options()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    check_vault_object(&file, true)?;
    Ok(file)
}

#[cfg(unix)]
fn open_vault_child(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let mut component = [0; RECORD_NAME_LEN + 1];
    component[..name.len()].copy_from_slice(name.as_bytes());
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let directory_access = libc::O_PATH;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let directory_access = libc::O_RDONLY;
    let flags = flags
        | if directory {
            libc::O_DIRECTORY | directory_access
        } else {
            libc::O_RDONLY
        };
    // `name` is a fixed vault component or a validated record name. The stack
    // buffer is NUL-terminated and `parent` stays open for the call.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr().cast(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // openat returned a new descriptor owned by this call.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(windows)]
fn open_vault_child(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
    use windows_sys::Win32::Storage::FileSystem::{FILE_READ_DATA, FILE_TRAVERSE};

    let access = if directory {
        FILE_TRAVERSE
    } else {
        FILE_READ_DATA
    };
    open_windows_vault_child(
        parent,
        name,
        directory,
        access,
        FILE_OPEN,
        0,
        WINDOWS_VAULT_SHARE,
    )
}

#[cfg(windows)]
const WINDOWS_VAULT_SHARE: u32 = {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
};

#[cfg(windows)]
fn open_windows_vault_child(
    parent: &File,
    name: &str,
    directory: bool,
    access: u32,
    disposition: u32,
    options: u32,
    share: u32,
) -> io::Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{OBJ_CASE_INSENSITIVE, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, SYNCHRONIZE};
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut component = [0u16; RECORD_NAME_LEN];
    for (unit, byte) in component.iter_mut().zip(name.bytes()) {
        *unit = u16::from(byte);
    }
    let length = (name.len() * size_of::<u16>()) as u16;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: component.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let access = access | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    let options = options
        | FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | if directory {
            0
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    let mut handle = null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // Each call opens one component, without following a final reparse point.
    // The borrowed directory, name buffer and out pointers live through the call.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            null(),
            0,
            share,
            disposition,
            options,
            null(),
            0,
        )
    };
    check_nt_status(status)?;
    // A successful open returned a new owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    check_vault_object(&file, directory)?;
    Ok(file)
}

#[cfg(windows)]
fn check_nt_status(status: windows_sys::Win32::Foundation::NTSTATUS) -> io::Result<()> {
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;

    if status < 0 {
        // The function accepts an NTSTATUS value and returns a Win32 error code.
        Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn check_vault_object(file: &File, directory: bool) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid file vault entry",
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn open_vault_child(_parent: &File, _name: &str, _directory: bool) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file vault requires relative file opens",
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

    let current = open_vault_directory(path)?;
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

    let file = open_windows_vault_child(
        dir,
        CREDENTIAL_STORE_LOCK_FILE,
        false,
        FILE_READ_DATA | FILE_WRITE_DATA,
        FILE_OPEN_IF,
        0,
        WINDOWS_VAULT_SHARE,
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
    pub fn new(root: impl AsRef<Path>, _ios_options: IosOptions) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            directory: Arc::new(OnceLock::new()),
        }
    }

    fn storage_directory(&self) -> AccountHomeResult<&FileVaultDirectory> {
        if let Some(directory) = self.directory.get() {
            directory.verify()?;
            return Ok(directory);
        }
        let root = match self.root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::io::create_durable_private_dir(&self.root, &self.root)?;
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
        let directory = self.directory.get_or_init(|| FileVaultDirectory {
            path: root,
            handle,
            namespace: OnceLock::new(),
        });
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

    fn owned_dir(&self, kind: RecordKind) -> AccountHomeResult<PathBuf> {
        Ok(self
            .storage_root()?
            .join(OWNED_SECRET_DIR)
            .join(record_directory_name(kind)))
    }

    fn owned_path(&self, kind: RecordKind, name: &str) -> AccountHomeResult<PathBuf> {
        validate_record_name(name)?;
        Ok(self.owned_dir(kind)?.join(name))
    }

    fn lock_directory(directory: &FileVaultDirectory) -> AccountHomeResult<FileVaultGuard> {
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
        let directory = self.owned_dir(RecordKind::Receipt)?;
        let mut result = Ok(());
        for name in names {
            let name = name.as_ref();
            validate_record_name(name)?;
            result = result.and(scrub_and_remove_local_secret_file(&directory.join(name)));
        }
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return result,
            Err(error) => return result.and(Err(error.into())),
        };
        let mut temporaries = Vec::new();
        for entry in entries {
            result = result.and((|| {
                let entry = entry?;
                if let Some(target) = entry.file_name().to_str().and_then(temporary_target)
                    && names
                        .binary_search_by(|name| name.as_ref().cmp(target))
                        .is_ok()
                {
                    temporaries.push(entry.path());
                }
                Ok(())
            })());
        }
        for temporary in temporaries {
            result = result.and(scrub_and_remove_local_secret_file(&temporary));
        }
        result
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
        let value = read_secret_text_with(|| directory.open_record(kind, name));
        directory.verify()?;
        match value {
            Ok(value) => Ok(Some(value)),
            Err(AccountHomeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()> {
        let path = self.owned_path(kind, name)?;
        let root = self.storage_root()?;
        if matches!(kind, RecordKind::Receipt) {
            if let Some(existing) = self.read(kind, name)? {
                if existing.as_str() == value {
                    return self.sync(kind);
                }
                return Err(AccountHomeError::SecretStore(
                    "owned credential receipts are immutable".into(),
                ));
            }
            return write_secret_bytes(root, &path, value.as_bytes());
        }
        write_private_bytes(root, &path, value.as_bytes())
    }

    fn sync(&self, kind: RecordKind) -> AccountHomeResult<()> {
        Ok(sync_directory(&self.owned_dir(kind)?)?)
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
