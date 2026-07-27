//! Secure import of an existing local-signing Nostr identity.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

use marmot_account::{AccountHome, AccountHomeError};
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_IDENTITY_BYTES: u64 = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExistingIdentityImport {
    pub account_id_hex: String,
    pub label: String,
    pub local_signing: bool,
}

#[derive(Debug, Error)]
pub enum ExistingIdentityError {
    #[error("could not open identity file ({0:?})")]
    Open(io::ErrorKind),
    #[error("could not read identity file ({0:?})")]
    Read(io::ErrorKind),
    #[error("identity source must be a regular file")]
    NotRegularFile,
    #[error("identity file must be owned by the current user")]
    WrongOwner,
    #[error("identity file must not be accessible by group or other users")]
    UnsafePermissions,
    #[error("identity file must have exactly one hard link")]
    MultipleHardLinks,
    #[error("identity input is empty")]
    Empty,
    #[error("identity input exceeds {MAX_IDENTITY_BYTES} bytes")]
    TooLarge,
    #[error("identity input is not valid UTF-8")]
    InvalidUtf8,
    #[error("expected identity must be an npub or 64-character hex public key")]
    InvalidExpectedIdentity,
    #[error("imported identity does not match the expected public identity")]
    ExpectedIdentityMismatch,
    #[error(transparent)]
    Account(#[from] AccountHomeError),
}

pub fn import_existing_identity_file(
    home: &Path,
    label: &str,
    identity_file: &Path,
    expected_identity: Option<&str>,
) -> Result<ExistingIdentityImport, ExistingIdentityError> {
    let file = open_private_identity_file(identity_file)?;
    let secret = read_identity(file)?;
    import_existing_identity_secret(home, label, secret.as_str(), expected_identity)
}

pub fn import_existing_identity_secret(
    home: &Path,
    label: &str,
    secret: &str,
    expected_identity: Option<&str>,
) -> Result<ExistingIdentityImport, ExistingIdentityError> {
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(ExistingIdentityError::Empty);
    }

    let account_id_hex = AccountHome::account_id_for_secret(secret)?;
    if let Some(expected_identity) = expected_identity {
        let expected_account_id = marmot_app::account_id_hex_from_ref(expected_identity)
            .map_err(|_| ExistingIdentityError::InvalidExpectedIdentity)?;
        if account_id_hex != expected_account_id {
            return Err(ExistingIdentityError::ExpectedIdentityMismatch);
        }
    }

    let account = AccountHome::open(home).import_account_idempotent(label, secret)?;
    Ok(ExistingIdentityImport {
        account_id_hex: account.account_id_hex,
        label: account.label,
        local_signing: account.local_signing,
    })
}

fn open_private_identity_file(path: &Path) -> Result<File, ExistingIdentityError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| ExistingIdentityError::Open(error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| ExistingIdentityError::Read(error.kind()))?;
    if !metadata.file_type().is_file() {
        return Err(ExistingIdentityError::NotRegularFile);
    }
    #[cfg(unix)]
    validate_unix_identity_metadata(&metadata)?;
    if metadata.len() > MAX_IDENTITY_BYTES {
        return Err(ExistingIdentityError::TooLarge);
    }
    Ok(file)
}

#[cfg(unix)]
fn validate_unix_identity_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), ExistingIdentityError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(ExistingIdentityError::WrongOwner);
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(ExistingIdentityError::UnsafePermissions);
    }
    if metadata.nlink() != 1 {
        return Err(ExistingIdentityError::MultipleHardLinks);
    }
    Ok(())
}

fn read_identity(reader: impl Read) -> Result<Zeroizing<String>, ExistingIdentityError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(128));
    reader
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ExistingIdentityError::Read(error.kind()))?;
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(ExistingIdentityError::TooLarge);
    }
    std::str::from_utf8(bytes.as_slice()).map_err(|_| ExistingIdentityError::InvalidUtf8)?;
    let bytes = std::mem::take(&mut *bytes);
    // SAFETY: UTF-8 validity was checked immediately above, before ownership
    // moved out of the zeroizing byte buffer.
    let secret = unsafe { String::from_utf8_unchecked(bytes) };
    let secret = Zeroizing::new(secret);
    if secret.trim().is_empty() {
        return Err(ExistingIdentityError::Empty);
    }
    Ok(secret)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    const NSEC: &str = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    const NPUB: &str = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";

    fn write_identity(path: &Path, value: &str) {
        std::fs::write(path, value).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn imports_and_idempotently_reuses_a_private_identity_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let identity = dir.path().join("identity.nsec");
        write_identity(&identity, NSEC);

        let first = import_existing_identity_file(&home, "agent", &identity, None).unwrap();
        let second = import_existing_identity_file(&home, "agent", &identity, None).unwrap();

        assert_eq!(second, first);
        assert_eq!(AccountHome::open(&home).accounts().unwrap().len(), 1);
        let output = serde_json::to_string(&first).unwrap();
        assert!(!output.contains(NSEC));
        let account_record =
            std::fs::read_to_string(home.join("accounts").join("agent").join("account.json"))
                .unwrap();
        assert!(!account_record.contains(NSEC));
        assert_eq!(std::fs::read_to_string(&identity).unwrap(), NSEC);
    }

    #[test]
    fn expected_identity_mismatch_fails_before_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let identity = dir.path().join("identity.nsec");
        write_identity(&identity, NSEC);
        let other_identity = format!("{}01", "00".repeat(31));

        let error = import_existing_identity_file(&home, "agent", &identity, Some(&other_identity))
            .unwrap_err();

        assert!(matches!(
            error,
            ExistingIdentityError::ExpectedIdentityMismatch
        ));
        assert!(AccountHome::open(&home).accounts().unwrap().is_empty());
    }

    #[test]
    fn matching_expected_npub_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.nsec");
        write_identity(&identity, NSEC);

        let imported =
            import_existing_identity_file(&dir.path().join("home"), "agent", &identity, Some(NPUB))
                .unwrap();

        assert!(imported.local_signing);
    }

    #[test]
    fn accepts_raw_hex_secret_key_representation() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.hex");
        let raw_secret = format!("{}01", "00".repeat(31));
        write_identity(&identity, &raw_secret);

        let imported =
            import_existing_identity_file(&dir.path().join("home"), "agent", &identity, None)
                .unwrap();

        assert!(imported.local_signing);
        assert_eq!(imported.account_id_hex.len(), 64);
    }

    #[test]
    fn rejects_group_readable_and_symlinked_identity_files() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.nsec");
        write_identity(&identity, NSEC);
        std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            import_existing_identity_file(&dir.path().join("home"), "agent", &identity, None),
            Err(ExistingIdentityError::UnsafePermissions)
        ));

        std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.path().join("alias.nsec");
        symlink(&identity, &alias).unwrap();
        assert!(matches!(
            import_existing_identity_file(&dir.path().join("home"), "agent", &alias, None),
            Err(ExistingIdentityError::Open(_))
        ));
    }

    #[test]
    fn rejects_identity_files_with_multiple_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.nsec");
        let alias = dir.path().join("identity-alias.nsec");
        write_identity(&identity, NSEC);
        std::fs::hard_link(&identity, &alias).unwrap();

        assert!(matches!(
            import_existing_identity_file(&dir.path().join("home"), "agent", &identity, None),
            Err(ExistingIdentityError::MultipleHardLinks)
        ));
        assert_eq!(std::fs::read_to_string(&identity).unwrap(), NSEC);
        assert_eq!(std::fs::read_to_string(&alias).unwrap(), NSEC);
    }

    #[test]
    fn rejects_malformed_identity_without_echoing_it() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.nsec");
        let malformed = "nsec1-not-valid-secret-material";
        write_identity(&identity, malformed);

        let error =
            import_existing_identity_file(&dir.path().join("home"), "agent", &identity, None)
                .unwrap_err();

        assert!(matches!(
            error,
            ExistingIdentityError::Account(AccountHomeError::InvalidSecretKey)
        ));
        assert!(!error.to_string().contains(malformed));
    }
}
