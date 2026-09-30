//! Backend-side revalidation of staged attachment copies.
//!
//! The bridge stages each batch into a private directory before calling
//! [`crate::Backend::run_with_attachments`]. Adapters call [`revalidate`]
//! immediately before spawning their backend so a replaced, resized, or
//! non-regular staged entry fails the whole turn instead of reaching the backend.

use std::io::Read;

use crate::{Attachment, HarnessError};

/// A staged attachment whose on-disk copy still matches the staged metadata.
pub struct Revalidated {
    /// Absolute UTF-8 path of the staged copy; it never begins with `-`.
    pub staged_path: String,
    /// Complete file content read through a no-follow descriptor.
    pub bytes: Vec<u8>,
}

/// Re-opens one staged copy without following symlinks and reads its full content.
///
/// Returns [`HarnessError::AttachmentInvalid`] for a relative or non-UTF-8 path, a
/// missing entry, a symlink, directory, FIFO or other non-regular file, and any
/// size mismatch against [`Attachment::size_bytes`].
pub fn revalidate(attachment: &Attachment) -> Result<Revalidated, HarnessError> {
    if !attachment.path.is_absolute() {
        return Err(HarnessError::AttachmentInvalid);
    }
    let staged_path = attachment
        .path
        .to_str()
        .ok_or(HarnessError::AttachmentInvalid)?
        .to_owned();
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options
        .open(&attachment.path)
        .map_err(|_| HarnessError::AttachmentInvalid)?;
    let metadata = file
        .metadata()
        .map_err(|_| HarnessError::AttachmentInvalid)?;
    if !metadata.file_type().is_file() || metadata.len() != attachment.size_bytes {
        return Err(HarnessError::AttachmentInvalid);
    }
    let read_limit = attachment
        .size_bytes
        .checked_add(1)
        .ok_or(HarnessError::AttachmentInvalid)?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| HarnessError::AttachmentInvalid)?;
    if u64::try_from(bytes.len()).ok() != Some(attachment.size_bytes) {
        return Err(HarnessError::AttachmentInvalid);
    }
    Ok(Revalidated { staged_path, bytes })
}

/// Whether the content is valid UTF-8 without NUL bytes.
pub fn is_utf8_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| !text.contains('\0'))
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use super::*;

    fn attachment(path: &Path, size_bytes: u64) -> Attachment {
        Attachment {
            path: path.to_path_buf(),
            media_type: "application/octet-stream".to_owned(),
            file_name: "attachment".to_owned(),
            size_bytes,
        }
    }

    fn rejected(attachment: &Attachment) -> bool {
        matches!(revalidate(attachment), Err(HarnessError::AttachmentInvalid))
    }

    #[test]
    fn revalidate_returns_the_exact_staged_content() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("000-notes.txt");
        fs::write(&path, b"notes\n").unwrap();
        let revalidated = revalidate(&attachment(&path, 6)).unwrap();
        assert_eq!(revalidated.staged_path, path.to_str().unwrap());
        assert_eq!(revalidated.bytes, b"notes\n");
    }

    #[test]
    fn revalidate_rejects_every_unsafe_or_changed_entry() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.txt");
        fs::write(&source, b"data").unwrap();

        let link = root.path().join("link.txt");
        symlink(&source, &link).unwrap();
        assert!(rejected(&attachment(&link, 4)));
        assert!(rejected(&attachment(&source, 3)));
        assert!(rejected(&attachment(&source, 5)));
        assert!(rejected(&attachment(&root.path().join("missing"), 0)));
        assert!(rejected(&attachment(root.path(), 0)));
        assert!(rejected(&attachment(&PathBuf::from("relative.txt"), 4)));

        let fifo = root.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(rejected(&attachment(&fifo, 0)));

        let non_utf8 = root
            .path()
            .join(std::ffi::OsString::from_vec(b"opaque-\xff".to_vec()));
        match fs::write(&non_utf8, b"data") {
            Ok(()) => assert!(rejected(&attachment(&non_utf8, 4))),
            Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => {
                // Filesystems such as APFS reject non-UTF-8 names during setup.
            }
            Err(error) => panic!("non-UTF-8 attachment fixture creation failed: {error}"),
        }
    }

    #[test]
    fn utf8_text_excludes_nul_and_invalid_sequences() {
        assert!(is_utf8_text(b"\x1b[31merror\x1b[0m\x0c\n"));
        assert!(is_utf8_text("h\u{e9}llo".as_bytes()));
        assert!(is_utf8_text(b""));
        assert!(!is_utf8_text(b"text\0tail"));
        assert!(!is_utf8_text(b"\xff\xfe"));
    }
}
