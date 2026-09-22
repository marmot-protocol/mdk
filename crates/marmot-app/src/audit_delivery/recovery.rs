use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use fs_private::{ExistingFileAccess, PreparedDirectory};

use super::state::{AuditDeliveryError, MAX_METADATA_BYTES};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) struct JournalDirectories {
    pub(super) root: PreparedDirectory,
    pub(super) segments: PreparedDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FaultPoint {
    Write,
    FileSync,
    Rename,
    DirectorySync,
    PayloadSync,
}

#[derive(Default)]
pub(super) struct Faults {
    #[cfg(test)]
    next: Option<(FaultPoint, u8)>,
}

impl Faults {
    #[cfg(test)]
    pub(super) fn fail_next(&mut self, point: FaultPoint) {
        self.fail_after(point, 0);
    }

    #[cfg(test)]
    pub(super) fn fail_after(&mut self, point: FaultPoint, matching_calls_to_skip: u8) {
        self.next = Some((point, matching_calls_to_skip));
    }

    pub(super) fn check(&mut self, point: FaultPoint) -> Result<(), AuditDeliveryError> {
        #[cfg(test)]
        if let Some((expected, remaining)) = &mut self.next
            && *expected == point
        {
            if *remaining > 0 {
                *remaining -= 1;
            } else {
                self.next = None;
                if point == FaultPoint::DirectorySync {
                    return Err(AuditDeliveryError::UncertainPublication {
                        source: io::Error::other("injected audit-delivery fault"),
                    });
                }
                return Err(AuditDeliveryError::Filesystem {
                    operation: point.operation(),
                    source: io::Error::other("injected audit-delivery fault"),
                });
            }
        }
        let _ = point;
        Ok(())
    }
}

#[cfg(test)]
impl FaultPoint {
    fn operation(self) -> &'static str {
        match self {
            Self::Write => "write metadata",
            Self::FileSync => "sync metadata file",
            Self::Rename => "publish metadata",
            Self::DirectorySync => "sync metadata directory",
            Self::PayloadSync => "sync payload prefix",
        }
    }
}

pub(super) fn validate_single_component(value: &str) -> Result<(), AuditDeliveryError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AuditDeliveryError::UnsafeIdentifier);
    }
    let mut components = Path::new(value).components();
    if !matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    ) {
        return Err(AuditDeliveryError::UnsafeIdentifier);
    }
    Ok(())
}

pub(super) fn create_journal_directories(
    path: &Path,
) -> Result<JournalDirectories, AuditDeliveryError> {
    let parent = path.parent().ok_or(AuditDeliveryError::UnsafePath)?;
    let parent = fs_private::prepare_directory_path(
        parent,
        fs_private::PRIVATE_DIR_MODE,
        fs_private::ExistingDirectoryMode::Enforce,
    )
    .map_err(|source| AuditDeliveryError::Filesystem {
        operation: "create private journal directory",
        source,
    })?;
    let name = path.file_name().ok_or(AuditDeliveryError::UnsafePath)?;
    let root = match parent.create_private_subdirectory(name) {
        Ok(root) => root,
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(AuditDeliveryError::GenerationCollision);
        }
        Err(source) => {
            return Err(AuditDeliveryError::Filesystem {
                operation: "create journal generation directory",
                source,
            });
        }
    };
    let segments = root
        .create_private_subdirectory(OsStr::new("segments"))
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "create journal segments directory",
            source,
        })?;
    Ok(JournalDirectories { root, segments })
}

pub(super) fn open_or_recover_empty_journal_directories(
    path: &Path,
) -> Result<JournalDirectories, AuditDeliveryError> {
    let root = open_generation_directory(path)?;
    let segments = match root.open_existing_private_subdirectory(
        OsStr::new("segments"),
        fs_private::ExistingDirectoryMode::Enforce,
    ) {
        Ok(segments) => segments,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let root_empty = root
                .is_empty()
                .map_err(|source| AuditDeliveryError::Filesystem {
                    operation: "inspect incomplete generation root",
                    source,
                })?;
            if !root_empty {
                return Err(AuditDeliveryError::IncompleteState);
            }
            root.create_private_subdirectory(OsStr::new("segments"))
                .map_err(map_generation_directory_error)?
        }
        Err(source) => return Err(map_generation_directory_error(source)),
    };
    Ok(JournalDirectories { root, segments })
}

fn open_generation_directory(path: &Path) -> Result<PreparedDirectory, AuditDeliveryError> {
    fs_private::open_existing_directory_path(
        path,
        fs_private::PRIVATE_DIR_MODE,
        fs_private::ExistingDirectoryMode::Enforce,
    )
    .map_err(map_generation_directory_error)
}

fn map_generation_directory_error(source: io::Error) -> AuditDeliveryError {
    if source.kind() == io::ErrorKind::NotFound {
        AuditDeliveryError::IncompleteState
    } else {
        AuditDeliveryError::UnsafePath
    }
}

pub(super) fn open_segment_read(
    segments: &PreparedDirectory,
    name: &OsStr,
) -> Result<File, AuditDeliveryError> {
    map_missing_segment(
        segments
            .open_existing_regular_file(name, ExistingFileAccess::Read)
            .map_err(open_artifact_error),
    )
}

pub(super) fn open_segment_sync(
    segments: &PreparedDirectory,
    name: &OsStr,
) -> Result<File, AuditDeliveryError> {
    map_missing_segment(
        segments
            .open_existing_regular_file(name, ExistingFileAccess::ReadWrite)
            .map_err(open_artifact_error),
    )
}

fn open_artifact_error(source: io::Error) -> AuditDeliveryError {
    if source.kind() == io::ErrorKind::InvalidInput {
        AuditDeliveryError::UnsafePath
    } else {
        AuditDeliveryError::Filesystem {
            operation: "open journal artifact",
            source,
        }
    }
}

fn map_missing_segment(
    result: Result<File, AuditDeliveryError>,
) -> Result<File, AuditDeliveryError> {
    match result {
        Err(AuditDeliveryError::Filesystem { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            Err(AuditDeliveryError::MissingSegment)
        }
        result => result,
    }
}

pub(super) fn read_bounded(
    root: &PreparedDirectory,
    name: &OsStr,
) -> Result<Vec<u8>, AuditDeliveryError> {
    let file = root
        .open_existing_regular_file(name, ExistingFileAccess::Read)
        .map_err(open_artifact_error)?;
    let length = file
        .metadata()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "inspect metadata file",
            source,
        })?
        .len();
    if length > MAX_METADATA_BYTES as u64 {
        return Err(AuditDeliveryError::MetadataTooLarge);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_METADATA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "read metadata file",
            source,
        })?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(AuditDeliveryError::MetadataTooLarge);
    }
    Ok(bytes)
}

pub(super) fn atomic_replace(
    root: &PreparedDirectory,
    target: &OsStr,
    bytes: &[u8],
    faults: &mut Faults,
) -> Result<(), AuditDeliveryError> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(AuditDeliveryError::MetadataTooLarge);
    }
    validate_existing_target(root, target)?;
    let (mut file, temporary) = create_temporary(root, target)?;
    let result = (|| {
        faults.check(FaultPoint::Write)?;
        file.write_all(bytes)
            .map_err(|source| AuditDeliveryError::Filesystem {
                operation: "write metadata",
                source,
            })?;
        faults.check(FaultPoint::FileSync)?;
        file.sync_all()
            .map_err(|source| AuditDeliveryError::Filesystem {
                operation: "sync metadata file",
                source,
            })?;
        drop(file);
        faults.check(FaultPoint::Rename)?;
        root.replace_entry(&temporary, target).map_err(|source| {
            AuditDeliveryError::Filesystem {
                operation: "publish metadata",
                source,
            }
        })?;
        faults.check(FaultPoint::DirectorySync)?;
        root.sync_all()
            .map_err(|source| AuditDeliveryError::UncertainPublication { source })
    })();
    if result.is_err() {
        let _ = root.remove_file(&temporary);
    }
    result
}

fn validate_existing_target(
    root: &PreparedDirectory,
    target: &OsStr,
) -> Result<(), AuditDeliveryError> {
    match root.open_existing_regular_file(target, ExistingFileAccess::Read) {
        Ok(_) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(open_artifact_error(source)),
    }
}

fn create_temporary(
    root: &PreparedDirectory,
    target: &OsStr,
) -> Result<(File, OsString), AuditDeliveryError> {
    for _ in 0..32 {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = OsString::from(".");
        name.push(target);
        name.push(format!(".tmp-{}-{nonce}", std::process::id()));
        match root.create_new_private_file(&name) {
            Ok(file) => return Ok((file, name)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(AuditDeliveryError::Filesystem {
                    operation: "create metadata staging file",
                    source,
                });
            }
        }
    }
    Err(AuditDeliveryError::TemporaryNameExhausted)
}
