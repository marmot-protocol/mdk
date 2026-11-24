//! Physical record operations anchored to a held directory.

#[cfg(unix)]
pub(crate) use unix::*;
#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(unix)]
mod unix {
    use std::ffi::{CStr, OsStr};
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use super::super::{overwrite_open_file_with_zeros, unix_directory};
    use unix_directory::{component_name, open_at, open_directory_at};

    pub(crate) fn open_root(path: &Path) -> io::Result<File> {
        let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW;
        #[cfg(target_vendor = "apple")]
        let flags = flags | libc::O_NOFOLLOW_ANY;
        OpenOptions::new().read(true).custom_flags(flags).open(path)
    }

    pub(crate) fn open_dir(parent: &File, name: &OsStr) -> io::Result<File> {
        open_directory_at(parent, &component_name(name, &mut [0; 256])?)
    }

    pub(crate) fn create_dir(parent: &File, name: &OsStr) -> io::Result<File> {
        unix_directory::create_child(parent, &component_name(name, &mut [0; 256])?)
    }

    pub(crate) fn open_record(parent: &File, name: &OsStr) -> io::Result<File> {
        open_at(
            parent,
            &component_name(name, &mut [0; 256])?,
            libc::O_RDONLY,
        )
    }

    pub(crate) fn create_stage(parent: &File, name: &OsStr) -> io::Result<File> {
        open_at(
            parent,
            &component_name(name, &mut [0; 256])?,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
    }

    pub(crate) fn sync(parent: &File) -> io::Result<()> {
        parent.sync_all()
    }

    pub(crate) fn replace(
        parent: &File,
        _source: &File,
        from: &OsStr,
        to: &OsStr,
    ) -> io::Result<()> {
        rename(parent, from, to)
    }

    pub(crate) fn replace_existing_stage(
        parent: &File,
        from: &OsStr,
        to: &OsStr,
    ) -> io::Result<()> {
        rename(parent, from, to)
    }

    pub(crate) fn link_new(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let (mut from_buffer, mut to_buffer) = ([0; 256], [0; 256]);
        let from = component_name(from, &mut from_buffer)?;
        let to = component_name(to, &mut to_buffer)?;
        let fd = parent.as_raw_fd();
        // SAFETY: Both components and the directory descriptor live through the call.
        if unsafe { libc::linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn rename(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let (mut from_buffer, mut to_buffer) = ([0; 256], [0; 256]);
        let from = component_name(from, &mut from_buffer)?;
        let to = component_name(to, &mut to_buffer)?;
        let fd = parent.as_raw_fd();
        // SAFETY: Both components and the directory descriptor live through the call.
        if unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn unlink(parent: &File, name: &OsStr) -> io::Result<()> {
        let mut buffer = [0; 256];
        let name = component_name(name, &mut buffer)?;
        // SAFETY: The component and directory descriptor live through the call.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(crate) fn discard_stage(parent: &File, _stage: &File, name: &OsStr) -> io::Result<()> {
        unlink(parent, name)
    }

    pub(crate) fn replace_secret(
        parent: &File,
        _stage: &File,
        from: &OsStr,
        name: &OsStr,
    ) -> io::Result<()> {
        let mut previous = match open_at(
            parent,
            &component_name(name, &mut [0; 256])?,
            libc::O_WRONLY,
        ) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(file) = &previous {
            super::super::check_scrubbable(file)?;
        }
        rename(parent, from, name)?;
        if let Some(file) = &mut previous
            && file.metadata().is_ok_and(|metadata| metadata.nlink() == 0)
        {
            let _ = overwrite_open_file_with_zeros(file);
        }
        Ok(())
    }

    pub(crate) fn remove_secret(parent: &File, name: &OsStr) -> io::Result<()> {
        let mut old = match open_at(
            parent,
            &component_name(name, &mut [0; 256])?,
            libc::O_WRONLY,
        ) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                // An owner may be allowed to unlink a file they cannot overwrite.
                check_regular_type(entry_type(parent, name)?)?;
                None
            }
            Err(error) => return Err(error),
        };
        if let Some(file) = &old {
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return check_regular_type(if metadata.is_dir() { libc::S_IFDIR } else { 0 });
            }
            if metadata.nlink() != 1 {
                old = None;
            }
        }
        let removed = unlink(parent, name);
        if let Some(file) = &mut old {
            // If unlink itself failed, retain best-effort in-place scrubbing.
            // Otherwise only scrub an inode the unlink actually detached.
            let expected_links = u64::from(removed.is_err());
            if file
                .metadata()
                .is_ok_and(|metadata| metadata.nlink() == expected_links)
            {
                let _ = overwrite_open_file_with_zeros(file);
            }
        }
        match removed {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    fn check_regular_type(kind: libc::mode_t) -> io::Result<()> {
        match kind {
            libc::S_IFREG => Ok(()),
            libc::S_IFDIR => Err(io::Error::from_raw_os_error(libc::EISDIR)),
            libc::S_IFLNK => Err(io::Error::from_raw_os_error(libc::ELOOP)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid credential file type",
            )),
        }
    }

    fn entry_type(parent: &File, name: &OsStr) -> io::Result<libc::mode_t> {
        let mut buffer = [0; 256];
        let name = component_name(name, &mut buffer)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: The descriptor, component and output buffer live through the call.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Successful fstatat initialized stat.
        Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT)
    }

    pub(crate) fn visit_entries<E: From<io::Error>>(
        parent: &File,
        mut visit: impl FnMut(&OsStr, bool) -> Result<(), E>,
    ) -> Result<(), E> {
        struct DirectoryStream(*mut libc::DIR);
        impl Drop for DirectoryStream {
            fn drop(&mut self) {
                // SAFETY: fdopendir returned this owned stream.
                unsafe { libc::closedir(self.0) };
            }
        }

        // Open a fresh cursor on the held directory. dup would share its offset.
        let directory = open_dir(parent, OsStr::new("."))?;
        // SAFETY: The descriptor is live and ownership transfers only on success.
        let stream = unsafe { libc::fdopendir(directory.as_raw_fd()) };
        if stream.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let _ = directory.into_raw_fd();
        let stream = DirectoryStream(stream);
        loop {
            // SAFETY: errno is local to this thread and stream is uniquely owned.
            let entry = unsafe {
                *errno_location() = 0;
                libc::readdir(stream.0)
            };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(())
                } else {
                    Err(error.into())
                };
            }
            // SAFETY: This result and its NUL-terminated name stay valid until the next read.
            let name =
                unsafe { OsStr::from_bytes(CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes()) };
            if name == "." || name == ".." {
                continue;
            }
            #[cfg(not(any(
                target_os = "solaris",
                target_os = "illumos",
                target_os = "haiku",
                target_os = "aix",
                target_os = "nto"
            )))]
            {
                // SAFETY: The same dirent remains live for this field access.
                let kind = unsafe { (*entry).d_type };
                if kind != libc::DT_UNKNOWN {
                    visit(name, kind == libc::DT_REG)?;
                    continue;
                }
            }
            let regular = match entry_type(parent, name) {
                Ok(kind) => kind == libc::S_IFREG,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            visit(name, regular)?;
        }
    }

    // readdir returns NULL for both end-of-stream and error.
    unsafe extern "C" {
        #[cfg_attr(
            any(target_vendor = "apple", target_os = "freebsd"),
            link_name = "__error"
        )]
        #[cfg_attr(
            any(
                target_os = "android",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "cygwin",
                target_env = "newlib"
            ),
            link_name = "__errno"
        )]
        #[cfg_attr(
            any(target_os = "illumos", target_os = "solaris"),
            link_name = "___errno"
        )]
        #[cfg_attr(target_os = "haiku", link_name = "_errnop")]
        #[cfg_attr(
            any(
                target_os = "linux",
                target_os = "dragonfly",
                target_os = "hurd",
                target_os = "emscripten",
                target_os = "redox"
            ),
            link_name = "__errno_location"
        )]
        #[cfg_attr(target_os = "aix", link_name = "_Errno")]
        #[cfg_attr(target_os = "nto", link_name = "__get_errno_ptr")]
        fn errno_location() -> *mut libc::c_int;
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DIRECTORY_INFORMATION, FILE_DISPOSITION_INFORMATION,
        FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
        FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH,
        FileDirectoryInformation, FileDispositionInformation, FileRenameInformation,
        FileRenameInformationEx, NtCreateFile, NtQueryDirectoryFile, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, STATUS_NO_MORE_FILES,
        STATUS_NO_SUCH_FILE, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, GetFileInformationByHandle,
        GetVolumeInformationByHandleW, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::super::{overwrite_open_file_with_zeros, temporary_name};

    pub(crate) const WINDOWS_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const DIRECTORY_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE;
    const MAX_COMPONENT: usize = 255;

    pub(crate) fn open_root(path: &Path) -> io::Result<File> {
        let file = File::options()
            .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        check_object(&file, true)?;
        Ok(file)
    }

    pub(crate) fn open_dir(parent: &File, name: &OsStr) -> io::Result<File> {
        open_child(
            parent,
            name,
            true,
            DIRECTORY_ACCESS,
            FILE_OPEN,
            0,
            WINDOWS_SHARE,
        )
    }

    pub(crate) fn create_dir(parent: &File, name: &OsStr) -> io::Result<File> {
        open_child(
            parent,
            name,
            true,
            DIRECTORY_ACCESS,
            FILE_OPEN_IF,
            0,
            WINDOWS_SHARE,
        )
    }

    pub(crate) fn open_record(parent: &File, name: &OsStr) -> io::Result<File> {
        open_child(
            parent,
            name,
            false,
            FILE_READ_DATA,
            FILE_OPEN,
            0,
            WINDOWS_SHARE,
        )
    }

    pub(crate) fn create_stage(parent: &File, name: &OsStr) -> io::Result<File> {
        open_child(
            parent,
            name,
            false,
            FILE_GENERIC_WRITE | DELETE,
            FILE_CREATE,
            FILE_WRITE_THROUGH,
            WINDOWS_SHARE,
        )
    }

    pub(crate) fn open_child(
        parent: &File,
        name: &OsStr,
        directory: bool,
        access: u32,
        disposition: u32,
        options: u32,
        share: u32,
    ) -> io::Result<File> {
        let mut component = [0u16; MAX_COMPONENT];
        let length = encode_component(name, &mut component)? as u16;
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
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            };
        let mut handle = null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: The parent, component and output buffers live through the call.
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
        check_status(status)?;
        // SAFETY: Successful NtCreateFile returned a new owned handle.
        let file = unsafe { File::from_raw_handle(handle) };
        check_object(&file, directory)?;
        Ok(file)
    }

    fn encode_component(name: &OsStr, buffer: &mut [u16; MAX_COMPONENT]) -> io::Result<u32> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid record component");
        if name.is_empty() || name == "." || name == ".." {
            return Err(invalid());
        }
        let mut length = 0;
        for unit in name.encode_wide() {
            if matches!(unit, 0 | 47 | 58 | 92) {
                return Err(invalid());
            }
            *buffer.get_mut(length).ok_or_else(invalid)? = unit;
            length += 1;
        }
        Ok((length * size_of::<u16>()) as u32)
    }

    fn check_status(status: NTSTATUS) -> io::Result<()> {
        if status < 0 {
            // SAFETY: RtlNtStatusToDosError accepts an NTSTATUS by value.
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            ));
        }
        Ok(())
    }

    fn check_object(file: &File, directory: bool) -> io::Result<()> {
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
                "invalid record entry",
            ));
        }
        Ok(())
    }

    pub(crate) fn sync(_parent: &File) -> io::Result<()> {
        // Publication uses write-through handles; FlushFileBuffers does not
        // provide a directory fsync on Windows.
        Ok(())
    }

    pub(crate) fn require_ntfs(file: &File, posix: bool) -> io::Result<()> {
        const FILE_SUPPORTS_POSIX_UNLINK_RENAME: u32 = 0x400;
        let mut filesystem = [0u16; 32];
        let mut flags = 0;
        // SAFETY: The handle and writable output buffers live through the call.
        if unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if !filesystem.starts_with(&[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0])
            || (posix && flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME == 0)
        {
            let message = if posix {
                "durable private replacement requires NTFS with POSIX rename support"
            } else {
                "durable file vault markers require NTFS"
            };
            return Err(io::Error::new(io::ErrorKind::Unsupported, message));
        }
        Ok(())
    }

    fn rename_handle(parent: &File, file: &File, name: &OsStr, replace: bool) -> io::Result<()> {
        #[repr(C)]
        struct Rename {
            flags: u32,
            root: HANDLE,
            length: u32,
            name: [u16; MAX_COMPONENT],
            padding: [u16; 4],
        }
        const {
            assert!(
                std::mem::offset_of!(Rename, name)
                    == std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
            );
            assert!(
                size_of::<Rename>()
                    >= size_of::<FILE_RENAME_INFORMATION>() + MAX_COMPONENT * size_of::<u16>()
            );
        }
        let mut rename = Rename {
            flags: if replace {
                FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS
            } else {
                0
            },
            root: parent.as_raw_handle(),
            length: 0,
            name: [0; MAX_COMPONENT],
            padding: [0; 4],
        };
        rename.length = encode_component(name, &mut rename.name)?;
        let class = if replace {
            FileRenameInformationEx
        } else {
            FileRenameInformation
        };
        let size = size_of::<FILE_RENAME_INFORMATION>() as u32 + rename.length;
        set_information(file, (&raw const rename).cast(), size, class)
    }

    fn set_information(
        file: &File,
        info: *const std::ffi::c_void,
        size: u32,
        class: FILE_INFORMATION_CLASS,
    ) -> io::Result<()> {
        let mut status = IO_STATUS_BLOCK::default();
        // SAFETY: Callers supply the initialized buffer for the class and its size.
        check_status(unsafe {
            NtSetInformationFile(file.as_raw_handle(), &mut status, info, size, class)
        })
    }

    pub(crate) fn publish_new(parent: &File, stage: &File, name: &OsStr) -> io::Result<()> {
        rename_handle(parent, stage, name, false)
    }

    pub(crate) fn replace(
        parent: &File,
        stage: &File,
        _from: &OsStr,
        name: &OsStr,
    ) -> io::Result<()> {
        require_ntfs(stage, true)?;
        rename_handle(parent, stage, name, true)
    }

    pub(crate) fn replace_existing_stage(
        parent: &File,
        from: &OsStr,
        to: &OsStr,
    ) -> io::Result<()> {
        let file = open_child(
            parent,
            from,
            false,
            DELETE,
            FILE_OPEN,
            FILE_WRITE_THROUGH,
            WINDOWS_SHARE,
        )?;
        replace(parent, &file, from, to)
    }

    fn delete_file(file: &File) -> io::Result<()> {
        let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        set_information(
            file,
            (&raw const disposition).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    }

    pub(crate) fn discard_stage(_parent: &File, stage: &File, _name: &OsStr) -> io::Result<()> {
        delete_file(stage)
    }

    // Keep old Windows secret replacement semantics without resolving either
    // name again. Legacy Windows deletion can hold a name pending while a
    // reader is open, so move the old file aside before installing the stage.
    pub(crate) fn replace_secret(
        parent: &File,
        stage: &File,
        _from: &OsStr,
        name: &OsStr,
    ) -> io::Result<()> {
        let mut old = match open_child(
            parent,
            name,
            false,
            DELETE | FILE_GENERIC_WRITE,
            FILE_OPEN,
            FILE_WRITE_THROUGH,
            WINDOWS_SHARE,
        ) {
            Ok(old) => old,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return publish_new(parent, stage, name);
            }
            Err(error) => return Err(error),
        };
        if !has_one_link(&old)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret scrub target must have exactly one hard link",
            ));
        }
        let aside = temporary_name(name, "old");
        publish_new(parent, &old, &aside)?;
        if let Err(error) = publish_new(parent, stage, name) {
            let _ = publish_new(parent, &old, name);
            return Err(error);
        }
        let _ = overwrite_open_file_with_zeros(&mut old);
        let _ = delete_file(&old);
        Ok(())
    }

    pub(crate) fn remove_secret(parent: &File, name: &OsStr) -> io::Result<()> {
        let (mut file, scrub) = match open_child(
            parent,
            name,
            false,
            DELETE | FILE_GENERIC_WRITE,
            FILE_OPEN,
            FILE_WRITE_THROUGH,
            WINDOWS_SHARE,
        ) {
            Ok(file) => {
                let scrub = has_one_link(&file).unwrap_or(false);
                (file, scrub)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                match open_child(
                    parent,
                    name,
                    false,
                    DELETE,
                    FILE_OPEN,
                    FILE_WRITE_THROUGH,
                    WINDOWS_SHARE,
                ) {
                    Ok(file) => (file, false),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        let removed = delete_file(&file);
        if scrub {
            let _ = overwrite_open_file_with_zeros(&mut file);
        }
        match removed {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    fn has_one_link(file: &File) -> io::Result<bool> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: The file handle and writable output buffer live through the call.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.nNumberOfLinks == 1)
    }

    pub(crate) fn visit_entries<E: From<io::Error>>(
        parent: &File,
        mut visit: impl FnMut(&OsStr, bool) -> Result<(), E>,
    ) -> Result<(), E> {
        const NAME_OFFSET: usize = std::mem::offset_of!(FILE_DIRECTORY_INFORMATION, FileName);
        let mut buffer = [0u64; 512];
        let mut restart_scan = true;
        loop {
            let mut status = IO_STATUS_BLOCK::default();
            // SAFETY: The handle is synchronous and both output buffers live through the call.
            let code = unsafe {
                NtQueryDirectoryFile(
                    parent.as_raw_handle(),
                    null_mut(),
                    None,
                    null(),
                    &mut status,
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    FileDirectoryInformation,
                    false,
                    null(),
                    restart_scan,
                )
            };
            if code == STATUS_NO_MORE_FILES || code == STATUS_NO_SUCH_FILE {
                return Ok(());
            }
            check_status(code)?;
            restart_scan = false;
            let invalid = || {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Windows directory entry",
                )
            };
            let used = status.Information;
            let mut offset = 0;
            loop {
                if offset + NAME_OFFSET > used
                    || used > size_of_val(&buffer)
                    || !offset.is_multiple_of(align_of::<FILE_DIRECTORY_INFORMATION>())
                {
                    return Err(invalid().into());
                }
                // SAFETY: The buffer is aligned and the fixed fields are inside the returned extent.
                let record = unsafe {
                    buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_DIRECTORY_INFORMATION>()
                };
                let (next, attributes, name_bytes) = unsafe {
                    (
                        (*record).NextEntryOffset as usize,
                        (*record).FileAttributes,
                        (*record).FileNameLength as usize,
                    )
                };
                if !name_bytes.is_multiple_of(2)
                    || offset + NAME_OFFSET + name_bytes > used
                    || (next != 0 && (next < NAME_OFFSET + name_bytes || offset + next >= used))
                {
                    return Err(invalid().into());
                }
                // SAFETY: The name is a bounded, aligned sequence of UTF-16 code units in the buffer.
                let name = unsafe {
                    std::slice::from_raw_parts(
                        record.cast::<u8>().add(NAME_OFFSET).cast::<u16>(),
                        name_bytes / 2,
                    )
                };
                if name != [b'.' as u16] && name != [b'.' as u16, b'.' as u16] {
                    let regular =
                        attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0;
                    let mut ascii = [0; MAX_COMPONENT];
                    if name.len() <= ascii.len() && name.iter().all(|&unit| unit <= 0x7f) {
                        for (byte, &unit) in ascii.iter_mut().zip(name) {
                            *byte = unit as u8;
                        }
                        let name =
                            std::str::from_utf8(&ascii[..name.len()]).expect("ASCII filename");
                        visit(OsStr::new(name), regular)?;
                    } else {
                        visit(&OsString::from_wide(name), regular)?;
                    }
                }
                if next == 0 {
                    break;
                }
                offset += next;
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) use unsupported::*;

#[cfg(not(any(unix, windows)))]
mod unsupported {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "record storage requires Unix or Windows",
        ))
    }

    pub(crate) fn open_root(_: &Path) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn open_dir(_: &File, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn create_dir(_: &File, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn open_record(_: &File, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn create_stage(_: &File, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn sync(_: &File) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn replace(_: &File, _: &File, _: &OsStr, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn replace_secret(_: &File, _: &File, _: &OsStr, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn replace_existing_stage(_: &File, _: &OsStr, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn discard_stage(_: &File, _: &File, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn remove_secret(_: &File, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn visit_entries<E: From<io::Error>>(
        _: &File,
        _: impl FnMut(&OsStr, bool) -> Result<(), E>,
    ) -> Result<(), E> {
        unsupported().map_err(E::from)
    }
}
