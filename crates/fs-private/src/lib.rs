//! Restrictive-by-construction creation of local files, directories, and Unix
//! sockets.
//!
//! Every helper creates the artifact already at its target mode (`O_CREAT` +
//! mode, or a staging directory for sockets) so there is no window where it is
//! reachable at the process umask's default permissions. Post-create
//! tightening is only used belt-and-braces for artifacts that already existed.
//!
//! Mode application is Unix-only; on other platforms the helpers still create
//! the artifacts and the mode calls are no-ops.

use std::fs::OpenOptions;
use std::io;
use std::path::Path;

/// Owner-only mode for files holding private data.
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// Owner-only mode for directories holding private artifacts.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Highest meaningful permission value (`suid|sgid|sticky` + `rwxrwxrwx`).
const MAX_MODE: u32 = 0o7777;

/// Configure `options` to create files owner-only (0600). No-op off Unix.
pub fn set_private_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    #[cfg(not(unix))]
    {
        let _ = options;
    }
}

/// Create `path` and any missing ancestors as 0700 directories; tighten the
/// leaf to 0700 if it already existed.
pub fn create_dir_all_private(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIR_MODE);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    }
    Ok(())
}

/// Write `bytes` to `path`, creating the file 0600; tightens a pre-existing
/// file to 0600 before writing.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    set_private_file_mode(&mut options);
    let mut file = options.open(path)?;
    set_handle_private(&file)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Open `path` for appending, creating it 0600; tightens a pre-existing file
/// to 0600.
pub fn open_private_append(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    set_private_file_mode(&mut options);
    let file = options.open(path)?;
    set_handle_private(&file)?;
    Ok(file)
}

/// Create `path` 0600, failing with `AlreadyExists` if it exists.
pub fn create_new_private(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_mode(&mut options);
    options.open(path)
}

/// Ensure a file exists at `path` with mode 0600: created atomically at 0600
/// if missing, tightened to 0600 if pre-existing. Contents are untouched.
pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    set_private_file_mode(&mut options);
    let file = options.open(path)?;
    set_handle_private(&file)
}

/// Tighten an existing file at `path` to 0600; `Ok(())` when it does not
/// exist (for optional sidecars such as `-wal`/`-shm`).
pub fn tighten_existing_private_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Make a SQLite database owner-only before SQLite can create it at the
/// process umask: pre-create the main file 0600 (SQLite then copies its mode
/// onto the `-wal`/`-shm`/journal sidecars it creates) and tighten any
/// sidecars left behind by earlier permissive builds — SQLite does not
/// rewrite pre-existing sidecar modes when the main file's mode changes.
pub fn ensure_private_db_files(path: &Path) -> io::Result<()> {
    ensure_private_file(path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        tighten_existing_private_file(Path::new(&sidecar))?;
    }
    Ok(())
}

fn set_handle_private(file: &std::fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

/// The workspace's one octal permission-mode parser.
///
/// Accepts an optional `0o` prefix followed by octal digits, parsed
/// whole-string in radix 8 (so `0600`, `00600`, `600`, and `0o600` all yield
/// `0o600`, and `0` yields mode 0 — rejecting useless-but-valid modes is the
/// caller's policy). Values above `0o7777`, empty input, and non-octal digits
/// are errors.
pub fn parse_octal_mode(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() && byte < b'8')
    {
        return Err(format!(
            "expected octal digits (e.g. 0600), got {trimmed:?}"
        ));
    }
    let mode = u32::from_str_radix(digits, 8)
        .map_err(|_| format!("octal mode out of range, got {trimmed:?}"))?;
    if mode > MAX_MODE {
        return Err(format!("octal mode out of range, got {trimmed:?}"));
    }
    Ok(mode)
}

/// The staging directory `bind_unix_listener_private` binds through for
/// `final_path`. Exposed so callers and tests can assert staging cleanup
/// without re-deriving the (otherwise private) naming scheme.
#[cfg(unix)]
pub fn socket_staging_dir(final_path: &Path) -> std::path::PathBuf {
    let parent = match final_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = final_path.file_name().unwrap_or_default();
    // Keyed by pid for crash recovery and by target name so concurrent binds
    // of different sockets in the same parent never share staging state.
    parent.join(format!(
        ".sock.{}.{}",
        std::process::id(),
        name.to_string_lossy()
    ))
}

/// Bind a Unix listener so the socket is never reachable at default
/// permissions: bind inside a fresh 0700 staging directory next to
/// `final_path`, chmod the socket to `mode`, then hard-link it into place
/// (failing with `AddrInUse` if `final_path` already exists, matching plain
/// `bind` semantics so callers keep their stale-socket recovery).
///
/// The staging directory name stays short (`.sock.<pid>.<name>`) to respect
/// `sun_path` length limits.
#[cfg(unix)]
pub fn bind_unix_listener_private(
    final_path: &Path,
    mode: u32,
) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;

    let name = final_path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket path has no file name")
    })?;
    let staging_dir = socket_staging_dir(final_path);
    // A leftover staging dir can only be ours (pid-suffixed, 0700) from a
    // crashed previous run; clear it so the atomic 0700 create succeeds.
    if staging_dir.symlink_metadata().is_ok() {
        std::fs::remove_dir_all(&staging_dir)?;
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(PRIVATE_DIR_MODE);
    builder.create(&staging_dir)?;

    let staged_socket = staging_dir.join(name);
    let outcome = (|| {
        let listener = std::os::unix::net::UnixListener::bind(&staged_socket)?;
        std::fs::set_permissions(&staged_socket, std::fs::Permissions::from_mode(mode))?;
        // link(2) fails if the target exists, unlike rename: preserves bind's
        // AddrInUse contract instead of silently replacing a live socket.
        std::fs::hard_link(&staged_socket, final_path).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{} already exists", final_path.display()),
                )
            } else {
                err
            }
        })?;
        Ok(listener)
    })();
    let _ = std::fs::remove_file(&staged_socket);
    let _ = std::fs::remove_dir(&staging_dir);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_octal_mode_accepts_0600_00600_600_and_0o600() {
        for input in ["0600", "00600", "600", "0o600", " 0600 "] {
            assert_eq!(parse_octal_mode(input), Ok(0o600), "input {input:?}");
        }
        assert_eq!(parse_octal_mode("0700"), Ok(0o700));
        assert_eq!(parse_octal_mode("7777"), Ok(0o7777));
    }

    #[test]
    fn parse_octal_mode_parses_bare_zero_to_mode_zero() {
        assert_eq!(parse_octal_mode("0"), Ok(0));
        assert_eq!(parse_octal_mode("00"), Ok(0));
    }

    #[test]
    fn parse_octal_mode_rejects_empty_non_octal_and_overlong() {
        for input in ["", "8", "abc", "077777", "0o", "6 00", "-600", "0x600"] {
            assert!(parse_octal_mode(input).is_err(), "input {input:?}");
        }
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn write_private_creates_file_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        write_private(&path, b"secret").unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn open_private_append_creates_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        drop(open_private_append(&path).unwrap());
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn create_new_private_creates_owner_only_and_rejects_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id");
        drop(create_new_private(&path).unwrap());
        assert_eq!(mode_of(&path), 0o600);
        let err = create_new_private(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn ensure_private_file_tightens_existing_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        std::fs::write(&path, b"data").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure_private_file(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"data", "contents untouched");
        let missing = dir.path().join("fresh.sqlite");
        ensure_private_file(&missing).unwrap();
        assert_eq!(mode_of(&missing), 0o600);
    }

    #[test]
    fn tighten_existing_private_file_ignores_missing_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite-wal");
        tighten_existing_private_file(&path).unwrap();
        std::fs::write(&path, b"wal").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        tighten_existing_private_file(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn ensure_private_db_files_tightens_main_db_and_stale_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cache.sqlite");
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.path().join(format!("cache.sqlite{suffix}"));
            std::fs::write(&path, b"x").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        ensure_private_db_files(&db).unwrap();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.path().join(format!("cache.sqlite{suffix}"));
            assert_eq!(mode_of(&path), 0o600, "suffix {suffix:?}");
        }
        // Missing sidecars are fine.
        let fresh = dir.path().join("fresh.sqlite");
        ensure_private_db_files(&fresh).unwrap();
        assert_eq!(mode_of(&fresh), 0o600);
    }

    #[test]
    fn create_dir_all_private_sets_0700() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b");
        create_dir_all_private(&path).unwrap();
        assert_eq!(mode_of(&path), 0o700);
        assert_eq!(mode_of(&dir.path().join("a")), 0o700);
    }

    #[test]
    fn bind_unix_listener_private_yields_0600_socket_and_no_staging_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let listener = bind_unix_listener_private(&socket, 0o600).unwrap();
        assert_eq!(mode_of(&socket), 0o600);
        assert!(
            !socket_staging_dir(&socket).exists(),
            "staging dir should be cleaned up"
        );
        // The listener must still accept connections at the final path.
        let client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        let (_server, _addr) = listener.accept().unwrap();
        drop(client);
    }

    #[test]
    fn bind_unix_listener_private_errors_addr_in_use_when_target_exists() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        std::fs::write(&socket, b"").unwrap();
        let err = bind_unix_listener_private(&socket, 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn bind_unix_listener_private_recovers_from_stale_staging_dir() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let staging = socket_staging_dir(&socket);
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("leftover"), b"x").unwrap();
        drop(bind_unix_listener_private(&socket, 0o600).unwrap());
        assert_eq!(mode_of(&socket), 0o600);
        assert!(!staging.exists());
    }

    #[test]
    fn concurrent_binds_in_same_parent_use_distinct_staging_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.sock");
        let second = dir.path().join("second.sock");
        assert_ne!(socket_staging_dir(&first), socket_staging_dir(&second));
        let first_listener = bind_unix_listener_private(&first, 0o600).unwrap();
        let second_listener = bind_unix_listener_private(&second, 0o600).unwrap();
        assert_eq!(mode_of(&first), 0o600);
        assert_eq!(mode_of(&second), 0o600);
        drop((first_listener, second_listener));
    }
}
