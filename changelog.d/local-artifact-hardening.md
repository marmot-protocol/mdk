### Breaking changes

- `fs_private::create_dir_all_private` now routes Unix path creation through `prepare_directory_path`, refusing
  user-owned symlinked ancestors and world-writable aliases such as `/tmp` on macOS (allowing only trusted root-owned
  platform aliases) (mdk#3799).
- `marmot_account::AccountHome` now rejects Windows-reserved device names (`CON`, `CONIN$`, `CONOUT$`, `PRN`, `AUX`,
  `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, and superscript variants), leading/trailing spaces, trailing dots, and
  Windows-forbidden filename characters on newly created or imported account labels across all platforms (existing Unix
  account records remain readable, updatable, and removable), `AccountHome::account_dir` now panics on unsafe
  path-traversal labels (use `try_account_dir` for untrusted input), and local-file secret reads (`secret.json`) now
  refuse group/world/executable/special permission bits with `PermissionDenied` (fix with `chmod 600`) (mdk#3799).

### Added

- Added `fs_private::open_existing_regular_nofollow` to open existing regular files without following symlinks or
  blocking on FIFOs, `media_store::format::checked_file_bytes` for overflow-checked encrypted file-length calculation,
  and `marmot_account::AccountHome::try_account_dir` for fallible account-directory resolution (mdk#3799, mdk#2554).

### Fixed

- Hardened `media-store` local file handling and concurrency invariants (mdk#3799, mdk#2554): in-flight file tracking
  now uses per-file reference counts so concurrent readers and sweeps do not drop active leases prematurely, cached
  readers check a revocation generation before re-insertion and mark missing files lost on reopen without swallowing
  catalog errors, reopen and trim paths reject symlinks and non-regular files, writer buffers zeroize on drop and honor
  poisoned state on flush, catalog sweeps verify regular files and valid layout sizes, and file-length/offset math uses
  checked arithmetic.
- Hardened `marmot-account` account-wipe cleanup and local secret I/O (mdk#3799, mdk#819, mdk#2145): account removal
  now resolves shared-credential checks before the tombstone rename commit and unconditionally scrubs tombstoned local
  secret files and removes the tombstone directory post-commit before propagating any independent secret-store deletion
  error; Windows secret reads verify live handle linkage so scrubbed or moved-aside handles are rejected and retried;
  tombstone roots use owner-only permissions; local secret reads reject symlinks and oversized files; and zero-scrub
  overwrites use bounded fixed chunks.
- Hardened `fs-private` local directory, file, and Unix socket helpers (mdk#3799): directory and file opens pass
  `O_NONBLOCK`, private file helpers verify regular files and tighten permissions before truncating, and private Unix
  socket binds serialize staging within a process so concurrent same-PID binds cannot collide.
