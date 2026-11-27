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
  secret files and removes the tombstone directory after commit even when an independent secret store fails; Windows
  secret reads verify live handle linkage so scrubbed or moved-aside handles are rejected and retried; tombstone roots
  use owner-only permissions; local secret reads reject symlinks, oversized files, and group/world/executable/special
  permission bits (`PermissionDenied`) rather than reading permissive key files; zero-scrub overwrites use bounded
  fixed chunks; newly created or imported account labels reject unsafe or Windows-reserved names while keeping existing
  Unix account records readable, updatable, and removable; and `AccountHome::account_dir` now panics on unsafe
  path-traversal labels (callers with untrusted input should use `try_account_dir`).
- Hardened `fs-private` local directory, file, and Unix socket helpers (mdk#3799): private directory creation walks
  components without following intermediate symlinks (refusing user-owned symlinked ancestors and allowing only trusted
  root-owned platform aliases, matching `prepare_directory_path`) and uses non-blocking directory opens, private file
  helpers verify regular files and tighten permissions before truncating, and private Unix socket staging uses recycled
  per-thread staging directories so concurrent binds within one process do not collide or grow `sun_path` lengths over
  thread churn.
