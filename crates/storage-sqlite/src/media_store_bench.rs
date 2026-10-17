//! Step-0 benchmark for mdk#2314: the local media file format against the
//! current SQLCipher retained-attachment path, on the machine it runs on.
//!
//! Every row is one `MDK_BENCH media_store ...` line. Rows per body size:
//!
//! - `seal` / `open`: the format in memory. This isolates the cipher from
//!   storage.
//! - `file_write`: plaintext from memory in 1 MiB host writes, sealed into a
//!   private temp file, `sync_all`, renamed, then the directory synced. On
//!   Apple platforms `sync_all` is `F_FULLFSYNC`, which SQLite does not use by
//!   default, so Apple targets add `file_write_fsync` with plain `fsync`: the
//!   durability SQLite's WAL commits get under `synchronous=FULL`.
//! - `file_write_direct`: the same body written straight to its final name and
//!   only the file synced (plain `fsync` on Apple): no rename, no directory
//!   sync. This prices relying on the `pending` row instead of a rename.
//!
//! The `file_write*` rows are file I/O only: creation, sealing and syncs. The
//! store's `pending` insert and `ready` commit, which a publication adds, are
//! not included, whereas `sqlcipher_write*` rows are a whole publication.
//! - `file_read`: a fresh handle reading the whole body in 1 MiB windows,
//!   the `read_attachment_asset` window size.
//! - `file_first_read`: a fresh handle reading the first window only, timed
//!   before any full read of that file. Its throughput counts one window.
//! - `sqlcipher_write`: today's import, `complete_attachment_acquisition_from_reader`
//!   (and `complete_attachment_acquisition` for bodies up to 16 MiB, the
//!   in-memory download path) into an encrypted account database.
//! - `sqlcipher_read` / `sqlcipher_first_read`: `read_retained_attachment` in
//!   1 MiB windows; the first-read row reopens the database first so its page
//!   cache is cold, and runs before any full read.
//!
//! Each row discards one untimed warmup iteration.
//!
//! The OS page cache stays warm in every row: unprivileged processes cannot
//! drop it on iOS or Android. First-read rows therefore measure decryption and
//! lookup cost, not flash latency, for both layouts alike.

use std::fs::File;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::{
    AttachmentAssetRef, AttachmentDemand, AttachmentHistoryEntry, AttachmentPublishResult,
    MAX_ATTACHMENT_LOCAL_READ_BYTES, SqlCipherKey, SqliteAccountStorage, StoredAppEvent,
};
use media_store::format::{
    FILE_ID_BYTES, FILE_KEY_BYTES, FileKey, MediaFileReader, MediaFileWriter,
};

/// Row label for the file format's cipher.
const BACKEND: &str = "openssl";
const WINDOW: usize = MAX_ATTACHMENT_LOCAL_READ_BYTES;
const GROUP: &str = "abababababababababababababababab";
const NOW: u64 = 1_000;
const LEASE_UNTIL: u64 = 1_000_000_000;
const MEMORY_PATH_LIMIT: usize = 16 * 1024 * 1024;
const LARGE_BODY: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct MediaStoreBenchConfig {
    /// Plaintext body sizes in bytes.
    pub sizes: Vec<usize>,
    /// Timed repetitions per row for bodies under 32 MiB.
    pub iterations: usize,
    /// Timed repetitions per row for bodies of 32 MiB or more.
    pub large_iterations: usize,
}

impl Default for MediaStoreBenchConfig {
    fn default() -> Self {
        Self {
            sizes: vec![64 * 1024, 1024 * 1024, 100 * 1024 * 1024],
            iterations: 7,
            large_iterations: 3,
        }
    }
}

/// Runs every row under `dir` (created if missing, emptied of its own files
/// afterwards) and passes each `MDK_BENCH` line to `emit`.
pub fn run_media_store_benchmark(
    dir: &Path,
    config: &MediaStoreBenchConfig,
    emit: &mut dyn FnMut(String),
) -> Result<(), String> {
    fs_private::create_dir_all_private(dir).map_err(error)?;
    emit(format!(
        "MDK_BENCH media_store_env arch={} os={} segment_bytes={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        media_store::format::SEGMENT_PLAINTEXT_BYTES,
    ));
    for &size in &config.sizes {
        let iterations = if size >= LARGE_BODY {
            config.large_iterations
        } else {
            config.iterations
        }
        .max(1);
        let body = body(size);
        format_rows(&body, iterations, emit)?;
        file_rows(dir, &body, iterations, emit)?;
        sqlcipher_rows(dir, &body, iterations, emit)?;
    }
    Ok(())
}

fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Incompressible, deterministic plaintext.
fn body(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn key() -> FileKey {
    FileKey::from_bytes([0x5a; FILE_KEY_BYTES])
}

fn file_id(counter: usize) -> [u8; FILE_ID_BYTES] {
    let mut id = [0; FILE_ID_BYTES];
    id[..8].copy_from_slice(&(counter as u64).to_be_bytes());
    id
}

fn row(
    case: &str,
    backend: &str,
    size: usize,
    samples: &mut [Duration],
    emit: &mut dyn FnMut(String),
) {
    samples.sort();
    let median = samples[samples.len() / 2];
    let min = samples[0];
    // First-window rows move one window, whatever the body size.
    let moved = if case.ends_with("first_read") {
        size.min(WINDOW)
    } else {
        size
    };
    let mib_per_s = moved as f64 / (1024.0 * 1024.0) / median.as_secs_f64().max(1e-9);
    emit(format!(
        "MDK_BENCH media_store case={case} backend={backend} bytes={size} iterations={} median_us={} min_us={} mib_per_s={mib_per_s:.1}",
        samples.len(),
        median.as_micros(),
        min.as_micros(),
    ));
}

fn timed<T>(f: impl FnOnce() -> Result<T, String>) -> Result<(Duration, T), String> {
    let started = Instant::now();
    let value = f()?;
    Ok((started.elapsed(), value))
}

fn format_rows(body: &[u8], iterations: usize, emit: &mut dyn FnMut(String)) -> Result<(), String> {
    let id = file_id(0);
    let mut seal = Vec::new();
    let mut open = Vec::new();
    for iteration in 0..=iterations {
        let (elapsed, sealed) = timed(|| {
            let mut writer = MediaFileWriter::new(
                Vec::with_capacity(body.len() + body.len() / 4096 + 64),
                &key(),
                &id,
            )
            .map_err(error)?;
            writer.write_all(body).map_err(error)?;
            writer.finish().map_err(error)
        })?;
        let warm = iteration > 0;
        if warm {
            seal.push(elapsed);
        }
        let mut plaintext = vec![0; body.len()];
        let (elapsed, ()) = timed(|| {
            let mut reader =
                MediaFileReader::open(Cursor::new(&sealed), &key(), &id).map_err(error)?;
            reader.read_at(0, &mut plaintext).map_err(error)?;
            Ok(())
        })?;
        if plaintext != body {
            return Err("in-memory round trip mismatch".into());
        }
        if warm {
            open.push(elapsed);
        }
    }
    row("seal", BACKEND, body.len(), &mut seal, emit);
    row("open", BACKEND, body.len(), &mut open, emit);
    Ok(())
}

fn read_whole_file(path: &Path, id: &[u8; FILE_ID_BYTES]) -> Result<u64, String> {
    let mut reader =
        MediaFileReader::open(File::open(path).map_err(error)?, &key(), id).map_err(error)?;
    let mut window = vec![0; WINDOW];
    let mut offset = 0;
    loop {
        let read = reader.read_at(offset, &mut window).map_err(error)?;
        if read == 0 {
            return Ok(offset);
        }
        offset += read as u64;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SyncKind {
    /// `File::sync_all`: `F_FULLFSYNC` on Apple platforms, `fsync` elsewhere.
    All,
    /// Plain `fsync`, SQLite's default on Apple platforms.
    #[cfg(target_vendor = "apple")]
    Fsync,
}

impl SyncKind {
    /// The cheapest sync with SQLite's default durability on this platform.
    #[cfg(target_vendor = "apple")]
    const SQLITE: Self = Self::Fsync;
    #[cfg(not(target_vendor = "apple"))]
    const SQLITE: Self = Self::All;

    fn run(self, file: &File) -> Result<(), String> {
        match self {
            Self::All => file.sync_all().map_err(error),
            #[cfg(target_vendor = "apple")]
            Self::Fsync => {
                use std::os::fd::AsRawFd;
                // SAFETY: `file` owns a valid open descriptor for the call.
                if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
                    Ok(())
                } else {
                    Err(error(std::io::Error::last_os_error()))
                }
            }
        }
    }
}

/// How a timed write publishes its file.
#[derive(Clone, Copy, PartialEq, Eq)]
struct WriteMode {
    case: &'static str,
    sync: SyncKind,
    /// Write `<id>.tmp`, sync it, rename to `<id>` and sync the directory;
    /// otherwise write `<id>` directly and sync only the file.
    rename: bool,
}

const WRITE_MODES: &[WriteMode] = &[
    WriteMode {
        case: "file_write",
        sync: SyncKind::All,
        rename: true,
    },
    #[cfg(target_vendor = "apple")]
    WriteMode {
        case: "file_write_fsync",
        sync: SyncKind::Fsync,
        rename: true,
    },
    WriteMode {
        case: "file_write_direct",
        sync: SyncKind::SQLITE,
        rename: false,
    },
];

fn file_rows(
    dir: &Path,
    body: &[u8],
    iterations: usize,
    emit: &mut dyn FnMut(String),
) -> Result<(), String> {
    let media = dir.join("media");
    fs_private::create_dir_all_private(&media).map_err(error)?;
    let (mut read, mut first) = (Vec::new(), Vec::new());
    for &mode in WRITE_MODES {
        let mut write = Vec::new();
        for iteration in 0..=iterations {
            let warm = iteration > 0;
            let id = file_id(iteration);
            let final_path = media.join(hex::encode(id));
            let temp_path = media.join(format!("{}.tmp", hex::encode(id)));
            let (elapsed, ()) = timed(|| {
                let target = if mode.rename { &temp_path } else { &final_path };
                let file = fs_private::create_new_private(target).map_err(error)?;
                let mut writer = MediaFileWriter::new(file, &key(), &id).map_err(error)?;
                for chunk in body.chunks(WINDOW) {
                    writer.write_all(chunk).map_err(error)?;
                }
                mode.sync.run(&writer.finish().map_err(error)?)?;
                if mode.rename {
                    std::fs::rename(&temp_path, &final_path).map_err(error)?;
                    mode.sync.run(&File::open(&media).map_err(error)?)?;
                }
                Ok(())
            })?;
            if warm {
                write.push(elapsed);
            }
            if mode == WRITE_MODES[0] {
                // The first window is timed before any full read of the file.
                let mut window = vec![0; WINDOW.min(body.len()).max(1)];
                let (first_elapsed, ()) = timed(|| {
                    let file = File::open(&final_path).map_err(error)?;
                    let mut reader = MediaFileReader::open(file, &key(), &id).map_err(error)?;
                    reader.read_at(0, &mut window).map_err(error)?;
                    Ok(())
                })?;
                let (elapsed, len) = timed(|| read_whole_file(&final_path, &id))?;
                if len != body.len() as u64 {
                    return Err("file read length mismatch".into());
                }
                if warm {
                    read.push(elapsed);
                    first.push(first_elapsed);
                } else {
                    let on_disk = std::fs::metadata(&final_path).map_err(error)?.len();
                    emit(format!(
                        "MDK_BENCH media_store_footprint layout=file backend={} bytes={} disk_bytes={on_disk}",
                        BACKEND,
                        body.len()
                    ));
                }
            }
            std::fs::remove_file(&final_path).map_err(error)?;
        }
        row(mode.case, BACKEND, body.len(), &mut write, emit);
    }
    row("file_read", BACKEND, body.len(), &mut read, emit);
    row("file_first_read", BACKEND, body.len(), &mut first, emit);
    Ok(())
}

struct SqlcipherBench {
    path: PathBuf,
    key: SqlCipherKey,
    store: SqliteAccountStorage,
    digest: [u8; 32],
    messages: usize,
}

impl SqlcipherBench {
    fn open(dir: &Path, body: &[u8]) -> Result<Self, String> {
        let path = dir.join("bench-account.sqlite");
        remove_database(&path)?;
        let key = SqlCipherKey::new(hex::encode([0x6b; 32])).map_err(error)?;
        let store = SqliteAccountStorage::open_encrypted(&path, &key).map_err(error)?;
        store
            .lock()
            .map_err(error)?
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
                [GROUP],
            )
            .map_err(error)?;
        Ok(Self {
            path,
            key,
            store,
            digest: Sha256::digest(body).into(),
            messages: 0,
        })
    }

    fn reopen(&mut self) -> Result<(), String> {
        self.store.close().map_err(error)?;
        self.store = SqliteAccountStorage::open_encrypted(&self.path, &self.key).map_err(error)?;
        Ok(())
    }

    /// Records a fresh message with one attachment and claims its download.
    fn claimed_job(&mut self) -> Result<crate::AttachmentAcquisition, String> {
        self.messages += 1;
        let message = format!("{:064x}", self.messages);
        let slot = vec![
            "imeta".to_owned(),
            "m application/octet-stream".to_owned(),
            format!("x {}", hex::encode(self.digest)),
        ];
        self.store
            .app_storage()
            .record_app_event(&StoredAppEvent {
                group_id_hex: GROUP.into(),
                message_id_hex: message.clone(),
                source_message_id_hex: Some(message.clone()),
                source_epoch: Some(1),
                direction: "received".into(),
                sender: "author".into(),
                plaintext: String::new(),
                kind: 9,
                tags: vec![slot.clone()],
                recorded_at: NOW,
                received_at: NOW,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .map_err(error)?;
        let selected = AttachmentHistoryEntry {
            emoji_tags: Vec::new(),
            message_id_hex: message.clone(),
            attachment_index: 0,
            source_message_id_hex: message,
            source_epoch: Some(1),
            sender: "author".into(),
            timeline_at: NOW,
            received_at: NOW,
            slot: serde_json::to_value(&slot).map_err(error)?,
        };
        let reference = match self
            .store
            .app_storage()
            .request_attachment_acquisition(GROUP, &selected, self.digest, NOW)
            .map_err(error)?
        {
            AttachmentDemand::Requested(reference) => reference,
            other => return Err(format!("unexpected attachment demand {other:?}")),
        };
        self.store
            .app_storage()
            .claim_attachment_acquisition(&reference, NOW, LEASE_UNTIL)
            .map_err(error)?
            .ok_or_else(|| "attachment job was not claimable".to_owned())
    }

    fn read_whole(&self, reference: &AttachmentAssetRef, len: usize) -> Result<(), String> {
        let mut offset = 0;
        while offset < len {
            let window = self
                .store
                .app_storage()
                .read_retained_attachment(reference, NOW, offset as u64, WINDOW)
                .map_err(error)?
                .ok_or_else(|| "retained attachment missing".to_owned())?;
            offset += window.len();
        }
        Ok(())
    }
}

fn remove_database(path: &Path) -> Result<(), String> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        match std::fs::remove_file(PathBuf::from(sidecar)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(error(e)),
        }
    }
    Ok(())
}

fn database_bytes(path: &Path) -> u64 {
    ["", "-wal", "-shm"]
        .iter()
        .filter_map(|suffix| {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            std::fs::metadata(PathBuf::from(sidecar)).ok()
        })
        .map(|metadata| metadata.len())
        .sum()
}

fn sqlcipher_rows(
    dir: &Path,
    body: &[u8],
    iterations: usize,
    emit: &mut dyn FnMut(String),
) -> Result<(), String> {
    let mut bench = SqlcipherBench::open(dir, body)?;
    let empty = database_bytes(&bench.path);
    let (mut write, mut memory_write, mut read, mut first) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut stored = Vec::new();
    for iteration in 0..=iterations {
        let warm = iteration > 0;
        let job = bench.claimed_job()?;
        let (elapsed, published) = timed(|| {
            bench
                .store
                .app_storage()
                .complete_attachment_acquisition_from_reader(
                    &job,
                    &mut Cursor::new(body),
                    body.len() as u64,
                    NOW,
                    i64::MAX as u64,
                    &|| false,
                )
                .map_err(error)
        })?;
        if published != AttachmentPublishResult::Published {
            return Err(format!("import was not published: {published:?}"));
        }
        if warm {
            write.push(elapsed);
            stored.push(job.reference);
        }
        if body.len() <= MEMORY_PATH_LIMIT {
            let job = bench.claimed_job()?;
            let (elapsed, published) = timed(|| {
                bench
                    .store
                    .app_storage()
                    .complete_attachment_acquisition(&job, body, NOW, i64::MAX as u64)
                    .map_err(error)
            })?;
            if published != AttachmentPublishResult::Published {
                return Err(format!("memory publish was not published: {published:?}"));
            }
            if warm {
                memory_write.push(elapsed);
            }
        }
    }
    emit(format!(
        "MDK_BENCH media_store_footprint layout=sqlcipher bodies={} bytes={} disk_bytes={}",
        bench.messages,
        body.len(),
        database_bytes(&bench.path).saturating_sub(empty)
    ));
    // First windows are timed before any full read, each after a reopen.
    for reference in &stored {
        bench.reopen()?;
        let (elapsed, ()) = timed(|| {
            bench
                .store
                .app_storage()
                .read_retained_attachment(reference, NOW, 0, WINDOW)
                .map_err(error)?
                .ok_or_else(|| "retained attachment missing".to_owned())
                .map(drop)
        })?;
        first.push(elapsed);
    }
    for reference in &stored {
        let (elapsed, ()) = timed(|| bench.read_whole(reference, body.len()))?;
        read.push(elapsed);
    }
    bench.store.close().map_err(error)?;
    remove_database(&bench.path)?;
    row("sqlcipher_write", "sqlcipher", body.len(), &mut write, emit);
    if !memory_write.is_empty() {
        row(
            "sqlcipher_write_memory",
            "sqlcipher",
            body.len(),
            &mut memory_write,
            emit,
        );
    }
    row("sqlcipher_read", "sqlcipher", body.len(), &mut read, emit);
    row(
        "sqlcipher_first_read",
        "sqlcipher",
        body.len(),
        &mut first,
        emit,
    );
    Ok(())
}
