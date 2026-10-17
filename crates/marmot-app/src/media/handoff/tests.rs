use super::*;

#[test]
fn copies_are_named_after_the_attachment_safely_with_an_extension() {
    let apk = "application/vnd.android.package-archive";
    for (name, media_type, expected) in [
        ("photo.jpg", "image/jpeg", "photo.jpg"),
        ("installer", apk, "installer.apk"),
        ("../../etc/passwd", "text/plain", "passwd.txt"),
        ("C:\\Users\\me\\report.pdf", "application/pdf", "report.pdf"),
        ("..hidden.png", "image/png", "hidden.png"),
        ("...", "image/png", "attachment.png"),
        ("", "application/octet-stream", "attachment.bin"),
        ("tab\tand\nnewline.txt", "text/plain", "tabandnewline.txt"),
        ("a:b.mp4", "video/mp4", "ab.mp4"),
        ("voice", "audio/mp4; codecs=mp4a", "voice.m4a"),
        ("notes.", "text/plain", "notes.txt"),
    ] {
        assert_eq!(handoff_name(name, media_type), expected, "{name:?}");
    }
    let long = format!("{}.apk", "x".repeat(300));
    let named = handoff_name(&long, apk);
    assert!(named.len() <= MAX_NAME_BYTES);
    assert!(named.ends_with(".apk"));
    let wide = "é".repeat(200);
    let named = handoff_name(&wide, "image/png");
    assert!(
        named.len() <= MAX_NAME_BYTES,
        "the extension counts toward the cap"
    );
    assert!(named.ends_with(".png"));
    let bare = "y".repeat(300);
    assert_eq!(handoff_name(&bare, "image/png").len(), MAX_NAME_BYTES);
}

#[test]
fn release_accepts_unknown_leases_and_refuses_malformed_ones() {
    assert!(release(&"ab".repeat(16)).is_ok());
    assert!(release(&"AB".repeat(16)).is_ok());
    for malformed in [
        "",
        "zz",
        &"ab".repeat(17),
        &"g".repeat(32),
        "../escape/aaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(release(malformed).is_err(), "{malformed:?}");
    }
}

#[test]
fn the_wipe_removes_what_no_live_lease_holds() {
    let directory = tempfile::tempdir().unwrap();
    let live = "11".repeat(16);
    let live_directory = directory.path().join(&live);
    std::fs::create_dir_all(&live_directory).unwrap();
    std::fs::write(live_directory.join("kept.bin"), b"live").unwrap();
    lock_leases().insert(live.clone(), live_directory.clone());
    let stale = directory.path().join("22".repeat(16));
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("left.bin"), b"stale").unwrap();
    let stray = directory.path().join("stray");
    std::fs::write(&stray, b"stray").unwrap();
    assert_eq!(wipe_stale(directory.path()), 2);
    assert!(live_directory.join("kept.bin").exists());
    assert!(!stale.exists());
    assert!(!stray.exists());
    release(&live).unwrap();
    assert!(!live_directory.exists(), "release deletes the live copy");
    assert_eq!(wipe_stale(&directory.path().join("absent")), 0);
}

/// A copy that cannot be deleted fails its release and stays leased, so a
/// retry after the fault clears deletes it.
#[cfg(unix)]
#[test]
fn a_failed_release_stays_leased_for_a_retry() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let lease = "33".repeat(16);
    let copy = directory.path().join(&lease);
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::write(copy.join("held.bin"), b"plaintext").unwrap();
    lock_leases().insert(lease.clone(), copy.clone());
    let set_mode = |mode| {
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    // A read-only lease directory cannot have its file removed (unless this
    // test runs as root, which ignores permissions).
    set_mode(0o500);
    let enforced = std::fs::remove_file(copy.join("probe")).is_err()
        && std::fs::File::create(copy.join("probe")).is_err();
    if enforced {
        assert!(release(&lease).is_err());
        assert!(copy.join("held.bin").exists());
        assert_eq!(live_leases_under(directory.path()), 1, "still leased");
    }
    set_mode(0o700);
    release(&lease).unwrap();
    assert!(!copy.exists());
    assert_eq!(live_leases_under(directory.path()), 0);
}

thread_local! {
    static DISCARDED_HERE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Notes that a discard ran on this thread.
pub(super) fn record_discard_thread() {
    DISCARDED_HERE.with(|here| here.set(true));
}

/// A finished copy that never reached the host is discarded with its lease,
/// on the runtime's blocking pool even when it is dropped on another thread
/// (a host cancelling a finished call), never on the dropping thread.
#[test]
fn an_undelivered_copy_is_discarded_on_the_blocking_pool() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let lease = "44".repeat(16);
    let copy = directory.path().join(&lease);
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::write(copy.join("left.bin"), b"plaintext").unwrap();
    lock_leases().insert(lease.clone(), copy.clone());
    let handoff = AttachmentHandoff {
        lease: lease.clone(),
        path: copy.join("left.bin"),
        byte_count: 9,
        media_type: "application/octet-stream".into(),
        file_name: "left.bin".into(),
    };
    // Made on the blocking pool, as `open` does.
    let pending = runtime
        .block_on(runtime.spawn_blocking(move || PendingHandoff::new(handoff)))
        .unwrap();
    // Dropped on a plain host thread.
    std::thread::spawn(move || {
        drop(pending);
        assert!(
            !DISCARDED_HERE.with(std::cell::Cell::get),
            "the dropping thread does no file I/O"
        );
    })
    .join()
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while copy.exists() || live_leases_under(directory.path()) != 0 {
        assert!(std::time::Instant::now() < deadline, "discarded");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// A write that fills the volume is the storage-full error, as a known
/// shortfall is; other write failures are not.
#[test]
fn a_full_volume_during_the_copy_is_storage_full() {
    assert!(matches!(
        handoff_error(std::io::Error::from(std::io::ErrorKind::StorageFull)),
        AppError::Storage(cgka_traits::StorageError::Capacity(_))
    ));
    assert!(matches!(
        handoff_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        AppError::InvalidEncryptedMedia(_)
    ));
}
