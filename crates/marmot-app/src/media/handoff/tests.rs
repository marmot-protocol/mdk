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
    assert!(named.len() <= MAX_NAME_BYTES + ".png".len());
    assert!(named.ends_with(".png"));
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
