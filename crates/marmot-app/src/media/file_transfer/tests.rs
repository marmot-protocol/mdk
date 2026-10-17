use super::*;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use std::io::SeekFrom;

fn fixture(directory: &Path, bytes: &[u8]) -> PrivateMediaFile {
    let mut file = PrivateMediaFile::create(directory).unwrap();
    file.file.write_all(bytes).unwrap();
    file.file.flush().unwrap();
    file.len = bytes.len() as u64;
    file.digest = Sha256::digest(bytes).into();
    file
}

/// The wire ciphertext of `source`, as an upload streams it, written to a
/// private file so the download side can be exercised against it.
fn encrypt_file(
    source: &PrivateMediaFile,
    directory: &Path,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    control: &MediaFileTransferControl,
) -> Result<PrivateMediaFile, AppError> {
    control.check()?;
    let mut reader = crate::media::outgoing::EncryptingReader::new(
        source.reader()?,
        source.len,
        key,
        nonce,
        aad,
    )?;
    let mut output = PrivateMediaFile::create(directory)?;
    output.len = std::io::copy(&mut reader, &mut output.file).map_err(staging_error)?;
    output.file.flush().map_err(staging_error)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut output.reader()?, &mut hash).map_err(staging_error)?;
    output.digest = hash.finalize().into();
    Ok(output)
}

/// What download and publication do in turn: authenticate into a discard
/// sink, then decrypt as the body is read (here into a file instead of the
/// media store).
fn decrypt_file(
    encrypted: &PrivateMediaFile,
    directory: &Path,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext_hash: [u8; 32],
    control: &MediaFileTransferControl,
) -> Result<PrivateMediaFile, AppError> {
    let mut input = encrypted.reader()?;
    decrypt_file_to_writer(
        &mut input,
        encrypted.len,
        encrypted.digest,
        key,
        nonce,
        aad,
        plaintext_hash,
        control,
        &mut std::io::sink(),
    )?;
    let mut reader = DecryptingReader::new(
        Box::new(encrypted.reader()?),
        encrypted.len,
        key,
        nonce,
        aad,
    )?;
    let mut output = PrivateMediaFile::create(directory)?;
    std::io::copy(&mut reader, &mut output.file).map_err(staging_error)?;
    output.file.flush().map_err(staging_error)?;
    output.len = output
        .file
        .as_file()
        .metadata()
        .map_err(staging_error)?
        .len();
    assert_eq!(output.len, encrypted.len - MEDIA_AEAD_TAG_BYTES);
    output.digest = plaintext_hash;
    Ok(output)
}

fn bytes(file: &PrivateMediaFile) -> Vec<u8> {
    let mut result = Vec::new();
    file.reader().unwrap().read_to_end(&mut result).unwrap();
    result
}

#[test]
fn streaming_wire_matches_existing_aead_across_chunk_boundaries_and_versions() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [9u8; 32];
    let nonce = [7u8; 12];
    for version in [
        super::super::EncryptedMediaVersion::V1,
        super::super::EncryptedMediaVersion::V2,
    ] {
        for len in [0, 1, 15, 16, 17, 65535, 65536, 65537, 131079] {
            let plain = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let digest = Sha256::digest(&plain).into();
            let key = super::super::crypto::derive_media_file_key(
                &secret,
                version,
                &digest,
                "application/octet-stream",
                "test.bin",
            )
            .unwrap();
            let aad = super::super::crypto::media_aad(
                version,
                &digest,
                "application/octet-stream",
                "test.bin",
            );
            let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            let expected = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &plain,
                        aad: &aad,
                    },
                )
                .unwrap();
            let source = fixture(directory.path(), &plain);
            let control = MediaFileTransferControl::default();
            let encrypted =
                encrypt_file(&source, directory.path(), &key, &nonce, &aad, &control).unwrap();
            assert_eq!(
                bytes(&encrypted),
                expected,
                "length {len}, version {version:?}"
            );
            assert_eq!(encrypted.len, len as u64 + 16);
            assert_eq!(
                encrypted.digest,
                <[u8; 32]>::from(Sha256::digest(&expected))
            );
            let decrypted = decrypt_file(
                &encrypted,
                directory.path(),
                &key,
                &nonce,
                &aad,
                digest,
                &control,
            )
            .unwrap();
            assert_eq!(bytes(&decrypted), plain);
        }
    }
}

#[test]
fn rejected_tag_never_returns_plaintext_and_cleans_private_partial() {
    let directory = tempfile::tempdir().unwrap();
    let source = fixture(directory.path(), b"sensitive test fixture");
    let key = [5u8; 32];
    let nonce = [8u8; 12];
    let control = MediaFileTransferControl::default();
    let mut encrypted = encrypt_file(
        &source,
        directory.path(),
        &key,
        &nonce,
        b"metadata",
        &control,
    )
    .unwrap();
    let last = *bytes(&encrypted).last().unwrap() ^ 1;
    encrypted.file.seek(SeekFrom::End(-1)).unwrap();
    encrypted.file.write_all(&[last]).unwrap();
    encrypted.file.flush().unwrap();
    // Rehash the corrupted bytes so the AEAD check, rather than the transport
    // hash check, is the boundary exercised here.
    encrypted.digest = Sha256::digest(bytes(&encrypted)).into();
    let before = std::fs::read_dir(directory.path()).unwrap().count();
    let plaintext_directory = directory.path().join("never-created-plaintext");
    let outcome = decrypt_file(
        &encrypted,
        &plaintext_directory,
        &key,
        &nonce,
        b"metadata",
        source.digest,
        &control,
    );
    assert!(outcome.is_err());
    assert!(
        !plaintext_directory.exists(),
        "rejected plaintext never reaches disk"
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), before);
}

#[test]
fn ciphertext_digest_plaintext_digest_and_length_are_verified_independently() {
    let directory = tempfile::tempdir().unwrap();
    let source = fixture(directory.path(), b"test payload");
    let key = [5u8; 32];
    let nonce = [8u8; 12];
    let control = MediaFileTransferControl::default();
    let mut encrypted = encrypt_file(
        &source,
        directory.path(),
        &key,
        &nonce,
        b"metadata",
        &control,
    )
    .unwrap();
    let plaintext_directory = directory.path().join("never-created-plaintext");
    assert!(
        decrypt_file(
            &encrypted,
            &plaintext_directory,
            &key,
            &nonce,
            b"metadata",
            [0; 32],
            &control
        )
        .is_err()
    );
    let digest = encrypted.digest;
    encrypted.digest = [0; 32];
    assert!(
        decrypt_file(
            &encrypted,
            &plaintext_directory,
            &key,
            &nonce,
            b"metadata",
            source.digest,
            &control
        )
        .is_err()
    );
    encrypted.digest = digest;
    encrypted.file.as_file().set_len(encrypted.len - 1).unwrap();
    assert!(
        decrypt_file(
            &encrypted,
            &plaintext_directory,
            &key,
            &nonce,
            b"metadata",
            source.digest,
            &control
        )
        .is_err()
    );
    assert!(
        !plaintext_directory.exists(),
        "failed hashes/length never create plaintext"
    );
}

#[test]
fn declared_batch_preflight_counts_every_aead_tag_before_preparation() {
    let item = |size| MediaFileUploadAttachmentRequest {
        source_path: "unused-private-source".into(),
        expected_size: size,
        file_name: "file.bin".into(),
        media_type: "application/octet-stream".into(),
        dim: None,
        thumbhash: None,
    };
    let mut request = MediaFileUploadRequest {
        attachments: vec![item(Some(MAX_FILE_MEDIA_CIPHERTEXT_BYTES / 2 - 16)); 2],
        caption: None,
        send: false,
        blossom_server: None,
        message_tags: vec![],
    };
    assert!(request.validate().is_ok());
    *request.attachments[1].expected_size.as_mut().unwrap() += 1;
    assert!(request.validate().is_err());
    request.attachments = vec![item(Some(MAX_FILE_MEDIA_CIPHERTEXT_BYTES - 16)), item(None)];
    assert!(
        request.validate().is_err(),
        "an unknown source still contributes an AEAD tag"
    );
}

#[test]
fn stale_snapshot_sweep_removes_only_old_private_snapshots() {
    let directory = tempfile::tempdir().unwrap();
    let fresh = PrivateMediaFile::create(directory.path()).unwrap();
    let stale = directory
        .path()
        .join(format!("{MEDIA_STAGING_PREFIX}stale"));
    std::fs::write(&stale, b"orphan").unwrap();
    let unrelated = directory.path().join("unrelated");
    std::fs::write(&unrelated, b"keep").unwrap();
    let old =
        std::time::SystemTime::now() - STALE_MEDIA_STAGING_AGE - std::time::Duration::from_secs(60);
    for path in [&stale, &unrelated] {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    assert_eq!(sweep_stale_media_staging(directory.path()), 1);
    assert!(!stale.exists());
    assert!(unrelated.exists());
    assert!(fresh.path().exists(), "a live snapshot is never swept");
    assert_eq!(
        sweep_stale_media_staging(&directory.path().join("absent")),
        0
    );
}

#[test]
#[ignore = "opt-in large-file bounded-memory measurement; no whole-file test allocation"]
fn generated_758_mb_streaming_crypto_roundtrip() {
    let directory = tempfile::tempdir().unwrap();
    let mut source = PrivateMediaFile::create(directory.path()).unwrap();
    source.file.as_file().set_len(758_000_000).unwrap();
    source.len = 758_000_000;
    let mut hash = Sha256::new();
    std::io::copy(&mut source.reader().unwrap(), &mut hash).unwrap();
    source.digest = hash.finalize().into();
    let control = MediaFileTransferControl::default();
    let encrypted = encrypt_file(
        &source,
        directory.path(),
        &[5; 32],
        &[8; 12],
        b"large",
        &control,
    )
    .unwrap();
    let decrypted = decrypt_file(
        &encrypted,
        directory.path(),
        &[5; 32],
        &[8; 12],
        b"large",
        source.digest,
        &control,
    )
    .unwrap();
    assert_eq!(decrypted.len, 758_000_000);
    assert_eq!(decrypted.digest, source.digest);
}
