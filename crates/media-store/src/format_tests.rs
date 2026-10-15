use std::io::{Cursor, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::format::*;

const FILE_ID: [u8; FILE_ID_BYTES] = [7; FILE_ID_BYTES];
const OTHER_ID: [u8; FILE_ID_BYTES] = [8; FILE_ID_BYTES];
const SEGMENT: usize = SEGMENT_PLAINTEXT_BYTES;

fn key() -> FileKey {
    FileKey::from_bytes([0x42; FILE_KEY_BYTES])
}

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + i / 251) as u8).collect()
}

fn seal(body: &[u8], backend: CipherBackend) -> Vec<u8> {
    let mut writer = MediaFileWriter::new(Vec::new(), &key(), &FILE_ID, backend).unwrap();
    // Uneven writes cross segment boundaries mid-call.
    for chunk in body.chunks(10_007) {
        writer.write_all(chunk).unwrap();
    }
    assert_eq!(writer.plaintext_bytes(), body.len() as u64);
    writer.finish().unwrap()
}

fn open_reader(
    file: Vec<u8>,
    backend: CipherBackend,
) -> MediaFormatResult<MediaFileReader<Cursor<Vec<u8>>>> {
    MediaFileReader::open(Cursor::new(file), &key(), &FILE_ID, backend)
}

fn open_all(file: Vec<u8>, backend: CipherBackend) -> MediaFormatResult<Vec<u8>> {
    let mut reader = open_reader(file, backend)?;
    let mut out = vec![0; reader.plaintext_bytes() as usize];
    assert_eq!(reader.read_at(0, &mut out)?, out.len());
    Ok(out)
}

struct AgeVector {
    name: String,
    expect_success: bool,
    payload_sha256: Option<String>,
    file_key: Vec<u8>,
    /// Everything after the header's MAC line: 16-byte nonce, then payload.
    body: Vec<u8>,
}

fn parse_age_vector(path: &Path) -> AgeVector {
    let raw = std::fs::read(path).unwrap();
    let split = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .expect("vector metadata ends with a blank line");
    let metadata = std::str::from_utf8(&raw[..split]).unwrap();
    let mut file = raw[split + 2..].to_vec();
    let field = |name: &str| {
        metadata
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(str::to_owned)
    };
    if field("compressed").as_deref() == Some("zlib") {
        let mut inflated = Vec::new();
        flate2::read::ZlibDecoder::new(file.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        file = inflated;
    }
    // The header ends with the line "--- <mac>\n"; stanza lines never start
    // with "---", so the first such line is the MAC line.
    let mac = file
        .windows(5)
        .position(|w| w == b"\n--- ")
        .expect("age header has a MAC line")
        + 1;
    let end = mac + file[mac..].iter().position(|b| *b == b'\n').unwrap() + 1;
    let expect = field("expect").unwrap();
    AgeVector {
        name: path.file_name().unwrap().to_string_lossy().into_owned(),
        expect_success: match expect.as_str() {
            "success" => true,
            "payload failure" => false,
            other => panic!("unexpected vector class {other}"),
        },
        payload_sha256: field("payload"),
        file_key: hex::decode(field("file key").unwrap()).unwrap(),
        body: file[end..].to_vec(),
    }
}

fn age_vectors() -> Vec<AgeVector> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/age");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_none())
        .collect();
    paths.sort();
    paths.iter().map(|path| parse_age_vector(path)).collect()
}

/// The C2SP CCTV age vectors whose outcome depends only on the payload: the
/// payload key is HKDF(file key, nonce, "payload"), the same derivation local
/// files use with the header as salt. Successful payloads must also reseal to
/// the identical ciphertext, which checks the writer's segmenting.
#[test]
fn age_payload_vectors_open_and_reseal_identically() {
    let vectors = age_vectors();
    let successes = vectors.iter().filter(|v| v.expect_success).count();
    assert!(
        successes >= 19 && vectors.len() - successes >= 18,
        "vector set shrank"
    );
    for backend in CipherBackend::ALL {
        for vector in &vectors {
            let name = &vector.name;
            let opened = (vector.body.len() >= 16).then(|| {
                let (nonce, payload) = vector.body.split_at(16);
                let key = PayloadKey::derive(&vector.file_key, nonce);
                (open_payload(&key, payload, backend), key, payload)
            });
            match (vector.expect_success, opened) {
                (true, Some((Ok(plaintext), key, payload))) => {
                    assert_eq!(
                        Some(hex::encode(Sha256::digest(&plaintext))),
                        vector.payload_sha256,
                        "{name} {backend:?}"
                    );
                    let mut writer =
                        MediaFileWriter::with_payload_key(Vec::new(), &key, backend).unwrap();
                    writer.write_all(&plaintext).unwrap();
                    assert_eq!(
                        writer.finish().unwrap(),
                        payload,
                        "{name} {backend:?} reseal"
                    );
                }
                (false, None) | (false, Some((Err(_), _, _))) => {}
                (expected, opened) => panic!(
                    "{name} {backend:?}: expected success={expected}, opened={:?}",
                    opened.map(|(result, _, _)| result.map(|p| p.len()))
                ),
            }
        }
    }
}

#[test]
fn round_trips_at_segment_boundaries_across_backends() {
    for len in [
        0,
        1,
        SEGMENT - 1,
        SEGMENT,
        SEGMENT + 1,
        2 * SEGMENT,
        3 * SEGMENT + 5,
    ] {
        let body = plaintext(len);
        let rust = seal(&body, CipherBackend::RustCrypto);
        let openssl = seal(&body, CipherBackend::OpenSsl);
        assert_eq!(
            rust, openssl,
            "backends must produce identical files at {len}"
        );
        let segments = len.div_ceil(SEGMENT).max(1);
        assert_eq!(
            rust.len(),
            HEADER_BYTES + len + segments * TAG_BYTES,
            "{len}"
        );
        for backend in CipherBackend::ALL {
            assert_eq!(open_all(rust.clone(), backend).unwrap(), body, "{len}");
        }
    }
}

#[test]
fn header_binds_magic_version_and_file_id() {
    let file = seal(b"body", CipherBackend::RustCrypto);
    assert_eq!(file[..HEADER_BYTES], header_bytes(&FILE_ID));
    assert!(matches!(
        MediaFileReader::open(
            Cursor::new(file.clone()),
            &key(),
            &OTHER_ID,
            CipherBackend::RustCrypto
        ),
        Err(MediaFormatError::FileIdMismatch)
    ));
    let mut wrong_magic = file.clone();
    wrong_magic[0] ^= 1;
    assert!(matches!(
        open_reader(wrong_magic, CipherBackend::RustCrypto),
        Err(MediaFormatError::InvalidHeader)
    ));
    let mut wrong_version = file.clone();
    wrong_version[8] = FORMAT_VERSION + 1;
    assert!(matches!(
        open_reader(wrong_version, CipherBackend::RustCrypto),
        Err(MediaFormatError::UnsupportedVersion)
    ));
    assert!(matches!(
        open_reader(file[..HEADER_BYTES - 1].to_vec(), CipherBackend::RustCrypto),
        Err(MediaFormatError::InvalidHeader)
    ));
    assert!(matches!(
        open_reader(file[..HEADER_BYTES].to_vec(), CipherBackend::RustCrypto),
        Err(MediaFormatError::InvalidLength)
    ));

    // Rewriting the file id in the header changes the payload key too, so a
    // file cannot be passed off as another row's even with the header fixed up.
    let mut relabelled = file;
    relabelled[9..HEADER_BYTES].copy_from_slice(&OTHER_ID);
    let mut reader = MediaFileReader::open(
        Cursor::new(relabelled),
        &key(),
        &OTHER_ID,
        CipherBackend::RustCrypto,
    )
    .unwrap();
    assert!(matches!(
        reader.read_at(0, &mut [0; 4]),
        Err(MediaFormatError::Authentication)
    ));
}

#[test]
fn offset_reads_span_segments_and_stop_at_the_end() {
    let body = plaintext(3 * SEGMENT + 123);
    let file = seal(&body, CipherBackend::OpenSsl);
    for backend in CipherBackend::ALL {
        let mut reader = open_reader(file.clone(), backend).unwrap();
        assert_eq!(reader.plaintext_bytes(), body.len() as u64);
        for (offset, len) in [
            (0, 10),
            (SEGMENT - 3, 7),
            (SEGMENT, SEGMENT),
            (2 * SEGMENT + 9, 2 * SEGMENT),
            (body.len() - 1, 5),
        ] {
            let mut out = vec![0; len];
            let read = reader.read_at(offset as u64, &mut out).unwrap();
            let expected = &body[offset..(offset + len).min(body.len())];
            assert_eq!(&out[..read], expected, "{offset}+{len}");
        }
        assert_eq!(reader.read_at(body.len() as u64, &mut [0; 8]).unwrap(), 0);
        let mut streamed = Vec::new();
        reader.read_to_end(&mut streamed).unwrap();
        assert_eq!(streamed, body);
    }
}

#[test]
fn tampering_truncation_extension_and_wrong_keys_fail_closed() {
    let body = plaintext(3 * SEGMENT + 123);
    let file = seal(&body, CipherBackend::RustCrypto);
    for backend in CipherBackend::ALL {
        // A flipped byte fails its own segment only.
        let mut flipped = file.clone();
        flipped[HEADER_BYTES + SEGMENT_CIPHERTEXT_BYTES + 5] ^= 1;
        let mut reader = open_reader(flipped, backend).unwrap();
        assert_eq!(reader.read_at(0, &mut [0; 16]).unwrap(), 16);
        assert!(matches!(
            reader.read_at(SEGMENT as u64, &mut [0; 16]),
            Err(MediaFormatError::Authentication)
        ));
        assert!(matches!(
            reader.read_at(0, &mut vec![0; body.len()]),
            Err(MediaFormatError::Authentication)
        ));

        // Truncating at a segment boundary makes a non-final segment last.
        let truncated = file[..HEADER_BYTES + 2 * SEGMENT_CIPHERTEXT_BYTES].to_vec();
        let mut reader = open_reader(truncated, backend).unwrap();
        assert!(matches!(
            reader.read_at(SEGMENT as u64, &mut [0; 1]),
            Err(MediaFormatError::Authentication)
        ));

        let mut extended = file.clone();
        extended.push(0);
        assert!(open_all(extended, backend).is_err());

        let other_key = FileKey::from_bytes([0x43; FILE_KEY_BYTES]);
        let mut reader =
            MediaFileReader::open(Cursor::new(file.clone()), &other_key, &FILE_ID, backend)
                .unwrap();
        assert!(matches!(
            reader.read_at(0, &mut [0; 1]),
            Err(MediaFormatError::Authentication)
        ));
    }
}

#[test]
fn empty_and_whole_segment_plaintexts_have_one_final_segment() {
    for backend in CipherBackend::ALL {
        let empty = seal(&[], backend);
        assert_eq!(empty.len(), HEADER_BYTES + TAG_BYTES);
        let mut reader = open_reader(empty.clone(), backend).unwrap();
        assert_eq!(reader.read_at(0, &mut [0; 4]).unwrap(), 0);
        let mut forged = empty;
        forged[HEADER_BYTES] ^= 1;
        let mut reader = open_reader(forged, backend).unwrap();
        assert!(
            reader.read_at(0, &mut [0; 4]).is_err(),
            "empty plaintext is still authenticated"
        );

        // Exactly one segment of plaintext is one full final segment, not a
        // full segment followed by an empty final one.
        let whole = seal(&plaintext(SEGMENT), backend);
        assert_eq!(whole.len(), HEADER_BYTES + SEGMENT_CIPHERTEXT_BYTES);
        let mut with_empty_final = whole[..HEADER_BYTES].to_vec();
        with_empty_final.extend_from_slice(&whole[HEADER_BYTES..]);
        with_empty_final.extend_from_slice(&[0; TAG_BYTES]);
        assert!(matches!(
            open_reader(with_empty_final, backend),
            Err(MediaFormatError::InvalidLength)
        ));
    }
}

/// A sink that accepts `remaining` bytes and then fails like a full disk.
struct FailingSink {
    remaining: usize,
}

impl Write for FailingSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("disk full"));
        }
        let accepted = data.len().min(self.remaining);
        self.remaining -= accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failed_segment_write_poisons_the_writer() {
    for backend in CipherBackend::ALL {
        // Room for the header and part of the first segment only.
        let sink = FailingSink {
            remaining: HEADER_BYTES + 100,
        };
        let mut writer = MediaFileWriter::new(sink, &key(), &FILE_ID, backend).unwrap();
        let body = plaintext(3 * SEGMENT);
        assert!(writer.write_all(&body).is_err());
        // Neither more data nor `finish` may reseal the failed segment.
        assert!(writer.write(&body[..10]).is_err());
        assert!(matches!(writer.finish(), Err(MediaFormatError::Poisoned)));
    }
}
