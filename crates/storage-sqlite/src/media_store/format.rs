//! Local encrypted media file format, version 1.
//!
//! A file is a fixed header followed by the age v1 payload (C2SP age spec,
//! "Payload"):
//!
//! ```text
//! header  = "mdkmedia" || version (1 byte) || file id (16 bytes)
//! payload = segment_0 || ... || segment_n
//! ```
//!
//! The payload key is HKDF-SHA256 of the file's random 32-byte key, with the
//! header bytes as salt and `"payload"` as info. The plaintext is split into
//! 64 KiB segments, each sealed with ChaCha20-Poly1305 under the nonce
//! `11-byte big-endian segment index || final flag`. Every segment is full
//! size except the last, which may be full or short, and is empty only when
//! the whole plaintext is empty.
//!
//! age salts the same derivation with a random 16-byte nonce. Salting it with
//! the header instead binds the format version and file id to every segment
//! while keeping the code that age's own test vectors exercise identical to
//! the code that seals local files. Segments cannot be reordered, dropped or
//! truncated undetected; a single segment can be authenticated on its own,
//! which is what makes offset reads cheap.

use std::io::{self, Read, Seek, SeekFrom, Write};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Plaintext bytes per segment.
pub const SEGMENT_PLAINTEXT_BYTES: usize = 64 * 1024;
/// Poly1305 tag appended to every segment.
pub const TAG_BYTES: usize = 16;
/// On-disk bytes of every non-final segment.
pub const SEGMENT_CIPHERTEXT_BYTES: usize = SEGMENT_PLAINTEXT_BYTES + TAG_BYTES;
/// Random per-file key length.
pub const FILE_KEY_BYTES: usize = 32;
/// Random file id length; the id is also the file name.
pub const FILE_ID_BYTES: usize = 16;
/// Current format version.
pub const FORMAT_VERSION: u8 = 1;
const MAGIC: [u8; 8] = *b"mdkmedia";
/// Header length; the payload starts at this offset.
pub const HEADER_BYTES: usize = MAGIC.len() + 1 + FILE_ID_BYTES;
const PAYLOAD_KEY_INFO: &[u8] = b"payload";

#[derive(Debug, thiserror::Error)]
pub enum MediaFormatError {
    #[error("media file I/O failed")]
    Io(#[from] io::Error),
    #[error("media file header is invalid")]
    InvalidHeader,
    #[error("media file format version is unsupported")]
    UnsupportedVersion,
    #[error("media file belongs to a different file id")]
    FileIdMismatch,
    #[error("media file payload length is invalid")]
    InvalidLength,
    #[error("media file segment failed authentication")]
    Authentication,
    #[error("media file cipher backend failed")]
    Backend,
    #[error("media file writer failed earlier and must be discarded")]
    Poisoned,
}

impl From<MediaFormatError> for io::Error {
    fn from(error: MediaFormatError) -> Self {
        match error {
            MediaFormatError::Io(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

pub type MediaFormatResult<T> = Result<T, MediaFormatError>;

/// ChaCha20-Poly1305 implementation. Both produce identical bytes; they differ
/// only in speed per platform, which the step-0 benchmark measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherBackend {
    /// RustCrypto `chacha20poly1305`.
    RustCrypto,
    /// OpenSSL's EVP ChaCha20-Poly1305, which has ARMv8 and x86 assembly.
    OpenSsl,
}

impl CipherBackend {
    pub const ALL: [Self; 2] = [Self::RustCrypto, Self::OpenSsl];

    pub fn name(self) -> &'static str {
        match self {
            Self::RustCrypto => "rustcrypto",
            Self::OpenSsl => "openssl",
        }
    }
}

/// The random key stored in a media file's database row.
pub struct FileKey(Zeroizing<[u8; FILE_KEY_BYTES]>);

impl FileKey {
    pub fn from_bytes(bytes: [u8; FILE_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; FILE_KEY_BYTES] {
        &self.0
    }
}

pub fn header_bytes(file_id: &[u8; FILE_ID_BYTES]) -> [u8; HEADER_BYTES] {
    let mut header = [0; HEADER_BYTES];
    header[..MAGIC.len()].copy_from_slice(&MAGIC);
    header[MAGIC.len()] = FORMAT_VERSION;
    header[MAGIC.len() + 1..].copy_from_slice(file_id);
    header
}

fn parse_header(
    header: &[u8; HEADER_BYTES],
    expected_id: &[u8; FILE_ID_BYTES],
) -> MediaFormatResult<()> {
    if header[..MAGIC.len()] != MAGIC {
        return Err(MediaFormatError::InvalidHeader);
    }
    if header[MAGIC.len()] != FORMAT_VERSION {
        return Err(MediaFormatError::UnsupportedVersion);
    }
    if header[MAGIC.len() + 1..] != expected_id[..] {
        return Err(MediaFormatError::FileIdMismatch);
    }
    Ok(())
}

/// The age payload key: HKDF-SHA256(ikm, salt, "payload").
pub(crate) struct PayloadKey(Zeroizing<[u8; 32]>);

impl PayloadKey {
    pub(crate) fn derive(ikm: &[u8], salt: &[u8]) -> Self {
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(salt), ikm)
            .expand(PAYLOAD_KEY_INFO, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self(key)
    }

    fn for_file(file_key: &FileKey, header: &[u8; HEADER_BYTES]) -> Self {
        Self::derive(file_key.as_bytes(), header)
    }
}

fn segment_nonce(index: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

enum SegmentCipher {
    RustCrypto(Box<ChaCha20Poly1305>),
    OpenSsl {
        key: Zeroizing<[u8; 32]>,
        context: CipherCtx,
    },
}

impl SegmentCipher {
    fn new(key: &PayloadKey, backend: CipherBackend) -> MediaFormatResult<Self> {
        Ok(match backend {
            CipherBackend::RustCrypto => Self::RustCrypto(Box::new(ChaCha20Poly1305::new(
                Key::from_slice(key.0.as_ref()),
            ))),
            CipherBackend::OpenSsl => Self::OpenSsl {
                key: key.0.clone(),
                context: CipherCtx::new().map_err(|_| MediaFormatError::Backend)?,
            },
        })
    }

    /// Encrypts `segment` in place and returns its tag.
    fn seal(
        &mut self,
        index: u64,
        last: bool,
        segment: &mut [u8],
    ) -> MediaFormatResult<[u8; TAG_BYTES]> {
        let nonce = segment_nonce(index, last);
        match self {
            Self::RustCrypto(cipher) => cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], segment)
                .map(Into::into)
                .map_err(|_| MediaFormatError::Backend),
            Self::OpenSsl { key, context } => {
                let mut tag = [0; TAG_BYTES];
                context
                    .encrypt_init(
                        Some(Cipher::chacha20_poly1305()),
                        Some(key.as_ref()),
                        Some(&nonce),
                    )
                    .and_then(|()| context.cipher_update_inplace(segment, segment.len()))
                    .and_then(|_| context.cipher_final(&mut []))
                    .and_then(|_| context.tag(&mut tag))
                    .map_err(|_| MediaFormatError::Backend)?;
                Ok(tag)
            }
        }
    }

    /// Decrypts `segment` in place, or fails without exposing plaintext.
    fn open(
        &mut self,
        index: u64,
        last: bool,
        segment: &mut [u8],
        tag: &[u8],
    ) -> MediaFormatResult<()> {
        let nonce = segment_nonce(index, last);
        let result = match self {
            Self::RustCrypto(cipher) => cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &[],
                    segment,
                    Tag::from_slice(tag),
                )
                .map_err(|_| MediaFormatError::Authentication),
            Self::OpenSsl { key, context } => context
                .decrypt_init(
                    Some(Cipher::chacha20_poly1305()),
                    Some(key.as_ref()),
                    Some(&nonce),
                )
                .and_then(|()| context.set_tag(tag))
                .and_then(|()| context.cipher_update_inplace(segment, segment.len()))
                .map_err(|_| MediaFormatError::Backend)
                .and_then(|_| {
                    context
                        .cipher_final(&mut [])
                        .map_err(|_| MediaFormatError::Authentication)
                })
                .map(|_| ()),
        };
        if result.is_err() {
            // OpenSSL decrypts before it checks the tag; never leave
            // unauthenticated plaintext in the caller's buffer.
            segment.fill(0);
        }
        result
    }
}

/// Segment count and plaintext length implied by a payload's byte length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PayloadLayout {
    payload_bytes: u64,
    segments: u64,
    plaintext_bytes: u64,
}

impl PayloadLayout {
    fn from_payload_bytes(payload_bytes: u64) -> MediaFormatResult<Self> {
        let full = SEGMENT_CIPHERTEXT_BYTES as u64;
        let tag = TAG_BYTES as u64;
        if payload_bytes == 0 {
            return Err(MediaFormatError::InvalidLength);
        }
        let segments = payload_bytes.div_ceil(full);
        let last = payload_bytes - (segments - 1) * full;
        // A final segment shorter than a tag cannot exist; an empty final
        // segment is only valid as the sole segment of an empty plaintext.
        if last < tag || (last == tag && segments > 1) {
            return Err(MediaFormatError::InvalidLength);
        }
        Ok(Self {
            payload_bytes,
            segments,
            plaintext_bytes: payload_bytes - segments * tag,
        })
    }

    fn segment_ciphertext_bytes(&self, index: u64) -> usize {
        if index + 1 == self.segments {
            (self.payload_bytes - index * SEGMENT_CIPHERTEXT_BYTES as u64) as usize
        } else {
            SEGMENT_CIPHERTEXT_BYTES
        }
    }
}

/// Streams plaintext into a media file. Nothing is final until `finish`
/// seals the last segment; a writer dropped earlier leaves a file that fails
/// authentication at its last segment. After any error the writer refuses
/// further writes and `finish`; it and its partial file must be discarded.
pub struct MediaFileWriter<W: Write> {
    inner: W,
    cipher: SegmentCipher,
    index: u64,
    buffer: Vec<u8>,
    plaintext_bytes: u64,
    /// Set while a segment is being sealed and written, cleared on success:
    /// after a failure the buffer may hold a sealed segment whose nonce was
    /// used, so it must never be sealed or written again.
    poisoned: bool,
}

impl<W: Write> MediaFileWriter<W> {
    /// Writes the header and returns a writer for the payload.
    pub fn new(
        mut inner: W,
        file_key: &FileKey,
        file_id: &[u8; FILE_ID_BYTES],
        backend: CipherBackend,
    ) -> MediaFormatResult<Self> {
        let header = header_bytes(file_id);
        inner.write_all(&header)?;
        Self::with_payload_key(inner, &PayloadKey::for_file(file_key, &header), backend)
    }

    pub(crate) fn with_payload_key(
        inner: W,
        key: &PayloadKey,
        backend: CipherBackend,
    ) -> MediaFormatResult<Self> {
        Ok(Self {
            inner,
            cipher: SegmentCipher::new(key, backend)?,
            index: 0,
            buffer: Vec::with_capacity(SEGMENT_CIPHERTEXT_BYTES),
            plaintext_bytes: 0,
            poisoned: false,
        })
    }

    /// Plaintext bytes accepted so far.
    pub fn plaintext_bytes(&self) -> u64 {
        self.plaintext_bytes
    }

    fn seal_buffered(&mut self, last: bool) -> MediaFormatResult<()> {
        if self.poisoned {
            return Err(MediaFormatError::Poisoned);
        }
        self.poisoned = true;
        let tag = self.cipher.seal(self.index, last, &mut self.buffer)?;
        self.buffer.extend_from_slice(&tag);
        self.inner.write_all(&self.buffer)?;
        self.buffer.clear();
        self.index = self
            .index
            .checked_add(1)
            .ok_or(MediaFormatError::InvalidLength)?;
        self.poisoned = false;
        Ok(())
    }

    /// Seals the final segment and flushes. The caller owns durability
    /// (syncing the file before anything relies on it).
    pub fn finish(mut self) -> MediaFormatResult<W> {
        self.seal_buffered(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for MediaFileWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(MediaFormatError::Poisoned.into());
        }
        if data.is_empty() {
            return Ok(0);
        }
        // A full buffer is only sealed as non-final once more plaintext
        // arrives, so a plaintext of whole segments ends in a full final one.
        if self.buffer.len() == SEGMENT_PLAINTEXT_BYTES {
            self.seal_buffered(false)?;
        }
        let accepted = data.len().min(SEGMENT_PLAINTEXT_BYTES - self.buffer.len());
        self.buffer.extend_from_slice(&data[..accepted]);
        self.plaintext_bytes += accepted as u64;
        Ok(accepted)
    }

    /// Flushes sealed segments only; the open segment stays buffered.
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Random-access reader over a media file. Each read authenticates every
/// segment it touches; the last decrypted segment is cached.
pub struct MediaFileReader<R: Read + Seek> {
    inner: R,
    cipher: SegmentCipher,
    payload_start: u64,
    layout: PayloadLayout,
    segment: Zeroizing<Vec<u8>>,
    cached: Option<u64>,
    position: u64,
}

impl<R: Read + Seek> MediaFileReader<R> {
    /// Validates the header against the file id the database expects and
    /// derives the layout from the file's length.
    pub fn open(
        mut inner: R,
        file_key: &FileKey,
        expected_id: &[u8; FILE_ID_BYTES],
        backend: CipherBackend,
    ) -> MediaFormatResult<Self> {
        let mut header = [0; HEADER_BYTES];
        inner.seek(SeekFrom::Start(0))?;
        inner.read_exact(&mut header).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                MediaFormatError::InvalidHeader
            } else {
                error.into()
            }
        })?;
        parse_header(&header, expected_id)?;
        let total = inner.seek(SeekFrom::End(0))?;
        Self::with_payload_key(
            inner,
            &PayloadKey::for_file(file_key, &header),
            HEADER_BYTES as u64,
            total - HEADER_BYTES as u64,
            backend,
        )
    }

    pub(crate) fn with_payload_key(
        inner: R,
        key: &PayloadKey,
        payload_start: u64,
        payload_bytes: u64,
        backend: CipherBackend,
    ) -> MediaFormatResult<Self> {
        Ok(Self {
            inner,
            cipher: SegmentCipher::new(key, backend)?,
            payload_start,
            layout: PayloadLayout::from_payload_bytes(payload_bytes)?,
            segment: Zeroizing::new(Vec::with_capacity(SEGMENT_CIPHERTEXT_BYTES)),
            cached: None,
            position: 0,
        })
    }

    /// Plaintext length implied by the file length. Callers compare it with
    /// the length their database row recorded.
    pub fn plaintext_bytes(&self) -> u64 {
        self.layout.plaintext_bytes
    }

    fn load_segment(&mut self, index: u64) -> MediaFormatResult<()> {
        if self.cached == Some(index) {
            return Ok(());
        }
        self.cached = None;
        let ciphertext_bytes = self.layout.segment_ciphertext_bytes(index);
        let offset = self.payload_start + index * SEGMENT_CIPHERTEXT_BYTES as u64;
        self.segment.resize(ciphertext_bytes, 0);
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read_exact(&mut self.segment)?;
        let plaintext_bytes = ciphertext_bytes - TAG_BYTES;
        let (body, tag) = self.segment.split_at_mut(plaintext_bytes);
        let last = index + 1 == self.layout.segments;
        self.cipher.open(index, last, body, tag)?;
        self.segment.truncate(plaintext_bytes);
        self.cached = Some(index);
        Ok(())
    }

    /// Fills `out` from plaintext `offset`; returns 0 at or past the end.
    pub fn read_at(&mut self, offset: u64, out: &mut [u8]) -> MediaFormatResult<usize> {
        let mut filled = 0;
        while filled < out.len() {
            let at = offset + filled as u64;
            if at >= self.layout.plaintext_bytes {
                break;
            }
            let index = at / SEGMENT_PLAINTEXT_BYTES as u64;
            let within = (at % SEGMENT_PLAINTEXT_BYTES as u64) as usize;
            self.load_segment(index)?;
            let available = &self.segment[within..];
            let copied = available.len().min(out.len() - filled);
            out[filled..filled + copied].copy_from_slice(&available[..copied]);
            filled += copied;
        }
        // An empty plaintext still has one segment to authenticate.
        if self.layout.plaintext_bytes == 0 {
            self.load_segment(0)?;
        }
        Ok(filled)
    }
}

impl<R: Read + Seek> Read for MediaFileReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.read_at(self.position, out)?;
        self.position += read as u64;
        Ok(read)
    }
}

/// Decrypts a whole age payload held in memory.
#[cfg(test)]
pub(crate) fn open_payload(
    key: &PayloadKey,
    payload: &[u8],
    backend: CipherBackend,
) -> MediaFormatResult<Vec<u8>> {
    let mut reader = MediaFileReader::with_payload_key(
        io::Cursor::new(payload),
        key,
        0,
        payload.len() as u64,
        backend,
    )?;
    let mut plaintext = vec![0; reader.plaintext_bytes() as usize];
    let read = reader.read_at(0, &mut plaintext)?;
    debug_assert_eq!(read, plaintext.len());
    Ok(plaintext)
}
