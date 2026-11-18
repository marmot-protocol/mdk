use hkdf::Hkdf;
use sha2::Sha256;

use super::{EncryptedMediaVersion, MediaAttachmentReference};
use crate::AppError;

/// The caller has irreversibly claimed this authenticated attachment in storage.
/// Never construct this for preview, automatic acquisition, or retained media.
pub(crate) enum ClaimedViewOnceConsumption {
    DurablyClaimed,
}

pub(crate) fn decrypt_claimed_view_once(
    reference: &MediaAttachmentReference,
    media_secret: &[u8],
    encrypted: Vec<u8>,
    _claim: ClaimedViewOnceConsumption,
) -> Result<zeroize::Zeroizing<Vec<u8>>, AppError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use sha2::Digest;
    use zeroize::Zeroizing;

    let mut plaintext = Zeroizing::new(encrypted);
    if EncryptedMediaVersion::parse(&reference.version)? != EncryptedMediaVersion::ViewOnceV1 {
        return Err(AppError::InvalidEncryptedMedia(
            "claimed download requires view-once media".into(),
        ));
    }
    reference.validate(false)?;
    if plaintext.len() < 16 || plaintext.len() > super::view_once_content::MAX_VIEW_ONCE_BYTES + 16
    {
        return Err(AppError::InvalidEncryptedMedia(
            "view-once media exceeds its size limit".into(),
        ));
    }
    if !super::encrypted_media_hash_matches(&plaintext, &reference.ciphertext_sha256) {
        return Err(AppError::MediaDownloadFailed(
            "encrypted blob hash does not match media reference".into(),
        ));
    }
    let hash = media_hash_from_reference(reference)?;
    let nonce = media_nonce_from_reference(reference)?;
    let key = Zeroizing::new(media_file_key_for_reference(media_secret, reference)?);
    let aad = media_aad(
        EncryptedMediaVersion::ViewOnceV1,
        &hash,
        &reference.media_type,
        &reference.file_name,
    );
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid media key length".into()))?;
    cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut *plaintext)
        .map_err(|_| AppError::MediaDownloadFailed("media decryption failed".into()))?;
    let actual: [u8; 32] = Sha256::digest(&*plaintext).into();
    if actual != hash {
        return Err(AppError::MediaDownloadFailed(
            "media plaintext hash does not match reference".into(),
        ));
    }
    super::view_once_content::validate_view_once_content(&plaintext, &reference.media_type)?;
    Ok(plaintext)
}

pub(crate) fn canonical_media_type_v1(value: &str) -> Result<String, AppError> {
    // Frozen V1 uses Rust's complete ASCII-whitespace set, including VT.
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .to_ascii_lowercase();
    if media_type.is_empty() || !media_type.contains('/') {
        return Err(AppError::InvalidEncryptedMedia(
            "media type must be a MIME type".into(),
        ));
    }
    Ok(match media_type.as_str() {
        "image/jpg" => "image/jpeg".to_owned(),
        other => other.to_owned(),
    })
}

pub(crate) fn canonical_media_type_v2(value: &str) -> Result<String, AppError> {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_matches(|c| matches!(c, '\u{0009}' | '\u{000a}' | '\u{000c}' | '\u{000d}' | ' '))
        .to_ascii_lowercase();
    let mut segments = media_type.split('/');
    let type_ = segments.next().unwrap_or_default();
    let subtype = segments.next().unwrap_or_default();
    if type_.is_empty()
        || subtype.is_empty()
        || segments.next().is_some()
        || type_.len() > 64
        || subtype.len() > 64
        || media_type.len() > 128
        || !type_.bytes().all(is_http_token_byte)
        || !subtype.bytes().all(is_http_token_byte)
    {
        return Err(AppError::InvalidEncryptedMedia(
            "media type is not a canonicalizable MIME type".into(),
        ));
    }
    Ok(match media_type.as_str() {
        "image/jpg" => "image/jpeg".to_owned(),
        other => other.to_owned(),
    })
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(crate) fn validate_sha256_hex(value: &str, label: &str) -> Result<(), AppError> {
    let hash = hex::decode(value)
        .map_err(|_| AppError::InvalidAppMessagePayload(format!("{label} must be hex")))?;
    if hash.len() != 32 {
        return Err(AppError::InvalidAppMessagePayload(format!(
            "{label} must be 32 bytes"
        )));
    }
    Ok(())
}

pub(crate) fn media_hash_from_reference(
    reference: &MediaAttachmentReference,
) -> Result<[u8; 32], AppError> {
    hex::decode(&reference.plaintext_sha256)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("media hash must be 32 bytes".into()))
}

pub(crate) fn media_nonce_from_reference(
    reference: &MediaAttachmentReference,
) -> Result<[u8; 12], AppError> {
    hex::decode(&reference.nonce_hex)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("media nonce must be 12 bytes".into()))
}

/// What opens a downloaded attachment.
#[derive(Clone, Copy)]
pub(crate) enum MediaKey<'a> {
    /// The source epoch's media secret, from which each file's key is derived.
    EpochSecret(&'a [u8]),
    /// One file's key itself, imported with a sibling's history (mdk#2628
    /// 4.2a) by a device that was never in the source epoch.
    File(&'a [u8; 32]),
}

impl MediaKey<'_> {
    pub(crate) fn file_key(
        self,
        version: EncryptedMediaVersion,
        file_hash: &[u8; 32],
        media_type: &str,
        file_name: &str,
    ) -> Result<[u8; 32], AppError> {
        match self {
            Self::EpochSecret(secret) => {
                derive_media_file_key(secret, version, file_hash, media_type, file_name)
            }
            Self::File(key) => Ok(*key),
        }
    }
}

/// `reference`'s file key, derived from its source epoch's media secret.
pub(crate) fn media_file_key_for_reference(
    media_secret: &[u8],
    reference: &MediaAttachmentReference,
) -> Result<[u8; 32], AppError> {
    let version = EncryptedMediaVersion::parse(&reference.version)?;
    let media_type = match version {
        EncryptedMediaVersion::V1 => canonical_media_type_v1(&reference.media_type)?,
        EncryptedMediaVersion::V2 | EncryptedMediaVersion::ViewOnceV1 => {
            canonical_media_type_v2(&reference.media_type)?
        }
    };
    derive_media_file_key(
        media_secret,
        version,
        &media_hash_from_reference(reference)?,
        &media_type,
        &reference.file_name,
    )
}

pub(crate) fn derive_media_file_key(
    media_secret: &[u8],
    version: EncryptedMediaVersion,
    file_hash: &[u8; 32],
    media_type: &str,
    file_name: &str,
) -> Result<[u8; 32], AppError> {
    let hkdf = Hkdf::<Sha256>::from_prk(media_secret).map_err(|_| {
        AppError::InvalidEncryptedMedia("invalid encrypted-media component secret".into())
    })?;
    let mut key = [0_u8; 32];
    hkdf.expand(
        &media_key_info(version, file_hash, media_type, file_name),
        &mut key,
    )
    .map_err(|_| AppError::InvalidEncryptedMedia("media key derivation failed".into()))?;
    Ok(key)
}

fn media_key_info(
    version: EncryptedMediaVersion,
    file_hash: &[u8; 32],
    media_type: &str,
    file_name: &str,
) -> Vec<u8> {
    let version = version.as_str();
    let mut info =
        Vec::with_capacity(version.len() + 1 + 32 + 1 + media_type.len() + 1 + file_name.len() + 4);
    info.extend_from_slice(version.as_bytes());
    info.push(0);
    info.extend_from_slice(file_hash);
    info.push(0);
    info.extend_from_slice(media_type.as_bytes());
    info.push(0);
    info.extend_from_slice(file_name.as_bytes());
    info.push(0);
    info.extend_from_slice(b"key");
    info
}

pub(crate) fn media_aad(
    version: EncryptedMediaVersion,
    file_hash: &[u8; 32],
    media_type: &str,
    file_name: &str,
) -> Vec<u8> {
    let version = version.as_str();
    let mut aad =
        Vec::with_capacity(version.len() + 1 + 32 + 1 + media_type.len() + 1 + file_name.len());
    aad.extend_from_slice(version.as_bytes());
    aad.push(0);
    aad.extend_from_slice(file_hash);
    aad.push(0);
    aad.extend_from_slice(media_type.as_bytes());
    aad.push(0);
    aad.extend_from_slice(file_name.as_bytes());
    aad
}
