use hkdf::Hkdf;
use sha2::Sha256;

use super::{EncryptedMediaVersion, MediaAttachmentReference};
use crate::AppError;

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
