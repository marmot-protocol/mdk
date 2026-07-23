//! `marmot.group.blossom.image.v1` component state and codec.

use super::codec::{decode_var_bytes, encode_component_vectors};

const IMAGE_HASH_LEN: usize = 32;
const IMAGE_KEY_LEN: usize = 32;
const IMAGE_NONCE_LEN: usize = 12;
const IMAGE_UPLOAD_KEY_LEN: usize = 32;
const MEDIA_TYPE_MAX_LEN: usize = 128;

/// Decoded `marmot.group.blossom.image.v1` state.
///
/// The key fields are MLS-protected secret material. The custom `Debug` implementation
/// deliberately redacts them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GroupBlossomImageV1 {
    pub image_hash: Vec<u8>,
    pub image_key: Vec<u8>,
    pub image_nonce: Vec<u8>,
    pub image_upload_key: Vec<u8>,
    pub media_type: String,
}

impl std::fmt::Debug for GroupBlossomImageV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupBlossomImageV1")
            .field("image_hash", &"<redacted>")
            .field("image_key", &"<redacted>")
            .field("image_nonce", &"<redacted>")
            .field("image_upload_key", &"<redacted>")
            .field("media_type", &self.media_type)
            .finish()
    }
}

impl GroupBlossomImageV1 {
    pub fn is_present(&self) -> bool {
        !self.image_hash.is_empty()
            || !self.image_key.is_empty()
            || !self.image_nonce.is_empty()
            || !self.image_upload_key.is_empty()
            || !self.media_type.is_empty()
    }
}

/// Encode group Blossom image state. Present-state media types are normalized with
/// the frozen Marmot media-type algorithm before encoding.
pub fn encode_group_blossom_image_v1(image: &GroupBlossomImageV1) -> Result<Vec<u8>, String> {
    if !image.is_present() {
        return Ok(encode_component_vectors(&[&[], &[], &[], &[], &[]]));
    }
    let media_type = validate_group_blossom_image_fields(image)?;
    Ok(encode_component_vectors(&[
        &image.image_hash,
        &image.image_key,
        &image.image_nonce,
        &image.image_upload_key,
        media_type.as_bytes(),
    ]))
}

/// Decode group Blossom image state and reject non-canonical media-type bytes.
pub fn decode_group_blossom_image_v1(bytes: &[u8]) -> Result<GroupBlossomImageV1, String> {
    let mut cursor = bytes;
    let image_hash = decode_var_bytes(&mut cursor, IMAGE_HASH_LEN, "group image hash")?;
    let image_key = decode_var_bytes(&mut cursor, IMAGE_KEY_LEN, "group image key")?;
    let image_nonce = decode_var_bytes(&mut cursor, IMAGE_NONCE_LEN, "group image nonce")?;
    let image_upload_key =
        decode_var_bytes(&mut cursor, IMAGE_UPLOAD_KEY_LEN, "group image upload key")?;
    let media_type = decode_var_bytes(&mut cursor, MEDIA_TYPE_MAX_LEN, "group image media type")?;
    if !cursor.is_empty() {
        return Err("group image component has trailing bytes".into());
    }
    let media_type = String::from_utf8(media_type)
        .map_err(|e| format!("group image media type is not UTF-8: {e}"))?;
    let image = GroupBlossomImageV1 {
        image_hash,
        image_key,
        image_nonce,
        image_upload_key,
        media_type,
    };
    if !image.is_present() {
        return Ok(image);
    }
    let canonical = validate_group_blossom_image_fields(&image)?;
    if canonical != image.media_type {
        return Err("group image media type is not canonical".into());
    }
    Ok(image)
}

fn validate_group_blossom_image_fields(image: &GroupBlossomImageV1) -> Result<String, String> {
    if image.image_hash.len() != IMAGE_HASH_LEN
        || image.image_key.len() != IMAGE_KEY_LEN
        || image.image_nonce.len() != IMAGE_NONCE_LEN
        || image.image_upload_key.len() != IMAGE_UPLOAD_KEY_LEN
        || image.media_type.is_empty()
    {
        return Err("group image component has invalid partial state".into());
    }
    canonicalize_marmot_media_type(&image.media_type)
}

/// Apply the frozen Marmot media-type canonicalization algorithm.
pub fn canonicalize_marmot_media_type(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let parameter_start = bytes
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(bytes.len());
    let mut media_type = &bytes[..parameter_start];
    while media_type
        .first()
        .is_some_and(|byte| is_marmot_ascii_whitespace(*byte))
    {
        media_type = &media_type[1..];
    }
    while media_type
        .last()
        .is_some_and(|byte| is_marmot_ascii_whitespace(*byte))
    {
        media_type = &media_type[..media_type.len() - 1];
    }

    let mut slash = None;
    for (index, byte) in media_type.iter().enumerate() {
        if *byte == b'/' && slash.replace(index).is_some() {
            return Err("media type must contain exactly one slash".into());
        }
    }
    let slash = slash.ok_or("media type must contain exactly one slash")?;
    let type_bytes = &media_type[..slash];
    let subtype_bytes = &media_type[slash + 1..];
    if type_bytes.is_empty() || subtype_bytes.is_empty() {
        return Err("media type and subtype must be non-empty".into());
    }
    if type_bytes.len() > 64 || subtype_bytes.len() > 64 || media_type.len() > MEDIA_TYPE_MAX_LEN {
        return Err("media type exceeds Marmot length bounds".into());
    }
    if !type_bytes
        .iter()
        .chain(subtype_bytes)
        .all(|byte| is_http_token_byte(*byte))
    {
        return Err("media type contains an invalid token byte".into());
    }

    let canonical = media_type
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let canonical = String::from_utf8(canonical)
        .map_err(|_| "media type must contain only ASCII token bytes".to_owned())?;
    Ok(if canonical == "image/jpg" {
        "image/jpeg".to_owned()
    } else {
        canonical
    })
}

fn is_marmot_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
