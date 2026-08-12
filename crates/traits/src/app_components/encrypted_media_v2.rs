//! `marmot.group.encrypted-media.v2` component state and codec.

use serde::{Deserialize, Serialize};
use url::Url;

use super::codec::{decode_var_bytes, encode_component_vectors, encode_var_bytes};
use super::encrypted_media::{
    ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN, ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN,
};
use super::{
    BLOSSOM_LOCATOR_KIND_V1, ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN, ENCRYPTED_MEDIA_FORMAT_V2,
    ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN, ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS,
    ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobStoreEndpointV2 {
    pub locator_kind: String,
    pub base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMediaPolicyV2 {
    pub media_format: String,
    pub allowed_locator_kinds: Vec<String>,
    pub default_blob_endpoints: Vec<BlobStoreEndpointV2>,
}

impl EncryptedMediaPolicyV2 {
    pub fn blossom_default(endpoints: impl IntoIterator<Item = String>) -> Result<Self, String> {
        Self::new(
            ENCRYPTED_MEDIA_FORMAT_V2.to_owned(),
            vec![BLOSSOM_LOCATOR_KIND_V1.to_owned()],
            endpoints.into_iter().map(|base_url| BlobStoreEndpointV2 {
                locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
                base_url,
            }),
        )
    }

    pub fn new(
        media_format: String,
        allowed_locator_kinds: Vec<String>,
        endpoints: impl IntoIterator<Item = BlobStoreEndpointV2>,
    ) -> Result<Self, String> {
        let media_format = media_format.trim().to_owned();
        if media_format != ENCRYPTED_MEDIA_FORMAT_V2 {
            return Err(format!(
                "encrypted media format must be {ENCRYPTED_MEDIA_FORMAT_V2}"
            ));
        }
        let allowed_locator_kinds = normalize_locator_kinds(allowed_locator_kinds)?;
        if allowed_locator_kinds.is_empty() {
            return Err("encrypted media policy must allow at least one locator kind".into());
        }
        if allowed_locator_kinds.len() > ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS {
            return Err(format!(
                "encrypted media policy allows more than {ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS} locator kinds"
            ));
        }

        let mut normalized_endpoints = Vec::new();
        for endpoint in endpoints {
            let locator_kind =
                normalize_locator_kind(&endpoint.locator_kind, "endpoint locator kind")?;
            if !allowed_locator_kinds.contains(&locator_kind) {
                return Err("encrypted media endpoint locator kind is not allowed".into());
            }
            let endpoint = BlobStoreEndpointV2 {
                locator_kind,
                base_url: validate_and_normalize_blob_endpoint_url_v2(&endpoint.base_url)?,
            };
            if !normalized_endpoints.contains(&endpoint) {
                normalized_endpoints.push(endpoint);
            }
        }
        if normalized_endpoints.is_empty() {
            return Err(
                "encrypted media policy must include at least one default blob endpoint".into(),
            );
        }
        if normalized_endpoints.len() > ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS {
            return Err(format!(
                "encrypted media policy includes more than {ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS} default blob endpoints"
            ));
        }

        Ok(Self {
            media_format,
            allowed_locator_kinds,
            default_blob_endpoints: normalized_endpoints,
        })
    }
}

pub fn encode_encrypted_media_policy_v2(
    policy: &EncryptedMediaPolicyV2,
) -> Result<Vec<u8>, String> {
    let policy = EncryptedMediaPolicyV2::new(
        policy.media_format.clone(),
        policy.allowed_locator_kinds.clone(),
        policy.default_blob_endpoints.clone(),
    )?;
    let mut allowed = Vec::new();
    for kind in &policy.allowed_locator_kinds {
        encode_var_bytes(kind.as_bytes(), &mut allowed);
    }
    let mut endpoints = Vec::new();
    for endpoint in &policy.default_blob_endpoints {
        encode_var_bytes(endpoint.locator_kind.as_bytes(), &mut endpoints);
        encode_var_bytes(endpoint.base_url.as_bytes(), &mut endpoints);
    }
    Ok(encode_component_vectors(&[
        policy.media_format.as_bytes(),
        allowed.as_slice(),
        endpoints.as_slice(),
    ]))
}

/// Strictly decode canonical `marmot.group.encrypted-media.v2` state.
pub fn decode_encrypted_media_policy_v2(bytes: &[u8]) -> Result<EncryptedMediaPolicyV2, String> {
    let mut cursor = bytes;
    let media_format = decode_var_bytes(&mut cursor, 64, "encrypted media format")?;
    let allowed_bytes = decode_var_bytes(
        &mut cursor,
        ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN,
        "encrypted media locator kinds",
    )?;
    let endpoints_bytes = decode_var_bytes(
        &mut cursor,
        ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN,
        "encrypted media default blob endpoints",
    )?;
    if !cursor.is_empty() {
        return Err("encrypted media policy has trailing bytes".into());
    }
    let media_format = String::from_utf8(media_format)
        .map_err(|e| format!("encrypted media format is not UTF-8: {e}"))?;
    if media_format != ENCRYPTED_MEDIA_FORMAT_V2 {
        return Err(format!(
            "encrypted media format must be {ENCRYPTED_MEDIA_FORMAT_V2}"
        ));
    }

    let mut allowed_cursor = allowed_bytes.as_slice();
    let mut allowed_locator_kinds = Vec::new();
    while !allowed_cursor.is_empty() {
        let kind = decode_var_bytes(
            &mut allowed_cursor,
            ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN,
            "encrypted media locator kind",
        )?;
        let kind = String::from_utf8(kind)
            .map_err(|e| format!("encrypted media locator kind is not UTF-8: {e}"))?;
        validate_locator_kind(&kind, "allowed locator kind")?;
        if allowed_locator_kinds.contains(&kind) {
            return Err("encrypted media policy has a duplicate allowed locator kind".into());
        }
        allowed_locator_kinds.push(kind);
    }
    if allowed_locator_kinds.is_empty() {
        return Err("encrypted media policy must allow at least one locator kind".into());
    }
    if allowed_locator_kinds.len() > ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS {
        return Err(format!(
            "encrypted media policy allows more than {ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS} locator kinds"
        ));
    }

    let mut endpoints_cursor = endpoints_bytes.as_slice();
    let mut default_blob_endpoints = Vec::new();
    while !endpoints_cursor.is_empty() {
        let locator_kind = decode_var_bytes(
            &mut endpoints_cursor,
            ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN,
            "encrypted media endpoint locator kind",
        )?;
        let base_url = decode_var_bytes(
            &mut endpoints_cursor,
            ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN,
            "encrypted media endpoint base URL",
        )?;
        let locator_kind = String::from_utf8(locator_kind)
            .map_err(|e| format!("encrypted media endpoint locator kind is not UTF-8: {e}"))?;
        let base_url = String::from_utf8(base_url)
            .map_err(|e| format!("encrypted media endpoint base URL is not UTF-8: {e}"))?;
        validate_locator_kind(&locator_kind, "endpoint locator kind")?;
        if !allowed_locator_kinds.contains(&locator_kind) {
            return Err("encrypted media endpoint locator kind is not allowed".into());
        }
        validate_blob_endpoint_url_is_canonical_v2(&base_url)?;
        let endpoint = BlobStoreEndpointV2 {
            locator_kind,
            base_url,
        };
        if default_blob_endpoints.contains(&endpoint) {
            return Err("encrypted media policy has a duplicate default blob endpoint".into());
        }
        default_blob_endpoints.push(endpoint);
    }
    if default_blob_endpoints.is_empty() {
        return Err(
            "encrypted media policy must include at least one default blob endpoint".into(),
        );
    }
    if default_blob_endpoints.len() > ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS {
        return Err(format!(
            "encrypted media policy includes more than {ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS} default blob endpoints"
        ));
    }

    Ok(EncryptedMediaPolicyV2 {
        media_format,
        allowed_locator_kinds,
        default_blob_endpoints,
    })
}

/// Producer-side WHATWG parse-and-serialize normalization for V2 endpoint
/// state. Reachability and permission to contact the endpoint are deliberately
/// not component validity rules.
pub fn validate_and_normalize_blob_endpoint_url_v2(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("encrypted media endpoint URL must not be empty".into());
    }
    if raw.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "encrypted media endpoint URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    let url =
        Url::parse(raw).map_err(|e| format!("encrypted media endpoint URL is invalid: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("encrypted media endpoint URL scheme must be http or https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("encrypted media endpoint URL must not include credentials".into());
    }
    if url.host().is_none() {
        return Err("encrypted media endpoint URL must include a host".into());
    }
    if url.query().is_some() {
        return Err("encrypted media endpoint URL must not include a query".into());
    }
    if url.fragment().is_some() {
        return Err("encrypted media endpoint URL must not include a fragment".into());
    }
    let normalized = url.as_str();
    if normalized.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "encrypted media endpoint URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_locator_kinds(kinds: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for kind in kinds {
        let kind = normalize_locator_kind(&kind, "allowed locator kind")?;
        if !normalized.contains(&kind) {
            normalized.push(kind);
        }
    }
    Ok(normalized)
}

fn normalize_locator_kind(value: &str, label: &'static str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    validate_locator_kind(&value, label)?;
    Ok(value)
}

fn validate_locator_kind(value: &str, label: &'static str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN {
        return Err(format!(
            "{label} exceeds {ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN} bytes"
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!(
            "{label} must contain only lowercase ASCII letters, digits, and '-'"
        ));
    }
    Ok(())
}

fn validate_blob_endpoint_url_is_canonical_v2(base_url: &str) -> Result<(), String> {
    let normalized = validate_and_normalize_blob_endpoint_url_v2(base_url)?;
    if normalized != base_url {
        return Err("encrypted media endpoint base URL is not normalized".into());
    }
    Ok(())
}
