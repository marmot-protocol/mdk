//! `marmot.group.encrypted-media.v1` component state and codec.

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use super::codec::{decode_var_bytes, encode_component_vectors, encode_var_bytes};
use super::host_safety::{is_loopback_host, reject_non_routable_ipv4, reject_non_routable_ipv6};
use super::{
    BLOSSOM_LOCATOR_KIND_V1, ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN, ENCRYPTED_MEDIA_FORMAT_V1,
    ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN, ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS,
    ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS,
};

// Upper bounds for nested var-bytes vectors before decoding them into owned buffers.
pub(crate) const ENCRYPTED_MEDIA_LOCATOR_KINDS_VECTOR_MAX_LEN: usize =
    ENCRYPTED_MEDIA_MAX_LOCATOR_KINDS * (ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN + 2);
const ENCRYPTED_MEDIA_ENDPOINT_ENTRY_MAX_LEN: usize =
    (ENCRYPTED_MEDIA_LOCATOR_KIND_MAX_LEN + 2) + (ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN + 2);
pub(crate) const ENCRYPTED_MEDIA_BLOB_ENDPOINTS_VECTOR_MAX_LEN: usize =
    ENCRYPTED_MEDIA_MAX_BLOB_ENDPOINTS * (ENCRYPTED_MEDIA_ENDPOINT_ENTRY_MAX_LEN + 2);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobStoreEndpointV1 {
    pub locator_kind: String,
    pub base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMediaPolicyV1 {
    pub media_format: String,
    pub allowed_locator_kinds: Vec<String>,
    pub default_blob_endpoints: Vec<BlobStoreEndpointV1>,
}

impl EncryptedMediaPolicyV1 {
    pub fn blossom_default(
        endpoints: impl IntoIterator<Item = String>,
        allow_loopback_http: bool,
    ) -> Result<Self, String> {
        Self::new(
            ENCRYPTED_MEDIA_FORMAT_V1.to_owned(),
            vec![BLOSSOM_LOCATOR_KIND_V1.to_owned()],
            endpoints.into_iter().map(|base_url| BlobStoreEndpointV1 {
                locator_kind: BLOSSOM_LOCATOR_KIND_V1.to_owned(),
                base_url,
            }),
            allow_loopback_http,
        )
    }

    pub fn new(
        media_format: String,
        allowed_locator_kinds: Vec<String>,
        endpoints: impl IntoIterator<Item = BlobStoreEndpointV1>,
        allow_loopback_http: bool,
    ) -> Result<Self, String> {
        let media_format = media_format.trim().to_owned();
        if media_format != ENCRYPTED_MEDIA_FORMAT_V1 {
            return Err(format!(
                "encrypted media format must be {ENCRYPTED_MEDIA_FORMAT_V1}"
            ));
        }
        let allowed_locator_kinds =
            normalize_locator_kinds(allowed_locator_kinds, "allowed locator kind")?;
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
            if !allowed_locator_kinds
                .iter()
                .any(|kind| kind == &locator_kind)
            {
                return Err("encrypted media endpoint locator kind is not allowed".into());
            }
            let base_url =
                validate_and_normalize_blob_endpoint_url(&endpoint.base_url, allow_loopback_http)?;
            let endpoint = BlobStoreEndpointV1 {
                locator_kind,
                base_url,
            };
            if !normalized_endpoints
                .iter()
                .any(|existing| existing == &endpoint)
            {
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

pub fn encode_encrypted_media_policy_v1(
    policy: &EncryptedMediaPolicyV1,
) -> Result<Vec<u8>, String> {
    let policy = EncryptedMediaPolicyV1::new(
        policy.media_format.clone(),
        policy.allowed_locator_kinds.clone(),
        policy.default_blob_endpoints.clone(),
        true,
    )?;
    let mut allowed = Vec::new();
    for kind in &policy.allowed_locator_kinds {
        encode_var_bytes(kind.as_bytes(), &mut allowed);
    }
    let mut endpoints = Vec::new();
    for endpoint in &policy.default_blob_endpoints {
        // Per group-encrypted-media-v1.md, `default_blob_endpoints` is `Type
        // items<V>`: one outer length (added by `encode_component_vectors`) then
        // the concatenated `BlobStoreEndpointV1` structs with NO per-item wrapper.
        encode_var_bytes(endpoint.locator_kind.as_bytes(), &mut endpoints);
        encode_var_bytes(endpoint.base_url.as_bytes(), &mut endpoints);
    }
    Ok(encode_component_vectors(&[
        policy.media_format.as_bytes(),
        allowed.as_slice(),
        endpoints.as_slice(),
    ]))
}

/// Decode `marmot.group.encrypted-media.v1` state strictly.
///
/// Per [`../foundation/canonical-encoding.md`] ("Canonical decoding"), this is a
/// decoder of signed, state-selecting Marmot bytes: it MUST reject input that is
/// not already canonical and MUST NOT trim, case-fold, normalize, deduplicate, or
/// reorder anything. Unlike the producer-side [`EncryptedMediaPolicyV1::new`],
/// nothing here repairs non-canonical state — every check is a validation, and a
/// failure is an `Err`.
pub fn decode_encrypted_media_policy_v1(bytes: &[u8]) -> Result<EncryptedMediaPolicyV1, String> {
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
    if media_format != ENCRYPTED_MEDIA_FORMAT_V1 {
        return Err(format!(
            "encrypted media format must be {ENCRYPTED_MEDIA_FORMAT_V1}"
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
    let mut default_blob_endpoints: Vec<BlobStoreEndpointV1> = Vec::new();
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
        // Loopback http is valid component state for every member, so the decoder
        // accepts it (acting on it is a separate local rule). The URL must already
        // be in WHATWG-normalized form: reject, never repair.
        validate_blob_endpoint_url_is_canonical(&base_url)?;
        let endpoint = BlobStoreEndpointV1 {
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

    Ok(EncryptedMediaPolicyV1 {
        media_format,
        allowed_locator_kinds,
        default_blob_endpoints,
    })
}

pub fn validate_and_normalize_blob_endpoint_url(
    raw: &str,
    allow_loopback_http: bool,
) -> Result<String, String> {
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
    if !url.username().is_empty() || url.password().is_some() {
        return Err("encrypted media endpoint URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("encrypted media endpoint URL must not include a fragment".into());
    }
    // Per group-encrypted-media-v1.md the invalidity list is userinfo, fragments,
    // missing hosts, and unsafe hosts only. Query strings are NOT invalid: WHATWG
    // parse-and-serialize preserves a query, so a spec-conformant producer can emit
    // `https://blossom.example/?x=1` as valid normalized state. Rejecting it here
    // forked commit acceptance (issue #374). This also matches the sibling avatar
    // validator, which has no query check.
    let host = url
        .host()
        .ok_or("encrypted media endpoint URL must include a host")?;
    match url.scheme() {
        "https" => match host {
            Host::Domain(domain) => {
                let lowered = domain.to_ascii_lowercase();
                if lowered == "localhost" || lowered.ends_with(".localhost") {
                    return Err("encrypted media https endpoint must not point at localhost".into());
                }
            }
            Host::Ipv4(addr) => reject_non_routable_ipv4(addr).map_err(|_| {
                "encrypted media endpoint URL must not point at a non-routable address".to_owned()
            })?,
            Host::Ipv6(addr) => reject_non_routable_ipv6(addr).map_err(|_| {
                "encrypted media endpoint URL must not point at a non-routable address".to_owned()
            })?,
        },
        "http" if allow_loopback_http && is_loopback_host(host) => {}
        "http" => {
            return Err(
                "encrypted media endpoint URL scheme must be https unless loopback http is explicitly allowed"
                    .into(),
            );
        }
        _ => return Err("encrypted media endpoint URL scheme must be https".into()),
    }
    // Normalization is WHATWG parse-and-serialize, matching group-avatar-url-v1.md
    // and group-encrypted-media-v1.md. The serializer's output is the stored form:
    // it serializes an empty path as `/`, so do NOT strip a trailing slash here.
    let normalized = url.as_str();
    if normalized.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "encrypted media endpoint URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_locator_kinds(kinds: Vec<String>, label: &'static str) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for kind in kinds {
        let kind = normalize_locator_kind(&kind, label)?;
        if !normalized.iter().any(|existing| existing == &kind) {
            normalized.push(kind);
        }
    }
    Ok(normalized)
}

/// Producer-side locator-kind normalization: trims and lowercases, then enforces
/// the same canonical rule a decoder validates with [`validate_locator_kind`].
fn normalize_locator_kind(value: &str, label: &'static str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    validate_locator_kind(&value, label)?;
    Ok(value)
}

/// Canonical locator-kind rule per group-encrypted-media-v1.md: 1..64 bytes,
/// lowercase ASCII letters (`a-z`), digits (`0-9`), and `-`. This is a pure
/// validation (no trimming, case-folding, or rewriting) so it can run on the
/// strict decode path.
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

/// Strict decode-side check that a stored endpoint base URL is already canonical:
/// it validates as an encrypted-media endpoint URL AND is byte-equal to its own
/// producer-side normalization. A non-normalized URL is rejected, never repaired.
/// Loopback http is accepted as valid component state (per the spec, acting on it
/// is a separate local rule), so `allow_loopback_http` is `true` here.
fn validate_blob_endpoint_url_is_canonical(base_url: &str) -> Result<(), String> {
    let normalized = validate_and_normalize_blob_endpoint_url(base_url, true)?;
    if normalized != base_url {
        return Err("encrypted media endpoint base URL is not normalized".into());
    }
    Ok(())
}
