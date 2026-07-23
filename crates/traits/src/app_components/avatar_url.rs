//! `marmot.group.avatar-url.v1` component state and codec.

use url::Url;

use super::codec::{decode_var_bytes, encode_var_bytes};
use super::{GROUP_AVATAR_HINT_MAX_LEN, GROUP_AVATAR_URL_MAX_LEN};

/// Decoded `marmot.group.avatar-url.v1` state. An absent avatar is an empty `url`.
/// Render hints stay as opaque bytes so decoding and re-encoding never rewrites
/// or drops a valid hint that an application cannot interpret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupAvatarUrlV1 {
    pub url: String,
    pub dim: Vec<u8>,
    pub thumbhash: Vec<u8>,
}

/// Encode `marmot.group.avatar-url.v1` state. The URL is validated and normalized;
/// an empty `url` encodes the absent/cleared avatar (all fields empty).
pub fn encode_group_avatar_url_v1(avatar: &GroupAvatarUrlV1) -> Result<Vec<u8>, String> {
    if avatar.url.is_empty() && (!avatar.dim.is_empty() || !avatar.thumbhash.is_empty()) {
        return Err("group avatar absent state must not include hints".into());
    }
    if avatar.dim.len() > GROUP_AVATAR_HINT_MAX_LEN {
        return Err(format!(
            "group avatar dim exceeds {GROUP_AVATAR_HINT_MAX_LEN} bytes"
        ));
    }
    if avatar.thumbhash.len() > GROUP_AVATAR_HINT_MAX_LEN {
        return Err(format!(
            "group avatar thumbhash exceeds {GROUP_AVATAR_HINT_MAX_LEN} bytes"
        ));
    }
    let url = if avatar.url.is_empty() {
        String::new()
    } else {
        validate_and_normalize_group_avatar_url(&avatar.url)?
    };
    let mut out = Vec::with_capacity(url.len() + avatar.dim.len() + avatar.thumbhash.len() + 6);
    encode_var_bytes(url.as_bytes(), &mut out);
    encode_var_bytes(&avatar.dim, &mut out);
    encode_var_bytes(&avatar.thumbhash, &mut out);
    Ok(out)
}

/// Decode `marmot.group.avatar-url.v1` state, re-validating a present URL.
pub fn decode_group_avatar_url_v1(bytes: &[u8]) -> Result<GroupAvatarUrlV1, String> {
    let mut cursor = bytes;
    let url = decode_var_bytes(&mut cursor, GROUP_AVATAR_URL_MAX_LEN, "group avatar URL")?;
    let dim = decode_var_bytes(&mut cursor, GROUP_AVATAR_HINT_MAX_LEN, "group avatar dim")?;
    let thumbhash = decode_var_bytes(
        &mut cursor,
        GROUP_AVATAR_HINT_MAX_LEN,
        "group avatar thumbhash",
    )?;
    if !cursor.is_empty() {
        return Err("group avatar component has trailing bytes".into());
    }
    let url = String::from_utf8(url).map_err(|e| format!("group avatar URL is not UTF-8: {e}"))?;
    // Presence is decided on the raw bytes: an absent state carries no hints.
    if url.is_empty() && (!dim.is_empty() || !thumbhash.is_empty()) {
        return Err("group avatar absent state must not include hints".into());
    }
    if !url.is_empty() {
        // Compare against normalized bytes so a non-normalized stored URL is rejected.
        let normalized = validate_and_normalize_group_avatar_url(&url)?;
        if normalized != url {
            return Err("group avatar URL is not normalized".into());
        }
    }
    // `dim` and `thumbhash` are opaque length-bounded hints. Preserve their exact
    // bytes here; interpretation belongs at the application rendering boundary.
    Ok(GroupAvatarUrlV1 {
        url,
        dim,
        thumbhash,
    })
}

/// Validate and normalize a group avatar URL: `https` only, length-bounded, no
/// credentials or fragment. Destination contact safety is local application
/// policy and deliberately does not affect component validity.
/// Returns the normalized URL string.
pub fn validate_and_normalize_group_avatar_url(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("group avatar URL must not be empty".into());
    }
    if raw.len() > GROUP_AVATAR_URL_MAX_LEN {
        return Err(format!(
            "group avatar URL exceeds {GROUP_AVATAR_URL_MAX_LEN} bytes"
        ));
    }
    let url = Url::parse(raw).map_err(|e| format!("group avatar URL is invalid: {e}"))?;
    if url.scheme() != "https" {
        return Err("group avatar URL scheme must be https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("group avatar URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("group avatar URL must not include a fragment".into());
    }
    url.host().ok_or("group avatar URL must include a host")?;
    let normalized = url.as_str();
    if normalized.len() > GROUP_AVATAR_URL_MAX_LEN {
        return Err(format!(
            "group avatar URL exceeds {GROUP_AVATAR_URL_MAX_LEN} bytes"
        ));
    }
    Ok(normalized.to_owned())
}
