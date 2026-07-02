//! `marmot.group.avatar-url.v1` component state and codec.

use url::{Host, Url};

use super::codec::{decode_var_bytes, encode_var_bytes};
use super::host_safety::{reject_non_routable_ipv4, reject_non_routable_ipv6};
use super::{GROUP_AVATAR_HINT_MAX_LEN, GROUP_AVATAR_URL_MAX_LEN};

/// Decoded `marmot.group.avatar-url.v1` state. An absent avatar is an empty `url`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupAvatarUrlV1 {
    pub url: String,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

/// Encode `marmot.group.avatar-url.v1` state. The URL is validated and normalized;
/// an empty `url` encodes the absent/cleared avatar (all fields empty).
pub fn encode_group_avatar_url_v1(avatar: &GroupAvatarUrlV1) -> Result<Vec<u8>, String> {
    if avatar.url.is_empty() && (avatar.dim.is_some() || avatar.thumbhash.is_some()) {
        return Err("group avatar absent state must not include hints".into());
    }
    let url = if avatar.url.is_empty() {
        String::new()
    } else {
        validate_and_normalize_group_avatar_url(&avatar.url)?
    };
    let dim = avatar.dim.as_deref().unwrap_or("");
    let thumbhash = avatar.thumbhash.as_deref().unwrap_or("");
    if dim.len() > GROUP_AVATAR_HINT_MAX_LEN {
        return Err(format!(
            "group avatar dim exceeds {GROUP_AVATAR_HINT_MAX_LEN} bytes"
        ));
    }
    if thumbhash.len() > GROUP_AVATAR_HINT_MAX_LEN {
        return Err(format!(
            "group avatar thumbhash exceeds {GROUP_AVATAR_HINT_MAX_LEN} bytes"
        ));
    }
    let mut out = Vec::with_capacity(url.len() + dim.len() + thumbhash.len() + 6);
    encode_var_bytes(url.as_bytes(), &mut out);
    encode_var_bytes(dim.as_bytes(), &mut out);
    encode_var_bytes(thumbhash.as_bytes(), &mut out);
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
    // `dim` and `thumbhash` are opaque length-bounded hints: a decoder validates
    // only their length (done above by decode_var_bytes) and interprets the bytes
    // as UTF-8 only for rendering. A non-UTF-8 hint is treated as ABSENT and MUST
    // NOT invalidate otherwise-valid state (spec/app-components/group-avatar-url-v1.md
    // and spec/foundation/canonical-encoding.md, "opaque hints"). Rejecting it
    // here would make the same commit accepted by some clients and not others.
    Ok(GroupAvatarUrlV1 {
        url,
        dim: if dim.is_empty() {
            None
        } else {
            String::from_utf8(dim).ok()
        },
        thumbhash: if thumbhash.is_empty() {
            None
        } else {
            String::from_utf8(thumbhash).ok()
        },
    })
}

/// Validate and normalize a group avatar URL: `https` only, length-bounded, no
/// credentials or fragment, and not pointing at localhost or a non-routable IP.
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
    match url.host().ok_or("group avatar URL must include a host")? {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            if lowered == "localhost" || lowered.ends_with(".localhost") {
                return Err("group avatar URL must not point at localhost".into());
            }
        }
        Host::Ipv4(addr) => reject_non_routable_ipv4(addr)?,
        Host::Ipv6(addr) => reject_non_routable_ipv6(addr)?,
    }
    let normalized = url.as_str();
    if normalized.len() > GROUP_AVATAR_URL_MAX_LEN {
        return Err(format!(
            "group avatar URL exceeds {GROUP_AVATAR_URL_MAX_LEN} bytes"
        ));
    }
    Ok(normalized.to_owned())
}
