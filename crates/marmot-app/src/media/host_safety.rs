use std::net::IpAddr;

pub(crate) use cgka_traits::app_components::is_loopback_host;
use cgka_traits::app_components::{
    BLOSSOM_LOCATOR_KIND_V1, ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN, is_loopback_ip, is_public_ip,
};
use url::{Host, Url};

use super::MediaLocator;
use crate::AppError;

/// Structurally validate one locator. Per encrypted-media.md Validation a
/// receiver MUST reject a media reference ONLY for structural reasons: an empty
/// locator kind or value, or a value that does not parse as a URL. Whether a
/// well-formed locator is in the group policy or supported by this client is a
/// FETCHABILITY question, decided at fetch time (see `fetch_encrypted_media_blob`)
/// and before emitting an outbound reference (see `validate_outbound`); it MUST
/// NOT invalidate the reference or drop the containing message here.
pub(crate) fn validate_locator(
    locator: &MediaLocator,
    allow_loopback_http: bool,
) -> Result<(), AppError> {
    if locator.kind.trim().is_empty() || locator.value.trim().is_empty() {
        return Err(AppError::InvalidAppMessagePayload(
            "media locator kind and value cannot be empty".into(),
        ));
    }
    // The locator KIND is a fetchability concern, not a validity condition: an
    // out-of-policy or client-unsupported kind (e.g. a non-Blossom `ipfs://`
    // locator) is kept and handled at fetch time, never dropped here, because
    // media is authenticated by its hashes + AEAD independent of the locator.
    let url = Url::parse(&locator.value)
        .map_err(|_| AppError::InvalidAppMessagePayload("media locator URL is invalid".into()))?;
    // Host safety is the exception that DOES drop: a Blossom locator is one this
    // client will fetch over HTTP, so an unsafe host (loopback / non-public /
    // IPv6-transition) or cleartext scheme is a hostile request vector that
    // hash-authentication does not neutralize. Only Blossom locators are ever
    // fetched (`fetch_encrypted_media_blob` filters to them), so a non-Blossom
    // locator skips this check — it is unfetchable-by-this-client, not unsafe.
    if locator.kind == BLOSSOM_LOCATOR_KIND_V1 {
        validate_blossom_fetch_url(&url, allow_loopback_http).map_err(|err| {
            AppError::InvalidAppMessagePayload(format!("media locator URL is unsafe: {err}"))
        })?;
    }
    Ok(())
}

pub(crate) fn validate_blossom_fetch_url(
    url: &Url,
    allow_loopback_http: bool,
) -> Result<(), String> {
    if url.as_str().len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("URL must not include a fragment".into());
    }
    let host = url.host().ok_or("URL must include a host")?;
    match url.scheme() {
        "https" => validate_public_or_allowed_loopback_host(host, false),
        "http" if allow_loopback_http && is_loopback_host(host) => Ok(()),
        "http" => Err("URL scheme must be https".into()),
        _ => Err("URL scheme must be https".into()),
    }
}

fn validate_public_or_allowed_loopback_host(
    host: Host<&str>,
    allow_loopback: bool,
) -> Result<(), String> {
    match host {
        Host::Domain(domain) => {
            if is_loopback_host(Host::Domain(domain)) {
                return if allow_loopback {
                    Ok(())
                } else {
                    Err("URL must not point at localhost".into())
                };
            }
            Ok(())
        }
        Host::Ipv4(addr) => reject_non_public_ip(IpAddr::V4(addr), allow_loopback),
        Host::Ipv6(addr) => reject_non_public_ip(IpAddr::V6(addr), allow_loopback),
    }
}

pub(crate) fn reject_non_public_ip(addr: IpAddr, allow_loopback: bool) -> Result<(), String> {
    if (allow_loopback && is_loopback_ip(addr)) || is_public_ip(addr) {
        return Ok(());
    }
    Err("URL must not point at a non-public address".into())
}

/// Whether `url` is a loopback-HTTP blob endpoint: scheme `http` (cleartext)
/// AND a loopback host (`localhost`/`*.localhost`, 127.0.0.0/8, or `::1`). Such
/// endpoints are valid component state but must not be acted on outside dev/test
/// (see `MarmotAppConfig::allow_loopback_blob_endpoints`). A URL that does not
/// parse, uses HTTPS, or targets a routable host is not a loopback-HTTP endpoint.
pub(crate) fn is_loopback_http_endpoint(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    parsed.host().is_some_and(is_loopback_host)
}
