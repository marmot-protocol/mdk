use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use nostr::{EventBuilder, JsonUtil, Kind, NostrSigner, Tag, Timestamp as NostrTimestamp};
use serde::Deserialize;
use url::{Host, Url};

use super::host_safety::{
    is_loopback_host, parse_profile_image_fetch_url, parse_profile_image_redirect_url,
    reject_non_public_ip, validate_blossom_fetch_url,
};
use crate::{AppError, unix_now_seconds};

#[cfg(test)]
use cgka_traits::app_components::ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN;

const BLOSSOM_UPLOAD_AUTH_TTL: Duration = Duration::from_secs(10 * 60);
const BLOSSOM_UPLOAD_CONTENT_TYPE: &str = "application/octet-stream";
const MAX_BLOSSOM_ERROR_BODY_BYTES: u64 = 1024;
pub(crate) const MAX_BLOSSOM_DESCRIPTOR_BYTES: u64 = 16 * 1024;
const MEDIA_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MEDIA_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MEDIA_HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
const MEDIA_BLOB_TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const BLOSSOM_REDIRECT_LIMIT: usize = 5;
/// Largest encrypted media blob this implementation will upload or download.
///
/// The encrypted-media wire format has no 64 MiB protocol limit. Keep this
/// implementation bound finite for resource safety while allowing release APKs
/// and other substantial application artifacts.
pub const MAX_ENCRYPTED_MEDIA_BLOB_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct BlossomBlobDescriptor {
    url: Option<String>,
    sha256: Option<String>,
}

pub(crate) async fn upload_blossom_blob(
    server: &str,
    blob: Bytes,
    blob_hash_hex: &str,
    signer: &dyn NostrSigner,
    allow_loopback_http: bool,
) -> Result<String, AppError> {
    upload_blossom_blob_with_content_type(
        server,
        blob,
        blob_hash_hex,
        signer,
        allow_loopback_http,
        BLOSSOM_UPLOAD_CONTENT_TYPE,
        None,
    )
    .await
}

pub(crate) async fn upload_blossom_blob_with_content_type(
    server: &str,
    blob: Bytes,
    blob_hash_hex: &str,
    signer: &dyn NostrSigner,
    allow_loopback_http: bool,
    content_type: &str,
    fallback_extension: Option<&str>,
) -> Result<String, AppError> {
    let (upload_url, server_host) = blossom_upload_endpoint(server)?;
    let authorization = blossom_authorization_header(signer, &server_host, blob_hash_hex).await?;
    let client = media_http_client_for_url(&upload_url, allow_loopback_http).await?;
    let response = client
        .put(upload_url.clone())
        .timeout(MEDIA_BLOB_TRANSFER_TIMEOUT)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .header("X-SHA-256", blob_hash_hex)
        .body(blob)
        .send()
        .await
        .map_err(reqwest_blob_error)?;
    if !response.status().is_success() {
        return Err(blossom_upload_status_error(response).await);
    }
    let descriptor_body = read_limited_blossom_body(response, MAX_BLOSSOM_DESCRIPTOR_BYTES)
        .await
        .map_err(|_| AppError::BlobStore("upload descriptor exceeds size limit".into()))?;
    let descriptor = serde_json::from_slice::<BlossomBlobDescriptor>(&descriptor_body)
        .map_err(|_| AppError::BlobStore("upload returned an invalid descriptor".into()))?;
    if let Some(sha256) = descriptor.sha256.as_deref()
        && sha256.to_ascii_lowercase() != blob_hash_hex
    {
        return Err(AppError::BlobStore(
            "upload descriptor hash did not match blob".into(),
        ));
    }
    let url = descriptor
        .url
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| {
            blossom_blob_url_with_extension(server, blob_hash_hex, fallback_extension)
        });
    let parsed_url = Url::parse(&url)
        .map_err(|_| AppError::BlobStore("upload descriptor URL is invalid".into()))?;
    validate_blossom_redirect_host(&upload_url, &parsed_url)
        .map_err(|err| AppError::BlobStore(format!("unsafe upload descriptor host: {err}")))?;
    let content_hash = blossom_content_hash_from_url(&url).ok_or_else(|| {
        AppError::BlobStore("upload descriptor URL did not include blob hash".into())
    })?;
    if content_hash != blob_hash_hex {
        return Err(AppError::BlobStore(
            "upload descriptor URL hash did not match blob".into(),
        ));
    }
    Ok(url)
}

async fn blossom_upload_status_error(response: reqwest::Response) -> AppError {
    let status = response.status().as_u16();
    let header_reason = response
        .headers()
        .get("X-Reason")
        .and_then(|value| value.to_str().ok())
        .and_then(privacy_safe_server_reason);
    let body = read_limited_blossom_body(response, MAX_BLOSSOM_ERROR_BODY_BYTES)
        .await
        .ok();
    let body_reason = body
        .as_deref()
        .and_then(blossom_error_body_reason)
        .and_then(|reason| privacy_safe_server_reason(&reason));
    match header_reason.or(body_reason) {
        Some(reason) => AppError::BlobStore(format!("upload returned HTTP {status}: {reason}")),
        None => AppError::BlobStore(format!("upload returned HTTP {status}")),
    }
}

fn blossom_error_body_reason(body: &[u8]) -> Option<String> {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        return ["reason", "message", "error"]
            .into_iter()
            .find_map(|key| value.get(key).and_then(|value| value.as_str()))
            .map(str::to_owned);
    }
    std::str::from_utf8(body).ok().map(str::to_owned)
}

/// Keep server-provided diagnostics useful without allowing an untrusted
/// response to inject blob hashes, pubkeys, URLs, or unbounded text into app
/// errors that may later be logged.
fn privacy_safe_server_reason(reason: &str) -> Option<String> {
    let reason = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    if reason.is_empty()
        || reason.len() > 256
        || !reason
            .chars()
            .all(|character| character.is_ascii() && !character.is_ascii_control())
    {
        return None;
    }
    let lowercase = reason.to_ascii_lowercase();
    if ["://", "nostr:", "npub1", "nsec1"]
        .iter()
        .any(|needle| lowercase.contains(needle))
    {
        return None;
    }
    if reason.split_ascii_whitespace().any(|token| {
        // Collapse punctuation so hyphenated hashes and UUIDs still register
        // as one long identifier.
        let token: String = token.chars().filter(char::is_ascii_alphanumeric).collect();
        token.len() >= 48
            || (token.len() >= 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit()))
    }) {
        return None;
    }
    Some(reason)
}

pub(crate) async fn fetch_blossom_blob(
    url: &str,
    allow_loopback_http: bool,
) -> Result<Vec<u8>, AppError> {
    fetch_blossom_blob_limited(url, MAX_ENCRYPTED_MEDIA_BLOB_BYTES, allow_loopback_http).await
}

pub(crate) async fn fetch_blossom_blob_limited(
    url: &str,
    max_bytes: u64,
    allow_loopback_http: bool,
) -> Result<Vec<u8>, AppError> {
    let current = Url::parse(url)
        .map_err(|_| AppError::InvalidEncryptedMedia("media URL is invalid".into()))?;
    validate_blossom_fetch_url(&current, allow_loopback_http)
        .map_err(|err| AppError::BlobStore(format!("unsafe Blossom URL: {err}")))?;
    fetch_http_with_bounded_redirects(
        current,
        max_bytes,
        MEDIA_BLOB_TRANSFER_TIMEOUT,
        move |url| {
            let allow_loopback_http = allow_loopback_http;
            async move { media_http_client_for_url(&url, allow_loopback_http).await }
        },
        move |current, location| {
            let next = current.join(location).map_err(|_| {
                AppError::BlobStore("redirect Location header is not a valid URL".into())
            })?;
            validate_blossom_redirect_target(current, &next, allow_loopback_http)?;
            Ok(next)
        },
    )
    .await
}

pub(crate) async fn fetch_profile_image(url: &str, max_bytes: u64) -> Result<Vec<u8>, AppError> {
    profile_operation_timeout(fetch_profile_image_impl(url, max_bytes)).await
}

#[cfg(test)]
pub(crate) async fn fetch_profile_image_with_loopback(
    url: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, AppError> {
    let raw = url.trim();
    if raw.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(AppError::UnsafeMediaFetch(format!(
            "profile image URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        )));
    }
    let current = Url::parse(raw).map_err(|err| {
        AppError::UnsafeMediaFetch(format!("profile image URL is invalid: {err}"))
    })?;
    validate_blossom_fetch_url(&current, true).map_err(AppError::UnsafeMediaFetch)?;
    profile_operation_timeout(fetch_http_with_bounded_redirects(
        current,
        max_bytes,
        MEDIA_HTTP_TOTAL_TIMEOUT,
        move |url| async move { media_http_client_for_url(&url, true).await },
        move |current, location| {
            let raw_location = location.trim();
            if raw_location.len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
                return Err(AppError::UnsafeMediaFetch(format!(
                    "profile image redirect URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
                )));
            }
            let next = current.join(raw_location).map_err(|err| {
                AppError::UnsafeMediaFetch(format!(
                    "profile image redirect URL is invalid: {err}"
                ))
            })?;
            validate_blossom_fetch_url(&next, true).map_err(AppError::UnsafeMediaFetch)?;
            Ok(next)
        },
    ))
    .await
}

async fn profile_operation_timeout<T>(
    operation: impl std::future::Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    tokio::time::timeout(MEDIA_HTTP_TOTAL_TIMEOUT, operation)
        .await
        .map_err(|_| AppError::BlobStore("request timed out".into()))?
}

async fn fetch_profile_image_impl(url: &str, max_bytes: u64) -> Result<Vec<u8>, AppError> {
    let current = parse_profile_image_fetch_url(url).map_err(AppError::UnsafeMediaFetch)?;
    fetch_http_with_bounded_redirects(
        current,
        max_bytes,
        MEDIA_HTTP_TOTAL_TIMEOUT,
        move |url| async move { media_http_client_for_profile(&url).await },
        move |current, location| {
            parse_profile_image_redirect_url(current, location).map_err(AppError::UnsafeMediaFetch)
        },
    )
    .await
}

/// Vet every DNS answer before pinning a profile-image fetch.
pub(crate) fn vet_profile_fetch_resolved_addresses(addrs: &[SocketAddr]) -> Result<(), AppError> {
    for addr in addrs {
        reject_non_public_ip(addr.ip(), false).map_err(|err| {
            AppError::UnsafeMediaFetch(format!("unsafe profile image host address: {err}"))
        })?;
    }
    Ok(())
}

/// Shared manual redirect loop for Blossom blob and profile-image fetches.
/// Keep policy differences in the caller-supplied client and redirect validators.
async fn fetch_http_with_bounded_redirects<C, CFut, R>(
    mut current: Url,
    max_body_bytes: u64,
    request_timeout: Duration,
    mut client_for_url: C,
    mut redirect_target: R,
) -> Result<Vec<u8>, AppError>
where
    C: FnMut(Url) -> CFut,
    CFut: std::future::Future<Output = Result<reqwest::Client, AppError>>,
    R: FnMut(&Url, &str) -> Result<Url, AppError>,
{
    let mut redirects = 0_usize;
    let deadline = tokio::time::Instant::now() + request_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(AppError::BlobStore("request timed out".into()));
        }
        let client = tokio::time::timeout(remaining, client_for_url(current.clone()))
            .await
            .map_err(|_| AppError::BlobStore("request timed out".into()))??;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(AppError::BlobStore("request timed out".into()));
        }
        let response = client
            .get(current.clone())
            .timeout(remaining)
            .send()
            .await
            .map_err(reqwest_blob_error)?;
        let status = response.status();
        if status.is_success() {
            return read_limited_blossom_body(response, max_body_bytes).await;
        }
        if !status.is_redirection() {
            return Err(AppError::BlobStore(format!(
                "download returned HTTP {}",
                status.as_u16()
            )));
        }

        if redirects >= BLOSSOM_REDIRECT_LIMIT {
            return Err(AppError::BlobStore(format!(
                "media redirect chain exceeded {BLOSSOM_REDIRECT_LIMIT} hops"
            )));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or_else(|| {
                AppError::BlobStore("redirect response did not include Location".into())
            })?
            .to_str()
            .map_err(|_| AppError::BlobStore("redirect Location header is invalid".into()))?;
        current = redirect_target(&current, location)?;
        redirects += 1;
    }
}

fn validated_media_domain_pin(
    domain: &str,
    addrs: &[SocketAddr],
    allow_loopback: bool,
) -> Result<(String, Vec<SocketAddr>), AppError> {
    if addrs.is_empty() {
        return Err(AppError::BlobStore(
            "media host DNS lookup returned no addresses".into(),
        ));
    }
    for addr in addrs {
        reject_non_public_ip(addr.ip(), allow_loopback)
            .map_err(|err| AppError::BlobStore(format!("unsafe media host address: {err}")))?;
    }
    Ok((domain.to_ascii_lowercase(), addrs.to_vec()))
}

async fn media_http_client_for_profile(url: &Url) -> Result<reqwest::Client, AppError> {
    let pin = resolve_media_host_for_profile(url).await?;
    build_pinned_media_http_client(pin)
}

async fn resolve_media_host_for_profile(
    url: &Url,
) -> Result<Option<(String, Vec<SocketAddr>)>, AppError> {
    match url
        .host()
        .ok_or_else(|| AppError::UnsafeMediaFetch("profile image URL is missing a host".into()))?
    {
        Host::Domain(domain) => {
            let port = url.port_or_known_default().ok_or_else(|| {
                AppError::UnsafeMediaFetch("profile image URL is missing a fetch port".into())
            })?;
            let addrs = tokio::net::lookup_host((domain, port))
                .await
                .map_err(|_| AppError::BlobStore("media host DNS lookup failed".into()))?
                .collect::<Vec<_>>();
            if addrs.is_empty() {
                return Err(AppError::BlobStore(
                    "media host DNS lookup returned no addresses".into(),
                ));
            }
            vet_profile_fetch_resolved_addresses(&addrs)?;
            Ok(Some((domain.to_ascii_lowercase(), addrs)))
        }
        Host::Ipv4(addr) => {
            reject_non_public_ip(IpAddr::V4(addr), false).map_err(|err| {
                AppError::UnsafeMediaFetch(format!("unsafe profile image host address: {err}"))
            })?;
            Ok(None)
        }
        Host::Ipv6(addr) => {
            reject_non_public_ip(IpAddr::V6(addr), false).map_err(|err| {
                AppError::UnsafeMediaFetch(format!("unsafe profile image host address: {err}"))
            })?;
            Ok(None)
        }
    }
}

pub(super) fn validate_blossom_redirect_target(
    current: &Url,
    next: &Url,
    allow_loopback_http: bool,
) -> Result<(), AppError> {
    validate_blossom_fetch_url(next, allow_loopback_http)
        .map_err(|err| AppError::BlobStore(format!("unsafe Blossom redirect URL: {err}")))?;
    validate_blossom_redirect_host(current, next)
        .map_err(|err| AppError::BlobStore(format!("unsafe Blossom redirect host: {err}")))
}

fn validate_blossom_redirect_host(current: &Url, next: &Url) -> Result<(), String> {
    let current_host = current
        .host()
        .ok_or("redirect source URL must include a host")?;
    let next_host = next
        .host()
        .ok_or("redirect target URL must include a host")?;
    if url_hosts_match(&current_host, &next_host) {
        return Ok(());
    }
    match (current_host, next_host) {
        (Host::Domain(current_domain), Host::Domain(next_domain))
            if same_registrable_domain(current_domain, next_domain) =>
        {
            Ok(())
        }
        _ => Err("redirect host must stay on the same host or registrable domain".into()),
    }
}

fn url_hosts_match(left: &Host<&str>, right: &Host<&str>) -> bool {
    match (left, right) {
        (Host::Domain(left), Host::Domain(right)) => left.eq_ignore_ascii_case(right),
        (Host::Ipv4(left), Host::Ipv4(right)) => left == right,
        (Host::Ipv6(left), Host::Ipv6(right)) => left == right,
        _ => false,
    }
}

fn same_registrable_domain(left: &str, right: &str) -> bool {
    let left = left.trim_end_matches('.').to_ascii_lowercase();
    let right = right.trim_end_matches('.').to_ascii_lowercase();
    match (psl::domain_str(&left), psl::domain_str(&right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

async fn media_http_client_for_url(
    url: &Url,
    allow_loopback_http: bool,
) -> Result<reqwest::Client, AppError> {
    validate_blossom_fetch_url(url, allow_loopback_http)
        .map_err(|err| AppError::BlobStore(format!("unsafe Blossom URL: {err}")))?;
    let allow_loopback = url.scheme() == "http"
        && allow_loopback_http
        && url.host().map(is_loopback_host).unwrap_or(false);
    let pin = resolve_media_host(url, allow_loopback).await?;
    build_pinned_media_http_client(pin)
}

fn build_pinned_media_http_client(
    pin: Option<(String, Vec<SocketAddr>)>,
) -> Result<reqwest::Client, AppError> {
    build_pinned_media_http_client_from_builder(reqwest::Client::builder(), pin)
}

fn build_pinned_media_http_client_from_builder(
    builder: reqwest::ClientBuilder,
    pin: Option<(String, Vec<SocketAddr>)>,
) -> Result<reqwest::Client, AppError> {
    let mut builder = builder
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(MEDIA_HTTP_CONNECT_TIMEOUT)
        .read_timeout(MEDIA_HTTP_READ_TIMEOUT)
        .timeout(MEDIA_HTTP_TOTAL_TIMEOUT)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate();
    if let Some((domain, addrs)) = pin {
        builder = builder.resolve_to_addrs(&domain, &addrs);
    }
    builder
        .build()
        .map_err(|_| AppError::BlobStore("failed to build HTTP client".into()))
}

#[cfg(test)]
pub(super) fn build_pinned_media_http_client_with_proxy_for_test(
    pin: Option<(String, Vec<SocketAddr>)>,
    proxy_url: &str,
) -> Result<reqwest::Client, AppError> {
    let proxy = reqwest::Proxy::all(proxy_url)
        .map_err(|_| AppError::BlobStore("failed to configure test HTTP proxy".into()))?;
    build_pinned_media_http_client_from_builder(reqwest::Client::builder().proxy(proxy), pin)
}

async fn resolve_media_host(
    url: &Url,
    allow_loopback: bool,
) -> Result<Option<(String, Vec<SocketAddr>)>, AppError> {
    match url
        .host()
        .ok_or_else(|| AppError::BlobStore("Blossom URL is missing a host".into()))?
    {
        Host::Domain(domain) => {
            let port = url
                .port_or_known_default()
                .ok_or_else(|| AppError::BlobStore("Blossom URL is missing a fetch port".into()))?;
            let addrs = tokio::net::lookup_host((domain, port))
                .await
                .map_err(|_| AppError::BlobStore("media host DNS lookup failed".into()))?
                .collect::<Vec<_>>();
            validated_media_domain_pin(domain, &addrs, allow_loopback).map(Some)
        }
        Host::Ipv4(addr) => {
            reject_non_public_ip(IpAddr::V4(addr), allow_loopback)
                .map_err(|err| AppError::BlobStore(format!("unsafe media host address: {err}")))?;
            Ok(None)
        }
        Host::Ipv6(addr) => {
            reject_non_public_ip(IpAddr::V6(addr), allow_loopback)
                .map_err(|err| AppError::BlobStore(format!("unsafe media host address: {err}")))?;
            Ok(None)
        }
    }
}

pub(crate) async fn read_limited_blossom_body(
    response: reqwest::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, AppError> {
    if let Some(content_length) = response.content_length()
        && content_length > max_bytes
    {
        return Err(AppError::BlobStore(format!(
            "download exceeds {max_bytes} bytes"
        )));
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(reqwest_blob_error)? {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| AppError::BlobStore(format!("download exceeds {max_bytes} bytes")))?;
        if next_len as u64 > max_bytes {
            return Err(AppError::BlobStore(format!(
                "download exceeds {max_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn blossom_upload_endpoint(server: &str) -> Result<(Url, String), AppError> {
    let mut url = Url::parse(server.trim())
        .map_err(|_| AppError::BlobStore("invalid Blossom server URL".into()))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::BlobStore(
                "Blossom server URL must be http or https".into(),
            ));
        }
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::BlobStore("Blossom server URL is missing a host".into()))?
        .to_ascii_lowercase();
    url.set_path("upload");
    url.set_query(None);
    url.set_fragment(None);
    Ok((url, host))
}

pub(crate) fn blossom_blob_url(server: &str, encrypted_hash_hex: &str) -> String {
    blossom_blob_url_with_extension(server, encrypted_hash_hex, Some(".bin"))
}

fn blossom_blob_url_with_extension(
    server: &str,
    hash_hex: &str,
    extension: Option<&str>,
) -> String {
    let suffix = extension.unwrap_or_default();
    match Url::parse(server.trim()) {
        Ok(mut url) => {
            url.set_path(&format!("{hash_hex}{suffix}"));
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => format!("{}/{}{}", server.trim_end_matches('/'), hash_hex, suffix),
    }
}

pub(crate) fn blossom_content_hash_from_url(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    let path = url.path();
    let bytes = path.as_bytes();
    bytes.windows(64).rev().find_map(|window| {
        let candidate = std::str::from_utf8(window).ok()?;
        (candidate.len() == 64 && hex::decode(candidate).is_ok())
            .then(|| candidate.to_ascii_lowercase())
    })
}

async fn blossom_authorization_header(
    signer: &dyn NostrSigner,
    server_host: &str,
    encrypted_hash_hex: &str,
) -> Result<String, AppError> {
    let now = unix_now_seconds();
    let expiration = now + BLOSSOM_UPLOAD_AUTH_TTL.as_secs();
    let tags = [
        Tag::parse(["t", "upload"]),
        Tag::parse(["expiration", &expiration.to_string()]),
        Tag::parse(["x", encrypted_hash_hex]),
        Tag::parse(["server", server_host]),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|err| AppError::BlobStore(format!("failed to build Blossom auth tag: {err}")))?;
    let public_key = signer
        .get_public_key()
        .await
        .map_err(|err| crate::external_signer_error(err, "Blossom auth public key"))?;
    let unsigned = EventBuilder::new(Kind::Custom(24242), "Upload Blob")
        .tags(tags)
        .custom_created_at(NostrTimestamp::from(now))
        .build(public_key);
    let event = signer
        .sign_event(unsigned)
        .await
        .map_err(|err| crate::external_signer_error(err, "Blossom auth"))?;
    Ok(format!(
        "Nostr {}",
        BASE64_URL_SAFE_NO_PAD.encode(event.as_json())
    ))
}

fn reqwest_blob_error(err: reqwest::Error) -> AppError {
    if let Some(status) = err.status() {
        AppError::BlobStore(format!("HTTP {}", status.as_u16()))
    } else if err.is_timeout() {
        AppError::BlobStore("request timed out".into())
    } else if err.is_connect() {
        AppError::BlobStore("connection failed".into())
    } else if err.is_decode() {
        AppError::BlobStore("invalid response body".into())
    } else {
        AppError::BlobStore("request failed".into())
    }
}
