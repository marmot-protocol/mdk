use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use nostr::{EventBuilder, JsonUtil, Kind, NostrSigner, Tag, Timestamp as NostrTimestamp};
use serde::Deserialize;
use url::{Host, Url};

use super::host_safety::{
    is_loopback_host, reject_non_public_ip, validate_blossom_fetch_url,
    validate_profile_image_fetch_url,
};
use crate::{AppError, unix_now_seconds};

const BLOSSOM_UPLOAD_AUTH_TTL: Duration = Duration::from_secs(10 * 60);
const BLOSSOM_UPLOAD_CONTENT_TYPE: &str = "application/octet-stream";
const MAX_BLOSSOM_ERROR_BODY_BYTES: u64 = 1024;
pub(crate) const MAX_BLOSSOM_DESCRIPTOR_BYTES: u64 = 16 * 1024;
const MEDIA_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MEDIA_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MEDIA_HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
const BLOSSOM_REDIRECT_LIMIT: usize = 5;
pub(crate) const MAX_ENCRYPTED_MEDIA_BLOB_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct BlossomBlobDescriptor {
    url: Option<String>,
    sha256: Option<String>,
}

pub(crate) async fn upload_blossom_blob(
    server: &str,
    blob: &[u8],
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
    blob: &[u8],
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
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .header("X-SHA-256", blob_hash_hex)
        .body(blob.to_vec())
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
    let mut current = Url::parse(url)
        .map_err(|_| AppError::InvalidEncryptedMedia("media URL is invalid".into()))?;
    validate_blossom_fetch_url(&current, allow_loopback_http)
        .map_err(|err| AppError::BlobStore(format!("unsafe Blossom URL: {err}")))?;
    let mut redirects = 0_usize;

    loop {
        let client = media_http_client_for_url(&current, allow_loopback_http).await?;
        let response = client
            .get(current.clone())
            .send()
            .await
            .map_err(reqwest_blob_error)?;
        let status = response.status();
        if status.is_success() {
            return read_limited_blossom_body(response, MAX_ENCRYPTED_MEDIA_BLOB_BYTES).await;
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
        let next = current.join(location).map_err(|_| {
            AppError::BlobStore("redirect Location header is not a valid URL".into())
        })?;
        validate_blossom_redirect_target(&current, &next, allow_loopback_http)?;
        current = next;
        redirects += 1;
    }
}

pub(crate) async fn fetch_profile_image(url: &str, max_bytes: u64) -> Result<Vec<u8>, AppError> {
    profile_operation_timeout(
        MEDIA_HTTP_TOTAL_TIMEOUT,
        fetch_profile_image_impl(url, max_bytes, ProfileResolveMode::Production),
    )
    .await
}

#[cfg(test)]
pub(crate) async fn fetch_profile_image_with_injected_addrs(
    url: &str,
    max_bytes: u64,
    injected_addrs: Vec<SocketAddr>,
) -> Result<Vec<u8>, AppError> {
    profile_operation_timeout(
        MEDIA_HTTP_TOTAL_TIMEOUT,
        fetch_profile_image_impl(url, max_bytes, ProfileResolveMode::Injected(injected_addrs)),
    )
    .await
}

async fn profile_operation_timeout<T>(
    timeout: Duration,
    operation: impl std::future::Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| AppError::BlobStore("request timed out".into()))?
}

#[cfg(test)]
pub(super) async fn profile_operation_timeout_for_test(timeout: Duration) -> Result<(), AppError> {
    profile_operation_timeout(timeout, std::future::pending()).await
}

enum ProfileResolveMode {
    Production,
    #[cfg(test)]
    Injected(Vec<SocketAddr>),
}

async fn fetch_profile_image_impl(
    url: &str,
    max_bytes: u64,
    resolve_mode: ProfileResolveMode,
) -> Result<Vec<u8>, AppError> {
    let mut current = Url::parse(url)
        .map_err(|_| AppError::InvalidAppMessagePayload("profile image URL is invalid".into()))?;
    validate_profile_image_fetch_url(&current).map_err(|err| {
        AppError::InvalidAppMessagePayload(format!("unsafe profile image URL: {err}"))
    })?;
    let mut redirects = 0_usize;

    loop {
        let client = media_http_client_for_profile(&current, &resolve_mode).await?;
        let response = client
            .get(current.clone())
            .send()
            .await
            .map_err(reqwest_blob_error)?;
        let status = response.status();
        if status.is_success() {
            return read_limited_blossom_body(response, max_bytes).await;
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
        let next = current.join(location).map_err(|_| {
            AppError::BlobStore("redirect Location header is not a valid URL".into())
        })?;
        validate_profile_image_fetch_url(&next).map_err(|err| {
            AppError::InvalidAppMessagePayload(format!("unsafe profile image redirect URL: {err}"))
        })?;
        current = next;
        redirects += 1;
    }
}

#[cfg(test)]
pub(super) fn plan_profile_image_pin(
    url: &Url,
    injected_addrs: &[SocketAddr],
) -> Result<Option<(String, Vec<SocketAddr>)>, AppError> {
    match url
        .host()
        .ok_or_else(|| AppError::BlobStore("media URL is missing a host".into()))?
    {
        Host::Domain(domain) => validated_media_domain_pin(domain, injected_addrs, false).map(Some),
        _ => Ok(None),
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

async fn profile_media_pin(
    url: &Url,
    resolve_mode: &ProfileResolveMode,
) -> Result<Option<(String, Vec<SocketAddr>)>, AppError> {
    match resolve_mode {
        ProfileResolveMode::Production => resolve_media_host(url, false).await,
        #[cfg(test)]
        ProfileResolveMode::Injected(addrs) => plan_profile_image_pin(url, addrs),
    }
}

async fn media_http_client_for_profile(
    url: &Url,
    resolve_mode: &ProfileResolveMode,
) -> Result<reqwest::Client, AppError> {
    let pin = profile_media_pin(url, resolve_mode).await?;
    build_pinned_media_http_client(MEDIA_HTTP_TOTAL_TIMEOUT, pin)
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
    build_pinned_media_http_client(MEDIA_HTTP_TOTAL_TIMEOUT, pin)
}

fn build_pinned_media_http_client(
    operation_timeout: Duration,
    pin: Option<(String, Vec<SocketAddr>)>,
) -> Result<reqwest::Client, AppError> {
    let connect_timeout = operation_timeout.min(MEDIA_HTTP_CONNECT_TIMEOUT);
    let read_timeout = operation_timeout.min(MEDIA_HTTP_READ_TIMEOUT);
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        .timeout(operation_timeout)
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
