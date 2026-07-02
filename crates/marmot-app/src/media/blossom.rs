use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use nostr::{EventBuilder, JsonUtil, Kind, Tag, Timestamp as NostrTimestamp};
use serde::Deserialize;
use url::{Host, Url};

use super::host_safety::{is_loopback_host, reject_non_public_ip, validate_blossom_fetch_url};
use crate::{AppError, unix_now_seconds};

const BLOSSOM_UPLOAD_AUTH_TTL: Duration = Duration::from_secs(10 * 60);
const BLOSSOM_UPLOAD_CONTENT_TYPE: &str = "application/octet-stream";
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
    encrypted: &[u8],
    encrypted_hash_hex: &str,
    signing_keys: &nostr::Keys,
    allow_loopback_http: bool,
) -> Result<String, AppError> {
    let (upload_url, server_host) = blossom_upload_endpoint(server)?;
    let authorization =
        blossom_authorization_header(signing_keys, &server_host, encrypted_hash_hex)?;
    let client = media_http_client_for_url(&upload_url, allow_loopback_http).await?;
    let response = client
        .put(upload_url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, BLOSSOM_UPLOAD_CONTENT_TYPE)
        .header("X-SHA-256", encrypted_hash_hex)
        .body(encrypted.to_vec())
        .send()
        .await
        .map_err(reqwest_blob_error)?;
    if !response.status().is_success() {
        return Err(AppError::BlobStore(format!(
            "upload returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let descriptor = response
        .json::<BlossomBlobDescriptor>()
        .await
        .map_err(|_| AppError::BlobStore("upload returned an invalid descriptor".into()))?;
    if let Some(sha256) = descriptor.sha256.as_deref()
        && sha256.to_ascii_lowercase() != encrypted_hash_hex
    {
        return Err(AppError::BlobStore(
            "upload descriptor hash did not match encrypted blob".into(),
        ));
    }
    let url = descriptor
        .url
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| blossom_blob_url(server, encrypted_hash_hex));
    let content_hash = blossom_content_hash_from_url(&url).ok_or_else(|| {
        AppError::BlobStore("upload descriptor URL did not include encrypted blob hash".into())
    })?;
    if content_hash != encrypted_hash_hex {
        return Err(AppError::BlobStore(
            "upload descriptor URL hash did not match encrypted blob".into(),
        ));
    }
    Ok(url)
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
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(MEDIA_HTTP_CONNECT_TIMEOUT)
        .read_timeout(MEDIA_HTTP_READ_TIMEOUT)
        .timeout(MEDIA_HTTP_TOTAL_TIMEOUT)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate();
    if let Some((domain, addrs)) = resolve_media_host(url, allow_loopback_http).await? {
        builder = builder.resolve_to_addrs(&domain, &addrs);
    }
    builder
        .build()
        .map_err(|_| AppError::BlobStore("failed to build HTTP client".into()))
}

async fn resolve_media_host(
    url: &Url,
    allow_loopback_http: bool,
) -> Result<Option<(String, Vec<SocketAddr>)>, AppError> {
    let allow_loopback = url.scheme() == "http"
        && allow_loopback_http
        && url.host().map(is_loopback_host).unwrap_or(false);
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
            if addrs.is_empty() {
                return Err(AppError::BlobStore(
                    "media host DNS lookup returned no addresses".into(),
                ));
            }
            for addr in &addrs {
                reject_non_public_ip(addr.ip(), allow_loopback).map_err(|err| {
                    AppError::BlobStore(format!("unsafe media host address: {err}"))
                })?;
            }
            Ok(Some((domain.to_ascii_lowercase(), addrs)))
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
    match Url::parse(server.trim()) {
        Ok(mut url) => {
            url.set_path(&format!("{encrypted_hash_hex}.bin"));
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => format!(
            "{}/{}.bin",
            server.trim_end_matches('/'),
            encrypted_hash_hex
        ),
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

fn blossom_authorization_header(
    keys: &nostr::Keys,
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
    let event = EventBuilder::new(Kind::Custom(24242), "Upload Blob")
        .tags(tags)
        .custom_created_at(NostrTimestamp::from(now))
        .sign_with_keys(keys)
        .map_err(|err| AppError::BlobStore(format!("failed to sign Blossom auth: {err}")))?;
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
