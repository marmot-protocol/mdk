//! The HTTP half of the historical v4 forensic audit upload (#2627): snapshot
//! capture, the per-account upload checkpoint record, endpoint validation, the
//! request and the response handling.
//!
//! `MarmotApp` (`audit_log.rs`) keeps the files: it validates and opens each
//! audit file, reads and writes the checkpoint file, and hands this module the
//! open file or the checkpoint it read. Nothing here opens a file. Failures are
//! [`AuditUploadError`], which `marmot-app` converts back to the `AppError` the
//! upload built before it had its own type.

use std::future::Future;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use transport_nostr::retired_relay_hosts;

use crate::{collector_host_safety, export_config};

const AUDIT_LOG_CONTENT_TYPE: &str = "application/x-ndjson";
// The whole-file Goggles endpoint accepts the historical v4 contract only.
// New v5 records use the separately configured, explicit OTLP delivery path.
const GOGGLES_UPLOAD_SCHEMA_VERSION: &str = "marmot-forensics-audit/v4";
pub const AUDIT_LOG_UPLOAD_MAX_BYTES: u64 = 64 * 1024 * 1024;
const AUDIT_LOG_UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) static AUDIT_UPLOAD_SCHEMA: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema = serde_json::from_str(include_str!(
        "../../marmot-forensics/schema/audit-log-event.v4.schema.json"
    ))
    .expect("bundled audit schema must be valid JSON");
    jsonschema::validator_for(&schema).expect("bundled audit schema must compile offline")
});

/// A failure of the upload half. Messages are context-free: no endpoint,
/// address, token, header or file content.
///
/// `From<AuditUploadError> for AppError` restores the variant, message and
/// `privacy_safe_kind` the upload built before it had its own type.
#[derive(Debug, thiserror::Error)]
pub enum AuditUploadError {
    #[error("invalid audit log file: {0}")]
    InvalidAuditLogFile(String),
    #[error("audit log upload failed: {0}")]
    AuditLogUpload(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// What the endpoint made of one complete snapshot. `marmot-app` adds the
/// path it opened to report the public upload result.
pub struct AuditSnapshotReceipt {
    pub status: u16,
    pub bytes_sent: u64,
    pub observed_bytes: u64,
    pub modified_at_ms: Option<u64>,
    pub complete: bool,
}

/// One snapshot's upload, short of a request failure.
pub enum AuditSnapshotPost {
    Uploaded(AuditSnapshotReceipt),
    Ineligible {
        observed_bytes: u64,
        modified_at_ms: Option<u64>,
    },
    /// No complete line yet; nothing was sent.
    Deferred,
    Rejected {
        status: u16,
        retry_after: Option<Duration>,
    },
}

/// Retry-After accepts either delta seconds or an HTTP date. Bound untrusted
/// deadlines to five minutes so one response cannot silence incident evidence for a day.
/// `None` means the header was absent. A header we cannot parse is still a
/// request to retry, so it yields a zero minimum instead of disappearing.
fn audit_retry_after(value: Option<&str>, now: SystemTime) -> Option<Duration> {
    let value = value?.trim();
    let delay = value
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
        .or_else(|| {
            httpdate::parse_http_date(value)
                .ok()
                .map(|date| date.duration_since(now).unwrap_or_default())
        })
        .unwrap_or_default();
    Some(delay.min(Duration::from_secs(5 * 60)))
}

pub struct AuditUploadSnapshot {
    pub(crate) body: Vec<u8>,
    pub(crate) observed_bytes: u64,
    pub(crate) modified_at_ms: Option<u64>,
    pub(crate) complete: bool,
}

impl AuditUploadSnapshot {
    /// Capture from a file `marmot-app` has already validated and opened.
    pub async fn capture(file: tokio::fs::File) -> Result<Self, AuditUploadError> {
        let metadata = file.metadata().await?;
        let observed_bytes = metadata.len();
        if observed_bytes > AUDIT_LOG_UPLOAD_MAX_BYTES {
            return Err(AuditUploadError::AuditLogUpload(format!(
                "audit log exceeds {} byte upload limit",
                AUDIT_LOG_UPLOAD_MAX_BYTES
            )));
        }
        let mut body = Vec::with_capacity(observed_bytes as usize);
        // Opening once preserves identity across rename/replacement. Bounding
        // the read excludes later appends, but is not sufficient by itself:
        // metadata can have sampled the middle of a JSONL write/flush.
        file.take(observed_bytes).read_to_end(&mut body).await?;
        let end = body
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |i| i + 1);
        body.truncate(end);
        Ok(Self {
            complete: body.len() as u64 == observed_bytes,
            body,
            observed_bytes,
            modified_at_ms: metadata.modified().ok().and_then(system_time_ms),
        })
    }

    /// Validate the exact immutable bytes that will be sent. No legacy migration
    /// or redaction: a single invalid complete row rejects the whole snapshot.
    fn validate(&self) -> Result<(), AuditUploadError> {
        let mut has_record = false;
        for line in self.body.split(|byte| *byte == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            // Strict typed decoding also rejects duplicate and unknown fields
            // before serde_json::Value could collapse duplicate object keys.
            let event = serde_json::from_slice::<marmot_forensics::AuditEvent>(line)
                .map_err(|_| invalid_audit_upload())?;
            if event.schema_version != GOGGLES_UPLOAD_SCHEMA_VERSION {
                return Err(invalid_audit_upload());
            }
            let value: serde_json::Value =
                serde_json::from_slice(line).map_err(|_| invalid_audit_upload())?;
            if !AUDIT_UPLOAD_SCHEMA.is_valid(&value) {
                return Err(invalid_audit_upload());
            }
            has_record = true;
        }
        if has_record {
            Ok(())
        } else {
            Err(invalid_audit_upload())
        }
    }
}

/// Test hooks for `marmot-app`'s audit tests (#2627): what a capture read.
#[cfg(any(test, feature = "test-support"))]
impl AuditUploadSnapshot {
    pub fn body_for_test(&self) -> &[u8] {
        &self.body
    }

    pub fn complete_for_test(&self) -> bool {
        self.complete
    }
}

pub fn invalid_audit_upload() -> AuditUploadError {
    // Never expose schema validation errors: they can contain the rejected data.
    AuditUploadError::InvalidAuditLogFile(
        "only valid v4 forensic audit records may be uploaded".into(),
    )
}

/// What the tracker already did with one audit file.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditUploadOutcome {
    /// The endpoint accepted the file's whole content.
    Uploaded,
    /// The tracker will not re-post this file's content: it is over the local
    /// `AUDIT_LOG_UPLOAD_MAX_BYTES` ceiling, or the endpoint answered `413`
    /// without `Retry-After` (RFC 9110 15.5.14 has a server send that header
    /// when the refusal is temporary). Recorded so the tracker reports it once
    /// instead of re-attempting on every trigger. Like every checkpoint entry
    /// it is keyed on the file's size and mtime, so deleting the sidecar clears
    /// it, and a manual per-file upload never consults it. A `413` that
    /// carries `Retry-After` is a cooldown, not this outcome.
    TooLargeToUpload,
    /// Contains legacy, malformed, or schema-ineligible records. Never sent.
    IneligibleSchema,
}

/// An audit file as the account's listing saw it: the checkpoint's key and the
/// metadata its entries are compared against.
#[derive(Clone, Copy, Debug)]
pub struct ListedAuditFile<'a> {
    pub file_name: &'a str,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
}

/// One acknowledged audit file, identified by the size and mtime it had when
/// the tracker was done with it.
///
/// Identity is metadata, not a content hash, precisely because the point of the
/// checkpoint is to *avoid reading* the file again. Audit files only ever grow
/// (segments never change at all), so a later enumeration reporting the exact
/// same pair means the acknowledged content is still the whole file. Every
/// mismatch — including the racy ones, where the file grew between enumeration
/// and upload — falls back to re-uploading, which the endpoint's `file_sha256`
/// short-circuit absorbs without parsing.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AuditUploadCheckpointEntry {
    size_bytes: u64,
    #[serde(default)]
    modified_at_ms: Option<u64>,
    outcome: AuditUploadOutcome,
}

/// Per-account upload checkpoint (mdk#1181).
///
/// Losing or corrupting this file is safe by design: the worst case is that
/// each still-present file transfers once more, and the upload endpoint
/// short-circuits a byte-identical re-upload on `file_sha256` without parsing
/// a line. That is why it is a plain sidecar rather than a migration in the
/// account database.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditUploadCheckpoint {
    #[serde(default)]
    files: std::collections::BTreeMap<String, AuditUploadCheckpointEntry>,
}

impl AuditUploadCheckpoint {
    /// What the tracker already did with `file`, if its content is unchanged
    /// since then.
    pub fn acknowledged<'a>(
        &self,
        file: impl Into<ListedAuditFile<'a>>,
    ) -> Option<AuditUploadOutcome> {
        let file = file.into();
        self.files
            .get(file.file_name)
            .filter(|entry| {
                entry.size_bytes == file.size_bytes && entry.modified_at_ms == file.modified_at_ms
            })
            .map(|entry| entry.outcome)
    }

    /// Record an oversized/ineligible-file verdict or an accepted complete snapshot.
    /// Successful uploads are checked against enumeration before checkpointing.
    pub fn acknowledge<'a>(
        &mut self,
        file: impl Into<ListedAuditFile<'a>>,
        acknowledged_bytes: u64,
        outcome: AuditUploadOutcome,
    ) {
        let file = file.into();
        self.files.insert(
            file.file_name.to_owned(),
            AuditUploadCheckpointEntry {
                size_bytes: acknowledged_bytes,
                modified_at_ms: file.modified_at_ms,
                outcome,
            },
        );
    }

    /// Drop entries for files that are no longer on disk, so the sidecar stays
    /// bounded by the account's live audit files. Returns whether anything
    /// changed.
    pub fn retain_present<'a>(&mut self, present: impl IntoIterator<Item = &'a str>) -> bool {
        let present: std::collections::BTreeSet<&str> = present.into_iter().collect();
        let before = self.files.len();
        self.files.retain(|name, _| present.contains(name.as_str()));
        before != self.files.len()
    }
}

/// Milliseconds since the Unix epoch. The listing and the snapshot both use it,
/// so a checkpoint entry's mtime compares equal to an unchanged file's.
pub fn system_time_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

pub(crate) fn audit_upload_host_is_retired(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    retired_relay_hosts()
        .iter()
        .any(|retired| host.eq_ignore_ascii_case(retired))
}

pub fn validate_audit_upload_endpoint(
    endpoint: &str,
    authorization_bearer_token: Option<&str>,
) -> Result<String, AuditUploadError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(AuditUploadError::AuditLogUpload(
            "forensic upload endpoint is empty".to_owned(),
        ));
    }
    let Some(url) = export_config::parse_relay_telemetry_endpoint(endpoint) else {
        return Err(AuditUploadError::AuditLogUpload(
            if export_config::endpoint_transport_allowed(endpoint) {
                "forensic upload endpoint is invalid".to_owned()
            } else {
                "forensic upload endpoint must be https, or loopback http for local testing"
                    .to_owned()
            },
        ));
    };
    if url.host_str().is_some_and(audit_upload_host_is_retired) {
        return Err(AuditUploadError::AuditLogUpload(
            "forensic upload endpoint is not allowed".to_owned(),
        ));
    }
    if !export_config::endpoint_host_is_loopback(endpoint)
        && authorization_bearer_token.is_none_or(|token| token.trim().is_empty())
    {
        return Err(AuditUploadError::AuditLogUpload(
            "forensic upload endpoint requires an authorization bearer token unless it is loopback"
                .to_owned(),
        ));
    }
    Ok(endpoint.to_owned())
}

/// Post one captured snapshot to an endpoint that passed
/// [`validate_audit_upload_endpoint`]. An empty complete-line prefix is
/// deferred without an HTTP request.
pub async fn post_audit_upload_snapshot(
    snapshot: AuditUploadSnapshot,
    endpoint: &str,
    authorization_bearer_token: Option<&str>,
    hardware_model: Option<&str>,
    platform: Option<&str>,
    app_version: Option<&str>,
) -> Result<AuditSnapshotPost, AuditUploadError> {
    if snapshot.body.is_empty() {
        return Ok(AuditSnapshotPost::Deferred);
    }
    // Validation of a bounded but potentially large file is CPU work. Keep
    // it off runtime workers; cancellation still prevents the later POST.
    let (snapshot, eligible) = tokio::task::spawn_blocking(move || {
        let eligible = snapshot.validate().is_ok();
        (snapshot, eligible)
    })
    .await
    .map_err(|_| AuditUploadError::AuditLogUpload("audit validation worker failed".into()))?;
    if !eligible {
        return Ok(AuditSnapshotPost::Ineligible {
            observed_bytes: snapshot.observed_bytes,
            modified_at_ms: snapshot.modified_at_ms,
        });
    }
    let bytes_sent = snapshot.body.len() as u64;
    let response = audit_network_attempt(send_audit_upload(
        endpoint,
        snapshot.body,
        authorization_bearer_token,
        hardware_model,
        platform,
        app_version,
        collector_host_safety::system_resolve,
    ))
    .await?;
    let status = response.status();
    if !status.is_success() {
        return Ok(AuditSnapshotPost::Rejected {
            status: status.as_u16(),
            retry_after: audit_retry_after(
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .map(|value| value.to_str().unwrap_or_default()),
                SystemTime::now(),
            ),
        });
    }
    Ok(AuditSnapshotPost::Uploaded(AuditSnapshotReceipt {
        status: status.as_u16(),
        bytes_sent,
        observed_bytes: snapshot.observed_bytes,
        modified_at_ms: snapshot.modified_at_ms,
        complete: snapshot.complete,
    }))
}

async fn audit_network_attempt<T, Fut>(op: Fut) -> Result<T, AuditUploadError>
where
    Fut: Future<Output = Result<T, AuditUploadError>>,
{
    tokio::time::timeout(AUDIT_LOG_UPLOAD_TIMEOUT, op)
        .await
        .map_err(|_| AuditUploadError::AuditLogUpload("request timed out".into()))?
}

async fn send_audit_upload<F, Fut>(
    endpoint: &str,
    body: Vec<u8>,
    authorization_bearer_token: Option<&str>,
    hardware_model: Option<&str>,
    platform: Option<&str>,
    app_version: Option<&str>,
    resolver: F,
) -> Result<reqwest::Response, AuditUploadError>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<IpAddr>>>,
{
    let pin = collector_host_safety::resolve_with(endpoint, resolver)
        .await
        .map_err(|_| AuditUploadError::AuditLogUpload("request failed".into()))?;
    let client = pin
        .build_client()
        .map_err(|_| AuditUploadError::AuditLogUpload("request failed".into()))?;
    audit_upload_request(
        &client,
        pin.url,
        body,
        authorization_bearer_token,
        hardware_model,
        platform,
        app_version,
    )
    .send()
    .await
    .map_err(audit_log_reqwest_error)
}

fn audit_upload_request(
    client: &reqwest::Client,
    url: reqwest::Url,
    body: Vec<u8>,
    authorization_bearer_token: Option<&str>,
    hardware_model: Option<&str>,
    platform: Option<&str>,
    app_version: Option<&str>,
) -> reqwest::RequestBuilder {
    let bytes_sent = body.len() as u64;
    let mut request = client
        .post(url)
        .timeout(AUDIT_LOG_UPLOAD_TIMEOUT)
        .header(reqwest::header::CONTENT_TYPE, AUDIT_LOG_CONTENT_TYPE)
        .header(reqwest::header::CONTENT_LENGTH, bytes_sent)
        .body(body);
    if let Some(token) = authorization_bearer_token {
        request = request.bearer_auth(token);
    }
    if let Some(value) = hardware_model {
        request = request.header("X-Goggles-Hardware-Model", value);
    }
    if let Some(value) = platform {
        request = request.header("X-Goggles-Platform", value);
    }
    if let Some(value) = app_version {
        request = request.header("X-Goggles-App-Version", value);
    }
    request
}

fn audit_log_reqwest_error(err: reqwest::Error) -> AuditUploadError {
    if let Some(status) = err.status() {
        AuditUploadError::AuditLogUpload(format!("HTTP {}", status.as_u16()))
    } else if err.is_timeout() {
        AuditUploadError::AuditLogUpload("request timed out".into())
    } else if err.is_connect() {
        AuditUploadError::AuditLogUpload("connection failed".into())
    } else if err.is_body() {
        AuditUploadError::AuditLogUpload("invalid response body".into())
    } else {
        AuditUploadError::AuditLogUpload("request failed".into())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use super::*;

    #[test]
    fn retry_after_supports_seconds_dates_and_bounded_invalid_input() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(
            audit_retry_after(Some("120"), now),
            Some(Duration::from_secs(120))
        );
        let date = httpdate::fmt_http_date(now + Duration::from_secs(180));
        assert_eq!(
            audit_retry_after(Some(&date), now),
            Some(Duration::from_secs(180))
        );
        let past = httpdate::fmt_http_date(now - Duration::from_secs(1));
        assert_eq!(audit_retry_after(Some(&past), now), Some(Duration::ZERO));
        assert_eq!(
            audit_retry_after(Some("18446744073709551615"), now),
            Some(Duration::from_secs(300))
        );
        assert_eq!(audit_retry_after(None, now), None);
        for malformed in ["nonsense", "-1", ""] {
            assert_eq!(
                audit_retry_after(Some(malformed), now),
                Some(Duration::ZERO),
                "a malformed Retry-After is still a request to retry"
            );
        }
    }

    fn assert_privacy_safe(error: &AuditUploadError) {
        let display = error.to_string();
        let debug = format!("{error:?}");
        for leak in [
            "secret.example",
            "secret-query",
            "bearer-secret",
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "Location",
            "/stolen",
        ] {
            assert!(
                !display.contains(leak) && !debug.contains(leak),
                "leaked {leak} via {display} / {debug}"
            );
        }
    }

    #[test]
    fn audit_upload_timeouts_keep_sixty_second_request_and_thirty_second_collector() {
        assert_eq!(AUDIT_LOG_UPLOAD_TIMEOUT, Duration::from_secs(60));
        assert_eq!(
            collector_host_safety::REQUEST_TIMEOUT,
            Duration::from_secs(30)
        );
        assert_eq!(
            collector_host_safety::CONNECT_TIMEOUT,
            Duration::from_secs(10)
        );
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn audit_upload_request_overrides_the_collector_timeout() {
        let client = reqwest::Client::builder()
            .timeout(collector_host_safety::REQUEST_TIMEOUT)
            .build()
            .expect("collector-default client");
        let request = audit_upload_request(
            &client,
            "https://example.test/ingest".parse().expect("url"),
            Vec::new(),
            None,
            None,
            None,
            None,
        )
        .build()
        .expect("audit request");
        assert_eq!(request.timeout(), Some(&AUDIT_LOG_UPLOAD_TIMEOUT));
        assert_ne!(
            request.timeout(),
            Some(&collector_host_safety::REQUEST_TIMEOUT)
        );
    }

    #[test]
    fn audit_endpoint_gate_rejects_structure_retired_hosts_and_missing_tokens() {
        let retired = retired_relay_hosts()
            .into_iter()
            .next()
            .expect("centralized retired host list");
        for endpoint in [
            "",
            "   ",
            "http://public.example/ingest",
            "http://10.0.0.1/ingest",
            "http://dev.localhost/ingest",
            "ftp://localhost/ingest",
            "https://user:password@secret.example/path?token=secret-query",
            "https://secret.example/path?token=secret-query#frag",
            "https://secret.example:0/ingest",
            "https:///",
            &format!("https://{retired}/ingest"),
            &format!("https://{}/ingest", retired.to_ascii_uppercase()),
            &format!("https://{retired}./ingest"),
        ] {
            let err = validate_audit_upload_endpoint(endpoint, Some("bearer-secret")).unwrap_err();
            assert_privacy_safe(&err);
        }
        let remote = "https://secret.example/path?token=secret-query";
        let missing_token = validate_audit_upload_endpoint(remote, None).unwrap_err();
        assert!(
            missing_token
                .to_string()
                .contains("authorization bearer token")
        );
        assert_privacy_safe(&missing_token);
        let subdomain =
            validate_audit_upload_endpoint("https://dev.localhost/ingest", None).unwrap_err();
        assert!(
            subdomain.to_string().contains("authorization bearer token"),
            "localhost subdomains are not the local-test exception"
        );
        assert_privacy_safe(&subdomain);
        assert!(
            validate_audit_upload_endpoint("http://127.0.0.1:9/ingest", None).is_ok(),
            "literal loopback remains the local-test opt-in"
        );
        assert!(validate_audit_upload_endpoint("https://localhost/ingest", None).is_ok());
        assert!(
            validate_audit_upload_endpoint(remote, Some("bearer-secret")).is_ok(),
            "structurally valid public HTTPS with a token is admitted before DNS"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_helper_failures_are_context_free() {
        let marker = "https://secret.example/path?token=secret-query";
        let errors = [
            send_audit_upload(
                marker,
                Vec::new(),
                Some("bearer-secret"),
                None,
                None,
                None,
                |_, _| async { Ok(Vec::new()) },
            )
            .await
            .unwrap_err(),
            send_audit_upload(
                marker,
                Vec::new(),
                Some("bearer-secret"),
                None,
                None,
                None,
                |_, _| async {
                    Err(std::io::Error::other(
                        "secret.example secret-query 127.0.0.1 bearer-secret",
                    ))
                },
            )
            .await
            .unwrap_err(),
            send_audit_upload(
                marker,
                Vec::new(),
                Some("bearer-secret"),
                None,
                None,
                None,
                |_, _| async { Ok(vec!["10.0.0.1".parse().unwrap()]) },
            )
            .await
            .unwrap_err(),
            send_audit_upload(
                "https://10.0.0.1/ingest",
                Vec::new(),
                Some("bearer-secret"),
                None,
                None,
                None,
                |_, _| async { panic!("literal address must not use DNS") },
            )
            .await
            .unwrap_err(),
        ];
        for error in errors {
            assert_eq!(error.to_string(), "audit log upload failed: request failed");
            assert_privacy_safe(&error);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_structure_never_resolves() {
        for endpoint in [
            "http://public.example/ingest",
            "https://user:password@secret.example/",
            "https://secret.example/#frag",
        ] {
            assert!(
                send_audit_upload(
                    endpoint,
                    Vec::new(),
                    Some("bearer-secret"),
                    None,
                    None,
                    None,
                    |_, _| async {
                        panic!("invalid URL reached DNS");
                    }
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn audit_network_deadline_is_sixty_seconds() {
        let start = tokio::time::Instant::now();
        let error = audit_network_attempt(async {
            std::future::pending::<Result<reqwest::Response, AuditUploadError>>().await
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "audit log upload failed: request timed out"
        );
        assert_eq!(start.elapsed(), AUDIT_LOG_UPLOAD_TIMEOUT);
        assert_privacy_safe(&error);
    }

    #[tokio::test(start_paused = true)]
    async fn audit_resolution_keeps_the_shared_ten_second_dns_bound() {
        let start = tokio::time::Instant::now();
        let error = send_audit_upload(
            "https://secret.example/path?token=secret-query",
            Vec::new(),
            Some("bearer-secret"),
            None,
            None,
            None,
            |_, _| async { std::future::pending().await },
        )
        .await
        .unwrap_err();
        assert_eq!(start.elapsed(), collector_host_safety::CONNECT_TIMEOUT);
        assert_eq!(error.to_string(), "audit log upload failed: request failed");
        assert_privacy_safe(&error);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::disallowed_methods)]
    async fn upload_snapshot_excludes_unfinished_tail_and_recovers_it_later() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-active.jsonl");
        let prefix = b"{\"seq\":1}\n";
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(b"{\"seq\":2,\"value\":\"part");
        fs::write(&path, &bytes).unwrap();
        let snapshot = AuditUploadSnapshot::capture(tokio::fs::File::open(&path).await.unwrap())
            .await
            .unwrap();
        assert_eq!(snapshot.body, prefix);
        assert!(!snapshot.complete);
        let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(b"ial\"}\n").unwrap();
        let complete = AuditUploadSnapshot::capture(tokio::fs::File::open(&path).await.unwrap())
            .await
            .unwrap();
        assert!(complete.complete);
        let rows: Vec<serde_json::Value> = std::str::from_utf8(&complete.body)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["value"], "partial");
        assert_eq!(
            snapshot.body, prefix,
            "later appends cannot mutate the captured request"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::disallowed_methods)]
    async fn upload_snapshot_keeps_the_opened_file_across_path_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-active.jsonl");
        fs::write(&path, b"{\"seq\":1}\n").unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();
        fs::rename(&path, dir.path().join("audit-segment.jsonl")).unwrap();
        fs::write(&path, b"{\"seq\":2}\n").unwrap();
        let snapshot = AuditUploadSnapshot::capture(file).await.unwrap();
        assert_eq!(snapshot.body, b"{\"seq\":1}\n");
        assert!(snapshot.complete);
    }
}
