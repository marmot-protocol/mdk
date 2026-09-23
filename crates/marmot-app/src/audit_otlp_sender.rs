//! Inactive, single-attempt audit OTLP/HTTP sender.
//!
//! The caller prepares a [`DeliveryBatch`] under its local account ownership,
//! releases that ownership while `send` runs, then reacquires it to call
//! `LocalAuditDelivery::finish` only for a known response. No runtime constructs
//! this sender, and it does not configure a production endpoint.

use std::fmt;
use std::time::Duration;

use marmot_forensics::local_delivery::{DeliveryBatch, ReceiverResult};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{audit_log::audit_upload_host_is_retired, collector_host_safety, config};

const MAX_RECORDS: usize = 96;
const MAX_BODY_BYTES: usize = 65_535;
const MAX_WIRE_BYTES: usize = 1024 * 1024;

/// A sender outcome for one prepared range. Only `Complete` may advance its
/// cursor. `Blocked` needs caller intervention; `Unknown` needs another attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOtlpSendResult {
    Complete,
    Partial,
    Retryable,
    Blocked,
    Unknown,
}

impl AuditOtlpSendResult {
    /// Return a local finish action only where the journal has a safe one.
    /// `Blocked` has no finish action: the current local journal has no way to
    /// undo a permanent block after credentials, routing, or input are fixed.
    /// The caller must pause and surface it while retaining the prepared range.
    pub fn for_finish(self) -> Option<ReceiverResult> {
        match self {
            Self::Complete => Some(ReceiverResult::Complete),
            Self::Partial => Some(ReceiverResult::Partial),
            Self::Retryable => Some(ReceiverResult::Retryable),
            Self::Blocked | Self::Unknown => None,
        }
    }
}

/// Intentionally contains no URL, token, response body, or source data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditOtlpSenderConfigError;

impl fmt::Display for AuditOtlpSenderConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid audit OTLP sender configuration")
    }
}

impl std::error::Error for AuditOtlpSenderConfigError {}

/// Dedicated audit endpoint and credential, held in memory only. Debug is
/// intentionally opaque so callers cannot accidentally log either value.
pub struct AuditOtlpSender {
    destination: String,
    endpoint: Zeroizing<String>,
    token: Zeroizing<String>,
    timeout: Duration,
}

impl fmt::Debug for AuditOtlpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditOtlpSender { redacted }")
    }
}

impl AuditOtlpSender {
    /// Create an inactive sender for a dedicated `https://.../v1/logs` gateway.
    /// `destination` is the stable profile identity also passed to
    /// `LocalAuditDelivery::open`; it must remain stable across token rotation.
    /// Loopback endpoints require the explicit dev/test constructor below.
    pub fn new(
        destination: impl Into<String>,
        endpoint: impl Into<String>,
        bearer_token: impl Into<String>,
    ) -> Result<Self, AuditOtlpSenderConfigError> {
        Self::build(
            destination.into(),
            endpoint.into(),
            bearer_token.into(),
            false,
        )
    }

    /// Permit an exact `localhost` or loopback-IP endpoint for local tests and
    /// development. The shared dial gate still checks every resolved address.
    pub fn for_loopback_dev(
        destination: impl Into<String>,
        endpoint: impl Into<String>,
        bearer_token: impl Into<String>,
    ) -> Result<Self, AuditOtlpSenderConfigError> {
        Self::build(
            destination.into(),
            endpoint.into(),
            bearer_token.into(),
            true,
        )
    }

    fn build(
        destination: String,
        endpoint: String,
        bearer_token: String,
        allow_loopback: bool,
    ) -> Result<Self, AuditOtlpSenderConfigError> {
        let url =
            config::parse_relay_telemetry_endpoint(&endpoint).ok_or(AuditOtlpSenderConfigError)?;
        let host = url.host_str().ok_or(AuditOtlpSenderConfigError)?;
        if destination.is_empty()
            || destination.len() > 256
            || url.path() != "/v1/logs"
            || url.query().is_some()
            || audit_upload_host_is_retired(host)
            || (config::endpoint_host_is_loopback(&endpoint) && !allow_loopback)
            || bearer_token.is_empty()
            || !bearer_token.is_ascii()
            || bearer_token.bytes().any(|byte| byte.is_ascii_control())
            || reqwest::header::HeaderValue::from_str(&format!("Bearer {bearer_token}")).is_err()
        {
            return Err(AuditOtlpSenderConfigError);
        }
        Ok(Self {
            destination,
            endpoint: Zeroizing::new(endpoint),
            token: Zeroizing::new(bearer_token),
            timeout: collector_host_safety::REQUEST_TIMEOUT,
        })
    }

    /// Send one owned, already prepared range. The destination identity must
    /// match the identity passed to `LocalAuditDelivery::open`; a mismatch is
    /// blocked before dialing. No local lease or file handle is held here.
    pub async fn send(&self, batch: DeliveryBatch) -> AuditOtlpSendResult {
        if batch.token.destination() != self.destination.as_str() {
            return AuditOtlpSendResult::Blocked;
        }
        let Some(body) = encode_batch(batch) else {
            return AuditOtlpSendResult::Blocked;
        };
        match tokio::time::timeout(self.timeout, self.send_body(body)).await {
            Ok(result) => result,
            Err(_) => AuditOtlpSendResult::Unknown,
        }
    }

    async fn send_body(&self, body: Vec<u8>) -> AuditOtlpSendResult {
        let Ok(pin) = collector_host_safety::resolve_with(
            self.endpoint.as_str(),
            collector_host_safety::system_resolve,
        )
        .await
        else {
            return AuditOtlpSendResult::Unknown;
        };
        let Ok(client) = pin.build_client() else {
            return AuditOtlpSendResult::Unknown;
        };
        let Ok(response) = client
            .post(pin.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(self.token.as_str())
            .body(body)
            .send()
            .await
        else {
            return AuditOtlpSendResult::Unknown;
        };
        match response.status().as_u16() {
            409 => return AuditOtlpSendResult::Partial,
            429 | 500..=599 => return AuditOtlpSendResult::Retryable,
            200 => {}
            _ => return AuditOtlpSendResult::Blocked,
        }
        let valid_success_headers = response.content_length() == Some(2)
            && response.headers().get(reqwest::header::CONTENT_TYPE)
                == Some(&reqwest::header::HeaderValue::from_static(
                    "application/json",
                ))
            && !response
                .headers()
                .contains_key(reqwest::header::CONTENT_ENCODING)
            && !response
                .headers()
                .contains_key(reqwest::header::TRANSFER_ENCODING);
        if !valid_success_headers {
            return AuditOtlpSendResult::Blocked;
        }
        match response.bytes().await {
            Ok(body) if body.as_ref() == b"{}" => AuditOtlpSendResult::Complete,
            Ok(_) => AuditOtlpSendResult::Blocked,
            Err(_) => AuditOtlpSendResult::Unknown,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope<'a> {
    resource_logs: [ResourceLogs<'a>; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceLogs<'a> {
    scope_logs: [ScopeLogs<'a>; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeLogs<'a> {
    scope: Scope,
    log_records: Vec<LogRecord<'a>>,
}

#[derive(Serialize)]
struct Scope {
    name: &'static str,
}

#[derive(Serialize)]
struct LogRecord<'a> {
    body: StringValue<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StringValue<'a> {
    string_value: &'a str,
}

fn encode_batch(batch: DeliveryBatch) -> Option<Vec<u8>> {
    if !(1..=MAX_RECORDS).contains(&batch.bodies.len()) {
        return None;
    }
    let mut records = Vec::with_capacity(batch.bodies.len());
    for line in &batch.bodies {
        let body = line.strip_suffix(b"\n")?;
        if body.is_empty()
            || body.len() > MAX_BODY_BYTES
            || body.contains(&b'\r')
            || body.contains(&b'\n')
        {
            return None;
        }
        let body = std::str::from_utf8(body).ok()?;
        records.push(LogRecord {
            body: StringValue { string_value: body },
        });
    }
    let envelope = Envelope {
        resource_logs: [ResourceLogs {
            scope_logs: [ScopeLogs {
                scope: Scope {
                    name: "marmot.audit",
                },
                log_records: records,
            }],
        }],
    };
    let wire = serde_json::to_vec(&envelope).ok()?;
    (wire.len() <= MAX_WIRE_BYTES).then_some(wire)
}

#[cfg(test)]
mod tests;
