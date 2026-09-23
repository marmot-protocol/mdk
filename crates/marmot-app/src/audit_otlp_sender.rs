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

use crate::{collector_host_safety, config, retired_relay_hosts};

const MAX_RECORDS: usize = 96;
const MAX_BODY_BYTES: usize = 65_535;
const MAX_WIRE_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024;

/// A receiver outcome for one prepared range. Only `Complete` may advance its
/// cursor. `Unknown` means no response can be applied to the local journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOtlpSendResult {
    Complete,
    Partial,
    Retryable,
    Blocked,
    Unknown,
}

impl AuditOtlpSendResult {
    /// Convert only an observed receiver verdict into a local finish action.
    /// A lost or unreadable response leaves the prepared range untouched.
    pub fn for_finish(self) -> Option<ReceiverResult> {
        match self {
            Self::Complete => Some(ReceiverResult::Complete),
            Self::Partial => Some(ReceiverResult::Partial),
            Self::Retryable => Some(ReceiverResult::Retryable),
            Self::Blocked => Some(ReceiverResult::Permanent),
            Self::Unknown => None,
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
    /// Loopback endpoints require the explicit dev/test constructor below.
    pub fn new(
        endpoint: impl Into<String>,
        bearer_token: impl Into<String>,
    ) -> Result<Self, AuditOtlpSenderConfigError> {
        Self::build(endpoint.into(), bearer_token.into(), false)
    }

    /// Permit an exact `localhost` or loopback-IP endpoint for local tests and
    /// development. The shared dial gate still checks every resolved address.
    pub fn for_loopback_dev(
        endpoint: impl Into<String>,
        bearer_token: impl Into<String>,
    ) -> Result<Self, AuditOtlpSenderConfigError> {
        Self::build(endpoint.into(), bearer_token.into(), true)
    }

    fn build(
        endpoint: String,
        bearer_token: String,
        allow_loopback: bool,
    ) -> Result<Self, AuditOtlpSenderConfigError> {
        let url =
            config::parse_relay_telemetry_endpoint(&endpoint).ok_or(AuditOtlpSenderConfigError)?;
        let host = url.host_str().ok_or(AuditOtlpSenderConfigError)?;
        if url.path() != "/v1/logs"
            || url.query().is_some()
            || retired_relay_hosts()
                .iter()
                .any(|retired| host.trim_end_matches('.').eq_ignore_ascii_case(retired))
            || (config::endpoint_host_is_loopback(&endpoint) && !allow_loopback)
            || bearer_token.is_empty()
            || !bearer_token.is_ascii()
            || bearer_token.bytes().any(|byte| byte.is_ascii_control())
            || reqwest::header::HeaderValue::from_str(&format!("Bearer {bearer_token}")).is_err()
        {
            return Err(AuditOtlpSenderConfigError);
        }
        Ok(Self {
            endpoint: Zeroizing::new(endpoint),
            token: Zeroizing::new(bearer_token),
            timeout: collector_host_safety::REQUEST_TIMEOUT,
        })
    }

    /// Send one owned, already prepared range. No local lease or file handle is
    /// held here. A network error after request acceptance is always `Unknown`.
    pub async fn send(&self, batch: DeliveryBatch) -> AuditOtlpSendResult {
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
        let Ok(mut response) = client
            .post(pin.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(self.token.as_str())
            .body(body)
            .send()
            .await
        else {
            return AuditOtlpSendResult::Unknown;
        };
        let status = response.status().as_u16();
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
        let mut response_body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if response_body.len() + chunk.len() <= MAX_RESPONSE_BYTES => {
                    response_body.extend_from_slice(&chunk);
                }
                // A bounded read is enough to reject a malformed success.
                // An explicit retryable or partial status retains its meaning
                // even when its diagnostic body is larger than our budget.
                Ok(Some(_)) => {
                    return match status {
                        409 => AuditOtlpSendResult::Partial,
                        429 | 500..=599 => AuditOtlpSendResult::Retryable,
                        _ => AuditOtlpSendResult::Blocked,
                    };
                }
                Ok(None) => break,
                Err(_) => return AuditOtlpSendResult::Unknown,
            }
        }
        match status {
            200 if valid_success_headers && response_body == b"{}" => AuditOtlpSendResult::Complete,
            409 => AuditOtlpSendResult::Partial,
            429 | 500..=599 => AuditOtlpSendResult::Retryable,
            _ => AuditOtlpSendResult::Blocked,
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
