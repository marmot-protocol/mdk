//! Versioned persisted outcomes, independent of the evolving public SendSummary.
use cgka_traits::{SendAcceptDisposition, SendMaintenanceDisposition};
use serde::{Deserialize, Serialize};

use crate::{AppError, LocalSendStatus, SendSummary};

#[derive(Serialize, Deserialize)]
struct RetainedLocalOutcome {
    version: u8,
    summary: OutcomeV1,
}

// Freeze these fields and discriminants for v1. Public DTO changes must update
// the explicit conversion, and a new storage shape needs a new version decoder.
#[derive(Serialize, Deserialize)]
struct OutcomeV1 {
    published: u64,
    message_ids: Vec<String>,
    accept_disposition: AcceptanceV1,
    maintenance_disposition: MaintenanceV1,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcceptanceV1 {
    Published,
    AcceptedPending,
    CompletionUnknown,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MaintenanceV1 {
    Ready,
    PostJoinRotationPendingRetryable,
}

/// A send MDK refused instead of sending, stored where a summary would be.
#[derive(Serialize, Deserialize)]
struct RetainedLocalRefusal {
    version: u8,
    refused: RefusalV1,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RefusalV1 {
    NewMembers,
}

pub(crate) fn encode_refused_new_members() -> String {
    serde_json::to_string(&RetainedLocalRefusal {
        version: 1,
        refused: RefusalV1::NewMembers,
    })
    .expect("a unit refusal serializes")
}

fn invalid_outcome() -> AppError {
    AppError::InvalidAppMessagePayload("invalid local submission outcome".into())
}

pub(super) fn encode_local_outcome(summary: &SendSummary) -> Result<String, AppError> {
    serde_json::to_string(&RetainedLocalOutcome {
        version: 1,
        summary: OutcomeV1 {
            published: summary
                .published
                .try_into()
                .map_err(|_| invalid_outcome())?,
            message_ids: summary.message_ids.clone(),
            accept_disposition: match summary.accept_disposition {
                SendAcceptDisposition::Published => AcceptanceV1::Published,
                SendAcceptDisposition::AcceptedPending => AcceptanceV1::AcceptedPending,
                SendAcceptDisposition::CompletionUnknown => AcceptanceV1::CompletionUnknown,
            },
            maintenance_disposition: match summary.maintenance_disposition {
                SendMaintenanceDisposition::Ready => MaintenanceV1::Ready,
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable => {
                    MaintenanceV1::PostJoinRotationPendingRetryable
                }
            },
        },
    })
    .map_err(|_| invalid_outcome())
}

pub(crate) fn decode_local_outcome(json: &str) -> Result<LocalSendStatus, AppError> {
    if let Ok(refusal) = serde_json::from_str::<RetainedLocalRefusal>(json) {
        if refusal.version != 1 {
            return Err(AppError::InvalidAppMessagePayload(
                "unsupported local submission outcome version".into(),
            ));
        }
        return Ok(match refusal.refused {
            RefusalV1::NewMembers => LocalSendStatus::RefusedNewMembers,
        });
    }
    let retained: RetainedLocalOutcome =
        serde_json::from_str(json).map_err(|_| invalid_outcome())?;
    if retained.version != 1 {
        return Err(AppError::InvalidAppMessagePayload(
            "unsupported local submission outcome version".into(),
        ));
    }
    Ok(LocalSendStatus::Completed(SendSummary {
        published: retained
            .summary
            .published
            .try_into()
            .map_err(|_| invalid_outcome())?,
        message_ids: retained.summary.message_ids,
        accept_disposition: match retained.summary.accept_disposition {
            AcceptanceV1::Published => SendAcceptDisposition::Published,
            AcceptanceV1::AcceptedPending => SendAcceptDisposition::AcceptedPending,
            AcceptanceV1::CompletionUnknown => SendAcceptDisposition::CompletionUnknown,
        },
        maintenance_disposition: match retained.summary.maintenance_disposition {
            MaintenanceV1::Ready => SendMaintenanceDisposition::Ready,
            MaintenanceV1::PostJoinRotationPendingRetryable => {
                SendMaintenanceDisposition::PostJoinRotationPendingRetryable
            }
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_outcome_v1_fixtures_keep_all_dispositions() {
        for (acceptance, accept_disposition) in [
            ("published", SendAcceptDisposition::Published),
            ("accepted_pending", SendAcceptDisposition::AcceptedPending),
            (
                "completion_unknown",
                SendAcceptDisposition::CompletionUnknown,
            ),
        ] {
            for (maintenance, maintenance_disposition) in [
                ("ready", SendMaintenanceDisposition::Ready),
                (
                    "post_join_rotation_pending_retryable",
                    SendMaintenanceDisposition::PostJoinRotationPendingRetryable,
                ),
            ] {
                // Literal storage fields/variants pin v1 independently of the encoder.
                let fixture = format!(
                    r#"{{"version":1,"summary":{{"published":2,"message_ids":["message"],"accept_disposition":"{acceptance}","maintenance_disposition":"{maintenance}"}}}}"#
                );
                let expected = SendSummary {
                    published: 2,
                    message_ids: vec!["message".into()],
                    accept_disposition,
                    maintenance_disposition,
                };
                assert_eq!(
                    decode_local_outcome(&fixture).unwrap(),
                    LocalSendStatus::Completed(expected.clone())
                );
                assert_eq!(encode_local_outcome(&expected).unwrap(), fixture);
                assert!(
                    decode_local_outcome(&fixture.replace("\"version\":1", "\"version\":2"))
                        .is_err()
                );
                assert!(decode_local_outcome(&fixture.replace("\"version\":1,", "")).is_err());
            }
        }
    }

    #[test]
    fn persisted_new_members_refusal_v1_fixture() {
        let fixture = r#"{"version":1,"refused":"new_members"}"#;
        assert_eq!(
            decode_local_outcome(fixture).unwrap(),
            LocalSendStatus::RefusedNewMembers
        );
        assert_eq!(encode_refused_new_members(), fixture);
        assert!(decode_local_outcome(&fixture.replace("1", "2")).is_err());
    }
}
