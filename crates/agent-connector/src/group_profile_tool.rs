//! Bounded, backend-independent group profile command over the existing socket.

use std::path::PathBuf;
use std::time::Duration;

use agent_control::{AgentControlRequest, AgentControlResponse};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::bootstrap::ControlClient;

/// Explicit local route; deliberately excludes secrets and identifiers from Debug.
pub struct GroupProfileToolConfig {
    pub socket: PathBuf,
    pub auth_token: Option<String>,
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub request_timeout: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    name: Option<String>,
    description: Option<String>,
}

/// Update once, without retries. Transport/protocol failures have unknown outcome.
pub async fn run_group_profile_tool(config: GroupProfileToolConfig, input: &[u8]) -> Value {
    let invalid = || json!({"ok": false, "error": "invalid_group_profile_input"});
    if input.len() > 8192 || config.request_timeout.is_zero() {
        return invalid();
    }
    let Ok(patch) = serde_json::from_slice::<Patch>(input) else {
        return invalid();
    };
    if patch.name.is_none() && patch.description.is_none()
        || patch.name.as_ref().is_some_and(|v| v.len() > 256)
        || patch.description.as_ref().is_some_and(|v| v.len() > 4096)
    {
        return invalid();
    }
    let account = config.account_id_hex.trim().to_ascii_lowercase();
    let group = config.group_id_hex.trim().to_ascii_lowercase();
    if !hex::decode(&account).is_ok_and(|v| v.len() == 32)
        || !hex::decode(&group).is_ok_and(|v| !v.is_empty())
    {
        return invalid();
    }
    let client = ControlClient::new(config.socket, config.auth_token, config.request_timeout);
    match client
        .request(AgentControlRequest::GroupProfileUpdate {
            account_id_hex: account,
            group_id_hex: group.clone(),
            name: patch.name,
            description: patch.description,
        })
        .await
    {
        Ok(response) => match response.payload {
            AgentControlResponse::GroupProfileUpdated {
                group_id_hex,
                message_ids_hex,
            } if group_id_hex == group
                && !message_ids_hex.is_empty()
                && message_ids_hex
                    .iter()
                    .all(|id| hex::decode(id).is_ok_and(|bytes| bytes.len() == 32)) =>
            {
                json!({"ok": true, "group_id_hex": group_id_hex, "message_ids_hex": message_ids_hex})
            }
            AgentControlResponse::Error {
                code, retryable, ..
            } => control_error(code, retryable),
            _ => unknown_outcome(),
        },
        Err(_) => unknown_outcome(),
    }
}

fn control_error(code: String, retryable: bool) -> Value {
    // Only explicit pre-mutation validation/authorization errors prove rejection.
    // A generic app/storage/publish error can occur after the commit is durable,
    // even when the connector marks that error non-retryable.
    if !retryable
        && matches!(
            code.as_str(),
            "not_group_admin" | "invalid_group_profile" | "unauthorized" | "invalid_hex"
        )
    {
        return json!({"ok": false, "error": code, "outcome": "rejected", "retryable": false,
            "control_retryable": retryable});
    }
    let mut result = unknown_outcome();
    result["control_error"] = json!(code);
    // Preserve the wire flag separately from permission to repeat this mutation.
    result["control_retryable"] = json!(retryable);
    result
}

fn unknown_outcome() -> Value {
    json!({"ok": false, "error": "group_profile_outcome_unknown", "outcome": "unknown",
        "retryable": false, "hint": "Check the current group details before retrying; the update may have committed."})
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_control::{AgentControlEnvelope, read_envelope, write_frame};
    use tokio::io::BufReader;
    use tokio::net::UnixListener;

    fn config(socket: PathBuf) -> GroupProfileToolConfig {
        GroupProfileToolConfig {
            socket,
            auth_token: Some("test-token".into()),
            account_id_hex: "11".repeat(32),
            group_id_hex: "22".repeat(16),
            request_timeout: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn validates_utf8_byte_limits_and_requires_a_change_before_connecting() {
        let root = tempfile::tempdir().unwrap();
        for patch in [
            json!({}),
            json!({"name": "é".repeat(129)}),
            json!({"description": "a".repeat(4097)}),
            json!({"relays": []}),
        ] {
            let result = run_group_profile_tool(
                config(root.path().join("absent")),
                &serde_json::to_vec(&patch).unwrap(),
            )
            .await;
            assert_eq!(result["error"], "invalid_group_profile_input");
        }
    }

    #[tokio::test]
    async fn partial_update_clear_admin_rejection_and_unknown_outcome_use_one_request() {
        let root = tempfile::tempdir().unwrap();
        for scenario in 0..7 {
            let socket = root.path().join(format!("socket-{scenario}"));
            let listener = UnixListener::bind(&socket).unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let request = read_envelope::<_, AgentControlRequest>(&mut reader)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(request.auth_token.as_deref(), Some("test-token"));
                let AgentControlRequest::GroupProfileUpdate {
                    account_id_hex,
                    group_id_hex,
                    name,
                    description,
                } = request.payload
                else {
                    panic!("wrong request")
                };
                assert_eq!(account_id_hex, "11".repeat(32));
                assert_eq!(group_id_hex, "22".repeat(16));
                assert_eq!(name, None);
                assert_eq!(description.as_deref(), Some(""));
                if scenario == 3 {
                    return;
                }
                let payload = if scenario == 2 || scenario >= 4 {
                    AgentControlResponse::Error {
                        code: if scenario == 2 || scenario == 6 {
                            "not_group_admin".into()
                        } else {
                            "app_error".into()
                        },
                        message: "private detail".into(),
                        retryable: scenario >= 5,
                    }
                } else {
                    AgentControlResponse::GroupProfileUpdated {
                        group_id_hex,
                        message_ids_hex: if scenario == 1 {
                            vec![]
                        } else {
                            vec!["33".repeat(32)]
                        },
                    }
                };
                write_frame(
                    reader.get_mut(),
                    &AgentControlEnvelope::request(request.id, payload),
                )
                .await
                .unwrap();
            });
            let result = run_group_profile_tool(config(socket), br#"{"description":""}"#).await;
            server.await.unwrap();
            match scenario {
                0 => assert_eq!(result["ok"], true),
                2 => {
                    assert_eq!(result["error"], "not_group_admin");
                    assert_eq!(result["control_retryable"], false);
                    assert!(!result.to_string().contains("private detail"));
                }
                4..=6 => {
                    assert_eq!(result["outcome"], "unknown");
                    assert_eq!(result["retryable"], false);
                    assert_eq!(result["control_retryable"], scenario >= 5);
                    assert!(!result.to_string().contains("private detail"));
                }
                _ => assert_eq!(result["outcome"], "unknown"),
            }
        }
    }
}
