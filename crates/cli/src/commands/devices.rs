//! Thin dev CLI rendering over the daemon-owned device-link and roster APIs.

use marmot_account::AccountHome;
use marmot_app::{
    DeviceLinkChoices, DeviceLinkEndReason, DeviceLinkPromptState, DeviceLinkSnapshot,
    LinkedDeviceStatus, MarmotAppRuntime, NewDeviceLinkState,
};
use serde_json::{Value, json};

use crate::args::{DeviceLinkCommand, DevicesCommand};
use crate::{CommandOutput, WnError, npub_for_account_id, resolve_account, terminal_safe_text};

pub(crate) async fn devices_command_with_runtime(
    home: &AccountHome,
    runtime: &MarmotAppRuntime,
    command: DevicesCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    let account = resolve_account(home, account_flag)?;
    let npub = npub_for_account_id(&account.account_id_hex)?;
    match command {
        DevicesCommand::List => {
            let devices = runtime.linked_devices(&account.label).await?;
            let plain = if devices.is_empty() {
                "no linked devices".to_owned()
            } else {
                devices
                    .iter()
                    .map(|device| {
                        format!(
                            "{} {}{} ({})",
                            device.slot_id_hex,
                            terminal_safe_text(&device.label),
                            if device.is_this_device {
                                " [this device]"
                            } else {
                                ""
                            },
                            status(device.status),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let devices = devices.into_iter().map(|d| json!({
                "slot_id_hex":d.slot_id_hex,"is_this_device":d.is_this_device,"label":d.label,
                "client":d.client,"platform":d.platform,"linked_at":d.linked_at,
                "linked_by_slot_id_hex":d.linked_by_slot_id_hex,"status":status(d.status),
                "add_to_all_chats":d.add_to_all_chats,"bring_history":d.bring_history,
                "keep_while_inactive":d.keep_while_inactive,"last_active_at":d.last_active_at,
                "inactive":d.inactive,"removal_pending":d.removal_pending,
            })).collect::<Vec<_>>();
            Ok(CommandOutput {
                plain,
                json: json!({"account_id":account.account_id_hex,"npub":npub,"devices":devices}),
            })
        }
        DevicesCommand::Link { command } => {
            let snapshot = match command {
                DeviceLinkCommand::Start => runtime.start_device_link(&account.label).await?,
                DeviceLinkCommand::Status => runtime.device_link_snapshot(&account.label).await?,
                DeviceLinkCommand::ConfirmMatch => {
                    runtime.confirm_device_link_match(&account.label).await?
                }
                DeviceLinkCommand::Cancel => runtime.cancel_device_link(&account.label).await?,
                DeviceLinkCommand::Approve {
                    prompt_id,
                    label,
                    no_add_to_all_chats,
                    no_bring_history,
                } => {
                    runtime
                        .link_device(
                            &account.label,
                            &prompt_id,
                            DeviceLinkChoices {
                                label,
                                add_to_all_chats: !no_add_to_all_chats,
                                bring_history: !no_bring_history,
                            },
                        )
                        .await?
                }
            };
            let mut value = snapshot_json(snapshot);
            let object = value.as_object_mut().expect("snapshot is an object");
            object.insert("account_id".to_owned(), json!(account.account_id_hex));
            object.insert("npub".to_owned(), json!(npub));
            Ok(CommandOutput {
                plain: snapshot_plain(&value),
                json: value,
            })
        }
    }
}

fn status(status: LinkedDeviceStatus) -> &'static str {
    match status {
        LinkedDeviceStatus::Active => "active",
        LinkedDeviceStatus::Inactive => "inactive",
        LinkedDeviceStatus::Leaving => "leaving",
        LinkedDeviceStatus::Moved => "moved",
    }
}

fn reason(reason: DeviceLinkEndReason) -> &'static str {
    match reason {
        DeviceLinkEndReason::Cancelled => "cancelled",
        DeviceLinkEndReason::CancelledElsewhere => "cancelled_elsewhere",
        DeviceLinkEndReason::CodesDiffer => "codes_differ",
        DeviceLinkEndReason::VerificationFailed => "verification_failed",
        DeviceLinkEndReason::TimedOut => "timed_out",
        DeviceLinkEndReason::AnsweredElsewhere => "answered_elsewhere",
        DeviceLinkEndReason::CannotLink => "cannot_link",
        DeviceLinkEndReason::Rejected => "rejected",
        DeviceLinkEndReason::LinkFailed => "link_failed",
    }
}

fn code(code: Vec<marmot_app::DeviceLinkEmoji>) -> Value {
    json!(
        code.into_iter()
            .map(|emoji| json!({"emoji":emoji.emoji,"description":emoji.description}))
            .collect::<Vec<_>>()
    )
}

fn snapshot_json(snapshot: DeviceLinkSnapshot) -> Value {
    let new_device = snapshot.new_device.map(|state| match state {
        NewDeviceLinkState::WaitingForAnswer => json!({"state":"waiting_for_answer"}),
        NewDeviceLinkState::Comparing { code: emojis } => {
            json!({"state":"comparing","code":code(emojis)})
        }
        NewDeviceLinkState::WaitingForOtherDevice => json!({"state":"waiting_for_other_device"}),
        NewDeviceLinkState::Joining => json!({"state":"joining"}),
        NewDeviceLinkState::Linked => json!({"state":"linked"}),
        NewDeviceLinkState::Ended { reason: why } => json!({"state":"ended","reason":reason(why)}),
    });
    let prompts=snapshot.prompts.into_iter().map(|prompt| {
        let mut state=match prompt.state {
            DeviceLinkPromptState::Preparing=>json!({"state":"preparing"}),
            DeviceLinkPromptState::Comparing {code:emojis}=>json!({"state":"comparing","code":code(emojis)}),
            DeviceLinkPromptState::CompetingRequests=>json!({"state":"competing_requests"}),
            DeviceLinkPromptState::RateLimited {retry_at}=>json!({"state":"rate_limited","retry_at":retry_at}),
            DeviceLinkPromptState::CannotLink {missing}=>json!({"state":"cannot_link","missing":missing}),
            DeviceLinkPromptState::TooManyDevices=>json!({"state":"too_many_devices"}),
            DeviceLinkPromptState::Linking=>json!({"state":"linking"}),DeviceLinkPromptState::Linked=>json!({"state":"linked"}),
            DeviceLinkPromptState::AddedElsewhere {device_label,added_by_label}=>json!({"state":"added_elsewhere","device_label":device_label,"added_by_label":added_by_label}),
            DeviceLinkPromptState::Ended {reason:why}=>json!({"state":"ended","reason":reason(why)}),
        };
        let object=state.as_object_mut().expect("prompt state is an object");
        object.insert("prompt_id".to_owned(),json!(prompt.prompt_id));
        object.insert("slot_id_hex".to_owned(),json!(prompt.slot_id_hex));
        object.insert("requested_at".to_owned(),json!(prompt.requested_at));
        state
    }).collect::<Vec<_>>();
    let moves = snapshot.moves.into_iter().map(|movement| {
        let state = match movement.state {
            marmot_app::DeviceGroupMoveState::WaitingForWelcome => "waiting_for_welcome",
            marmot_app::DeviceGroupMoveState::Joining => "joining",
            marmot_app::DeviceGroupMoveState::Made => "made",
            marmot_app::DeviceGroupMoveState::Failed => "failed",
        };
        let old_siblings = movement.old_siblings.into_iter().map(|sibling| json!({
            "slot_id_hex": sibling.slot_id_hex, "label": sibling.label,
            "question_suppressed": sibling.question_suppressed,
        })).collect::<Vec<_>>();
        json!({"move_id":movement.move_id,"state":state,"old_siblings":old_siblings,"overridden_rejection_slots":movement.overridden_rejection_slots})
    }).collect::<Vec<_>>();
    json!({"new_device":new_device,"prompts":prompts,"moves":moves})
}

fn snapshot_plain(snapshot: &Value) -> String {
    let mut lines = Vec::new();
    if let Some(state) = snapshot["new_device"].as_object() {
        lines.push(format!(
            "new device: {}",
            state["state"].as_str().unwrap_or("unknown")
        ));
        append_details(&mut lines, &snapshot["new_device"]);
    }
    for prompt in snapshot["prompts"].as_array().into_iter().flatten() {
        lines.push(format!(
            "prompt {}: {}",
            terminal_safe_text(prompt["prompt_id"].as_str().unwrap_or("")),
            prompt["state"].as_str().unwrap_or("unknown")
        ));
        append_details(&mut lines, prompt);
    }
    for movement in snapshot["moves"].as_array().into_iter().flatten() {
        lines.push(format!(
            "move {}: {}",
            terminal_safe_text(movement["move_id"].as_str().unwrap_or("")),
            terminal_safe_text(movement["state"].as_str().unwrap_or("unknown"))
        ));
        for sibling in movement["old_siblings"].as_array().into_iter().flatten() {
            if sibling["question_suppressed"].as_bool() == Some(true) {
                lines.push(format!(
                    "previously linked device: {}",
                    terminal_safe_text(sibling["label"].as_str().unwrap_or(""))
                ));
            }
        }
        if movement["overridden_rejection_slots"]
            .as_array()
            .is_some_and(|slots| !slots.is_empty())
        {
            lines.push("a confirmed destination link overrode an earlier rejection".to_owned());
        }
    }
    if lines.is_empty() {
        "no device link in progress".to_owned()
    } else {
        lines.join("\n")
    }
}

fn append_details(lines: &mut Vec<String>, state: &Value) {
    if let Some(emojis) = state["code"].as_array() {
        lines.push(format!(
            "code: {}",
            emojis
                .iter()
                .map(|e| terminal_safe_text(e["emoji"].as_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join(" ")
        ));
        lines.push("Compare all seven emoji on both devices before confirming.".to_owned());
    }
    if let Some(retry_at) = state["retry_at"].as_u64() {
        lines.push(format!("retry at Unix time: {retry_at}"));
    }
    if let (Some(device), Some(added_by)) = (
        state["device_label"].as_str(),
        state["added_by_label"].as_str(),
    ) {
        lines.push(format!(
            "{} was added by {}",
            terminal_safe_text(device),
            terminal_safe_text(added_by)
        ));
    }
    if let Some(reason) = state["reason"].as_str() {
        lines.push(format!("reason: {}", terminal_safe_text(reason)));
    }
    if let Some(missing) = state["missing"].as_array() {
        lines.push(format!(
            "missing: {}",
            missing
                .iter()
                .filter_map(Value::as_str)
                .map(terminal_safe_text)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_app::DeviceLinkPrompt;

    /// CLI display marshals real typed prompt states, retaining actionable
    /// capability details while treating sibling-provided labels as untrusted.
    #[test]
    fn plain_prompt_details_keep_capability_names_and_sanitize_device_labels() {
        let device_label = "Tablet\x1b[2J\u{202e}\nrow";
        let added_by_label = "Phone\x1b]0;title\x07";
        let json = snapshot_json(DeviceLinkSnapshot {
            new_device: None,
            prompts: vec![
                DeviceLinkPrompt {
                    prompt_id: "01".repeat(16),
                    slot_id_hex: None,
                    requested_at: 1,
                    state: DeviceLinkPromptState::AddedElsewhere {
                        device_label: device_label.to_owned(),
                        added_by_label: added_by_label.to_owned(),
                    },
                },
                DeviceLinkPrompt {
                    prompt_id: "02".repeat(16),
                    slot_id_hex: None,
                    requested_at: 1,
                    state: DeviceLinkPromptState::CannotLink {
                        // Exact names produced by the core missing-capability reader.
                        missing: vec![
                            "app_component:0x800e".to_owned(),
                            "app_component:0x8004".to_owned(),
                        ],
                    },
                },
            ],
            moves: Vec::new(),
        });
        assert!(
            json["prompts"][0]["device_label"] == device_label,
            "JSON should preserve the device label"
        );
        assert!(
            json["prompts"][0]["added_by_label"] == added_by_label,
            "JSON should preserve the approver label"
        );
        let plain = snapshot_plain(&json);
        assert_eq!(
            plain.lines().count(),
            4,
            "one header/detail pair per prompt"
        );
        assert!(plain.contains("Tablet[2Jrow was added by Phone]0;title"));
        assert!(
            !plain
                .chars()
                .any(|ch| matches!(ch, '\x1b' | '\x07' | '\u{202e}')),
            "untrusted label controls must not reach the terminal"
        );
        assert!(plain.contains(": added_elsewhere"));
        assert!(plain.contains(": cannot_link"));
        assert!(plain.contains("missing: app_component:0x800e, app_component:0x8004"));
    }
}
