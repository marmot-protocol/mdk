//! `group` and `groups` command namespace handlers and group output helpers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cgka_traits::{GroupId, MessageId, PeriodicMaintenancePolicy};
use marmot_account::AccountHome;
use marmot_app::{
    AppCreateGroupOptions, AppDisbandRequest, AppError, AppGroupImageComponent,
    AppGroupLifecycleState, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppInitialGroupImage, MarmotApp, MarmotAppRuntime, PendingWelcomeDelivery, SendSummary,
};
use serde_json::{Value, json};

use crate::{
    CommandOutput, GroupCommand, GroupsCommand, MaintenancePolicySetting, WnError,
    ensure_local_signing, group_json, group_list_plain, group_show_output, normalize_group_id_hex,
    npub_for_account_id, parse_public_key, resolve_account, terminal_safe_text, write_private_file,
};

async fn accept_group_invite_retrying_busy(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
    group_id: &GroupId,
) -> Result<AppGroupRecord, AppError> {
    // A one-shot `wn groups accept` starts its own runtime and can race that
    // runtime's initial catch-up, and the inviter may have returned before the
    // Welcome landed. Keep the same runtime alive for a bounded 30-second
    // retry window; restarting the CLI would only recreate the race.
    const BUSY_RETRY_ATTEMPTS: usize = 600;
    const BUSY_RETRY_DELAY: Duration = Duration::from_millis(50);

    let mut last_retryable = AppError::AccountWorkerBusy;
    for attempt in 0..BUSY_RETRY_ATTEMPTS {
        match runtime.accept_group_invite(account_ref, group_id).await {
            Err(error @ (AppError::AccountWorkerBusy | AppError::UnknownGroup(_))) => {
                last_retryable = error;
                if attempt + 1 < BUSY_RETRY_ATTEMPTS {
                    tokio::time::sleep(BUSY_RETRY_DELAY).await;
                }
            }
            // Every other result is terminal for this CLI invocation. In
            // particular, never retry an ambiguous worker response timeout.
            result => return result,
        }
    }

    Err(last_retryable)
}

fn group_command_requires_welcome_drain(command: &GroupCommand) -> bool {
    matches!(
        command,
        GroupCommand::Create { .. } | GroupCommand::Invite { .. }
    )
}

fn groups_command_requires_welcome_drain(command: &GroupsCommand) -> bool {
    matches!(
        command,
        GroupsCommand::Create { .. } | GroupsCommand::AddMembers { .. }
    )
}

pub(crate) async fn group_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: GroupCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    let runtime = app.runtime();
    let requires_welcome_drain = group_command_requires_welcome_drain(&command);
    let result =
        group_command_with_runtime(account_home, app, &runtime, command, account_flag).await;
    // Only create/invite launch post-response Welcome fanout. Read-only and
    // unrelated mutation commands must not join a retained startup Welcome.
    let drain_result = if requires_welcome_drain {
        runtime.drain_in_flight_work().await
    } else {
        Ok(())
    };
    runtime.shutdown().await;
    drain_result?;
    result
}

pub(crate) async fn group_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: GroupCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    match command {
        GroupCommand::Create {
            name,
            members,
            description,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = runtime
                .create_group(&account.label, &name, &members, description.clone())
                .await?;
            created_group_output(app, runtime, &account, &group_id).await
        }
        GroupCommand::Members { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let members = runtime.group_members(&account.label, &group_id).await?;
            Ok(CommandOutput {
                plain: group_members_plain(&members)?,
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": group_members_json(members)?,
                }),
            })
        }
        GroupCommand::Invite {
            group,
            members,
            admins,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            // Initial admins ride the same invite commit, so an admin that is
            // not an invitee is a caller mistake to reject before publishing
            // rather than a follow-up promotion to emulate.
            let initial_admins = initial_admin_ids(&members, &admins)?;
            let summary = runtime
                .invite_members_with_initial_admins(
                    &account.label,
                    &group_id,
                    &members,
                    &initial_admins,
                )
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "invited {} member(s) admins={} published={}",
                    members.len(),
                    initial_admins.len(),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": members,
                    "initial_admins": initial_admins,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "maintenance_disposition": summary.maintenance_disposition,
                }),
            })
        }
        GroupCommand::Remove { group, members } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let summary = runtime
                .remove_members(&account.label, &group_id, &members)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "removed {} member(s) published={}",
                    members.len(),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "members": members,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "maintenance_disposition": summary.maintenance_disposition,
                }),
            })
        }
        GroupCommand::Update {
            group,
            name,
            description,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let summary = runtime
                .update_group_profile(&account.label, &group_id, name, description)
                .await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            Ok(CommandOutput {
                plain: format!(
                    "updated group {group_id_hex} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group": group_json(group),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "maintenance_disposition": summary.maintenance_disposition,
                }),
            })
        }
        GroupCommand::SetAvatarUrl {
            group,
            url,
            dim,
            thumbhash,
            clear,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            // clap guarantees exactly one of `--url` / `--clear` is present, and
            // that `--dim` / `--thumbhash` only accompany `--url`. An explicit
            // empty `--url ""` is a malformed URL, not a clear — surface it as the
            // typed `invalid_group_avatar_url` error rather than silently clearing.
            // Validation/normalization (https-only, length bound, reject
            // localhost/private hosts) is enforced in the codec; the CLI passes
            // the URL through.
            let url = if clear {
                None
            } else {
                match url {
                    Some(url) if url.is_empty() => {
                        return Err(AppError::InvalidGroupAvatarUrl(
                            "group avatar URL must not be empty".to_owned(),
                        )
                        .into());
                    }
                    other => other,
                }
            };
            let summary = runtime
                .update_group_avatar_url(&account.label, &group_id, url, dim, thumbhash)
                .await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            let action = if group.avatar_url.present {
                "set"
            } else {
                "cleared"
            };
            Ok(CommandOutput {
                plain: format!(
                    "{action} avatar-url for group {group_id_hex} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group": group_json(group),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "maintenance_disposition": summary.maintenance_disposition,
                }),
            })
        }
    }
}

pub(crate) async fn groups_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: GroupsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    let runtime = app.runtime();
    let requires_welcome_drain = groups_command_requires_welcome_drain(&command);
    let result =
        groups_command_with_runtime(account_home, app, &runtime, command, account_flag).await;
    let drain_result = if requires_welcome_drain {
        runtime.drain_in_flight_work().await
    } else {
        Ok(())
    };
    runtime.shutdown().await;
    drain_result?;
    result
}

pub(crate) async fn groups_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: GroupsCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    match command {
        GroupsCommand::List => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let groups = app.visible_groups(&account.label)?;
            Ok(CommandOutput {
                plain: group_list_plain(&groups),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "groups": groups.into_iter().map(group_json).collect::<Vec<_>>(),
                }),
            })
        }
        GroupsCommand::Create {
            name,
            members,
            description,
            retention,
            image,
            image_media_type,
        } => {
            if retention.is_none() && image.is_none() {
                return group_command_with_runtime(
                    account_home,
                    app,
                    runtime,
                    GroupCommand::Create {
                        name,
                        members,
                        description,
                    },
                    account_flag,
                )
                .await;
            }
            // Founding retention and a founding image are part of the create
            // commit itself (`create_group_with_options`), never a second
            // post-create component update.
            let disappearing_message_secs = retention
                .as_deref()
                .map(parse_retention_duration)
                .transpose()?
                .unwrap_or(0);
            let initial_image = image
                .as_deref()
                .map(|path| read_group_image_file(Path::new(path), image_media_type.clone()))
                .transpose()?
                .map(|(plaintext, media_type)| AppInitialGroupImage {
                    plaintext,
                    media_type,
                    source_url: None,
                    dim: None,
                    thumbhash: None,
                });
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = runtime
                .create_group_with_options(
                    &account.label,
                    &name,
                    &members,
                    AppCreateGroupOptions {
                        description: description.unwrap_or_default(),
                        initial_image,
                        disappearing_message_secs,
                    },
                )
                .await?;
            created_group_output(app, runtime, &account, &group_id).await
        }
        GroupsCommand::Show { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let mls = runtime
                .group_mls_state(&account.label, &group_id)
                .await
                .map(group_mls_state_json)?;
            group_show_output(app, account, group_id_hex, Some(mls))
        }
        GroupsCommand::AddMembers {
            group_id,
            members,
            admins,
        } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Invite {
                    group: group_id,
                    members,
                    admins,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::RemoveMembers { group_id, members } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Remove {
                    group: group_id,
                    members,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::Members { group_id } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Members { group: group_id },
                account_flag,
            )
            .await
        }
        GroupsCommand::Admins { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = normalize_group_id_hex(&group_id)?;
            let group = app
                .group(&account.label, &group_id)?
                .ok_or_else(|| AppError::UnknownGroup(group_id.clone()))?;
            let admins = group
                .admin_policy
                .admins
                .iter()
                .map(|admin| {
                    Ok(json!({
                        "admin_id": admin,
                        "npub": npub_for_account_id(admin)?,
                    }))
                })
                .collect::<Result<Vec<_>, WnError>>()?;
            Ok(CommandOutput {
                plain: if admins.is_empty() {
                    "no admins".to_owned()
                } else {
                    admins
                        .iter()
                        .filter_map(|admin| admin.get("npub").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id,
                    "admins": admins,
                }),
            })
        }
        GroupsCommand::Relays { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = normalize_group_id_hex(&group_id)?;
            let group = app
                .group(&account.label, &group_id)?
                .ok_or_else(|| AppError::UnknownGroup(group_id.clone()))?;
            Ok(CommandOutput {
                plain: terminal_safe_text(&group.endpoint),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id,
                    "relays": [group.endpoint],
                }),
            })
        }
        GroupsCommand::Leave { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime.leave_group(&account.label, &group_id).await?;
            Ok(CommandOutput {
                plain: format!(
                    "left group {} published={}",
                    hex::encode(group_id.as_slice()),
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "maintenance_disposition": summary.maintenance_disposition,
                }),
            })
        }
        GroupsCommand::Rename { group_id, name } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Update {
                    group: group_id,
                    name: Some(name),
                    description: None,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::SetAvatarUrl {
            group_id,
            url,
            dim,
            thumbhash,
            clear,
        } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::SetAvatarUrl {
                    group: group_id,
                    url,
                    dim,
                    thumbhash,
                    clear,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::Invites => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let invites = app
                .groups(&account.label)?
                .into_iter()
                .filter(|group| group.pending_confirmation)
                .collect::<Vec<_>>();
            Ok(CommandOutput {
                plain: pending_invites_plain(&invites),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "invites": invites.into_iter().map(group_json).collect::<Vec<_>>(),
                }),
            })
        }
        GroupsCommand::Accept { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let group =
                accept_group_invite_retrying_busy(runtime, &account.label, &group_id).await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            Ok(CommandOutput {
                plain: format!("accepted invite {group_id_hex}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group": group_json(group),
                    "accepted": true,
                }),
            })
        }
        GroupsCommand::Decline { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let declined = runtime
                .decline_group_invite(&account.label, &group_id)
                .await?;
            let group_id_hex = hex::encode(group_id.as_slice());
            Ok(CommandOutput {
                plain: format!(
                    "declined invite {group_id_hex} published={}",
                    declined.summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group": group_json(declined.group),
                    "declined": true,
                    "published": declined.summary.published,
                    "message_ids": declined.summary.message_ids,
                }),
            })
        }
        GroupsCommand::Promote { group_id, pubkey } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_admin_policy_output(
                app,
                runtime,
                account,
                group_id,
                GroupAdminAction::Promote(pubkey),
            )
            .await
        }
        GroupsCommand::Demote { group_id, pubkey } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_admin_policy_output(
                app,
                runtime,
                account,
                group_id,
                GroupAdminAction::Demote(pubkey),
            )
            .await
        }
        GroupsCommand::SelfDemote { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            group_admin_policy_output(
                app,
                runtime,
                account,
                group_id,
                GroupAdminAction::SelfDemote,
            )
            .await
        }
        GroupsCommand::MaintenanceStatus { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let status = runtime
                .maintenance_status(&account.label, &group_id)
                .await?;
            let active = status
                .obligations
                .iter()
                .filter(|obligation| {
                    !matches!(
                        obligation.phase,
                        cgka_traits::MaintenancePhase::Complete
                            | cgka_traits::MaintenancePhase::Failed
                    )
                })
                .count();
            Ok(CommandOutput {
                plain: format!(
                    "maintenance group={} active={} paused={}",
                    hex::encode(group_id.as_slice()),
                    active,
                    status.paused
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "maintenance": status,
                }),
            })
        }
        GroupsCommand::ScheduleSelfUpdate { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let obligation_id = runtime
                .schedule_manual_self_update(&account.label, &group_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "scheduled self-update for group {}",
                    hex::encode(group_id.as_slice())
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": hex::encode(group_id.as_slice()),
                    "obligation_id": obligation_id,
                    "scheduled": true,
                }),
            })
        }
        GroupsCommand::MaintenancePolicy { set } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            if let Some(setting) = set {
                let policy = match setting {
                    MaintenancePolicySetting::Enabled => {
                        PeriodicMaintenancePolicy::EnabledForNewGroups
                    }
                    MaintenancePolicySetting::Disabled => PeriodicMaintenancePolicy::Disabled,
                };
                runtime
                    .set_periodic_maintenance_policy(&account.label, policy)
                    .await?;
            }
            let policy = runtime.periodic_maintenance_policy(&account.label).await?;
            let policy_name = match policy {
                PeriodicMaintenancePolicy::EnabledForNewGroups => "enabled_for_new_groups",
                PeriodicMaintenancePolicy::Disabled => "disabled",
            };
            Ok(CommandOutput {
                plain: policy_name.to_owned(),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "periodic_maintenance_policy": policy,
                }),
            })
        }
        GroupsCommand::PauseMaintenance => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            runtime.pause_maintenance(&account.label).await?;
            Ok(CommandOutput {
                plain: "maintenance paused".to_owned(),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "paused": true,
                }),
            })
        }
        GroupsCommand::ResumeMaintenance => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            runtime.resume_maintenance(&account.label).await?;
            Ok(CommandOutput {
                plain: "maintenance resumed".to_owned(),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "paused": false,
                }),
            })
        }
        GroupsCommand::RunMaintenance => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let summary = runtime.run_due_maintenance(&account.label).await?;
            Ok(CommandOutput {
                plain: format!("maintenance published={}", summary.published),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                    "deferred": summary.deferred,
                    "ambiguous_exposure": summary.ambiguous_exposure,
                    "failures": summary.failures,
                }),
            })
        }
        GroupsCommand::Update {
            group_id,
            name,
            description,
        } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Update {
                    group: group_id,
                    name,
                    description,
                },
                account_flag,
            )
            .await
        }
        GroupsCommand::Retention { group_id, set } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let summary = match set.as_deref() {
                Some(duration) => {
                    let disappearing_message_secs = parse_retention_duration(duration)?;
                    Some(
                        runtime
                            .update_message_retention(
                                &account.label,
                                &group_id,
                                disappearing_message_secs,
                            )
                            .await?,
                    )
                }
                None => None,
            };
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            let secs = group.message_retention.disappearing_message_secs;
            let mut json = json!({
                "account_id": account.account_id_hex,
                "npub": npub_for_account_id(&account.account_id_hex)?,
                "group_id": group_id_hex,
                "disappearing_message_secs": secs,
                "enabled": secs != 0,
                "message_retention": group.message_retention,
            });
            let plain = match summary {
                Some(summary) => {
                    insert_send_summary(&mut json, &summary);
                    format!(
                        "retention group={group_id_hex} disappearing_message_secs={secs} published={}",
                        summary.published
                    )
                }
                None => format!("retention group={group_id_hex} disappearing_message_secs={secs}"),
            };
            Ok(CommandOutput { plain, json })
        }
        GroupsCommand::EnableDisbanding { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let summary = runtime
                .enable_group_disbanding(&account.label, &group_id)
                .await?;
            let mls = runtime.group_mls_state(&account.label, &group_id).await?;
            let mut json = json!({
                "account_id": account.account_id_hex,
                "npub": npub_for_account_id(&account.account_id_hex)?,
                "group_id": group_id_hex,
                "disbanding_enabled": mls.disbanding_enabled,
                "lifecycle_state": mls.lifecycle_state,
                "disbanding_blockers": mls.disbanding_blockers,
            });
            insert_send_summary(&mut json, &summary);
            Ok(CommandOutput {
                plain: format!(
                    "disbanding enabled={} for group {group_id_hex} published={}",
                    mls.disbanding_enabled, summary.published
                ),
                json,
            })
        }
        GroupsCommand::Disband { group_id, confirm } => {
            if !confirm {
                return Err(WnError::ConfirmationRequired {
                    command: "groups disband",
                    flag: "--confirm",
                    reason: "disbanding a group is irreversible for every member",
                });
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let request = runtime.disband_group(&account.label, &group_id).await?;
            // A returned request is durable local intent, not proof that the
            // terminal commit published or that any member observed the end.
            let (group, mls) = group_record_and_mls(app, runtime, &account, &group_id_hex).await?;
            let mut json = disband_status_json(&group, mls.as_ref());
            json["disband_request"] = json!(request);
            json["state"] = json!(disband_state(&group, mls.as_ref(), Some(&request)));
            insert_account_fields(&mut json, &account)?;
            Ok(CommandOutput {
                plain: format!(
                    "disband requested for group {group_id_hex} state={}",
                    json["state"].as_str().unwrap_or("pending")
                ),
                json,
            })
        }
        GroupsCommand::DisbandStatus { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let (group, mls) = group_record_and_mls(app, runtime, &account, &group_id_hex).await?;
            let mut json = disband_status_json(&group, mls.as_ref());
            insert_account_fields(&mut json, &account)?;
            Ok(CommandOutput {
                plain: format!(
                    "disband group={group_id_hex} state={} disbanding={} disbanded={}",
                    json["state"].as_str().unwrap_or("unknown"),
                    group.disbanding,
                    group.disbanded
                ),
                json,
            })
        }
        GroupsCommand::AcknowledgeDisbandFailure { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let acknowledged = runtime
                .acknowledge_disband_failure(&account.label, &group_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "acknowledged disband failure={acknowledged} for group {group_id_hex}"
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "acknowledged": acknowledged,
                }),
            })
        }
        GroupsCommand::Management { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            let members = runtime.group_members(&account.label, &group_id).await?;
            let mls = runtime.group_mls_state(&account.label, &group_id).await?;
            let mut json = group_management_json(&account.account_id_hex, &group, &members, &mls);
            insert_account_fields(&mut json, &account)?;
            Ok(CommandOutput {
                plain: format!(
                    "management group={group_id_hex} admin={} can_invite={} can_leave={} can_disband={}",
                    json["is_self_admin"],
                    json["can_invite"],
                    json["can_leave"],
                    json["can_disband"]
                ),
                json,
            })
        }
        GroupsCommand::RecoveryStatus { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let status = runtime
                .group_recovery_status(&account.label, &group_id)
                .await?;
            let mut json = json!(status);
            json["group_id"] = json!(group_id_hex);
            insert_account_fields(&mut json, &account)?;
            Ok(CommandOutput {
                plain: format!(
                    "recovery group={group_id_hex} automatic_recovery_failed={} pending_reinvites={} failed_reinvites={} rejoin_invitations={}",
                    status.automatic_recovery_failed,
                    status.pending_reinvites,
                    status.failed_reinvites,
                    status.rejoin_invitations.len()
                ),
                json,
            })
        }
        GroupsCommand::ConfirmRejoin {
            welcome_id,
            local_state_token,
            confirm,
        } => {
            if !confirm {
                return Err(WnError::ConfirmationRequired {
                    command: "groups confirm-rejoin",
                    flag: "--confirm",
                    reason: "rejoining discards the current local copy of the group",
                });
            }
            let welcome_id_hex = normalize_welcome_id_hex(&welcome_id)?;
            let token = parse_rejoin_token(&local_state_token)?;
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let status = runtime
                .confirm_group_rejoin(
                    &account.label,
                    &MessageId::new(hex::decode(&welcome_id_hex)?),
                    &token,
                )
                .await?;
            let mut json = json!(status);
            json["welcome_id"] = json!(welcome_id_hex);
            json["confirmed"] = json!(true);
            insert_account_fields(&mut json, &account)?;
            Ok(CommandOutput {
                plain: format!("confirmed rejoin {welcome_id_hex}"),
                json,
            })
        }
        GroupsCommand::DeclineRejoin { welcome_id } => {
            let welcome_id_hex = normalize_welcome_id_hex(&welcome_id)?;
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            runtime
                .decline_group_rejoin(
                    &account.label,
                    &MessageId::new(hex::decode(&welcome_id_hex)?),
                )
                .await?;
            Ok(CommandOutput {
                plain: format!("declined rejoin {welcome_id_hex}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "welcome_id": welcome_id_hex,
                    "declined": true,
                }),
            })
        }
        GroupsCommand::Quarantined => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let quarantined = runtime.quarantined_groups(&account.label).await?;
            Ok(CommandOutput {
                plain: if quarantined.is_empty() {
                    "no quarantined groups".to_owned()
                } else {
                    quarantined
                        .iter()
                        .map(|group| {
                            format!(
                                "{} {}",
                                terminal_safe_text(&group.group_id_hex),
                                json!(group.reason).as_str().unwrap_or("unknown")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "quarantined": quarantined,
                }),
            })
        }
        GroupsCommand::RetryHydrate { group_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let recovered = runtime
                .retry_hydrate_quarantined_group(&account.label, &group_id)
                .await?;
            Ok(CommandOutput {
                plain: format!("retry-hydrate group={group_id_hex} recovered={recovered}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "recovered": recovered,
                }),
            })
        }
        GroupsCommand::DeleteLocal { group_id, confirm } => {
            if !confirm {
                return Err(WnError::ConfirmationRequired {
                    command: "groups delete-local",
                    flag: "--confirm",
                    reason: "deletes this group's local messages and projection without leaving",
                });
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let deleted = runtime
                .delete_group_local(&account.label, &group_id)
                .await?;
            Ok(CommandOutput {
                plain: format!("deleted local data for group {group_id_hex} deleted={deleted}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "deleted": deleted,
                }),
            })
        }
        GroupsCommand::SetImage {
            group_id,
            file_path,
            media_type,
        } => {
            let (plaintext, media_type) = read_group_image_file(Path::new(&file_path), media_type)?;
            group_image_update_output(
                app,
                runtime,
                account_home,
                account_flag,
                &group_id,
                plaintext,
                media_type,
                "set",
            )
            .await
        }
        GroupsCommand::ClearImage { group_id } => {
            group_image_update_output(
                app,
                runtime,
                account_home,
                account_flag,
                &group_id,
                Vec::new(),
                String::new(),
                "cleared",
            )
            .await
        }
        GroupsCommand::DownloadImage { group_id, output } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group_id)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            if !group.image.present {
                return Err(WnError::GroupImageAbsent(group_id_hex));
            }
            let bytes = runtime
                .download_group_blossom_image(&account.label, &group_id)
                .await?;
            let output_path = output.map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(format!(
                    "group-image.{}",
                    group_image_extension(group.image.media_type.as_deref())
                ))
            });
            write_private_file(&output_path, &bytes)?;
            Ok(CommandOutput {
                plain: terminal_safe_text(&output_path.display().to_string()),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "image": group_image_summary_json(&group.image),
                    "output_path": output_path.display().to_string(),
                    "size_bytes": bytes.len(),
                }),
            })
        }
        GroupsCommand::PendingWelcomes => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let pending = runtime.pending_welcome_deliveries(&account.label).await?;
            Ok(CommandOutput {
                plain: if pending.is_empty() {
                    "no pending welcome deliveries".to_owned()
                } else {
                    pending
                        .iter()
                        .map(|delivery| {
                            format!(
                                "group={} message={} recipient={}",
                                terminal_safe_text(&delivery.group_id_hex),
                                terminal_safe_text(&delivery.message_id_hex),
                                terminal_safe_text(&delivery.recipient_hex)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "pending_welcome_deliveries": pending_welcome_deliveries_json(&pending)?,
                }),
            })
        }
        GroupsCommand::RedeliverWelcome { message_id } => {
            let message_id_hex = normalize_welcome_id_hex(&message_id)?;
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let summary = runtime
                .redeliver_welcome(&account.label, &message_id_hex)
                .await?;
            let mut json = json!({
                "account_id": account.account_id_hex,
                "npub": npub_for_account_id(&account.account_id_hex)?,
                "message_id": message_id_hex,
            });
            insert_send_summary(&mut json, &summary);
            Ok(CommandOutput {
                plain: format!(
                    "redelivered welcome {message_id_hex} published={}",
                    summary.published
                ),
                json,
            })
        }
        GroupsCommand::SubscribeState { .. } => Err(WnError::MessagesSubscribeRequiresDaemon),
    }
}

/// Shared create-group response for the legacy and option-carrying paths.
async fn created_group_output(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: &marmot_account::AccountSummary,
    group_id: &GroupId,
) -> Result<CommandOutput, WnError> {
    let group_id_hex = hex::encode(group_id.as_slice());
    let group = app
        .group(&account.label, &group_id_hex)?
        .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
    let members = runtime.group_members(&account.label, group_id).await?;
    Ok(CommandOutput {
        plain: format!("created group {group_id_hex}"),
        json: created_group_json(&account.account_id_hex, group, members)?,
    })
}

/// The `groups create` / `group create` response. A founding `--image` is the
/// path that populates the image component's capability keys, so the image is
/// reported through the same redacted summary as the image commands (mdk#1253).
pub(crate) fn created_group_json(
    account_id_hex: &str,
    group: AppGroupRecord,
    members: Vec<AppGroupMemberRecord>,
) -> Result<Value, WnError> {
    Ok(json!({
        "account_id": account_id_hex,
        "npub": npub_for_account_id(account_id_hex)?,
        "group_id": group.group_id_hex,
        "name": group.profile.name.clone(),
        "profile": group.profile,
        "image": group_image_summary_json(&group.image),
        "admin_policy": group.admin_policy,
        "agent_text_stream": group.agent_text_stream,
        "message_retention": group.message_retention,
        "members": group_members_json(members)?,
    }))
}

/// Resolve `--admin` refs to hex ids and require each one to be an invitee.
fn initial_admin_ids(members: &[String], admins: &[String]) -> Result<Vec<String>, WnError> {
    let invitees = members
        .iter()
        .map(|member| parse_public_key(member))
        .collect::<Result<Vec<_>, _>>()?;
    let mut initial_admins = Vec::with_capacity(admins.len());
    for admin in admins {
        let admin_id = parse_public_key(admin)?;
        if !invitees.contains(&admin_id) {
            return Err(WnError::InitialAdminNotInvited(admin.clone()));
        }
        if !initial_admins.contains(&admin_id) {
            initial_admins.push(admin_id);
        }
    }
    Ok(initial_admins)
}

/// Parse a disappearing-message retention: `0`/`off` disable, a bare integer
/// is seconds, and `s`/`m`/`h`/`d`/`w` suffixes scale a positive integer.
pub(crate) fn parse_retention_duration(value: &str) -> Result<u64, WnError> {
    let invalid = || WnError::InvalidRetentionDuration(value.to_owned());
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid());
    }
    if ["off", "disabled", "none", "never"]
        .iter()
        .any(|word| trimmed.eq_ignore_ascii_case(word))
    {
        return Ok(0);
    }
    if let Ok(seconds) = trimmed.parse::<u64>() {
        return Ok(seconds);
    }
    let Some((number, unit)) = trimmed.split_at_checked(trimmed.len().saturating_sub(1)) else {
        return Err(invalid());
    };
    let amount = number.parse::<u64>().map_err(|_| invalid())?;
    let unit_seconds = match unit {
        "s" | "S" => 1,
        "m" | "M" => 60,
        "h" | "H" => 60 * 60,
        "d" | "D" => 24 * 60 * 60,
        "w" | "W" => 7 * 24 * 60 * 60,
        _ => return Err(invalid()),
    };
    amount.checked_mul(unit_seconds).ok_or_else(invalid)
}

fn normalize_welcome_id_hex(value: &str) -> Result<String, WnError> {
    let bytes = hex::decode(value.trim()).map_err(|_| WnError::InvalidWelcomeId)?;
    if bytes.is_empty() {
        return Err(WnError::InvalidWelcomeId);
    }
    Ok(hex::encode(bytes))
}

/// The rejoin token is the exact 32-byte `local_state_token` from a reviewed
/// `recovery-status` snapshot; consent is bound to that branch, never implied
/// by ordinary invite acceptance.
fn parse_rejoin_token(value: &str) -> Result<Vec<u8>, WnError> {
    let bytes = hex::decode(value.trim()).map_err(|_| WnError::InvalidRejoinToken)?;
    if bytes.len() != 32 {
        return Err(WnError::InvalidRejoinToken);
    }
    Ok(bytes)
}

fn read_group_image_file(
    path: &Path,
    media_type: Option<String>,
) -> Result<(Vec<u8>, String), WnError> {
    let plaintext = std::fs::read(path)?;
    if plaintext.is_empty() {
        return Err(WnError::EmptyGroupImage);
    }
    let media_type =
        media_type.unwrap_or_else(|| crate::commands::media::guess_media_type(path).to_owned());
    Ok((plaintext, media_type))
}

fn group_image_extension(media_type: Option<&str>) -> &'static str {
    match media_type {
        Some("image/png") => "png",
        Some("image/jpeg") => "jpg",
        Some("image/gif") => "gif",
        Some("image/webp") => "webp",
        _ => "bin",
    }
}

/// Redacted image projection for command output. The full component carries
/// the avatar decryption key, Blossom upload secret, and key-bearing
/// `data_hex`; these image commands only report presence, hash, and type
/// (mdk#1253).
pub(crate) fn group_image_summary_json(image: &AppGroupImageComponent) -> Value {
    json!({
        "component_id": image.component_id,
        "component": image.component,
        "present": image.present,
        "image_hash_hex": image.image_hash_hex,
        "media_type": image.media_type,
    })
}

#[allow(clippy::too_many_arguments)]
async fn group_image_update_output(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account_home: &AccountHome,
    account_flag: Option<String>,
    group_id: &str,
    plaintext: Vec<u8>,
    media_type: String,
    action: &str,
) -> Result<CommandOutput, WnError> {
    let account = resolve_account(account_home, account_flag)?;
    ensure_local_signing(&account)?;
    app.status(&account.label)?;
    let group_id_hex = normalize_group_id_hex(group_id)?;
    let group_id = GroupId::new(hex::decode(&group_id_hex)?);
    let summary = runtime
        .update_group_image(&account.label, &group_id, plaintext, media_type)
        .await?;
    let group = app
        .group(&account.label, &group_id_hex)?
        .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
    let mut json = json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex)?,
        "group_id": group_id_hex,
        "image": group_image_summary_json(&group.image),
    });
    insert_send_summary(&mut json, &summary);
    Ok(CommandOutput {
        plain: format!(
            "{action} group image for {group_id_hex} present={} published={}",
            group.image.present, summary.published
        ),
        json,
    })
}

fn insert_send_summary(value: &mut Value, summary: &SendSummary) {
    if let Some(object) = value.as_object_mut() {
        object.insert("published".to_owned(), json!(summary.published));
        object.insert("message_ids".to_owned(), json!(summary.message_ids));
        object.insert(
            "maintenance_disposition".to_owned(),
            json!(summary.maintenance_disposition),
        );
    }
}

fn insert_account_fields(
    value: &mut Value,
    account: &marmot_account::AccountSummary,
) -> Result<(), WnError> {
    if let Some(object) = value.as_object_mut() {
        object.insert("account_id".to_owned(), json!(account.account_id_hex));
        object.insert(
            "npub".to_owned(),
            json!(npub_for_account_id(&account.account_id_hex)?),
        );
    }
    Ok(())
}

/// Read the group record plus its MLS state. The MLS read is best-effort: a
/// terminal or quarantined group still has a durable record worth reporting.
async fn group_record_and_mls(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: &marmot_account::AccountSummary,
    group_id_hex: &str,
) -> Result<(AppGroupRecord, Option<AppGroupMlsState>), WnError> {
    let group = app
        .group(&account.label, group_id_hex)?
        .ok_or_else(|| AppError::UnknownGroup(group_id_hex.to_owned()))?;
    let group_id = GroupId::new(hex::decode(group_id_hex)?);
    let mls = runtime
        .group_mls_state(&account.label, &group_id)
        .await
        .ok();
    Ok((group, mls))
}

/// One word for scripts: `not_enabled`, `enabled`, `pending` (durable local
/// request awaiting its terminal commit), `converging` (an authenticated
/// inbound disband is settling), `failed` (acknowledge to clear), or the
/// terminal `disbanded`.
fn disband_state(
    group: &AppGroupRecord,
    mls: Option<&AppGroupMlsState>,
    request: Option<&AppDisbandRequest>,
) -> &'static str {
    let lifecycle_disbanded =
        mls.is_some_and(|mls| matches!(mls.lifecycle_state, AppGroupLifecycleState::Disbanded));
    if group.disbanded || lifecycle_disbanded {
        return "disbanded";
    }
    let request = request
        .or(group.disband_request.as_ref())
        .or(mls.and_then(|mls| mls.disband_request.as_ref()));
    match request {
        Some(AppDisbandRequest::Failed { .. }) => "failed",
        Some(AppDisbandRequest::Pending { .. }) => "pending",
        None if group.disbanding || mls.is_some_and(|mls| mls.disbanding) => "converging",
        None if mls.is_some_and(|mls| mls.disbanding_enabled) => "enabled",
        None => "not_enabled",
    }
}

fn disband_status_json(group: &AppGroupRecord, mls: Option<&AppGroupMlsState>) -> Value {
    let request = group
        .disband_request
        .clone()
        .or_else(|| mls.and_then(|mls| mls.disband_request.clone()));
    json!({
        "group_id": group.group_id_hex,
        "state": disband_state(group, mls, None),
        "lifecycle_state": mls.map(|mls| json!(mls.lifecycle_state)).unwrap_or(Value::Null),
        "disbanding_enabled": mls.map(|mls| mls.disbanding_enabled),
        "disbanding": group.disbanding || mls.is_some_and(|mls| mls.disbanding),
        "disbanding_blockers": mls.map(|mls| mls.disbanding_blockers.clone()).unwrap_or_default(),
        "disband_request": request,
        "disbanded": group.disbanded
            || mls.is_some_and(|mls| matches!(mls.lifecycle_state, AppGroupLifecycleState::Disbanded)),
        "unrecoverable": group.unrecoverable || mls.is_some_and(|mls| mls.unrecoverable),
        "self_membership": crate::self_membership_json(group),
    })
}

/// Mirror of the MarmotKit `GroupManagementState` derivation so scripts and
/// the TUI can gate affordances from one runtime read instead of guessing.
fn group_management_json(
    my_account_id_hex: &str,
    group: &AppGroupRecord,
    members: &[AppGroupMemberRecord],
    mls: &AppGroupMlsState,
) -> Value {
    let admins = &group.admin_policy.admins;
    let is_admin = |member_id_hex: &str| admins.iter().any(|admin| admin == member_id_hex);
    let admin_count = members
        .iter()
        .filter(|member| is_admin(&member.member_id_hex))
        .count();
    let self_member = members
        .iter()
        .find(|member| member.member_id_hex == my_account_id_hex);
    let is_self_admin = self_member.is_some_and(|member| is_admin(&member.member_id_hex));
    let is_last_admin = is_self_admin && admin_count == 1;
    let lifecycle_terminal = matches!(mls.lifecycle_state, AppGroupLifecycleState::Disbanded);
    let ordinary_actions_enabled = !mls.disbanding && !lifecycle_terminal;
    let leave_request_pending = group.leave_requested_at_ms.is_some();
    let stable = matches!(mls.lifecycle_state, AppGroupLifecycleState::Stable);
    let member_actions = members
        .iter()
        .map(|member| {
            let member_is_admin = is_admin(&member.member_id_hex);
            let is_self = member.member_id_hex == my_account_id_hex;
            let would_remove_last_admin = member_is_admin && admin_count == 1;
            json!({
                "member_id": member.member_id_hex,
                "is_self": is_self,
                "is_admin": member_is_admin,
                "can_remove": is_self_admin
                    && ordinary_actions_enabled
                    && !is_self
                    && !would_remove_last_admin,
                "can_promote": is_self_admin && ordinary_actions_enabled && !member_is_admin,
                "can_demote": is_self_admin
                    && ordinary_actions_enabled
                    && member_is_admin
                    && !is_self
                    && !would_remove_last_admin,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "group_id": group.group_id_hex,
        "my_account_id": my_account_id_hex,
        "is_self_admin": is_self_admin,
        "is_last_admin": is_last_admin,
        "can_invite": is_self_admin && ordinary_actions_enabled,
        "can_leave": self_member.is_some()
            && !is_self_admin
            && !leave_request_pending
            && ordinary_actions_enabled,
        "requires_self_demote_before_leave": self_member.is_some()
            && is_self_admin
            && ordinary_actions_enabled,
        "leave_request_pending": leave_request_pending,
        "leave_requested_at_ms": group.leave_requested_at_ms,
        "lifecycle_state": mls.lifecycle_state,
        "disbanding_enabled": mls.disbanding_enabled,
        "disbanding": mls.disbanding,
        "can_enable_disbanding": is_self_admin
            && ordinary_actions_enabled
            && stable
            && !mls.disbanding_enabled
            && mls.disbanding_blockers.is_empty(),
        "can_disband": is_self_admin && ordinary_actions_enabled && stable && mls.disbanding_enabled,
        "disbanding_blockers": mls.disbanding_blockers,
        "disband_request": mls.disband_request.clone().or_else(|| group.disband_request.clone()),
        "member_actions": member_actions,
    })
}

fn pending_welcome_deliveries_json(
    pending: &[PendingWelcomeDelivery],
) -> Result<Vec<Value>, WnError> {
    pending
        .iter()
        .map(|delivery| {
            Ok(json!({
                "group_id": delivery.group_id_hex,
                "message_id": delivery.message_id_hex,
                "recipient": delivery.recipient_hex,
                "recipient_npub": npub_for_account_id(&delivery.recipient_hex)?,
                "recorded_at": delivery.recorded_at,
            }))
        })
        .collect()
}

enum GroupAdminAction {
    Promote(String),
    Demote(String),
    SelfDemote,
}

async fn group_admin_policy_output(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    group_id: String,
    action: GroupAdminAction,
) -> Result<CommandOutput, WnError> {
    app.status(&account.label)?;
    let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
    let group_id_hex = hex::encode(group_id.as_slice());
    let (verb, admin_id, summary) = match action {
        GroupAdminAction::Promote(pubkey) => {
            let admin_id = parse_public_key(&pubkey)?;
            let summary = runtime
                .promote_admin(&account.label, &group_id, &pubkey)
                .await?;
            ("promoted", admin_id, summary)
        }
        GroupAdminAction::Demote(pubkey) => {
            let admin_id = parse_public_key(&pubkey)?;
            let summary = runtime
                .demote_admin(&account.label, &group_id, &pubkey)
                .await?;
            ("demoted", admin_id, summary)
        }
        GroupAdminAction::SelfDemote => {
            let admin_id = account.account_id_hex.clone();
            let summary = runtime.self_demote_admin(&account.label, &group_id).await?;
            ("self-demoted", admin_id, summary)
        }
    };
    let group = app
        .group(&account.label, &group_id_hex)?
        .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
    let admin_npub = npub_for_account_id(&admin_id)?;
    Ok(CommandOutput {
        plain: format!("{verb} admin {} published={}", admin_id, summary.published),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex)?,
            "group_id": group_id_hex,
            "admin_id": admin_id,
            "admin_npub": admin_npub,
            "group": group_json(group),
            "published": summary.published,
            "message_ids": summary.message_ids,
            "maintenance_disposition": summary.maintenance_disposition,
        }),
    })
}

pub(crate) fn group_mls_state_json(state: AppGroupMlsState) -> Value {
    json!({
        "group_id": state.group_id_hex,
        "epoch": state.epoch,
        "member_count": state.member_count,
        "required_app_components": state.required_app_components,
        "protocol_profile": state.protocol_profile,
        "lifecycle_state": state.lifecycle_state,
        "unrecoverable": state.unrecoverable,
        "disbanding_enabled": state.disbanding_enabled,
        "disbanding": state.disbanding,
        "disbanding_blockers": state.disbanding_blockers,
        "disband_request": state.disband_request,
    })
}

fn group_members_plain(members: &[AppGroupMemberRecord]) -> Result<String, WnError> {
    if members.is_empty() {
        return Ok("no members".to_owned());
    }
    Ok(members
        .iter()
        .map(|member| npub_for_account_id(&member.member_id_hex))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n"))
}

fn pending_invites_plain(invites: &[marmot_app::AppGroupRecord]) -> String {
    if invites.is_empty() {
        return "no pending invites".to_owned();
    }
    invites
        .iter()
        .map(|group| {
            let sanitized_name = terminal_safe_text(&group.profile.name);
            let name = if sanitized_name.trim().is_empty() {
                "unnamed".to_owned()
            } else {
                sanitized_name
            };
            let group_id = terminal_safe_text(&group.group_id_hex);
            match group.welcomer_account_id_hex.as_deref() {
                Some(welcomer) => {
                    format!(
                        "{} {} from {}",
                        group_id,
                        name,
                        terminal_safe_text(welcomer)
                    )
                }
                None => format!("{group_id} {name}"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn group_members_json(members: Vec<AppGroupMemberRecord>) -> Result<Vec<Value>, WnError> {
    members
        .into_iter()
        .map(|member| {
            Ok(json!({
                "member_id": member.member_id_hex,
                "npub": npub_for_account_id(&member.member_id_hex)?,
                "local": member.local,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_welcome_launching_group_commands_require_a_drain() {
        assert!(group_command_requires_welcome_drain(
            &GroupCommand::Create {
                name: "name".into(),
                members: Vec::new(),
                description: None,
            }
        ));
        assert!(group_command_requires_welcome_drain(
            &GroupCommand::Invite {
                group: "group".into(),
                members: vec!["member".into()],
                admins: Vec::new(),
            }
        ));

        assert!(!group_command_requires_welcome_drain(
            &GroupCommand::Members {
                group: "group".into(),
            }
        ));
        assert!(!group_command_requires_welcome_drain(
            &GroupCommand::Remove {
                group: "group".into(),
                members: vec!["member".into()],
            }
        ));
        assert!(!group_command_requires_welcome_drain(
            &GroupCommand::Update {
                group: "group".into(),
                name: Some("name".into()),
                description: None,
            }
        ));
        assert!(!group_command_requires_welcome_drain(
            &GroupCommand::SetAvatarUrl {
                group: "group".into(),
                url: None,
                dim: None,
                thumbhash: None,
                clear: true,
            }
        ));
    }

    #[test]
    fn only_welcome_launching_groups_commands_require_a_drain() {
        assert!(groups_command_requires_welcome_drain(
            &GroupsCommand::Create {
                name: "name".into(),
                members: Vec::new(),
                description: None,
                retention: None,
                image: None,
                image_media_type: None,
            }
        ));
        assert!(groups_command_requires_welcome_drain(
            &GroupsCommand::AddMembers {
                group_id: "group".into(),
                members: vec!["member".into()],
                admins: Vec::new(),
            }
        ));

        assert!(!groups_command_requires_welcome_drain(&GroupsCommand::List));
        assert!(!groups_command_requires_welcome_drain(
            &GroupsCommand::Show {
                group_id: "group".into(),
            }
        ));
        assert!(!groups_command_requires_welcome_drain(
            &GroupsCommand::RemoveMembers {
                group_id: "group".into(),
                members: vec!["member".into()],
            }
        ));
        assert!(!groups_command_requires_welcome_drain(
            &GroupsCommand::Members {
                group_id: "group".into(),
            }
        ));
    }

    fn sample_group(name: &str, welcomer: Option<&str>) -> marmot_app::AppGroupRecord {
        let mut group: marmot_app::AppGroupRecord = serde_json::from_value(json!({
            "group_id_hex": "aa".repeat(16),
            "endpoint": "wss://relay.example",
            "nostr_routing": {
                "component_id": 1,
                "component": "marmot.transport.nostr.routing.v1",
                "nostr_group_id_hex": "bb".repeat(16),
                "relays": ["wss://relay.example"],
                "data_hex": ""
            },
            "profile": {
                "component_id": 2,
                "component": "marmot.group.profile.v1",
                "name": name,
                "description": "",
                "data_hex": ""
            },
            "image": {
                "component_id": 3,
                "component": "marmot.group.blossom-image.v1",
                "present": false,
                "image_hash_hex": "",
                "image_key_hex": "",
                "image_nonce_hex": "",
                "image_upload_key_hex": "",
                "data_hex": ""
            },
            "admin_policy": {
                "component_id": 4,
                "component": "marmot.group.admin-policy.v1",
                "admins": [],
                "data_hex": ""
            }
        }))
        .expect("sample group");
        group.welcomer_account_id_hex = welcomer.map(str::to_owned);
        group
    }

    #[test]
    fn pending_invites_plain_sanitizes_names_and_keeps_unnamed_fallback() {
        let named = sample_group("ops\u{1b}]52;c;YXR0YWNr\u{7}", Some("alice\u{202e}"));
        let blank = sample_group("\u{1b}\u{7}\u{202e}", None);
        let listed = pending_invites_plain(&[named, blank]);
        assert_eq!(
            listed,
            format!(
                "{} ops]52;c;YXR0YWNr from alice\n{} unnamed",
                "aa".repeat(16),
                "aa".repeat(16)
            )
        );
        assert_eq!(listed.matches('\n').count(), 1);
        assert!(!listed.contains('\u{1b}'));
    }
}
