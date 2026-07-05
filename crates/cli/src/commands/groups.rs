//! `group` and `groups` command namespace handlers and group output helpers.

use cgka_traits::GroupId;
use marmot_account::AccountHome;
use marmot_app::{AppError, AppGroupMemberRecord, AppGroupMlsState, MarmotApp, MarmotAppRuntime};
use serde_json::{Value, json};

use crate::{
    CommandOutput, GroupCommand, GroupsCommand, WnError, ensure_local_signing, group_json,
    group_list_plain, group_show_output, normalize_group_id_hex, npub_for_account_id,
    parse_public_key, resolve_account,
};

pub(crate) async fn group_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: GroupCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    let runtime = app.runtime();
    group_command_with_runtime(account_home, app, &runtime, command, account_flag).await
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
            let group_id_hex = hex::encode(group_id.as_slice());
            let group = app
                .group(&account.label, &group_id_hex)?
                .ok_or_else(|| AppError::UnknownGroup(group_id_hex.clone()))?;
            let members = runtime.group_members(&account.label, &group_id).await?;
            Ok(CommandOutput {
                plain: format!("created group {group_id_hex}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group.group_id_hex,
                    "name": group.profile.name.clone(),
                    "profile": group.profile,
                    "image": group.image,
                    "admin_policy": group.admin_policy,
                    "agent_text_stream": group.agent_text_stream,
                    "members": group_members_json(members)?,
                }),
            })
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
        GroupCommand::Invite { group, members } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group)?)?);
            let summary = runtime
                .invite_members(&account.label, &group_id, &members)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "invited {} member(s) published={}",
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
    groups_command_with_runtime(account_home, app, &runtime, command, account_flag).await
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
        } => {
            group_command_with_runtime(
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
            .await
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
        GroupsCommand::AddMembers { group_id, members } => {
            group_command_with_runtime(
                account_home,
                app,
                runtime,
                GroupCommand::Invite {
                    group: group_id,
                    members,
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
                plain: group.endpoint.clone(),
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
            let group = runtime
                .accept_group_invite(&account.label, &group_id)
                .await?;
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
        GroupsCommand::SubscribeState { .. } => Err(WnError::MessagesSubscribeRequiresDaemon),
    }
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
        }),
    })
}

pub(crate) fn group_mls_state_json(state: AppGroupMlsState) -> Value {
    json!({
        "group_id": state.group_id_hex,
        "epoch": state.epoch,
        "member_count": state.member_count,
        "required_app_components": state.required_app_components,
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
            let name = if group.profile.name.trim().is_empty() {
                "unnamed"
            } else {
                group.profile.name.as_str()
            };
            match group.welcomer_account_id_hex.as_deref() {
                Some(welcomer) => format!("{} {} from {}", group.group_id_hex, name, welcomer),
                None => format!("{} {}", group.group_id_hex, name),
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
