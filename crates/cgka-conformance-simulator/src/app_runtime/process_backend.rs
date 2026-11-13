//! Public app API bridge; the scenario coordinator never opens child storage.
use super::process_io::{ProcessClient, WireError};
use cgka_traits::engine::GroupEvent;
use cgka_traits::{GroupId, MessageId};
use marmot_app::{
    AppCreateGroupOptions, AppError, AppGroupMemberRecord, AppGroupMlsState, AppGroupRecord,
    AppMessageQuery, AppPerformanceSnapshot, AppStatus, GroupRecoveryStatus, MarmotApp,
    MarmotAppRuntime, MemberResolutionPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub(crate) fn require_member_operation<T>(
    result: marmot_app::GroupMemberResult<T>,
) -> Result<T, AppError> {
    result.operation.ok_or_else(|| {
        AppError::Io(std::io::Error::other(
            "scenario member operation unavailable",
        ))
    })
}

#[derive(Clone)]
pub(super) enum ParticipantApp {
    Local(Box<MarmotApp>),
    Remote(ProcessClient),
}
#[derive(Clone)]
pub(super) enum ParticipantRuntime {
    Local(Box<MarmotAppRuntime>),
    Remote(ProcessClient),
}

/// Only fields consumed by scenario commands, never private MLS state.
#[derive(Serialize, Deserialize)]
pub(super) struct SendReceipt {
    pub published: usize,
    pub message_ids: Vec<String>,
}
impl From<marmot_app::SendSummary> for SendReceipt {
    fn from(s: marmot_app::SendSummary) -> Self {
        Self {
            published: s.published,
            message_ids: s.message_ids,
        }
    }
}
/// An executed repair pass is distinct from a certificate of history coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HistoryRepairOutcome {
    Complete,
    CoverageUnproven,
}

pub(crate) fn history_repair_outcome(
    result: Result<(), AppError>,
) -> Result<HistoryRepairOutcome, AppError> {
    match result {
        Ok(()) => Ok(HistoryRepairOutcome::Complete),
        Err(error)
            if matches!(
                error.full_history_repair_incomplete(),
                Some((
                    marmot_app::FullHistoryRepairIncompleteReason::CoverageUnproven
                        | marmot_app::FullHistoryRepairIncompleteReason::BelowRetentionWindow,
                    false,
                ))
            ) =>
        {
            Ok(HistoryRepairOutcome::CoverageUnproven)
        }
        Err(error) => Err(error),
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct EventSummary {
    pub count: usize,
    pub errors: Vec<String>,
    #[serde(default)]
    pub superseded_group_changes: Vec<(GroupId, super::SupersededGroupChange)>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Init {
    pub root: std::path::PathBuf,
    pub relay_url: String,
    /// Further endpoints of the same relay process.
    #[serde(default)]
    pub extra_relay_urls: Vec<String>,
    pub settlement_ms: Option<u64>,
    pub immediate_maintenance: bool,
    pub create_identity: bool,
}
/// Every record in the forensic audit files, one JSON value per line.
fn read_audit_records(files: &[marmot_app::AuditLogFile]) -> Result<Vec<Value>, AppError> {
    let mut records = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file.path)?;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            records.push(serde_json::from_str(line)?);
        }
    }
    Ok(records)
}

async fn audit_records(runtime: &MarmotAppRuntime) -> Result<Vec<Value>, AppError> {
    let files = runtime.audit_log_files()?;
    tokio::task::spawn_blocking(move || read_audit_records(&files))
        .await
        .map_err(|error| AppError::Io(std::io::Error::other(error)))?
}

/// Count the queued intents the engine refuses at drain, from `events`, until
/// the runtime closes.
fn tally_queued_intent_refusals(
    mut events: tokio::sync::broadcast::Receiver<marmot_app::MarmotAppEvent>,
    refusals: Arc<Mutex<super::QueuedIntentRefusals>>,
) {
    use tokio::sync::broadcast::error::RecvError;
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(marmot_app::MarmotAppEvent::GroupEvent(event)) => {
                    if let GroupEvent::QueuedIntentRefused {
                        intent_kind,
                        reason,
                        ..
                    } = event.event
                    {
                        let mut refusals = refusals.lock().expect("refusal tally lock");
                        let key = format!("{intent_kind}:{reason}");
                        *refusals.by_kind_and_reason.entry(key).or_default() += 1;
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(missed)) => {
                    refusals.lock().expect("refusal tally lock").lagged_events += missed;
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

impl ParticipantRuntime {
    pub async fn set_audit_log(&self, enabled: bool) -> Result<(), AppError> {
        match self {
            Self::Local(r) => r
                .set_audit_log_settings(marmot_app::AuditLogSettings { enabled })
                .await
                .map(drop),
            Self::Remote(p) => p
                .call_async("set_audit_log", json!([enabled]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn audit_records(&self) -> Result<Vec<Value>, AppError> {
        match self {
            Self::Local(r) => audit_records(r).await,
            Self::Remote(p) => p
                .call_async("audit_records", json!([]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn queued_intent_refusals(&self) -> Result<super::QueuedIntentRefusals, AppError> {
        match self {
            // The harness doesn't tally an in-process participant's events.
            Self::Local(_) => Err(AppError::Io(std::io::Error::other(
                "queued intent refusals are tallied in participant processes",
            ))),
            Self::Remote(p) => p
                .call_async("queued_intent_refusals", json!([]))
                .await
                .map_err(WireError::app),
        }
    }
    pub fn drain_events(&self) -> Result<EventSummary, AppError> {
        match self {
            Self::Local(_) => Ok(EventSummary::default()),
            Self::Remote(p) => p.call("events", json!([])).map_err(WireError::app),
        }
    }
    pub fn app_performance_snapshot(&self) -> Result<AppPerformanceSnapshot, AppError> {
        match self {
            Self::Local(r) => Ok(r.app_performance_snapshot()),
            Self::Remote(p) => p.call("performance", json!([])).map_err(WireError::app),
        }
    }
    pub async fn shutdown_and_close(&self) -> Result<(), AppError> {
        match self {
            Self::Local(r) => r.shutdown_and_close().await,
            Self::Remote(p) => {
                let close = p.call_async::<()>("close", json!([])).await;
                let exit = p.reap();
                close.map_err(WireError::app)?;
                exit.map_err(WireError::app)
            }
        }
    }
    pub async fn accept_group_invite_retrying_busy(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<(), AppError> {
        match self {
            Self::Local(r) => super::accept_group_invite_retrying_busy(r, account, group).await,
            Self::Remote(p) => p
                .call_async("accept_group_invite_retrying_busy", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn catch_up_accounts(&self) -> Result<(), AppError> {
        match self {
            Self::Local(r) => r.catch_up_accounts().await,
            Self::Remote(p) => p
                .call_async("catch_up_accounts", json!([]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn repair_full_history(
        &self,
        account: &str,
    ) -> Result<HistoryRepairOutcome, AppError> {
        match self {
            Self::Local(r) => history_repair_outcome(r.repair_full_history(account).await),
            Self::Remote(p) => p
                .call_async("repair_full_history", json!([account]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn pause_maintenance(&self, account: &str) -> Result<(), AppError> {
        match self {
            Self::Local(r) => r.pause_maintenance(account).await,
            Self::Remote(p) => p
                .call_async("pause_maintenance", json!([account]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn resume_maintenance(&self, account: &str) -> Result<(), AppError> {
        match self {
            Self::Local(r) => r.resume_maintenance(account).await,
            Self::Remote(p) => p
                .call_async("resume_maintenance", json!([account]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn create_group(
        &self,
        account: &str,
        name: &str,
        members: &[String],
        description: Option<String>,
    ) -> Result<GroupId, AppError> {
        match self {
            Self::Local(r) => r
                .create_group_with_options(
                    account,
                    name,
                    members,
                    AppCreateGroupOptions {
                        description: description.unwrap_or_default(),
                        member_resolution: MemberResolutionPolicy::Atomic,
                        ..Default::default()
                    },
                )
                .await
                .and_then(require_member_operation),
            Self::Remote(p) => p
                .call_async("create_group", json!([account, name, members, description]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn group_members(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<Vec<AppGroupMemberRecord>, AppError> {
        match self {
            Self::Local(r) => r.group_members(account, group).await,
            Self::Remote(p) => p
                .call_async("group_members", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn group_mls_state(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<AppGroupMlsState, AppError> {
        match self {
            Self::Local(r) => r.group_mls_state(account, group).await,
            Self::Remote(p) => p
                .call_async("group_mls_state", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn group_recovery_status(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<GroupRecoveryStatus, AppError> {
        match self {
            Self::Local(r) => r.group_recovery_status(account, group).await,
            Self::Remote(p) => p
                .call_async("group_recovery_status", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn account_recovery_status(
        &self,
        account: &str,
    ) -> Result<marmot_app::AccountRecoveryStatus, AppError> {
        match self {
            Self::Local(r) => r.account_recovery_status(account).await,
            Self::Remote(p) => p
                .call_async("account_recovery_status", json!([account]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn confirm_group_rejoin(
        &self,
        account: &str,
        welcome: &MessageId,
        token: &[u8],
    ) -> Result<GroupRecoveryStatus, AppError> {
        match self {
            Self::Local(r) => r.confirm_group_rejoin(account, welcome, token).await,
            Self::Remote(p) => p
                .call_async("confirm_group_rejoin", json!([account, welcome, token]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn schedule_manual_self_update(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<String, AppError> {
        match self {
            Self::Local(r) => r.schedule_manual_self_update(account, group).await,
            Self::Remote(p) => p
                .call_async("schedule_manual_self_update", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn maintenance_status(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<cgka_traits::GroupMaintenanceStatus, AppError> {
        match self {
            Self::Local(r) => r.maintenance_status(account, group).await,
            Self::Remote(p) => p
                .call_async("maintenance_status", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn run_due_maintenance(&self, account: &str) -> Result<(), AppError> {
        match self {
            Self::Local(r) => r.run_due_maintenance(account).await.map(|_| ()),
            Self::Remote(p) => p
                .call_async("run_due_maintenance", json!([account]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn invite_members(
        &self,
        account: &str,
        group: &GroupId,
        members: &[String],
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r
                .invite_members_with_initial_admins(
                    account,
                    group,
                    members,
                    &[],
                    MemberResolutionPolicy::Atomic,
                )
                .await
                .and_then(require_member_operation)
                .map(Into::into),
            Self::Remote(p) => p
                .call_async("invite_members", json!([account, group, members]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn remove_members(
        &self,
        account: &str,
        group: &GroupId,
        members: &[String],
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r
                .remove_members(account, group, members)
                .await
                .map(Into::into),
            Self::Remote(p) => p
                .call_async("remove_members", json!([account, group, members]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn promote_admin(
        &self,
        account: &str,
        group: &GroupId,
        member: &str,
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r
                .promote_admin(account, group, member)
                .await
                .map(Into::into),
            Self::Remote(p) => p
                .call_async("promote_admin", json!([account, group, member]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn demote_admin(
        &self,
        account: &str,
        group: &GroupId,
        member: &str,
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r.demote_admin(account, group, member).await.map(Into::into),
            Self::Remote(p) => p
                .call_async("demote_admin", json!([account, group, member]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn self_demote_admin(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r.self_demote_admin(account, group).await.map(Into::into),
            Self::Remote(p) => p
                .call_async("self_demote_admin", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn leave_group(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r.leave_group(account, group).await.map(Into::into),
            Self::Remote(p) => p
                .call_async("leave_group", json!([account, group]))
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn update_group_profile(
        &self,
        account: &str,
        group: &GroupId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r
                .update_group_profile(account, group, name, description)
                .await
                .map(Into::into),
            Self::Remote(p) => p
                .call_async(
                    "update_group_profile",
                    json!([account, group, name, description]),
                )
                .await
                .map_err(WireError::app),
        }
    }
    pub async fn send_message(
        &self,
        account: &str,
        group: &GroupId,
        payload: Vec<u8>,
    ) -> Result<SendReceipt, AppError> {
        match self {
            Self::Local(r) => r
                .send_message(account, group, payload)
                .await
                .map(Into::into),
            Self::Remote(p) => p
                .call_async("send_message", json!([account, group, payload]))
                .await
                .map_err(WireError::app),
        }
    }
    pub fn timeline_message(
        &self,
        account: &str,
        group: &str,
        message: &str,
    ) -> Result<Option<marmot_app::TimelineMessageRecord>, AppError> {
        match self {
            Self::Local(r) => r.timeline_message(account, group, message),
            Self::Remote(p) => p
                .call("timeline_message", json!([account, group, message]))
                .map_err(WireError::app),
        }
    }
}
impl ParticipantApp {
    pub fn group(&self, account: &str, group: &str) -> Result<Option<AppGroupRecord>, AppError> {
        match self {
            Self::Local(a) => a.group(account, group),
            Self::Remote(p) => p
                .call("group", json!([account, group]))
                .map_err(WireError::app),
        }
    }
    pub fn status(&self, account: &str) -> Result<AppStatus, AppError> {
        match self {
            Self::Local(a) => a.status(account),
            Self::Remote(p) => p.call("status", json!([account])).map_err(WireError::app),
        }
    }
    pub fn messages_with_query(
        &self,
        account: &str,
        query: AppMessageQuery,
    ) -> Result<Vec<marmot_app::AppMessageRecord>, AppError> {
        match self {
            Self::Local(a) => a.messages_with_query(account, query),
            Self::Remote(p) => p
                .call(
                    "messages",
                    json!([account, query.group_id_hex, query.kinds, query.limit]),
                )
                .map_err(WireError::app),
        }
    }
}

pub(super) async fn remote_participant(
    init: Init,
) -> Result<(ParticipantApp, ParticipantRuntime, String), AppError> {
    let p = ProcessClient::spawn("participant", &init.root).map_err(WireError::app)?;
    let account = p
        .call_async(
            "initialize",
            serde_json::to_value(&init).map_err(AppError::from)?,
        )
        .await
        .map_err(WireError::app)?;
    Ok((
        ParticipantApp::Remote(p.clone()),
        ParticipantRuntime::Remote(p),
        account,
    ))
}

pub(super) struct ParticipantServer {
    pub app: MarmotApp,
    pub runtime: MarmotAppRuntime,
    pub events: tokio::sync::broadcast::Receiver<marmot_app::MarmotAppEvent>,
    refusals: Arc<Mutex<super::QueuedIntentRefusals>>,
}
fn args<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, WireError> {
    serde_json::from_value(value)
        .map_err(|_| WireError::environment("app_process_invalid_arguments"))
}
fn value<T: Serialize>(value: T) -> Result<Value, WireError> {
    serde_json::to_value(value).map_err(|_| WireError::environment("app_process_result_encode"))
}
impl ParticipantServer {
    pub async fn initialize(init: Init) -> Result<(Self, String), WireError> {
        if !init.root.is_absolute() {
            return Err(WireError::environment("app_process_root_not_absolute"));
        }
        fs_private::create_dir_all_private(&init.root)
            .map_err(|_| WireError::environment("app_process_root_failed"))?;
        let relay_urls = std::iter::once(init.relay_url.clone())
            .chain(init.extra_relay_urls.iter().cloned())
            .collect::<Vec<_>>();
        let app = super::app_for_root(
            &init.root,
            &relay_urls,
            init.settlement_ms,
            init.immediate_maintenance
                .then(marmot_app::MaintenanceTiming::immediate),
        );
        let runtime = MarmotAppRuntime::new(app.clone());
        let setup: Result<String, WireError> = async {
            runtime.start().await?;
            let account = if init.create_identity {
                let endpoints = super::relay_endpoints(&relay_urls);
                runtime
                    .create_identity(marmot_app::AccountSetupRequest {
                        default_relays: endpoints.clone(),
                        bootstrap_relays: endpoints,
                        publish_missing_relay_lists: true,
                        publish_initial_key_package: true,
                        ..Default::default()
                    })
                    .await?
                    .account
                    .account_id_hex
            } else {
                let accounts = runtime.accounts().managed_accounts()?;
                if accounts.len() != 1 {
                    return Err(WireError::environment("app_process_identity_count"));
                }
                accounts[0].account_id_hex.clone()
            };
            Ok(account)
        }
        .await;
        let account = match setup {
            Ok(account) => account,
            Err(error) => {
                runtime.shutdown_and_close().await?;
                return Err(error);
            }
        };
        let events = runtime.subscribe();
        let refusals = Arc::default();
        tally_queued_intent_refusals(runtime.subscribe(), Arc::clone(&refusals));
        Ok((
            Self {
                app,
                runtime,
                events,
                refusals,
            },
            account,
        ))
    }
    pub async fn handle(&mut self, method: &str, arguments: Value) -> Result<Value, WireError> {
        let r = &self.runtime;
        match method {
            "catch_up_accounts" => {
                let _: [Value; 0] = args(arguments)?;
                value(r.catch_up_accounts().await?)
            }
            "repair_full_history" => {
                let (account,): (String,) = args(arguments)?;
                value(history_repair_outcome(
                    r.repair_full_history(&account).await,
                )?)
            }
            "pause_maintenance" => {
                let (account,): (String,) = args(arguments)?;
                value(r.pause_maintenance(&account).await?)
            }
            "resume_maintenance" => {
                let (account,): (String,) = args(arguments)?;
                value(r.resume_maintenance(&account).await?)
            }
            "create_group" => {
                let (account, name, members, description): (
                    String,
                    String,
                    Vec<String>,
                    Option<String>,
                ) = args(arguments)?;
                value(require_member_operation(
                    r.create_group_with_options(
                        &account,
                        &name,
                        &members,
                        AppCreateGroupOptions {
                            description: description.unwrap_or_default(),
                            member_resolution: MemberResolutionPolicy::Atomic,
                            ..Default::default()
                        },
                    )
                    .await?,
                )?)
            }
            "group_members" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                value(r.group_members(&account, &group).await?)
            }
            "group_mls_state" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                value(r.group_mls_state(&account, &group).await?)
            }
            "group_recovery_status" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                value(r.group_recovery_status(&account, &group).await?)
            }
            "account_recovery_status" => {
                let (account,): (String,) = args(arguments)?;
                value(r.account_recovery_status(&account).await?)
            }
            "set_audit_log" => {
                let (enabled,): (bool,) = args(arguments)?;
                r.set_audit_log_settings(marmot_app::AuditLogSettings { enabled })
                    .await?;
                value(())
            }
            "audit_records" => {
                let _: [Value; 0] = args(arguments)?;
                value(audit_records(r).await?)
            }
            "queued_intent_refusals" => {
                let _: [Value; 0] = args(arguments)?;
                value(self.refusals.lock().expect("refusal tally lock").clone())
            }
            "confirm_group_rejoin" => {
                let (account, welcome, token): (String, MessageId, Vec<u8>) = args(arguments)?;
                value(r.confirm_group_rejoin(&account, &welcome, &token).await?)
            }
            "schedule_manual_self_update" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                value(r.schedule_manual_self_update(&account, &group).await?)
            }
            "maintenance_status" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                value(r.maintenance_status(&account, &group).await?)
            }
            "run_due_maintenance" => {
                let (account,): (String,) = args(arguments)?;
                r.run_due_maintenance(&account).await?;
                value(())
            }
            "invite_members" => {
                let (account, group, members): (String, GroupId, Vec<String>) = args(arguments)?;
                value(SendReceipt::from(require_member_operation(
                    r.invite_members_with_initial_admins(
                        &account,
                        &group,
                        &members,
                        &[],
                        MemberResolutionPolicy::Atomic,
                    )
                    .await?,
                )?))
            }
            "remove_members" => {
                let (account, group, members): (String, GroupId, Vec<String>) = args(arguments)?;
                value(SendReceipt::from(
                    r.remove_members(&account, &group, &members).await?,
                ))
            }
            "promote_admin" => {
                let (account, group, member): (String, GroupId, String) = args(arguments)?;
                value(SendReceipt::from(
                    r.promote_admin(&account, &group, &member).await?,
                ))
            }
            "demote_admin" => {
                let (account, group, member): (String, GroupId, String) = args(arguments)?;
                value(SendReceipt::from(
                    r.demote_admin(&account, &group, &member).await?,
                ))
            }
            "self_demote_admin" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                value(SendReceipt::from(
                    r.self_demote_admin(&account, &group).await?,
                ))
            }
            "leave_group" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                value(SendReceipt::from(r.leave_group(&account, &group).await?))
            }
            "update_group_profile" => {
                let (account, group, name, description): (
                    String,
                    GroupId,
                    Option<String>,
                    Option<String>,
                ) = args(arguments)?;
                value(SendReceipt::from(
                    r.update_group_profile(&account, &group, name, description)
                        .await?,
                ))
            }
            "send_message" => {
                let (account, group, payload): (String, GroupId, Vec<u8>) = args(arguments)?;
                value(SendReceipt::from(
                    r.send_message(&account, &group, payload).await?,
                ))
            }
            "group" => {
                let (account, group): (String, String) = args(arguments)?;
                value(self.app.group(&account, &group)?)
            }
            "status" => {
                let (account,): (String,) = args(arguments)?;
                value(self.app.status(&account)?)
            }
            "messages" => {
                let (account, group_id_hex, kinds, limit): (
                    String,
                    Option<String>,
                    Option<Vec<u64>>,
                    Option<usize>,
                ) = args(arguments)?;
                value(self.app.messages_with_query(
                    &account,
                    AppMessageQuery {
                        group_id_hex,
                        kinds,
                        limit,
                    },
                )?)
            }
            "timeline_message" => {
                let (account, group, message): (String, String, String) = args(arguments)?;
                value(r.timeline_message(&account, &group, &message)?)
            }
            "performance" => value(r.app_performance_snapshot()),
            "accept_group_invite_retrying_busy" => {
                let (account, group): (String, GroupId) = args(arguments)?;
                super::accept_group_invite_retrying_busy(r, &account, &group).await?;
                value(())
            }
            "events" => {
                let mut summary = EventSummary::default();
                loop {
                    match self.events.try_recv() {
                        Ok(event) => {
                            summary.count += 1;
                            summary
                                .superseded_group_changes
                                .extend(super::superseded_group_change(&event));
                            if let marmot_app::MarmotAppEvent::AccountError(e) = event {
                                summary.errors.push(e.message);
                                if summary.errors.len() > 8 {
                                    summary.errors.remove(0);
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
                value(summary)
            }
            "close" => {
                r.shutdown_and_close().await?;
                value(())
            }
            _ => Err(WireError::environment("app_process_unknown_method")),
        }
    }
}

#[cfg(test)]
mod repair_outcome_tests {
    use super::*;
    use marmot_app::FullHistoryRepairIncompleteReason as Reason;

    #[test]
    fn only_unproven_or_window_only_coverage_without_loss_can_continue_to_independent_oracles() {
        assert_eq!(
            history_repair_outcome(Ok(())).unwrap(),
            HistoryRepairOutcome::Complete
        );
        for reason in [
            Reason::CoverageUnproven,
            Reason::BelowRetentionWindow,
            Reason::Cancelled,
            Reason::Deadline,
            Reason::DeliveryLoss,
            Reason::EoseTimeout,
            Reason::NoRelayEose,
            Reason::NovelProgressYield,
            Reason::NoProgressYield,
            Reason::Unconfirmed,
        ] {
            for loss in [false, true] {
                let result = history_repair_outcome(Err(AppError::FullHistoryRepairIncomplete {
                    reason,
                    delivery_loss_pending: loss,
                }));
                if matches!(
                    reason,
                    Reason::CoverageUnproven | Reason::BelowRetentionWindow
                ) && !loss
                {
                    let outcome = result.unwrap();
                    assert_eq!(outcome, HistoryRepairOutcome::CoverageUnproven);
                    let wire = serde_json::to_value(outcome).unwrap();
                    assert_ne!(
                        wire,
                        serde_json::to_value(HistoryRepairOutcome::Complete).unwrap()
                    );
                    assert_eq!(
                        serde_json::from_value::<HistoryRepairOutcome>(wire).unwrap(),
                        outcome
                    );
                } else {
                    assert!(result.is_err(), "{reason:?}, loss={loss}");
                }
            }
        }
        assert!(history_repair_outcome(Err(AppError::AccountWorkerResponseTimedOut)).is_err());
        assert!(
            history_repair_outcome(Err(AppError::AccountCatchUp(
                marmot_app::AccountCatchUpFailure::new(
                    "full_history_coverage_unproven".into(),
                    marmot_app::SyncFailureClassification::UNKNOWN,
                )
            )))
            .is_err(),
            "text is not typed coverage evidence"
        );
    }
}
