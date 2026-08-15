//! Background reconciliation of pending group invites against the welcomer allowlist.
//!
//! Scheduling (mdk#1380): the worker is event- and retry-driven. `GroupJoined`
//! runtime events are applied immediately; failed applies retry on their own
//! bounded per-candidate backoff (`InvitePolicyRetryState::next_due` wakes the
//! worker exactly when the earliest retry matures). Full enumeration of
//! pending invites is a *safety net* that rediscovers durably pending invites
//! after a process restart or a missed event — it runs once at startup and
//! then on an interval that doubles while passes keep finding nothing
//! (capped), resetting to the base interval whenever work arrives.

use std::collections::HashSet;

use cgka_traits::{GroupId, MemberId, engine::GroupEvent};
use marmot_app::MarmotAppEvent;

use crate::error::ConnectorError;
use crate::reconcile_telemetry::{ReconcileSource, ReconcileTelemetry};
use crate::validation::{InvitePolicyKey, InvitePolicyRetryState, PendingInvitePolicyCandidate};
use crate::{
    AgentConnector, INVITE_POLICY_RECONCILE_INTERVAL, INVITE_POLICY_RECONCILE_MAX_INTERVAL,
};

/// Cadence for the invite-policy safety-net enumeration. Production builds use
/// [`crate::INVITE_POLICY_RECONCILE_INTERVAL`] /
/// [`crate::INVITE_POLICY_RECONCILE_MAX_INTERVAL`]; tests may inject shorter
/// intervals to exercise the adaptive schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvitePolicySchedule {
    pub(crate) base: std::time::Duration,
    pub(crate) max: std::time::Duration,
}

impl AgentConnector {
    pub(crate) fn spawn_invite_policy_worker(&self) {
        let connector = self.clone();
        tokio::spawn(async move {
            connector
                .run_invite_policy_worker(InvitePolicySchedule {
                    base: INVITE_POLICY_RECONCILE_INTERVAL,
                    max: INVITE_POLICY_RECONCILE_MAX_INTERVAL,
                })
                .await;
        });
    }

    pub(crate) async fn run_invite_policy_worker(self, schedule: InvitePolicySchedule) {
        let mut events = self.runtime.subscribe();
        let mut retry_state = InvitePolicyRetryState::default();
        let base = schedule.base.max(std::time::Duration::from_millis(1));
        let mut safety_interval = base.min(schedule.max);
        // A pending invite can survive a process restart without any live
        // event ever reaching this worker: the startup enumeration is the
        // one pass that must always run.
        let _ = self
            .reconcile_pending_invite_policies(&mut retry_state)
            .await;
        let mut safety_deadline = tokio::time::Instant::now() + safety_interval;
        loop {
            let retry_due = retry_state.next_due();
            let retry_sleep = async move {
                match retry_due {
                    Some(due) => tokio::time::sleep_until(due).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = tokio::time::sleep_until(safety_deadline) => {
                    let found_work = self
                        .reconcile_pending_invite_policies(&mut retry_state)
                        .await
                        .is_some_and(|candidates| candidates > 0)
                        || retry_state.has_pending();
                    safety_interval = if found_work {
                        base
                    } else {
                        (safety_interval * 2).min(schedule.max)
                    };
                    safety_deadline = tokio::time::Instant::now() + safety_interval;
                }
                _ = retry_sleep, if retry_due.is_some() => {
                    // A matured retry is just an enumeration whose due gate now
                    // passes; it does not perturb the safety net's cadence.
                    let _ = self
                        .reconcile_pending_invite_policies(&mut retry_state)
                        .await;
                }
                event = events.recv() => {
                    let event = match event {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(lagged)) => {
                            tracing::warn!(
                                target: "agent_connector",
                                method = "run_invite_policy_worker",
                                lagged,
                                "invite policy event stream lagged; reconciling pending invites"
                            );
                            let _ = self
                                .reconcile_pending_invite_policies(&mut retry_state)
                                .await;
                            safety_interval = base;
                            safety_deadline = tokio::time::Instant::now() + safety_interval;
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    };
                    let MarmotAppEvent::GroupEvent(group_event) = event else {
                        continue;
                    };
                    let GroupEvent::GroupJoined {
                        group_id, welcomer, ..
                    } = group_event.event
                    else {
                        continue;
                    };
                    let group_id_hex = hex::encode(group_id.as_slice());
                    let candidate = PendingInvitePolicyCandidate {
                        key: InvitePolicyKey::new(&group_event.account_id_hex, &group_id_hex),
                        group_id,
                        welcomer,
                    };
                    let now = tokio::time::Instant::now();
                    if retry_state.is_due(&candidate.key, now) {
                        self.apply_invite_policy_candidate(candidate, &mut retry_state, now)
                            .await;
                    }
                    // A joined group means reconcile-relevant state changed:
                    // pull the safety net back to the base interval.
                    safety_interval = base;
                    safety_deadline = tokio::time::Instant::now() + safety_interval;
                }
            }
        }
    }

    /// Enumerate pending invite candidates and apply the policy to every one
    /// whose retry backoff has matured. Returns the number of pending
    /// candidates found, or `None` when the enumeration itself failed.
    /// Per-candidate apply failures are retried on their own backoff and do
    /// not fail the pass.
    async fn reconcile_pending_invite_policies(
        &self,
        retry_state: &mut InvitePolicyRetryState,
    ) -> Option<usize> {
        let started = tokio::time::Instant::now();
        ReconcileTelemetry::bump(&self.reconcile_telemetry.invite_enumerations_started);
        let (candidates, accounts_considered) = match self.pending_invite_policy_candidates() {
            Ok(result) => result,
            Err(err) => {
                ReconcileTelemetry::bump(&self.reconcile_telemetry.invite_enumerations_failed);
                tracing::warn!(
                    target: "agent_connector",
                    method = "reconcile_pending_invite_policies",
                    source = ReconcileSource::InvitePolicy.as_str(),
                    duration_ms = started.elapsed().as_millis() as u64,
                    result = "error",
                    error_code = err.privacy_safe_code(),
                    "pending invite policy reconciliation failed"
                );
                return None;
            }
        };
        let candidate_count = candidates.len();
        ReconcileTelemetry::bump(&self.reconcile_telemetry.invite_enumerations_completed);
        ReconcileTelemetry::add(
            &self.reconcile_telemetry.invite_accounts_considered,
            accounts_considered,
        );
        ReconcileTelemetry::add(
            &self.reconcile_telemetry.invite_candidate_rows_considered,
            candidate_count,
        );
        tracing::debug!(
            target: "agent_connector",
            method = "reconcile_pending_invite_policies",
            source = ReconcileSource::InvitePolicy.as_str(),
            duration_ms = started.elapsed().as_millis() as u64,
            result = "ok",
            accounts_considered,
            candidates_considered = candidate_count,
            retry_backoffs_pending = retry_state.has_pending(),
            "pending invite policy reconciliation completed"
        );
        let pending = candidates
            .iter()
            .map(|candidate| candidate.key.clone())
            .collect::<HashSet<_>>();
        retry_state.retain_pending(&pending);
        let now = tokio::time::Instant::now();
        for candidate in candidates {
            if retry_state.is_due(&candidate.key, now) {
                self.apply_invite_policy_candidate(candidate, retry_state, now)
                    .await;
            }
        }
        Some(candidate_count)
    }

    /// The pending-invite candidate set, reading only the two projection
    /// columns the policy needs (`group_id`, `welcomer`) — never the full
    /// account projection, seen-event window, or component blobs (mdk#1380).
    /// Returns the candidates plus how many local-signing accounts were
    /// enumerated, for aggregate telemetry.
    fn pending_invite_policy_candidates(
        &self,
    ) -> Result<(Vec<PendingInvitePolicyCandidate>, usize), ConnectorError> {
        let mut candidates = Vec::new();
        let accounts = self
            .account_home
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
            .collect::<Vec<_>>();
        let accounts_considered = accounts.len();
        for account in accounts {
            for invite in self.app.pending_group_invites(&account.label)? {
                candidates.push(PendingInvitePolicyCandidate {
                    key: InvitePolicyKey::new(
                        &account.account_id_hex,
                        &hex::encode(invite.group_id.as_slice()),
                    ),
                    group_id: invite.group_id,
                    welcomer: invite.welcomer,
                });
            }
        }
        Ok((candidates, accounts_considered))
    }

    async fn apply_invite_policy_candidate(
        &self,
        candidate: PendingInvitePolicyCandidate,
        retry_state: &mut InvitePolicyRetryState,
        now: tokio::time::Instant,
    ) {
        match self
            .apply_invite_policy(
                &candidate.key.account_id_hex,
                &candidate.group_id,
                candidate.welcomer,
            )
            .await
        {
            Ok(()) => {
                retry_state.clear(&candidate.key);
                ReconcileTelemetry::bump(&self.reconcile_telemetry.invite_policy_applied);
            }
            Err(err) => {
                let (attempts, retry_delay) = retry_state.record_failure(candidate.key, now);
                ReconcileTelemetry::bump(&self.reconcile_telemetry.invite_policy_apply_failures);
                tracing::warn!(
                    target: "agent_connector",
                    method = "apply_invite_policy_candidate",
                    error_code = err.privacy_safe_code(),
                    attempts,
                    retry_delay_ms = retry_delay.as_millis() as u64,
                    "invite policy application failed; will retry"
                );
            }
        }
    }

    async fn apply_invite_policy(
        &self,
        account_id_hex: &str,
        group_id: &GroupId,
        welcomer: Option<MemberId>,
    ) -> Result<(), ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let (welcomer_present, welcomer_allowlisted) = match welcomer {
            Some(welcomer) => {
                let allowlisted = if self.dev_allow_any_invites {
                    false
                } else {
                    let welcomer_account_id_hex = hex::encode(welcomer.as_slice());
                    self.allowlists
                        .contains(&account.account_id_hex, &welcomer_account_id_hex)?
                };
                (true, allowlisted)
            }
            None => (false, false),
        };
        let allowed = invite_policy_allows(
            self.dev_allow_any_invites,
            welcomer_present,
            welcomer_allowlisted,
        );
        if allowed {
            // A catch-up-owned worker returns AccountWorkerBusy as a
            // definitely-not-started result. Propagating it here is
            // deliberate: apply_invite_policy_candidate records the failure
            // in its per-invite bounded backoff and retries safely.
            self.runtime
                .accept_group_invite(&account.label, group_id)
                .await?;
        } else {
            self.runtime
                .decline_group_invite(&account.label, group_id)
                .await?;
        }
        Ok(())
    }
}

pub(crate) fn invite_policy_allows(
    dev_allow_any_invites: bool,
    welcomer_present: bool,
    welcomer_allowlisted: bool,
) -> bool {
    welcomer_present && (dev_allow_any_invites || welcomer_allowlisted)
}
