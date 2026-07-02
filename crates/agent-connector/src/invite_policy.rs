//! Background reconciliation of pending group invites against the welcomer allowlist.

use std::collections::HashSet;

use cgka_traits::{GroupId, MemberId, engine::GroupEvent};
use marmot_app::MarmotAppEvent;

use crate::error::ConnectorError;
use crate::validation::{
    InvitePolicyKey, InvitePolicyRetryState, PendingInvitePolicyCandidate, normalize_hex,
};
use crate::{AgentConnector, INVITE_POLICY_RECONCILE_INTERVAL};

impl AgentConnector {
    pub(crate) fn spawn_invite_policy_worker(&self) {
        let connector = self.clone();
        tokio::spawn(async move {
            connector.run_invite_policy_worker().await;
        });
    }

    async fn run_invite_policy_worker(self) {
        let mut events = self.runtime.subscribe();
        let mut retry_state = InvitePolicyRetryState::default();
        let mut reconcile_interval = tokio::time::interval_at(
            tokio::time::Instant::now(),
            INVITE_POLICY_RECONCILE_INTERVAL,
        );
        reconcile_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = reconcile_interval.tick() => {
                    self.reconcile_pending_invite_policies(&mut retry_state).await;
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
                            self.reconcile_pending_invite_policies(&mut retry_state).await;
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
                }
            }
        }
    }

    async fn reconcile_pending_invite_policies(&self, retry_state: &mut InvitePolicyRetryState) {
        let candidates = match self.pending_invite_policy_candidates() {
            Ok(candidates) => candidates,
            Err(err) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "reconcile_pending_invite_policies",
                    error_code = err.privacy_safe_code(),
                    "pending invite policy reconciliation failed"
                );
                return;
            }
        };
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
    }

    fn pending_invite_policy_candidates(
        &self,
    ) -> Result<Vec<PendingInvitePolicyCandidate>, ConnectorError> {
        let mut candidates = Vec::new();
        for account in self
            .account_home
            .accounts()?
            .into_iter()
            .filter(|account| account.local_signing)
        {
            for group in self.app.groups(&account.label)? {
                if !group.pending_confirmation || group.archived {
                    continue;
                }
                let group_id_hex = normalize_hex(&group.group_id_hex)?;
                let group_id = GroupId::new(hex::decode(&group_id_hex)?);
                let welcomer = match group.welcomer_account_id_hex.as_deref() {
                    Some(welcomer) => Some(MemberId::new(hex::decode(normalize_hex(welcomer)?)?)),
                    None => None,
                };
                candidates.push(PendingInvitePolicyCandidate {
                    key: InvitePolicyKey::new(&account.account_id_hex, &group_id_hex),
                    group_id,
                    welcomer,
                });
            }
        }
        Ok(candidates)
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
            Ok(()) => retry_state.clear(&candidate.key),
            Err(err) => {
                let (attempts, retry_delay) = retry_state.record_failure(candidate.key, now);
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
        let allowed = self.allow_any
            || match welcomer {
                Some(welcomer) => {
                    let welcomer_account_id_hex = hex::encode(welcomer.as_slice());
                    self.allowlists
                        .contains(&account.account_id_hex, &welcomer_account_id_hex)?
                }
                None => false,
            };
        if allowed {
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
