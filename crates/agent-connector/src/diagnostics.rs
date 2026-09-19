//! Identifier-free `diagnostic_status` handler.

use agent_control::{
    AGENT_CONTROL_PROTOCOL_V2, AgentControlAccountSelection, AgentControlDiagnosticHome,
    AgentControlDiagnosticKeyPackage, AgentControlDiagnosticRelays, AgentControlDiagnosticStatus,
    AgentControlKeyPackageAvailability, AgentControlResponse,
};
use cgka_traits::{GroupId, TransportFanoutAttemptState};

use crate::AgentConnector;
use crate::error::ConnectorError;
use crate::validation::{normalize_hex, unix_now_seconds};

impl AgentConnector {
    pub(crate) async fn diagnostic_status_response(
        &self,
        account_id_hex: Option<&str>,
        home_group_id_hex: Option<&str>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let accounts = self.account_home.accounts()?;
        let account_count = u32::try_from(accounts.len()).unwrap_or(u32::MAX);
        let signing: Vec<_> = accounts
            .into_iter()
            .filter(|account| account.local_signing)
            .collect();
        let local_signing_account_count = u32::try_from(signing.len()).unwrap_or(u32::MAX);

        let (selection, selected) = match account_id_hex {
            Some(requested) => {
                let requested = normalize_hex(requested)?;
                match signing
                    .into_iter()
                    .find(|account| account.account_id_hex == requested)
                {
                    Some(account) => (AgentControlAccountSelection::Selected, Some(account)),
                    None => (AgentControlAccountSelection::ExplicitUnavailable, None),
                }
            }
            None if local_signing_account_count == 0 => (AgentControlAccountSelection::None, None),
            None if local_signing_account_count == 1 => (
                AgentControlAccountSelection::Selected,
                signing.into_iter().next(),
            ),
            None => (AgentControlAccountSelection::Ambiguous, None),
        };

        let (welcomer_count, key_package, home) = if let Some(account) = selected.as_ref() {
            let welcomer_count =
                u32::try_from(self.allowlists.list(&account.account_id_hex)?.len())
                    .unwrap_or(u32::MAX);
            let key_package = self.diagnostic_key_package(&account.label).await;
            let home = self
                .diagnostic_home(&account.label, home_group_id_hex)
                .await?;
            (welcomer_count, key_package, home)
        } else {
            (
                0,
                AgentControlDiagnosticKeyPackage::unavailable(),
                if home_group_id_hex.is_some() {
                    AgentControlDiagnosticHome {
                        requested: true,
                        resolved: false,
                        worker_available: false,
                        member_count: None,
                        is_direct: None,
                    }
                } else {
                    AgentControlDiagnosticHome::not_requested()
                },
            )
        };

        let health = self.app.relay_telemetry().await.health;
        Ok(AgentControlResponse::DiagnosticStatus {
            report: AgentControlDiagnosticStatus {
                protocol: AGENT_CONTROL_PROTOCOL_V2.to_owned(),
                connector_version: env!("CARGO_PKG_VERSION").to_owned(),
                account_count,
                local_signing_account_count,
                selection,
                welcomer_count,
                allow_any: self.dev_allow_any_invites,
                key_package,
                relays: AgentControlDiagnosticRelays {
                    configured: u32::try_from(self.configured_relay_endpoints().len())
                        .unwrap_or(u32::MAX),
                    connected: u32::try_from(health.connected).unwrap_or(u32::MAX),
                    disconnected: u32::try_from(
                        health.disconnected.saturating_add(health.terminated),
                    )
                    .unwrap_or(u32::MAX),
                },
                replay: self.reconcile_telemetry.diagnostic_replay(),
                home,
            },
        })
    }

    async fn diagnostic_key_package(&self, account_ref: &str) -> AgentControlDiagnosticKeyPackage {
        match self
            .runtime
            .diagnostic_key_package_maintenance_status(account_ref)
            .await
        {
            Ok(Some(Some(status))) => {
                let accepted = status
                    .publication_targets
                    .iter()
                    .filter(|target| target.state == TransportFanoutAttemptState::Accepted)
                    .count() as u32;
                let unattempted = status
                    .publication_targets
                    .iter()
                    .filter(|target| target.state == TransportFanoutAttemptState::Unattempted)
                    .count() as u32;
                let failed = status
                    .publication_targets
                    .iter()
                    .filter(|target| target.state == TransportFanoutAttemptState::AttemptedFailed)
                    .count() as u32;
                let prohibited = status
                    .publication_targets
                    .iter()
                    .filter(|target| target.state == TransportFanoutAttemptState::PolicyProhibited)
                    .count() as u32;
                let present = status.current_key_package_ref.is_some();
                let now = unix_now_seconds();
                let expired = status
                    .current_not_after
                    .map(|stamp| present && stamp.0 < now);
                let availability = if status.pending_replacement.is_some() {
                    AgentControlKeyPackageAvailability::Pending
                } else if present && (expired == Some(true) || failed > 0) {
                    AgentControlKeyPackageAvailability::Degraded
                } else if present {
                    AgentControlKeyPackageAvailability::Present
                } else {
                    AgentControlKeyPackageAvailability::Absent
                };
                AgentControlDiagnosticKeyPackage {
                    availability,
                    phase: Some(status.phase.as_str().to_owned()),
                    present,
                    expired,
                    accepted_fanout_targets: accepted,
                    unattempted_fanout_targets: unattempted,
                    failed_fanout_targets: failed,
                    policy_prohibited_fanout_targets: prohibited,
                }
            }
            Ok(Some(None)) => AgentControlDiagnosticKeyPackage {
                availability: AgentControlKeyPackageAvailability::Absent,
                phase: None,
                present: false,
                expired: None,
                accepted_fanout_targets: 0,
                unattempted_fanout_targets: 0,
                failed_fanout_targets: 0,
                policy_prohibited_fanout_targets: 0,
            },
            Ok(None) | Err(_) => AgentControlDiagnosticKeyPackage::unavailable(),
        }
    }

    async fn diagnostic_home(
        &self,
        account_ref: &str,
        home_group_id_hex: Option<&str>,
    ) -> Result<AgentControlDiagnosticHome, ConnectorError> {
        let Some(home_group_id_hex) = home_group_id_hex else {
            return Ok(AgentControlDiagnosticHome::not_requested());
        };
        let group_id_hex = normalize_hex(home_group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        match self
            .runtime
            .diagnostic_group_mls_state(account_ref, &group_id)
            .await
        {
            Ok(Some(state)) => {
                let member_count = u32::try_from(state.member_count).unwrap_or(u32::MAX);
                Ok(AgentControlDiagnosticHome {
                    requested: true,
                    resolved: true,
                    worker_available: true,
                    member_count: Some(member_count),
                    is_direct: Some(state.member_count == 2),
                })
            }
            Ok(None) => Ok(AgentControlDiagnosticHome {
                requested: true,
                resolved: false,
                worker_available: false,
                member_count: None,
                is_direct: None,
            }),
            Err(_) => Ok(AgentControlDiagnosticHome {
                requested: true,
                resolved: false,
                worker_available: true,
                member_count: None,
                is_direct: None,
            }),
        }
    }
}
