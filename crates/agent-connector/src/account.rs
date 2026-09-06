//! Account and group membership, profile publishing, and welcomer-allowlist operations.

use agent_control::{AgentControlAccount, AgentControlProfileLookupStatus, AgentControlResponse};
use marmot_account::{AccountHome, AccountHomeError, AccountSummary};
use marmot_app::{AccountRelayListBootstrap, UserProfileMetadata};

use crate::AgentConnector;
use crate::error::ConnectorError;
use crate::validation::{unix_now_seconds, validate_profile_name};

impl AgentConnector {
    pub(crate) fn account_list_response(&self) -> Result<AgentControlResponse, ConnectorError> {
        let accounts = self
            .account_home
            .accounts()?
            .into_iter()
            .map(|account| AgentControlAccount {
                account_id_hex: account.account_id_hex,
                label: account.label,
                local_signing: account.local_signing,
            })
            .collect();
        Ok(AgentControlResponse::AccountList { accounts })
    }

    pub(crate) async fn create_account_response(
        &self,
        label: Option<String>,
        publish_key_package: bool,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = match label {
            Some(label) => self.account_home.create_account(&label)?,
            None => self.account_home.create_nostr_account()?,
        };
        if publish_key_package {
            self.runtime.publish_key_package(&account.label).await?;
        }
        Ok(AgentControlResponse::AccountCreated {
            account: AgentControlAccount {
                account_id_hex: account.account_id_hex,
                label: account.label,
                local_signing: account.local_signing,
            },
        })
    }

    pub(crate) async fn create_group_response(
        &self,
        account_id_hex: &str,
        name: String,
        members: Vec<String>,
        description: Option<String>,
        relays: Option<Vec<String>>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account_id_hex = crate::validation::normalize_hex(account_id_hex)?;
        let account = self.local_account_for_account_id(&account_id_hex)?;
        crate::validation::validate_group_create(&name, &members, description.as_deref())?;
        let group_id = self
            .runtime
            .create_group_with_options(
                &account.label,
                &name,
                &members,
                marmot_app::AppCreateGroupOptions {
                    description: description.unwrap_or_default(),
                    relays,
                    ..Default::default()
                },
            )
            .await?;
        let group_id_hex = hex::encode(group_id.as_slice());
        // Provenance is activation metadata only; it never changes sender authorization.
        // Preserve the canonical create result on persistence failure so clients
        // do not create a duplicate. False disables automatic activation until repaired.
        let agent_created = match self
            .agent_created_groups
            .add(&account_id_hex, &group_id_hex)
        {
            Ok(()) => true,
            Err(_) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "create_group_response",
                    error_code = "agent_created_groups_write_failed",
                    "group created but activation provenance could not be persisted"
                );
                false
            }
        };
        // Creation is already canonical. A failed status read must not invite
        // a retry of the non-idempotent create operation.
        let pending_welcome_count = self
            .runtime
            .pending_welcome_deliveries(&account.label)
            .await
            .ok()
            .map(|pending| {
                pending
                    .iter()
                    .filter(|delivery| delivery.group_id_hex == group_id_hex)
                    .count()
            });
        Ok(AgentControlResponse::GroupCreated {
            group_id_hex,
            pending_welcome_count,
            agent_created,
        })
    }

    pub(crate) async fn leave_group_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account_id_hex = crate::validation::normalize_hex(account_id_hex)?;
        let group_id_hex = crate::validation::normalize_hex(group_id_hex)?;
        let account = self.local_account_for_account_id(&account_id_hex)?;
        let group_id = cgka_traits::GroupId::new(hex::decode(&group_id_hex)?);
        // Runtime errors (including failed publication) use the existing App
        // projections. Never remove provenance or acknowledge a failed leave.
        self.runtime.leave_group(&account.label, &group_id).await?;
        // Leave is already canonical. Metadata cleanup must not turn success
        // into an error that invites a duplicate LeaveAlreadyRequested retry.
        if self
            .agent_created_groups
            .remove(&account_id_hex, &group_id_hex)
            .is_err()
        {
            tracing::warn!(
                target: "agent_connector",
                method = "leave_group_response",
                error_code = "agent_created_groups_cleanup_failed",
                "group left but activation provenance cleanup failed"
            );
        }
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) async fn publish_profile_response(
        &self,
        account_id_hex: &str,
        name: String,
        display_name: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let name = validate_profile_name(name)?;
        let display_name = display_name
            .map(validate_profile_name)
            .transpose()?
            .unwrap_or_else(|| name.clone());
        let bootstrap_relays = self.configured_relay_endpoints();
        let profile = UserProfileMetadata {
            name: Some(name.clone()),
            display_name: Some(display_name.clone()),
            created_at: unix_now_seconds(),
            ..UserProfileMetadata::default()
        };
        self.runtime
            .publish_user_profile(
                &account.label,
                profile,
                AccountRelayListBootstrap::new(bootstrap_relays.clone(), bootstrap_relays),
            )
            .await?;
        Ok(AgentControlResponse::ProfilePublished {
            account_id_hex: account.account_id_hex,
            name,
            display_name: Some(display_name),
        })
    }

    pub(crate) async fn profile_lookup_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let source_relays = self.configured_relay_endpoints();
        if source_relays.is_empty() {
            return Ok(AgentControlResponse::ProfileLookup {
                account_id_hex: account.account_id_hex,
                status: AgentControlProfileLookupStatus::Indeterminate,
                retryable: true,
            });
        }

        let status = match self
            .runtime
            .fetch_current_user_profile_for_account_id(&account.account_id_hex, source_relays)
            .await
        {
            Ok(Some(_)) => AgentControlProfileLookupStatus::ProfileFound,
            Ok(None) => AgentControlProfileLookupStatus::ProfileNotFound,
            Err(_) => AgentControlProfileLookupStatus::Indeterminate,
        };
        Ok(AgentControlResponse::ProfileLookup {
            account_id_hex: account.account_id_hex,
            status,
            retryable: status == AgentControlProfileLookupStatus::Indeterminate,
        })
    }

    pub(crate) fn local_account_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<AccountSummary, ConnectorError> {
        self.account_home
            .accounts()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .ok_or_else(|| AccountHomeError::UnknownAccount(account_id_hex.to_owned()).into())
    }

    pub(crate) fn allowlist_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        Ok(AgentControlResponse::Allowlist {
            account_id_hex: account.account_id_hex.clone(),
            welcomer_account_ids_hex: self.allowlists.list(&account.account_id_hex)?,
        })
    }

    pub(crate) fn allowlist_add_response(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let welcomer_account_id_hex =
            AccountHome::account_id_for_public_key(welcomer_account_id_hex)?;
        Ok(AgentControlResponse::Allowlist {
            account_id_hex: account.account_id_hex.clone(),
            welcomer_account_ids_hex: self
                .allowlists
                .add(&account.account_id_hex, &welcomer_account_id_hex)?,
        })
    }

    pub(crate) fn allowlist_remove_response(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let welcomer_account_id_hex =
            AccountHome::account_id_for_public_key(welcomer_account_id_hex)?;
        Ok(AgentControlResponse::Allowlist {
            account_id_hex: account.account_id_hex.clone(),
            welcomer_account_ids_hex: self
                .allowlists
                .remove(&account.account_id_hex, &welcomer_account_id_hex)?,
        })
    }

    pub(crate) fn invite_policy_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        Ok(AgentControlResponse::InvitePolicy {
            account_id_hex: account.account_id_hex.clone(),
            policy: self.allowlists.policy(&account.account_id_hex)?,
        })
    }

    pub(crate) fn invite_policy_set_response(
        &self,
        account_id_hex: &str,
        policy: agent_control::AgentControlInvitePolicy,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        Ok(AgentControlResponse::InvitePolicy {
            account_id_hex: account.account_id_hex.clone(),
            policy: self
                .allowlists
                .set_policy(&account.account_id_hex, policy)?,
        })
    }
}
