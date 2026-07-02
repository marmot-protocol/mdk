//! Account listing/creation, profile publishing, and welcomer-allowlist operations.

use agent_control::{AgentControlAccount, AgentControlResponse};
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
}
