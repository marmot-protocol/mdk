use super::*;
use crate::{
    ViewOnceActivationRefusal, ViewOnceConsumeOutcome, ViewOnceMediaRequest, ViewOnceState,
};

impl MarmotAppRuntime {
    /// Advisory eligibility. Activation rechecks every authenticated member's support.
    pub async fn view_once_activation_refusal(
        &self,
        account_ref: &str,
        group: &GroupId,
    ) -> Result<Option<ViewOnceActivationRefusal>, AppError> {
        let command = self.accounts.worker_commands(account_ref).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ViewOnceActivation {
                group_id: group.clone(),
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        account_worker_response(response).await
    }

    /// Explicitly require view-once support in an eligible group.
    pub async fn enable_view_once(
        &self,
        account_ref: &str,
        group: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.accounts.enable_view_once(account_ref, group).await
    }

    /// Upload and send once without exposing an intermediate downloadable reference.
    pub async fn send_view_once_media(
        &self,
        account_ref: &str,
        group: &GroupId,
        request: ViewOnceMediaRequest,
    ) -> Result<SendSummary, AppError> {
        let account = self.accounts.resolve(account_ref)?;
        let (command, admission) = self.accounts.media_worker_commands(&account.label).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::SendViewOnce {
                admission,
                group_id: group.clone(),
                request,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        response.await.map_err(|_| AppError::TransportClosed)?
    }

    /// Spend one receiving device's attachment before any plaintext is decrypted.
    /// A failed or cancelled opening after the commit remains consumed.
    pub async fn consume_view_once(
        &self,
        account_ref: &str,
        group: &GroupId,
        message_id: &str,
        attachment_index: u32,
    ) -> Result<ViewOnceConsumeOutcome, AppError> {
        validate_once_target(message_id, attachment_index)?;
        let account = self.accounts.resolve(account_ref)?;
        match self
            .view_once_state(&account.label, group, message_id, attachment_index)
            .await?
        {
            ViewOnceState::Consumed => return Ok(ViewOnceConsumeOutcome::Consumed),
            ViewOnceState::Expired => return Ok(ViewOnceConsumeOutcome::Expired),
            ViewOnceState::Sent | ViewOnceState::Unavailable => {
                return Ok(ViewOnceConsumeOutcome::Unavailable);
            }
            ViewOnceState::Unopened => {}
        }
        let permit = self
            .accounts
            .app
            .view_once_sessions
            .reserve(&account.label)?;
        let (command, admission) = self.accounts.media_worker_commands(&account.label).await?;
        let (respond, response) = oneshot::channel();
        command
            .send(AccountWorkerCommand::ConsumeViewOnce {
                admission,
                group_id: group.clone(),
                message_id: message_id.to_ascii_lowercase(),
                attachment_index,
                permit,
                respond,
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        response.await.map_err(|_| AppError::TransportClosed)?
    }

    /// Durable presentation state; does not download or claim an attachment.
    pub async fn view_once_state(
        &self,
        account_ref: &str,
        group: &GroupId,
        message_id: &str,
        attachment_index: u32,
    ) -> Result<ViewOnceState, AppError> {
        validate_once_target(message_id, attachment_index)?;
        let group = hex::encode(group.as_slice());
        let message = message_id.to_ascii_lowercase();
        self.attachment_read(account_ref, move |storage, _| {
            storage
                .app_storage()
                .view_once_state(
                    &group,
                    &message,
                    attachment_index,
                    crate::unix_now_seconds(),
                )
                .map_err(Into::into)
        })
        .await
    }
}

fn validate_once_target(message: &str, index: u32) -> Result<(), AppError> {
    if index != 0 || message.len() != 64 || !message.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::InvalidEncryptedMedia(
            "invalid view-once message target".into(),
        ));
    }
    Ok(())
}
