use super::*;
use crate::view_once::{ViewOnceAccess, ViewOncePermit};
use crate::{ViewOnceConsumeOutcome, ViewOnceMediaRequest, ViewOnceViewer};
use storage_sqlite::ViewOnceClaim;

pub(crate) struct ViewOnceSendHttp {
    request: ViewOnceMediaRequest,
    source_pin: cgka_traits::EpochPin,
    secret: SecretBytes,
    signer: Arc<dyn MarmotNostrSigner>,
    endpoints: Vec<AppBlobEndpoint>,
    allowed_kinds: Vec<String>,
    transport: BlossomHttpTransport,
    allow_loopback: bool,
}

impl ViewOnceSendHttp {
    pub(crate) async fn run(self) -> Result<MediaAttachmentReference, AppError> {
        let mut result = crate::media::upload_view_once_media(
            self.request,
            self.source_pin.epoch.0,
            self.secret.as_ref(),
            self.signer.as_ref(),
            MediaOperationPolicy {
                version: EncryptedMediaVersion::ViewOnceV1,
                default_endpoints: &self.endpoints,
                allowed_locator_kinds: &self.allowed_kinds,
                allow_loopback_http: self.allow_loopback,
            },
            &self.transport,
        )
        .await?;
        result.reference.source_epoch_identity = Some(hex::encode(self.source_pin.identity));
        Ok(result.reference)
    }
}

pub(crate) struct ViewOnceConsumeHttp {
    reference: MediaAttachmentReference,
    secret: SecretBytes,
    candidates: Vec<crate::media::MediaFetchCandidate>,
    transport: BlossomHttpTransport,
    viewer: Arc<ViewOnceViewer>,
}

impl ViewOnceConsumeHttp {
    pub(crate) async fn run(self) -> Result<ViewOnceConsumeOutcome, AppError> {
        let bytes = tokio::time::timeout_at(
            self.viewer.deadline(),
            crate::media::download_claimed_view_once(
                self.reference,
                self.secret.as_ref(),
                self.candidates,
                &self.transport,
                crate::media::ClaimedViewOnceConsumption::DurablyClaimed,
            ),
        )
        .await
        .map_err(|_| AppError::MediaDownloadFailed("view-once opening timed out".into()))??;
        if !self.viewer.finish(bytes).await? {
            self.viewer.close();
            return Ok(ViewOnceConsumeOutcome::Unavailable);
        }
        Ok(ViewOnceConsumeOutcome::Opened {
            viewer: self.viewer,
        })
    }
}

pub(crate) enum ViewOncePreparation {
    Ready(Box<ViewOnceConsumeHttp>),
    Terminal(ViewOnceConsumeOutcome),
}

impl AppClient {
    pub(crate) fn view_once_activation_refusal(
        &self,
        group: &GroupId,
    ) -> Result<Option<crate::ViewOnceActivationRefusal>, AppError> {
        self.ensure_group(group)?;
        Ok(self.runtime.view_once_activation_refusal(group)?)
    }

    pub(crate) async fn enable_view_once(
        &mut self,
        group: &GroupId,
    ) -> Result<SendSummary, AppError> {
        self.ensure_group(group)?;
        self.ensure_group_commit_admitted(group)?;
        self.sync_runtime_groups_for_send("enable_view_once")
            .await?;
        let context = Self::local_human_action_context(
            "enable_view_once",
            vec!["app_components"],
            vec![cgka_traits::app_components::VIEW_ONCE_COMPONENT_ID],
            None,
        );
        let effects = self
            .runtime
            .send_host_change_with_audit_context(
                SendIntent::EnableViewOnce {
                    group_id: group.clone(),
                },
                context.clone(),
            )
            .await?;
        self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
            .await?;
        self.record_human_action_succeeded(group, &context, &effects);
        self.remember_published_reports(&effects);
        self.refresh_group(group);
        self.save_state_with_pending_local_group_deletion_frontier_clears()?;
        Ok(send_summary_from_effects(&effects))
    }

    pub(crate) async fn prepare_view_once_send(
        &mut self,
        group: &GroupId,
        request: ViewOnceMediaRequest,
    ) -> Result<ViewOnceSendHttp, AppError> {
        self.ensure_group_application_messages_allowed(group)?;
        self.sync_runtime_groups_for_send("prepare_view_once_send")
            .await?;
        let source_pin = self.runtime.epoch_pin(group)?;
        if !self
            .runtime
            .view_once_required_at(group, source_pin.epoch)?
        {
            return Err(AppError::InvalidEncryptedMedia(
                "view-once support is not required by this group".into(),
            ));
        }
        let now = unix_now_seconds();
        if request.unopened_expires_at <= now
            || request.unopened_expires_at.saturating_sub(now)
                > cgka_traits::app_components::VIEW_ONCE_MAX_LIFETIME_SECONDS
        {
            return Err(AppError::InvalidEncryptedMedia(
                "invalid view-once unopened deadline".into(),
            ));
        }
        let policy = self.encrypted_media_policy_for_group(group)?;
        if policy.version != EncryptedMediaVersion::V2 {
            return Err(AppError::InvalidEncryptedMedia(
                "view-once requires encrypted media v2".into(),
            ));
        }
        let (_, secret) = self.encrypted_media_secret(group)?;
        let account = self.app.account_home().account(&self.state.label)?;
        let signer = self
            .app
            .account_signer_for_summary(&account)?
            .as_nostr_signer();
        Ok(ViewOnceSendHttp {
            request,
            source_pin,
            secret,
            signer,
            endpoints: policy.default_blob_endpoints,
            allowed_kinds: policy.allowed_locator_kinds,
            transport: self.blossom_http_transport.clone(),
            allow_loopback: self.app.allow_loopback_blob_endpoints(),
        })
    }

    pub(crate) async fn finish_view_once_send<F>(
        &mut self,
        group: &GroupId,
        reference: MediaAttachmentReference,
        expires_at: u64,
        on_local_projection: F,
    ) -> Result<SendSummary, AppError>
    where
        F: FnMut(crate::AppProjectionUpdate),
    {
        if !self
            .runtime
            .view_once_required_at(group, self.runtime.epoch_pin(group)?.epoch)?
        {
            return Err(AppError::InvalidEncryptedMedia(
                "view-once support is not required by this group".into(),
            ));
        }
        let intent = AppMessageIntent::Media {
            attachments: vec![reference],
            caption: None,
            message_tags: vec![vec![
                "view-once".into(),
                "view-once-v1".into(),
                expires_at.to_string(),
            ]],
        };
        let (_, summary) = self
            .send_app_event_with_local_projection(group, intent, on_local_projection)
            .await?;
        Ok(summary)
    }

    pub(crate) fn prepare_view_once_consume(
        &mut self,
        group: &GroupId,
        message: &str,
        index: u32,
        permit: ViewOncePermit,
    ) -> Result<ViewOncePreparation, AppError> {
        self.ensure_group_application_messages_allowed(group)?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let group_hex = hex::encode(group.as_slice());
        let own = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let Some((tag, expected_epoch, _)) =
            storage.view_once_metadata(&group_hex, message, index, &own, unix_now_seconds())?
        else {
            let outcome =
                match storage.view_once_state(&group_hex, message, index, unix_now_seconds())? {
                    crate::ViewOnceState::Consumed => ViewOnceConsumeOutcome::Consumed,
                    crate::ViewOnceState::Expired => ViewOnceConsumeOutcome::Expired,
                    _ => ViewOnceConsumeOutcome::Unavailable,
                };
            return Ok(ViewOncePreparation::Terminal(outcome));
        };
        let reference = match crate::parse_media_attachment(
            &tag,
            Some(expected_epoch),
            self.app.allow_loopback_blob_endpoints(),
        ) {
            Ok(reference) => reference,
            Err(_) => {
                return Ok(ViewOncePreparation::Terminal(
                    ViewOnceConsumeOutcome::Unavailable,
                ));
            }
        };
        let policy = self.encrypted_media_policy_for_group(group)?;
        let candidates = crate::media::plan_media_fetch(
            &reference,
            &policy.default_blob_endpoints,
            &policy.allowed_locator_kinds,
            &self.blossom_http_transport,
        );
        if !candidates
            .iter()
            .any(|candidate| matches!(candidate, crate::media::MediaFetchCandidate::Ready(_)))
        {
            return Ok(ViewOncePreparation::Terminal(
                ViewOnceConsumeOutcome::Unavailable,
            ));
        }
        let secret = match self.encrypted_media_secret_if_available(
            group,
            expected_epoch,
            cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
        )? {
            EpochMediaSecret::Available(secret) => secret,
            EpochMediaSecret::Unavailable(_) => {
                return Ok(ViewOncePreparation::Terminal(
                    ViewOnceConsumeOutcome::Unavailable,
                ));
            }
        };
        let claimed_at = tokio::time::Instant::now();
        let (claimed_tag, source_epoch, expires_at) = match storage.claim_view_once(
            crate::media::view_once_content::VIEW_ONCE_MIME,
            &group_hex,
            message,
            index,
            &own,
            unix_now_seconds(),
        )? {
            ViewOnceClaim::Consumed => {
                return Ok(ViewOncePreparation::Terminal(
                    ViewOnceConsumeOutcome::Consumed,
                ));
            }
            ViewOnceClaim::Expired => {
                return Ok(ViewOncePreparation::Terminal(
                    ViewOnceConsumeOutcome::Expired,
                ));
            }
            ViewOnceClaim::Unavailable => {
                return Ok(ViewOncePreparation::Terminal(
                    ViewOnceConsumeOutcome::Unavailable,
                ));
            }
            ViewOnceClaim::Claimed {
                imeta_tag,
                source_epoch,
                expires_at,
            } => (imeta_tag, source_epoch, expires_at),
        };
        // Every path below follows the terminal commit. Failure never releases that claim.
        if source_epoch != expected_epoch || claimed_tag != tag {
            return Ok(ViewOncePreparation::Terminal(
                ViewOnceConsumeOutcome::Unavailable,
            ));
        }
        let viewer = ViewOnceViewer::opening(
            &self.app,
            &self.state.label,
            ViewOnceAccess {
                storage,
                group: group_hex,
                message: message.to_owned(),
                attachment_index: index,
                expires_at,
                claimed_at,
            },
            permit,
            reference.media_type.clone(),
        )?;
        Ok(ViewOncePreparation::Ready(Box::new(ViewOnceConsumeHttp {
            reference,
            secret,
            candidates,
            transport: self.blossom_http_transport.clone(),
            viewer,
        })))
    }
}
