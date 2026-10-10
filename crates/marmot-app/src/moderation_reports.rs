//! Private NIP-56 user reports to the deployment's moderation team, gift-wrapped per NIP-59.
//!
//! This is additive to in-group moderation (`report_message`, `content_reports`,
//! `dismiss_reports`), which stays the primary path: admins moderate their own groups. A
//! moderation report tells the deployment operator about an account so it can act at the
//! account level. It names only the reported public key, a NIP-56 report type, an origin label
//! and an optional explanation; it never carries message content, message ids, group ids,
//! relay or group metadata, or anything else that identifies a conversation.
//!
//! The rumor (kind 1984, authored by the reporter) is sealed by the reporter's key and wrapped
//! by a one-time key through [`transport_nostr_peeler::gift_wrap_rumor`], the same NIP-59
//! construction Welcomes use. Wraps go only to the host-configured relays, through a publisher
//! that never authenticates as the account. The signed wrap is staged in the account database
//! before any relay sees it, so a refused, unacknowledged or interrupted publish is retried
//! later; the wrap is dropped once a relay accepts it.
//!
//! See `docs/marmot-architecture/moderation-reports.md` for the wire format.
use crate::relay_plane::RelayEndpointPolicy;
use crate::{AppError, MarmotApp, ReportReason};
use cgka_traits::{TransportEndpoint, TransportEndpointFailure, TransportEndpointFailureKind};
use marmot_account::AccountHomeError;
use nostr::prelude::{EventBuilder, FinalizeUnsignedEvent, Kind, PublicKey, Tag, UnsignedEvent};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage_sqlite::{ModerationReportOutboxEntry, ModerationReportOutboxOutcome};
use tokio::sync::watch;
use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

/// NIP-32 namespace of the origin label on every moderation report rumor.
pub const MODERATION_REPORT_LABEL_NAMESPACE: &str = "chat.whitenoise.report";
/// Longest explanation kept, in Unicode scalar values, after trimming.
pub const MODERATION_REPORT_EXPLANATION_MAX_CHARS: usize = 1_000;
/// A repeat of the same (target, reason, origin) inside this window returns the first outcome.
pub const MODERATION_REPORT_IDEMPOTENCY_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Local cap against runaway clients; it is not abuse protection.
pub const MODERATION_REPORT_RATE_LIMIT: u64 = 20;
pub const MODERATION_REPORT_RATE_WINDOW: Duration = Duration::from_secs(60 * 60);
/// An unpublished report older than this is abandoned rather than retried forever.
const PENDING_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_BATCH_LIMIT: usize = 20;
const MAX_RELAYS: usize = 16;
const NIP56_REPORT_KIND: u16 = 1984;
const DEDUPE_DOMAIN: &[u8] = b"marmot.moderation-report.dedupe.v1";

/// Host-supplied destination for moderation reports. Hosts set it per build flavor so
/// production and staging never mix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModerationReportConfig {
    /// The moderation team's reports key: 64-character hex or `npub`.
    pub recipient_pubkey: String,
    /// Relays to publish to. Every entry must pass the relay safety policy.
    pub relays: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ModerationReportOrigin {
    /// A plain "Report" action.
    Report,
    /// The report half of a "Block and Report" action. Blocking itself is a
    /// separate call (`block_user`).
    BlockAndReport,
}

impl ModerationReportOrigin {
    /// The `l` label value on the rumor.
    pub fn label(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::BlockAndReport => "block",
        }
    }
}

/// Same vocabulary as send summaries. Neither retained state is a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModerationReportStatus {
    /// A configured relay accepted the wrap.
    Published,
    /// No relay accepted it yet; it is queued and retried on catch-up.
    AcceptedPending,
    /// A relay may have received it without acknowledging; it is queued and retried.
    CompletionUnknown,
}

impl From<ModerationReportOutboxOutcome> for ModerationReportStatus {
    fn from(value: ModerationReportOutboxOutcome) -> Self {
        match value {
            ModerationReportOutboxOutcome::Published => Self::Published,
            ModerationReportOutboxOutcome::AcceptedPending => Self::AcceptedPending,
            ModerationReportOutboxOutcome::CompletionUnknown => Self::CompletionUnknown,
        }
    }
}

impl ModerationReportStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::AcceptedPending => "accepted_pending",
            Self::CompletionUnknown => "completion_unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModerationReportOutcome {
    /// Stable local id (32 hex characters). Never sent anywhere.
    pub report_id: String,
    pub status: ModerationReportStatus,
}

/// Aggregate result of one retry pass over an account's queued reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModerationReportRetrySummary {
    pub published: usize,
    pub pending: usize,
    pub abandoned: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedModerationReportConfig {
    pub(crate) recipient: PublicKey,
    pub(crate) relays: Vec<TransportEndpoint>,
}

/// Process-wide moderation-report state, shared by every `MarmotApp` clone.
#[derive(Default)]
pub(crate) struct ModerationReportState {
    /// `None` until first read, then the installed configuration (if valid).
    config: RwLock<Option<Option<ValidatedModerationReportConfig>>>,
    accounts: Mutex<HashMap<String, Arc<AccountSlot>>>,
    /// Anonymous publisher: never shares a socket with an account's authenticated pool.
    publisher: OnceLock<Arc<dyn NostrRelayClient>>,
    #[cfg(test)]
    fail_next_purge: std::sync::atomic::AtomicBool,
}

struct AccountSlot {
    /// Serializes one account's admission (dedupe, rate limit, signing, staging),
    /// retry selection and purge. Never held across a relay publish.
    work: tokio::sync::Mutex<()>,
    /// Bumped by a purge so in-flight work for the account stops.
    generation: watch::Sender<u64>,
    /// Set while a retry pass runs, so overlapping catch-ups do not double-publish.
    retrying: std::sync::atomic::AtomicBool,
    /// Open [`ModerationReportFence`]s. While nonzero, no report is admitted
    /// or retried. Sign-out and wipe hold one from purge through teardown,
    /// because the account stays signed in until teardown commits.
    fences: std::sync::atomic::AtomicUsize,
    /// Reports with a publish running in this process. A retry skips them
    /// instead of taking their in-flight mark for an interrupted attempt.
    publishing: Mutex<std::collections::HashSet<String>>,
}

impl AccountSlot {
    /// Whether work admitted now may stage or publish. Call with `work` held,
    /// after subscribing to `generation`: a fence raised before the
    /// subscription is seen here, and one raised after it bumps the generation
    /// the publish waits on.
    fn admits(&self, generation: &watch::Receiver<u64>) -> bool {
        self.fences.load(std::sync::atomic::Ordering::Acquire) == 0
            && !generation.has_changed().unwrap_or(true)
    }
}

/// Claims one report's publish in this process until dropped.
struct PublishClaim<'a> {
    slot: &'a AccountSlot,
    report_id: String,
}

impl<'a> PublishClaim<'a> {
    fn try_claim(slot: &'a AccountSlot, report_id: &str) -> Option<Self> {
        slot.publishing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(report_id.to_owned())
            .then(|| Self {
                slot,
                report_id: report_id.to_owned(),
            })
    }
}

impl Drop for PublishClaim<'_> {
    fn drop(&mut self) {
        self.slot
            .publishing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.report_id);
    }
}

/// Keeps one account's report admission closed until dropped.
#[must_use = "admission reopens as soon as the fence is dropped"]
pub(crate) struct ModerationReportFence(Arc<AccountSlot>);

impl Drop for ModerationReportFence {
    fn drop(&mut self) {
        self.0
            .fences
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl ModerationReportState {
    fn slot(&self, label: &str) -> Arc<AccountSlot> {
        self.accounts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(label.to_owned())
            .or_insert_with(|| {
                Arc::new(AccountSlot {
                    work: tokio::sync::Mutex::new(()),
                    generation: watch::channel(0).0,
                    retrying: std::sync::atomic::AtomicBool::new(false),
                    fences: std::sync::atomic::AtomicUsize::new(0),
                    publishing: Mutex::default(),
                })
            })
            .clone()
    }
}

impl MarmotApp {
    /// Install or clear the moderation-report destination. An invalid configuration is
    /// rejected whole and leaves reporting unconfigured, never partially applied.
    pub fn set_moderation_report_config(
        &self,
        config: Option<ModerationReportConfig>,
    ) -> Result<(), AppError> {
        let validated = config
            .as_ref()
            .map(|config| self.validate_moderation_report_config(config))
            .transpose();
        let mut slot = self
            .moderation_reports
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match validated {
            Ok(validated) => {
                *slot = Some(validated);
                Ok(())
            }
            Err(error) => {
                *slot = Some(None);
                Err(error)
            }
        }
    }

    /// Whether a valid moderation-report destination is installed.
    pub fn moderation_reporting_available(&self) -> bool {
        self.moderation_report_config().is_some()
    }

    pub(crate) fn moderation_report_config(&self) -> Option<ValidatedModerationReportConfig> {
        if let Some(installed) = self
            .moderation_reports
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            return installed.clone();
        }
        // First read: adopt the construction-time configuration, if any.
        let mut slot = self
            .moderation_reports
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.get_or_insert_with(|| {
            let configured = self.config.moderation_report_config.as_ref()?;
            match self.validate_moderation_report_config(configured) {
                Ok(validated) => Some(validated),
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::moderation_reports",
                        method = "moderation_report_config",
                        error_kind = error.privacy_safe_kind(),
                        "rejected configured moderation report destination"
                    );
                    None
                }
            }
        })
        .clone()
    }

    pub(crate) fn validate_moderation_report_config(
        &self,
        config: &ModerationReportConfig,
    ) -> Result<ValidatedModerationReportConfig, AppError> {
        let invalid = |reason: &str| AppError::InvalidModerationReportConfig(reason.to_owned());
        let recipient = config.recipient_pubkey.trim();
        let well_formed = (recipient.len() == 64
            && recipient.bytes().all(|b| b.is_ascii_hexdigit()))
            || recipient.starts_with("npub1");
        if !well_formed {
            return Err(invalid(
                "recipient_pubkey must be a 64-character hex or npub public key",
            ));
        }
        let recipient = parse_curve_point(recipient)
            .ok_or_else(|| invalid("recipient_pubkey is not a valid x-only public key"))?;
        if config.relays.is_empty() {
            return Err(invalid("at least one relay is required"));
        }
        if config.relays.len() > MAX_RELAYS {
            return Err(invalid("too many relays"));
        }
        let mut relays: Vec<TransportEndpoint> = Vec::with_capacity(config.relays.len());
        for (index, classification) in self
            .relay_plane
            .classify_relay_endpoints(config.relays.clone())
            .into_iter()
            .enumerate()
        {
            let rejection = match classification.policy {
                RelayEndpointPolicy::Allowed => None,
                RelayEndpointPolicy::Invalid => Some("malformed"),
                RelayEndpointPolicy::Unsafe => Some("unsafe"),
                RelayEndpointPolicy::Retired => Some("retired"),
            };
            if let Some(rejection) = rejection {
                // Name the position, never the URL: errors can reach logs.
                return Err(AppError::InvalidModerationReportConfig(format!(
                    "relay {index} is {rejection}"
                )));
            }
            let normalized = classification
                .normalized_endpoint
                .ok_or_else(|| invalid("relay did not normalize"))?;
            if !relays.iter().any(|existing| existing.0 == normalized) {
                relays.push(TransportEndpoint(normalized));
            }
        }
        Ok(ValidatedModerationReportConfig { recipient, relays })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_moderation_report_purge_for_test(&self) {
        self.moderation_reports
            .fail_next_purge
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn install_moderation_report_publisher_for_test(
        &self,
        publisher: Arc<dyn NostrRelayClient>,
    ) {
        assert!(
            self.moderation_reports.publisher.set(publisher).is_ok(),
            "moderation report publisher already installed"
        );
    }

    fn moderation_report_publisher(&self) -> Arc<dyn NostrRelayClient> {
        self.moderation_reports
            .publisher
            .get_or_init(|| {
                // No authenticator: relays see only the one-time wrap key, never an
                // AUTH linking the account to the report.
                Arc::new(NostrSdkRelayClient::from_builder(
                    nostr_sdk::prelude::Client::builder(),
                ))
            })
            .clone()
    }

    /// Submit one private report about `reported_pubkey` to the configured moderation team.
    ///
    /// `stopping` resolves when the runtime shuts down; an interrupted publish leaves the
    /// staged report queued and returns [`ModerationReportStatus::CompletionUnknown`].
    pub(crate) async fn submit_moderation_report(
        &self,
        label: &str,
        reported_pubkey: &str,
        reason: ReportReason,
        explanation: &str,
        origin: ModerationReportOrigin,
        stopping: Option<watch::Receiver<bool>>,
    ) -> Result<ModerationReportOutcome, AppError> {
        let result = self
            .submit_moderation_report_at(
                label,
                reported_pubkey,
                reason,
                explanation,
                origin,
                stopping,
                unix_now_ms(),
            )
            .await;
        let outcome = match &result {
            Ok((outcome, deduplicated)) => {
                if *deduplicated {
                    "duplicate"
                } else {
                    outcome.status.as_str()
                }
            }
            Err(error) => error.privacy_safe_kind(),
        };
        tracing::info!(
            target: "marmot_app::moderation_reports",
            method = "submit_moderation_report",
            origin = origin.label(),
            outcome,
            "moderation_report_submitted"
        );
        result.map(|(outcome, _)| outcome)
    }

    /// [`Self::submit_moderation_report`] at an explicit clock. Returns whether the outcome
    /// was an idempotent repeat of an earlier report.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn submit_moderation_report_at(
        &self,
        label: &str,
        reported_pubkey: &str,
        reason: ReportReason,
        explanation: &str,
        origin: ModerationReportOrigin,
        mut stopping: Option<watch::Receiver<bool>>,
        now_ms: u64,
    ) -> Result<(ModerationReportOutcome, bool), AppError> {
        let account = self.account_home.account(label)?;
        if !account.can_sign() || account.signed_out {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
        }
        let config = self
            .moderation_report_config()
            .ok_or(AppError::ModerationReportingNotConfigured)?;
        let reported = parse_reported_pubkey(reported_pubkey)?;
        let reporter =
            PublicKey::from_hex(&account.account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
        if reported == reporter {
            return Err(AppError::CannotReportSelf);
        }
        let explanation = normalize_explanation(explanation);
        let dedupe_key = dedupe_key(&config.recipient, &reported, reason, origin);

        let slot = self.moderation_reports.slot(label);
        let mut generation = slot.generation.subscribe();
        let work = slot.work.lock().await;
        // Re-read the account under the lock: a sign-out may have closed
        // admission or committed while this submission waited.
        if !slot.admits(&generation) || self.account_home.account(label)?.signed_out {
            return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
        }
        let storage = self.account_storage(label)?;
        storage.prune_moderation_reports(
            now_ms.saturating_sub(window_ms(MODERATION_REPORT_RATE_WINDOW)),
            now_ms.saturating_sub(window_ms(PENDING_MAX_AGE)),
        )?;
        if let Some(existing) = storage.moderation_report_by_dedupe_key(
            &dedupe_key,
            now_ms.saturating_sub(window_ms(MODERATION_REPORT_IDEMPOTENCY_WINDOW)),
        )? {
            return Ok((
                ModerationReportOutcome {
                    report_id: existing.report_id,
                    status: existing.outcome.into(),
                },
                true,
            ));
        }
        if storage.moderation_reports_created_since(
            now_ms.saturating_sub(window_ms(MODERATION_REPORT_RATE_WINDOW)),
        )? >= MODERATION_REPORT_RATE_LIMIT
        {
            return Err(AppError::ModerationReportRateLimited);
        }

        let signer = self.account_signer_for_summary(&account)?.as_nostr_signer();
        let rumor = moderation_report_rumor(reporter, reported, reason, origin, &explanation);
        // An external signer may be slow; a purge or shutdown must not wait on it.
        let wrap = tokio::select! {
            wrap = transport_nostr_peeler::gift_wrap_rumor(signer, config.recipient, rumor) => wrap
                .map_err(|error| AppError::Publish(format!("moderation report wrap: {error}")))?,
            _ = generation_changed(&mut generation) => {
                return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
            }
            _ = runtime_stopping(&mut stopping) => return Err(AppError::RuntimeStopping),
        };
        let event = NostrTransportEvent::from_nostr_event(&wrap)
            .map_err(|error| AppError::Publish(format!("moderation report event: {error}")))?;
        let report_id = hex::encode(rand::random::<[u8; 16]>());
        // Record intent before any relay can see the wrap.
        storage.stage_moderation_report(&ModerationReportOutboxEntry {
            report_id: report_id.clone(),
            dedupe_key,
            recipient_pubkey_hex: config.recipient.to_hex(),
            outcome: ModerationReportOutboxOutcome::AcceptedPending,
            event_json: Some(serde_json::to_string(&event)?),
            created_at_ms: now_ms,
            attempts: 0,
        })?;
        // Durably mark the attempt before relay I/O: if it is interrupted,
        // shutdown, cancellation or process death leave it `CompletionUnknown`.
        // The claim keeps a concurrent retry pass off this live attempt.
        let _claim = PublishClaim::try_claim(&slot, &report_id)
            .ok_or_else(|| AppError::Publish("moderation report already publishing".into()))?;
        storage.begin_moderation_report_attempt(&report_id)?;
        // Publish without the account lock so a slow relay never blocks another
        // report, a retry selection or a purge. A purge that lands meanwhile
        // deletes the row, and the attempt record below then updates nothing.
        drop(work);

        let outcome = tokio::select! {
            outcome = self.publish_moderation_wrap(&config, &event) => outcome,
            _ = generation_changed(&mut generation) => {
                // The purge that bumped the generation deletes the staged row.
                return Err(AccountHomeError::SecretNotFound(account.account_id_hex).into());
            }
            _ = runtime_stopping(&mut stopping) => {
                // Left queued and marked in flight; the wrap may already have
                // reached a relay. The next catch-up after restart retries it.
                return Ok((
                    ModerationReportOutcome {
                        report_id,
                        status: ModerationReportStatus::CompletionUnknown,
                    },
                    false,
                ));
            }
        };
        if let Err(error) = storage.record_moderation_report_attempt(&report_id, outcome, now_ms) {
            // The relay outcome stands; a stale row only causes one more idempotent retry.
            tracing::warn!(
                target: "marmot_app::moderation_reports",
                method = "submit_moderation_report",
                error_kind = AppError::from(error).privacy_safe_kind(),
                "failed to record moderation report attempt"
            );
        }
        Ok((
            ModerationReportOutcome {
                report_id,
                status: outcome.into(),
            },
            false,
        ))
    }

    /// Retry this account's queued reports against the current configuration. Reports
    /// staged for a different recipient are dropped, never redirected.
    pub(crate) async fn retry_pending_moderation_reports(
        &self,
        label: &str,
        mut stopping: Option<watch::Receiver<bool>>,
    ) -> Result<ModerationReportRetrySummary, AppError> {
        let account = self.account_home.account(label)?;
        if account.signed_out {
            return Ok(ModerationReportRetrySummary::default());
        }
        let slot = self.moderation_reports.slot(label);
        let Some(_pass) = RetryPass::begin(&slot) else {
            return Ok(ModerationReportRetrySummary::default());
        };
        let mut generation = slot.generation.subscribe();
        let work = slot.work.lock().await;
        if !slot.admits(&generation) || self.account_home.account(label)?.signed_out {
            return Ok(ModerationReportRetrySummary::default());
        }
        let storage = self.account_storage(label)?;
        let now_ms = unix_now_ms();
        let mut summary = ModerationReportRetrySummary {
            abandoned: storage.prune_moderation_reports(
                now_ms.saturating_sub(window_ms(MODERATION_REPORT_RATE_WINDOW)),
                now_ms.saturating_sub(window_ms(PENDING_MAX_AGE)),
            )? as usize,
            ..Default::default()
        };
        let pending = storage.pending_moderation_reports(RETRY_BATCH_LIMIT)?;
        drop(work);
        let Some(config) = self.moderation_report_config() else {
            summary.pending = pending.len();
            return Ok(summary);
        };
        let recipient_hex = config.recipient.to_hex();
        for entry in pending {
            let event = entry
                .event_json
                .as_deref()
                .filter(|_| entry.recipient_pubkey_hex == recipient_hex)
                .and_then(|json| serde_json::from_str::<NostrTransportEvent>(json).ok());
            let Some(event) = event else {
                storage.delete_moderation_report(&entry.report_id)?;
                summary.abandoned += 1;
                continue;
            };
            // A report still publishing in this process is not interrupted.
            let Some(_claim) = PublishClaim::try_claim(&slot, &entry.report_id) else {
                summary.pending += 1;
                continue;
            };
            if !storage.begin_moderation_report_attempt(&entry.report_id)? {
                // Purged or published since selection.
                continue;
            }
            let outcome = tokio::select! {
                outcome = self.publish_moderation_wrap(&config, &event) => outcome,
                _ = generation_changed(&mut generation) => break,
                _ = runtime_stopping(&mut stopping) => break,
            };
            storage.record_moderation_report_attempt(&entry.report_id, outcome, unix_now_ms())?;
            if outcome == ModerationReportOutboxOutcome::Published {
                summary.published += 1;
            } else {
                summary.pending += 1;
            }
        }
        tracing::info!(
            target: "marmot_app::moderation_reports",
            method = "retry_pending_moderation_reports",
            published = summary.published,
            pending = summary.pending,
            abandoned = summary.abandoned,
            "moderation report retry pass finished"
        );
        Ok(summary)
    }

    /// Whether `label` has reports waiting for a relay. Cheap; used to skip retry passes.
    pub(crate) fn has_pending_moderation_reports(&self, label: &str) -> bool {
        self.account_storage(label)
            .and_then(|storage| Ok(storage.has_pending_moderation_reports()?))
            .unwrap_or(false)
    }

    /// Stop in-flight report work for `label` and delete every report it queued.
    #[cfg(test)]
    pub(crate) async fn purge_moderation_reports(&self, label: &str) -> Result<u64, AppError> {
        let (_fence, purged) = self.fence_moderation_reports(label).await;
        purged
    }

    /// Close `label`'s report admission, stop its in-flight report work and
    /// delete every report it queued. Admission stays closed until the fence
    /// drops, so a teardown holds it until the account is signed out or gone.
    /// The fence is returned even when the purge fails.
    pub(crate) async fn fence_moderation_reports(
        &self,
        label: &str,
    ) -> (ModerationReportFence, Result<u64, AppError>) {
        let slot = self.moderation_reports.slot(label);
        // Raise the fence before bumping: work that subscribes after the bump
        // sees the fence under the lock instead.
        slot.fences
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let fence = ModerationReportFence(slot.clone());
        slot.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        let _work = slot.work.lock().await;
        // An account that cannot sign, or whose database was never created,
        // has no reports. Do not create and migrate a database to learn that.
        #[cfg(test)]
        if self
            .moderation_reports
            .fail_next_purge
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return (
                fence,
                Err(AppError::Storage(cgka_traits::storage::StorageError::Busy(
                    "injected".into(),
                ))),
            );
        }
        let purged = match self.account_home.account(label) {
            Ok(account) if !account.can_sign() => Ok(0),
            Ok(_) if !self.account_storage_path(label).exists() => Ok(0),
            _ => self
                .account_storage(label)
                .and_then(|storage| Ok(storage.purge_moderation_reports()?)),
        };
        if let Err(error) = &purged {
            tracing::warn!(
                target: "marmot_app::moderation_reports",
                method = "fence_moderation_reports",
                error_kind = error.privacy_safe_kind(),
                "failed to purge queued moderation reports"
            );
        }
        (fence, purged)
    }

    async fn publish_moderation_wrap(
        &self,
        config: &ValidatedModerationReportConfig,
        event: &NostrTransportEvent,
    ) -> ModerationReportOutboxOutcome {
        // Re-check at the dial chokepoint even though the configuration was validated.
        let endpoints = match self
            .relay_plane
            .sanitize_relay_endpoints(config.relays.clone(), "moderation report publish")
        {
            Ok(endpoints) if !endpoints.is_empty() => endpoints,
            _ => return ModerationReportOutboxOutcome::AcceptedPending,
        };
        let publisher = self.moderation_report_publisher();
        match tokio::time::timeout(
            PUBLISH_TIMEOUT,
            publisher.publish_event(&endpoints, event, 1),
        )
        .await
        {
            Ok(Ok(outcome)) if !outcome.accepted.is_empty() => {
                ModerationReportOutboxOutcome::Published
            }
            Ok(Ok(outcome)) => unaccepted_outcome(&outcome.failed),
            Ok(Err(error)) => unaccepted_outcome(error.publish_endpoint_failures()),
            Err(_) => ModerationReportOutboxOutcome::CompletionUnknown,
        }
    }
}

/// No relay accepted: pending when every failure provably never left, else unknown.
fn unaccepted_outcome(failures: &[TransportEndpointFailure]) -> ModerationReportOutboxOutcome {
    if !failures.is_empty()
        && failures
            .iter()
            .all(|failure| failure.kind != TransportEndpointFailureKind::PossiblyExposed)
    {
        ModerationReportOutboxOutcome::AcceptedPending
    } else {
        ModerationReportOutboxOutcome::CompletionUnknown
    }
}

fn parse_reported_pubkey(value: &str) -> Result<PublicKey, AppError> {
    let value = value.trim();
    let well_formed = (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        || value.starts_with("npub1");
    if !well_formed {
        return Err(AppError::InvalidReportedPublicKey);
    }
    parse_curve_point(value).ok_or(AppError::InvalidReportedPublicKey)
}

/// Parse a hex or `npub` key that is a real secp256k1 x-only point.
/// `PublicKey::parse` only decodes 32 bytes; `xonly` checks curve membership.
fn parse_curve_point(value: &str) -> Option<PublicKey> {
    PublicKey::parse(value)
        .ok()
        .filter(|key| key.xonly().is_ok())
}

/// Trim, bound to [`MODERATION_REPORT_EXPLANATION_MAX_CHARS`], and trim again so a cut
/// never leaves trailing whitespace. Empty means "no explanation".
pub(crate) fn normalize_explanation(explanation: &str) -> String {
    explanation
        .trim()
        .chars()
        .take(MODERATION_REPORT_EXPLANATION_MAX_CHARS)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// Scoped to the recipient: after a reports-key change, a repeat is a new report
/// to the new key, never an echo of a wrap addressed to the old one.
fn dedupe_key(
    recipient: &PublicKey,
    reported: &PublicKey,
    reason: ReportReason,
    origin: ModerationReportOrigin,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        DEDUPE_DOMAIN,
        &recipient.to_bytes()[..],
        &reported.to_bytes()[..],
        reason.as_str().as_bytes(),
        origin.label().as_bytes(),
    ] {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

/// The unsigned kind-1984 rumor. Its only tags are the reported key with its NIP-56 type and
/// the NIP-32 origin label; there is never an `e` tag or any conversation identifier.
pub(crate) fn moderation_report_rumor(
    reporter: PublicKey,
    reported: PublicKey,
    reason: ReportReason,
    origin: ModerationReportOrigin,
    explanation: &str,
) -> UnsignedEvent {
    let tags = [
        vec![
            "p".to_owned(),
            reported.to_hex(),
            reason.as_str().to_owned(),
        ],
        vec!["L".to_owned(), MODERATION_REPORT_LABEL_NAMESPACE.to_owned()],
        vec![
            "l".to_owned(),
            origin.label().to_owned(),
            MODERATION_REPORT_LABEL_NAMESPACE.to_owned(),
        ],
    ]
    .into_iter()
    .map(|tag| Tag::parse(tag).expect("static report tags parse"));
    EventBuilder::new(Kind::from(NIP56_REPORT_KIND), explanation)
        .tags(tags)
        .finalize_unsigned(reporter)
}

/// Marks one account's retry pass as running until dropped.
struct RetryPass<'a>(&'a AccountSlot);

impl<'a> RetryPass<'a> {
    fn begin(slot: &'a AccountSlot) -> Option<Self> {
        use std::sync::atomic::Ordering;
        slot.retrying
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(slot))
    }
}

impl Drop for RetryPass<'_> {
    fn drop(&mut self) {
        self.0
            .retrying
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

fn window_ms(window: Duration) -> u64 {
    u64::try_from(window.as_millis()).unwrap_or(u64::MAX)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

async fn generation_changed(generation: &mut watch::Receiver<u64>) {
    if generation.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn runtime_stopping(stopping: &mut Option<watch::Receiver<bool>>) {
    let Some(stopping) = stopping else {
        return std::future::pending().await;
    };
    loop {
        if *stopping.borrow_and_update() {
            return;
        }
        if stopping.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

#[cfg(test)]
mod tests;
