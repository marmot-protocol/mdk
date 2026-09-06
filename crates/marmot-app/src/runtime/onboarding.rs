//! Durable, host-driven onboarding. Discovery never authorizes publication.
//! A repair is a separate proposal and revision-checked approval; its signed
//! bytes are checkpointed before they can reach a relay.
use super::*;
use crate::relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord, RelayEndpointPolicy};
use nostr::{EventBuilder, Kind, PublicKey, Tag, Timestamp};
use transport_nostr_peeler::NostrTransportEvent;

mod single_device;

const ONBOARDING_VERSION: u32 = 2;
const STEP_COUNT: usize = 6;
const MAX_RELAYS: usize = 16;
const CHECK_WAIT: Duration = Duration::from_secs(15);
const CHECK_MAX_AGE: u64 = 300;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnboardingStep {
    Profile,
    Follows,
    Relays,
    InboxRelays,
    KeyPackage,
    SingleDevice,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnboardingStatus {
    Pending,
    Checking,
    Passed,
    NeedsInput,
    RetryableFailure,
    WaitingForSigner,
    Skipped,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnboardingIssue {
    Missing,
    Malformed,
    FutureDated,
    InvalidRelay,
    RetiredRelay,
    UnsafeRelay,
    Unreachable,
    TimedOut,
    AuthenticationRequired,
    PaymentRequired,
    AccessRestricted,
    NoUsableRoute,
    PublicationFailed,
    SignerUnavailable,
    SignerRejected,
    RecordChanged,
    Interrupted,
    TooManyRelays,
    MultiDeviceUnsupported,
    OtherInstallationPossible,
    DiscoveryIncomplete,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnboardingAction {
    Retry,
    ContinueWithout,
    UseRecommendedRelays,
    EditRelays,
    EditProfile,
    EditFollows,
    ApproveRepair,
    CancelRepair,
    ReconnectSigner,
    EditDiscoveryRelays,
    ContinueAnyway,
    CancelOnboarding,
}
/// Evidence from the queried relays, never a claim that multi-device use is safe.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnboardingDeviceDiscovery {
    NoneFound,
    OtherInstallationPossible,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingDevicePackage {
    pub slot_id: String,
    pub key_package_ref_hex: String,
    pub event_id_hex: String,
    /// Original event timestamp, not a last-active timestamp.
    pub published_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingSingleDeviceNotice {
    pub discovery: OnboardingDeviceDiscovery,
    pub other_packages: Vec<OnboardingDevicePackage>,
    pub discovery_complete: bool,
    pub acknowledged_at: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingFinding {
    pub issue: OnboardingIssue,
    pub endpoint: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingStepState {
    pub step: OnboardingStep,
    pub status: OnboardingStatus,
    pub findings: Vec<OnboardingFinding>,
    pub actions: Vec<OnboardingAction>,
    pub checked_at: Option<u64>,
}
/// The relay declarations that approval will publish. Unknown non-relay tags
/// and the original event content are retained internally.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingRepairProposal {
    pub step: OnboardingStep,
    pub revision: u64,
    pub previous_event_id: Option<String>,
    pub read_relays: Vec<String>,
    pub write_relays: Vec<String>,
    pub profile: Option<UserProfileMetadata>,
    pub follows: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingSnapshot {
    pub account_id_hex: String,
    pub revision: u64,
    pub ready: bool,
    pub steps: Vec<OnboardingStepState>,
    pub proposal: Option<OnboardingRepairProposal>,
    #[serde(default)]
    pub single_device_notice: Option<OnboardingSingleDeviceNotice>,
}
/// Hosts pass the same default relay set used by account creation. Discovery
/// relays are independent indexers and are never implicitly published.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingOptions {
    pub default_relays: Vec<String>,
    pub discovery_relays: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct OnboardingCheckpoint {
    version: u32,
    snapshot: OnboardingSnapshot,
    options: OnboardingOptions,
    records: Vec<Option<NostrTransportEvent>>,
    // Persisted before signing/publication. Approval survives cancellation;
    // a retry republishes precisely the same event once signed.
    approved: bool,
    signed_repair: Option<NostrTransportEvent>,
    #[serde(default)]
    single_device_acknowledged: bool,
}

pub struct OnboardingSubscription {
    pub snapshot: OnboardingSnapshot,
    receiver: watch::Receiver<OnboardingSnapshot>,
}
impl OnboardingSubscription {
    pub async fn recv(&mut self) -> Option<OnboardingSnapshot> {
        self.receiver.changed().await.ok()?;
        Some(self.receiver.borrow_and_update().clone())
    }
}
impl OnboardingStep {
    fn index(self) -> usize {
        match self {
            Self::Profile => 0,
            Self::Follows => 1,
            Self::Relays => 2,
            Self::InboxRelays => 3,
            Self::SingleDevice => 4,
            Self::KeyPackage => 5,
        }
    }
    fn kind(self) -> u64 {
        match self {
            Self::Profile => 0,
            Self::Follows => 3,
            Self::Relays => 10002,
            Self::InboxRelays => 10050,
            Self::KeyPackage | Self::SingleDevice => 30443,
        }
    }
    fn optional(self) -> bool {
        matches!(self, Self::Profile | Self::Follows)
    }
    fn relay(self) -> bool {
        matches!(self, Self::Relays | Self::InboxRelays)
    }
}
impl OnboardingCheckpoint {
    fn new(account: &AccountSummary, options: OnboardingOptions) -> Self {
        let steps = [
            OnboardingStep::Profile,
            OnboardingStep::Follows,
            OnboardingStep::Relays,
            OnboardingStep::InboxRelays,
            OnboardingStep::SingleDevice,
            OnboardingStep::KeyPackage,
        ]
        .into_iter()
        .map(|step| OnboardingStepState {
            step,
            status: OnboardingStatus::Pending,
            findings: Vec::new(),
            actions: Vec::new(),
            checked_at: None,
        })
        .collect();
        Self {
            version: ONBOARDING_VERSION,
            snapshot: OnboardingSnapshot {
                account_id_hex: account.account_id_hex.clone(),
                revision: 0,
                ready: false,
                steps,
                proposal: None,
                single_device_notice: None,
            },
            options,
            records: vec![None; STEP_COUNT],
            approved: false,
            signed_repair: None,
            single_device_acknowledged: false,
        }
    }
    fn set(
        &mut self,
        step: OnboardingStep,
        status: OnboardingStatus,
        findings: Vec<OnboardingFinding>,
    ) {
        let actions = match status {
            OnboardingStatus::NeedsInput if step == OnboardingStep::SingleDevice => vec![
                OnboardingAction::ContinueAnyway,
                OnboardingAction::CancelOnboarding,
                OnboardingAction::Retry,
                OnboardingAction::EditDiscoveryRelays,
            ],
            OnboardingStatus::NeedsInput | OnboardingStatus::RetryableFailure => {
                let mut actions = vec![
                    OnboardingAction::Retry,
                    OnboardingAction::EditDiscoveryRelays,
                ];
                if step.optional() {
                    actions.push(OnboardingAction::ContinueWithout);
                    if status == OnboardingStatus::NeedsInput {
                        actions.push(if step == OnboardingStep::Profile {
                            OnboardingAction::EditProfile
                        } else {
                            OnboardingAction::EditFollows
                        });
                    }
                }
                // No replacement may be proposed from inconclusive discovery.
                if step.relay() && status == OnboardingStatus::NeedsInput {
                    actions.extend([
                        OnboardingAction::UseRecommendedRelays,
                        OnboardingAction::EditRelays,
                    ]);
                }
                actions
            }
            OnboardingStatus::WaitingForSigner => {
                vec![OnboardingAction::ReconnectSigner, OnboardingAction::Retry]
            }
            _ => Vec::new(),
        };
        self.snapshot.steps[step.index()] = OnboardingStepState {
            step,
            status,
            findings,
            actions,
            checked_at: Some(unix_now_seconds()),
        };
        self.snapshot.ready = self.snapshot.steps.iter().all(|s| {
            matches!(
                s.status,
                OnboardingStatus::Passed | OnboardingStatus::Skipped
            )
        });
    }
}
fn finding(issue: OnboardingIssue) -> OnboardingFinding {
    OnboardingFinding {
        issue,
        endpoint: None,
    }
}
fn onboarding_error() -> AppError {
    AppError::OnboardingActionUnavailable
}

impl AccountManager {
    fn onboarding_transaction(&self, id: &str) -> Arc<Mutex<()>> {
        let mut locks = self
            .onboarding_transactions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(id).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(id.to_owned(), Arc::downgrade(&lock));
        lock
    }
    fn onboarding_checkpoint(
        &self,
        account_ref: &str,
    ) -> Result<Option<OnboardingCheckpoint>, AppError> {
        let Some(bytes) = self.app.account_home().account_onboarding(account_ref)? else {
            return Ok(None);
        };
        let mut checkpoint: OnboardingCheckpoint = serde_json::from_slice(&bytes)?;
        let account = self.resolve(account_ref)?;
        // Upgrade the pre-notice checkpoint without activating an unfinished
        // account. Completed accounts are not retroactively gated; a new sign-in
        // resets every step and requires the notice then.
        if checkpoint.version == 1
            && checkpoint.snapshot.steps.len() == 5
            && checkpoint.records.len() == 5
            && checkpoint.snapshot.steps.iter().map(|s| s.step).eq([
                OnboardingStep::Profile,
                OnboardingStep::Follows,
                OnboardingStep::Relays,
                OnboardingStep::InboxRelays,
                OnboardingStep::KeyPackage,
            ])
        {
            checkpoint.snapshot.steps.insert(
                4,
                OnboardingStepState {
                    step: OnboardingStep::SingleDevice,
                    status: if checkpoint.snapshot.ready {
                        OnboardingStatus::Skipped
                    } else {
                        OnboardingStatus::Pending
                    },
                    findings: Vec::new(),
                    actions: Vec::new(),
                    checked_at: None,
                },
            );
            checkpoint.records.insert(4, None);
            if !checkpoint.snapshot.ready {
                checkpoint.set(
                    OnboardingStep::KeyPackage,
                    OnboardingStatus::Pending,
                    Vec::new(),
                );
            }
            checkpoint.version = ONBOARDING_VERSION;
        }
        if checkpoint.version != ONBOARDING_VERSION
            || checkpoint.snapshot.account_id_hex != account.account_id_hex
            || checkpoint.snapshot.steps.len() != STEP_COUNT
            || checkpoint.records.len() != STEP_COUNT
        {
            return Err(onboarding_error());
        }
        for (index, step) in checkpoint.snapshot.steps.iter().enumerate() {
            if step.step.index() != index {
                return Err(onboarding_error());
            }
        }
        Ok(Some(checkpoint))
    }
    fn save_onboarding(&self, checkpoint: &mut OnboardingCheckpoint) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        if checkpoint.approved
            && let Some(proposal) = &checkpoint.snapshot.proposal
        {
            let state = &mut checkpoint.snapshot.steps[proposal.step.index()];
            state.actions = match state.status {
                OnboardingStatus::WaitingForSigner => {
                    vec![OnboardingAction::ReconnectSigner, OnboardingAction::Retry]
                }
                OnboardingStatus::RetryableFailure => vec![OnboardingAction::Retry],
                _ => Vec::new(),
            };
        }
        checkpoint.snapshot.revision += 1;
        self.app.account_home().set_account_onboarding(
            &checkpoint.snapshot.account_id_hex,
            &serde_json::to_vec(checkpoint)?,
        )?;
        if let Some(sender) = self
            .onboarding_updates
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&checkpoint.snapshot.account_id_hex)
        {
            sender.send_replace(checkpoint.snapshot.clone());
        }
        Ok(())
    }
    pub fn onboarding_snapshot(
        &self,
        account_ref: &str,
    ) -> Result<Option<OnboardingSnapshot>, AppError> {
        Ok(self.onboarding_checkpoint(account_ref)?.map(|c| c.snapshot))
    }
    pub fn subscribe_onboarding(
        &self,
        account_ref: &str,
    ) -> Result<OnboardingSubscription, AppError> {
        // Lock before reading disk so a concurrent persisted update cannot be
        // lost between snapshot acquisition and receiver registration.
        let mut updates = self
            .onboarding_updates
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.shared.lifecycle().ensure_running()?;
        updates.retain(|_, sender| sender.receiver_count() > 0);
        let snapshot = self
            .onboarding_snapshot(account_ref)?
            .ok_or_else(onboarding_error)?;
        let sender = updates
            .entry(snapshot.account_id_hex.clone())
            .or_insert_with(|| watch::channel(snapshot.clone()).0);
        sender.send_replace(snapshot.clone());
        Ok(OnboardingSubscription {
            snapshot,
            receiver: sender.subscribe(),
        })
    }
    pub(super) fn require_onboarding_complete(&self, account_ref: &str) -> Result<(), AppError> {
        let required = match self.onboarding_snapshot(account_ref)? {
            Some(snapshot) => !snapshot.ready,
            None => self
                .app
                .account_home()
                .account_setup_state(account_ref)?
                .is_some_and(|s| s.kind == AccountSetupKind::InteractiveIdentity),
        };
        if required {
            return Err(AppError::OnboardingRequired);
        }
        Ok(())
    }
    pub(super) fn onboarding_worker_allowed(&self, account_ref: &str) -> Result<bool, AppError> {
        let checkpoint = self.onboarding_checkpoint(account_ref)?;
        if checkpoint.is_none()
            && self
                .app
                .account_home()
                .account_setup_state(account_ref)?
                .is_some_and(|s| s.kind == AccountSetupKind::InteractiveIdentity)
        {
            return Ok(false);
        }
        Ok(checkpoint.is_none_or(|c| {
            c.snapshot.ready
                || matches!(
                    c.snapshot.steps[OnboardingStep::KeyPackage.index()].status,
                    OnboardingStatus::Checking
                        | OnboardingStatus::WaitingForSigner
                        | OnboardingStatus::Passed
                )
        }))
    }
    fn validate_onboarding_options(&self, options: &OnboardingOptions) -> Result<(), AppError> {
        for endpoints in [&options.default_relays, &options.discovery_relays] {
            if endpoints.is_empty()
                || endpoints.len() > MAX_RELAYS
                || self
                    .app
                    .relay_plane
                    .classify_relay_endpoints(endpoints.clone())
                    .iter()
                    .any(|c| c.policy != RelayEndpointPolicy::Allowed)
            {
                return Err(onboarding_error());
            }
        }
        Ok(())
    }
    fn initialize_onboarding(
        &self,
        account: &AccountSummary,
        options: OnboardingOptions,
    ) -> Result<OnboardingSnapshot, AppError> {
        if let Some(mut existing) = self.onboarding_checkpoint(&account.label)? {
            if account.signed_out && existing.snapshot.ready {
                existing.single_device_acknowledged = false;
                existing.snapshot.single_device_notice = None;
                for index in 0..STEP_COUNT {
                    let step = existing.snapshot.steps[index].step;
                    existing.set(step, OnboardingStatus::Pending, Vec::new());
                }
                self.save_onboarding(&mut existing)?;
            }
            return Ok(existing.snapshot);
        }
        let mut checkpoint = OnboardingCheckpoint::new(account, options);
        self.save_onboarding(&mut checkpoint)?;
        Ok(checkpoint.snapshot)
    }
    /// Import only the identity. No relay records or KeyPackages are published.
    /// A retained account/checkpoint is returned even if later checks fail.
    pub async fn begin_onboarding(
        &self,
        nsec: Zeroizing<String>,
        options: OnboardingOptions,
    ) -> Result<OnboardingSnapshot, AppError> {
        self.shared.lifecycle().ensure_running()?;
        self.validate_onboarding_options(&options)?;
        let id = AccountHome::account_id_for_secret(&nsec)?;
        let transaction = self.onboarding_transaction(&id);
        let _transaction = transaction.lock().await;
        let _workers = self.worker_transactions.lock().await;
        let snapshot = match self.app.account_home().account(&id) {
            Ok(account) if account.local_signing => {
                // Reset a completed checkpoint before import clears signed_out.
                // A crash between the two writes must leave the account gated.
                let snapshot = self.initialize_onboarding(&account, options)?;
                self.app
                    .account_home()
                    .import_account_idempotent(&account.label, &nsec)?;
                snapshot
            }
            Ok(_) => return Err(onboarding_error()),
            Err(AccountHomeError::UnknownAccount(_)) => {
                let account = self
                    .app
                    .account_home()
                    .import_nostr_account_for_onboarding(&nsec)?
                    .account()
                    .clone();
                self.initialize_onboarding(&account, options)?
            }
            Err(error) => return Err(error.into()),
        };
        self.reconcile_locked().await?;
        Ok(snapshot)
    }
    pub async fn begin_external_signer_onboarding<S: crate::ExternalAccountSigner + 'static>(
        &self,
        public_key: String,
        signer: S,
        options: OnboardingOptions,
    ) -> Result<OnboardingSnapshot, AppError> {
        self.shared.lifecycle().ensure_running()?;
        self.validate_onboarding_options(&options)?;
        let id = AccountHome::account_id_for_public_key(&public_key)?;
        if signer
            .get_public_key()
            .await
            .map_err(crate::external_signer_public_key_error)?
            .to_hex()
            != id
        {
            return Err(AppError::ExternalSignerMismatch);
        }
        let transaction = self.onboarding_transaction(&id);
        let _transaction = transaction.lock().await;
        let _workers = self.worker_transactions.lock().await;
        // Existing identities must be gated before promotion can clear their
        // signed-out state, and before signer registration makes them runnable.
        let snapshot = match self.app.account_home().account(&id) {
            Ok(account) => {
                let snapshot = self.initialize_onboarding(&account, options)?;
                self.app
                    .account_home()
                    .add_external_signer_account(&public_key)?;
                snapshot
            }
            Err(AccountHomeError::UnknownAccount(_)) => {
                let account = self
                    .app
                    .account_home()
                    .add_external_signer_account(&public_key)?;
                self.initialize_onboarding(&account, options)?
            }
            Err(error) => return Err(error.into()),
        };
        self.reconcile_locked().await?;
        drop(_workers);
        self.app.register_external_signer(&id, signer).await?;
        Ok(snapshot)
    }
    /// Run pending checks until a decision or retry is needed. Cancelling this
    /// future is safe: the next call retries its last checkpointed operation.
    pub async fn run_onboarding(&self, account_ref: &str) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        self.run_onboarding_locked(&mut c).await?;
        Ok(c.snapshot)
    }
    async fn run_onboarding_locked(&self, c: &mut OnboardingCheckpoint) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        if c.snapshot.ready {
            // Completion is checkpointed before journal cleanup; a crash in
            // between must leave only idempotent housekeeping to resume.
            self.app
                .account_home()
                .complete_account_setup(&c.snapshot.account_id_hex)?;
            return Ok(());
        }
        if !c.approved && c.snapshot.proposal.is_none() {
            // A long pause cannot turn a historical reachability check into
            // evidence for today's publication route.
            for index in 0..4 {
                if c.snapshot.steps[index].status == OnboardingStatus::Passed
                    && c.snapshot.steps[index]
                        .checked_at
                        .is_none_or(|at| unix_now_seconds().saturating_sub(at) > CHECK_MAX_AGE)
                {
                    let step = c.snapshot.steps[index].step;
                    c.set(step, OnboardingStatus::Pending, Vec::new());
                    c.set(
                        OnboardingStep::KeyPackage,
                        OnboardingStatus::Pending,
                        Vec::new(),
                    );
                }
            }
            self.save_onboarding(c)?;
        }
        if c.approved {
            if !self.publish_onboarding_repair(c).await? {
                return Ok(());
            }
        } else if c.snapshot.proposal.is_some() {
            return Ok(());
        }
        for index in 0..STEP_COUNT {
            let step = c.snapshot.steps[index].step;
            match c.snapshot.steps[index].status {
                OnboardingStatus::Passed | OnboardingStatus::Skipped => continue,
                OnboardingStatus::NeedsInput
                | OnboardingStatus::RetryableFailure
                | OnboardingStatus::WaitingForSigner => return Ok(()),
                _ => {}
            }
            c.set(step, OnboardingStatus::Checking, Vec::new());
            self.save_onboarding(c)?;
            if step == OnboardingStep::SingleDevice {
                if c.single_device_acknowledged {
                    c.set(step, OnboardingStatus::Passed, Vec::new());
                } else {
                    self.check_onboarding_single_device(c).await?;
                }
            } else if step == OnboardingStep::KeyPackage {
                let account = self.resolve(&c.snapshot.account_id_hex)?;
                if account.external_signing
                    && !self.app.has_external_signer(&account.account_id_hex)
                {
                    c.set(
                        step,
                        OnboardingStatus::WaitingForSigner,
                        vec![finding(OnboardingIssue::SignerUnavailable)],
                    );
                } else {
                    if self
                        .app
                        .account_home()
                        .account_setup_state(&account.label)?
                        .is_none()
                    {
                        self.app.account_home().begin_account_setup_with(
                            &account,
                            false,
                            if account.external_signing {
                                AccountSetupKind::ExternalSigner
                            } else {
                                AccountSetupKind::ImportedIdentity
                            },
                            AccountSetupPhase::KeyPackagePublicationStarted,
                        )?;
                    } else {
                        self.app.account_home().set_account_setup_phase(
                            &account.label,
                            AccountSetupPhase::KeyPackagePublicationStarted,
                        )?;
                    }
                    if account.external_signing {
                        c.set(step, OnboardingStatus::WaitingForSigner, Vec::new());
                        self.save_onboarding(c)?;
                    }
                    let account = self
                        .app
                        .account_home()
                        .set_account_signed_out(&account.label, false)?;
                    match self.publish_initial_key_package_for_account(&account).await {
                        Ok(_) => {
                            self.app.account_home().set_account_setup_phase(
                                &account.label,
                                AccountSetupPhase::KeyPackagePublicationConfirmed,
                            )?;
                            c.set(step, OnboardingStatus::Passed, Vec::new());
                        }
                        Err(error) => set_operation_error(c, step, &error),
                    }
                }
            } else {
                let (status, findings, event) = self.check_onboarding_step(c, step).await;
                c.records[index] = event.clone();
                // Cache even imperfect signed data for settings visibility;
                // routing still filters it through the relay safety chokepoint.
                if let Some(event) = event {
                    self.app
                        .ingest_directory_relay_event(DirectoryRelayEventRecord {
                            endpoints: c
                                .options
                                .discovery_relays
                                .iter()
                                .cloned()
                                .map(TransportEndpoint)
                                .collect(),
                            event,
                        })?;
                }
                c.set(step, status, findings);
            }
            self.save_onboarding(c)?;
            if c.snapshot.steps[index].status != OnboardingStatus::Passed {
                self.reconcile().await?;
                return Ok(());
            }
        }
        if c.snapshot.ready {
            self.app
                .account_home()
                .complete_account_setup(&c.snapshot.account_id_hex)?;
        }
        Ok(())
    }
    pub async fn retry_onboarding_step(
        &self,
        account_ref: &str,
        step: OnboardingStep,
    ) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        if c.approved {
            self.run_onboarding_locked(&mut c).await?;
        } else {
            c.snapshot.proposal = None;
            // Rechecking earlier prerequisites invalidates publication readiness.
            if step == OnboardingStep::SingleDevice {
                c.single_device_acknowledged = false;
                c.snapshot.single_device_notice = None;
            }
            for index in step.index()..STEP_COUNT {
                let next = c.snapshot.steps[index].step;
                c.set(next, OnboardingStatus::Pending, Vec::new());
            }
            self.save_onboarding(&mut c)?;
            self.reconcile().await?;
            self.run_onboarding_locked(&mut c).await?;
        }
        Ok(c.snapshot)
    }
    /// Retry discovery through an explicitly selected source set. This never
    /// changes published relay declarations or publishes defaults.
    pub async fn set_onboarding_discovery_relays(
        &self,
        account_ref: &str,
        discovery_relays: Vec<String>,
    ) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        if c.approved {
            return Err(onboarding_error());
        }
        let options = OnboardingOptions {
            default_relays: c.options.default_relays.clone(),
            discovery_relays,
        };
        self.validate_onboarding_options(&options)?;
        c.options = options;
        c.snapshot.proposal = None;
        for index in 0..STEP_COUNT {
            if c.snapshot.steps[index].status != OnboardingStatus::Skipped {
                let step = c.snapshot.steps[index].step;
                c.set(step, OnboardingStatus::Pending, Vec::new());
            }
        }
        self.save_onboarding(&mut c)?;
        self.reconcile().await?;
        self.run_onboarding_locked(&mut c).await?;
        Ok(c.snapshot)
    }
    pub async fn continue_onboarding_without(
        &self,
        account_ref: &str,
        step: OnboardingStep,
    ) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        if c.approved
            || !step.optional()
            || !c.snapshot.steps[step.index()]
                .actions
                .contains(&OnboardingAction::ContinueWithout)
        {
            return Err(onboarding_error());
        }
        c.set(step, OnboardingStatus::Skipped, Vec::new());
        self.save_onboarding(&mut c)?;
        self.run_onboarding_locked(&mut c).await?;
        Ok(c.snapshot)
    }
}

fn set_operation_error(c: &mut OnboardingCheckpoint, step: OnboardingStep, error: &AppError) {
    let (status, issue) = match error {
        AppError::ExternalSignerUnavailable(_) => (
            OnboardingStatus::WaitingForSigner,
            OnboardingIssue::SignerUnavailable,
        ),
        AppError::ExternalSignerRejected => (
            OnboardingStatus::WaitingForSigner,
            OnboardingIssue::SignerRejected,
        ),
        _ => (
            OnboardingStatus::RetryableFailure,
            OnboardingIssue::PublicationFailed,
        ),
    };
    c.set(step, status, vec![finding(issue)]);
}

impl AccountManager {
    async fn inspect_onboarding_relays(
        &self,
        account_id: &str,
        kind: u64,
        endpoints: Vec<String>,
    ) -> (Vec<NostrTransportEvent>, Vec<OnboardingFinding>, usize) {
        let signer = self
            .resolve(account_id)
            .ok()
            .and_then(|account| self.app.account_signer_for_summary(&account).ok())
            .map(|signer| signer.as_nostr_signer());
        let mut tasks = JoinSet::new();
        let classifications = self.app.relay_plane.classify_relay_endpoints(endpoints);
        let mut failures = Vec::new();
        let mut seen = HashSet::new();
        for c in classifications {
            let issue = match c.policy {
                RelayEndpointPolicy::Allowed => None,
                RelayEndpointPolicy::Retired => Some(OnboardingIssue::RetiredRelay),
                RelayEndpointPolicy::Unsafe => Some(OnboardingIssue::UnsafeRelay),
                RelayEndpointPolicy::Invalid => Some(OnboardingIssue::InvalidRelay),
            };
            if let Some(issue) = issue {
                failures.push(OnboardingFinding {
                    issue,
                    endpoint: Some(c.endpoint),
                });
                continue;
            }
            let endpoint = c.normalized_endpoint.unwrap_or(c.endpoint);
            let url = nostr::RelayUrl::parse(&endpoint).expect("classified relay");
            if !seen.insert(url) {
                continue;
            }
            if seen.len() > MAX_RELAYS {
                failures.push(finding(OnboardingIssue::TooManyRelays));
                break;
            }
            let plane = self.app.relay_plane.clone();
            let signer = signer.clone();
            let query = DirectoryEventQuery::new(kind, vec![account_id.to_owned()], 32);
            tasks.spawn(async move {
                let result = timeout(
                    CHECK_WAIT,
                    plane.inspect_directory_events(
                        TransportEndpoint(endpoint.clone()),
                        query,
                        signer,
                    ),
                )
                .await;
                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err("timeout".into()),
                };
                (endpoint, result)
            });
        }
        let mut records = Vec::new();
        let mut completed = 0;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((_, Ok(events))) => {
                    completed += 1;
                    // A full bounded page may omit another installation's slot.
                    if kind == 30443 && events.len() >= 32 {
                        failures.push(finding(OnboardingIssue::DiscoveryIncomplete));
                    }
                    records.extend(events.into_iter().map(|r| r.event));
                }
                Ok((endpoint, Err(error))) => {
                    let issue = match error.as_str() {
                        "timeout" => OnboardingIssue::TimedOut,
                        "auth-required" => OnboardingIssue::AuthenticationRequired,
                        "payment-required" => OnboardingIssue::PaymentRequired,
                        "restricted" => OnboardingIssue::AccessRestricted,
                        _ => OnboardingIssue::Unreachable,
                    };
                    failures.push(OnboardingFinding {
                        issue,
                        endpoint: Some(endpoint),
                    });
                }
                Err(_) => failures.push(finding(OnboardingIssue::Interrupted)),
            }
        }
        // Enforce the event boundary even for injected fetchers. Never let an
        // older valid event hide a newer signed but malformed declaration.
        records.retain(|event| {
            let valid = event.kind == kind
                && event.pubkey == account_id
                && event.to_verified_nostr_event().is_ok();
            if kind == 30443 && !valid {
                failures.push(finding(OnboardingIssue::Malformed));
            }
            valid
        });
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        records.dedup_by(|a, b| a.id == b.id);
        (records, failures, completed)
    }
    async fn onboarding_sources(
        &self,
        c: &OnboardingCheckpoint,
        step: OnboardingStep,
    ) -> Vec<String> {
        let mut sources = c.options.discovery_relays.clone();
        let list = if let Some(event) = &c.records[OnboardingStep::Relays.index()] {
            Some(event.clone())
        } else if step.optional() {
            self.inspect_onboarding_relays(&c.snapshot.account_id_hex, 10002, sources.clone())
                .await
                .0
                .into_iter()
                .next()
        } else {
            None
        };
        if let Some(event) = list.filter(|e| e.created_at <= unix_now_seconds() + CHECK_MAX_AGE)
            && let Some(state) = crate::relay_list_state_from_event(&event)
        {
            let safe = self.app.relay_plane.retain_safe_discovered_endpoints(
                state.relays.into_iter().map(TransportEndpoint).collect(),
                "onboarding discovery",
            );
            for endpoint in safe {
                if !sources.contains(&endpoint.0) {
                    sources.push(endpoint.0);
                }
            }
        }
        sources
    }
    async fn check_onboarding_step(
        &self,
        c: &OnboardingCheckpoint,
        step: OnboardingStep,
    ) -> (
        OnboardingStatus,
        Vec<OnboardingFinding>,
        Option<NostrTransportEvent>,
    ) {
        if step == OnboardingStep::InboxRelays
            && self
                .resolve(&c.snapshot.account_id_hex)
                .is_ok_and(|account| {
                    account.external_signing
                        && !self.app.has_external_signer(&account.account_id_hex)
                })
        {
            return (
                OnboardingStatus::WaitingForSigner,
                vec![finding(OnboardingIssue::SignerUnavailable)],
                c.records[step.index()].clone(),
            );
        }
        let sources = self.onboarding_sources(c, step).await;
        let (records, failures, completed) = self
            .inspect_onboarding_relays(&c.snapshot.account_id_hex, step.kind(), sources)
            .await;
        let Some(event) = records.into_iter().next() else {
            return if completed == 0 || !failures.is_empty() {
                (
                    OnboardingStatus::RetryableFailure,
                    if failures.is_empty() {
                        vec![finding(OnboardingIssue::Unreachable)]
                    } else {
                        failures
                    },
                    None,
                )
            } else {
                (
                    OnboardingStatus::NeedsInput,
                    vec![finding(OnboardingIssue::Missing)],
                    None,
                )
            };
        };
        if event.created_at > unix_now_seconds() + CHECK_MAX_AGE {
            return (
                OnboardingStatus::RetryableFailure,
                vec![finding(OnboardingIssue::FutureDated)],
                Some(event),
            );
        }
        let mut findings = validate_onboarding_record(&event);
        if step.relay() {
            let name = if step == OnboardingStep::Relays {
                "r"
            } else {
                "relay"
            };
            let raw = event
                .tags
                .iter()
                .filter(|t| t.first().is_some_and(|v| v == name))
                .filter_map(|t| t.get(1).cloned())
                .collect();
            for classified in self.app.relay_plane.classify_relay_endpoints(raw) {
                let issue = match classified.policy {
                    RelayEndpointPolicy::Allowed => continue,
                    RelayEndpointPolicy::Invalid => OnboardingIssue::InvalidRelay,
                    RelayEndpointPolicy::Retired => OnboardingIssue::RetiredRelay,
                    RelayEndpointPolicy::Unsafe => OnboardingIssue::UnsafeRelay,
                };
                findings.push(OnboardingFinding {
                    issue,
                    endpoint: Some(classified.endpoint),
                });
            }
            let state = crate::relay_list_state_from_event(&event);
            if let Some(state) = state {
                let mut endpoints = state.relays.clone();
                if step == OnboardingStep::Relays {
                    for endpoint in state.read_relays {
                        if !endpoints.contains(&endpoint) {
                            endpoints.push(endpoint);
                        }
                    }
                }
                if endpoints.is_empty() {
                    findings.push(finding(OnboardingIssue::NoUsableRoute));
                } else {
                    // EOSE proves an actual query completed, not merely a TCP
                    // connection. Publication is independently confirmed below.
                    let (_, failures, completed) = self
                        .inspect_onboarding_relays(
                            &c.snapshot.account_id_hex,
                            if step == OnboardingStep::InboxRelays {
                                1059
                            } else {
                                10002
                            },
                            endpoints,
                        )
                        .await;
                    findings.extend(failures);
                    if completed == 0 || (step == OnboardingStep::Relays && state.relays.is_empty())
                    {
                        findings.push(finding(OnboardingIssue::NoUsableRoute));
                    }
                }
            } else {
                findings.push(finding(OnboardingIssue::Malformed));
            }
        }
        let status = if findings.is_empty() {
            OnboardingStatus::Passed
        } else {
            OnboardingStatus::NeedsInput
        };
        (status, findings, Some(event))
    }
    /// Prepare a relay replacement without signing or publishing it. Passing
    /// None uses the same recommended defaults supplied at identity creation.
    /// For inbox lists use read_relays; write_relays must be empty.
    pub async fn propose_onboarding_relays(
        &self,
        account_ref: &str,
        step: OnboardingStep,
        selection: Option<(Vec<String>, Vec<String>)>,
    ) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        if !step.relay()
            || c.approved
            || c.snapshot.steps[step.index()].status != OnboardingStatus::NeedsInput
        {
            return Err(onboarding_error());
        }
        let (read_relays, write_relays) = selection.unwrap_or_else(|| {
            (
                c.options.default_relays.clone(),
                if step == OnboardingStep::Relays {
                    c.options.default_relays.clone()
                } else {
                    Vec::new()
                },
            )
        });
        let all = read_relays
            .iter()
            .chain(&write_relays)
            .cloned()
            .collect::<Vec<_>>();
        if all.is_empty()
            || all.iter().collect::<HashSet<_>>().len() > MAX_RELAYS
            || (step == OnboardingStep::Relays && write_relays.is_empty())
            || (step == OnboardingStep::InboxRelays && !write_relays.is_empty())
            || self
                .app
                .relay_plane
                .classify_relay_endpoints(all)
                .iter()
                .any(|v| v.policy != RelayEndpointPolicy::Allowed)
        {
            return Err(onboarding_error());
        }
        c.snapshot.proposal = Some(OnboardingRepairProposal {
            step,
            revision: c.snapshot.revision + 1,
            previous_event_id: c.records[step.index()].as_ref().map(|e| e.id.clone()),
            read_relays,
            write_relays,
            profile: None,
            follows: None,
        });
        c.snapshot.steps[step.index()].actions = vec![
            OnboardingAction::ApproveRepair,
            OnboardingAction::CancelRepair,
        ];
        self.save_onboarding(&mut c)?;
        Ok(c.snapshot)
    }
    pub async fn propose_onboarding_profile(
        &self,
        account_ref: &str,
        profile: UserProfileMetadata,
    ) -> Result<OnboardingSnapshot, AppError> {
        self.propose_onboarding_optional(account_ref, Some(profile), None)
            .await
    }
    pub async fn propose_onboarding_follows(
        &self,
        account_ref: &str,
        follows: Vec<String>,
    ) -> Result<OnboardingSnapshot, AppError> {
        if follows.len() > 10000
            || follows
                .iter()
                .any(|key| key.len() != 64 || PublicKey::from_hex(key).is_err())
        {
            return Err(onboarding_error());
        }
        self.propose_onboarding_optional(account_ref, None, Some(follows))
            .await
    }
    async fn propose_onboarding_optional(
        &self,
        account_ref: &str,
        profile: Option<UserProfileMetadata>,
        follows: Option<Vec<String>>,
    ) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        let step = if profile.is_some() {
            OnboardingStep::Profile
        } else {
            OnboardingStep::Follows
        };
        if c.approved || c.snapshot.steps[step.index()].status != OnboardingStatus::NeedsInput {
            return Err(onboarding_error());
        }
        c.snapshot.proposal = Some(OnboardingRepairProposal {
            step,
            revision: c.snapshot.revision + 1,
            previous_event_id: c.records[step.index()].as_ref().map(|e| e.id.clone()),
            read_relays: Vec::new(),
            write_relays: Vec::new(),
            profile,
            follows,
        });
        c.snapshot.steps[step.index()].actions = vec![
            OnboardingAction::ApproveRepair,
            OnboardingAction::CancelRepair,
        ];
        self.save_onboarding(&mut c)?;
        Ok(c.snapshot)
    }
    pub async fn cancel_onboarding_repair(
        &self,
        account_ref: &str,
    ) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        if c.approved {
            return Err(onboarding_error());
        }
        let proposal = c.snapshot.proposal.take().ok_or_else(onboarding_error)?;
        let findings = c.snapshot.steps[proposal.step.index()].findings.clone();
        c.set(proposal.step, OnboardingStatus::NeedsInput, findings);
        self.save_onboarding(&mut c)?;
        Ok(c.snapshot)
    }
    pub async fn approve_onboarding_repair(
        &self,
        account_ref: &str,
        revision: u64,
    ) -> Result<OnboardingSnapshot, AppError> {
        let transaction = self.onboarding_transaction(&self.resolve(account_ref)?.account_id_hex);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        let proposal = c.snapshot.proposal.clone().ok_or_else(onboarding_error)?;
        if c.approved || c.snapshot.revision != revision || proposal.revision != revision {
            return Err(onboarding_error());
        }
        let sources = self.onboarding_sources(&c, proposal.step).await;
        let (records, failures, completed) = self
            .inspect_onboarding_relays(&c.snapshot.account_id_hex, proposal.step.kind(), sources)
            .await;
        if completed == 0 || !failures.is_empty() {
            c.set(proposal.step, OnboardingStatus::RetryableFailure, failures);
            c.snapshot.proposal = None;
        } else if records.first().map(|e| &e.id) != proposal.previous_event_id.as_ref() {
            c.records[proposal.step.index()] = records.first().cloned();
            c.snapshot.proposal = None;
            c.set(
                proposal.step,
                OnboardingStatus::RetryableFailure,
                vec![finding(OnboardingIssue::RecordChanged)],
            );
        } else {
            c.approved = true;
            c.set(proposal.step, OnboardingStatus::Checking, Vec::new());
            // All route-dependent checks must be repeated after publication.
            c.set(
                OnboardingStep::KeyPackage,
                OnboardingStatus::Pending,
                Vec::new(),
            );
        }
        self.save_onboarding(&mut c)?;
        if c.approved {
            self.run_onboarding_locked(&mut c).await?;
        }
        Ok(c.snapshot)
    }
    async fn publish_onboarding_repair(
        &self,
        c: &mut OnboardingCheckpoint,
    ) -> Result<bool, AppError> {
        let proposal = c.snapshot.proposal.clone().ok_or_else(onboarding_error)?;
        let account = self.resolve(&c.snapshot.account_id_hex)?;
        let signer = match self.app.account_signer_for_summary(&account) {
            Ok(signer) => signer.as_nostr_signer(),
            Err(error) => {
                set_operation_error(c, proposal.step, &error);
                self.save_onboarding(c)?;
                return Ok(false);
            }
        };
        if c.signed_repair.is_none() {
            if account.external_signing {
                c.set(
                    proposal.step,
                    OnboardingStatus::WaitingForSigner,
                    Vec::new(),
                );
                self.save_onboarding(c)?;
            }
            let (tags, content, created_at) = relay_repair_event(c, &proposal);
            let tags = tags
                .into_iter()
                .map(Tag::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| onboarding_error())?;
            let unsigned = EventBuilder::new(Kind::from(proposal.step.kind() as u16), content)
                .tags(tags)
                .custom_created_at(Timestamp::from(created_at))
                .build(
                    PublicKey::parse(&account.account_id_hex)
                        .map_err(|_| AppError::InvalidPublicKey)?,
                );
            let signed = match signer.sign_event(unsigned).await {
                Ok(event) => event,
                Err(error) => {
                    set_operation_error(
                        c,
                        proposal.step,
                        &crate::external_signer_error(error, "onboarding repair"),
                    );
                    self.save_onboarding(c)?;
                    return Ok(false);
                }
            };
            c.signed_repair = Some(
                NostrTransportEvent::from_nostr_event(&signed).map_err(|_| onboarding_error())?,
            );
            c.set(proposal.step, OnboardingStatus::Checking, Vec::new());
            self.save_onboarding(c)?;
        }
        let event = c.signed_repair.clone().ok_or_else(onboarding_error)?;
        let mut endpoints = self.onboarding_sources(c, proposal.step).await;
        endpoints.extend(
            proposal
                .read_relays
                .iter()
                .chain(&proposal.write_relays)
                .cloned(),
        );
        let endpoints = self.app.relay_plane.retain_safe_discovered_endpoints(
            endpoints.into_iter().map(TransportEndpoint).collect(),
            "onboarding repair",
        );
        let outcome = self
            .app
            .relay_client_for_account_id(&account.account_id_hex, signer)
            .publish_event(&endpoints, &event, 1)
            .await;
        match outcome {
            Ok(outcome) if !outcome.accepted.is_empty() => {
                self.app
                    .ingest_directory_relay_event(DirectoryRelayEventRecord {
                        endpoints,
                        event: event.clone(),
                    })?;
                c.records[proposal.step.index()] = Some(event);
                c.approved = false;
                c.signed_repair = None;
                c.snapshot.proposal = None;
                c.set(proposal.step, OnboardingStatus::Pending, Vec::new());
                if proposal.step == OnboardingStep::Relays {
                    c.set(
                        OnboardingStep::InboxRelays,
                        OnboardingStatus::Pending,
                        Vec::new(),
                    );
                    for step in [OnboardingStep::Profile, OnboardingStep::Follows] {
                        if c.snapshot.steps[step.index()].status != OnboardingStatus::Skipped {
                            c.set(step, OnboardingStatus::Pending, Vec::new());
                        }
                    }
                }
                self.save_onboarding(c)?;
                Ok(true)
            }
            _ => {
                c.set(
                    proposal.step,
                    OnboardingStatus::RetryableFailure,
                    vec![finding(OnboardingIssue::PublicationFailed)],
                );
                self.save_onboarding(c)?;
                Ok(false)
            }
        }
    }
}

fn validate_onboarding_record(event: &NostrTransportEvent) -> Vec<OnboardingFinding> {
    let malformed = match event.kind {
        0 => match serde_json::from_str::<serde_json::Value>(&event.content) {
            Ok(serde_json::Value::Object(map)) => {
                [
                    "name",
                    "display_name",
                    "about",
                    "picture",
                    "banner",
                    "website",
                    "nip05",
                    "lud06",
                    "lud16",
                ]
                .iter()
                .any(|key| {
                    map.get(*key)
                        .is_some_and(|v| !v.is_string() && !v.is_null())
                }) || ["picture", "banner", "website"].iter().any(|key| {
                    map.get(*key)
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.is_empty())
                        .is_some_and(|value| {
                            url::Url::parse(value).map_or(true, |url| {
                                !matches!(url.scheme(), "https" | "http")
                                    || url.host_str().is_none()
                                    || !url.username().is_empty()
                                    || url.password().is_some()
                            })
                        })
                })
            }
            _ => true,
        },
        3 => event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|v| v == "p"))
            .any(|tag| {
                tag.get(1)
                    .is_none_or(|key| key.len() != 64 || PublicKey::from_hex(key).is_err())
            }),
        10002 => event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|v| v == "r"))
            .any(|tag| {
                tag.get(1).is_none_or(String::is_empty)
                    || tag
                        .get(2)
                        .is_some_and(|role| !matches!(role.as_str(), "read" | "write"))
            }),
        10050 => event
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|v| v == "relay"))
            .any(|tag| tag.get(1).is_none_or(String::is_empty)),
        _ => false,
    };
    if malformed {
        vec![finding(OnboardingIssue::Malformed)]
    } else {
        Vec::new()
    }
}
fn relay_repair_event(
    c: &OnboardingCheckpoint,
    proposal: &OnboardingRepairProposal,
) -> (Vec<Vec<String>>, String, u64) {
    let previous = c.records[proposal.step.index()].as_ref();
    if let Some(profile) = &proposal.profile {
        let mut content = previous
            .and_then(|e| serde_json::from_str::<serde_json::Value>(&e.content).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        if let Some(patch) = crate::directory::records::profile_content_json(profile).as_object() {
            content.extend(patch.clone());
        }
        // None means preserve; an explicitly supplied empty string clears a
        // field, including one whose remote value had the wrong JSON type.
        for (name, value) in [
            ("name", &profile.name),
            ("display_name", &profile.display_name),
            ("about", &profile.about),
            ("picture", &profile.picture),
            ("banner", &profile.banner),
            ("nip05", &profile.nip05),
            ("lud16", &profile.lud16),
        ] {
            if value.as_ref().is_some_and(String::is_empty) {
                content.remove(name);
            }
        }
        return (
            previous.map(|e| e.tags.clone()).unwrap_or_default(),
            serde_json::Value::Object(content).to_string(),
            unix_now_seconds().max(previous.map_or(0, |e| e.created_at.saturating_add(1))),
        );
    }
    if let Some(follows) = &proposal.follows {
        let mut tags = previous
            .map(|e| {
                e.tags
                    .iter()
                    .filter(|t| {
                        t.first().is_none_or(|v| v != "p")
                            || t.get(1).is_some_and(|key| follows.contains(key))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for key in follows {
            if !tags
                .iter()
                .any(|t| t.first().is_some_and(|v| v == "p") && t.get(1) == Some(key))
            {
                tags.push(vec!["p".into(), key.clone()]);
            }
        }
        return (
            tags,
            previous.map(|e| e.content.clone()).unwrap_or_default(),
            unix_now_seconds().max(previous.map_or(0, |e| e.created_at.saturating_add(1))),
        );
    }
    let tag_name = if proposal.step == OnboardingStep::Relays {
        "r"
    } else {
        "relay"
    };
    let mut tags = previous
        .map(|e| {
            e.tags
                .iter()
                .filter(|t| t.first().is_none_or(|v| v != tag_name))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut relays = proposal.read_relays.clone();
    for relay in &proposal.write_relays {
        if !relays.contains(relay) {
            relays.push(relay.clone());
        }
    }
    for relay in relays {
        let mut tag = vec![tag_name.to_owned(), relay.clone()];
        if proposal.step == OnboardingStep::Relays {
            match (
                proposal.read_relays.contains(&relay),
                proposal.write_relays.contains(&relay),
            ) {
                (true, false) => tag.push("read".into()),
                (false, true) => tag.push("write".into()),
                _ => {}
            }
        }
        tags.push(tag);
    }
    (
        tags,
        previous.map(|e| e.content.clone()).unwrap_or_default(),
        unix_now_seconds().max(previous.map_or(0, |e| e.created_at.saturating_add(1))),
    )
}

#[cfg(test)]
mod tests;
