//! Account-device runtime and session for Marmot.
//!
//! The runtime ([`AccountDeviceRuntime`]) is the app-level coordination over
//! one account-device session: it opens the session from a [`SessionConfig`],
//! then drives transport account activation, transport routing, KeyPackage
//! publication, and publish confirmation or rollback. The session wires the
//! engine to encrypted SQLite storage. It is private: hosts reach it only
//! through the runtime, and the `test-support` feature re-exports it as
//! `AccountDeviceSession` for tests that drive it directly (mdk#2602).

mod error;
mod key_package;
mod recovery_key;
mod routing;
mod runtime;
mod session;
mod time;

pub use error::{AccountError, AccountResult};
pub use key_package::{
    KeyPackageEventDeletion, KeyPackagePublication, KeyPackagePublishError,
    KeyPackagePublishReceipt, KeyPackagePublisher, KeyPackageSlotWithdrawal,
    NoopKeyPackagePublisher,
};
pub use recovery_key::seal_to_recovery_key;
pub use routing::{StaticTransportRouting, TransportRoutingError, TransportRoutingPolicy};
pub use runtime::{
    AccountDeviceEffects, AccountDeviceRuntime, AccountIngestEffects, AccountIngestPhase,
    CompletedWelcomePublishTask, DeviceRosterEdit, DeviceRosterEditBlocked, DeviceSelfReport,
    FailedApplicationMessage, ForeignSlotOutcome, ForeignSlotPublication, MaintenanceActivity,
    MaintenanceAttemptDuration, MaintenanceTiming, PendingResolution, PreparedSessionCommit,
    PreparedSessionSend, PreparedWelcomePublishTask, PublishFailure, PublishedApplicationMessage,
    UndeliveredCommit, UnresolvedApplicationMessage, UnresolvedPublish, UnresolvedPublishReason,
    WelcomeDeliveryFailure,
};
pub use session::{
    CreateGroupEffects, GroupAuthorityView, HydrationProgress, PublishWork, QueuedIntentRef,
    SessionConfig, SessionEffects, SessionError, SessionOpenTimings, SessionResult,
};
// The session and the types only its own API hands out, for tests that drive
// it directly. Production reaches the session only through the runtime.
#[cfg(feature = "test-support")]
pub use session::{AccountDeviceSession, IngestEffects};
// Engine items the session's API exposes, re-exported so hosts need not name
// the engine (mdk#2602).
pub use session::RECOVERY_ENTROPY_LEN;
pub use session::{
    AccountIdentityProofRequest, AccountIdentityProofSigner, CanonicalGroupMembership,
    CanonicalizationPolicy, FeatureRegistry, GroupAuthoritySnapshot, KeyPackageMetadata,
    KeyPackageRequirements, OwedSiblingWelcome, V1_SETTLEMENT_QUIESCENCE_MS, WelcomeDeliveryIndex,
    WelcomeWithdrawal, application_message_len, durably_owned_key_packages, key_package_metadata,
};
pub use session::{
    KIND_PRIVATE_KEY_PACKAGE_HAND_OFF, KIND_PRIVATE_KEY_PACKAGE_REQUEST, KIND_SIBLING_WELCOME,
    MAX_HAND_OFF_KEY_PACKAGES, MAX_PRIVATE_KEY_PACKAGE_WANT, PRIVATE_KEY_PACKAGE_STOCK_LOW,
    PRIVATE_KEY_PACKAGE_STOCK_TARGET, PrivateKeyPackageHandOff, PrivateKeyPackageRequest,
    SiblingWelcome, private_key_package_stock, validate_received_private_key_package,
};
pub use time::{
    MaintenanceRandom, MonotonicClock, OsMaintenanceRandom, SystemMonotonicClock, SystemWallClock,
    WallClock,
};
