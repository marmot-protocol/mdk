//! Account-device runtime and session for Marmot.
//!
//! The runtime ([`AccountDeviceRuntime`]) is the app-level coordination over
//! one account-device session: it opens the session from a [`SessionConfig`],
//! then drives transport account activation, transport routing, KeyPackage
//! publication, and publish confirmation or rollback. The session
//! ([`AccountDeviceSession`]) wires the engine to encrypted SQLite storage.

mod error;
mod key_package;
mod routing;
mod runtime;
mod session;
mod time;

pub use error::{AccountError, AccountResult};
pub use key_package::{
    KeyPackagePublication, KeyPackagePublishError, KeyPackagePublishReceipt, KeyPackagePublisher,
    NoopKeyPackagePublisher,
};
pub use routing::{StaticTransportRouting, TransportRoutingError, TransportRoutingPolicy};
pub use runtime::{
    AccountDeviceEffects, AccountDeviceRuntime, AccountIngestEffects, AccountIngestPhase,
    CompletedWelcomePublishTask, FailedApplicationMessage, MaintenanceActivity,
    MaintenanceAttemptDuration, MaintenanceTiming, PendingResolution, PreparedSessionCommit,
    PreparedSessionSend, PreparedWelcomePublishTask, PublishFailure, PublishedApplicationMessage,
    UndeliveredCommit, UnresolvedApplicationMessage, UnresolvedPublish, UnresolvedPublishReason,
    WelcomeDeliveryFailure,
};
pub use session::{
    AccountDeviceSession, CreateGroupEffects, GroupAuthorityView, HydrationProgress, IngestEffects,
    PublishWork, QueuedIntentRef, SessionConfig, SessionEffects, SessionError, SessionOpenTimings,
    SessionResult,
};
// Engine items the session's API exposes, re-exported so hosts need not name
// the engine (mdk#2602).
pub use session::{
    AccountIdentityProofRequest, AccountIdentityProofSigner, CanonicalGroupMembership,
    CanonicalizationPolicy, FeatureRegistry, GroupAuthoritySnapshot, KeyPackageMetadata,
    KeyPackageRequirements, V1_SETTLEMENT_QUIESCENCE_MS, WelcomeDeliveryIndex,
    application_message_len, durably_owned_key_packages, key_package_metadata,
};
pub use time::{
    MaintenanceRandom, MonotonicClock, OsMaintenanceRandom, SystemMonotonicClock, SystemWallClock,
    WallClock,
};
