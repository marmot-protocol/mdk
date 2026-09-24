//! Per-domain `impl Marmot` command blocks for the UniFFI surface.
//!
//! [`crate::lib`] keeps the [`Marmot`](crate::Marmot) struct, the UniFFI
//! scaffolding, construction/lifecycle methods, broadly-shared free helpers,
//! and the re-exports. Each sub-module here adds an `impl Marmot { ... }` block
//! for one app-API domain, mirroring the split already used in
//! `crate::conversions`. The blocks keep every `#[uniffi::export]` attribute
//! attached to the same methods, so the generated bindings are unaffected.

mod account;
mod agent_stream;
mod audit;
mod chat_list;
mod directory;
mod draft;
mod group;
mod local_submissions;
mod media;
mod message;
mod nostr_verification;
pub use local_submissions::{LocalSendAcceptanceFfi, LocalSendStatusFfi, MediaUploadSubmissionFfi};
mod notification;
mod onboarding;
mod push;
mod relay;
mod subscription;
mod telemetry;
mod timeline;

pub use group::{
    CreateGroupOptionsFfi, InitialGroupImageFfi, MemberKeyPackagePrewarmSummaryFfi,
    PreparedGroupImageUploadFfi, PreparedGroupImageUploadStateFfi,
};
pub use media::parse_media_imeta_tag;
pub use nostr_verification::verify_public_nostr_event_json;
pub use onboarding::OnboardingSubscription;

mod product_analytics;

mod presentation;

mod chat_window;

mod conversation_window;
pub mod user_blocks;

mod avatar;
pub mod moderation;

mod attachment_history;

mod attachment_access;

mod attachment_controls;
pub use attachment_controls::AttachmentTransferSubscription;
