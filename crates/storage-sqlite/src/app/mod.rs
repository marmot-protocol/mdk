//! App storage: projections, timeline, chat list, recovery and media.

pub(crate) mod account_projection;
pub(crate) mod account_recovery;
pub(crate) mod attachment_acquisition;
pub(crate) mod attachment_history;
pub(crate) mod avatar_cache;
pub(crate) mod chat_list;
pub(crate) mod chat_presentation;
pub(crate) mod encrypted_media_secrets;
pub(crate) mod group_system;
pub(crate) mod handle;
pub(crate) mod local_submissions;
pub(crate) mod media_catalog;
pub(crate) mod message_drafts;
pub(crate) mod pending_welcome_delivery;
pub(crate) mod recovery_health;
pub(crate) mod timeline;
pub(crate) mod transport;
