//! Mechanical mappings of MDK's selected presentation; localization stays on the host.
use super::{ChatListAvatarFfi, ChatListRowFfi};
use marmot_app as app;

#[derive(Clone, uniffi::Enum)]
pub enum PresentationTextFfi {
    Literal { text: String },
    UnnamedGroup { member_count: Option<u64> },
    UnavailableConversation,
}
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PresentationSourceFfi {
    Group,
    PeerProfile,
    PeerFallback,
    GroupFallback,
    UnknownFallback,
}
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PresentationResolutionFfi {
    Cached,
    LastKnown,
    Fallback,
}
#[derive(Clone, uniffi::Enum)]
pub enum SelectedAvatarFfi {
    RemoteImage {
        url: String,
        cache_key: String,
    },
    EncryptedGroupImage {
        image: ChatListAvatarFfi,
        cache_key: String,
    },
    Placeholder {
        stable_seed: String,
        source: PresentationSourceFfi,
    },
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationPresentationFfi {
    pub title: PresentationTextFfi,
    pub avatar: SelectedAvatarFfi,
    pub title_source: PresentationSourceFfi,
    pub avatar_source: PresentationSourceFfi,
    pub peer_id: Option<String>,
    pub resolution: PresentationResolutionFfi,
}
#[derive(Clone, uniffi::Record)]
pub struct PresentationVersionFfi {
    pub account_store_epoch: Vec<u8>,
    pub revision: u64,
}
#[derive(Clone, uniffi::Record)]
pub struct PresentedChatRowFfi {
    pub row: ChatListRowFfi,
    pub presentation: ConversationPresentationFfi,
}
#[derive(Clone, uniffi::Record)]
pub struct PresentedChatListSnapshotFfi {
    pub rows: Vec<PresentedChatRowFfi>,
    pub presentation_version: PresentationVersionFfi,
}
#[derive(Clone, uniffi::Record)]
pub struct PresentedChatListUpdateFfi {
    pub subscription_generation: String,
    pub sequence: u64,
    pub snapshot: PresentedChatListSnapshotFfi,
}

macro_rules! impl_redacted_fmt {
    ($($ty:ty),* $(,)?) => {$(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct(stringify!($ty)).finish_non_exhaustive() }
    })*};
}
impl_redacted_fmt!(
    PresentationTextFfi,
    SelectedAvatarFfi,
    ConversationPresentationFfi,
    PresentationVersionFfi,
    PresentedChatRowFfi,
    PresentedChatListSnapshotFfi,
    PresentedChatListUpdateFfi
);
impl From<app::PresentationText> for PresentationTextFfi {
    fn from(v: app::PresentationText) -> Self {
        match v {
            app::PresentationText::Literal(text) => Self::Literal { text },
            app::PresentationText::UnnamedGroup { member_count } => {
                Self::UnnamedGroup { member_count }
            }
            app::PresentationText::UnavailableConversation => Self::UnavailableConversation,
        }
    }
}
impl From<app::PresentationSource> for PresentationSourceFfi {
    fn from(v: app::PresentationSource) -> Self {
        match v {
            app::PresentationSource::Group => Self::Group,
            app::PresentationSource::PeerProfile => Self::PeerProfile,
            app::PresentationSource::PeerFallback => Self::PeerFallback,
            app::PresentationSource::GroupFallback => Self::GroupFallback,
            app::PresentationSource::UnknownFallback => Self::UnknownFallback,
        }
    }
}
impl From<app::PresentationResolution> for PresentationResolutionFfi {
    fn from(v: app::PresentationResolution) -> Self {
        match v {
            app::PresentationResolution::Cached => Self::Cached,
            app::PresentationResolution::LastKnown => Self::LastKnown,
            app::PresentationResolution::Fallback => Self::Fallback,
        }
    }
}
impl From<app::SelectedAvatar> for SelectedAvatarFfi {
    fn from(v: app::SelectedAvatar) -> Self {
        match v {
            app::SelectedAvatar::RemoteImage { url, cache_key } => {
                Self::RemoteImage { url, cache_key }
            }
            app::SelectedAvatar::EncryptedGroupImage { image, cache_key } => {
                Self::EncryptedGroupImage {
                    image: image.into(),
                    cache_key,
                }
            }
            app::SelectedAvatar::Placeholder {
                stable_seed,
                source,
            } => Self::Placeholder {
                stable_seed,
                source: source.into(),
            },
        }
    }
}
impl From<app::ConversationPresentation> for ConversationPresentationFfi {
    fn from(v: app::ConversationPresentation) -> Self {
        Self {
            title: v.title.into(),
            avatar: v.avatar.into(),
            title_source: v.title_source.into(),
            avatar_source: v.avatar_source.into(),
            peer_id: v.peer_id,
            resolution: v.resolution.into(),
        }
    }
}
impl From<app::ChatPresentationVersion> for PresentationVersionFfi {
    fn from(v: app::ChatPresentationVersion) -> Self {
        Self {
            account_store_epoch: v.store_epoch,
            revision: v.revision,
        }
    }
}
impl From<app::PresentedChatRow> for PresentedChatRowFfi {
    fn from(v: app::PresentedChatRow) -> Self {
        Self {
            row: v.row.into(),
            presentation: v.presentation.into(),
        }
    }
}
impl From<app::PresentedChatListSnapshot> for PresentedChatListSnapshotFfi {
    fn from(v: app::PresentedChatListSnapshot) -> Self {
        Self {
            rows: v.rows.into_iter().map(Into::into).collect(),
            presentation_version: v.presentation_version.into(),
        }
    }
}
impl From<app::PresentedChatListUpdate> for PresentedChatListUpdateFfi {
    fn from(v: app::PresentedChatListUpdate) -> Self {
        Self {
            subscription_generation: v.subscription_generation,
            sequence: v.sequence,
            snapshot: v.snapshot.into(),
        }
    }
}
