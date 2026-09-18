//! Encoded avatar metadata and bounded local byte results; hosts own decoding.
use marmot_app as app;
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AvatarAvailabilityFfi {
    Missing,
    Ready,
    Stale,
    Invalidated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AvatarAcquisitionStateFfi {
    Idle,
    Queued,
    Fetching,
    RetryScheduled,
    Blocked,
}
#[derive(Clone, uniffi::Record)]
pub struct AvatarAssetFfi {
    pub target: String,
    pub reference: Option<String>,
    pub availability: AvatarAvailabilityFfi,
    pub acquisition: Option<AvatarAcquisitionStateFfi>,
    pub content_revision: u64,
    pub byte_count: u64,
}
#[derive(Clone, uniffi::Record)]
pub struct AvatarBytesFfi {
    pub reference: String,
    pub availability: AvatarAvailabilityFfi,
    pub content_revision: u64,
    pub byte_count: u64,
    pub deferred: bool,
    /// Empty unless a complete validated cache entry fit the batch budget.
    pub bytes: Vec<u8>,
    pub media_type: Option<String>,
    pub width: u32,
    pub height: u32,
}
redact!(AvatarAssetFfi);
redact!(AvatarBytesFfi);
impl From<app::AvatarAvailability> for AvatarAvailabilityFfi {
    fn from(v: app::AvatarAvailability) -> Self {
        match v {
            app::AvatarAvailability::Missing => Self::Missing,
            app::AvatarAvailability::Ready => Self::Ready,
            app::AvatarAvailability::Stale => Self::Stale,
            app::AvatarAvailability::Invalidated => Self::Invalidated,
        }
    }
}
impl From<app::AvatarAcquisitionState> for AvatarAcquisitionStateFfi {
    fn from(v: app::AvatarAcquisitionState) -> Self {
        match v {
            app::AvatarAcquisitionState::Idle => Self::Idle,
            app::AvatarAcquisitionState::Queued => Self::Queued,
            app::AvatarAcquisitionState::Fetching => Self::Fetching,
            app::AvatarAcquisitionState::RetryScheduled => Self::RetryScheduled,
            app::AvatarAcquisitionState::Blocked => Self::Blocked,
        }
    }
}
impl From<app::AvatarAssetPresentation> for AvatarAssetFfi {
    fn from(v: app::AvatarAssetPresentation) -> Self {
        Self {
            target: v.target.to_opaque(),
            reference: v.reference.map(|r| r.to_opaque()),
            availability: v.status.availability.into(),
            acquisition: v.acquisition.map(Into::into),
            content_revision: v.status.content_revision,
            byte_count: v.status.byte_count,
        }
    }
}
impl From<app::LocalAvatarRead> for AvatarBytesFfi {
    fn from(v: app::LocalAvatarRead) -> Self {
        let image = v.result.image;
        Self {
            reference: v.reference.to_opaque(),
            availability: v.result.status.availability.into(),
            content_revision: v.result.status.content_revision,
            byte_count: v.result.status.byte_count,
            deferred: v.deferred,
            bytes: image
                .as_ref()
                .map(|i| i.bytes().to_vec())
                .unwrap_or_default(),
            media_type: image.as_ref().map(|i| i.format().media_type().to_owned()),
            width: image.as_ref().map(|i| i.width()).unwrap_or_default(),
            height: image.as_ref().map(|i| i.height()).unwrap_or_default(),
        }
    }
}
