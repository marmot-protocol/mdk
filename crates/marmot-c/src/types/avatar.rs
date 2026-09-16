//! Native avatar metadata and encoded-byte ownership.
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::conversions::*;
c_enum! { MarmotAvatarAvailability from AvatarAvailabilityFfi { Missing, Ready, Stale, Invalidated, } }
c_enum! { #[derive(Default)] MarmotAvatarAcquisitionState from AvatarAcquisitionStateFfi { #[default] Idle, Queued, Fetching, RetryScheduled, Blocked, } }
c_mirror! { MarmotAvatarAsset from AvatarAssetFfi, free marmot_avatar_asset_free, list(MarmotAvatarAssetList, marmot_avatar_asset_list_free) {
    str target,
    opt_str reference,
    copy availability: MarmotAvatarAvailability,
    opt_copy has_acquisition/acquisition: MarmotAvatarAcquisitionState,
    copy content_revision: u64,
    copy byte_count: u64,
} }
c_mirror! { MarmotAvatarBytes from AvatarBytesFfi, free marmot_avatar_bytes_free, list(MarmotAvatarBytesList, marmot_avatar_bytes_list_free) {
    str reference,
    copy availability: MarmotAvatarAvailability,
    copy content_revision: u64,
    copy byte_count: u64,
    copy deferred: bool,
    bytes bytes/bytes_len,
    opt_str media_type,
    copy width: u32,
    copy height: u32,
} }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    #[test]
    fn avatar_bytes_deep_free_preserves_binary_payload() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        let image = AvatarBytesFfi {
            reference: "ref".into(),
            availability: AvatarAvailabilityFfi::Stale,
            content_revision: 4,
            byte_count: 4,
            deferred: false,
            bytes: vec![0, 1, 0, 255],
            media_type: Some("image/png".into()),
            width: 1,
            height: 1,
        };
        let mirror: MarmotAvatarBytesList = vec![image].into();
        unsafe {
            assert_eq!(
                (*mirror.items).availability,
                MarmotAvatarAvailability::Stale
            );
            assert_eq!(
                std::slice::from_raw_parts((*mirror.items).bytes, (*mirror.items).bytes_len),
                &[0, 1, 0, 255]
            );
            marmot_avatar_bytes_list_free(boxed(mirror));
            marmot_avatar_bytes_list_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(before, audit::live_allocations());
    }
}
