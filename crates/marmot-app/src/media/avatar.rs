//! Acquisition admission for avatar bytes. Clients still own full frame decoding.
use super::{blossom::BlossomHttpTransport, group_image};
use crate::AppError;
use storage_sqlite::{AvatarImage, AvatarImageFormat, MAX_AVATAR_BYTES, SelectedAvatar};

pub(crate) fn validate(bytes: Vec<u8>, declared: Option<&str>) -> Result<AvatarImage, AppError> {
    let mut bytes = zeroize::Zeroizing::new(bytes);
    let (media_type, width, height) = group_image::inspect_group_image_input(&bytes, declared)?;
    let format = match media_type.as_str() {
        "image/png" => AvatarImageFormat::Png,
        "image/jpeg" => AvatarImageFormat::Jpeg,
        "image/gif" => AvatarImageFormat::Gif,
        "image/webp" => AvatarImageFormat::Webp,
        _ => {
            return Err(AppError::InvalidEncryptedMedia(
                "unsupported avatar image".into(),
            ));
        }
    };
    // Transfer the same allocation into AvatarImage's Zeroizing buffer; both
    // validation errors here and the eventual image drop wipe their owner.
    Ok(AvatarImage::new(
        std::mem::take(&mut *bytes),
        format,
        width,
        height,
    )?)
}

pub(crate) async fn fetch(
    selected: &SelectedAvatar,
    transport: &BlossomHttpTransport,
) -> Result<AvatarImage, AppError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        fetch_inner(selected, transport),
    )
    .await
    .map_err(|_| AppError::BlobStore("avatar acquisition timed out".into()))?
}

async fn fetch_inner(
    selected: &SelectedAvatar,
    transport: &BlossomHttpTransport,
) -> Result<AvatarImage, AppError> {
    match selected {
        SelectedAvatar::RemoteImage { url, .. } => {
            let bytes = super::download_profile_image(url.clone(), MAX_AVATAR_BYTES as u64).await?;
            validate(bytes, None)
        }
        SelectedAvatar::EncryptedGroupImage { image, .. } => {
            let declared = image.media_type.as_deref().unwrap_or_default();
            let bytes = group_image::fetch_group_image_with_transport(
                &image.image_hash_hex,
                &image.image_key_hex,
                &image.image_nonce_hex,
                declared,
                None,
                transport,
            )
            .await?;
            validate(bytes, Some(declared))
        }
        SelectedAvatar::Placeholder { .. } => Err(AppError::InvalidEncryptedMedia(
            "avatar has no remote source".into(),
        )),
    }
}

pub(crate) fn retryable(error: &AppError) -> bool {
    // A hash/decryption/header failure can be a transient bad response at an
    // unchanged source. Reject its bytes, but allow durable backoff to repair it.
    !matches!(error, AppError::UnsafeMediaFetch(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn encoded(format: image::ImageFormat, width: u32) -> Vec<u8> {
        let image = image::DynamicImage::new_rgb8(width, 1);
        let mut out = Cursor::new(Vec::new());
        image.write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    #[test]
    fn avatar_download_admission_rejects_unrenderable_headers_and_mime_mismatch() {
        let malformed = validate(b"not an image".to_vec(), None).unwrap_err();
        assert!(
            retryable(&malformed),
            "a corrected response at the same source must be retryable"
        );
        assert!(validate(encoded(image::ImageFormat::Png, 1), Some("image/jpeg")).is_err());
        assert!(validate(encoded(image::ImageFormat::Png, 4097), None).is_err());
        let mut huge = encoded(image::ImageFormat::Png, 1);
        huge.resize(MAX_AVATAR_BYTES + 1, 0);
        assert!(validate(huge, None).is_err());
        for format in [
            image::ImageFormat::Png,
            image::ImageFormat::Jpeg,
            image::ImageFormat::Gif,
            image::ImageFormat::WebP,
        ] {
            let bytes = encoded(format, 2);
            let admitted = validate(bytes.clone(), None).unwrap();
            assert_eq!(admitted.bytes(), bytes);
            assert_eq!((admitted.width(), admitted.height()), (2, 1));
        }
    }

    #[tokio::test]
    async fn avatar_selected_url_policy_rejects_local_hosts_without_fallback() {
        let selected = SelectedAvatar::RemoteImage {
            url: "https://127.0.0.1/image.png".into(),
            cache_key: "test".into(),
        };
        let error = fetch(&selected, &BlossomHttpTransport::new(false))
            .await
            .unwrap_err();
        assert!(!retryable(&error));
        assert!(matches!(error, AppError::UnsafeMediaFetch(_)));
    }
}
