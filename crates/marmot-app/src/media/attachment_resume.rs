//! Durable ciphertext only. Native byte/progress access remains a separate contract.
use super::AttachmentDownloadFailure;
use crate::AppError;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use storage_sqlite::{
    ATTACHMENT_CHECKPOINT_BYTES, AttachmentAcquisition, AttachmentPartial,
    AttachmentPartialIdentity, SqliteAccountStorage,
};

#[derive(Clone)]
pub(crate) struct AttachmentResume {
    pub storage: SqliteAccountStorage,
    pub job: AttachmentAcquisition,
    pub ciphertext_digest: [u8; 32],
    pub budget: u64,
    pub directory: PathBuf,
    pub disk_reserve: u64,
}
fn retry(message: &str) -> AttachmentDownloadFailure {
    AttachmentDownloadFailure::Retry(AppError::BlobStore(message.into()))
}
fn stop(message: &str) -> AttachmentDownloadFailure {
    AttachmentDownloadFailure::Stop(AppError::BlobStore(message.into()))
}

impl AttachmentResume {
    pub(super) async fn load(
        &self,
        url: &url::Url,
        max: u64,
    ) -> Result<Option<AttachmentPartial>, AttachmentDownloadFailure> {
        let this = self.clone();
        let locator_digest = Sha256::digest(url.as_str().as_bytes()).into();
        tokio::task::spawn_blocking(move || {
            this.storage.load_attachment_partial(
                &this.job,
                crate::unix_now_seconds(),
                max,
                Some((&this.ciphertext_digest, &locator_digest)),
            )
        })
        .await
        .map_err(|_| retry("partial checkpoint task failed"))?
        .map_err(|_| retry("partial checkpoint read failed"))
    }
    pub(crate) async fn clear(&self) -> Result<(), AttachmentDownloadFailure> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            this.storage
                .clear_attachment_partial(&this.job, crate::unix_now_seconds())
        })
        .await
        .map_err(|_| retry("partial checkpoint task failed"))?
        .map_err(|_| retry("partial checkpoint cleanup failed"))?;
        Ok(())
    }
    async fn save(
        &self,
        identity: AttachmentPartialIdentity,
        offset: usize,
        bytes: Vec<u8>,
    ) -> Result<(), AttachmentDownloadFailure> {
        let this = self.clone();
        let saved = tokio::task::spawn_blocking(move || {
            let free = fs4::available_space(&this.directory).unwrap_or(0);
            if free
                < this
                    .disk_reserve
                    .saturating_add(4 * ATTACHMENT_CHECKPOINT_BYTES as u64)
            {
                return Ok(false);
            }
            this.storage.checkpoint_attachment_partial(
                &this.job,
                &identity,
                offset as u64,
                &bytes,
                crate::unix_now_seconds(),
                this.budget,
            )
        })
        .await
        .map_err(|_| retry("partial checkpoint task failed"))?
        .map_err(|_| retry("partial checkpoint write failed"))?;
        if !saved {
            return Err(retry("partial checkpoint no longer admitted"));
        }
        Ok(())
    }
}

pub(super) fn strong_etag(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(reqwest::header::ETAG).iter();
    let tag = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || tag.len() < 2
        || tag.len() > 1024
        || !tag.starts_with('"')
        || !tag.ends_with('"')
        || !tag.as_bytes()[1..tag.len() - 1]
            .iter()
            .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
    {
        return None;
    }
    Some(tag.to_owned())
}

/// Accept only a single exact suffix of the saved representation. Unknown totals,
/// multipart, shortened/overlapping ranges and duplicate range headers fail closed.
pub(super) fn valid_range(response: &reqwest::Response, part: &AttachmentPartial) -> bool {
    let mut ranges = response
        .headers()
        .get_all(reqwest::header::CONTENT_RANGE)
        .iter();
    let Some(raw) = ranges.next().and_then(|h| h.to_str().ok()) else {
        return false;
    };
    if ranges.next().is_some() {
        return false;
    }
    let expected = format!(
        "bytes {}-{}/{}",
        part.bytes.len(),
        part.identity.total - 1,
        part.identity.total
    );
    raw == expected
        && response
            .content_length()
            .is_none_or(|n| n == part.identity.total - part.bytes.len() as u64)
}

pub(super) async fn read_body(
    mut response: reqwest::Response,
    url: &url::Url,
    max: u64,
    first_byte_deadline: tokio::time::Instant,
    context: &Arc<AttachmentResume>,
    prefix: Option<AttachmentPartial>,
) -> Result<Vec<u8>, AttachmentDownloadFailure> {
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes() != b"identity")
    {
        let _ = context.clear().await;
        return Err(stop("encoded response cannot be resumed"));
    }
    let (mut bytes, identity) = if let Some(part) = prefix {
        (part.bytes, Some(part.identity))
    } else {
        // A replacement checkpoint atomically replaces the old locator's prefix.
        // Preserve it if this fallback fails before saving any useful bytes.
        let identity = strong_etag(response.headers())
            .zip(response.content_length())
            .filter(|(_, n)| *n > 0 && *n <= max)
            .map(|(etag, total)| AttachmentPartialIdentity {
                ciphertext_digest: context.ciphertext_digest,
                locator_digest: Sha256::digest(url.as_str().as_bytes()).into(),
                etag,
                total,
            });
        (Vec::new(), identity)
    };
    let expected_total = identity
        .as_ref()
        .map(|i| i.total)
        .or_else(|| response.content_length());
    if expected_total.is_some_and(|n| n > max) {
        let _ = context.clear().await;
        return Err(stop("download exceeds size limit"));
    }
    let mut saved = bytes.len();
    let mut first = true;
    loop {
        let next = if first {
            tokio::time::timeout_at(first_byte_deadline, response.chunk())
                .await
                .map_err(|_| retry("request timed out"))?
                .map_err(|_| retry("body transfer failed"))
        } else {
            response
                .chunk()
                .await
                .map_err(|_| retry("body transfer failed"))
        };
        let chunk = match next {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(err) => {
                if let Some(identity) = &identity {
                    checkpoint_tail(context, identity, &bytes, &mut saved).await?;
                }
                return Err(err);
            }
        };
        first = false;
        let size = bytes.len().saturating_add(chunk.len()) as u64;
        if size > max || expected_total.is_some_and(|n| size > n) {
            let _ = context.clear().await;
            return Err(stop("download exceeds response size bound"));
        }
        bytes.extend_from_slice(&chunk);
        if let Some(identity) = &identity {
            while bytes.len() - saved >= ATTACHMENT_CHECKPOINT_BYTES {
                let end = saved + ATTACHMENT_CHECKPOINT_BYTES;
                context
                    .save(identity.clone(), saved, bytes[saved..end].to_vec())
                    .await?;
                saved = end;
            }
        }
    }
    if expected_total.is_some_and(|n| bytes.len() as u64 != n) {
        if let Some(identity) = &identity {
            checkpoint_tail(context, identity, &bytes, &mut saved).await?;
        }
        return Err(retry("incomplete media body"));
    }
    // Complete bodies go straight to verification/publication. Do not write a
    // final tiny checkpoint only to delete it on success.
    Ok(bytes)
}
async fn checkpoint_tail(
    context: &AttachmentResume,
    identity: &AttachmentPartialIdentity,
    bytes: &[u8],
    saved: &mut usize,
) -> Result<(), AttachmentDownloadFailure> {
    if bytes.len() > *saved {
        context
            .save(identity.clone(), *saved, bytes[*saved..].to_vec())
            .await?;
        *saved = bytes.len();
    }
    Ok(())
}
