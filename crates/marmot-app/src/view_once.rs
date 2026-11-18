//! Device-local viewer ownership. A durable claim, not this handle, spends a message.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use storage_sqlite::SqliteAppStorage;
use zeroize::{Zeroize, Zeroizing};

use crate::{AppError, MarmotApp};

pub const MAX_VIEW_ONCE_READ_BYTES: u32 = 1024 * 1024;
pub const VIEW_ONCE_VIEWER_SECONDS: u64 = 60;

/// Input transfers to MDK. MDK does not retain a sender copy after publication.
pub struct ViewOnceMediaRequest {
    pub plaintext: Vec<u8>,
    pub media_type: String,
    pub unopened_expires_at: u64,
    pub blossom_server: Option<String>,
}

impl Drop for ViewOnceMediaRequest {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

impl std::fmt::Debug for ViewOnceMediaRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewOnceMediaRequest")
            .finish_non_exhaustive()
    }
}

pub enum ViewOnceConsumeOutcome {
    Opened { viewer: Arc<ViewOnceViewer> },
    Consumed,
    Expired,
    Unavailable,
}

impl std::fmt::Debug for ViewOnceConsumeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Opened { .. } => "Opened",
            Self::Consumed => "Consumed",
            Self::Expired => "Expired",
            Self::Unavailable => "Unavailable",
        })
    }
}

#[derive(Default)]
pub(crate) struct ViewOnceSessions {
    active: Mutex<HashMap<String, Option<std::sync::Weak<ViewerInner>>>>,
}

impl ViewOnceSessions {
    pub(crate) fn reserve(self: &Arc<Self>, label: &str) -> Result<ViewOncePermit, AppError> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.contains_key(label) {
            return Err(AppError::AccountWorkerBusy);
        }
        active.insert(label.to_owned(), None);
        Ok(ViewOncePermit {
            sessions: self.clone(),
            label: label.to_owned(),
        })
    }

    pub(crate) fn revalidate(&self, label: &str) {
        let viewer = self
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(label)
            .and_then(Option::as_ref)
            .and_then(std::sync::Weak::upgrade);
        if let Some(viewer) = viewer {
            // A failed source read closes the viewer, rather than retaining uncertain access.
            if !matches!(viewer.valid(), Ok(true)) {
                viewer.close();
            }
        }
    }
}

pub(crate) struct ViewOncePermit {
    sessions: Arc<ViewOnceSessions>,
    label: String,
}

impl Drop for ViewOncePermit {
    fn drop(&mut self) {
        self.sessions
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.label);
    }
}

pub(crate) struct ViewOnceAccess {
    pub(crate) storage: SqliteAppStorage,
    pub(crate) group: String,
    pub(crate) message: String,
    pub(crate) attachment_index: u32,
    pub(crate) expires_at: u64,
    pub(crate) claimed_at: tokio::time::Instant,
}

struct ViewerBody {
    bytes: Option<Zeroizing<Vec<u8>>>,
    permit: Option<ViewOncePermit>,
    closed: bool,
}

struct ViewerInner {
    access: ViewOnceAccess,
    deadline: tokio::time::Instant,
    body: Mutex<ViewerBody>,
}

impl ViewerInner {
    fn close(&self) {
        let mut body = self.body.lock().unwrap_or_else(|e| e.into_inner());
        body.closed = true;
        body.bytes.take();
        body.permit.take();
    }

    fn valid(&self) -> Result<bool, AppError> {
        if tokio::time::Instant::now() >= self.deadline {
            self.close();
            return Ok(false);
        }
        let access = &self.access;
        match access.storage.view_once_access_valid(
            &access.group,
            &access.message,
            access.attachment_index,
            crate::unix_now_seconds(),
        ) {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.close();
                Ok(false)
            }
            Err(error) => {
                self.close();
                Err(error.into())
            }
        }
    }
}

/// One claimed playback session. Returned bytes belong to the host and cannot be recalled.
/// Close, timeout, deletion and account teardown prevent subsequent reads.
pub struct ViewOnceViewer {
    inner: Arc<ViewerInner>,
    media_type: String,
    size: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for ViewOnceViewer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewOnceViewer").finish_non_exhaustive()
    }
}

impl ViewOnceViewer {
    pub(crate) fn opening(
        app: &MarmotApp,
        label: &str,
        access: ViewOnceAccess,
        permit: ViewOncePermit,
        media_type: String,
    ) -> Result<Arc<Self>, AppError> {
        let _lifecycle = app.begin_storage_open("view-once viewer")?;
        let remaining = access.expires_at.saturating_sub(crate::unix_now_seconds());
        let deadline = (access.claimed_at + Duration::from_secs(VIEW_ONCE_VIEWER_SECONDS))
            .min(tokio::time::Instant::now() + Duration::from_secs(remaining));
        let inner = Arc::new(ViewerInner {
            access,
            deadline,
            body: Mutex::new(ViewerBody {
                bytes: None,
                permit: Some(permit),
                closed: false,
            }),
        });
        app.view_once_sessions
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(label.to_owned(), Some(Arc::downgrade(&inner)));
        let weak = Arc::downgrade(&inner);
        app.close_registry.register(close_key(label), move || {
            if let Some(inner) = weak.upgrade() {
                inner.close();
            }
        });
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            if let Some(inner) = weak.upgrade() {
                inner.close();
            }
        });
        Ok(Arc::new(Self {
            inner,
            media_type,
            size: std::sync::atomic::AtomicU64::new(0),
        }))
    }

    pub(crate) fn deadline(&self) -> tokio::time::Instant {
        self.inner.deadline
    }

    pub(crate) async fn finish(&self, bytes: Zeroizing<Vec<u8>>) -> Result<bool, AppError> {
        let inner = self.inner.clone();
        let size = bytes.len() as u64;
        let ready = tokio::task::spawn_blocking(move || {
            if !inner.valid()? {
                return Ok(false);
            }
            let mut body = inner.body.lock().unwrap_or_else(|e| e.into_inner());
            if body.closed {
                return Ok(false);
            }
            body.bytes = Some(bytes);
            Ok(true)
        })
        .await
        .map_err(|_| AppError::BlockingTask("view-once access failed".into()))?;
        if matches!(ready, Ok(true)) {
            self.size.store(size, std::sync::atomic::Ordering::Release);
        }
        ready
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn size_bytes(&self) -> u64 {
        self.size.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Bounded decoder reads, including seeks, within this one playback session.
    pub async fn read(
        &self,
        offset: u64,
        limit: u32,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
        if limit == 0 || limit > MAX_VIEW_ONCE_READ_BYTES {
            return Err(AppError::InvalidEncryptedMedia(
                "invalid view-once byte range".into(),
            ));
        }
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            if !inner.valid()? {
                return Ok(None);
            }
            let body = inner.body.lock().unwrap_or_else(|e| e.into_inner());
            let Some(bytes) = body.bytes.as_ref().filter(|_| !body.closed) else {
                return Ok(None);
            };
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            let end = start.saturating_add(limit as usize).min(bytes.len());
            Ok(Some(Zeroizing::new(bytes[start..end].to_vec())))
        })
        .await
        .map_err(|_| AppError::BlockingTask("view-once read failed".into()))?
    }

    pub fn close(&self) {
        self.inner.close();
    }
}

pub(crate) fn close_key(label: &str) -> String {
    format!("view-once:{label}")
}

pub(crate) fn is_view_once(tags: &[Vec<String>]) -> bool {
    tags.iter().any(|tag| {
        tag.first().is_some_and(|name| name == "view-once")
            || (tag.first().is_some_and(|name| name == "imeta")
                && tag.iter().skip(1).any(|field| {
                    field
                        .strip_prefix("v ")
                        .is_some_and(|version| version.starts_with("encrypted-media-view-once"))
                }))
    })
}

pub(crate) fn redact_fields(plaintext: &mut String, tags: &mut Vec<Vec<String>>) {
    if is_view_once(tags) {
        plaintext.zeroize();
        let mut marker = false;
        tags.retain_mut(|tag| {
            if marker || tag.first().is_none_or(|name| name != "view-once") {
                tag.zeroize();
                return false;
            }
            for field in tag.iter_mut().skip(1) {
                field.zeroize();
            }
            tag.truncate(1);
            marker = true;
            true
        });
        if !marker {
            tags.push(vec!["view-once".into()]);
        }
    }
}

#[cfg(test)]
mod tests;
