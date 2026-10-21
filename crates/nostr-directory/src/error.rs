//! The directory's error type.
//!
//! Directory code returns [`DirectoryError`]. `marmot-app` converts it back to
//! its `AppError` at the boundary, restoring the variant, message and
//! `privacy_safe_kind` used before the directory had its own type (step 3 of
//! `docs/marmot-architecture/review/brief-directory.md`).

use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageError;

use super::published_records::MissingRelayListKind;

/// Every failure directory code reports. Each variant's message matches the
/// `AppError` variant it converts to.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("invalid Marmot KeyPackage event: {0}")]
    InvalidKeyPackageEvent(String),
    #[error("invalid Nostr public key")]
    InvalidPublicKey,
    #[error("relay directory fetch failed: {0}")]
    RelayDirectory(String),
    #[error("{reason}")]
    MissingKeyPackage {
        account: String,
        reason: MissingKeyPackageReason,
    },
    #[error("invalid user directory search: {0}")]
    InvalidDirectorySearch(String),
    #[error("account directory lookup did not complete")]
    DirectoryLookupIncomplete(String),
    #[error("missing account relay lists: {0:?}")]
    MissingRelayLists(Vec<MissingRelayListKind>),
    #[error("transport event stream closed")]
    TransportClosed,
    #[error("member has no valid Marmot inbox relay")]
    MissingMemberInboxRoute(String),
    #[error("invalid public event reference batch: {0}")]
    InvalidPublicEventReferences(String),
    #[error("no directory entry for account")]
    MissingDirectoryEntry(String),
    #[error("invalid Nostr routing component: {0}")]
    InvalidNostrRouting(String),
    #[error("invalid cached identity page: {0}")]
    InvalidCachedIdentityPage(String),
    #[error("blocking app task failed: {0}")]
    BlockingTask(String),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    /// A KeyPackage failed the engine's requirements check. The app reports it
    /// through its session error, as it did before the directory had its own
    /// type.
    #[error(transparent)]
    KeyPackageRequirements(EngineError),
    /// A failure from the app, carried unchanged; see [`ResourceError`].
    #[error(transparent)]
    Resource(ResourceError),
}

impl DirectoryError {
    /// The same stable kind the `AppError` this converts to reports.
    pub fn privacy_safe_kind(&self) -> &'static str {
        match self {
            Self::InvalidKeyPackageEvent(_) => "invalid_key_package_event",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::RelayDirectory(_) => "relay_directory",
            Self::MissingKeyPackage { .. } => "missing_key_package",
            Self::InvalidDirectorySearch(_) => "invalid_directory_search",
            Self::DirectoryLookupIncomplete(_) => "directory_lookup_incomplete",
            Self::MissingRelayLists(_) => "missing_relay_lists",
            Self::TransportClosed => "transport_closed",
            Self::MissingMemberInboxRoute(_) => "missing_member_inbox_route",
            Self::InvalidPublicEventReferences(_) => "invalid_public_event_references",
            Self::MissingDirectoryEntry(_) => "missing_directory_entry",
            Self::InvalidNostrRouting(_) => "invalid_nostr_routing",
            Self::InvalidCachedIdentityPage(_) => "invalid_cached_identity_page",
            Self::BlockingTask(_) => "blocking_task",
            Self::Storage(error) => storage_error_kind(error),
            Self::Io(_) => "io",
            Self::Json(_) => "json",
            Self::Sqlite(error) => sqlite_error_kind(error),
            Self::Hex(_) => "hex",
            // As the app's session error classifies an engine error.
            Self::KeyPackageRequirements(EngineError::Storage(error)) => storage_error_kind(error),
            Self::KeyPackageRequirements(error) => error.privacy_safe_kind(),
            Self::Resource(error) => error.privacy_safe_kind(),
        }
    }
}

/// An error from the app (closed storage, a missing secret, an unknown
/// account), carried through the directory unchanged. Only the app builds
/// one, from its own error, so the boundary always gets that error back.
pub struct ResourceError {
    inner: Box<dyn std::error::Error + Send + Sync>,
    kind: &'static str,
}

impl ResourceError {
    /// Wraps an app error together with its privacy-safe kind. For the app's
    /// use only.
    pub fn from_app(
        error: impl std::error::Error + Send + Sync + 'static,
        kind: &'static str,
    ) -> Self {
        Self {
            inner: Box::new(error),
            kind,
        }
    }

    /// The wrapped app error.
    pub fn into_inner(self) -> Box<dyn std::error::Error + Send + Sync> {
        self.inner
    }

    /// The wrapped error's privacy-safe kind, recorded when it was wrapped.
    pub fn privacy_safe_kind(&self) -> &'static str {
        self.kind
    }
}

impl std::fmt::Debug for ResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl std::error::Error for ResourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

/// Why a completed KeyPackage lookup found nothing usable for joins.
/// Both reasons describe only the searched relays; neither proves global
/// absence, and neither relaxes current-profile admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MissingKeyPackageReason {
    /// No newest slot held a KeyPackage publication.
    #[error("no published key package for account")]
    NotFound,
    /// Every newest slot held a legacy-profile publication: the account
    /// must update and publish a current KeyPackage before it can be invited.
    #[error("account has only obsolete key packages published")]
    ObsoleteOnly,
}

impl MissingKeyPackageReason {
    /// Stable token for CLI JSON and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::ObsoleteOnly => "obsolete_only",
        }
    }
}

pub fn storage_error_kind(error: &StorageError) -> &'static str {
    match error {
        StorageError::NotFound => "storage_not_found",
        StorageError::AlreadyExists => "storage_already_exists",
        StorageError::SnapshotMissing(_) => "storage_snapshot_missing",
        StorageError::TimelineCursorExpired => "storage_timeline_cursor_expired",
        StorageError::Busy(_) => "storage_busy",
        StorageError::Corruption(_) => "storage_corruption",
        StorageError::Capacity(_) => "storage_capacity",
        StorageError::Closed(_) => "storage_closed",
        StorageError::UnsupportedSchemaVersion { .. } => "storage_unsupported_schema_version",
        StorageError::InvalidAttachmentBody(_) => "storage_invalid_attachment_body",
        StorageError::Backend(_) => "storage_backend",
        StorageError::Serialization(_) => "storage_serialization",
    }
}

/// The stable kind of a SQLite failure.
pub fn sqlite_error_kind(error: &rusqlite::Error) -> &'static str {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            "storage_busy"
        }
        Some(rusqlite::ErrorCode::DatabaseCorrupt) => "storage_corruption",
        Some(rusqlite::ErrorCode::DiskFull) => "storage_capacity",
        _ => "sqlite",
    }
}

/// Runs `task` on Tokio's blocking pool, as `marmot-app`'s `blocking_app_task`
/// does for the app.
pub async fn blocking_directory_task<T>(
    task: impl FnOnce() -> Result<T, DirectoryError> + Send + 'static,
) -> Result<T, DirectoryError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err| DirectoryError::BlockingTask(err.to_string()))?
}
