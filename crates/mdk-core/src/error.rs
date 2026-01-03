// Copyright (c) 2024-2025 Jeff Gardner
// Copyright (c) 2025 Rust Nostr Developers
// Distributed under the MIT software license

//! MDK errors

use std::string::FromUtf8Error;
use std::{fmt, str};

use nostr::nips::nip44;
use nostr::types::url;
use nostr::{Kind, SignerError, event, key};
use openmls::credentials::errors::BasicCredentialError;
use openmls::error::LibraryError;
use openmls::extensions::errors::InvalidExtensionError;
use openmls::framing::errors::ProtocolMessageError;
use openmls::group::{
    AddMembersError, CommitToPendingProposalsError, CreateGroupContextExtProposalError,
    CreateMessageError, ExportSecretError, MergePendingCommitError, NewGroupError,
    ProcessMessageError, SelfUpdateError, WelcomeError,
};
use openmls::key_packages::errors::{KeyPackageNewError, KeyPackageVerifyError};
use openmls::prelude::{MlsGroupStateError, ValidationError};
use openmls_traits::types::CryptoError;

/// Nostr MLS error
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    /// Hex error
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    /// Keys error
    #[error(transparent)]
    Keys(#[from] key::Error),
    /// Event error
    #[error(transparent)]
    Event(#[from] event::Error),
    /// Event Builder error
    #[error(transparent)]
    EventBuilder(#[from] event::builder::Error),
    /// Nostr Signer error
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// NIP44 error
    #[error(transparent)]
    NIP44(#[from] nip44::Error),
    /// Relay URL error
    #[error(transparent)]
    RelayUrl(#[from] url::Error),
    /// TLS error
    #[error(transparent)]
    Tls(#[from] tls_codec::Error),
    /// UTF8 error
    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),
    /// Crypto error
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Generic OpenMLS error
    #[error(transparent)]
    OpenMlsGeneric(#[from] LibraryError),
    /// Invalid extension error
    #[error(transparent)]
    InvalidExtension(#[from] InvalidExtensionError),
    /// Create message error
    #[error(transparent)]
    CreateMessage(#[from] CreateMessageError),
    /// Export secret error
    #[error(transparent)]
    ExportSecret(#[from] ExportSecretError),
    /// Basic credential error
    #[error(transparent)]
    BasicCredential(#[from] BasicCredentialError),
    /// Process message error - epoch mismatch
    #[error("Message epoch differs from the group's epoch")]
    ProcessMessageWrongEpoch,
    /// Process message error - wrong group ID
    #[error("Wrong group ID")]
    ProcessMessageWrongGroupId,
    /// Process message error - use after eviction
    #[error("Use after eviction")]
    ProcessMessageUseAfterEviction,
    /// Process message error - other
    #[error("{0}")]
    ProcessMessageOther(String),
    /// Protocol message error
    #[error("{0}")]
    ProtocolMessage(String),
    /// Key package error
    #[error("{0}")]
    KeyPackage(String),
    /// Group error
    #[error("{0}")]
    Group(String),
    /// Group exporter secret not found
    #[error("group exporter secret not found")]
    GroupExporterSecretNotFound,
    /// Message error
    #[error("{0}")]
    Message(String),
    /// Cannot decrypt own message
    #[error("cannot decrypt own message")]
    CannotDecryptOwnMessage,
    /// Merge pending commit error
    #[error("{0}")]
    MergePendingCommit(String),
    /// Commit to pending proposal
    #[error("unable to commit to pending proposal")]
    CommitToPendingProposalsError,
    /// Self update error
    #[error("{0}")]
    SelfUpdate(String),
    /// Welcome error
    #[error("{0}")]
    Welcome(String),
    /// We're missing a Welcome for an existing ProcessedWelcome
    #[error("missing welcome for processed welcome")]
    MissingWelcomeForProcessedWelcome,
    /// Processed welcome not found
    #[error("processed welcome not found")]
    ProcessedWelcomeNotFound,
    /// Provider error
    #[error("{0}")]
    Provider(String),
    /// Group not found
    #[error("group not found")]
    GroupNotFound,
    /// Protocol message group ID doesn't match the current group ID
    #[error("protocol message group ID doesn't match the current group ID")]
    ProtocolGroupIdMismatch,
    /// Own leaf not found
    #[error("own leaf not found")]
    OwnLeafNotFound,
    /// Failed to load signer
    #[error("can't load signer")]
    CantLoadSigner,
    /// Invalid Welcome message
    #[error("invalid welcome message")]
    InvalidWelcomeMessage,
    /// Unexpected event
    #[error("unexpected event kind: expected={expected}, received={received}")]
    UnexpectedEvent {
        /// Expected event kind
        expected: Kind,
        /// Received event kind
        received: Kind,
    },
    /// Unexpected extension type
    #[error("Unexpected extension type")]
    UnexpectedExtensionType,
    /// Nostr group data extension not found
    #[error("Nostr group data extension not found")]
    NostrGroupDataExtensionNotFound,
    /// Message from a non-member of a group
    #[error("Message received from non-member")]
    MessageFromNonMember,
    /// Code path is not yet implemented
    #[error("{0}")]
    NotImplemented(String),
    /// Stored message not found
    #[error("stored message not found")]
    MessageNotFound,
    /// Proposal message received from a non-admin
    #[error("not processing proposal from non-admin")]
    ProposalFromNonAdmin,
    /// Commit message received from a non-admin
    #[error("not processing commit from non-admin")]
    CommitFromNonAdmin,
    /// Error when updating group context extensions
    #[error("Error when updating group context extensions {0}")]
    UpdateGroupContextExts(String),
    /// Invalid image hash length
    #[error("invalid image hash length")]
    InvalidImageHashLength,
    /// Invalid image key length
    #[error("invalid image key length")]
    InvalidImageKeyLength,
    /// Invalid image nonce length
    #[error("invalid image nonce length")]
    InvalidImageNonceLength,
    /// Invalid image upload key length
    #[error("invalid image upload key length")]
    InvalidImageUploadKeyLength,
    /// Invalid extension version
    #[error("invalid extension version: {0}")]
    InvalidExtensionVersion(u16),
    /// Rumor pubkey does not match MLS sender credential
    #[error("author mismatch: rumor pubkey does not match MLS sender")]
    AuthorMismatch,
    /// Key package identity binding mismatch - credential identity doesn't match event signer
    #[error(
        "key package identity mismatch: credential identity {credential_identity} doesn't match event signer {event_signer}"
    )]
    KeyPackageIdentityMismatch {
        /// The identity claimed in the BasicCredential
        credential_identity: String,
        /// The public key that signed the event
        event_signer: String,
    },
    /// Rumor event is missing its ID
    #[error("rumor event is missing its ID")]
    MissingRumorEventId,
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Self::Utf8(e.utf8_error())
    }
}

impl From<ProtocolMessageError> for Error {
    fn from(e: ProtocolMessageError) -> Self {
        Self::ProtocolMessage(e.to_string())
    }
}

impl From<KeyPackageNewError> for Error {
    fn from(e: KeyPackageNewError) -> Self {
        Self::KeyPackage(e.to_string())
    }
}

impl From<KeyPackageVerifyError> for Error {
    fn from(e: KeyPackageVerifyError) -> Self {
        Self::KeyPackage(e.to_string())
    }
}

impl<T> From<NewGroupError<T>> for Error
where
    T: fmt::Display,
{
    fn from(e: NewGroupError<T>) -> Self {
        Self::Group(e.to_string())
    }
}

impl<T> From<AddMembersError<T>> for Error
where
    T: fmt::Display,
{
    fn from(e: AddMembersError<T>) -> Self {
        Self::Group(e.to_string())
    }
}

impl<T> From<MergePendingCommitError<T>> for Error
where
    T: fmt::Display,
{
    fn from(e: MergePendingCommitError<T>) -> Self {
        Self::MergePendingCommit(e.to_string())
    }
}

impl<T> From<CommitToPendingProposalsError<T>> for Error
where
    T: fmt::Display,
{
    fn from(_e: CommitToPendingProposalsError<T>) -> Self {
        Self::CommitToPendingProposalsError
    }
}

impl<T> From<SelfUpdateError<T>> for Error
where
    T: fmt::Display,
{
    fn from(e: SelfUpdateError<T>) -> Self {
        Self::SelfUpdate(e.to_string())
    }
}

impl<T> From<WelcomeError<T>> for Error
where
    T: fmt::Display,
{
    fn from(e: WelcomeError<T>) -> Self {
        Self::Welcome(e.to_string())
    }
}

impl<T> From<CreateGroupContextExtProposalError<T>> for Error
where
    T: fmt::Display,
{
    fn from(e: CreateGroupContextExtProposalError<T>) -> Self {
        Self::UpdateGroupContextExts(e.to_string())
    }
}

/// Convert ProcessMessageError to our structured error variants
impl<T> From<ProcessMessageError<T>> for Error
where
    T: fmt::Display,
{
    fn from(e: ProcessMessageError<T>) -> Self {
        match e {
            ProcessMessageError::ValidationError(validation_error) => match validation_error {
                ValidationError::WrongEpoch => Self::ProcessMessageWrongEpoch,
                ValidationError::WrongGroupId => Self::ProcessMessageWrongGroupId,
                ValidationError::CannotDecryptOwnMessage => Self::CannotDecryptOwnMessage,
                _ => Self::ProcessMessageOther(validation_error.to_string()),
            },
            ProcessMessageError::GroupStateError(group_state_error) => match group_state_error {
                MlsGroupStateError::UseAfterEviction => Self::ProcessMessageUseAfterEviction,
                _ => Self::ProcessMessageOther(group_state_error.to_string()),
            },
            _ => Self::ProcessMessageOther(e.to_string()),
        }
    }
}
