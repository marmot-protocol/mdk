//! NIP-51 custom emoji sets (kind 30030) and the account's own emoji list
//! (kind 10030, read only).
//!
//! Egress is explicit. Discovery, `fetch_emoji_set` and `user_emoji_list`
//! read text events from relays and never fetch an image. Image bytes come
//! only from `fetch_emoji_set_asset` (one preview), `fetch_emoji_set_cover`
//! (the set's cover) and `install_emoji_set` (every emoji of a set), each of
//! which tells the image host the user's IP address, so hosts call them only
//! after an explicit user action. Each takes the event id of the version the
//! user was shown and fails with `EmojiSetChanged`, before any download,
//! when a later read stored another version: the user never reveals their
//! address to a host they were not shown.
//!
//! Installing snapshots one set version: each emoji is downloaded once,
//! validated, and stored with its SHA-256 under the account. Reading an
//! installed emoji never touches the network, and a later change of URL or
//! image cannot replace what was installed until the user reinstalls.
//! Nothing here builds a group message: hosts re-upload installed bytes as
//! encrypted attachments, so no set URL or address reaches a chat.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use cgka_traits::TransportEndpoint;
use futures::StreamExt;
use nostr::nips::nip19::{FromBech32, Nip19Coordinate};
use nostr::prelude::{Event, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::{
    EmojiSetInstallLimits, EmojiSetInstallOutcome, SqliteAppStorage, StoredEmojiSet,
    StoredEmojiSetEntry, StoredEmojiSetVersion, StoredEmojiSkip, StoredInstalledEmoji,
    StoredInstalledEmojiRow, StoredInstalledEmojiSet,
};
use url::Url;

use crate::image_inspect::{self, ImageRejection};
use crate::media::{PublicImageFetchError, fetch_public_image_limited, validate_blossom_fetch_url};
use crate::{AppError, MarmotApp, unix_now_seconds};

/// NIP-51 emoji set (addressable).
pub const EMOJI_SET_KIND: u16 = 30030;
/// NIP-51 user emoji list (replaceable): loose `emoji` tags plus `a`
/// pointers to emoji sets.
pub const USER_EMOJI_LIST_KIND: u16 = 10030;

/// Newest sets one discovery fetch asks relays for.
pub const MAX_DISCOVERY_EMOJI_SETS: usize = 60;
/// Discovered sets kept locally; installed ones are never pruned.
const MAX_STORED_EMOJI_SETS: usize = 200;
/// Replaceable versions read per set or list fetch.
const MAX_REPLACEABLE_VERSIONS_PER_FETCH: usize = 16;
const MAX_EMOJI_SET_RELAY_HINTS: usize = 8;
const MAX_INPUT_CHARS: usize = 2048;
const MAX_IDENTIFIER_BYTES: usize = 256;
/// NIP-30 shortcode length bound, shared with chat custom emoji.
pub const MAX_CUSTOM_EMOJI_SHORTCODE_BYTES: usize = 64;
const MAX_EMOJI_URL_BYTES: usize = 2048;
const MAX_TITLE_BYTES: usize = 256;
const MAX_DESCRIPTION_BYTES: usize = 2048;
/// Valid emoji kept per set; later valid entries are skipped as over the cap.
pub const MAX_EMOJI_PER_SET: usize = 500;
/// Skipped entries a set records individually; `skipped_count` counts all.
const MAX_RECORDED_SKIPS: usize = 64;
/// `a` pointers read from the user's kind-10030 list.
const MAX_USER_LIST_SET_POINTERS: usize = 64;
/// Bytes per emoji image.
pub const MAX_EMOJI_IMAGE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_INSTALLED_EMOJI_SETS: usize = 50;
/// Stored bytes per installed set.
pub const MAX_INSTALLED_EMOJI_SET_BYTES: u64 = 32 * 1024 * 1024;
/// Stored bytes across every installed set of the account.
pub const MAX_INSTALLED_EMOJI_BYTES: u64 = 128 * 1024 * 1024;
const EMOJI_DOWNLOAD_CONCURRENCY: usize = 4;
/// Relay reads in flight at once when resolving a user list's pointers.
const EMOJI_SET_READ_CONCURRENCY: usize = 4;
const MAX_FUTURE_EVENT_SKEW_SECONDS: u64 = 5 * 60;

/// Why an `emoji` entry was not offered or not installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppEmojiSkipReason {
    /// Not 1–64 bytes of ASCII letters, digits, `-` and `_`.
    InvalidShortcode,
    /// Missing, not HTTPS, credentials or a fragment, a non-public literal
    /// host, or refused by the dial policy before anything was fetched.
    InvalidUrl,
    /// A later entry with a shortcode the set already used.
    Duplicate,
    /// Past the per-set emoji cap or the stored-byte budget.
    OverCap,
    /// The image host could not be reached or answered with an error.
    DownloadFailed,
    /// Over 4 MiB, 4096 px per side, or 200 frames.
    TooLarge,
    /// Not PNG/APNG, GIF, WebP or JPEG, or malformed.
    UnsupportedImage,
    /// The response stated a type that is not an image type (such as
    /// `text/html`) for bytes that decode as an image.
    MimeMismatch,
}

impl AppEmojiSkipReason {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidShortcode => "invalid_shortcode",
            Self::InvalidUrl => "invalid_url",
            Self::Duplicate => "duplicate",
            Self::OverCap => "over_cap",
            Self::DownloadFailed => "download_failed",
            Self::TooLarge => "too_large",
            Self::UnsupportedImage => "unsupported_image",
            Self::MimeMismatch => "mime_mismatch",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        [
            Self::InvalidShortcode,
            Self::InvalidUrl,
            Self::Duplicate,
            Self::OverCap,
            Self::DownloadFailed,
            Self::TooLarge,
            Self::UnsupportedImage,
            Self::MimeMismatch,
        ]
        .into_iter()
        .find(|reason| reason.code() == code)
    }

    fn into_error(self) -> AppError {
        match self {
            Self::InvalidShortcode | Self::Duplicate => invalid("invalid emoji entry"),
            Self::InvalidUrl => invalid("emoji URL is not a public HTTPS URL"),
            Self::OverCap => AppError::EmojiSetLimit("emoji is over the set's cap".into()),
            Self::DownloadFailed => AppError::EmojiSetNetwork("emoji download failed".into()),
            Self::TooLarge => AppError::EmojiImageTooLarge("emoji image exceeds limits".into()),
            Self::UnsupportedImage => {
                AppError::EmojiImageUnsupported("emoji image format is unsupported".into())
            }
            Self::MimeMismatch => {
                AppError::EmojiImageUnsupported("emoji image was served as a non-image type".into())
            }
        }
    }
}

/// One skipped entry. Parse-time skips carry `position`, the entry's index
/// among the event's `emoji` tags; `shortcode` is present when it is valid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEmojiSkip {
    pub position: Option<u32>,
    pub shortcode: Option<String>,
    pub reason: AppEmojiSkipReason,
}

/// One valid entry of a discovered set. `url` is shown for disclosure only:
/// load its image through `fetch_emoji_set_asset`, which applies the dial
/// policy and the image limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEmojiSetEmoji {
    pub shortcode: String,
    pub url: String,
}

/// The installed snapshot of a set, when there is one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInstalledEmojiSetState {
    /// The version the snapshot pinned.
    pub event_id_hex: String,
    pub created_at: u64,
    pub installed_at: u64,
    pub emoji_count: u32,
    pub byte_len: u64,
    /// A different version than the snapshot is now known; reinstalling
    /// takes it.
    pub update_available: bool,
}

/// A discovered emoji set (kind 30030), or a user's kind-10030 list read as
/// the set of its loose emoji (`identifier` empty, `title` absent).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEmojiSet {
    pub coordinate: String,
    pub kind: u16,
    pub author_pubkey_hex: String,
    pub identifier: String,
    pub event_id_hex: String,
    pub created_at: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub emoji: Vec<AppEmojiSetEmoji>,
    /// At most 64 skipped entries; `skipped_count` counts all of them.
    pub skipped: Vec<AppEmojiSkip>,
    pub skipped_count: u32,
    pub installed: Option<AppInstalledEmojiSetState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEmojiSetSyncResult {
    /// Distinct sets with at least one valid emoji the fetch returned.
    pub discovered: u32,
    /// Sets stored or replaced by a newer version.
    pub updated: u32,
    /// Whether every relay answered in full.
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEmojiSetInstallResult {
    pub set: AppEmojiSet,
    pub installed_count: u32,
    /// Every entry not installed: the set's parse-time skips first, then
    /// install-time ones (downloads, validation, caps).
    pub skipped: Vec<AppEmojiSkip>,
}

/// The account's own kind-10030 emoji list, as suggestions. MDK never
/// publishes or edits this list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUserEmojiList {
    pub event_id_hex: Option<String>,
    pub created_at: Option<u64>,
    /// The list's loose emoji as an installable set, coordinate
    /// `10030:<pubkey>:`.
    pub own_emoji: Option<AppEmojiSet>,
    /// Sets the list points to that relays returned with a valid emoji.
    pub sets: Vec<AppEmojiSet>,
    /// Valid pointers no relay returned a set for.
    pub missing_set_coordinates: Vec<String>,
    /// Whether every relay answered the list read and every set read in
    /// full. When false, a missing set may still exist.
    pub complete: bool,
}

/// One emoji's validated image fetched for a preview. Not stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEmojiSetAsset {
    pub set_coordinate: String,
    pub shortcode: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// A set's validated cover image (its `image` tag) fetched for display. Not
/// stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppEmojiSetCover {
    pub set_coordinate: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// Progress of one install, read from its [`EmojiSetInstallControl`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmojiSetInstallProgress {
    /// Entries finished so far: stored, skipped or given up on.
    pub completed_emoji: u32,
    /// Entries the install will try: the version's valid emoji. Zero until
    /// the install has read the stored version.
    pub total_emoji: u32,
    /// Response bytes received from image hosts, valid or not, counted as
    /// each download finishes.
    pub transferred_bytes: u64,
}

/// Cancellation and progress for one `install_emoji_set` call. Create one
/// per install. A cancelled install stops starting downloads, drops the ones
/// in flight, stores nothing and fails with `EmojiSetInstallCancelled`; a
/// reinstall leaves the previous snapshot as it was. The final storage write
/// is atomic and not interruptible: a cancellation that arrives once it has
/// started is too late, and the install succeeds.
#[derive(Debug, Default)]
pub struct EmojiSetInstallControl {
    cancelled: tokio_util::sync::CancellationToken,
    completed_emoji: AtomicU32,
    total_emoji: AtomicU32,
    transferred_bytes: AtomicU64,
}

impl EmojiSetInstallControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.is_cancelled()
    }

    pub fn progress(&self) -> EmojiSetInstallProgress {
        EmojiSetInstallProgress {
            completed_emoji: self.completed_emoji.load(Ordering::Acquire),
            total_emoji: self.total_emoji.load(Ordering::Acquire),
            transferred_bytes: self.transferred_bytes.load(Ordering::Acquire),
        }
    }

    fn start(&self, total: usize) {
        self.total_emoji
            .store(total.try_into().unwrap_or(u32::MAX), Ordering::Release);
    }

    fn finish_entries(&self, count: usize, transferred: u64) {
        self.transferred_bytes
            .fetch_add(transferred, Ordering::AcqRel);
        self.completed_emoji
            .fetch_add(count.try_into().unwrap_or(u32::MAX), Ordering::AcqRel);
    }
}

/// One installed emoji for a picker. Shortcodes may repeat across sets;
/// MDK does not choose between them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInstalledCustomEmoji {
    pub set_coordinate: String,
    pub set_title: Option<String>,
    pub author_pubkey_hex: String,
    pub shortcode: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub sha256: String,
    pub byte_len: u64,
    /// Another installed set also has this exact shortcode.
    pub shortcode_collision: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInstalledCustomEmojiAsset {
    pub emoji: AppInstalledCustomEmoji,
    pub bytes: Vec<u8>,
}

/// NIP-30 shortcode: 1–64 bytes of ASCII letters, digits, `-` and `_`. The
/// same rule decides whether a chat message's `emoji` tag names an inline
/// custom emoji.
pub(crate) fn is_custom_emoji_shortcode(shortcode: &str) -> bool {
    !shortcode.is_empty()
        && shortcode.len() <= MAX_CUSTOM_EMOJI_SHORTCODE_BYTES
        && shortcode
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EmojiSetAddress {
    kind: u16,
    author_pubkey_hex: String,
    identifier: String,
}

impl EmojiSetAddress {
    fn new(kind: u16, author_pubkey_hex: &str, identifier: String) -> Result<Self, AppError> {
        let author = PublicKey::from_hex(author_pubkey_hex)
            .map_err(|_| invalid("emoji set author is invalid"))?;
        let valid = match kind {
            EMOJI_SET_KIND => identifier.len() <= MAX_IDENTIFIER_BYTES,
            USER_EMOJI_LIST_KIND => identifier.is_empty(),
            _ => return Err(invalid("address is not an emoji set")),
        };
        if !valid {
            return Err(invalid("emoji set identifier is invalid"));
        }
        Ok(Self {
            kind,
            author_pubkey_hex: author.to_hex(),
            identifier,
        })
    }

    fn parse_coordinate(input: &str) -> Option<Result<Self, AppError>> {
        let mut parts = input.splitn(3, ':');
        let kind = parts.next()?.parse::<u16>().ok()?;
        let author = parts.next()?;
        let identifier = parts.next()?;
        if author.len() != 64 || !author.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self::new(kind, author, identifier.to_owned()))
    }

    fn coordinate(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind, self.author_pubkey_hex, self.identifier
        )
    }

    fn filter(&self) -> Result<Filter, AppError> {
        let author = PublicKey::from_hex(&self.author_pubkey_hex)
            .map_err(|_| invalid("emoji set author is invalid"))?;
        let filter = Filter::new()
            .author(author)
            .kind(Kind::Custom(self.kind))
            .limit(MAX_REPLACEABLE_VERSIONS_PER_FETCH);
        Ok(if self.kind == EMOJI_SET_KIND {
            filter.custom_tag(SingleLetterTag::LOWERCASE_D, self.identifier.clone())
        } else {
            filter
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedEmojiSetInput {
    address: EmojiSetAddress,
    relay_hints: Vec<TransportEndpoint>,
}

/// Normalize a pasted emoji set address to its coordinate: a coordinate
/// (`30030:<hex pubkey>:<d>` or `10030:<hex pubkey>:`), or an NIP-19
/// `naddr` with or without `nostr:`.
pub fn parse_emoji_set_input(input: &str) -> Result<String, AppError> {
    parse_input_with_relays(input).map(|parsed| parsed.address.coordinate())
}

fn parse_input_with_relays(input: &str) -> Result<ParsedEmojiSetInput, AppError> {
    let input = input.trim();
    if input.is_empty() || input.chars().count() > MAX_INPUT_CHARS {
        return Err(invalid("invalid emoji set address"));
    }
    if let Some(address) = EmojiSetAddress::parse_coordinate(input) {
        return Ok(ParsedEmojiSetInput {
            address: address?,
            relay_hints: Vec::new(),
        });
    }
    let bech32 = input.strip_prefix("nostr:").unwrap_or(input);
    if !bech32.starts_with("naddr1") {
        return Err(invalid("invalid emoji set address"));
    }
    let nip19 =
        Nip19Coordinate::from_bech32(bech32).map_err(|_| invalid("invalid emoji set address"))?;
    let address = EmojiSetAddress::new(
        nip19.coordinate.kind.as_u16(),
        &nip19.coordinate.public_key.to_hex(),
        nip19.coordinate.identifier.clone(),
    )?;
    Ok(ParsedEmojiSetInput {
        address,
        relay_hints: normalize_relay_hints(nip19.relays.iter().map(ToString::to_string)),
    })
}

fn normalize_relay_hints(relays: impl IntoIterator<Item = String>) -> Vec<TransportEndpoint> {
    let mut normalized = Vec::new();
    for relay in relays {
        if normalized.len() >= MAX_EMOJI_SET_RELAY_HINTS {
            break;
        }
        let Ok(relay) = RelayUrl::parse(relay.trim()) else {
            continue;
        };
        let endpoint = TransportEndpoint(relay.to_string());
        if !normalized.contains(&endpoint) {
            normalized.push(endpoint);
        }
    }
    normalized
}

/// An HTTPS URL with no credentials or fragment whose literal host, if any,
/// is public. Hostnames are resolved and pinned to public addresses only
/// when an image is fetched.
fn validate_emoji_url(raw: &str, allow_loopback_http: bool) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_EMOJI_URL_BYTES || raw.trim() != raw {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    validate_blossom_fetch_url(&url, allow_loopback_http).ok()?;
    Some(url.to_string())
}

fn bounded_text(value: Option<&String>, max_bytes: usize, multiline: bool) -> Option<String> {
    let value = value?.trim();
    let allowed = |character: char| !character.is_control() || (multiline && character == '\n');
    (!value.is_empty() && value.len() <= max_bytes && value.chars().all(allowed))
        .then(|| value.to_owned())
}

struct SkipLog {
    recorded: Vec<StoredEmojiSkip>,
    count: u32,
}

impl SkipLog {
    fn push(&mut self, position: u32, shortcode: Option<&str>, reason: AppEmojiSkipReason) {
        self.count = self.count.saturating_add(1);
        if self.recorded.len() < MAX_RECORDED_SKIPS {
            self.recorded.push(StoredEmojiSkip {
                position,
                shortcode: shortcode.map(str::to_owned),
                reason: reason.code().to_owned(),
            });
        }
    }
}

/// Validate a kind-30030 set or kind-10030 list into the stored projection.
/// Invalid entries are dropped and recorded; a set left with no valid emoji
/// is refused, so discovery hides it.
fn stored_set_from_event(
    event: &Event,
    allow_loopback_http: bool,
) -> Result<StoredEmojiSet, AppError> {
    let kind = event.kind.as_u16();
    if kind != EMOJI_SET_KIND && kind != USER_EMOJI_LIST_KIND {
        return Err(invalid("event is not an emoji set"));
    }
    event
        .verify()
        .map_err(|_| invalid("emoji set signature verification failed"))?;
    if event.created_at.as_secs() > unix_now_seconds().saturating_add(MAX_FUTURE_EVENT_SKEW_SECONDS)
    {
        return Err(invalid("emoji set timestamp is too far in the future"));
    }
    let mut identifier = None;
    let mut title = None;
    let mut description = None;
    let mut image = None;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut skips = SkipLog {
        recorded: Vec::new(),
        count: 0,
    };
    let mut position = 0_u32;
    for tag in event.tags.iter() {
        let values = tag.as_slice();
        match values.first().map(String::as_str) {
            Some("d") => {
                identifier.get_or_insert_with(|| values.get(1).cloned().unwrap_or_default());
            }
            Some("title") => {
                title.get_or_insert_with(|| bounded_text(values.get(1), MAX_TITLE_BYTES, false));
            }
            Some("description") => {
                description.get_or_insert_with(|| {
                    bounded_text(values.get(1), MAX_DESCRIPTION_BYTES, true)
                });
            }
            Some("image") => {
                image.get_or_insert_with(|| {
                    values
                        .get(1)
                        .and_then(|url| validate_emoji_url(url, allow_loopback_http))
                });
            }
            Some("emoji") => {
                let index = position;
                position = position.saturating_add(1);
                let shortcode = values
                    .get(1)
                    .map(String::as_str)
                    .filter(|shortcode| is_custom_emoji_shortcode(shortcode));
                let Some(shortcode) = shortcode else {
                    skips.push(index, None, AppEmojiSkipReason::InvalidShortcode);
                    continue;
                };
                let Some(url) = values
                    .get(2)
                    .and_then(|url| validate_emoji_url(url, allow_loopback_http))
                else {
                    skips.push(index, Some(shortcode), AppEmojiSkipReason::InvalidUrl);
                    continue;
                };
                if !seen.insert(shortcode.to_owned()) {
                    skips.push(index, Some(shortcode), AppEmojiSkipReason::Duplicate);
                    continue;
                }
                if entries.len() >= MAX_EMOJI_PER_SET {
                    skips.push(index, Some(shortcode), AppEmojiSkipReason::OverCap);
                    continue;
                }
                entries.push(StoredEmojiSetEntry {
                    shortcode: shortcode.to_owned(),
                    url,
                });
            }
            _ => {}
        }
    }
    // A version with no valid emoji is still kept: it must supersede older
    // versions under replacement ordering. Listings hide it, and fetch and
    // install refuse it.
    let identifier = if kind == EMOJI_SET_KIND {
        identifier.unwrap_or_default()
    } else {
        String::new()
    };
    let address = EmojiSetAddress::new(kind, &event.pubkey.to_hex(), identifier)?;
    Ok(StoredEmojiSet {
        coordinate: address.coordinate(),
        kind,
        author_pubkey_hex: address.author_pubkey_hex,
        identifier: address.identifier,
        version: StoredEmojiSetVersion {
            event_id_hex: event.id.to_hex(),
            created_at: event.created_at.as_secs(),
        },
        title: title.flatten(),
        description: description.flatten(),
        image_url: image.flatten(),
        emoji: entries,
        skipped: skips.recorded,
        skipped_count: skips.count,
    })
}

/// A validated image: size, format, dimensions and frames within limits, and
/// served as an image type (or with no type, or a generic binary one).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedEmojiImage {
    mime: &'static str,
    width: u32,
    height: u32,
    frames: u32,
    sha256: String,
    bytes: Vec<u8>,
}

fn validate_emoji_image(
    bytes: Vec<u8>,
    stated_mime: Option<&str>,
) -> Result<ValidatedEmojiImage, AppEmojiSkipReason> {
    if bytes.is_empty() {
        return Err(AppEmojiSkipReason::UnsupportedImage);
    }
    if bytes.len() as u64 > MAX_EMOJI_IMAGE_BYTES {
        return Err(AppEmojiSkipReason::TooLarge);
    }
    let inspected = image_inspect::inspect_image(&bytes).map_err(|rejection| match rejection {
        ImageRejection::ExceedsLimits(_) => AppEmojiSkipReason::TooLarge,
        ImageRejection::Unsupported(_) | ImageRejection::Malformed(_) => {
            AppEmojiSkipReason::UnsupportedImage
        }
    })?;
    if !stated_mime_allows_image(stated_mime) {
        return Err(AppEmojiSkipReason::MimeMismatch);
    }
    Ok(ValidatedEmojiImage {
        mime: inspected.mime,
        width: inspected.width,
        height: inspected.height,
        frames: inspected.frames,
        sha256: hex::encode(Sha256::digest(&bytes)),
        bytes,
    })
}

/// Whether the response's stated type lets the bytes be used as an image.
/// The bytes decide the format: `inspect_image` has already parsed their
/// header, and the stored MIME type comes from it, never from the server.
/// No type, a generic binary type, or any `image/*` type (servers commonly
/// label a GIF or WebP `image/png`) defers to them. A stated non-image type
/// such as `text/html` is refused, so a document that also parses as an
/// image is not installed.
fn stated_mime_allows_image(stated: Option<&str>) -> bool {
    match stated {
        None | Some("application/octet-stream" | "binary/octet-stream") => true,
        Some(stated) => stated
            .strip_prefix("image/")
            .is_some_and(|subtype| !subtype.is_empty()),
    }
}

struct EmojiAccountContext {
    label: String,
    account_id_hex: String,
    storage: SqliteAppStorage,
    endpoints: Vec<TransportEndpoint>,
}

impl MarmotApp {
    /// Discovered (or, with `installed_only`, installed) sets from local
    /// storage. `search` matches title, description, author (hex or `npub`)
    /// and shortcodes. No network; the read runs on the blocking pool.
    pub async fn emoji_sets(
        &self,
        account_ref: &str,
        installed_only: bool,
        search: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<AppEmojiSet>, AppError> {
        let storage = self.emoji_storage(account_ref)?;
        let search = search.map(normalize_search);
        let limit = limit.unwrap_or(50);
        read_blocking(move || {
            let installed = installed_states(&storage)?;
            storage
                .emoji_sets(installed_only, search.as_deref(), limit)?
                .into_iter()
                .map(|set| app_set(set, &installed))
                .collect()
        })
        .await
    }

    /// One stored set by coordinate or `naddr`. No network; the read runs on
    /// the blocking pool.
    pub async fn emoji_set(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<Option<AppEmojiSet>, AppError> {
        let coordinate = parse_emoji_set_input(input)?;
        let storage = self.emoji_storage(account_ref)?;
        read_blocking(move || {
            let installed = installed_states(&storage)?;
            storage
                .emoji_set(&coordinate)?
                .map(|set| app_set(set, &installed))
                .transpose()
        })
        .await
    }

    /// Fetch the newest kind-30030 sets from the account's relays (the ones
    /// sticker discovery uses), keeping only the newest version of each
    /// address. Text only: never fetches an image. A `search` that is an
    /// `npub` or hex public key narrows the fetch to that author; other text
    /// is matched locally by [`MarmotApp::emoji_sets`].
    pub async fn sync_emoji_sets(
        &self,
        account_ref: &str,
        search: Option<&str>,
    ) -> Result<AppEmojiSetSyncResult, AppError> {
        let context = self.emoji_context(account_ref)?;
        let lock = self.emoji_set_mutation_lock(&context.label);
        let _guard = lock.lock().await;
        let mut filter = Filter::new()
            .kind(Kind::Custom(EMOJI_SET_KIND))
            .limit(MAX_DISCOVERY_EMOJI_SETS);
        if let Some(author) = search.and_then(author_search) {
            filter = filter.author(author);
        }
        let fetched = self
            .relay_plane
            .fetch_public_events(
                context.endpoints.clone(),
                vec![filter],
                MAX_DISCOVERY_EMOJI_SETS * 2,
            )
            .await
            .map_err(|_| AppError::EmojiSetNetwork("emoji set discovery failed".into()))?;
        let (discovered, updated) = ingest_discovered_sets(
            &context.storage,
            fetched.events,
            self.allow_loopback_blob_endpoints(),
        )?;
        context
            .storage
            .prune_uninstalled_emoji_sets(MAX_STORED_EMOJI_SETS, &[])?;
        Ok(AppEmojiSetSyncResult {
            discovered: discovered.try_into().unwrap_or(u32::MAX),
            updated: updated.try_into().unwrap_or(u32::MAX),
            complete: fetched.complete,
        })
    }

    /// Fetch one set by coordinate or `naddr` (its relay hints, at most 8,
    /// are tried as well as the account's relays). Text only.
    pub async fn fetch_emoji_set(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<AppEmojiSet, AppError> {
        let parsed = parse_input_with_relays(input)?;
        let context = self.emoji_context(account_ref)?;
        let lock = self.emoji_set_mutation_lock(&context.label);
        let _guard = lock.lock().await;
        let coordinate = parsed.address.coordinate();
        self.fetch_set_into_storage(&context, &parsed.address, &parsed.relay_hints)
            .await?;
        context.storage.prune_uninstalled_emoji_sets(
            MAX_STORED_EMOJI_SETS,
            std::slice::from_ref(&coordinate),
        )?;
        let set = stored_app_set(&context.storage, &coordinate)?;
        if set.emoji.is_empty() {
            return Err(no_valid_emoji());
        }
        Ok(set)
    }

    /// Read the account's own kind-10030 emoji list and the sets it points
    /// to, as suggestions to install. Text only. Never publishes or edits
    /// the list: it is public and shared with other Nostr clients.
    pub async fn user_emoji_list(&self, account_ref: &str) -> Result<AppUserEmojiList, AppError> {
        let context = self.emoji_context(account_ref)?;
        let lock = self.emoji_set_mutation_lock(&context.label);
        let _guard = lock.lock().await;
        let allow_loopback = self.allow_loopback_blob_endpoints();
        let author = PublicKey::from_hex(&context.account_id_hex)
            .map_err(|_| invalid("invalid account identity"))?;
        let fetched = self
            .relay_plane
            .fetch_public_events(
                context.endpoints.clone(),
                vec![
                    Filter::new()
                        .author(author)
                        .kind(Kind::Custom(USER_EMOJI_LIST_KIND))
                        .limit(MAX_REPLACEABLE_VERSIONS_PER_FETCH),
                ],
                MAX_REPLACEABLE_VERSIONS_PER_FETCH.saturating_mul(context.endpoints.len().max(1)),
            )
            .await
            .map_err(|_| AppError::EmojiSetNetwork("emoji list read failed".into()))?;
        let mut lists = fetched
            .events
            .into_iter()
            .filter(|event| {
                event.pubkey == author
                    && event.kind == Kind::Custom(USER_EMOJI_LIST_KIND)
                    && event.verify().is_ok()
                    && event.created_at.as_secs()
                        <= unix_now_seconds().saturating_add(MAX_FUTURE_EVENT_SKEW_SECONDS)
            })
            .collect::<Vec<_>>();
        lists.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        let Some(list) = lists.into_iter().next() else {
            return Ok(AppUserEmojiList {
                event_id_hex: None,
                created_at: None,
                own_emoji: None,
                sets: Vec::new(),
                missing_set_coordinates: Vec::new(),
                complete: fetched.complete,
            });
        };
        let own_coordinate = match stored_set_from_event(&list, allow_loopback) {
            Ok(own) => {
                context.storage.replace_emoji_set_if_newer(&own)?;
                Some(own.coordinate)
            }
            Err(_) => None,
        };
        let pointers = list_set_pointers(&list);
        let sets_complete = self
            .fetch_pointed_sets(&context, &pointers, allow_loopback)
            .await?;
        let mut keep = pointers
            .iter()
            .map(EmojiSetAddress::coordinate)
            .collect::<Vec<_>>();
        keep.extend(own_coordinate.clone());
        context
            .storage
            .prune_uninstalled_emoji_sets(MAX_STORED_EMOJI_SETS, &keep)?;
        let installed = installed_states(&context.storage)?;
        let own_emoji = own_coordinate
            .map(|coordinate| context.storage.emoji_set(&coordinate))
            .transpose()?
            .flatten()
            .filter(|set| !set.emoji.is_empty())
            .map(|set| app_set(set, &installed))
            .transpose()?;
        let mut sets = Vec::new();
        let mut missing_set_coordinates = Vec::new();
        for coordinate in keep.iter().take(pointers.len()) {
            match context.storage.emoji_set(coordinate)? {
                // Hidden like in discovery: nothing in it can be installed.
                Some(set) if set.emoji.is_empty() => {}
                Some(set) => sets.push(app_set(set, &installed)?),
                None => missing_set_coordinates.push(coordinate.clone()),
            }
        }
        Ok(AppUserEmojiList {
            event_id_hex: Some(list.id.to_hex()),
            created_at: Some(list.created_at.as_secs()),
            own_emoji,
            sets,
            missing_set_coordinates,
            complete: fetched.complete && sets_complete,
        })
    }

    /// Download one emoji of a stored set for a preview, validated but not
    /// stored. This reveals the user's IP address to the image host the set
    /// author chose: call it only after the user opens the set, passing the
    /// event id of the version shown. Another stored version fails with
    /// `EmojiSetChanged` before anything is fetched.
    pub async fn fetch_emoji_set_asset(
        &self,
        account_ref: &str,
        coordinate: &str,
        expected_event_id_hex: &str,
        shortcode: &str,
    ) -> Result<AppEmojiSetAsset, AppError> {
        let coordinate = parse_emoji_set_input(coordinate)?;
        let storage = self.emoji_storage(account_ref)?;
        let set = shown_version(&storage, &coordinate, expected_event_id_hex)?;
        let entry = set
            .emoji
            .into_iter()
            .find(|entry| entry.shortcode == shortcode)
            .ok_or(AppError::EmojiSetNotFound)?;
        let image = self
            .download_emoji(&entry.url)
            .await
            .0
            .map_err(AppEmojiSkipReason::into_error)?;
        Ok(AppEmojiSetAsset {
            set_coordinate: coordinate,
            shortcode: entry.shortcode,
            mime: image.mime.to_owned(),
            width: image.width,
            height: image.height,
            frames: image.frames,
            sha256: image.sha256,
            bytes: image.bytes,
        })
    }

    /// Download a stored set's cover image (its `image` tag), validated
    /// under the emoji image limits but not stored. Like
    /// [`Self::fetch_emoji_set_asset`] it reveals the user's IP address to
    /// the host the set author chose: call it only after the user opens the
    /// set, with the event id of the version shown. A set without a cover
    /// fails with `EmojiSetNotFound`.
    pub async fn fetch_emoji_set_cover(
        &self,
        account_ref: &str,
        coordinate: &str,
        expected_event_id_hex: &str,
    ) -> Result<AppEmojiSetCover, AppError> {
        let coordinate = parse_emoji_set_input(coordinate)?;
        let storage = self.emoji_storage(account_ref)?;
        let url = shown_version(&storage, &coordinate, expected_event_id_hex)?
            .image_url
            .ok_or(AppError::EmojiSetNotFound)?;
        let image = self
            .download_emoji(&url)
            .await
            .0
            .map_err(AppEmojiSkipReason::into_error)?;
        Ok(AppEmojiSetCover {
            set_coordinate: coordinate,
            mime: image.mime.to_owned(),
            width: image.width,
            height: image.height,
            frames: image.frames,
            sha256: image.sha256,
            bytes: image.bytes,
        })
    }

    /// Install the stored version of a set: download every emoji once,
    /// validate it and store its bytes and SHA-256 under the account,
    /// replacing any earlier snapshot of the same set. Entries that are
    /// invalid, duplicated, fail to download or validate, or go over a cap
    /// are reported, not fatal. This reveals the user's IP address to every
    /// image host in the set.
    ///
    /// `expected_event_id_hex` is the version the user was shown. When the
    /// stored version is another one (a sync or fetch replaced it), the call
    /// fails with `EmojiSetChanged` before any download; with nothing stored
    /// it fails with `EmojiSetNotFound` and never fetches the set itself.
    /// `control` reports progress and cancels; see
    /// [`EmojiSetInstallControl`]. Runtime shutdown or storage close cancels
    /// the install the same way.
    pub async fn install_emoji_set(
        &self,
        account_ref: &str,
        coordinate: &str,
        expected_event_id_hex: &str,
        control: &EmojiSetInstallControl,
    ) -> Result<AppEmojiSetInstallResult, AppError> {
        let coordinate = parse_emoji_set_input(coordinate)?;
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?.app_storage();
        let lock = self.emoji_set_mutation_lock(&account.label);
        let stop = self.emoji_install_stopped(control);
        tokio::pin!(stop);
        // Owned so the write below can keep it if this call is cancelled.
        let guard = tokio::select! {
            biased;
            () = &mut stop => return Err(AppError::EmojiSetInstallCancelled),
            guard = lock.lock_owned() => guard,
        };
        let set = shown_version(&storage, &coordinate, expected_event_id_hex)?;
        if set.emoji.is_empty() {
            return Err(no_valid_emoji());
        }
        let installed_sets = storage.installed_emoji_sets()?;
        if installed_sets.len() >= MAX_INSTALLED_EMOJI_SETS
            && !installed_sets
                .iter()
                .any(|installed| installed.coordinate == coordinate)
        {
            return Err(AppError::EmojiSetLimit(
                "too many installed emoji sets".into(),
            ));
        }
        let budget = MAX_INSTALLED_EMOJI_SET_BYTES.min(
            MAX_INSTALLED_EMOJI_BYTES
                .saturating_sub(storage.installed_emoji_bytes_excluding(&coordinate)?),
        );
        if budget == 0 {
            return Err(AppError::EmojiSetLimit(
                "installed emoji storage is full".into(),
            ));
        }
        let mut skipped = parse_skips(&set.skipped);
        control.start(set.emoji.len());
        let (kept, install_skips) = tokio::select! {
            biased;
            () = &mut stop => return Err(AppError::EmojiSetInstallCancelled),
            downloaded = self.download_set(&set.emoji, budget, control) => downloaded,
        };
        if kept.is_empty() {
            return Err(nothing_installed_error(&install_skips));
        }
        skipped.extend(install_skips);
        let snapshot = StoredInstalledEmojiSet {
            coordinate: coordinate.clone(),
            kind: set.kind,
            author_pubkey_hex: set.author_pubkey_hex.clone(),
            identifier: set.identifier.clone(),
            version: set.version.clone(),
            title: set.title.clone(),
            description: set.description.clone(),
            installed_at: unix_now_seconds(),
            emoji_count: 0,
            byte_len: 0,
        };
        let installed_count = kept.len().try_into().unwrap_or(u32::MAX);
        let writer = storage.clone();
        // The last point a cancellation or shutdown can stop the install.
        if control.is_cancelled() || self.emoji_install_stop.is_cancelled() {
            return Err(AppError::EmojiSetInstallCancelled);
        }
        let outcome = write_holding_guard(guard, move || {
            writer.install_emoji_set(
                &snapshot,
                &kept,
                EmojiSetInstallLimits {
                    max_sets: MAX_INSTALLED_EMOJI_SETS,
                    max_total_bytes: MAX_INSTALLED_EMOJI_BYTES,
                },
            )
        })
        .await??;
        match outcome {
            EmojiSetInstallOutcome::Installed => {}
            EmojiSetInstallOutcome::TooManySets => {
                return Err(AppError::EmojiSetLimit(
                    "too many installed emoji sets".into(),
                ));
            }
            EmojiSetInstallOutcome::OverByteBudget => {
                return Err(AppError::EmojiSetLimit(
                    "installed emoji storage is full".into(),
                ));
            }
        }
        Ok(AppEmojiSetInstallResult {
            set: stored_app_set(&storage, &coordinate)?,
            installed_count,
            skipped,
        })
    }

    /// Remove an installed set and every emoji byte stored for it. Returns
    /// whether it was installed. No network.
    pub async fn uninstall_emoji_set(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<bool, AppError> {
        let coordinate = parse_emoji_set_input(input)?;
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?.app_storage();
        let lock = self.emoji_set_mutation_lock(&account.label);
        let _guard = lock.lock().await;
        Ok(storage.uninstall_emoji_set(&coordinate)?)
    }

    /// Every installed emoji, flattened in set install order then each set's
    /// own order, for a picker. Shortcode collisions between sets are
    /// reported, not resolved. No network; the read runs on the blocking
    /// pool.
    pub async fn installed_custom_emoji(
        &self,
        account_ref: &str,
    ) -> Result<Vec<AppInstalledCustomEmoji>, AppError> {
        let storage = self.emoji_storage(account_ref)?;
        read_blocking(move || {
            let rows = storage.installed_custom_emoji()?;
            let collisions = colliding_shortcodes(&rows);
            Ok(rows
                .into_iter()
                .map(|row| app_installed_emoji(row, &collisions))
                .collect())
        })
        .await
    }

    /// An installed emoji's stored bytes, checked against their stored
    /// SHA-256. No network; the read and the hash run on the blocking pool.
    pub async fn read_installed_custom_emoji(
        &self,
        account_ref: &str,
        coordinate: &str,
        shortcode: &str,
    ) -> Result<AppInstalledCustomEmojiAsset, AppError> {
        let coordinate = parse_emoji_set_input(coordinate)?;
        let storage = self.emoji_storage(account_ref)?;
        let shortcode = shortcode.to_owned();
        read_blocking(move || {
            let (row, bytes) = storage
                .installed_custom_emoji_bytes(&coordinate, &shortcode)?
                .ok_or(AppError::EmojiSetNotFound)?;
            let collisions = colliding_shortcodes(&storage.installed_custom_emoji()?);
            Ok(AppInstalledCustomEmojiAsset {
                emoji: app_installed_emoji(row, &collisions),
                bytes,
            })
        })
        .await
    }

    /// Fetch and validate one emoji image. Also returns the bytes the fetch
    /// may have transferred, validated or not: a body over the image cap is
    /// charged at the cap, since the stream stops just past it.
    async fn download_emoji(
        &self,
        url: &str,
    ) -> (Result<ValidatedEmojiImage, AppEmojiSkipReason>, u64) {
        match fetch_public_image_limited(
            url,
            MAX_EMOJI_IMAGE_BYTES,
            self.allow_loopback_blob_endpoints(),
        )
        .await
        {
            Ok((bytes, stated_mime)) => {
                let transferred = bytes.len() as u64;
                (
                    validate_emoji_image(bytes, stated_mime.as_deref()),
                    transferred,
                )
            }
            Err(PublicImageFetchError::TooLarge) => {
                (Err(AppEmojiSkipReason::TooLarge), MAX_EMOJI_IMAGE_BYTES)
            }
            Err(PublicImageFetchError::Refused) => (Err(AppEmojiSkipReason::InvalidUrl), 0),
            Err(PublicImageFetchError::Failed) => (Err(AppEmojiSkipReason::DownloadFailed), 0),
        }
    }

    /// Download a set's emoji in order, a few at a time, keeping those that
    /// validate and still fit `budget`; one that does not fit is skipped and
    /// later, smaller ones are still tried. Once the bytes transferred,
    /// valid or not, reach twice the budget, the rest are skipped without
    /// being fetched (beyond the few already in flight). Each finished entry
    /// advances `control`'s progress; cancellation is the caller's to race.
    async fn download_set(
        &self,
        entries: &[StoredEmojiSetEntry],
        budget: u64,
        control: &EmojiSetInstallControl,
    ) -> (Vec<(StoredInstalledEmoji, Vec<u8>)>, Vec<AppEmojiSkip>) {
        let mut kept = Vec::new();
        let mut skipped = Vec::new();
        let mut used = 0_u64;
        let mut fetched = 0_u64;
        // Owned inputs keep the stream's closure free of higher-ranked
        // borrows, which the FFI's `Send` future bound cannot prove.
        let urls: Vec<(usize, String)> = entries
            .iter()
            .map(|entry| entry.url.clone())
            .enumerate()
            .collect();
        let mut downloads = futures::stream::iter(urls)
            .map(|(index, url)| async move { (index, self.download_emoji(&url).await) })
            .buffered(EMOJI_DOWNLOAD_CONCURRENCY);
        let mut done = 0_usize;
        while let Some((index, (result, transferred))) = downloads.next().await {
            done += 1;
            fetched = fetched.saturating_add(transferred);
            control.finish_entries(1, transferred);
            let entry = &entries[index];
            let skip = |reason| AppEmojiSkip {
                position: None,
                shortcode: Some(entry.shortcode.clone()),
                reason,
            };
            match result {
                Ok(image) => {
                    let len = image.bytes.len() as u64;
                    if used.saturating_add(len) > budget {
                        skipped.push(skip(AppEmojiSkipReason::OverCap));
                    } else {
                        used += len;
                        kept.push((
                            StoredInstalledEmoji {
                                shortcode: entry.shortcode.clone(),
                                sha256: image.sha256,
                                mime: image.mime.to_owned(),
                                width: image.width,
                                height: image.height,
                                frames: image.frames,
                                byte_len: len,
                            },
                            image.bytes,
                        ));
                    }
                }
                Err(reason) => skipped.push(skip(reason)),
            }
            if fetched >= budget.saturating_mul(2) {
                break;
            }
        }
        drop(downloads);
        control.finish_entries(entries.len().saturating_sub(done), 0);
        skipped.extend(entries.iter().skip(done).map(|entry| AppEmojiSkip {
            position: None,
            shortcode: Some(entry.shortcode.clone()),
            reason: AppEmojiSkipReason::OverCap,
        }));
        (kept, skipped)
    }

    async fn fetch_set_into_storage(
        &self,
        context: &EmojiAccountContext,
        address: &EmojiSetAddress,
        relay_hints: &[TransportEndpoint],
    ) -> Result<(), AppError> {
        let coordinate = address.coordinate();
        let filter = address.filter()?;
        // Hints only add candidates: every version passes NIP-01 replacement
        // ordering, so an old version on a hint relay cannot hide a newer one.
        let mut found = false;
        if !relay_hints.is_empty() {
            match self
                .fetch_set_versions(context, &coordinate, relay_hints.to_vec(), filter.clone())
                .await
            {
                Ok(hinted) => found = hinted,
                Err(AppError::EmojiSetNetwork(_)) => {}
                Err(error) => return Err(error),
            }
        }
        match self
            .fetch_set_versions(context, &coordinate, context.endpoints.clone(), filter)
            .await
        {
            Ok(_) => {}
            Err(AppError::EmojiSetNetwork(_)) if found => {}
            Err(error) => return Err(error),
        }
        if context.storage.emoji_set(&coordinate)?.is_none() {
            return Err(AppError::EmojiSetNotFound);
        }
        Ok(())
    }

    async fn fetch_set_versions(
        &self,
        context: &EmojiAccountContext,
        coordinate: &str,
        endpoints: Vec<TransportEndpoint>,
        filter: Filter,
    ) -> Result<bool, AppError> {
        let events = self
            .relay_plane
            .fetch_public_events(endpoints, vec![filter], MAX_REPLACEABLE_VERSIONS_PER_FETCH)
            .await
            .map_err(|_| AppError::EmojiSetNetwork("emoji set fetch failed".into()))?
            .events;
        let mut found = false;
        for event in events {
            match stored_set_from_event(&event, self.allow_loopback_blob_endpoints()) {
                Ok(set) if set.coordinate == coordinate => {
                    found = true;
                    context.storage.replace_emoji_set_if_newer(&set)?;
                }
                _ => {}
            }
        }
        Ok(found)
    }

    /// Fetch every set a kind-10030 list points to: one exact filter per
    /// author (that author and only the identifiers the list names for
    /// them), one filter per request because relays bound filters per
    /// request, a few requests at a time. Returns whether every read
    /// completed; a failed, truncated or full read leaves its sets
    /// unresolved rather than failing the list.
    async fn fetch_pointed_sets(
        &self,
        context: &EmojiAccountContext,
        pointers: &[EmojiSetAddress],
        allow_loopback: bool,
    ) -> Result<bool, AppError> {
        let wanted = pointers
            .iter()
            .map(EmojiSetAddress::coordinate)
            .collect::<HashSet<_>>();
        let mut by_author: Vec<(PublicKey, Vec<String>)> = Vec::new();
        for pointer in pointers {
            let Ok(author) = PublicKey::from_hex(&pointer.author_pubkey_hex) else {
                continue;
            };
            match by_author.iter_mut().find(|(known, _)| *known == author) {
                Some((_, identifiers)) => identifiers.push(pointer.identifier.clone()),
                None => by_author.push((author, vec![pointer.identifier.clone()])),
            }
        }
        let endpoints = context.endpoints.clone();
        let mut reads = futures::stream::iter(by_author)
            .map(|(author, identifiers)| {
                let endpoints = endpoints.clone();
                let limit = identifiers.len() * MAX_REPLACEABLE_VERSIONS_PER_FETCH;
                let filter = Filter::new()
                    .kind(Kind::Custom(EMOJI_SET_KIND))
                    .author(author)
                    .custom_tags(SingleLetterTag::LOWERCASE_D, identifiers)
                    .limit(limit);
                async move {
                    let read = self
                        .relay_plane
                        .fetch_public_events(endpoints, vec![filter], limit)
                        .await;
                    (read, limit)
                }
            })
            .buffer_unordered(EMOJI_SET_READ_CONCURRENCY);
        let mut complete = true;
        while let Some((read, limit)) = reads.next().await {
            let Ok(fetched) = read else {
                complete = false;
                continue;
            };
            // A relay applies `limit` to the whole filter: a full reply may be
            // all versions of one set, hiding another of the same author.
            complete &= fetched.complete && fetched.events.len() < limit;
            for event in fetched.events {
                if let Ok(set) = stored_set_from_event(&event, allow_loopback)
                    && wanted.contains(&set.coordinate)
                {
                    context.storage.replace_emoji_set_if_newer(&set)?;
                }
            }
        }
        Ok(complete)
    }

    /// Resolves when `control` is cancelled or this app stops installs
    /// (runtime shutdown or storage close); the latter also cancels
    /// `control`, so the host reads the same state.
    async fn emoji_install_stopped(&self, control: &EmojiSetInstallControl) {
        tokio::select! {
            () = control.cancelled.cancelled() => {}
            () = self.emoji_install_stop.cancelled() => control.cancel(),
        }
    }

    /// Cancel every running emoji set install and refuse later ones. Called
    /// when the runtime shuts down and when storage closes, so a backgrounded
    /// host never keeps downloading or writes after close.
    pub(crate) fn stop_emoji_set_installs(&self) {
        self.emoji_install_stop.cancel();
    }

    fn emoji_set_mutation_lock(&self, account_label: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.emoji_set_mutation_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(account_label.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn emoji_storage(&self, account_ref: &str) -> Result<SqliteAppStorage, AppError> {
        let account = self.account_home().account(account_ref)?;
        Ok(self.account_storage(&account.label)?.app_storage())
    }

    /// The relays sticker discovery uses: the account's outbox relays.
    fn emoji_context(&self, account_ref: &str) -> Result<EmojiAccountContext, AppError> {
        let account = self.account_home().account(account_ref)?;
        let relay_lists = self
            .directory()
            .account_relay_list_status_for_account_id(&account.account_id_hex)?;
        let endpoints = self.key_package_endpoints(&account.label, &relay_lists)?;
        if endpoints.is_empty() {
            return Err(AppError::EmojiSetNetwork(
                "no account relays configured".into(),
            ));
        }
        Ok(EmojiAccountContext {
            label: account.label.clone(),
            account_id_hex: account.account_id_hex,
            storage: self.account_storage(&account.label)?.app_storage(),
            endpoints,
        })
    }
}

/// Store the newest version of each address among `events`, up to the
/// discovery bound, including versions with no valid emoji so they supersede
/// older ones. Returns (distinct sets with a valid emoji, sets stored or
/// replaced).
fn ingest_discovered_sets(
    storage: &SqliteAppStorage,
    mut events: Vec<Event>,
    allow_loopback: bool,
) -> Result<(usize, usize), AppError> {
    events.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut seen = HashSet::new();
    let mut discovered = 0;
    let mut updated = 0;
    for event in events.into_iter().take(MAX_DISCOVERY_EMOJI_SETS * 2) {
        if event.kind != Kind::Custom(EMOJI_SET_KIND) {
            continue;
        }
        let Ok(set) = stored_set_from_event(&event, allow_loopback) else {
            continue;
        };
        if seen.len() >= MAX_DISCOVERY_EMOJI_SETS && !seen.contains(&set.coordinate) {
            continue;
        }
        if !seen.insert(set.coordinate.clone()) {
            continue;
        }
        if !set.emoji.is_empty() {
            discovered += 1;
        }
        if storage.replace_emoji_set_if_newer(&set)? {
            updated += 1;
        }
    }
    Ok((discovered, updated))
}

/// Valid, distinct kind-30030 `a` pointers of a kind-10030 list, bounded.
fn list_set_pointers(list: &Event) -> Vec<EmojiSetAddress> {
    let mut pointers = Vec::new();
    let mut seen = HashSet::new();
    for tag in list.tags.iter() {
        let values = tag.as_slice();
        if values.first().map(String::as_str) != Some("a") {
            continue;
        }
        let Some(Ok(address)) = values
            .get(1)
            .and_then(|value| EmojiSetAddress::parse_coordinate(value))
        else {
            continue;
        };
        if address.kind != EMOJI_SET_KIND || !seen.insert(address.coordinate()) {
            continue;
        }
        pointers.push(address);
        if pointers.len() >= MAX_USER_LIST_SET_POINTERS {
            break;
        }
    }
    pointers
}

fn author_search(search: &str) -> Option<PublicKey> {
    let search = search.trim();
    let search = search.strip_prefix("nostr:").unwrap_or(search);
    if search.starts_with("npub1") {
        PublicKey::from_bech32(search).ok()
    } else if search.len() == 64 {
        PublicKey::from_hex(search).ok()
    } else {
        None
    }
}

/// An `npub` search matches the author's hex key in storage.
fn normalize_search(search: &str) -> String {
    match author_search(search) {
        Some(author) => author.to_hex(),
        None => search.to_owned(),
    }
}

fn parse_skips(skips: &[StoredEmojiSkip]) -> Vec<AppEmojiSkip> {
    skips
        .iter()
        .filter_map(|skip| {
            Some(AppEmojiSkip {
                position: Some(skip.position),
                shortcode: skip.shortcode.clone(),
                reason: AppEmojiSkipReason::from_code(&skip.reason)?,
            })
        })
        .collect()
}

/// Run a storage write on the blocking pool while it owns the account's
/// emoji mutation guard. A cancelled caller stops waiting but cannot release
/// the guard before the write finishes, so a later mutation (an uninstall)
/// never runs between the cancellation and the write.
async fn write_holding_guard<T, F>(
    guard: tokio::sync::OwnedMutexGuard<()>,
    write: F,
) -> Result<T, AppError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        write()
    })
    .await
    .map_err(|_| AppError::BlockingTask("emoji set write task failed".into()))
}

/// The stored version of `coordinate` when it is the one the user was
/// shown. Nothing stored is `EmojiSetNotFound` (the host fetches with
/// `fetch_emoji_set`); another version is `EmojiSetChanged`.
fn shown_version(
    storage: &SqliteAppStorage,
    coordinate: &str,
    expected_event_id_hex: &str,
) -> Result<StoredEmojiSet, AppError> {
    let set = storage
        .emoji_set(coordinate)?
        .ok_or(AppError::EmojiSetNotFound)?;
    if !set
        .version
        .event_id_hex
        .eq_ignore_ascii_case(expected_event_id_hex.trim())
    {
        return Err(AppError::EmojiSetChanged {
            current_event_id_hex: set.version.event_id_hex,
        });
    }
    Ok(set)
}

/// Run a local read on the blocking pool, so SQLCipher reads (a full picker
/// list, a 4 MiB emoji and its hash) never hold an async worker.
async fn read_blocking<T, F>(read: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(read)
        .await
        .map_err(|_| AppError::BlockingTask("emoji set read task failed".into()))?
}

fn no_valid_emoji() -> AppError {
    invalid("emoji set has no valid emoji")
}

fn nothing_installed_error(skips: &[AppEmojiSkip]) -> AppError {
    let all = |reason| skips.iter().all(|skip| skip.reason == reason);
    let all_unsupported = skips.iter().all(|skip| {
        matches!(
            skip.reason,
            AppEmojiSkipReason::UnsupportedImage | AppEmojiSkipReason::MimeMismatch
        )
    });
    if all(AppEmojiSkipReason::DownloadFailed) {
        AppError::EmojiSetNetwork("no emoji in the set could be downloaded".into())
    } else if all(AppEmojiSkipReason::OverCap) {
        AppError::EmojiSetLimit("no emoji in the set fits the storage budget".into())
    } else if all(AppEmojiSkipReason::TooLarge) {
        AppError::EmojiImageTooLarge("every emoji image in the set exceeds limits".into())
    } else if all_unsupported {
        AppError::EmojiImageUnsupported("no emoji image in the set is supported".into())
    } else {
        invalid("no emoji in the set could be installed")
    }
}

fn installed_states(
    storage: &SqliteAppStorage,
) -> Result<HashMap<String, StoredInstalledEmojiSet>, AppError> {
    Ok(storage
        .installed_emoji_sets()?
        .into_iter()
        .map(|set| (set.coordinate.clone(), set))
        .collect())
}

fn stored_app_set(storage: &SqliteAppStorage, coordinate: &str) -> Result<AppEmojiSet, AppError> {
    let installed = installed_states(storage)?;
    storage
        .emoji_set(coordinate)?
        .ok_or(AppError::EmojiSetNotFound)
        .and_then(|set| app_set(set, &installed))
}

fn app_set(
    set: StoredEmojiSet,
    installed: &HashMap<String, StoredInstalledEmojiSet>,
) -> Result<AppEmojiSet, AppError> {
    let installed = installed
        .get(&set.coordinate)
        .map(|snapshot| AppInstalledEmojiSetState {
            update_available: snapshot.version != set.version,
            event_id_hex: snapshot.version.event_id_hex.clone(),
            created_at: snapshot.version.created_at,
            installed_at: snapshot.installed_at,
            emoji_count: snapshot.emoji_count,
            byte_len: snapshot.byte_len,
        });
    Ok(AppEmojiSet {
        skipped: parse_skips(&set.skipped),
        coordinate: set.coordinate,
        kind: set.kind,
        author_pubkey_hex: set.author_pubkey_hex,
        identifier: set.identifier,
        event_id_hex: set.version.event_id_hex,
        created_at: set.version.created_at,
        title: set.title,
        description: set.description,
        image_url: set.image_url,
        emoji: set
            .emoji
            .into_iter()
            .map(|entry| AppEmojiSetEmoji {
                shortcode: entry.shortcode,
                url: entry.url,
            })
            .collect(),
        skipped_count: set.skipped_count,
        installed,
    })
}

fn colliding_shortcodes(rows: &[StoredInstalledEmojiRow]) -> HashSet<String> {
    let mut sets_by_shortcode: HashMap<&str, HashSet<&str>> = HashMap::new();
    for row in rows {
        sets_by_shortcode
            .entry(&row.emoji.shortcode)
            .or_default()
            .insert(&row.set_coordinate);
    }
    sets_by_shortcode
        .into_iter()
        .filter(|(_, sets)| sets.len() > 1)
        .map(|(shortcode, _)| shortcode.to_owned())
        .collect()
}

fn app_installed_emoji(
    row: StoredInstalledEmojiRow,
    collisions: &HashSet<String>,
) -> AppInstalledCustomEmoji {
    AppInstalledCustomEmoji {
        shortcode_collision: collisions.contains(&row.emoji.shortcode),
        set_coordinate: row.set_coordinate,
        set_title: row.set_title,
        author_pubkey_hex: row.author_pubkey_hex,
        shortcode: row.emoji.shortcode,
        mime: row.emoji.mime,
        width: row.emoji.width,
        height: row.emoji.height,
        frames: row.emoji.frames,
        sha256: row.emoji.sha256,
        byte_len: row.emoji.byte_len,
    }
}

fn invalid(reason: &'static str) -> AppError {
    AppError::InvalidEmojiSet(reason.to_owned())
}

#[cfg(test)]
#[path = "emoji_sets/tests.rs"]
mod tests;
