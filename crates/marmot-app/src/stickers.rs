use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cgka_traits::TransportEndpoint;
use nostr::nips::nip19::{FromBech32, Nip19Coordinate};
#[cfg(test)]
use nostr::prelude::FinalizeEvent;
use nostr::prelude::FinalizeUnsignedEvent;
use nostr::prelude::{
    Event, EventBuilder, Filter, Kind, PublicKey, RelayUrl, SingleLetterTag, Tag,
    Timestamp as NostrTimestamp,
};
use serde::{Deserialize, Serialize};
use sonar_stickers::{
    InstalledPackList, PACK_FORMAT, PackAddress, STICKER_PACK_KIND, Sticker, StickerRef,
    USER_STICKER_PACKS_KIND, build_installed_packs_tags, build_sticker_ref_tag,
    parse_installed_pack_list, parse_pack_event, parse_sticker_ref_tag, sha256_hex,
};
#[cfg(test)]
use sonar_stickers::{StickerPack, build_pack_tags};
use storage_sqlite::{
    SqliteAppStorage, StoredSticker, StoredStickerOutboxEvent, StoredStickerPack,
    StoredStickerPackVersion,
};
use url::Url;
use zeroize::Zeroizing;

use crate::image_inspect::{self, InspectedImage};
use crate::media::fetch_blossom_blob_limited;
use crate::{AppError, MarmotApp, ReceivedMessage, unix_now_seconds};
use cgka_traits::MemberId;
use transport_nostr_peeler::NostrTransportEvent;

const MAX_STICKER_ASSET_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DISCOVERY_PACKS: usize = 100;
const MAX_INSTALLED_PACKS: usize = 100;
const MAX_LINK_CHARS: usize = 2048;
const MAX_STICKER_RELAY_HINTS: usize = 8;
const STICKER_SHARE_LINK_BASE: &str = "https://sonarprivacy.xyz/stickers";
const MAX_FUTURE_EVENT_SKEW_SECONDS: u64 = 5 * 60;
/// Replaceable versions read per pack or installed-list fetch.
const MAX_REPLACEABLE_VERSIONS_PER_FETCH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStickerRef {
    pub pack_coordinate: String,
    pub shortcode: String,
    pub plaintext_sha256: String,
}

impl AppStickerRef {
    fn to_sdk(&self) -> Result<StickerRef, AppError> {
        StickerRef::new(
            PackAddress::parse(&self.pack_coordinate)
                .map_err(|_| invalid_sticker("invalid pack coordinate"))?,
            self.shortcode.clone(),
            self.plaintext_sha256.clone(),
        )
        .map_err(|_| invalid_sticker("invalid sticker reference"))
    }
}

impl From<StickerRef> for AppStickerRef {
    fn from(value: StickerRef) -> Self {
        Self {
            pack_coordinate: value.pack.coordinate(),
            shortcode: value.shortcode,
            plaintext_sha256: value.plaintext_sha256,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSticker {
    pub pack_coordinate: String,
    pub shortcode: String,
    pub url: String,
    pub sha256: String,
    pub mime: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub alt: Option<String>,
    pub emoji: Option<String>,
}

impl AppSticker {
    pub fn reference(&self) -> AppStickerRef {
        AppStickerRef {
            pack_coordinate: self.pack_coordinate.clone(),
            shortcode: self.shortcode.clone(),
            plaintext_sha256: self.sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStickerPack {
    pub coordinate: String,
    pub author_pubkey_hex: String,
    pub identifier: String,
    pub event_id_hex: String,
    pub created_at: u64,
    pub title: String,
    pub description: Option<String>,
    pub cover: Option<AppSticker>,
    pub stickers: Vec<AppSticker>,
    pub license: Option<String>,
    pub installed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStickerAsset {
    pub sticker: AppSticker,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStickerSyncResult {
    pub discovered: u32,
    pub updated: u32,
    pub installed: u32,
    pub pending_operations: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppStickerImportResult {
    pub pack: AppStickerPack,
    pub skipped_signal_sticker_ids: Vec<u32>,
}

/// Parse exactly one valid Sonar sticker tag from a kind-9 message. Multiple
/// sticker tags are rejected as ambiguous. Host apps receive this typed value
/// and never need to reinterpret raw Nostr tags.
pub fn sticker_ref_from_tags(kind: u64, tags: &[Vec<String>]) -> Option<AppStickerRef> {
    if kind != u64::from(Kind::Custom(9).as_u16()) {
        return None;
    }
    let sticker_tags = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "sticker"))
        .collect::<Vec<_>>();
    if sticker_tags.len() != 1 {
        return None;
    }
    let tag = Tag::parse(sticker_tags[0].clone()).ok()?;
    let sonar_tag = nostr044::Tag::parse(tag.clone().to_vec()).ok()?;
    parse_sticker_ref_tag(&sonar_tag).ok().map(Into::into)
}

pub fn sticker_ref_from_message(message: &ReceivedMessage) -> Option<AppStickerRef> {
    sticker_ref_from_tags(message.kind, &message.tags)
}

fn sonar_tag_to_app(tag: nostr044::Tag) -> Result<Tag, AppError> {
    let json = serde_json::to_string(&tag).map_err(|_| invalid_sticker("invalid sticker tag"))?;
    Tag::parse(
        serde_json::from_str::<Vec<String>>(&json)
            .map_err(|_| invalid_sticker("invalid sticker tag"))?,
    )
    .map_err(|_| invalid_sticker("invalid sticker tag"))
}

fn app_event_to_sonar(event: &Event) -> Result<nostr044::Event, AppError> {
    let json = serde_json::to_vec(event).map_err(|_| invalid_sticker("invalid sticker event"))?;
    serde_json::from_slice(&json).map_err(|_| invalid_sticker("sticker event could not be decoded"))
}

pub(crate) fn sticker_ref_tag(sticker_ref: &AppStickerRef) -> Result<Vec<String>, AppError> {
    let tag = build_sticker_ref_tag(&sticker_ref.to_sdk()?);
    let parsed = sonar_tag_to_app(tag)?;
    Ok(parsed.to_vec())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedStickerPackInput {
    coordinate: String,
    relay_hints: Vec<TransportEndpoint>,
}

/// Accept a canonical coordinate, an NIP-19 `naddr`/`nostr:naddr`, or Sonar's
/// documented HTTPS viewer link.
pub fn parse_sticker_pack_input(input: &str) -> Result<String, AppError> {
    parse_sticker_pack_input_with_relays(input).map(|parsed| parsed.coordinate)
}

fn parse_sticker_pack_input_with_relays(input: &str) -> Result<ParsedStickerPackInput, AppError> {
    let input = input.trim();
    if input.is_empty() || input.chars().count() > MAX_LINK_CHARS {
        return Err(invalid_sticker("invalid sticker pack link"));
    }
    if let Ok(address) = PackAddress::parse(input) {
        return Ok(ParsedStickerPackInput {
            coordinate: address.coordinate(),
            relay_hints: Vec::new(),
        });
    }
    let bech32 = input.strip_prefix("nostr:").unwrap_or(input);
    if bech32.starts_with("naddr1") {
        let nip19 = Nip19Coordinate::from_bech32(bech32)
            .map_err(|_| invalid_sticker("invalid sticker pack address"))?;
        if nip19.coordinate.kind != Kind::Custom(STICKER_PACK_KIND) {
            return Err(invalid_sticker("sticker pack address has the wrong kind"));
        }
        let address = PackAddress::new(
            nip19.coordinate.public_key.to_hex(),
            nip19.coordinate.identifier,
        )
        .map_err(|_| invalid_sticker("invalid sticker pack address"))?;
        return Ok(ParsedStickerPackInput {
            coordinate: address.coordinate(),
            relay_hints: normalize_sticker_relay_hints(
                nip19.relays.into_iter().map(|relay| relay.to_string()),
            ),
        });
    }
    let url = Url::parse(input).map_err(|_| invalid_sticker("invalid sticker pack link"))?;
    let canonical = Url::parse(STICKER_SHARE_LINK_BASE).expect("valid sticker viewer URL");
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || !url.host_str().is_some_and(|host| {
            Some(host) == canonical.host_str() || host == "www.sonarprivacy.xyz"
        })
        || url.path().trim_end_matches('/') != canonical.path()
    {
        return Err(invalid_sticker("untrusted sticker pack link"));
    }
    let query_pairs = url.query_pairs().collect::<Vec<_>>();
    let value = query_pairs
        .iter()
        .find_map(|(key, value)| (key == "a").then(|| value.as_ref().to_owned()))
        .ok_or_else(|| invalid_sticker("sticker pack link is missing its address"))?;
    let mut parsed = parse_sticker_pack_input_with_relays(&value)?;
    let link_relays = normalize_sticker_relay_hints(
        query_pairs
            .into_iter()
            .filter_map(|(key, value)| (key == "relay").then(|| value.into_owned())),
    );
    for relay in link_relays {
        if parsed.relay_hints.len() >= MAX_STICKER_RELAY_HINTS {
            break;
        }
        if !parsed.relay_hints.contains(&relay) {
            parsed.relay_hints.push(relay);
        }
    }
    Ok(parsed)
}

fn normalize_sticker_relay_hints(
    relays: impl IntoIterator<Item = String>,
) -> Vec<TransportEndpoint> {
    let mut normalized = Vec::new();
    for relay in relays {
        let Ok(relay) = RelayUrl::parse(relay.trim()) else {
            continue;
        };
        let endpoint = TransportEndpoint(relay.to_string());
        if !normalized.contains(&endpoint) {
            normalized.push(endpoint);
        }
        if normalized.len() >= MAX_STICKER_RELAY_HINTS {
            break;
        }
    }
    normalized
}

fn build_sticker_share_link(
    address: &PackAddress,
    relays: impl IntoIterator<Item = String>,
) -> String {
    let mut url = Url::parse(STICKER_SHARE_LINK_BASE).expect("valid sticker viewer URL");
    url.query_pairs_mut()
        .append_pair("a", &address.coordinate());
    let mut link = url.to_string();
    for relay in normalize_sticker_relay_hints(relays) {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("relay", relay.as_str())
            .finish();
        if link.len() + 1 + query.len() <= MAX_LINK_CHARS {
            link.push('&');
            link.push_str(&query);
        }
    }
    link
}

fn retain_sticker_relays(
    storage: &SqliteAppStorage,
    coordinate: &str,
    endpoints: &[TransportEndpoint],
) -> Result<(), AppError> {
    let relays = normalize_sticker_relay_hints(
        storage
            .sticker_pack_relays(coordinate)?
            .into_iter()
            .chain(endpoints.iter().map(|endpoint| endpoint.0.clone())),
    )
    .into_iter()
    .map(|endpoint| endpoint.0)
    .collect::<Vec<_>>();
    storage.set_sticker_pack_relays(coordinate, &relays)?;
    Ok(())
}

fn validate_signal_sticker_link(input: &str) -> Result<String, AppError> {
    let input = input.trim();
    if input.is_empty() || input.chars().count() > MAX_LINK_CHARS {
        return Err(invalid_sticker("invalid Signal sticker link"));
    }
    let url = Url::parse(input).map_err(|_| invalid_sticker("invalid Signal sticker link"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.host_str() != Some("signal.art")
        || url.path().trim_end_matches('/') != "/addstickers"
    {
        return Err(invalid_sticker("untrusted Signal sticker link"));
    }
    let encoded = url
        .fragment()
        .or_else(|| url.query())
        .ok_or_else(|| invalid_sticker("Signal sticker link is missing credentials"))?;
    let parameters = url::form_urlencoded::parse(encoded.as_bytes()).collect::<HashMap<_, _>>();
    let pack_id = parameters
        .get("pack_id")
        .filter(|value| {
            value.len() == 32 && value.chars().all(|character| character.is_ascii_hexdigit())
        })
        .ok_or_else(|| invalid_sticker("Signal sticker link has an invalid pack id"))?;
    if parameters
        .get("pack_key")
        .is_none_or(|value| value.is_empty())
    {
        return Err(invalid_sticker(
            "Signal sticker link is missing credentials",
        ));
    }
    Ok(pack_id.to_ascii_lowercase())
}

impl MarmotApp {
    /// Build a Sonar viewer link without network I/O. Retained fetch candidates
    /// take precedence over account relays; hints are not delivery guarantees.
    pub fn sticker_pack_share_link(
        &self,
        account_ref: &str,
        coordinate: &str,
    ) -> Result<String, AppError> {
        let address = PackAddress::parse(coordinate)
            .map_err(|_| invalid_sticker("invalid sticker pack coordinate"))?;
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?.app_storage();
        let mut relays = storage.sticker_pack_relays(&address.coordinate())?;
        if relays.is_empty() {
            let relay_lists = self
                .directory()
                .account_relay_list_status_for_account_id(&account.account_id_hex)?;
            relays = self
                .key_package_endpoints(&account.label, &relay_lists)?
                .into_iter()
                .map(|endpoint| endpoint.0)
                .collect();
        }
        Ok(build_sticker_share_link(&address, relays))
    }

    pub fn sticker_packs(
        &self,
        account_ref: &str,
        installed_only: bool,
        search: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<AppStickerPack>, AppError> {
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?.app_storage();
        let installed = storage
            .desired_installed_sticker_packs()?
            .into_iter()
            .collect::<HashSet<_>>();
        storage
            .sticker_packs(installed_only, search, limit.unwrap_or(50))?
            .into_iter()
            .map(|pack| app_pack_from_stored(pack, &installed))
            .collect()
    }

    pub fn sticker_pack(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<Option<AppStickerPack>, AppError> {
        let coordinate = parse_sticker_pack_input(input)?;
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?.app_storage();
        let installed = storage
            .desired_installed_sticker_packs()?
            .into_iter()
            .collect::<HashSet<_>>();
        storage
            .sticker_pack(&coordinate)?
            .map(|pack| app_pack_from_stored(pack, &installed))
            .transpose()
    }

    pub async fn fetch_sticker_asset(
        &self,
        account_ref: &str,
        sticker_ref: AppStickerRef,
    ) -> Result<AppStickerAsset, AppError> {
        let sticker_ref = sticker_ref.to_sdk()?;
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?.app_storage();
        let coordinate = sticker_ref.pack.coordinate();
        let mut stored = storage.sticker_for_ref(
            &coordinate,
            &sticker_ref.shortcode,
            &sticker_ref.plaintext_sha256,
        )?;
        if stored.is_none() {
            // A received sticker may reference a historical pack version that
            // lost replacement ordering, or a pack outside the recent discovery
            // window. Resolve the address on demand even when a newer current
            // pack is already stored, then authorize the exact shortcode/hash
            // before touching its Blossom URL.
            let context = self.sticker_context(account_ref)?;
            let mutation_lock = self.sticker_mutation_lock(&context.label);
            let _guard = mutation_lock.lock().await;
            if storage
                .sticker_for_ref(
                    &coordinate,
                    &sticker_ref.shortcode,
                    &sticker_ref.plaintext_sha256,
                )?
                .is_none()
            {
                let _ = fetch_pack_into_storage(self, &context, &coordinate, &[]).await;
            }
            stored = storage.sticker_for_ref(
                &sticker_ref.pack.coordinate(),
                &sticker_ref.shortcode,
                &sticker_ref.plaintext_sha256,
            )?;
        }
        let stored = stored.ok_or(AppError::StickerNotFound)?;
        let bytes = fetch_blossom_blob_limited(
            &stored.url,
            MAX_STICKER_ASSET_BYTES,
            self.allow_loopback_blob_endpoints(),
        )
        .await
        .map_err(|_| AppError::StickerRelay("sticker asset download failed".into()))?;
        validate_downloaded_sticker(&stored, &bytes)?;
        Ok(AppStickerAsset {
            sticker: app_sticker_from_stored(sticker_ref.pack.coordinate(), stored),
            bytes,
        })
    }

    pub(crate) fn authorize_sticker_ref(
        &self,
        account_ref: &str,
        sticker_ref: &AppStickerRef,
    ) -> Result<(), AppError> {
        let sticker_ref = sticker_ref.to_sdk()?;
        let account = self.account_home().account(account_ref)?;
        self.account_storage(&account.label)?
            .app_storage()
            .sticker_for_ref(
                &sticker_ref.pack.coordinate(),
                &sticker_ref.shortcode,
                &sticker_ref.plaintext_sha256,
            )?
            .ok_or(AppError::StickerNotFound)
            .map(|_| ())
    }

    /// Refresh recent public packs and this account's installed-list projection
    /// from its configured outbox relays. Pending local operations are rebased
    /// over the winning remote list and published after the fetch.
    pub async fn sync_sticker_packs(
        &self,
        account_ref: &str,
    ) -> Result<AppStickerSyncResult, AppError> {
        let context = self.sticker_context(account_ref)?;
        let mutation_lock = self.sticker_mutation_lock(&context.label);
        let _guard = mutation_lock.lock().await;
        let rebased = rebase_and_flush_sticker_outbox_best_effort(self, &context).await?;

        let filter = Filter::new()
            .kind(Kind::Custom(STICKER_PACK_KIND))
            .custom_tag(SingleLetterTag::LOWERCASE_T, PACK_FORMAT.to_owned())
            .limit(MAX_DISCOVERY_PACKS);
        let events = self
            .relay_plane
            .fetch_public_events(
                context.endpoints.clone(),
                vec![filter],
                MAX_DISCOVERY_PACKS * 2,
            )
            .await
            .map_err(AppError::StickerRelay)?
            .events;
        let discovered = events.len().min(MAX_DISCOVERY_PACKS);
        let updated = ingest_pack_events(&context.storage, events, &context.endpoints)?;

        let desired = context.storage.desired_installed_sticker_packs()?;
        for coordinate in desired.iter().take(MAX_INSTALLED_PACKS) {
            match fetch_pack_into_storage(self, &context, coordinate, &[]).await {
                Ok(_) | Err(AppError::StickerRelay(_) | AppError::StickerNotFound) => {}
                Err(error) => return Err(error),
            }
        }
        if rebased {
            publish_pending_installed_list(self, &context).await?;
        }
        let installed = context.storage.desired_installed_sticker_packs()?.len();
        let pending_operations = context.storage.sticker_install_operations()?.len();
        Ok(AppStickerSyncResult {
            discovered: discovered.try_into().unwrap_or(u32::MAX),
            updated: updated.try_into().unwrap_or(u32::MAX),
            installed: installed.try_into().unwrap_or(u32::MAX),
            pending_operations: pending_operations.try_into().unwrap_or(u32::MAX),
        })
    }

    pub async fn fetch_sticker_pack(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<AppStickerPack, AppError> {
        let parsed = parse_sticker_pack_input_with_relays(input)?;
        let context = self.sticker_context(account_ref)?;
        let mutation_lock = self.sticker_mutation_lock(&context.label);
        let _guard = mutation_lock.lock().await;
        fetch_pack_into_storage(self, &context, &parsed.coordinate, &parsed.relay_hints).await?;
        context
            .storage
            .prune_uninstalled_sticker_discovery(MAX_DISCOVERY_PACKS, &parsed.coordinate)?;
        app_pack_for_context(&context, &parsed.coordinate)
    }

    pub async fn install_sticker_pack(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<AppStickerPack, AppError> {
        let parsed = parse_sticker_pack_input_with_relays(input)?;
        let coordinate = &parsed.coordinate;
        let context = self.sticker_context(account_ref)?;
        let mutation_lock = self.sticker_mutation_lock(&context.label);
        let _guard = mutation_lock.lock().await;
        let rebased = rebase_and_flush_sticker_outbox_best_effort(self, &context).await?;
        if context.storage.sticker_pack(coordinate)?.is_none() {
            fetch_pack_into_storage(self, &context, coordinate, &parsed.relay_hints).await?;
        } else {
            // A validated cached pack is enough to record an install while
            // offline. Refresh opportunistically without making connectivity
            // a precondition for the user's local intent.
            tolerate_offline(
                fetch_pack_into_storage(self, &context, coordinate, &parsed.relay_hints)
                    .await
                    .map(|_| ()),
            )?;
        }
        let mut desired = context.storage.desired_installed_sticker_packs()?;
        validate_install_capacity(&desired, coordinate)?;
        desired.retain(|pack| pack != coordinate);
        desired.push(coordinate.clone());
        // Refusal must leave the existing operation journal untouched. Once
        // authorized, persist intent before any relay-visible publication.
        let event = if rebased {
            Some(sign_installed_list(self, &context, &desired).await?)
        } else {
            None
        };
        context
            .storage
            .enqueue_sticker_install_operation(coordinate, true, unix_now_seconds())?;
        if let Some(event) = event {
            tolerate_unpublished(publish_outboxed_event(self, &context, &event).await)?;
        }
        app_pack_for_context(&context, coordinate)
    }

    pub async fn uninstall_sticker_pack(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<(), AppError> {
        let coordinate = parse_sticker_pack_input(input)?;
        let context = self.sticker_context(account_ref)?;
        let mutation_lock = self.sticker_mutation_lock(&context.label);
        let _guard = mutation_lock.lock().await;
        let rebased = rebase_and_flush_sticker_outbox_best_effort(self, &context).await?;
        let event = if rebased {
            let mut desired = context.storage.desired_installed_sticker_packs()?;
            desired.retain(|pack| pack != &coordinate);
            Some(sign_installed_list(self, &context, &desired).await?)
        } else {
            None
        };
        context.storage.enqueue_sticker_install_operation(
            &coordinate,
            false,
            unix_now_seconds(),
        )?;
        if let Some(event) = event {
            tolerate_unpublished(publish_outboxed_event(self, &context, &event).await)?;
        }
        Ok(())
    }

    /// Signal import is refused before any network call.
    ///
    /// The pinned `sonar-stickers` importer dials Signal's CDN with its own
    /// `reqwest` client: proxies and redirects stay enabled, and resolved
    /// addresses are not pinned. That bypasses this runtime's dial discipline.
    /// The library does not accept an injected fetch, and its decrypt helpers
    /// are private, so MDK cannot pin the download itself. The public command
    /// stays in place and validates the link, then returns
    /// [`AppError::StickerImport`] without reading account state or dialing.
    /// The link is zeroized and never persisted.
    ///
    /// Re-enable only after `sonar-stickers` accepts a caller-supplied fetch
    /// that this runtime can pin the same way as Blossom and profile-image
    /// downloads. External-signer accounts remain unsupported for that future
    /// path: Blossom would otherwise require one authorization signature per
    /// asset.
    pub async fn import_signal_sticker_pack(
        &self,
        _account_ref: &str,
        signal_link: String,
        _blossom_server: Option<&str>,
    ) -> Result<AppStickerImportResult, AppError> {
        let signal_link = Zeroizing::new(signal_link);
        validate_signal_sticker_link(signal_link.as_str())?;
        Err(AppError::StickerImport(
            "Signal sticker import is unavailable until its fetch can be pinned".into(),
        ))
    }

    fn sticker_mutation_lock(&self, account_label: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.sticker_mutation_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(account_label.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn sticker_context(&self, account_ref: &str) -> Result<StickerAccountContext, AppError> {
        let account = self.account_home().account(account_ref)?;
        let relay_lists = self
            .directory()
            .account_relay_list_status_for_account_id(&account.account_id_hex)?;
        let endpoints = self.key_package_endpoints(&account.label, &relay_lists)?;
        if endpoints.is_empty() {
            return Err(AppError::StickerRelay(
                "no account relays configured".into(),
            ));
        }
        Ok(StickerAccountContext {
            label: account.label.clone(),
            account_id_hex: account.account_id_hex,
            storage: self.account_storage(&account.label)?.app_storage(),
            endpoints,
        })
    }
}

async fn fetch_pack_into_storage(
    app: &MarmotApp,
    context: &StickerAccountContext,
    coordinate: &str,
    relay_hints: &[TransportEndpoint],
) -> Result<bool, AppError> {
    let address = PackAddress::parse(coordinate)
        .map_err(|_| invalid_sticker("invalid sticker pack coordinate"))?;
    let author = PublicKey::parse(&address.author_pubkey_hex)
        .map_err(|_| invalid_sticker("invalid sticker pack author"))?;
    let filter = Filter::new()
        .author(author)
        .kind(Kind::Custom(STICKER_PACK_KIND))
        .custom_tag(SingleLetterTag::LOWERCASE_D, address.identifier.clone())
        .limit(MAX_REPLACEABLE_VERSIONS_PER_FETCH);
    // Hints only add candidates. Versions from the hint relays and from the
    // account relays all pass through NIP-01 replacement ordering, so an older
    // version on a hint relay cannot hide a newer one on the account relays.
    let (mut updated, mut found) = (false, false);
    if !relay_hints.is_empty() {
        match fetch_pack_from_endpoints(
            app,
            context,
            coordinate,
            relay_hints.to_vec(),
            filter.clone(),
        )
        .await
        {
            Ok(hinted) => (updated, found) = hinted,
            Err(AppError::StickerRelay(_)) => {}
            Err(error) => return Err(error),
        }
    }
    match fetch_pack_from_endpoints(app, context, coordinate, context.endpoints.clone(), filter)
        .await
    {
        Ok((account_updated, _)) => updated |= account_updated,
        // A hint already supplied a validated version; unreachable account
        // relays do not discard it.
        Err(AppError::StickerRelay(_)) if found => {}
        Err(error) => return Err(error),
    }
    if context.storage.sticker_pack(coordinate)?.is_none() {
        return Err(AppError::StickerNotFound);
    }
    Ok(updated)
}

async fn fetch_pack_from_endpoints(
    app: &MarmotApp,
    context: &StickerAccountContext,
    coordinate: &str,
    endpoints: Vec<TransportEndpoint>,
    filter: Filter,
) -> Result<(bool, bool), AppError> {
    let events = app
        .relay_plane
        .fetch_public_events(
            endpoints.clone(),
            vec![filter],
            MAX_REPLACEABLE_VERSIONS_PER_FETCH,
        )
        .await
        .map_err(AppError::StickerRelay)?
        .events;
    let mut updated = false;
    let mut found = false;
    for event in events {
        let stored = match stored_pack_from_event(&event) {
            Ok(pack) if pack.coordinate == coordinate => pack,
            _ => continue,
        };
        found = true;
        updated |= context.storage.replace_sticker_pack_if_newer(&stored)?;
    }
    if found {
        retain_sticker_relays(&context.storage, coordinate, &endpoints)?;
    }
    Ok((updated, found))
}

fn ingest_pack_events(
    storage: &SqliteAppStorage,
    events: Vec<Event>,
    endpoints: &[TransportEndpoint],
) -> Result<usize, AppError> {
    let mut updated = 0_usize;
    let mut seen = HashSet::new();
    for event in events.into_iter().take(MAX_DISCOVERY_PACKS * 2) {
        let stored = match stored_pack_from_event(&event) {
            Ok(pack) => pack,
            Err(_) => continue,
        };
        if !seen.insert((
            stored.coordinate.clone(),
            stored.version.event_id_hex.clone(),
        )) {
            continue;
        }
        if storage.replace_sticker_pack_if_newer(&stored)? {
            updated += 1;
        }
        retain_sticker_relays(storage, &stored.coordinate, endpoints)?;
    }
    storage
        .prune_uninstalled_sticker_discovery(MAX_DISCOVERY_PACKS, "")
        .map_err(AppError::Storage)?;
    Ok(updated)
}

/// Refresh the remote installed-list winner before flushing any locally
/// outboxed kind-10031 event. If the account is offline, leave both outbox and
/// operations untouched so the next successful refresh can rebase first.
///
/// Returns whether the remote base was refreshed. A caller that then publishes
/// the installed list must gate on it: a list signed over a stale base plus
/// local intent would replace concurrent remote installs and uninstalls.
async fn rebase_and_flush_sticker_outbox_best_effort(
    app: &MarmotApp,
    context: &StickerAccountContext,
) -> Result<bool, AppError> {
    match refresh_installed_base(app, context).await {
        Ok(()) => {
            tolerate_unpublished(flush_sticker_outbox(app, context).await)?;
            Ok(true)
        }
        Err(AppError::StickerRelay(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_install_capacity(desired: &[String], coordinate: &str) -> Result<(), AppError> {
    if desired.len() >= MAX_INSTALLED_PACKS && !desired.iter().any(|pack| pack == coordinate) {
        return Err(invalid_sticker("too many installed sticker packs"));
    }
    Ok(())
}

/// Read the account's current kind-10031 winner with completion evidence.
///
/// A read that did not finish on every outbox relay (a relay that timed out,
/// closed the subscription, or truncated the result) is indistinguishable
/// from "nothing published yet", and a base of nothing plus local intent is
/// exactly the stale list that erases another device's changes once
/// published. Only a complete read counts as a refresh.
async fn refresh_installed_base(
    app: &MarmotApp,
    context: &StickerAccountContext,
) -> Result<(), AppError> {
    let author = PublicKey::parse(&context.account_id_hex)
        .map_err(|_| invalid_sticker("invalid account identity"))?;
    let filter = Filter::new()
        .author(author)
        .kind(Kind::Custom(USER_STICKER_PACKS_KIND))
        .limit(MAX_REPLACEABLE_VERSIONS_PER_FETCH);
    let fetched = app
        .relay_plane
        .fetch_public_events(
            context.endpoints.clone(),
            vec![filter],
            MAX_REPLACEABLE_VERSIONS_PER_FETCH.saturating_mul(context.endpoints.len()),
        )
        .await
        .map_err(AppError::StickerRelay)?;
    if !fetched.complete {
        return Err(AppError::StickerRelay(
            "installed sticker list read did not complete".into(),
        ));
    }
    let mut candidates = fetched
        .events
        .into_iter()
        .filter(|event| {
            event.pubkey.to_hex() == context.account_id_hex
                && event.kind == Kind::Custom(USER_STICKER_PACKS_KIND)
                && event.verify().is_ok()
                && event.created_at.as_secs()
                    <= unix_now_seconds().saturating_add(MAX_FUTURE_EVENT_SKEW_SECONDS)
        })
        .filter_map(|event| {
            let list = parse_installed_pack_list(&app_event_to_sonar(&event).ok()?).ok()?;
            (list.packs.len() <= MAX_INSTALLED_PACKS).then_some((event, list))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|(left, _), (right, _)| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    if let Some((event, list)) = candidates.into_iter().next() {
        let version = StoredStickerPackVersion {
            event_id_hex: event.id.to_hex(),
            created_at: event.created_at.as_secs(),
        };
        let packs = list
            .packs
            .into_iter()
            .map(|address| address.coordinate())
            .collect::<Vec<_>>();
        context
            .storage
            .replace_installed_sticker_packs_if_newer(&version, &packs)?;
    }
    Ok(())
}

async fn publish_pending_installed_list(
    app: &MarmotApp,
    context: &StickerAccountContext,
) -> Result<(), AppError> {
    if context.storage.sticker_install_operations()?.is_empty() {
        return Ok(());
    }
    context
        .storage
        .trim_sticker_install_operations_to_capacity(MAX_INSTALLED_PACKS)?;
    if context.storage.sticker_install_operations()?.is_empty() {
        return Ok(());
    }
    let desired = context.storage.desired_installed_sticker_packs()?;
    let event = sign_installed_list(app, context, &desired).await?;
    publish_outboxed_event(app, context, &event).await
}

async fn sign_installed_list(
    app: &MarmotApp,
    context: &StickerAccountContext,
    desired: &[String],
) -> Result<Event, AppError> {
    if desired.len() > MAX_INSTALLED_PACKS {
        return Err(invalid_sticker("too many installed sticker packs"));
    }
    let addresses = desired
        .iter()
        .map(|coordinate| {
            PackAddress::parse(coordinate)
                .map_err(|_| invalid_sticker("installed sticker address is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    sign_public_event(
        app,
        context,
        USER_STICKER_PACKS_KIND,
        build_installed_packs_tags(&InstalledPackList::new(addresses)),
        next_installed_list_publication_timestamp(&context.storage)?,
    )
    .await
}

fn next_installed_list_publication_timestamp(storage: &SqliteAppStorage) -> Result<u64, AppError> {
    let now = unix_now_seconds();
    let installed_created_at = storage
        .installed_sticker_state()?
        .version
        .map(|version| version.created_at);
    let outbox_created_at = storage
        .sticker_outbox_events()?
        .into_iter()
        .filter(|event| event.kind == u64::from(USER_STICKER_PACKS_KIND))
        .map(|event| event.created_at)
        .max();
    let latest = installed_created_at
        .into_iter()
        .chain(outbox_created_at)
        .max();
    next_monotonic_publication_timestamp(
        now,
        latest,
        "installed-list timestamp is too far in the future",
    )
}

fn next_monotonic_publication_timestamp(
    now: u64,
    latest: Option<u64>,
    future_error: &'static str,
) -> Result<u64, AppError> {
    let Some(latest) = latest else {
        return Ok(now);
    };
    let next = now.max(latest.saturating_add(1));
    if next > now.saturating_add(MAX_FUTURE_EVENT_SKEW_SECONDS) {
        return Err(invalid_sticker(future_error));
    }
    Ok(next)
}

async fn sign_public_event(
    app: &MarmotApp,
    context: &StickerAccountContext,
    kind: u16,
    tags: Vec<nostr044::Tag>,
    created_at: u64,
) -> Result<Event, AppError> {
    let account = app.account_home().account(&context.label)?;
    let signer = app.account_signer_for_summary(&account)?.as_nostr_signer();
    let public_key = signer
        .get_public_key()
        .await
        .map_err(|error| crate::external_signer_error(error, "sticker public key"))?;
    if public_key.to_hex() != context.account_id_hex {
        return Err(AppError::ExternalSignerMismatch);
    }
    let tags = tags
        .into_iter()
        .map(sonar_tag_to_app)
        .collect::<Result<Vec<_>, _>>()?;
    let mut unsigned = EventBuilder::new(Kind::Custom(kind), "")
        .tags(tags)
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .finalize_unsigned(public_key);
    unsigned.ensure_id();
    signer
        .sign_event(unsigned)
        .await
        .map_err(|error| crate::external_signer_error(error, "sticker event"))
}

async fn publish_outboxed_event(
    app: &MarmotApp,
    context: &StickerAccountContext,
    event: &Event,
) -> Result<(), AppError> {
    if event.kind == Kind::Custom(USER_STICKER_PACKS_KIND) {
        // A newer installed-list event includes every pending operation. Drop
        // older unsent variants so publishing one later can never clear local
        // intent that it did not contain. A crash between these deletes and
        // the insert is safe: operations remain and sync regenerates the event.
        for pending in context.storage.sticker_outbox_events()? {
            if pending.kind == u64::from(USER_STICKER_PACKS_KIND)
                && pending.event_id_hex != event.id.to_hex()
            {
                context
                    .storage
                    .clear_sticker_outbox_event(&pending.event_id_hex)?;
            }
        }
    }
    context
        .storage
        .put_sticker_outbox_event(&StoredStickerOutboxEvent {
            event_id_hex: event.id.to_hex(),
            kind: u64::from(event.kind.as_u16()),
            event_json: event.as_json(),
            created_at: event.created_at.as_secs(),
        })?;
    publish_account_event(app, context, event).await?;
    apply_published_sticker_event(&context.storage, event)?;
    context
        .storage
        .clear_sticker_outbox_event(&event.id.to_hex())?;
    Ok(())
}

/// Publish one of the account's own signed sticker events through the
/// account's publish client: the same signer-bound, proxy-aware client that
/// profile metadata and the NIP-51 block list use, separate from the receive
/// pool, authenticating only as the event's own author.
async fn publish_account_event(
    app: &MarmotApp,
    context: &StickerAccountContext,
    event: &Event,
) -> Result<(), AppError> {
    require_account_author(event, &context.account_id_hex)?;
    let transport_event = NostrTransportEvent::from_nostr_event(event)
        .map_err(|_| invalid_sticker("sticker publication is invalid"))?;
    let account_id = MemberId::new(
        hex::decode(&context.account_id_hex)
            .map_err(|_| invalid_sticker("invalid account identity"))?,
    );
    let account = app.account_home().account(&context.label)?;
    let signer = app.account_signer_for_summary(&account)?;
    let outcome = app
        .relay_client_for_account_id(&context.account_id_hex, signer.as_nostr_signer())
        .publish_event_for_account(&account_id, &context.endpoints, &transport_event, 1)
        .await
        .map_err(|error| {
            AppError::account_publish_failure(&error, || {
                AppError::StickerRelay("sticker publication failed".into())
            })
        })?;
    if outcome.accepted.is_empty() {
        return Err(AppError::StickerRelay(
            "no account relay acknowledged the sticker publication".into(),
        ));
    }
    Ok(())
}

/// A sticker event is only ever published for the account that signed it.
fn require_account_author(event: &Event, account_id_hex: &str) -> Result<(), AppError> {
    if event.pubkey.to_hex() == account_id_hex {
        Ok(())
    } else {
        Err(AppError::ExternalSignerMismatch)
    }
}

async fn flush_sticker_outbox(
    app: &MarmotApp,
    context: &StickerAccountContext,
) -> Result<(), AppError> {
    // Kind-10031 outbox events are snapshots of an older remote base plus the
    // still-persisted local operations. Never replay that snapshot verbatim
    // after a refresh: even a lower-timestamp remote winner may contain packs
    // that were unknown when the snapshot was signed. Keep the operations and
    // let `publish_pending_installed_list` re-sign the freshly rebased desired
    // list. Pack events are self-contained and remain safe to replay.
    discard_outboxed_installed_lists(&context.storage)?;
    for pending in context.storage.sticker_outbox_events()? {
        let event = Event::from_json(&pending.event_json)
            .map_err(|_| invalid_sticker("stored sticker publication is invalid"))?;
        event
            .verify()
            .map_err(|_| invalid_sticker("stored sticker publication signature is invalid"))?;
        publish_account_event(app, context, &event).await?;
        apply_published_sticker_event(&context.storage, &event)?;
        context
            .storage
            .clear_sticker_outbox_event(&pending.event_id_hex)?;
    }
    Ok(())
}

fn discard_outboxed_installed_lists(storage: &SqliteAppStorage) -> Result<(), AppError> {
    for pending in storage.sticker_outbox_events()? {
        if pending.kind == u64::from(USER_STICKER_PACKS_KIND) {
            storage.clear_sticker_outbox_event(&pending.event_id_hex)?;
        }
    }
    Ok(())
}

fn apply_published_sticker_event(
    storage: &SqliteAppStorage,
    event: &Event,
) -> Result<(), AppError> {
    match event.kind {
        Kind::Custom(STICKER_PACK_KIND) => {
            let pack = stored_pack_from_event(event)?;
            storage.replace_sticker_pack_if_newer(&pack)?;
        }
        Kind::Custom(USER_STICKER_PACKS_KIND) => {
            let list = parse_installed_pack_list(&app_event_to_sonar(event)?)
                .map_err(|_| invalid_sticker("installed sticker list is invalid"))?;
            if list.packs.len() > MAX_INSTALLED_PACKS {
                return Err(invalid_sticker("too many installed sticker packs"));
            }
            let version = StoredStickerPackVersion {
                event_id_hex: event.id.to_hex(),
                created_at: event.created_at.as_secs(),
            };
            let packs = list
                .packs
                .into_iter()
                .map(|address| address.coordinate())
                .collect::<Vec<_>>();
            storage.commit_installed_sticker_publication(&version, &packs)?;
        }
        _ => return Err(invalid_sticker("unsupported sticker outbox event")),
    }
    Ok(())
}

fn app_pack_for_context(
    context: &StickerAccountContext,
    coordinate: &str,
) -> Result<AppStickerPack, AppError> {
    let installed = context
        .storage
        .desired_installed_sticker_packs()?
        .into_iter()
        .collect::<HashSet<_>>();
    context
        .storage
        .sticker_pack(coordinate)?
        .ok_or(AppError::StickerNotFound)
        .and_then(|pack| app_pack_from_stored(pack, &installed))
}

fn tolerate_offline(result: Result<(), AppError>) -> Result<(), AppError> {
    match result {
        Ok(()) | Err(AppError::StickerRelay(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

/// A publication the account's relays did not take, offline or too large for
/// every relay (mdk#2334), stays owed: its operation and outbox entry remain,
/// and the next sync publishes it again and reports a size refusal.
fn tolerate_unpublished(result: Result<(), AppError>) -> Result<(), AppError> {
    match result {
        Err(AppError::EventTooLarge { .. }) => Ok(()),
        result => tolerate_offline(result),
    }
}

struct StickerAccountContext {
    label: String,
    account_id_hex: String,
    storage: SqliteAppStorage,
    endpoints: Vec<TransportEndpoint>,
}

fn app_pack_from_stored(
    pack: StoredStickerPack,
    installed: &HashSet<String>,
) -> Result<AppStickerPack, AppError> {
    let coordinate = pack.coordinate.clone();
    Ok(AppStickerPack {
        installed: installed.contains(&coordinate),
        coordinate: coordinate.clone(),
        author_pubkey_hex: pack.author_pubkey_hex,
        identifier: pack.identifier,
        event_id_hex: pack.version.event_id_hex,
        created_at: pack.version.created_at,
        title: pack.title,
        description: pack.description,
        cover: pack
            .cover
            .map(|sticker| app_sticker_from_stored(coordinate.clone(), sticker)),
        stickers: pack
            .stickers
            .into_iter()
            .map(|sticker| app_sticker_from_stored(coordinate.clone(), sticker))
            .collect(),
        license: pack.license,
    })
}

fn app_sticker_from_stored(pack_coordinate: String, sticker: StoredSticker) -> AppSticker {
    AppSticker {
        pack_coordinate,
        shortcode: sticker.shortcode,
        url: sticker.url,
        sha256: sticker.sha256,
        mime: sticker.mime,
        width: sticker.width,
        height: sticker.height,
        alt: sticker.alt,
        emoji: sticker.emoji,
    }
}

fn stored_sticker(sticker: Sticker) -> StoredSticker {
    StoredSticker {
        shortcode: sticker.shortcode,
        url: sticker.url,
        sha256: sticker.sha256,
        mime: sticker.mime,
        width: sticker.width,
        height: sticker.height,
        alt: sticker.alt,
        emoji: sticker.emoji,
    }
}

fn stored_pack_from_event(event: &Event) -> Result<StoredStickerPack, AppError> {
    event
        .verify()
        .map_err(|_| invalid_sticker("sticker pack signature verification failed"))?;
    if event.created_at.as_secs() > unix_now_seconds().saturating_add(MAX_FUTURE_EVENT_SKEW_SECONDS)
    {
        return Err(invalid_sticker(
            "sticker pack timestamp is too far in the future",
        ));
    }
    let pack = parse_pack_event(&app_event_to_sonar(event)?)
        .map_err(|_| invalid_sticker("sticker pack metadata is invalid"))?;
    let coordinate = pack.address.coordinate();
    Ok(StoredStickerPack {
        coordinate,
        author_pubkey_hex: pack.address.author_pubkey_hex,
        identifier: pack.address.identifier,
        version: StoredStickerPackVersion {
            event_id_hex: event.id.to_hex(),
            created_at: event.created_at.as_secs(),
        },
        title: pack.title,
        description: pack.description,
        cover: pack.cover.map(stored_sticker),
        stickers: pack.stickers.into_iter().map(stored_sticker).collect(),
        license: pack.license,
    })
}

fn invalid_sticker(reason: &'static str) -> AppError {
    AppError::InvalidSticker(reason.to_owned())
}

fn validate_downloaded_sticker(sticker: &StoredSticker, bytes: &[u8]) -> Result<(), AppError> {
    validate_sticker_asset_size(bytes)?;
    if sha256_hex(bytes) != sticker.sha256 {
        return Err(invalid_sticker("sticker asset hash mismatch"));
    }
    let inspected = inspect_image(bytes)?;
    if inspected.mime != sticker.mime {
        return Err(invalid_sticker("sticker asset MIME mismatch"));
    }
    if sticker.width.is_some_and(|width| width != inspected.width)
        || sticker
            .height
            .is_some_and(|height| height != inspected.height)
    {
        return Err(invalid_sticker("sticker asset dimensions mismatch"));
    }
    Ok(())
}

fn validate_sticker_asset_size(bytes: &[u8]) -> Result<(), AppError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STICKER_ASSET_BYTES {
        return Err(invalid_sticker("sticker asset size is invalid"));
    }
    Ok(())
}

/// Sonar packs carry PNG/APNG, GIF and WebP. The shared inspector also reads
/// JPEG for custom emoji; a sticker asset keeps refusing it.
fn inspect_image(bytes: &[u8]) -> Result<InspectedImage, AppError> {
    let inspected = image_inspect::inspect_image(bytes)
        .map_err(|rejection| invalid_sticker(rejection.reason()))?;
    if inspected.mime == "image/jpeg" {
        return Err(invalid_sticker("unsupported sticker image format"));
    }
    Ok(inspected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_inspect::test_images::png;
    use nostr::prelude::{Keys, UnsignedEvent};
    use transport_nostr_peeler::{MarmotNostrSigner, MarmotSignerError, SignerFuture};

    #[derive(Debug)]
    struct RejectStickerSigner {
        keys: Keys,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MarmotNostrSigner for RejectStickerSigner {
        fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, MarmotSignerError>> {
            MarmotNostrSigner::get_public_key(&self.keys)
        }

        fn sign_event(
            &self,
            _unsigned: UnsignedEvent,
        ) -> SignerFuture<'_, Result<Event, MarmotSignerError>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Err(MarmotSignerError::from(
                    crate::external_signer::EXTERNAL_SIGNER_REJECTED,
                ))
            })
        }

        fn nip04_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip04_encrypt(&self.keys, public_key, content)
        }

        fn nip04_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            payload: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip04_decrypt(&self.keys, public_key, payload)
        }

        fn nip44_encrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            content: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip44_encrypt(&self.keys, public_key, content)
        }

        fn nip44_decrypt<'a>(
            &'a self,
            public_key: &'a PublicKey,
            payload: &'a str,
        ) -> SignerFuture<'a, Result<String, MarmotSignerError>> {
            MarmotNostrSigner::nip44_decrypt(&self.keys, public_key, payload)
        }
    }

    impl marmot_session::AccountIdentityProofSigner for RejectStickerSigner {
        fn sign_account_identity_proof(
            &self,
            _request: &marmot_session::AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            Err(crate::external_signer::EXTERNAL_SIGNER_REJECTED.to_owned())
        }
    }

    async fn external_sticker_fixture() -> (
        tempfile::TempDir,
        MarmotApp,
        Keys,
        String,
        String,
        nostr_relay_builder::LocalRelay,
    ) {
        use nostr_relay_builder::prelude::{
            MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, RelayBuilder,
        };

        let keys = Keys::generate();
        let pack = StickerPack::new(
            PackAddress::new(keys.public_key().to_hex(), "cats".to_owned()).unwrap(),
            "Cats".to_owned(),
            None,
            None,
            vec![
                Sticker::new(
                    "wave".to_owned(),
                    format!("https://cdn.example/{}.png", "11".repeat(32)),
                    "11".repeat(32),
                    "image/png".to_owned(),
                    Some(32),
                    Some(32),
                    None,
                    None,
                )
                .unwrap(),
            ],
            None,
        )
        .unwrap();
        let event = EventBuilder::new(Kind::Custom(STICKER_PACK_KIND), "")
            .tags(
                build_pack_tags(&pack)
                    .into_iter()
                    .map(|tag| sonar_tag_to_app(tag).unwrap())
                    .collect::<Vec<_>>(),
            )
            .finalize(&keys)
            .unwrap();
        let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(8),
        });
        database
            .save_event(&serde_json::from_str(&event.as_json()).unwrap())
            .await
            .unwrap();
        let relay =
            nostr_relay_builder::LocalRelay::new(RelayBuilder::default().database(database));
        relay.run().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let home = crate::AccountHome::open(directory.path());
        let account = home
            .add_external_signer_account(&keys.public_key().to_hex())
            .unwrap();
        let app = MarmotApp::with_relays_and_account_home_and_config(
            directory.path(),
            vec![relay.url().await.to_string()],
            home,
            crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
        );
        let coordinate = format!("30031:{}:cats", keys.public_key().to_hex());
        (
            directory,
            app,
            keys,
            account.account_id_hex,
            coordinate,
            relay,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unsigned_external_pack_fetch() {
        let (directory, app, _keys, account_id, coordinate, relay) =
            external_sticker_fixture().await;
        assert!(!app.has_external_signer(&account_id));
        let context = app.sticker_context(&account_id).unwrap();
        assert!(context.storage.sticker_pack(&coordinate).unwrap().is_none());

        let pack = app
            .fetch_sticker_pack(&account_id, &coordinate)
            .await
            .unwrap();

        assert_eq!(pack.coordinate, coordinate);
        assert_eq!(pack.title, "Cats");
        assert!(!pack.installed);
        assert!(context.storage.sticker_pack(&coordinate).unwrap().is_some());
        assert!(!app.has_external_signer(&account_id));
        drop(context);
        drop(app);
        let app = MarmotApp::with_relays_and_account_home_and_config(
            directory.path(),
            vec!["wss://different.example".to_owned()],
            crate::AccountHome::open(directory.path()),
            crate::MarmotAppConfig::default(),
        );
        let link = app
            .sticker_pack_share_link(&account_id, &coordinate)
            .unwrap();
        assert_eq!(
            parse_sticker_pack_input_with_relays(&link).unwrap(),
            ParsedStickerPackInput {
                coordinate,
                relay_hints: vec![TransportEndpoint(relay.url().await.to_string())],
            }
        );
    }

    enum StickerAction {
        Install,
        Uninstall,
    }

    async fn reject_keeps_intent(action: StickerAction) {
        let install = matches!(action, StickerAction::Install);
        for prior_intent in [false, true] {
            let (_directory, app, keys, account_id, coordinate, _relay) =
                external_sticker_fixture().await;
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            app.register_external_signer(
                &account_id,
                RejectStickerSigner {
                    keys,
                    calls: calls.clone(),
                },
            )
            .await
            .unwrap();
            let context = app.sticker_context(&account_id).unwrap();
            if prior_intent {
                // The rejected mutation would replace this row, not merely
                // append a new operation, and must preserve unrelated intent.
                context
                    .storage
                    .enqueue_sticker_install_operation(&coordinate, !install, 1)
                    .unwrap();
                context
                    .storage
                    .enqueue_sticker_install_operation(&self::coordinate(), true, 2)
                    .unwrap();
            }
            let before = context.storage.sticker_install_operations().unwrap();
            let desired = context.storage.desired_installed_sticker_packs().unwrap();

            let result = if install {
                app.install_sticker_pack(&account_id, &coordinate)
                    .await
                    .map(|_| ())
            } else {
                app.uninstall_sticker_pack(&account_id, &coordinate).await
            };

            assert!(
                matches!(result, Err(AppError::ExternalSignerRejected)),
                "prior_intent={prior_intent}: {result:?}"
            );
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                context.storage.sticker_install_operations().unwrap(),
                before
            );
            assert_eq!(
                context.storage.desired_installed_sticker_packs().unwrap(),
                desired
            );
            assert!(context.storage.sticker_outbox_events().unwrap().is_empty());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn install_reject_keeps_intent() {
        reject_keeps_intent(StickerAction::Install).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn uninstall_reject_keeps_intent() {
        reject_keeps_intent(StickerAction::Uninstall).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn future_list_keeps_intent() {
        for install in [false, true] {
            let (_directory, app, keys, account_id, coordinate, _relay) =
                external_sticker_fixture().await;
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            app.register_external_signer(
                &account_id,
                RejectStickerSigner {
                    keys,
                    calls: calls.clone(),
                },
            )
            .await
            .unwrap();
            let context = app.sticker_context(&account_id).unwrap();
            context
                .storage
                .replace_installed_sticker_packs_if_newer(
                    &StoredStickerPackVersion {
                        event_id_hex: "ef".repeat(32),
                        created_at: unix_now_seconds() + MAX_FUTURE_EVENT_SKEW_SECONDS + 60,
                    },
                    &[],
                )
                .unwrap();
            context
                .storage
                .enqueue_sticker_install_operation(&coordinate, !install, 1)
                .unwrap();
            let before = context.storage.sticker_install_operations().unwrap();

            let result = if install {
                app.install_sticker_pack(&account_id, &coordinate)
                    .await
                    .map(|_| ())
            } else {
                app.uninstall_sticker_pack(&account_id, &coordinate).await
            };

            assert!(matches!(result, Err(AppError::InvalidSticker(_))));
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(
                context.storage.sticker_install_operations().unwrap(),
                before
            );
            assert!(context.storage.sticker_outbox_events().unwrap().is_empty());
        }
    }

    fn coordinate() -> String {
        format!("30031:{}:cats", "ab".repeat(32))
    }

    #[test]
    fn sticker_tag_roundtrips_and_ambiguous_tags_are_rejected() {
        let sticker_ref = AppStickerRef {
            pack_coordinate: coordinate(),
            shortcode: "wave".to_owned(),
            plaintext_sha256: "11".repeat(32),
        };
        let tag = sticker_ref_tag(&sticker_ref).unwrap();
        assert_eq!(
            sticker_ref_from_tags(9, std::slice::from_ref(&tag)),
            Some(sticker_ref)
        );
        assert!(sticker_ref_from_tags(1, std::slice::from_ref(&tag)).is_none());
        assert!(sticker_ref_from_tags(9, &[tag, vec!["sticker".to_owned()]]).is_none());
    }

    #[test]
    fn pack_input_accepts_only_canonical_and_trusted_sonar_links() {
        let coordinate = coordinate();
        assert_eq!(parse_sticker_pack_input(&coordinate).unwrap(), coordinate);
        let link = format!(
            "https://sonarprivacy.xyz/stickers?a={coordinate}\
             &relay=wss%3A%2F%2Frelay.damus.io\
             &relay=wss%3A%2F%2Fnos.lol\
             &relay=wss%3A%2F%2Fnos.lol\
             &relay=not-a-relay"
        );
        assert_eq!(parse_sticker_pack_input(&link).unwrap(), coordinate);
        assert_eq!(
            parse_sticker_pack_input_with_relays(&link)
                .unwrap()
                .relay_hints,
            vec![
                TransportEndpoint("wss://relay.damus.io".to_owned()),
                TransportEndpoint("wss://nos.lol".to_owned()),
            ]
        );
        assert!(
            parse_sticker_pack_input(&format!("https://evil.test/stickers?a={coordinate}"))
                .is_err()
        );
        assert!(
            parse_sticker_pack_input(&format!(
                "https://attacker@sonarprivacy.xyz/stickers?a={coordinate}"
            ))
            .is_err()
        );
        assert!(parse_sticker_pack_input("http://sonarprivacy.xyz/stickers").is_err());
    }

    #[test]
    fn share_link_roundtrip() {
        let coordinate = format!("30031:{}:cats._-", "ab".repeat(32));
        let address = PackAddress::parse(&coordinate).unwrap();
        let relays = (0..10).map(|index| format!("wss://relay{index}.example/path?q=a&b=c"));
        let link = build_sticker_share_link(
            &address,
            [
                "invalid".to_owned(),
                "wss://relay0.example/path?q=a&b=c".to_owned(),
            ]
            .into_iter()
            .chain(relays),
        );
        assert!(link.starts_with("https://sonarprivacy.xyz/stickers?a=30031%3A"));
        assert_eq!(
            parse_sticker_pack_input_with_relays(&link).unwrap(),
            ParsedStickerPackInput {
                coordinate,
                relay_hints: (0..8)
                    .map(|index| TransportEndpoint(format!(
                        "wss://relay{index}.example/path?q=a&b=c"
                    )))
                    .collect(),
            }
        );
        let bare = build_sticker_share_link(&PackAddress::parse(&self::coordinate()).unwrap(), []);
        assert_eq!(parse_sticker_pack_input(&bare).unwrap(), self::coordinate());
        assert_eq!(Url::parse(&bare).unwrap().query_pairs().count(), 1);
    }

    #[test]
    fn share_link_length_limit() {
        let coordinate = coordinate();
        let link = build_sticker_share_link(
            &PackAddress::parse(&coordinate).unwrap(),
            [
                format!("wss://relay.example/{}", "a".repeat(MAX_LINK_CHARS)),
                "wss://short.example".to_owned(),
            ],
        );
        assert!(link.len() <= MAX_LINK_CHARS);
        assert_eq!(
            parse_sticker_pack_input_with_relays(&link).unwrap(),
            ParsedStickerPackInput {
                coordinate,
                relay_hints: vec![TransportEndpoint("wss://short.example".to_owned())],
            }
        );
    }

    #[test]
    fn future_pack_event_is_rejected_before_it_can_freeze_replacement_state() {
        let keys = nostr::prelude::Keys::generate();
        let pack = StickerPack::new(
            PackAddress::new(keys.public_key().to_hex(), "cats".to_owned()).unwrap(),
            "Cats".to_owned(),
            None,
            None,
            vec![
                Sticker::new(
                    "wave".to_owned(),
                    format!("https://cdn.example/{}.png", "11".repeat(32)),
                    "11".repeat(32),
                    "image/png".to_owned(),
                    Some(32),
                    Some(32),
                    None,
                    None,
                )
                .unwrap(),
            ],
            None,
        )
        .unwrap();
        let event = EventBuilder::new(Kind::Custom(STICKER_PACK_KIND), "")
            .tags(
                build_pack_tags(&pack)
                    .into_iter()
                    .map(|tag| sonar_tag_to_app(tag).unwrap())
                    .collect::<Vec<_>>(),
            )
            .custom_created_at(NostrTimestamp::from_secs(
                unix_now_seconds() + MAX_FUTURE_EVENT_SKEW_SECONDS + 1,
            ))
            .finalize(&keys)
            .unwrap();

        assert!(stored_pack_from_event(&event).is_err());
    }

    #[test]
    fn signal_import_only_accepts_the_canonical_https_origin() {
        assert!(
            validate_signal_sticker_link(
                "https://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef&pack_key=def"
            )
            .is_ok()
        );
        assert!(
            validate_signal_sticker_link(
                "https://signal.art/addstickers?pack_id=0123456789abcdef0123456789abcdef&pack_key=def"
            )
            .is_ok()
        );
        assert!(
            validate_signal_sticker_link(
                "https://evil.test/addstickers/#pack_id=0123456789abcdef0123456789abcdef&pack_key=def"
            )
            .is_err()
        );
        assert!(
            validate_signal_sticker_link(
                "http://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef&pack_key=def"
            )
            .is_err()
        );
        assert!(
            validate_signal_sticker_link(
                "https://signal.art:8443/addstickers/#pack_id=0123456789abcdef0123456789abcdef&pack_key=def"
            )
            .is_err()
        );
        assert!(
            validate_signal_sticker_link(
                "https://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef"
            )
            .is_err()
        );
        assert!(
            validate_signal_sticker_link(
                "https://signal.art/addstickers/#pack_id=abc&pack_key=def"
            )
            .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signal_import_is_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(directory.path(), Vec::new());
        let result = app.import_signal_sticker_pack(
            "not-an-account",
            "https://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef&pack_key=def".to_owned(),
            None,
        ).await;
        assert!(matches!(result, Err(AppError::StickerImport(_))));
    }

    #[test]
    fn sticker_publications_must_be_authored_by_the_account() {
        let keys = nostr::prelude::Keys::generate();
        let event = EventBuilder::new(Kind::Custom(USER_STICKER_PACKS_KIND), "")
            .finalize(&keys)
            .unwrap();
        assert!(require_account_author(&event, &keys.public_key().to_hex()).is_ok());
        let other = nostr::prelude::Keys::generate().public_key().to_hex();
        assert!(matches!(
            require_account_author(&event, &other),
            Err(AppError::ExternalSignerMismatch)
        ));
    }

    #[test]
    fn install_capacity_rejects_only_a_new_pack_at_the_limit() {
        let installed = (0..MAX_INSTALLED_PACKS)
            .map(|index| format!("pack-{index}"))
            .collect::<Vec<_>>();
        assert!(validate_install_capacity(&installed, "pack-new").is_err());
        assert!(validate_install_capacity(&installed, "pack-0").is_ok());
    }

    #[test]
    fn outboxed_installed_snapshot_is_discarded_without_clearing_rebase_operations() {
        let storage = storage_sqlite::SqliteAccountStorage::in_memory()
            .unwrap()
            .app_storage();
        storage
            .enqueue_sticker_install_operation("pack-b", true, 6)
            .unwrap();
        storage
            .put_sticker_outbox_event(&StoredStickerOutboxEvent {
                event_id_hex: "ef".repeat(32),
                kind: u64::from(USER_STICKER_PACKS_KIND),
                event_json: "{}".to_owned(),
                created_at: 7,
            })
            .unwrap();

        discard_outboxed_installed_lists(&storage).unwrap();

        assert!(storage.sticker_outbox_events().unwrap().is_empty());
        assert_eq!(storage.sticker_install_operations().unwrap().len(), 1);
        assert_eq!(
            storage.desired_installed_sticker_packs().unwrap(),
            vec!["pack-b".to_owned()]
        );
    }

    #[test]
    fn sticker_asset_size_rejects_empty_and_oversized_buffers() {
        assert!(validate_sticker_asset_size(&[]).is_err());
        assert!(
            validate_sticker_asset_size(&vec![0; MAX_STICKER_ASSET_BYTES as usize + 1]).is_err()
        );
    }

    #[test]
    fn downloaded_asset_requires_exact_hash_mime_and_dimensions() {
        let bytes = png(64, 32, None);
        let sticker = StoredSticker {
            shortcode: "wave".to_owned(),
            url: "https://example.test/hash.png".to_owned(),
            sha256: sha256_hex(&bytes),
            mime: "image/png".to_owned(),
            width: Some(64),
            height: Some(32),
            alt: None,
            emoji: None,
        };
        assert!(validate_downloaded_sticker(&sticker, &bytes).is_ok());
        let mut wrong_hash = sticker.clone();
        wrong_hash.sha256 = "00".repeat(32);
        assert!(validate_downloaded_sticker(&wrong_hash, &bytes).is_err());
        let mut wrong_mime = sticker.clone();
        wrong_mime.mime = "image/webp".to_owned();
        assert!(validate_downloaded_sticker(&wrong_mime, &bytes).is_err());
        let mut wrong_width = sticker.clone();
        wrong_width.width = Some(65);
        assert!(validate_downloaded_sticker(&wrong_width, &bytes).is_err());
        let mut wrong_height = sticker.clone();
        wrong_height.height = Some(31);
        assert!(validate_downloaded_sticker(&wrong_height, &bytes).is_err());
    }
}
