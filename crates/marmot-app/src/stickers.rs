use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cgka_traits::TransportEndpoint;
use nostr::nips::nip19::{FromBech32, Nip19Coordinate};
use nostr::{
    Alphabet, Event, EventBuilder, Filter, JsonUtil, Kind, NostrSigner, PublicKey, SingleLetterTag,
    Tag, Timestamp as NostrTimestamp,
};
use serde::{Deserialize, Serialize};
use sonar_stickers::{
    InstalledPackList, PACK_FORMAT, PackAddress, STICKER_PACK_KIND, Sticker, StickerPack,
    StickerRef, USER_STICKER_PACKS_KIND, build_installed_packs_tags, build_pack_tags,
    build_sticker_ref_tag, parse_installed_pack_list, parse_pack_event, parse_sticker_ref_tag,
    sha256_hex,
};
use storage_sqlite::{
    SqliteAccountStorage, StoredSticker, StoredStickerOutboxEvent, StoredStickerPack,
    StoredStickerPackVersion,
};
use url::Url;
use zeroize::Zeroizing;

use crate::external_signer::AccountSigner;
use crate::media::{fetch_blossom_blob_limited, upload_blossom_blob};
use crate::{AppError, MarmotApp, ReceivedMessage, unix_now_seconds};

pub const DEFAULT_STICKER_BLOSSOM_SERVER_URL: &str = "https://nostr.download";
const MAX_STICKER_ASSET_BYTES: u64 = 4 * 1024 * 1024;
const MAX_STICKER_DIMENSION: u32 = 4096;
const MAX_STICKER_PIXELS: u64 = 4096 * 4096;
const MAX_STICKER_ANIMATION_FRAMES: u32 = 200;
const MAX_DISCOVERY_PACKS: usize = 100;
const MAX_INSTALLED_PACKS: usize = 100;
const MAX_LINK_CHARS: usize = 2048;
const MAX_FUTURE_EVENT_SKEW_SECONDS: u64 = 5 * 60;

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
    parse_sticker_ref_tag(&tag).ok().map(Into::into)
}

pub fn sticker_ref_from_message(message: &ReceivedMessage) -> Option<AppStickerRef> {
    sticker_ref_from_tags(message.kind, &message.tags)
}

pub(crate) fn sticker_ref_tag(sticker_ref: &AppStickerRef) -> Result<Vec<String>, AppError> {
    Ok(build_sticker_ref_tag(&sticker_ref.to_sdk()?).to_vec())
}

/// Accept a canonical coordinate, an NIP-19 `naddr`/`nostr:naddr`, or Sonar's
/// documented HTTPS viewer link. Relay hints embedded in links are deliberately
/// ignored; only the account's already-approved relay set is used for fetches.
pub fn parse_sticker_pack_input(input: &str) -> Result<String, AppError> {
    let input = input.trim();
    if input.is_empty() || input.chars().count() > MAX_LINK_CHARS {
        return Err(invalid_sticker("invalid sticker pack link"));
    }
    if let Ok(address) = PackAddress::parse(input) {
        return Ok(address.coordinate());
    }
    let bech32 = input.strip_prefix("nostr:").unwrap_or(input);
    if bech32.starts_with("naddr1") {
        let coordinate = Nip19Coordinate::from_bech32(bech32)
            .map_err(|_| invalid_sticker("invalid sticker pack address"))?;
        if coordinate.coordinate.kind != Kind::Custom(STICKER_PACK_KIND) {
            return Err(invalid_sticker("sticker pack address has the wrong kind"));
        }
        return PackAddress::new(
            coordinate.coordinate.public_key.to_hex(),
            coordinate.coordinate.identifier,
        )
        .map(|address| address.coordinate())
        .map_err(|_| invalid_sticker("invalid sticker pack address"));
    }
    let url = Url::parse(input).map_err(|_| invalid_sticker("invalid sticker pack link"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || !url
            .host_str()
            .is_some_and(|host| matches!(host, "sonarprivacy.xyz" | "www.sonarprivacy.xyz"))
        || url.path().trim_end_matches('/') != "/stickers"
    {
        return Err(invalid_sticker("untrusted sticker pack link"));
    }
    let value = url
        .query_pairs()
        .find_map(|(key, value)| (key == "a").then(|| value.into_owned()))
        .ok_or_else(|| invalid_sticker("sticker pack link is missing its address"))?;
    parse_sticker_pack_input(&value)
}

fn validate_signal_sticker_link(input: &str) -> Result<(), AppError> {
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
    if parameters
        .get("pack_id")
        .is_none_or(|value| value.is_empty())
        || parameters
            .get("pack_key")
            .is_none_or(|value| value.is_empty())
    {
        return Err(invalid_sticker(
            "Signal sticker link is missing credentials",
        ));
    }
    Ok(())
}

impl MarmotApp {
    pub fn sticker_packs(
        &self,
        account_ref: &str,
        installed_only: bool,
        search: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<AppStickerPack>, AppError> {
        let account = self.account_home().account(account_ref)?;
        let storage = self.account_storage(&account.label)?;
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
        let storage = self.account_storage(&account.label)?;
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
        let stored = self
            .account_storage(&account.label)?
            .sticker_for_ref(
                &sticker_ref.pack.coordinate(),
                &sticker_ref.shortcode,
                &sticker_ref.plaintext_sha256,
            )?
            .ok_or(AppError::StickerNotFound)?;
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
        refresh_installed_base(self, &context).await?;
        tolerate_offline(flush_sticker_outbox(self, &context).await)?;

        let filter = Filter::new()
            .kind(Kind::Custom(STICKER_PACK_KIND))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::T),
                PACK_FORMAT.to_owned(),
            )
            .limit(MAX_DISCOVERY_PACKS);
        let events = self
            .relay_plane
            .fetch_public_events(context.endpoints.clone(), filter)
            .await
            .map_err(AppError::StickerRelay)?;
        let discovered = events.len().min(MAX_DISCOVERY_PACKS);
        let updated = ingest_pack_events(&context.storage, events)?;

        let desired = context.storage.desired_installed_sticker_packs()?;
        for coordinate in desired.iter().take(MAX_INSTALLED_PACKS) {
            if context.storage.sticker_pack(coordinate)?.is_none() {
                let _ = fetch_pack_into_storage(self, &context, coordinate).await;
            }
        }
        publish_pending_installed_list(self, &context).await?;
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
        let coordinate = parse_sticker_pack_input(input)?;
        let context = self.sticker_context(account_ref)?;
        let mutation_lock = self.sticker_mutation_lock(&context.label);
        let _guard = mutation_lock.lock().await;
        fetch_pack_into_storage(self, &context, &coordinate).await?;
        app_pack_for_context(&context, &coordinate)
    }

    pub async fn install_sticker_pack(
        &self,
        account_ref: &str,
        input: &str,
    ) -> Result<AppStickerPack, AppError> {
        let coordinate = parse_sticker_pack_input(input)?;
        let context = self.sticker_context(account_ref)?;
        let mutation_lock = self.sticker_mutation_lock(&context.label);
        let _guard = mutation_lock.lock().await;
        rebase_and_flush_sticker_outbox_best_effort(self, &context).await?;
        if context.storage.sticker_pack(&coordinate)?.is_none() {
            fetch_pack_into_storage(self, &context, &coordinate).await?;
        } else {
            // A validated cached pack is enough to record an install while
            // offline. Refresh opportunistically without making connectivity
            // a precondition for the user's local intent.
            tolerate_offline(
                fetch_pack_into_storage(self, &context, &coordinate)
                    .await
                    .map(|_| ()),
            )?;
        }
        let desired = context.storage.desired_installed_sticker_packs()?;
        validate_install_capacity(&desired, &coordinate)?;
        context
            .storage
            .enqueue_sticker_install_operation(&coordinate, true, unix_now_seconds())?;
        tolerate_offline(publish_pending_installed_list(self, &context).await)?;
        app_pack_for_context(&context, &coordinate)
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
        rebase_and_flush_sticker_outbox_best_effort(self, &context).await?;
        context.storage.enqueue_sticker_install_operation(
            &coordinate,
            false,
            unix_now_seconds(),
        )?;
        tolerate_offline(publish_pending_installed_list(self, &context).await)
    }

    /// Import/decrypt a Signal pack with `sonar-stickers`, validate every
    /// plaintext image, upload content-addressed public bytes to Blossom, then
    /// publish and install the Sonar pack. The link is zeroized by this wrapper
    /// and is never persisted. External-signing accounts are explicitly gated:
    /// Blossom requires one authorization signature per asset, which would
    /// otherwise trigger up to 200 Amber prompts.
    pub async fn import_signal_sticker_pack(
        &self,
        account_ref: &str,
        signal_link: String,
        blossom_server: Option<&str>,
    ) -> Result<AppStickerImportResult, AppError> {
        let signal_link = Zeroizing::new(signal_link);
        validate_signal_sticker_link(signal_link.as_str())?;
        let context = self.sticker_context(account_ref)?;
        if !context.local_signing {
            return Err(AppError::StickerExternalSignerImportUnsupported);
        }
        let mutation_lock = self.sticker_mutation_lock(&context.label);
        let _guard = mutation_lock.lock().await;

        let imported = sonar_stickers::signal::import_signal_pack(signal_link.as_str())
            .await
            .map_err(|_| AppError::StickerImport("Signal pack could not be imported".into()))?;
        let server = blossom_server
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .unwrap_or(DEFAULT_STICKER_BLOSSOM_SERVER_URL);
        let signer = context.signer.as_nostr_signer();
        let mut stickers_by_id = HashMap::new();
        let mut stickers = Vec::with_capacity(imported.stickers.len());
        for imported_sticker in &imported.stickers {
            let inspected = inspect_image(&imported_sticker.bytes)?;
            if sha256_hex(&imported_sticker.bytes) != imported_sticker.sha256 {
                return Err(invalid_sticker("Signal sticker hash mismatch"));
            }
            let url = upload_blossom_blob(
                server,
                &imported_sticker.bytes,
                &imported_sticker.sha256,
                signer.as_ref(),
                self.allow_loopback_blob_endpoints(),
            )
            .await
            .map_err(|_| AppError::StickerImport("sticker asset upload failed".into()))?;
            let sticker = Sticker::new(
                imported_sticker.shortcode.clone(),
                url,
                imported_sticker.sha256.clone(),
                inspected.mime,
                Some(inspected.width),
                Some(inspected.height),
                imported_sticker
                    .emoji
                    .as_ref()
                    .map(|emoji| format!("{emoji} sticker")),
                imported_sticker.emoji.clone(),
            )
            .map_err(|_| invalid_sticker("imported sticker metadata is invalid"))?;
            stickers_by_id.insert(imported_sticker.id, sticker.clone());
            stickers.push(sticker);
        }
        let cover = imported
            .cover
            .as_ref()
            .and_then(|cover| stickers_by_id.get(&cover.id))
            .filter(|sticker| sticker.mime == "image/webp")
            .cloned();
        let address = PackAddress::new(
            context.account_id_hex.clone(),
            format!("signal-{}", imported.pack_id),
        )
        .map_err(|_| invalid_sticker("imported pack address is invalid"))?;
        let description = imported
            .author
            .as_deref()
            .map(|author| truncate_chars(author.trim(), 500))
            .filter(|author| !author.is_empty());
        let pack = StickerPack::new(
            address,
            truncate_chars(imported.title.trim(), 80),
            description,
            cover,
            stickers,
            None,
        )
        .map_err(|_| invalid_sticker("imported sticker pack is invalid"))?;
        let coordinate = pack.address.coordinate();
        let created_at = next_pack_publication_timestamp(&context.storage, &coordinate)?;
        let event = sign_public_event(
            &context,
            STICKER_PACK_KIND,
            build_pack_tags(&pack),
            created_at,
        )
        .await?;
        publish_outboxed_event(self, &context, &event).await?;
        // The newly published pack is already durable locally. A transient
        // relay read must not prevent recording the user's install intent;
        // the same pending-operation projection used by normal installs will
        // reconcile it on the next sync.
        tolerate_offline(refresh_installed_base(self, &context).await)?;
        let desired = context.storage.desired_installed_sticker_packs()?;
        validate_install_capacity(&desired, &coordinate)?;
        context
            .storage
            .enqueue_sticker_install_operation(&coordinate, true, unix_now_seconds())?;
        tolerate_offline(publish_pending_installed_list(self, &context).await)?;
        Ok(AppStickerImportResult {
            pack: app_pack_for_context(&context, &coordinate)?,
            skipped_signal_sticker_ids: imported.skipped_sticker_ids,
        })
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
        let relay_lists = self.account_relay_list_status_for_account_id(&account.account_id_hex)?;
        let endpoints = self.key_package_endpoints(&relay_lists);
        if endpoints.is_empty() {
            return Err(AppError::StickerRelay(
                "no account relays configured".into(),
            ));
        }
        let signer = self.account_signer_for_summary(&account)?;
        Ok(StickerAccountContext {
            label: account.label.clone(),
            account_id_hex: account.account_id_hex,
            local_signing: account.local_signing,
            storage: self.account_storage(&account.label)?,
            endpoints,
            signer,
        })
    }
}

async fn fetch_pack_into_storage(
    app: &MarmotApp,
    context: &StickerAccountContext,
    coordinate: &str,
) -> Result<bool, AppError> {
    let address = PackAddress::parse(coordinate)
        .map_err(|_| invalid_sticker("invalid sticker pack coordinate"))?;
    let author = PublicKey::parse(&address.author_pubkey_hex)
        .map_err(|_| invalid_sticker("invalid sticker pack author"))?;
    let filter = Filter::new()
        .author(author)
        .kind(Kind::Custom(STICKER_PACK_KIND))
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            address.identifier.clone(),
        )
        .limit(16);
    let events = app
        .relay_plane
        .fetch_public_events(context.endpoints.clone(), filter)
        .await
        .map_err(AppError::StickerRelay)?;
    let mut updated = false;
    for event in events {
        let stored = match stored_pack_from_event(&event) {
            Ok(pack) if pack.coordinate == coordinate => pack,
            _ => continue,
        };
        updated |= context.storage.replace_sticker_pack_if_newer(&stored)?;
    }
    if context.storage.sticker_pack(coordinate)?.is_none() {
        return Err(AppError::StickerNotFound);
    }
    Ok(updated)
}

fn ingest_pack_events(
    storage: &SqliteAccountStorage,
    events: Vec<Event>,
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
    }
    Ok(updated)
}

/// Refresh the remote installed-list winner before flushing any locally
/// outboxed kind-10031 event. If the account is offline, leave both outbox and
/// operations untouched so the next successful refresh can rebase first.
async fn rebase_and_flush_sticker_outbox_best_effort(
    app: &MarmotApp,
    context: &StickerAccountContext,
) -> Result<(), AppError> {
    match refresh_installed_base(app, context).await {
        Ok(()) => tolerate_offline(flush_sticker_outbox(app, context).await),
        Err(AppError::StickerRelay(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_install_capacity(desired: &[String], coordinate: &str) -> Result<(), AppError> {
    if desired.len() >= MAX_INSTALLED_PACKS && !desired.iter().any(|pack| pack == coordinate) {
        return Err(invalid_sticker("too many installed sticker packs"));
    }
    Ok(())
}

async fn refresh_installed_base(
    app: &MarmotApp,
    context: &StickerAccountContext,
) -> Result<(), AppError> {
    let author = PublicKey::parse(&context.account_id_hex)
        .map_err(|_| invalid_sticker("invalid account identity"))?;
    let filter = Filter::new()
        .author(author)
        .kind(Kind::Custom(USER_STICKER_PACKS_KIND))
        .limit(16);
    let mut candidates = app
        .relay_plane
        .fetch_public_events(context.endpoints.clone(), filter)
        .await
        .map_err(AppError::StickerRelay)?
        .into_iter()
        .filter(|event| {
            event.pubkey.to_hex() == context.account_id_hex
                && event.kind == Kind::Custom(USER_STICKER_PACKS_KIND)
                && event.verify().is_ok()
                && event.created_at.as_secs()
                    <= unix_now_seconds().saturating_add(MAX_FUTURE_EVENT_SKEW_SECONDS)
        })
        .filter_map(|event| {
            let list = parse_installed_pack_list(&event).ok()?;
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
    let desired = context.storage.desired_installed_sticker_packs()?;
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
    let event = sign_public_event(
        context,
        USER_STICKER_PACKS_KIND,
        build_installed_packs_tags(&InstalledPackList::new(addresses)),
        next_installed_list_publication_timestamp(&context.storage)?,
    )
    .await?;
    publish_outboxed_event(app, context, &event).await
}

fn next_installed_list_publication_timestamp(
    storage: &SqliteAccountStorage,
) -> Result<u64, AppError> {
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

fn next_pack_publication_timestamp(
    storage: &SqliteAccountStorage,
    coordinate: &str,
) -> Result<u64, AppError> {
    let now = unix_now_seconds();
    let stored_created_at = storage
        .sticker_pack(coordinate)?
        .map(|pack| pack.version.created_at);
    let mut outbox_created_at: Option<u64> = None;
    for pending in storage
        .sticker_outbox_events()?
        .into_iter()
        .filter(|event| event.kind == u64::from(STICKER_PACK_KIND))
    {
        let Ok(event) = Event::from_json(&pending.event_json) else {
            continue;
        };
        let Ok(pack) = parse_pack_event(&event) else {
            continue;
        };
        if pack.address.coordinate() == coordinate {
            outbox_created_at = Some(
                outbox_created_at
                    .unwrap_or_default()
                    .max(event.created_at.as_secs()),
            );
        }
    }
    next_monotonic_publication_timestamp(
        now,
        stored_created_at.into_iter().chain(outbox_created_at).max(),
        "sticker-pack timestamp is too far in the future",
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
    context: &StickerAccountContext,
    kind: u16,
    tags: Vec<Tag>,
    created_at: u64,
) -> Result<Event, AppError> {
    let signer = context.signer.as_nostr_signer();
    let public_key = signer
        .get_public_key()
        .await
        .map_err(|error| crate::external_signer_error(error, "sticker public key"))?;
    if public_key.to_hex() != context.account_id_hex {
        return Err(AppError::ExternalSignerMismatch);
    }
    let unsigned = EventBuilder::new(Kind::Custom(kind), "")
        .tags(tags)
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .build(public_key);
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
    app.relay_plane
        .publish_public_event(context.endpoints.clone(), event)
        .await
        .map_err(AppError::StickerRelay)?;
    apply_published_sticker_event(&context.storage, event)?;
    context
        .storage
        .clear_sticker_outbox_event(&event.id.to_hex())?;
    Ok(())
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
        app.relay_plane
            .publish_public_event(context.endpoints.clone(), &event)
            .await
            .map_err(AppError::StickerRelay)?;
        apply_published_sticker_event(&context.storage, &event)?;
        context
            .storage
            .clear_sticker_outbox_event(&pending.event_id_hex)?;
    }
    Ok(())
}

fn discard_outboxed_installed_lists(storage: &SqliteAccountStorage) -> Result<(), AppError> {
    for pending in storage.sticker_outbox_events()? {
        if pending.kind == u64::from(USER_STICKER_PACKS_KIND) {
            storage.clear_sticker_outbox_event(&pending.event_id_hex)?;
        }
    }
    Ok(())
}

fn apply_published_sticker_event(
    storage: &SqliteAccountStorage,
    event: &Event,
) -> Result<(), AppError> {
    match event.kind {
        Kind::Custom(STICKER_PACK_KIND) => {
            let pack = stored_pack_from_event(event)?;
            storage.replace_sticker_pack_if_newer(&pack)?;
        }
        Kind::Custom(USER_STICKER_PACKS_KIND) => {
            let list = parse_installed_pack_list(event)
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

fn truncate_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn tolerate_offline(result: Result<(), AppError>) -> Result<(), AppError> {
    match result {
        Ok(()) | Err(AppError::StickerRelay(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

struct StickerAccountContext {
    label: String,
    account_id_hex: String,
    local_signing: bool,
    storage: SqliteAccountStorage,
    endpoints: Vec<TransportEndpoint>,
    signer: AccountSigner,
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
    let pack =
        parse_pack_event(event).map_err(|_| invalid_sticker("sticker pack metadata is invalid"))?;
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
    if bytes.is_empty() || bytes.len() as u64 > MAX_STICKER_ASSET_BYTES {
        return Err(invalid_sticker("sticker asset size is invalid"));
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InspectedImage {
    mime: &'static str,
    width: u32,
    height: u32,
    frames: u32,
}

fn inspect_image(bytes: &[u8]) -> Result<InspectedImage, AppError> {
    let inspected = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        inspect_png(bytes)?
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        inspect_gif(bytes)?
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        inspect_webp(bytes)?
    } else {
        return Err(invalid_sticker("unsupported sticker image format"));
    };
    if inspected.width == 0
        || inspected.height == 0
        || inspected.width > MAX_STICKER_DIMENSION
        || inspected.height > MAX_STICKER_DIMENSION
        || u64::from(inspected.width) * u64::from(inspected.height) > MAX_STICKER_PIXELS
    {
        return Err(invalid_sticker("sticker image dimensions exceed limits"));
    }
    if inspected.frames == 0 || inspected.frames > MAX_STICKER_ANIMATION_FRAMES {
        return Err(invalid_sticker(
            "sticker animation frame count exceeds limits",
        ));
    }
    Ok(inspected)
}

fn inspect_png(bytes: &[u8]) -> Result<InspectedImage, AppError> {
    if bytes.len() < 33 || bytes.get(12..16) != Some(b"IHDR") {
        return Err(invalid_sticker("invalid PNG sticker"));
    }
    let width = be_u32(bytes, 16)?;
    let height = be_u32(bytes, 20)?;
    let mut offset = 8_usize;
    let mut frames = 1_u32;
    let mut animated = false;
    let mut saw_iend = false;
    while offset.checked_add(12).is_some_and(|end| end <= bytes.len()) {
        let length = be_u32(bytes, offset)? as usize;
        let chunk_end = offset
            .checked_add(12)
            .and_then(|base| base.checked_add(length))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid_sticker("invalid PNG chunk length"))?;
        let kind = &bytes[offset + 4..offset + 8];
        if kind == b"acTL" {
            if length != 8 {
                return Err(invalid_sticker("invalid APNG animation header"));
            }
            frames = be_u32(bytes, offset + 8)?;
            animated = true;
        }
        offset = chunk_end;
        if kind == b"IEND" {
            saw_iend = true;
            break;
        }
    }
    if !saw_iend {
        return Err(invalid_sticker("PNG sticker is truncated"));
    }
    Ok(InspectedImage {
        mime: if animated { "image/apng" } else { "image/png" },
        width,
        height,
        frames,
    })
}

fn inspect_gif(bytes: &[u8]) -> Result<InspectedImage, AppError> {
    if bytes.len() < 14 {
        return Err(invalid_sticker("invalid GIF sticker"));
    }
    let width = le_u16(bytes, 6)? as u32;
    let height = le_u16(bytes, 8)? as u32;
    let packed = bytes[10];
    let mut offset = 13_usize;
    if packed & 0x80 != 0 {
        let table = 3_usize
            .checked_mul(1_usize << (usize::from(packed & 0x07) + 1))
            .ok_or_else(|| invalid_sticker("invalid GIF color table"))?;
        offset = offset
            .checked_add(table)
            .filter(|offset| *offset <= bytes.len())
            .ok_or_else(|| invalid_sticker("truncated GIF color table"))?;
    }
    let mut frames = 0_u32;
    let mut saw_trailer = false;
    while offset < bytes.len() {
        match bytes[offset] {
            0x2c => {
                frames = frames.saturating_add(1);
                if frames > MAX_STICKER_ANIMATION_FRAMES {
                    break;
                }
                if offset + 10 > bytes.len() {
                    return Err(invalid_sticker("truncated GIF image descriptor"));
                }
                let image_packed = bytes[offset + 9];
                offset += 10;
                if image_packed & 0x80 != 0 {
                    let table = 3_usize
                        .checked_mul(1_usize << (usize::from(image_packed & 0x07) + 1))
                        .ok_or_else(|| invalid_sticker("invalid GIF local color table"))?;
                    offset = offset
                        .checked_add(table)
                        .filter(|offset| *offset <= bytes.len())
                        .ok_or_else(|| invalid_sticker("truncated GIF local color table"))?;
                }
                if offset >= bytes.len() {
                    return Err(invalid_sticker("truncated GIF image data"));
                }
                offset += 1;
                offset = skip_gif_sub_blocks(bytes, offset)?;
            }
            0x21 => {
                if offset + 2 > bytes.len() {
                    return Err(invalid_sticker("truncated GIF extension"));
                }
                offset = skip_gif_sub_blocks(bytes, offset + 2)?;
            }
            0x3b => {
                saw_trailer = true;
                break;
            }
            _ => return Err(invalid_sticker("invalid GIF block")),
        }
    }
    if !saw_trailer || frames == 0 {
        return Err(invalid_sticker("GIF sticker is incomplete"));
    }
    Ok(InspectedImage {
        mime: "image/gif",
        width,
        height,
        frames,
    })
}

fn skip_gif_sub_blocks(bytes: &[u8], mut offset: usize) -> Result<usize, AppError> {
    loop {
        let length = *bytes
            .get(offset)
            .ok_or_else(|| invalid_sticker("truncated GIF sub-block"))?
            as usize;
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(length)
            .filter(|offset| *offset <= bytes.len())
            .ok_or_else(|| invalid_sticker("truncated GIF sub-block"))?;
    }
}

fn inspect_webp(bytes: &[u8]) -> Result<InspectedImage, AppError> {
    if bytes.len() < 20 {
        return Err(invalid_sticker("invalid WebP sticker"));
    }
    let riff_len = le_u32(bytes, 4)? as usize;
    if riff_len
        .checked_add(8)
        .is_none_or(|length| length > bytes.len())
    {
        return Err(invalid_sticker("truncated WebP sticker"));
    }
    let mut offset = 12_usize;
    let mut dimensions = None;
    let mut frames = 0_u32;
    while offset.checked_add(8).is_some_and(|end| end <= bytes.len()) {
        let kind = &bytes[offset..offset + 4];
        let length = le_u32(bytes, offset + 4)? as usize;
        let data = offset + 8;
        let end = data
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid_sticker("invalid WebP chunk length"))?;
        match kind {
            b"VP8X" if length >= 10 => {
                dimensions = Some((
                    le_u24(bytes, data + 4)?.saturating_add(1),
                    le_u24(bytes, data + 7)?.saturating_add(1),
                ));
            }
            b"VP8L" if length >= 5 && bytes[data] == 0x2f => {
                let bits = le_u32(bytes, data + 1)?;
                dimensions = Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1));
            }
            b"VP8 " if length >= 10 && bytes.get(data + 3..data + 6) == Some(b"\x9d\x01\x2a") => {
                dimensions = Some((
                    u32::from(le_u16(bytes, data + 6)? & 0x3fff),
                    u32::from(le_u16(bytes, data + 8)? & 0x3fff),
                ));
            }
            b"ANMF" => frames = frames.saturating_add(1),
            _ => {}
        }
        offset = end + (length & 1);
    }
    let (width, height) = dimensions.ok_or_else(|| invalid_sticker("WebP dimensions missing"))?;
    Ok(InspectedImage {
        mime: "image/webp",
        width,
        height,
        frames: frames.max(1),
    })
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32, AppError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| invalid_sticker("truncated image header"))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, AppError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| invalid_sticker("truncated image header"))
}

fn le_u24(bytes: &[u8], offset: usize) -> Result<u32, AppError> {
    let bytes = bytes
        .get(offset..offset + 3)
        .ok_or_else(|| invalid_sticker("truncated image header"))?;
    Ok(u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, AppError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| invalid_sticker("truncated image header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinate() -> String {
        format!("30031:{}:cats", "ab".repeat(32))
    }

    fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(payload);
        chunk.extend_from_slice(&[0; 4]);
        chunk
    }

    fn png(width: u32, height: u32, animation_frames: Option<u32>) -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes.extend(chunk(b"IHDR", &ihdr));
        if let Some(frames) = animation_frames {
            let mut actl = Vec::new();
            actl.extend_from_slice(&frames.to_be_bytes());
            actl.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend(chunk(b"acTL", &actl));
        }
        bytes.extend(chunk(b"IEND", &[]));
        bytes
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
        let link =
            format!("https://sonarprivacy.xyz/stickers?a={coordinate}&relay=wss://evil.test");
        assert_eq!(parse_sticker_pack_input(&link).unwrap(), coordinate);
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
    fn future_pack_event_is_rejected_before_it_can_freeze_replacement_state() {
        let keys = nostr::Keys::generate();
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
            .tags(build_pack_tags(&pack))
            .custom_created_at(NostrTimestamp::from_secs(
                unix_now_seconds() + MAX_FUTURE_EVENT_SKEW_SECONDS + 1,
            ))
            .sign_with_keys(&keys)
            .unwrap();

        assert!(stored_pack_from_event(&event).is_err());
    }

    #[test]
    fn signal_import_only_accepts_the_canonical_https_origin() {
        assert!(
            validate_signal_sticker_link(
                "https://signal.art/addstickers/#pack_id=abc&pack_key=def"
            )
            .is_ok()
        );
        assert!(
            validate_signal_sticker_link("https://signal.art/addstickers?pack_id=abc&pack_key=def")
                .is_ok()
        );
        assert!(
            validate_signal_sticker_link("https://evil.test/addstickers/#pack_id=abc&pack_key=def")
                .is_err()
        );
        assert!(
            validate_signal_sticker_link("http://signal.art/addstickers/#pack_id=abc&pack_key=def")
                .is_err()
        );
        assert!(
            validate_signal_sticker_link(
                "https://signal.art:8443/addstickers/#pack_id=abc&pack_key=def"
            )
            .is_err()
        );
        assert!(
            validate_signal_sticker_link("https://signal.art/addstickers/#pack_id=abc").is_err()
        );
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
        let storage = SqliteAccountStorage::in_memory().unwrap();
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
    fn pack_republication_timestamp_advances_past_same_second_version() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let created_at = unix_now_seconds();
        let coordinate = coordinate();
        storage
            .replace_sticker_pack_if_newer(&StoredStickerPack {
                coordinate: coordinate.clone(),
                author_pubkey_hex: "ab".repeat(32),
                identifier: "cats".to_owned(),
                version: StoredStickerPackVersion {
                    event_id_hex: "cd".repeat(32),
                    created_at,
                },
                title: "Cats".to_owned(),
                description: None,
                cover: None,
                stickers: Vec::new(),
                license: None,
            })
            .unwrap();

        assert!(next_pack_publication_timestamp(&storage, &coordinate).unwrap() > created_at);
    }

    #[test]
    fn image_inspection_enforces_dimensions_and_animation_limits() {
        assert_eq!(
            inspect_image(&png(512, 256, None)).unwrap(),
            InspectedImage {
                mime: "image/png",
                width: 512,
                height: 256,
                frames: 1,
            }
        );
        assert_eq!(
            inspect_image(&png(32, 48, Some(2))).unwrap().mime,
            "image/apng"
        );
        assert!(inspect_image(&png(4097, 1, None)).is_err());
        assert!(inspect_image(&png(32, 32, Some(MAX_STICKER_ANIMATION_FRAMES + 1))).is_err());
        assert!(inspect_image(b"not an image").is_err());
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
    }
}
