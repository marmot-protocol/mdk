//! Sealed history deliveries to this account's other devices (mdk#2628 4.2b
//! and 4.2c, D60, D76, D77): a chat's history sent through the device group
//! to one sibling and readable only by it. `history_delivery.rs` holds the
//! format.
//!
//! Only the adder sends (D76). When this device's own Commit that adds a
//! sibling to a chat is confirmed, the engine records the sibling's slot in
//! the same transaction (`SiblingAddStorage`). A maintenance pass turns each
//! such add into an owed history before sending anything, then exports the
//! chat's history in inline bundles, seals each bundle's key and hash to the
//! receiver's history key, and sends one delivery per bundle. Whether the
//! sibling asks for history is read then. A send that reached no relay leaves
//! the history owed; a delivery that branch selection withdraws, or whose
//! queued publish later fails for good, makes it owed again. There are no
//! receipts: a withdrawal is acted on only when this device hears of it, so
//! one whose device-group record was evicted, or that a crash interrupted,
//! loses that history.
//!
//! A history longer than [`MAX_INLINE_BUNDLES`], or with an event too large
//! for one, goes through Blossom instead (D77): its newest
//! [`MAX_BLOSSOM_BUNDLES`] bundles of up to 8 MiB, older ones left out, each
//! uploaded as one blob to the first of the chat's Blossom endpoints that
//! takes it. The upload runs off the account worker ([`HistoryUpload`]); its
//! deliveries are sent once every blob is uploaded, each naming its server.
//! A failed upload or send waits and tries again, uploading afresh, until the
//! history is a week old. A chat with no Blossom endpoint gets no such
//! history. Blobs are never deleted, as attachment blobs are not.
//!
//! The receiver reads a delivery only from a sibling whose leaf is tagged,
//! only when it names this device, and only when it opens with this device's
//! history key. It imports an inline bundle through 4.2a once it holds the
//! chat and parks the delivery until then. It parks a Blossom delivery's
//! servers and fetches the blob off the worker once it holds the chat
//! ([`HistoryFetch`]), trying again after a failed fetch.
//!
//! Owed and parked deliveries go after a week. A history is owed from the
//! add's confirmation, so one is still sent when branch selection later
//! withdraws that Commit; the sibling imports it only if it joins the chat.

use std::sync::Arc;

use bytes::Bytes;
use cgka_traits::app_components::{BLOSSOM_LOCATOR_KIND_V1, DeviceSlotId};
use cgka_traits::app_event::MarmotAppEvent;
use cgka_traits::storage::SiblingAddStorage as _;
use cgka_traits::{EpochId, GroupId, MessageId};
use storage_sqlite::{
    HISTORY_DELIVERY_RETENTION_SECS, OwedHistoryDelivery, ParkedBundle, ParkedHistoryDelivery,
    SqliteAccountStorage,
};
use transport_nostr_peeler::MarmotNostrSigner;
use zeroize::Zeroizing;

use super::AppClient;
use super::chat_history::{ExportedBundle, export_history, newest_bundles_start};
use super::device_group::Exchange;
use crate::history_bundle::{ChatPosition, HISTORY_BUNDLE_MAX_PLAINTEXT, seal_history_bundle};
use crate::history_delivery::{
    DeliveredBundle, HistoryDelivery, INLINE_BUNDLE_MAX_PLAINTEXT, KIND_HISTORY_DELIVERY,
    MAX_BLOSSOM_BUNDLES, MAX_HISTORY_DELIVERY_CONTENT_BYTES, MAX_INLINE_BUNDLES,
    blossom_server_is_valid, delivery_context, opened_key_and_hash, sealed_plaintext,
};
use crate::media::{BlossomHttpTransport, fetch_history_blob, upload_history_blob};
use crate::{AppError, unix_now_seconds};

const TRACE_TARGET: &str = "marmot_app::client::history_delivery";
/// The longest ciphertext a bundle has: its most plaintext and the AEAD tag.
const MAX_BUNDLE_CIPHERTEXT_BYTES: u64 = HISTORY_BUNDLE_MAX_PLAINTEXT as u64 + 16;
/// The first wait after a failed Blossom upload, send or fetch, in seconds;
/// each further failure doubles it, up to [`MAX_BLOSSOM_RETRY_SECS`].
const BLOSSOM_RETRY_SECS: u64 = 60;
const MAX_BLOSSOM_RETRY_SECS: u64 = 60 * 60;

/// When a Blossom upload, send or fetch that failed `attempts` times before
/// is tried again.
fn blossom_retry_at(now: u64, attempts: u64) -> u64 {
    let wait = (BLOSSOM_RETRY_SECS << attempts.min(6)).min(MAX_BLOSSOM_RETRY_SECS);
    now.saturating_add(wait)
}

/// A history to send through Blossom, prepared on the account worker by
/// [`AppClient::prepare_history_upload`]. Running it exports, encrypts and
/// uploads each bundle off the worker, one at a time, holding only the
/// bundle keys it uploaded; [`AppClient::finish_history_upload`] then seals
/// them and sends the deliveries.
pub(crate) struct HistoryUpload {
    owed: OwedHistoryDelivery,
    storage: SqliteAccountStorage,
    chat: GroupId,
    servers: Vec<String>,
    signer: Arc<dyn MarmotNostrSigner>,
    transport: BlossomHttpTransport,
    allow_loopback_http: bool,
}

/// What a [`HistoryUpload`] uploaded, or why it stopped.
pub(crate) struct HistoryUploadOutcome {
    owed: OwedHistoryDelivery,
    result: Result<Vec<UploadedBundle>, AppError>,
}

/// One uploaded bundle: what its delivery seals, and the server that holds it.
struct UploadedBundle {
    key: Zeroizing<[u8; 32]>,
    ciphertext_sha256: [u8; 32],
    server: String,
}

impl HistoryUpload {
    pub(crate) async fn run(self) -> HistoryUploadOutcome {
        let result = self.upload().await;
        HistoryUploadOutcome {
            owed: self.owed,
            result,
        }
    }

    async fn upload(&self) -> Result<Vec<UploadedBundle>, AppError> {
        let group_id_hex = self.owed.group_id_hex.clone();
        let export = |after: Option<ChatPosition>| {
            let (storage, chat, group_id_hex) = (
                self.storage.clone(),
                self.chat.clone(),
                group_id_hex.clone(),
            );
            let allow_loopback_http = self.allow_loopback_http;
            tokio::task::spawn_blocking(move || {
                export_history(
                    &storage,
                    &chat,
                    &group_id_hex,
                    after.as_ref(),
                    HISTORY_BUNDLE_MAX_PLAINTEXT,
                    allow_loopback_http,
                )?
                .map(|ExportedBundle { bundle, .. }| {
                    Ok::<_, AppError>((seal_history_bundle(&bundle)?, bundle.to))
                })
                .transpose()
            })
        };
        let start = {
            let (storage, chat, group_id_hex) = (
                self.storage.clone(),
                self.chat.clone(),
                group_id_hex.clone(),
            );
            let allow_loopback_http = self.allow_loopback_http;
            tokio::task::spawn_blocking(move || {
                newest_bundles_start(
                    &storage,
                    &chat,
                    &group_id_hex,
                    HISTORY_BUNDLE_MAX_PLAINTEXT,
                    MAX_BLOSSOM_BUNDLES,
                    allow_loopback_http,
                )
            })
            .await
            .map_err(|_| AppError::BlockingTask("history export failed".into()))??
        };
        let mut after = start;
        let mut uploaded = Vec::new();
        while uploaded.len() < MAX_BLOSSOM_BUNDLES {
            let Some((sealed, to)) = export(after)
                .await
                .map_err(|_| AppError::BlockingTask("history export failed".into()))??
            else {
                break;
            };
            let server = upload_history_blob(
                &self.servers,
                Bytes::from(sealed.ciphertext),
                &hex::encode(sealed.ciphertext_sha256),
                self.signer.as_ref(),
                &self.transport,
            )
            .await?;
            uploaded.push(UploadedBundle {
                key: sealed.key,
                ciphertext_sha256: sealed.ciphertext_sha256,
                server,
            });
            after = Some(to);
        }
        Ok(uploaded)
    }
}

/// A parked Blossom delivery to fetch, prepared on the account worker by
/// [`AppClient::prepare_history_fetch`]. Running it fetches the blob off the
/// worker; [`AppClient::finish_history_fetch`] imports it.
pub(crate) struct HistoryFetch {
    parked: ParkedHistoryDelivery,
    servers: Vec<String>,
    ciphertext_sha256: [u8; 32],
    transport: BlossomHttpTransport,
}

/// What a [`HistoryFetch`] fetched, or why it did not.
pub(crate) struct HistoryFetchOutcome {
    parked: ParkedHistoryDelivery,
    result: Result<Vec<u8>, AppError>,
}

impl HistoryFetch {
    /// Fetch the blob from each server in turn until one returns the bytes
    /// its hash names.
    pub(crate) async fn run(self) -> HistoryFetchOutcome {
        let mut result = Err(AppError::BlobStore("history blob has no server".into()));
        for server in &self.servers {
            result = fetch_history_blob(
                server,
                &self.ciphertext_sha256,
                MAX_BUNDLE_CIPHERTEXT_BYTES,
                &self.transport,
            )
            .await;
            if result.is_ok() {
                break;
            }
        }
        HistoryFetchOutcome {
            parked: self.parked,
            result,
        }
    }
}

impl AppClient {
    /// Maintenance's history-delivery pass: expire week-old deliveries,
    /// import parked ones whose chat this device now holds, owe the history
    /// of each chat this device added a sibling to, then send what is owed. A
    /// pass that fails waits for the next.
    pub(crate) async fn drive_history_deliveries(&mut self) {
        if self.runtime.maintenance_is_paused() || !self.app.device_groups_enabled() {
            return;
        }
        let result = match self
            .import_parked_history_deliveries()
            .and_then(|()| self.owe_added_siblings_history())
        {
            Ok(()) => self.send_owed_history_deliveries().await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "drive_history_deliveries",
                error_kind = error.privacy_safe_kind(),
                "history deliveries were not settled; retrying at the next maintenance pass"
            );
        }
    }

    /// Owe each sibling that one of this device's own confirmed Commits added
    /// to a chat the chat's history, counted from the add, then forget the
    /// add. An add a week old is forgotten unowed, as its history would have
    /// been. Owing again what is already owed changes nothing, so a crash
    /// between the two only owes it again.
    fn owe_added_siblings_history(&self) -> Result<(), AppError> {
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        let expired_before = unix_now_seconds().saturating_sub(HISTORY_DELIVERY_RETENTION_SECS);
        for add in account.sibling_adds()? {
            if add.added_at >= expired_before {
                storage.owe_history_delivery(
                    &hex::encode(add.group_id.as_slice()),
                    &hex::encode(add.slot),
                    add.added_at,
                )?;
            }
            account.forget_sibling_add(&add)?;
        }
        Ok(())
    }

    /// Send each owed history, one delivery per bundle. Each delivery's chat
    /// and receiver are recorded before it is sent, so its withdrawal can owe
    /// the history again. A delivery that reached no relay stops the pass
    /// with its history still owed; sending one twice costs the receiver only
    /// the download, since import never adds a row twice. A history that can
    /// no longer be sent is forgotten.
    async fn send_owed_history_deliveries(&mut self) -> Result<(), AppError> {
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        // Siblings read nothing this device sends until its leaf is tagged.
        if !exchange.tagged {
            return Ok(());
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let mut sent = 0;
        for owed in storage.unsent_history_deliveries()? {
            // One going through Blossom is the upload's.
            if owed.blossom_due_at.is_some() {
                continue;
            }
            let events = match self.inline_history_deliveries(&exchange, &owed) {
                Ok(Some(events)) => events,
                Ok(None) => {
                    storage.send_history_delivery_by_blossom(&owed, unix_now_seconds())?;
                    continue;
                }
                Err(AppError::DeviceGroupRefused(reason)) => {
                    storage.forget_history_delivery(&owed)?;
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "send_owed_history_deliveries",
                        reason,
                        "an owed history cannot be sent and is forgotten"
                    );
                    continue;
                }
                Err(error) => return Err(error),
            };
            for event in events {
                storage.record_history_delivery_send(
                    &event.id,
                    &owed.group_id_hex,
                    &owed.receiver_slot_hex,
                    unix_now_seconds(),
                )?;
                if !self
                    .send_device_group_event(&exchange.group_id, event)
                    .await?
                {
                    return Ok(());
                }
                sent += 1;
            }
            storage.mark_history_delivery_sent(&owed, unix_now_seconds())?;
        }
        if sent > 0 {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "send_owed_history_deliveries",
                deliveries = sent,
                "history deliveries sent"
            );
        }
        Ok(())
    }

    /// Who `owed` goes to and for which chat: the receiver, while it is a
    /// sibling that asks for history with a key this device can seal to, and
    /// the chat, while this device holds it. Refused otherwise.
    fn history_destination(
        &self,
        exchange: &Exchange,
        owed: &OwedHistoryDelivery,
    ) -> Result<(DeviceSlotId, GroupId), AppError> {
        let refused = AppError::DeviceGroupRefused;
        let receiver = hex::decode(&owed.receiver_slot_hex)
            .ok()
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
            .filter(|slot| exchange.is_sibling(slot))
            .ok_or(refused("history_delivery_receiver"))?;
        let entry = &exchange.roster.devices[&receiver];
        if !entry.settings.bring_history {
            return Err(refused("history_delivery_not_wanted"));
        }
        if entry.history_key.is_none() {
            return Err(refused("history_delivery_key"));
        }
        let chat = hex::decode(&owed.group_id_hex)
            .map(GroupId::new)
            .map_err(|_| refused("history_delivery_chat"))?;
        match self.history_chat(&chat) {
            Ok(_) => Ok((receiver, chat)),
            Err(AppError::UnknownGroup(_) | AppError::DeviceGroupRefused(_)) => {
                Err(refused("history_delivery_chat"))
            }
            // A storage failure is not a refusal: the history stays owed.
            Err(error) => Err(error),
        }
    }

    /// The deliveries that carry `owed` inline: the chat's whole history in
    /// at most [`MAX_INLINE_BUNDLES`] bundles, each sealed to the receiver.
    /// None when it needs more, or an event too large for an inline bundle,
    /// so it goes through Blossom.
    fn inline_history_deliveries(
        &self,
        exchange: &Exchange,
        owed: &OwedHistoryDelivery,
    ) -> Result<Option<Vec<MarmotAppEvent>>, AppError> {
        let (receiver, chat) = self.history_destination(exchange, owed)?;
        let mut bundles = Vec::new();
        let mut after = None;
        while let Some(exported) =
            self.export_chat_history(&chat, after.as_ref(), INLINE_BUNDLE_MAX_PLAINTEXT)?
        {
            if bundles.len() == MAX_INLINE_BUNDLES || exported.left_out_oversized {
                return Ok(None);
            }
            after = Some(exported.bundle.to.clone());
            bundles.push(exported.bundle);
        }
        bundles
            .iter()
            .map(|bundle| {
                let sealed_bundle = seal_history_bundle(bundle)?;
                self.history_delivery_event(
                    exchange,
                    &receiver,
                    &chat,
                    &sealed_bundle.key,
                    &sealed_bundle.ciphertext_sha256,
                    DeliveredBundle::Inline(sealed_bundle.ciphertext),
                )
            })
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// The delivery of one bundle to `receiver`, its key and hash sealed to
    /// the receiver's history key.
    fn history_delivery_event(
        &self,
        exchange: &Exchange,
        receiver: &DeviceSlotId,
        chat: &GroupId,
        key: &[u8; 32],
        ciphertext_sha256: &[u8; 32],
        bundle: DeliveredBundle,
    ) -> Result<MarmotAppEvent, AppError> {
        let refused = AppError::DeviceGroupRefused;
        let history_key = exchange.roster.devices[receiver]
            .history_key
            .as_deref()
            .ok_or(refused("history_delivery_key"))?;
        let sealed = self
            .runtime
            .seal_history(
                history_key,
                &delivery_context(&exchange.own_slot, receiver, chat.as_slice()),
                &sealed_plaintext(key, ciphertext_sha256),
            )
            .ok_or(refused("history_delivery_key"))?;
        let content = HistoryDelivery {
            from: exchange.own_slot,
            to: *receiver,
            chat: chat.as_slice().to_vec(),
            sealed,
            bundle,
        }
        .encode();
        if content.len() > MAX_HISTORY_DELIVERY_CONTENT_BYTES {
            return Err(refused("history_delivery_too_large"));
        }
        self.device_group_event(KIND_HISTORY_DELIVERY, content)
    }

    /// The Blossom servers this device uploads `chat`'s history to: the
    /// chat's Blossom endpoints a delivery can name, loopback ones only in a
    /// build that allows them. Refused when there are none.
    fn history_blossom_servers(&self, chat: &GroupId) -> Result<Vec<String>, AppError> {
        let allow_loopback = self.app.allow_loopback_blob_endpoints();
        let servers = self
            .encrypted_media_policy_for_group(chat)?
            .default_blob_endpoints
            .into_iter()
            .filter(|endpoint| {
                endpoint.locator_kind == BLOSSOM_LOCATOR_KIND_V1
                    && blossom_server_is_valid(&endpoint.base_url)
                    && (allow_loopback
                        || !crate::media::is_loopback_http_endpoint(&endpoint.base_url))
            })
            .map(|endpoint| endpoint.base_url)
            .collect::<Vec<_>>();
        if servers.is_empty() {
            return Err(AppError::DeviceGroupRefused("history_delivery_no_blossom"));
        }
        Ok(servers)
    }

    /// The next history due to go through Blossom, ready to upload off the
    /// worker. One that can no longer be sent is forgotten, including one
    /// whose chat has no Blossom endpoint.
    pub(crate) fn prepare_history_upload(&mut self) -> Result<Option<HistoryUpload>, AppError> {
        if self.runtime.maintenance_is_paused() || !self.app.device_groups_enabled() {
            return Ok(None);
        }
        let Some(exchange) = self
            .device_group_exchange()?
            .filter(|exchange| exchange.tagged)
        else {
            return Ok(None);
        };
        let account = self.app.account_storage(&self.state.label)?;
        let storage = account.app_storage();
        for owed in storage.due_blossom_history_deliveries(unix_now_seconds())? {
            let prepared = self
                .history_destination(&exchange, &owed)
                .and_then(|(_, chat)| Ok((self.history_blossom_servers(&chat)?, chat)));
            let (servers, chat) = match prepared {
                Ok(prepared) => prepared,
                Err(AppError::DeviceGroupRefused(reason)) => {
                    storage.forget_history_delivery(&owed)?;
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "prepare_history_upload",
                        reason,
                        "an owed history cannot be sent and is forgotten"
                    );
                    continue;
                }
                Err(error) => return Err(error),
            };
            // A signer that is not available yet, such as an external one not
            // registered again since launch, backs off as a failed upload does.
            let signer = self
                .app
                .account_home()
                .account(&self.state.label)
                .map_err(AppError::from)
                .and_then(|summary| self.app.account_signer_for_summary(&summary));
            let signer = match signer {
                Ok(signer) => signer,
                Err(error) => {
                    let retry_at = blossom_retry_at(unix_now_seconds(), owed.blossom_attempts);
                    storage.defer_blossom_history_delivery(&owed, retry_at)?;
                    return Err(error);
                }
            };
            return Ok(Some(HistoryUpload {
                owed,
                storage: account,
                chat,
                servers,
                signer: signer.as_nostr_signer(),
                transport: self.blossom_http_transport.clone(),
                allow_loopback_http: self.app.allow_loopback_blob_endpoints(),
            }));
        }
        Ok(None)
    }

    /// Send the deliveries of a history whose blobs were uploaded, each
    /// naming the server that holds its blob, and mark it sent. An upload or
    /// send that failed tries again later; a history that can no longer be
    /// sent is forgotten. Returns whether the history was settled, so the
    /// next one may start at once.
    pub(crate) async fn finish_history_upload(&mut self, outcome: HistoryUploadOutcome) -> bool {
        let HistoryUploadOutcome { owed, result } = outcome;
        let Err(error) = self.send_uploaded_history(&owed, result).await else {
            return true;
        };
        tracing::warn!(
            target: TRACE_TARGET,
            method = "finish_history_upload",
            error_kind = error.privacy_safe_kind(),
            "an uploaded history was not sent; retrying later"
        );
        if let Ok(storage) = self.app.account_storage(&self.state.label) {
            let retry_at = blossom_retry_at(unix_now_seconds(), owed.blossom_attempts);
            let _ = storage
                .app_storage()
                .defer_blossom_history_delivery(&owed, retry_at);
        }
        false
    }

    async fn send_uploaded_history(
        &mut self,
        owed: &OwedHistoryDelivery,
        uploaded: Result<Vec<UploadedBundle>, AppError>,
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let forget = |storage: &storage_sqlite::SqliteAppStorage, reason| {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "finish_history_upload",
                reason,
                "an owed history cannot be sent and is forgotten"
            );
            storage.forget_history_delivery(owed)
        };
        let uploaded = match uploaded {
            Ok(uploaded) => uploaded,
            Err(AppError::DeviceGroupRefused(reason)) => return Ok(forget(&storage, reason)?),
            Err(error) => return Err(error),
        };
        let Some(exchange) = self
            .device_group_exchange()?
            .filter(|exchange| exchange.tagged)
        else {
            return Err(AppError::DeviceGroupRefused("not_trusted_device_group"));
        };
        let (receiver, chat) = match self.history_destination(&exchange, owed) {
            Ok(destination) => destination,
            Err(AppError::DeviceGroupRefused(reason)) => return Ok(forget(&storage, reason)?),
            Err(error) => return Err(error),
        };
        for bundle in &uploaded {
            let event = match self.history_delivery_event(
                &exchange,
                &receiver,
                &chat,
                &bundle.key,
                &bundle.ciphertext_sha256,
                DeliveredBundle::Blossom(vec![bundle.server.clone()]),
            ) {
                Ok(event) => event,
                Err(AppError::DeviceGroupRefused(reason)) => return Ok(forget(&storage, reason)?),
                Err(error) => return Err(error),
            };
            storage.record_history_delivery_send(
                &event.id,
                &owed.group_id_hex,
                &owed.receiver_slot_hex,
                unix_now_seconds(),
            )?;
            if !self
                .send_device_group_event(&exchange.group_id, event)
                .await?
            {
                return Err(AppError::BlobStore(
                    "a history delivery reached no relay".into(),
                ));
            }
        }
        storage.mark_history_delivery_sent(owed, unix_now_seconds())?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "finish_history_upload",
            deliveries = uploaded.len(),
            "history deliveries sent through Blossom"
        );
        Ok(())
    }

    /// The next parked Blossom delivery due to be fetched for a chat this
    /// device holds, ready to fetch off the worker. One whose sender is no
    /// longer a sibling, or that no longer opens, is dropped.
    pub(crate) fn prepare_history_fetch(&mut self) -> Result<Option<HistoryFetch>, AppError> {
        if self.runtime.maintenance_is_paused() || !self.app.device_groups_enabled() {
            return Ok(None);
        }
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(None);
        };
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        for parked in storage.due_parked_history_fetches(unix_now_seconds(), usize::MAX)? {
            let ParkedBundle::Blossom { servers, .. } = &parked.bundle else {
                continue;
            };
            if !self
                .state
                .groups
                .iter()
                .any(|group| group.group_id_hex == parked.group_id_hex)
            {
                continue;
            }
            let servers = servers.clone();
            match self.open_parked_history_delivery(&exchange, &parked) {
                Ok((_, _, _, hash)) => {
                    return Ok(Some(HistoryFetch {
                        parked,
                        servers,
                        ciphertext_sha256: hash,
                        transport: self.blossom_http_transport.clone(),
                    }));
                }
                Err(AppError::DeviceGroupRefused(reason)) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "prepare_history_fetch",
                        reason,
                        "a parked history delivery was refused"
                    );
                    storage.drop_parked_history_delivery(&parked.app_event_id)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Import a fetched blob and drop its parked delivery. A fetch that
    /// failed tries again later, as does an import that failed for any
    /// reason but a refusal. Returns whether the delivery was settled, so the
    /// next one may start at once.
    pub(crate) fn finish_history_fetch(&mut self, outcome: HistoryFetchOutcome) -> bool {
        let HistoryFetchOutcome { parked, result } = outcome;
        let result = result.and_then(|ciphertext| {
            let exchange = self
                .device_group_exchange()?
                .ok_or(AppError::DeviceGroupRefused("not_trusted_device_group"))?;
            let (chat, from, key, hash) = self.open_parked_history_delivery(&exchange, &parked)?;
            self.import_delivered_bundle(&chat, &from, &key, &hash, &ciphertext)
        });
        let Ok(storage) = self.app.account_storage(&self.state.label) else {
            return false;
        };
        let storage = storage.app_storage();
        let mut progressed = true;
        let settled = match result {
            Ok(()) => storage.drop_parked_history_delivery(&parked.app_event_id),
            Err(AppError::DeviceGroupRefused(reason)) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "finish_history_fetch",
                    reason,
                    "a parked history delivery was refused"
                );
                storage.drop_parked_history_delivery(&parked.app_event_id)
            }
            Err(error) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "finish_history_fetch",
                    error_kind = error.privacy_safe_kind(),
                    "a history blob was not imported; retrying later"
                );
                progressed = false;
                let attempts = match &parked.bundle {
                    ParkedBundle::Blossom { fetch_attempts, .. } => *fetch_attempts,
                    ParkedBundle::Inline(_) => 0,
                };
                storage.defer_parked_history_fetch(
                    &parked.app_event_id,
                    blossom_retry_at(unix_now_seconds(), attempts),
                )
            }
        };
        if settled.is_err() {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "finish_history_fetch",
                "a parked history delivery was not settled"
            );
            return false;
        }
        progressed
    }

    /// Upload and fetch every due Blossom history in place, as the account
    /// worker does off it. Test support only.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn drive_history_blobs(&mut self) {
        while let Ok(Some(upload)) = self.prepare_history_upload() {
            let outcome = upload.run().await;
            if !self.finish_history_upload(outcome).await {
                break;
            }
        }
        while let Ok(Some(fetch)) = self.prepare_history_fetch() {
            let outcome = fetch.run().await;
            if !self.finish_history_fetch(outcome) {
                break;
            }
        }
    }

    /// Read a delivery sent in the device group this device trusts. One for
    /// another device is ignored. One from anything but a sibling whose leaf
    /// is tagged, or that does not open with this device's history key, is
    /// refused. The bundle is imported when this device holds the chat and
    /// parked until it does.
    pub(crate) fn receive_history_delivery(
        &mut self,
        group_id: &GroupId,
        app_event_id: &str,
        sender: (EpochId, Option<u32>),
        content: &str,
    ) -> Result<(), AppError> {
        let exchange = self
            .device_group_exchange()?
            .filter(|exchange| exchange.group_id == *group_id)
            .ok_or(AppError::DeviceGroupRefused("not_trusted_device_group"))?;
        let delivery = HistoryDelivery::decode(content)?;
        if delivery.to != exchange.own_slot {
            return Ok(());
        }
        if !exchange.is_sibling(&delivery.from) {
            return Err(AppError::DeviceGroupRefused("history_delivery_sender"));
        }
        self.ensure_sent_by(group_id, &exchange.roster, sender, &delivery.from)?;
        // Opened now, so one that never opens is refused rather than parked.
        let (key, hash) = self.open_history_delivery(
            &delivery.from,
            &exchange.own_slot,
            &delivery.chat,
            &delivery.sealed,
        )?;
        let chat = GroupId::new(delivery.chat.clone());
        let now = unix_now_seconds();
        let bundle = match delivery.bundle {
            DeliveredBundle::Inline(bundle) => match self.history_chat(&chat) {
                Ok(_) => {
                    return self.import_delivered_bundle(
                        &chat,
                        &delivery.from,
                        &key,
                        &hash,
                        &bundle,
                    );
                }
                Err(AppError::UnknownGroup(_)) => ParkedBundle::Inline(bundle),
                Err(error) => return Err(error),
            },
            // Fetched off the worker, once this device holds the chat.
            DeliveredBundle::Blossom(servers) => ParkedBundle::Blossom {
                servers,
                fetch_due_at: now,
                fetch_attempts: 0,
            },
        };
        self.app
            .account_storage(&self.state.label)?
            .app_storage()
            .park_history_delivery(&ParkedHistoryDelivery {
                app_event_id: app_event_id.to_owned(),
                group_id_hex: hex::encode(&delivery.chat),
                sender_slot_hex: hex::encode(delivery.from),
                sealed: delivery.sealed,
                bundle,
                received_at: now,
            })?;
        Ok(())
    }

    /// Drop week-old deliveries, then import each parked inline one whose
    /// chat this device now holds; a Blossom one waits for its fetch. A
    /// parked delivery goes once imported or refused, as when its sender is
    /// no longer a sibling; any other failure stops the pass and keeps it for
    /// the next.
    fn import_parked_history_deliveries(&mut self) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        storage.expire_history_deliveries(unix_now_seconds())?;
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        for group_id_hex in storage.parked_history_delivery_chats()? {
            if !self
                .state
                .groups
                .iter()
                .any(|group| group.group_id_hex == group_id_hex)
            {
                continue;
            }
            for parked in storage.parked_history_deliveries(&group_id_hex)? {
                let ParkedBundle::Inline(bundle) = &parked.bundle else {
                    continue;
                };
                let imported = self
                    .open_parked_history_delivery(&exchange, &parked)
                    .and_then(|(chat, from, key, hash)| {
                        self.import_delivered_bundle(&chat, &from, &key, &hash, bundle)
                    });
                match imported {
                    Ok(()) => {}
                    Err(AppError::DeviceGroupRefused(reason)) => {
                        tracing::warn!(
                            target: TRACE_TARGET,
                            method = "import_parked_history_deliveries",
                            reason,
                            "a parked history delivery was refused"
                        );
                    }
                    Err(error) => return Err(error),
                }
                storage.drop_parked_history_delivery(&parked.app_event_id)?;
            }
        }
        Ok(())
    }

    /// A parked delivery's chat, its sender while still a sibling, and its
    /// bundle key and hash, opened again with this device's history key.
    #[allow(clippy::type_complexity)]
    fn open_parked_history_delivery(
        &self,
        exchange: &Exchange,
        parked: &ParkedHistoryDelivery,
    ) -> Result<(GroupId, DeviceSlotId, Zeroizing<[u8; 32]>, [u8; 32]), AppError> {
        let from = hex::decode(&parked.sender_slot_hex)
            .ok()
            .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
            .filter(|slot| exchange.is_sibling(slot))
            .ok_or(AppError::DeviceGroupRefused("history_delivery_sender"))?;
        let chat = hex::decode(&parked.group_id_hex)
            .map_err(|_| AppError::DeviceGroupRefused("history_delivery_chat"))?;
        let (key, hash) =
            self.open_history_delivery(&from, &exchange.own_slot, &chat, &parked.sealed)?;
        Ok((GroupId::new(chat), from, key, hash))
    }

    /// A delivery's bundle key and ciphertext hash, opened with this device's
    /// history key.
    fn open_history_delivery(
        &self,
        from: &DeviceSlotId,
        to: &DeviceSlotId,
        chat: &[u8],
        sealed: &[u8],
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), AppError> {
        let opened = self
            .runtime
            .open_history(&delivery_context(from, to, chat), sealed)?
            .map(Zeroizing::new);
        opened
            .as_deref()
            .and_then(|opened| opened_key_and_hash(opened))
            .ok_or(AppError::DeviceGroupRefused("history_delivery_seal"))
    }

    /// Import one delivered bundle and announce what changed.
    fn import_delivered_bundle(
        &mut self,
        chat: &GroupId,
        from: &DeviceSlotId,
        key: &[u8; 32],
        hash: &[u8; 32],
        bundle: &[u8],
    ) -> Result<(), AppError> {
        if let Some(update) = self.import_history_bundle(chat, from, key, hash, bundle)? {
            self.pending_projection_updates.push(update);
        }
        Ok(())
    }

    /// Branch selection withdrew the device-group message `message_id`, of
    /// the delivery kind: when this device sent it, its history is owed again.
    pub(crate) fn history_delivery_withdrawn(
        &mut self,
        group_id: &GroupId,
        message_id: &MessageId,
    ) -> Result<(), AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some(app_event_id) = storage.device_group_message_event_id(
            &hex::encode(group_id.as_slice()),
            &hex::encode(message_id.as_slice()),
        )?
        else {
            return Ok(());
        };
        if storage.owe_history_delivery_again(&app_event_id)? {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "history_delivery_withdrawn",
                "a withdrawn history delivery is owed again"
            );
        }
        Ok(())
    }

    /// The publish of `app_event_id` failed for good, perhaps in a drain after
    /// the send that queued it: when it was a history delivery, owe its
    /// history again.
    pub(crate) fn history_delivery_failed(&self, app_event_id: &str) -> Result<(), AppError> {
        if self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .owe_history_delivery_again(app_event_id)?
        {
            tracing::debug!(
                target: TRACE_TARGET,
                method = "history_delivery_failed",
                "a failed history delivery is owed again"
            );
        }
        Ok(())
    }

    /// Test-policy hook: record that this device added the sibling at
    /// `receiver` to `chat`, as the engine does when its own Commit that
    /// adds it is confirmed.
    #[cfg(feature = "test-policy-overrides")]
    #[doc(hidden)]
    pub fn dev_record_sibling_add(
        &mut self,
        chat: &GroupId,
        receiver: &DeviceSlotId,
    ) -> Result<(), AppError> {
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .record_sibling_adds(chat, &[*receiver], unix_now_seconds())?)
    }
}
