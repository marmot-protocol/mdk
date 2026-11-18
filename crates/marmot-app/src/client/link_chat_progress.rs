//! Approver-scoped chat inventories for a recently linked device. A report is
//! advisory: it cannot cause a join, spend a KeyPackage, or import history.
use std::collections::HashMap;

use cgka_traits::app_components::{
    DeviceEntryV1, DeviceSlotId, DeviceStatusV1, encode_component_vectors,
};
use cgka_traits::{EpochId, GroupId, MessageId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::{LinkChatPage, LinkChatReport};

use super::AppClient;
use super::device_group::{Exchange, device_slot};
use super::linked_device_chats::{LINK_CHAT_ADD_SECS, NewDevice};
use crate::{AppError, LinkChatProgress, SelfMembership, unix_now_seconds};

pub(super) const KIND_LINK_CHAT_INVENTORY: u64 = 477;
const PAGE_SIZE: usize = 128;
const RESEND_SECS: u64 = 3600;
// Limit retained authenticated data to 8 MiB per incoming link.
const MAX_CHATS: usize = 262_144;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryPage {
    v: u8,
    to: String,
    link: String,
    revision: u32,
    expires_at: u64,
    total: u32,
    page: u32,
    // Concatenated SHA-256 tokens, each scoped to this link's KeyPackageRef.
    chats: String,
}

fn chat_token(link: &[u8], chat: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"marmot.link-chat-inventory.v1");
    digest.update(encode_component_vectors(&[link, chat]));
    digest.finalize().into()
}

#[derive(Default)]
pub(crate) struct LinkChatProgressState {
    received: Option<ReceivedInventory>,
    // Restart repeats the latest inventory from page zero.
    links: HashMap<(GroupId, DeviceSlotId), Publication>,
    prune_at: u64,
}

struct ReceivedInventory {
    group: String,
    link: String,
    revision: u32,
    tokens: Vec<[u8; 32]>,
}

struct Publication {
    report: LinkChatReport,
    revision: u32,
    next_page: usize,
    due: u64,
    repeat_after: u64,
}

fn participating(entry: &DeviceEntryV1) -> bool {
    entry.status == DeviceStatusV1::Active && entry.settings.add_to_all_chats
}

impl AppClient {
    pub(super) fn prune_link_chat_progress(&mut self, now: u64) -> Result<(), AppError> {
        if now >= self.link_chat_progress.prune_at {
            self.app
                .account_storage(&self.state.label)?
                .app_storage()
                .prune_link_chat_progress(now)?;
            self.link_chat_progress
                .links
                .retain(|_, p| p.report.expires_at > now);
            self.link_chat_progress.prune_at = now.saturating_add(RESEND_SECS);
        }
        Ok(())
    }

    pub(super) async fn report_link_chats(
        &mut self,
        exchange: &Exchange,
        device: &NewDevice,
        expected: &[&GroupId],
        remaining: usize,
    ) -> Result<(), AppError> {
        let slot = device.slot;
        let expires_at = device.expires_at;
        let link = hex::decode(&device.link_ref)?;
        let group = hex::encode(exchange.group_id.as_slice());
        let mut tokens: Vec<_> = expected
            .iter()
            .map(|g| chat_token(&link, g.as_slice()))
            .collect();
        tokens.sort_unstable();
        let now = unix_now_seconds();
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let slot_hex = hex::encode(slot);
        let report = LinkChatReport {
            slot: slot_hex.clone(),
            link_ref: device.link_ref.clone(),
            digest: Sha256::digest(tokens.as_flattened()).to_vec(),
            total: u32::try_from(tokens.len()).unwrap_or(u32::MAX),
            remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            expires_at,
        };
        // The worker owns this link. Only a changed scan (or the first one
        // after reopen) needs a durable write. Counts may change while the
        // inventory being sent is identical.
        let key = (exchange.group_id.clone(), slot);
        let schedule = &mut self.link_chat_progress.links;
        if schedule.get(&key).is_none_or(|last| last.report != report) {
            let revision = storage.save_link_chat_report(&group, &report)?;
            let restart = schedule.get(&key).is_none_or(|last| {
                last.revision != revision || last.report.link_ref != report.link_ref
            });
            let cursor = schedule.entry(key.clone()).or_insert_with(|| Publication {
                report: report.clone(),
                revision,
                next_page: 0,
                due: 0,
                repeat_after: RESEND_SECS,
            });
            if restart {
                cursor.next_page = 0;
                cursor.due = 0;
                cursor.repeat_after = RESEND_SECS;
            }
            cursor.report = report;
            cursor.revision = revision;
            self.device_link_changed = true;
        }
        let cursor = &schedule[&key];
        if now < cursor.due {
            return Ok(());
        }
        let page = cursor.next_page;
        // One bounded page per target per maintenance pass. Oversize inventories
        // explicitly replace an older inventory with an unavailable report.
        let oversize = tokens.len() > MAX_CHATS;
        let pages = if oversize {
            1
        } else {
            tokens.len().div_ceil(PAGE_SIZE).max(1)
        };
        let bytes = if oversize {
            &[][..]
        } else {
            tokens[page * PAGE_SIZE..tokens.len().min((page + 1) * PAGE_SIZE)].as_flattened()
        };
        let content = serde_json::to_string(&InventoryPage {
            v: 1,
            to: slot_hex,
            link: cursor.report.link_ref.clone(),
            revision: cursor.revision,
            expires_at,
            total: cursor.report.total,
            page: page as u32,
            chats: hex::encode(bytes),
        })?;
        let event = self.device_group_event(KIND_LINK_CHAT_INVENTORY, content)?;
        if self
            .send_device_group_event_at(&exchange.group_id, event, Some(exchange.pin))
            .await?
            && let Some(cursor) = self.link_chat_progress.links.get_mut(&key)
        {
            cursor.next_page = (page + 1) % pages;
            cursor.due = if cursor.next_page == 0 {
                let due = now.saturating_add(cursor.repeat_after);
                cursor.repeat_after = (cursor.repeat_after * 4).min(24 * RESEND_SECS);
                due
            } else {
                now
            };
        }
        Ok(())
    }

    pub(super) fn repeat_withdrawn_link_chat_reports(&mut self, group: &GroupId) {
        for ((id, _), publication) in &mut self.link_chat_progress.links {
            if id == group {
                publication.next_page = 0;
                publication.due = 0;
                publication.repeat_after = RESEND_SECS;
            }
        }
    }

    pub(super) fn receive_link_chat_page(
        &mut self,
        group: &GroupId,
        message_id: &MessageId,
        sender: (EpochId, Option<u32>),
        content: &str,
    ) -> Result<(), AppError> {
        if content.len() > PAGE_SIZE * 64 + 512 {
            return Ok(());
        }
        let Ok(page) = serde_json::from_str::<InventoryPage>(content) else {
            return Ok(());
        };
        let now = unix_now_seconds();
        if page.v != 1
            || page.revision == 0
            || page.expires_at <= now
            || page.expires_at > now.saturating_add(LINK_CHAT_ADD_SECS + 3600)
        {
            return Ok(());
        }
        let total = page.total as usize;
        let oversize = total > MAX_CHATS;
        let pages = if oversize {
            1
        } else {
            total.div_ceil(PAGE_SIZE).max(1)
        };
        if page.page as usize >= pages {
            return Ok(());
        }
        let count = if oversize {
            0
        } else {
            (total - page.page as usize * PAGE_SIZE).min(PAGE_SIZE)
        };
        if page.chats.len() != count * 64 || page.chats.bytes().any(|b| b.is_ascii_uppercase()) {
            return Ok(());
        }
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(());
        };
        if group != &exchange.group_id || page.to != hex::encode(exchange.own_slot) {
            return Ok(());
        }
        let entry = &exchange.roster.devices[&exchange.own_slot];
        let Some(from) = entry.linked_by else {
            return Ok(());
        };
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let group_hex = hex::encode(group.as_slice());
        let confirmed = storage
            .device_group(&group_hex)?
            .and_then(|record| record.key_package_ref_hex);
        if !participating(entry)
            || !exchange.is_sibling(&from)
            || confirmed.as_ref() != Some(&page.link)
        {
            return Ok(());
        }
        self.ensure_sent_by(group, &exchange.roster, sender, &from)?;
        let Ok(tokens) = hex::decode(page.chats) else {
            return Ok(());
        };
        storage.receive_link_chat_page(
            &group_hex,
            &LinkChatPage {
                link_ref: &page.link,
                revision: page.revision,
                page: page.page,
                total: page.total,
                expires_at: page.expires_at,
                tokens: &tokens,
                message_id: message_id.as_slice(),
            },
        )?;
        Ok(())
    }

    pub(super) fn link_chat_progress_views(
        &mut self,
        now: u64,
    ) -> Result<Vec<LinkChatProgress>, AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        if !storage.has_link_chat_progress(now)? {
            return Ok(Vec::new());
        }
        let Some(exchange) = self.device_group_exchange()? else {
            return Ok(Vec::new());
        };
        let own = exchange.own_slot;
        let me = &exchange.roster.devices[&own];
        let group = hex::encode(exchange.group_id.as_slice());
        let mut views = Vec::new();
        let reports = storage.link_chat_reports(&group, now)?;
        if !reports.is_empty() {
            let devices = self.devices_to_add_to_chats(&exchange, now)?;
            for report in reports {
                let slot = device_slot(&report.slot)?;
                if !devices
                    .iter()
                    .any(|device| device.slot == slot && device.link_ref == report.link_ref)
                {
                    continue;
                }
                views.push(LinkChatProgress {
                    slot_id_hex: report.slot,
                    on_new_device: false,
                    total: report.total,
                    remaining: report.remaining,
                });
            }
        }
        if participating(me)
            && me
                .linked_by
                .is_some_and(|from| exchange.roster.devices.contains_key(&from))
            && let Some(link_ref) = storage
                .device_group(&group)?
                .and_then(|r| r.key_package_ref_hex)
            && let Some(view) = self.received_link_chat_progress(&group, &link_ref, own, now)?
        {
            views.push(view);
        }
        Ok(views)
    }

    fn received_link_chat_progress(
        &mut self,
        group: &str,
        link_ref: &str,
        own: DeviceSlotId,
        now: u64,
    ) -> Result<Option<LinkChatProgress>, AppError> {
        // The pairing drive compares snapshots after each delivery. Read and
        // validate the inventory only after a page changes or this client opens.
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let cached = &mut self.link_chat_progress.received;
        let Some(report) = storage.received_link_chat_report(group, link_ref, now)? else {
            *cached = None;
            return Ok(None);
        };
        let total = report.total as usize;
        if total > MAX_CHATS || report.available_pages as usize != total.div_ceil(PAGE_SIZE).max(1)
        {
            *cached = None;
            return Ok(None);
        }
        if cached.as_ref().is_none_or(|held| {
            held.group != group || held.link != link_ref || held.revision != report.revision
        }) {
            let bytes = storage.received_link_chat_tokens(group, link_ref, report.revision)?;
            let (tokens, tail) = bytes.as_chunks::<32>();
            if !tail.is_empty()
                || tokens.len() != total
                || !tokens.windows(2).all(|pair| pair[0] < pair[1])
            {
                *cached = None;
                return Ok(None);
            }
            *cached = Some(ReceivedInventory {
                group: group.to_owned(),
                link: link_ref.to_owned(),
                revision: report.revision,
                tokens: tokens.to_vec(),
            });
        }
        let Some(report) = cached.as_ref() else {
            return Ok(None);
        };
        let total = report.tokens.len() as u32;
        let link = hex::decode(link_ref)?;
        let joined = self
            .state
            .groups
            .iter()
            .filter(|g| g.self_membership == SelfMembership::Member && !g.disbanded)
            .filter_map(|g| hex::decode(&g.group_id_hex).ok())
            .filter(|id| report.tokens.binary_search(&chat_token(&link, id)).is_ok())
            .count();
        Ok(Some(LinkChatProgress {
            slot_id_hex: hex::encode(own),
            on_new_device: true,
            total,
            remaining: total.saturating_sub(joined as u32),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{InventoryPage, chat_token};

    #[test]
    fn wire_inventory_rejects_duplicate_fields() {
        let content = r#"{"v":1,"to":"ab","link":"cd","revision":1,"expires_at":1,"total":1,"total":0,"page":0,"chats":""}"#;
        assert!(
            serde_json::from_str::<InventoryPage>(content)
                .is_err_and(|error| error.to_string().contains("duplicate field"))
        );
    }

    #[test]
    fn chat_token_matches_the_device_group_wire_vector() {
        let link: Vec<u8> = (0..32).collect();
        let group: Vec<u8> = (0..64).collect();
        assert_eq!(
            hex::encode(chat_token(&link, &group)),
            "40851b595a738955daa54e7b6bf77c5b9314d4a62af3559982f4c06192cea75b"
        );
    }
}
