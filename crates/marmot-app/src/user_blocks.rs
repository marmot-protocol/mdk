//! Account-private block policy and NIP-51 synchronization.
use crate::relay_plane::DirectoryEventQuery;
use crate::{AppError, MarmotApp};
use cgka_traits::{TransportEndpoint, TransportEndpointFailureKind};
use nostr::prelude::{EventBuilder, FinalizeEventAsync, Kind, PublicKey, Tag, Timestamp};
use std::sync::Arc;
use storage_sqlite::{PendingBlockPublication, StoredBlockList};
use transport_nostr_peeler::{NostrTransportEvent, SdkSigner};

pub use storage_sqlite::{BlockListSnapshot, BlockedUser};
pub(crate) const MUTE_LIST_KIND: u64 = 10000;

impl MarmotApp {
    pub(crate) async fn block_update_lock(&self, label: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.block_list_locks
            .lock()
            .expect("block locks poisoned")
            .entry(label.to_owned())
            .or_default()
            .clone()
    }

    pub(crate) fn block_list_endpoints(&self, account_id: &str) -> Vec<TransportEndpoint> {
        let relays = self
            .account_relay_list_status_for_account_id(account_id)
            .map(|s| s.nip65.relays)
            .unwrap_or_default();
        if relays.is_empty() {
            self.directory_source_relays(&[])
        } else {
            relays.into_iter().map(TransportEndpoint).collect()
        }
    }

    pub(crate) async fn ingest_block_list_event(
        &self,
        event: NostrTransportEvent,
    ) -> Result<(), AppError> {
        let Some(account) = self
            .account_home
            .accounts()?
            .into_iter()
            .find(|a| a.account_id_hex == event.pubkey)
        else {
            return Ok(());
        };
        let lock = self.block_update_lock(&account.label).await;
        let _guard = lock.lock().await;
        self.adopt_block_event(&account.label, &event).await?;
        self.reconcile_block_pending(&account.label)?;
        Ok(())
    }

    async fn adopt_block_event(
        &self,
        label: &str,
        event: &NostrTransportEvent,
    ) -> Result<(), AppError> {
        let account = self.account_home.account(label)?;
        if event.kind != MUTE_LIST_KIND
            || event.pubkey != account.account_id_hex
            || event.to_verified_nostr_event().is_err()
        {
            return Err(AppError::BlockListUnavailable);
        }
        if event.created_at > crate::unix_now_seconds().saturating_add(300) {
            return Err(AppError::BlockListUnavailable);
        }
        let storage = self.account_storage(label)?;
        let current = storage.stored_block_list()?;
        if !event_is_newer(event, &current) {
            return Ok(());
        }
        let signer = self.account_signer_for_summary(&account)?.as_nostr_signer();
        let own = PublicKey::from_hex(&account.account_id_hex)
            .map_err(|_| AppError::BlockListUnavailable)?;
        let private_tags = async {
            if event.content.is_empty() {
                return Ok(Vec::new());
            }
            let plaintext = match signer.nip44_decrypt(&own, &event.content).await {
                Ok(text) => text,
                Err(_) => signer
                    .nip04_decrypt(&own, &event.content)
                    .await
                    .map_err(|_| AppError::BlockListUnavailable)?,
            };
            serde_json::from_str::<Vec<Vec<String>>>(&plaintext)
                .map_err(|_| AppError::BlockListUnavailable)
        }
        .await;
        let private_tags = match private_tags {
            Ok(tags) => tags,
            Err(error) => {
                storage.record_unreadable_block_list(&event.id, event.created_at)?;
                return Err(error);
            }
        };
        let list = StoredBlockList {
            event_id: event.id.clone(),
            event_created_at: event.created_at,
            public_tags: event.tags.clone(),
            private_tags,
        };
        let entries = block_entries(&list, &account.account_id_hex);
        // The atomic replacement rebuilds every chat projection. Keep that
        // potentially large synchronous transaction off the Tokio executor.
        let local_account_id = account.account_id_hex.clone();
        let app = self.clone();
        let label = label.to_owned();
        crate::blocking_app_task(move || {
            if storage.adopt_block_list(
                &list,
                &entries,
                crate::notifications::unix_now_ms(),
                &local_account_id,
                &Self::chat_list_mention_classifier(&local_account_id),
            )? {
                // Commit and invalidation stay in the same blocking task even
                // if its async caller is cancelled while the transaction runs.
                if let Ok(version) = storage.chat_presentation_version() {
                    let _ = app.presentation_signals.updates.send(
                        crate::chat_presentation::signals::PresentationInvalidation {
                            account_label: label,
                            version,
                        },
                    );
                }
                app.block_list_updates
                    .send_modify(|revision| *revision = revision.wrapping_add(1));
            }
            Ok(())
        })
        .await?;
        Ok(())
    }

    fn reconcile_block_pending(&self, label: &str) -> Result<(), AppError> {
        let storage = self.account_storage(label)?;
        if let Some(pending) = storage.pending_block_publication()? {
            let event: NostrTransportEvent = serde_json::from_str(&pending.event_json)
                .map_err(|_| AppError::BlockListUnavailable)?;
            if !event_is_newer(&event, &storage.stored_block_list()?) {
                storage.clear_block_publication()?;
            }
        }
        Ok(())
    }

    pub(crate) async fn fetch_block_list(&self, label: &str) -> Result<(), AppError> {
        let account = self.account_home.account(label)?;
        let outcome = self
            .relay_plane
            .fetch_directory_events_with_completion(
                self.block_list_endpoints(&account.account_id_hex),
                vec![DirectoryEventQuery::new(
                    MUTE_LIST_KIND,
                    vec![account.account_id_hex.clone()],
                    // One replaceable event is expected; leave room to prove EOSE was not truncated.
                    2,
                )],
            )
            .await
            .map_err(|_| AppError::BlockListUnavailable)?;
        if !outcome.complete {
            return Err(AppError::BlockListUnavailable);
        }
        let mut events = outcome
            .records
            .into_iter()
            .map(|r| r.event)
            .filter(|e| e.kind == MUTE_LIST_KIND && e.pubkey == account.account_id_hex)
            .collect::<Vec<_>>();
        events.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        if let Some(event) = events.first() {
            self.adopt_block_event(label, event).await?;
        }
        if self
            .account_storage(label)?
            .block_list_has_unreadable_replacement()?
        {
            return Err(AppError::BlockListUnavailable);
        }
        self.reconcile_block_pending(label)
    }

    pub(crate) async fn set_user_blocked(
        &self,
        label: &str,
        target: &str,
        blocked: bool,
    ) -> Result<(), AppError> {
        let target = crate::parse_account_id_hex(target)?;
        let account = self.account_home.account(label)?;
        if target == account.account_id_hex {
            return Ok(());
        }
        let lock = self.block_update_lock(label).await;
        let _guard = lock.lock().await;
        let storage = self.account_storage(label)?;
        if storage.pending_block_publication()?.is_none()
            && storage.is_user_blocked(&target)? == blocked
        {
            return Ok(());
        }
        self.fetch_block_list(label).await?;
        let list = storage.stored_block_list()?;
        let pending = storage.pending_block_publication()?;
        let retrying_uncertain = pending.is_some();
        let event = if let Some(pending) = pending {
            if pending.target != target || pending.blocked != blocked {
                return Err(AppError::BlockPublicationUncertain);
            }
            serde_json::from_str::<NostrTransportEvent>(&pending.event_json)
                .map_err(|_| AppError::BlockListUnavailable)?
        } else {
            if storage.is_user_blocked(&target)? == blocked {
                return Ok(());
            }
            let mut public = list.public_tags;
            let mut private = list.private_tags;
            let is_target = |tag: &Vec<String>| {
                tag.first().is_some_and(|t| t == "p")
                    && tag
                        .get(1)
                        .and_then(|p| PublicKey::parse(p).ok())
                        .is_some_and(|p| p.to_hex() == target)
            };
            public.retain(|tag| !is_target(tag));
            private.retain(|tag| !is_target(tag));
            if blocked {
                private.push(vec!["p".into(), target.clone()]);
            }
            let signer = self.account_signer_for_summary(&account)?.as_nostr_signer();
            let own = PublicKey::from_hex(&account.account_id_hex)
                .map_err(|_| AppError::BlockListUnavailable)?;
            let content = if private.is_empty() {
                String::new()
            } else {
                signer
                    .nip44_encrypt(&own, &serde_json::to_string(&private)?)
                    .await
                    .map_err(|_| AppError::BlockListUnavailable)?
            };
            let tags = public
                .into_iter()
                .map(Tag::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AppError::BlockListUnavailable)?;
            // Avoid same-second replacements losing against the previous event id.
            let at = crate::unix_now_seconds().max(list.event_created_at.saturating_add(1));
            if at > crate::unix_now_seconds().saturating_add(300) {
                return Err(AppError::BlockListUnavailable);
            }
            let signed = EventBuilder::new(Kind::from(MUTE_LIST_KIND as u16), content)
                .tags(tags)
                .custom_created_at(Timestamp::from_secs(at))
                .finalize_async(&SdkSigner(signer.clone()))
                .await
                .map_err(|_| AppError::BlockListUnavailable)?;
            let event = NostrTransportEvent::from_nostr_event(&signed)
                .map_err(|_| AppError::BlockListUnavailable)?;
            storage.stage_block_publication(&PendingBlockPublication {
                target,
                blocked,
                event_json: serde_json::to_string(&event)?,
            })?;
            event
        };
        let signer = self.account_signer_for_summary(&account)?.as_nostr_signer();
        let endpoints = self.outbox_endpoints(
            &account.account_id_hex,
            self.block_list_endpoints(&account.account_id_hex),
        );
        let result = self
            .relay_client_for_account_id(&account.account_id_hex, signer)
            .publish_event(&endpoints, &event, 1)
            .await;
        match result {
            Ok(outcome) if !outcome.accepted.is_empty() => {
                self.adopt_block_event(label, &event)
                    .await
                    .map_err(|_| AppError::BlockPublicationUncertain)?;
                storage
                    .clear_block_publication()
                    .map_err(|_| AppError::BlockPublicationUncertain)?;
                Ok(())
            }
            other => {
                let failures = match &other {
                    Ok(outcome) => outcome.failed.as_slice(),
                    Err(error) => error.publish_endpoint_failures(),
                };
                let definite = !failures.is_empty()
                    && failures
                        .iter()
                        .all(|f| f.kind != TransportEndpointFailureKind::PossiblyExposed);
                if definite && !retrying_uncertain {
                    storage.clear_block_publication()?;
                    Err(AppError::BlockListUnavailable)
                } else {
                    Err(AppError::BlockPublicationUncertain)
                }
            }
        }
    }
}

fn event_is_newer(event: &NostrTransportEvent, current: &StoredBlockList) -> bool {
    current.event_id.is_empty()
        || event.created_at > current.event_created_at
        || (event.created_at == current.event_created_at && event.id < current.event_id)
}
fn block_entries(list: &StoredBlockList, own: &str) -> Vec<(String, bool)> {
    list.public_tags
        .iter()
        .map(|t| (t, false))
        .chain(list.private_tags.iter().map(|t| (t, true)))
        .filter_map(|(tag, private)| {
            if tag.first().is_none_or(|t| t != "p") {
                return None;
            }
            let key = PublicKey::parse(tag.get(1)?).ok()?.to_hex();
            (key != own).then_some((key, private))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::FinalizeEvent;
    use transport_nostr_peeler::MarmotNostrSigner;
    #[tokio::test]
    async fn user_blocks_private_legacy_interop_and_unreadable_event_preserves_state() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(dir.path(), vec![]);
        let account = app.account_home().create_account("alice").unwrap();
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let target = nostr::prelude::Keys::generate().public_key().to_hex();
        let runtime = app.runtime();
        let mut subscription = runtime.subscribe_blocked_users("alice").unwrap();
        assert!(subscription.snapshot.users.is_empty());
        for (offset, legacy) in [(0, true), (1, false)] {
            let private = serde_json::to_string(&vec![
                vec!["p", target.as_str()],
                vec!["word", "preserve me"],
            ])
            .unwrap();
            let content = if legacy {
                keys.nip04_encrypt(&keys.public_key(), &private)
                    .await
                    .unwrap()
            } else {
                keys.nip44_encrypt(&keys.public_key(), &private)
                    .await
                    .unwrap()
            };
            let event = EventBuilder::new(Kind::MuteList, content)
                .custom_created_at(Timestamp::from_secs(crate::unix_now_seconds() + offset))
                .finalize(&keys)
                .unwrap();
            app.ingest_block_list_event(NostrTransportEvent::from_nostr_event(&event).unwrap())
                .await
                .unwrap();
            let update =
                tokio::time::timeout(std::time::Duration::from_secs(1), subscription.recv())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(update.users[0].public_key, target);
            assert!(update.users[0].is_private);
            assert!(runtime.is_user_blocked("alice", &target).unwrap());
        }
        let before = app
            .account_storage("alice")
            .unwrap()
            .block_list_snapshot()
            .unwrap();
        let unreadable = EventBuilder::new(Kind::MuteList, "not ciphertext")
            .custom_created_at(Timestamp::from_secs(crate::unix_now_seconds() + 3))
            .finalize(&keys)
            .unwrap();
        assert!(
            app.ingest_block_list_event(
                NostrTransportEvent::from_nostr_event(&unreadable).unwrap()
            )
            .await
            .is_err()
        );
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .block_list_snapshot()
                .unwrap(),
            before
        );
        assert_eq!(
            app.account_storage("alice")
                .unwrap()
                .stored_block_list()
                .unwrap()
                .private_tags[1],
            ["word", "preserve me"]
        );
        runtime
            .block_user("alice", &account.account_id_hex)
            .await
            .unwrap();
        assert!(runtime.is_user_blocked("alice", "bad key").is_err());
        runtime.shutdown().await;
        assert!(subscription.recv().await.is_none());
    }
}
