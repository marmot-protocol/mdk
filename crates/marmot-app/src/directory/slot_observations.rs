//! Durable account-storage handoff independent of publication lifecycle writes.
use crate::{AppError, MarmotApp};
use cgka_traits::{MessageId, transport::Timestamp};
use storage_sqlite::KeyPackageSlotObservation;
use transport_nostr_peeler::NostrTransportEvent;

impl MarmotApp {
    pub(crate) fn own_key_package_slot_observation(
        &self,
        label: &str,
    ) -> Result<Option<KeyPackageSlotObservation>, AppError> {
        let storage = self.account_storage(label)?;
        let _admission = self.begin_storage_open("key package slot observation")?;
        Ok(storage.key_package_slot_observation()?)
    }

    pub(crate) fn clear_own_key_package_slot_observation(
        &self,
        label: &str,
        observed: &KeyPackageSlotObservation,
    ) -> Result<(), AppError> {
        let storage = self.account_storage(label)?;
        let _admission = self.begin_storage_open("key package slot observation")?;
        Ok(storage.clear_key_package_slot_observation(observed)?)
    }

    pub(crate) fn remember_own_key_package_slot_observation(
        &self,
        event: &NostrTransportEvent,
    ) -> Result<(), AppError> {
        if event.kind != crate::KIND_MARMOT_KEY_PACKAGE {
            return Ok(());
        }
        let accounts = self.account_home().accounts()?;
        let Some(account) = accounts.iter().find(|account| {
            account.account_id_hex == event.pubkey
                && (account.local_signing || account.external_signing)
        }) else {
            return Ok(());
        };
        if event.to_verified_nostr_event().is_err() {
            return Ok(());
        }
        let Some(slot) = event.tag_value("d") else {
            return Ok(());
        };
        // Read-only authority check. The account owner revalidates local authorship
        // and ordering before recording any conflict or generating private material.
        use cgka_traits::storage::MaintenanceStorage;
        let storage = self.account_storage(&account.label)?;
        let _admission = self.begin_storage_open("key package slot observation")?;
        let Some(lifecycle) = storage.key_package_lifecycle()? else {
            return Ok(());
        };
        let event_id = MessageId::new(hex::decode(&event.id)?);
        if !lifecycle.is_foreign_slot_winner(slot, &event_id, Timestamp(event.created_at)) {
            return Ok(());
        }
        let observation = KeyPackageSlotObservation {
            slot_id: slot.to_owned(),
            event_id,
            created_at: Timestamp(event.created_at),
        };
        storage.remember_key_package_slot_observation(&observation)?;
        Ok(())
    }
}
