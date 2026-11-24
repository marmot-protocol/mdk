use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    AccountHomeError, AccountHomeResult, AcquiredSecret, SecretClaimMode, SecretCredential,
    SecretCredentialKind, SecretOrigin, SecretReleaseMode, SecretReleaseOutcome,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum RecordKind {
    Receipt,
    Retirement,
}

pub(crate) trait VaultStorage: Send + Sync {
    fn read(&self, kind: RecordKind, name: &str) -> AccountHomeResult<Option<Zeroizing<String>>>;
    // A successful write must be durable. The next step may delete the only other copy.
    fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()>;
    // Replay may find a record from a write that returned an error after publishing it.
    // Providers that publish durably in one operation need no replay barrier.
    fn sync(&self, _kind: RecordKind) -> AccountHomeResult<()> {
        Ok(())
    }
    fn remove(&self, kind: RecordKind, name: &str) -> AccountHomeResult<()>;
    fn names(&self, kind: RecordKind) -> AccountHomeResult<Vec<String>>;
}

#[derive(Clone, Copy)]
pub(crate) enum Addressing {
    Label,
    AccountId,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct LegacySecret {
    pub(crate) label: String,
    pub(crate) account_id_hex: String,
    #[serde(default)]
    pub(crate) origin_scope: Option<String>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Lifecycle {
    Preserved,
    Retired,
    Adopted,
}

impl Lifecycle {
    fn has_preserve_hold(self) -> bool {
        matches!(self, Self::Preserved)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    state: Lifecycle,
    legacy: Option<LegacySecret>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    secret_key_hex: StoredSecretKeyHex,
    origin: SecretOrigin,
    legacy: Option<LegacySecret>,
    adopted_from: Option<String>,
}

pub(crate) struct StoredSecretKeyHex(Zeroizing<String>);

impl StoredSecretKeyHex {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Serialize for StoredSecretKeyHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StoredSecretKeyHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

fn invalid_state(message: &str) -> AccountHomeError {
    AccountHomeError::SecretStore(message.to_owned())
}

fn validate_identity(value: &str) -> AccountHomeResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_state(
            "credential home and owner identities must be lowercase 32-byte hex",
        ));
    }
    Ok(())
}

pub(crate) fn slot_name(credential: SecretCredential<'_>, addressing: Addressing) -> String {
    let mut hash = Sha256::new();
    hash.update(b"mdk-owned-secret-v1\0");
    hash.update([match credential.kind {
        SecretCredentialKind::Signing => 0,
        SecretCredentialKind::ExternalDatabase => 1,
        SecretCredentialKind::Nip46Session => 2,
    }]);
    if credential.kind != SecretCredentialKind::Signing {
        hash.update(credential.home_id.as_bytes());
    }
    match addressing {
        Addressing::Label => hash.update(credential.label.as_bytes()),
        Addressing::AccountId => hash.update(credential.account_id_hex.as_bytes()),
    }
    hex::encode(hash.finalize())
}

fn receipt_name(
    credential: SecretCredential<'_>,
    addressing: Addressing,
) -> AccountHomeResult<String> {
    validate_identity(credential.home_id)?;
    validate_identity(credential.owner_id)?;
    Ok(format!(
        "{}-{}",
        slot_name(credential, addressing),
        credential.owner_id
    ))
}

fn read_receipt(storage: &impl VaultStorage, name: &str) -> AccountHomeResult<Option<Receipt>> {
    storage
        .read(RecordKind::Receipt, name)?
        .map(|value| serde_json::from_str(value.as_str()).map_err(Into::into))
        .transpose()
}

fn read_retirement(
    storage: &impl VaultStorage,
    name: &str,
) -> AccountHomeResult<Option<Retirement>> {
    storage
        .read(RecordKind::Retirement, name)?
        .map(|value| serde_json::from_str(value.as_str()).map_err(Into::into))
        .transpose()
}

fn write_retirement(
    storage: &impl VaultStorage,
    name: &str,
    retirement: &Retirement,
) -> AccountHomeResult<()> {
    let value = serde_json::to_string(retirement)?;
    storage.write(RecordKind::Retirement, name, &value)
}

fn receipt_keys(
    credential: SecretCredential<'_>,
    receipt: &Receipt,
    proposed: Option<&nostr::prelude::Keys>,
) -> AccountHomeResult<nostr::prelude::Keys> {
    let keys = nostr::prelude::Keys::parse(receipt.secret_key_hex.as_str())
        .map_err(|_| AccountHomeError::InvalidSecretKey)?;
    validate_material(credential, &keys, proposed)?;
    Ok(keys)
}

fn validate_material(
    credential: SecretCredential<'_>,
    keys: &nostr::prelude::Keys,
    proposed: Option<&nostr::prelude::Keys>,
) -> AccountHomeResult<()> {
    if credential.kind == SecretCredentialKind::Signing
        && keys.public_key().to_hex() != credential.account_id_hex
    {
        return Err(AccountHomeError::AccountIdMismatch);
    }
    if proposed.is_some_and(|proposed| proposed.secret_key() != keys.secret_key()) {
        return Err(AccountHomeError::AccountIdMismatch);
    }
    Ok(())
}

fn finish_adoption(storage: &impl VaultStorage, source: &str) -> AccountHomeResult<()> {
    let mut retirement = read_retirement(storage, source)?
        .ok_or_else(|| invalid_state("preserved credential source lost its lifecycle record"))?;
    if retirement.state.has_preserve_hold() {
        retirement.state = Lifecycle::Adopted;
        write_retirement(storage, source, &retirement)?;
    } else {
        storage.sync(RecordKind::Retirement)?;
    }
    storage.remove(RecordKind::Receipt, source)
}

fn slot_receipts(storage: &impl VaultStorage, slot: &str) -> AccountHomeResult<Vec<String>> {
    let mut names = storage.names(RecordKind::Receipt)?;
    names.retain(|name| name.starts_with(slot) && name.as_bytes().get(slot.len()) == Some(&b'-'));
    Ok(names)
}

fn check_receipt_listing(
    storage: &impl VaultStorage,
    slot: &str,
    listed: &[String],
) -> AccountHomeResult<()> {
    let mut current = slot_receipts(storage, slot)?;
    current.sort_unstable();
    if current.as_slice() != listed {
        return Err(invalid_state(
            "credential receipt listing changed; retry acquisition",
        ));
    }
    Ok(())
}

pub(crate) fn acquire(
    storage: &impl VaultStorage,
    credential: SecretCredential<'_>,
    addressing: Addressing,
    mode: SecretClaimMode,
    proposed: Option<&nostr::prelude::Keys>,
    legacy_lookup: impl FnOnce() -> AccountHomeResult<Option<(nostr::prelude::Keys, Option<String>)>>,
) -> AccountHomeResult<AcquiredSecret> {
    let name = receipt_name(credential, addressing)?;
    if read_retirement(storage, &name)?.is_some() {
        return Err(invalid_state(
            "retired credential owner cannot acquire again",
        ));
    }
    if let Some(receipt) = read_receipt(storage, &name)? {
        let keys = receipt_keys(credential, &receipt, proposed)?;
        storage.sync(RecordKind::Receipt)?;
        if let Some(source) = &receipt.adopted_from {
            finish_adoption(storage, source)?;
        }
        return Ok(AcquiredSecret {
            keys,
            origin: receipt.origin,
        });
    }

    let slot = slot_name(credential, addressing);
    let mut names = slot_receipts(storage, &slot)?;
    names.sort_unstable();
    let mut selected = None;
    let mut skipped = false;
    for candidate in &names {
        let state = read_retirement(storage, candidate)?;
        if state
            .as_ref()
            .is_some_and(|state| !state.state.has_preserve_hold())
        {
            skipped = true;
            continue;
        }
        let preserved = state.is_some();
        if selected.is_some() && !preserved {
            continue;
        }
        let Some(receipt) = read_receipt(storage, candidate)? else {
            skipped = true;
            continue;
        };
        if mode == SecretClaimMode::CreateOnly {
            return Err(AccountHomeError::AccountExists(credential.label.to_owned()));
        }
        let keys = receipt_keys(credential, &receipt, proposed)?;
        selected = Some((keys, receipt.legacy, preserved.then_some(candidate)));
        if preserved {
            break;
        }
    }
    if selected.is_none() && skipped {
        // Adoption publishes its replacement before retiring the listed source.
        check_receipt_listing(storage, &slot, &names)?;
    }

    let (keys, origin, legacy, adopted_from) = if let Some((keys, legacy, source)) = selected {
        (keys, SecretOrigin::Existing, legacy, source)
    } else if mode == SecretClaimMode::MigrateLegacy {
        match legacy_lookup()? {
            Some((keys, origin_scope)) => {
                validate_material(credential, &keys, proposed)?;
                let legacy = LegacySecret {
                    label: credential.label.to_owned(),
                    account_id_hex: credential.account_id_hex.to_owned(),
                    origin_scope,
                };
                (keys, SecretOrigin::Existing, Some(legacy), None)
            }
            None => {
                let keys = proposed
                    .ok_or_else(|| AccountHomeError::SecretNotFound(credential.label.to_owned()))?
                    .clone();
                validate_material(credential, &keys, None)?;
                (keys, SecretOrigin::Created, None, None)
            }
        }
    } else {
        if mode == SecretClaimMode::AdoptOnly {
            return Err(AccountHomeError::SecretNotFound(
                credential.label.to_owned(),
            ));
        }
        let keys = proposed
            .ok_or_else(|| AccountHomeError::SecretNotFound(credential.label.to_owned()))?
            .clone();
        validate_material(credential, &keys, None)?;
        (keys, SecretOrigin::Created, None, None)
    };
    let receipt = Receipt {
        secret_key_hex: StoredSecretKeyHex::new(keys.secret_key().to_secret_hex()),
        origin,
        legacy,
        adopted_from: adopted_from.cloned(),
    };
    let value = Zeroizing::new(serde_json::to_string(&receipt)?);
    storage.write(RecordKind::Receipt, &name, value.as_str())?;
    if read_retirement(storage, &name)?.is_some() {
        return Err(invalid_state("credential owner retired during acquisition"));
    }
    if let Some(source) = &receipt.adopted_from {
        finish_adoption(storage, source)?;
    }
    Ok(AcquiredSecret { keys, origin })
}

pub(crate) fn load(
    storage: &impl VaultStorage,
    credential: SecretCredential<'_>,
    addressing: Addressing,
) -> AccountHomeResult<nostr::prelude::Keys> {
    let name = receipt_name(credential, addressing)?;
    if read_retirement(storage, &name)?.is_some() {
        return Err(AccountHomeError::SecretNotFound(
            credential.label.to_owned(),
        ));
    }
    let receipt = read_receipt(storage, &name)?
        .ok_or_else(|| AccountHomeError::SecretNotFound(credential.label.to_owned()))?;
    let keys = receipt_keys(credential, &receipt, None)?;
    if read_retirement(storage, &name)?.is_some() {
        return Err(AccountHomeError::SecretNotFound(
            credential.label.to_owned(),
        ));
    }
    Ok(keys)
}

fn legacy_outcome<N: AsRef<str>>(
    legacy: Option<&LegacySecret>,
    current_scope: impl FnOnce() -> AccountHomeResult<Option<N>>,
    legacy_lookup: impl FnOnce(&LegacySecret) -> AccountHomeResult<bool>,
) -> AccountHomeResult<SecretReleaseOutcome> {
    if let Some(legacy) = legacy {
        let Some(origin_scope) = legacy.origin_scope.as_deref() else {
            return Ok(SecretReleaseOutcome::PendingLegacy);
        };
        let current_scope = match current_scope() {
            Ok(Some(scope)) => scope,
            Ok(None) | Err(_) => return Ok(SecretReleaseOutcome::PendingLegacy),
        };
        if origin_scope != current_scope.as_ref() {
            return Ok(SecretReleaseOutcome::PendingLegacy);
        }
        match legacy_lookup(legacy) {
            Ok(false) => {}
            Ok(true) | Err(_) => return Ok(SecretReleaseOutcome::PendingLegacy),
        }
    }
    Ok(SecretReleaseOutcome::Released)
}

pub(crate) fn release<N: AsRef<str>>(
    storage: &impl VaultStorage,
    credential: SecretCredential<'_>,
    addressing: Addressing,
    mode: SecretReleaseMode,
    current_scope: impl FnOnce() -> AccountHomeResult<Option<N>>,
    legacy_lookup: impl FnOnce(&LegacySecret) -> AccountHomeResult<bool>,
) -> AccountHomeResult<SecretReleaseOutcome> {
    let name = receipt_name(credential, addressing)?;
    if let Some(retirement) = read_retirement(storage, &name)? {
        storage.sync(RecordKind::Retirement)?;
        if retirement.state.has_preserve_hold() {
            if mode != SecretReleaseMode::Preserve {
                return Err(invalid_state(
                    "preserved credential release mode cannot change",
                ));
            }
            return Ok(SecretReleaseOutcome::Released);
        }
        storage.remove(RecordKind::Receipt, &name)?;
        if matches!(retirement.state, Lifecycle::Adopted) && mode == SecretReleaseMode::Preserve {
            return Ok(SecretReleaseOutcome::Released);
        }
        return legacy_outcome(retirement.legacy.as_ref(), current_scope, legacy_lookup);
    }
    let receipt = read_receipt(storage, &name)?;
    if let Some(receipt) = &receipt {
        if mode == SecretReleaseMode::Preserve || receipt.adopted_from.is_some() {
            storage.sync(RecordKind::Receipt)?;
        }
        if let Some(source) = &receipt.adopted_from {
            finish_adoption(storage, source)?;
        }
    }
    if mode == SecretReleaseMode::Preserve && receipt.is_some() {
        let retirement = Retirement {
            state: Lifecycle::Preserved,
            legacy: receipt.and_then(|receipt| receipt.legacy),
        };
        write_retirement(storage, &name, &retirement)?;
        return Ok(SecretReleaseOutcome::Released);
    }
    let legacy = receipt.map_or_else(
        || {
            Some(LegacySecret {
                label: credential.label.to_owned(),
                account_id_hex: credential.account_id_hex.to_owned(),
                origin_scope: None,
            })
        },
        |receipt| receipt.legacy,
    );
    let retirement = Retirement {
        state: Lifecycle::Retired,
        legacy,
    };
    write_retirement(storage, &name, &retirement)?;
    storage.remove(RecordKind::Receipt, &name)?;
    legacy_outcome(retirement.legacy.as_ref(), current_scope, legacy_lookup)
}

pub(crate) fn has_managed(
    storage: &impl VaultStorage,
    credential: SecretCredential<'_>,
    addressing: Addressing,
) -> AccountHomeResult<bool> {
    let slot = slot_name(credential, addressing);
    let mut names = slot_receipts(storage, &slot)?;
    for name in &names {
        if read_retirement(storage, name)?.is_some_and(|state| !state.state.has_preserve_hold()) {
            continue;
        }
        if storage.read(RecordKind::Receipt, name)?.is_some() {
            return Ok(true);
        }
    }
    if !names.is_empty() {
        names.sort_unstable();
        check_receipt_listing(storage, &slot, &names)?;
    }
    Ok(false)
}

pub(crate) fn reconcile(storage: &impl VaultStorage) -> AccountHomeResult<()> {
    let mut failure = None;
    for name in storage.names(RecordKind::Retirement)? {
        let result = (|| {
            if read_retirement(storage, &name)?
                .is_some_and(|record| !record.state.has_preserve_hold())
            {
                storage.sync(RecordKind::Retirement)?;
                storage.remove(RecordKind::Receipt, &name)?;
            }
            Ok(())
        })();
        if let Err(error) = result
            && failure.is_none()
        {
            failure = Some(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountSecretStore, LocalFileSecretStore};
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(10);

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PauseAfter {
        Read,
        Listing,
    }

    struct PausedReceiptStorage {
        storage: LocalFileSecretStore,
        pause_after: PauseAfter,
        entered: mpsc::Sender<()>,
        resume: Mutex<Option<mpsc::Receiver<()>>>,
    }

    impl PausedReceiptStorage {
        fn new(
            storage: LocalFileSecretStore,
            pause_after: PauseAfter,
        ) -> (Self, mpsc::Receiver<()>, mpsc::Sender<()>) {
            let (entered, wait_for_entry) = mpsc::channel();
            let (release, resume) = mpsc::channel();
            (
                Self {
                    storage,
                    pause_after,
                    entered,
                    resume: Mutex::new(Some(resume)),
                },
                wait_for_entry,
                release,
            )
        }

        fn pause(&self, kind: RecordKind, point: PauseAfter) {
            if matches!(kind, RecordKind::Receipt)
                && self.pause_after == point
                && let Some(resume) = self.resume.lock().unwrap().take()
                && self.entered.send(()).is_ok()
                && let Err(mpsc::RecvTimeoutError::Timeout) =
                    resume.recv_timeout(CHECKPOINT_TIMEOUT)
            {
                panic!("receipt checkpoint was not released");
            }
        }
    }

    impl VaultStorage for PausedReceiptStorage {
        fn read(
            &self,
            kind: RecordKind,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            let value = self.storage.read(kind, name)?;
            self.pause(kind, PauseAfter::Read);
            Ok(value)
        }

        fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()> {
            self.storage.write(kind, name, value)
        }

        fn sync(&self, kind: RecordKind) -> AccountHomeResult<()> {
            self.storage.sync(kind)
        }

        fn remove(&self, kind: RecordKind, name: &str) -> AccountHomeResult<()> {
            self.storage.remove(kind, name)
        }

        fn names(&self, kind: RecordKind) -> AccountHomeResult<Vec<String>> {
            let names = self.storage.names(kind)?;
            self.pause(kind, PauseAfter::Listing);
            Ok(names)
        }
    }

    #[test]
    fn load_rechecks_retirement_after_receipt_read() {
        let directory = tempfile::tempdir().unwrap();
        let storage = LocalFileSecretStore::new(directory.path(), crate::IosOptions::default());
        let keys = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
        let account = keys.public_key().to_hex();
        let home = "11".repeat(32);
        let owner = "22".repeat(32);
        let credential = SecretCredential {
            label: "retiring",
            account_id_hex: &account,
            home_id: &home,
            owner_id: &owner,
            kind: SecretCredentialKind::Signing,
        };
        storage
            .acquire_secret(credential, SecretClaimMode::CreateOnly, Some(&keys))
            .unwrap();
        std::thread::scope(|scope| {
            let (reader, entered, resume) =
                PausedReceiptStorage::new(storage.clone(), PauseAfter::Read);
            let reading = scope.spawn(move || load(&reader, credential, Addressing::Label));
            entered
                .recv_timeout(CHECKPOINT_TIMEOUT)
                .expect("reader did not read the receipt");
            let retired = storage.release_secret(credential, SecretReleaseMode::DeleteIfUnowned);
            resume.send(()).expect("paused reader exited");
            let loaded = reading.join().unwrap();
            assert_eq!(retired.unwrap(), SecretReleaseOutcome::Released);
            assert!(
                matches!(loaded, Err(AccountHomeError::SecretNotFound(label)) if label == "retiring")
            );
        });
        assert!(matches!(storage.load_secret(credential),
            Err(AccountHomeError::SecretNotFound(label)) if label == "retiring"));
    }

    #[test]
    fn adopt_rejects_stale_absence() {
        let directory = tempfile::tempdir().unwrap();
        let storage = LocalFileSecretStore::new(directory.path(), crate::IosOptions::default());
        let keys = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
        let account = keys.public_key().to_hex();
        let home = "11".repeat(32);
        let original_id = "22".repeat(32);
        let adopter_id = "33".repeat(32);
        let waiting_id = "44".repeat(32);
        let original = SecretCredential {
            label: "shared",
            account_id_hex: &account,
            home_id: &home,
            owner_id: &original_id,
            kind: SecretCredentialKind::Signing,
        };
        storage
            .acquire_secret(original, SecretClaimMode::CreateOnly, Some(&keys))
            .unwrap();
        assert_eq!(
            storage
                .release_secret(original, SecretReleaseMode::Preserve)
                .unwrap(),
            SecretReleaseOutcome::Released
        );
        let adopter = SecretCredential {
            owner_id: &adopter_id,
            ..original
        };
        let waiting = SecretCredential {
            owner_id: &waiting_id,
            ..original
        };

        std::thread::scope(|scope| {
            let (reader, entered, resume) =
                PausedReceiptStorage::new(storage.clone(), PauseAfter::Listing);
            let acquiring = scope.spawn(move || {
                acquire(
                    &reader,
                    waiting,
                    Addressing::Label,
                    SecretClaimMode::AdoptOnly,
                    None,
                    || Ok(None),
                )
            });
            entered
                .recv_timeout(CHECKPOINT_TIMEOUT)
                .expect("reader did not list receipts");
            let adopted = storage
                .acquire_secret(adopter, SecretClaimMode::AdoptOnly, None)
                .unwrap();
            assert_eq!(adopted.keys.secret_key(), keys.secret_key());
            let source = receipt_name(original, Addressing::Label).unwrap();
            assert!(
                !storage
                    .names(RecordKind::Receipt)
                    .unwrap()
                    .contains(&source)
            );
            resume.send(()).expect("paused reader exited");
            assert!(
                matches!(acquiring.join().unwrap(), Err(AccountHomeError::SecretStore(error))
                if error == "credential receipt listing changed; retry acquisition")
            );
        });

        let retried = storage
            .acquire_secret(waiting, SecretClaimMode::AdoptOnly, None)
            .unwrap();
        assert_eq!(retried.keys.secret_key(), keys.secret_key());
        assert_eq!(retried.origin, SecretOrigin::Existing);
    }

    #[test]
    fn unknown_scope_keeps_pending() {
        for (original_scope, current_scope) in [(None, Some("scope-a")), (Some("scope-a"), None)] {
            let directory = tempfile::tempdir().unwrap();
            let storage = LocalFileSecretStore::new(directory.path(), crate::IosOptions::default());
            let keys = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
            let account = keys.public_key().to_hex();
            let home = "11".repeat(32);
            let first_owner = "22".repeat(32);
            let next_owner = "33".repeat(32);
            let first = SecretCredential {
                label: "legacy-user",
                account_id_hex: &account,
                home_id: &home,
                owner_id: &first_owner,
                kind: SecretCredentialKind::Signing,
            };
            acquire(
                &storage,
                first,
                Addressing::AccountId,
                SecretClaimMode::MigrateLegacy,
                None,
                || Ok(Some((keys, original_scope.map(str::to_owned)))),
            )
            .unwrap();
            release(
                &storage,
                first,
                Addressing::AccountId,
                SecretReleaseMode::Preserve,
                || Ok(current_scope),
                |_| Ok(false),
            )
            .unwrap();
            let next = SecretCredential {
                owner_id: &next_owner,
                ..first
            };
            acquire(
                &storage,
                next,
                Addressing::AccountId,
                SecretClaimMode::AdoptOnly,
                None,
                || Ok(None),
            )
            .unwrap();
            for _ in 0..2 {
                let reopened =
                    LocalFileSecretStore::new(directory.path(), crate::IosOptions::default());
                assert_eq!(
                    release(
                        &reopened,
                        next,
                        Addressing::AccountId,
                        SecretReleaseMode::DeleteIfUnowned,
                        || Ok(current_scope),
                        |_| Ok(false),
                    )
                    .unwrap(),
                    SecretReleaseOutcome::PendingLegacy
                );
                assert!(reopened.names(RecordKind::Receipt).unwrap().is_empty());
                assert!(matches!(
                    acquire(
                        &reopened,
                        next,
                        Addressing::AccountId,
                        SecretClaimMode::AdoptOnly,
                        None,
                        || Ok(None)
                    ),
                    Err(AccountHomeError::SecretStore(_))
                ));
            }
        }
    }

    #[test]
    fn adoption_keeps_legacy_scope() {
        let directory = tempfile::tempdir().unwrap();
        let storage = LocalFileSecretStore::new(directory.path(), crate::IosOptions::default());
        let keys = nostr::prelude::Keys::parse(&"01".repeat(32)).unwrap();
        let account = keys.public_key().to_hex();
        let original = directory.path().join("legacy-a");
        let other = directory.path().join("legacy-b");
        let secret = keys.secret_key().to_secret_hex();
        crate::io::write_secret_bytes(&original, secret.as_bytes()).unwrap();
        let home = "11".repeat(32);
        let first_id = "22".repeat(32);
        let second_id = "33".repeat(32);
        let first = SecretCredential {
            label: "legacy-user",
            account_id_hex: &account,
            home_id: &home,
            owner_id: &first_id,
            kind: SecretCredentialKind::Signing,
        };
        acquire(
            &storage,
            first,
            Addressing::AccountId,
            SecretClaimMode::MigrateLegacy,
            None,
            || Ok(Some((keys, Some("scope-a".into())))),
        )
        .unwrap();
        assert_eq!(
            release(
                &storage,
                first,
                Addressing::AccountId,
                SecretReleaseMode::Preserve,
                || Ok(Some("scope-a")),
                |_| Ok(original.try_exists()?)
            )
            .unwrap(),
            SecretReleaseOutcome::Released
        );
        let second = SecretCredential {
            owner_id: &second_id,
            ..first
        };
        let adopted = acquire(
            &storage,
            second,
            Addressing::AccountId,
            SecretClaimMode::AdoptOnly,
            None,
            || Ok(None),
        )
        .unwrap();
        assert_eq!(adopted.keys.public_key().to_hex(), account);
        assert_eq!(adopted.origin, SecretOrigin::Existing);
        let original_owner =
            LocalFileSecretStore::new(directory.path(), crate::IosOptions::default());
        assert_eq!(
            release(
                &original_owner,
                first,
                Addressing::AccountId,
                SecretReleaseMode::Preserve,
                || Ok(Some("scope-a")),
                |_| Ok(original.try_exists()?)
            )
            .unwrap(),
            SecretReleaseOutcome::Released
        );
        assert_eq!(
            release(
                &original_owner,
                first,
                Addressing::AccountId,
                SecretReleaseMode::DeleteIfUnowned,
                || Ok(Some("scope-a")),
                |_| Ok(original.try_exists()?)
            )
            .unwrap(),
            SecretReleaseOutcome::PendingLegacy
        );
        assert_eq!(
            release(
                &storage,
                second,
                Addressing::AccountId,
                SecretReleaseMode::DeleteIfUnowned,
                || Ok(Some("scope-b")),
                |_| Ok(other.try_exists()?)
            )
            .unwrap(),
            SecretReleaseOutcome::PendingLegacy
        );
        assert!(storage.names(RecordKind::Receipt).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&original).unwrap(), secret);
        drop(storage);

        let reopened = LocalFileSecretStore::new(directory.path(), crate::IosOptions::default());
        assert_eq!(
            release(
                &reopened,
                second,
                Addressing::AccountId,
                SecretReleaseMode::DeleteIfUnowned,
                || Ok(Some("scope-b")),
                |_| Ok(other.try_exists()?)
            )
            .unwrap(),
            SecretReleaseOutcome::PendingLegacy
        );
        assert_eq!(
            release(
                &reopened,
                second,
                Addressing::AccountId,
                SecretReleaseMode::DeleteIfUnowned,
                || Ok(Some("scope-a")),
                |_| Ok(original.try_exists()?)
            )
            .unwrap(),
            SecretReleaseOutcome::PendingLegacy
        );
        std::fs::remove_file(&original).unwrap();
        assert_eq!(
            release(
                &reopened,
                second,
                Addressing::AccountId,
                SecretReleaseMode::DeleteIfUnowned,
                || Ok(Some("scope-a")),
                |_| Ok(original.try_exists()?)
            )
            .unwrap(),
            SecretReleaseOutcome::Released
        );
        let missing_id = "44".repeat(32);
        let missing = SecretCredential {
            owner_id: &missing_id,
            ..first
        };
        assert_eq!(
            release(
                &reopened,
                missing,
                Addressing::AccountId,
                SecretReleaseMode::DeleteIfUnowned,
                || Ok(Some("scope-a")),
                |_| Ok(false)
            )
            .unwrap(),
            SecretReleaseOutcome::PendingLegacy
        );
    }
}
