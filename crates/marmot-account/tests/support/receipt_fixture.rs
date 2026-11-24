#[derive(Clone, Copy)]
enum AcquireFault {
    BeforeWrite,
    AfterWrite,
}

struct FaultAcquireStore {
    inner: LocalFileSecretStore,
    fault: Mutex<Option<AcquireFault>>,
}

impl AccountSecretStore for FaultAcquireStore {
    fn cleanup_namespace(&self) -> AccountHomeResult<String> {
        self.inner.cleanup_namespace()
    }

    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        self.inner.has_secret_for_label(label)
    }

    fn has_secret_for_account_id(&self, account_id_hex: &str) -> AccountHomeResult<bool> {
        self.inner.has_secret_for_account_id(account_id_hex)
    }

    fn acquire_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        let fault = if credential.kind == SecretCredentialKind::Nip46Session
            && mode == SecretClaimMode::CreateOrAdopt
        {
            self.fault.lock().unwrap().take()
        } else {
            None
        };
        if matches!(fault, Some(AcquireFault::BeforeWrite)) {
            return Err(AccountHomeError::SecretStore(
                "injected unavailable vault before write".into(),
            ));
        }
        let acquired = self.inner.acquire_secret(credential, mode, proposed)?;
        if matches!(fault, Some(AcquireFault::AfterWrite)) {
            return Err(AccountHomeError::SecretStore(
                "injected unavailable vault after write".into(),
            ));
        }
        Ok(acquired)
    }

    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        self.inner.load_secret(credential)
    }

    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome> {
        self.inner.release_secret(credential, mode)
    }

    fn reconcile_cleanup(&self) -> AccountHomeResult<()> {
        self.inner.reconcile_cleanup()
    }
}

const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(10);

struct VaultCheckpoint {
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}

struct VaultPause {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl VaultCheckpoint {
    fn new() -> (Self, VaultPause) {
        let (signal_entry, entered) = mpsc::channel();
        let (release, await_release) = mpsc::channel();
        (
            Self { entered, release },
            VaultPause {
                entered: signal_entry,
                release: Mutex::new(await_release),
            },
        )
    }

    fn wait_for_entry(&self) {
        self.entered
            .recv_timeout(CHECKPOINT_TIMEOUT)
            .expect("worker did not reach the vault checkpoint");
    }

    fn before_release<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (finished, result) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = finished.send(operation());
        });
        result
            .recv_timeout(CHECKPOINT_TIMEOUT)
            .expect("competing operation did not finish while the vault was paused")
    }

    fn release(self) {
        self.release.send(()).expect("paused worker exited");
    }
}

impl VaultPause {
    fn wait(&self) {
        if self.entered.send(()).is_ok() {
            // Dropping the checkpoint on failure disconnects the waiting worker.
            match self
                .release
                .lock()
                .unwrap()
                .recv_timeout(CHECKPOINT_TIMEOUT)
            {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => panic!("vault checkpoint was not released"),
            }
        }
    }
}

struct PausedReadStore {
    inner: Arc<dyn AccountSecretStore>,
    pause: VaultPause,
}

impl AccountSecretStore for PausedReadStore {
    fn cleanup_namespace(&self) -> AccountHomeResult<String> {
        self.inner.cleanup_namespace()
    }

    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        self.inner.has_secret_for_label(label)
    }

    fn has_secret_for_account_id(&self, account_id_hex: &str) -> AccountHomeResult<bool> {
        self.inner.has_secret_for_account_id(account_id_hex)
    }

    fn acquire_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        self.inner.acquire_secret(credential, mode, proposed)
    }

    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        self.pause.wait();
        self.inner.load_secret(credential)
    }

    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome> {
        self.inner.release_secret(credential, mode)
    }

    fn reconcile_cleanup(&self) -> AccountHomeResult<()> {
        self.inner.reconcile_cleanup()
    }
}

struct MemorySecretStore {
    namespace: String,
    fail_namespace: AtomicBool,
    pause: Mutex<Option<StorePause>>,
    keys: Mutex<HashMap<String, String>>,
    ownership: Mutex<MemoryOwnership>,
    account_id_keys: AtomicBool,
    fail_lookup: AtomicBool,
    fail_id_lookup: AtomicBool,
    hide_presence: AtomicBool,
    load_error: Mutex<Option<AccountHomeError>>,
    fail_write: AtomicBool,
    fail_write_after_commit: AtomicBool,
    interrupt_before_write: AtomicBool,
    interrupt_after_write: AtomicBool,
    fail_remove: AtomicBool,
    fail_remove_after_delete: AtomicBool,
}

#[derive(Default)]
struct MemoryOwnership {
    owners: HashMap<String, MemoryOwner>,
    counts: HashMap<String, usize>,
    retired: HashMap<String, (MemoryCredential, SecretReleaseMode)>,
    retained: HashSet<String>,
}

struct MemoryCredential {
    label: String,
    account_id_hex: String,
    home_id: String,
    kind: SecretCredentialKind,
}

impl MemoryCredential {
    fn new(credential: SecretCredential<'_>) -> Self {
        Self {
            label: credential.label.to_owned(),
            account_id_hex: credential.account_id_hex.to_owned(),
            home_id: credential.home_id.to_owned(),
            kind: credential.kind,
        }
    }

    fn matches(&self, credential: SecretCredential<'_>) -> bool {
        self.label == credential.label
            && self.account_id_hex == credential.account_id_hex
            && self.home_id == credential.home_id
            && self.kind == credential.kind
    }
}

struct MemoryOwner {
    credential: MemoryCredential,
    key: String,
    origin: SecretOrigin,
}

struct StorePause {
    operation: &'static str,
    pause: VaultPause,
}

impl Default for MemorySecretStore {
    fn default() -> Self {
        Self {
            namespace: nostr::prelude::Keys::generate().public_key().to_hex(),
            fail_namespace: AtomicBool::default(),
            pause: Mutex::default(),
            keys: Mutex::default(),
            ownership: Mutex::default(),
            account_id_keys: AtomicBool::default(),
            fail_lookup: AtomicBool::default(),
            fail_id_lookup: AtomicBool::default(),
            hide_presence: AtomicBool::default(),
            load_error: Mutex::default(),
            fail_write: AtomicBool::default(),
            fail_write_after_commit: AtomicBool::default(),
            interrupt_before_write: AtomicBool::default(),
            interrupt_after_write: AtomicBool::default(),
            fail_remove: AtomicBool::default(),
            fail_remove_after_delete: AtomicBool::default(),
        }
    }
}

impl MemorySecretStore {
    fn finish_release(
        &self,
        state: &mut MemoryOwnership,
        keys: &mut HashMap<String, String>,
        owner_id: &str,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<()> {
        if !state.owners.contains_key(owner_id) {
            return Ok(());
        }
        if self.fail_remove.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected removal failure".into(),
            ));
        }
        let owner = state.owners.remove(owner_id).unwrap();
        let count = state.counts.get_mut(&owner.key).unwrap();
        *count -= 1;
        let unused = *count == 0;
        if unused {
            state.counts.remove(&owner.key);
        }
        if mode == SecretReleaseMode::Preserve {
            state.retained.insert(owner.key);
        } else if unused && !state.retained.contains(&owner.key) {
            keys.remove(&owner.key);
        }
        if self.fail_remove_after_delete.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected post-delete failure".into(),
            ));
        }
        Ok(())
    }

    fn pause_once(&self, operation: &'static str) -> VaultCheckpoint {
        let (checkpoint, pause) = VaultCheckpoint::new();
        *self.pause.lock().unwrap() = Some(StorePause { operation, pause });
        checkpoint
    }

    fn pause_operation(&self, operation: &str) {
        let pause = {
            let mut pause = self.pause.lock().unwrap();
            if pause
                .as_ref()
                .is_some_and(|pause| pause.operation == operation)
            {
                pause.take()
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            pause.pause.wait();
        }
    }

    fn credential_key(&self, credential: SecretCredential<'_>) -> String {
        let key = if self.account_id_keys.load(Ordering::SeqCst) {
            credential.account_id_hex
        } else {
            credential.label
        };
        if credential.kind == SecretCredentialKind::Signing {
            key.to_owned()
        } else {
            format!("{}:{:?}:{key}", credential.home_id, credential.kind)
        }
    }
}

impl AccountSecretStore for MemorySecretStore {
    fn cleanup_namespace(&self) -> AccountHomeResult<String> {
        if self.fail_namespace.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected namespace lookup failure".into(),
            ));
        }
        Ok(self.namespace.clone())
    }
    fn has_secret_for_account_id(&self, id: &str) -> AccountHomeResult<bool> {
        self.pause_operation("has_id");
        if self.fail_id_lookup.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected account-id lookup failure".into(),
            ));
        }
        Ok(self.account_id_keys.load(Ordering::SeqCst)
            && self.keys.lock().unwrap().contains_key(id))
    }
    fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
        if self.fail_lookup.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected locked vault".into(),
            ));
        }
        Ok(!self.account_id_keys.load(Ordering::SeqCst)
            && !self.hide_presence.load(Ordering::SeqCst)
            && self.keys.lock().unwrap().contains_key(label))
    }
    fn acquire_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretClaimMode,
        proposed: Option<&nostr::prelude::Keys>,
    ) -> AccountHomeResult<AcquiredSecret> {
        self.pause_operation("write");
        if proposed.is_some() {
            assert!(
                !self.interrupt_before_write.load(Ordering::SeqCst),
                "interrupted before vault write"
            );
        }
        let mut state = self.ownership.lock().unwrap();
        let mut keys = self.keys.lock().unwrap();
        if state.retired.contains_key(credential.owner_id) {
            return Err(AccountHomeError::SecretStore(
                "retired owner cannot acquire again".into(),
            ));
        }
        if let Some(error) = self.load_error.lock().unwrap().take() {
            return Err(error);
        }
        if let Some(owner) = state.owners.get(credential.owner_id) {
            if !owner.credential.matches(credential) {
                return Err(AccountHomeError::AccountIdMismatch);
            }
            let stored = keys.get(&owner.key).ok_or_else(|| {
                AccountHomeError::SecretStore("owned credential material is missing".into())
            })?;
            let stored = nostr::prelude::Keys::parse(stored)
                .map_err(|_| AccountHomeError::InvalidSecretKey)?;
            if proposed.is_some_and(|keys| keys.secret_key() != stored.secret_key()) {
                return Err(AccountHomeError::AccountIdMismatch);
            }
            return Ok(AcquiredSecret {
                keys: stored,
                origin: owner.origin,
            });
        }
        let key = self.credential_key(credential);
        let (material, origin) = if let Some(stored) = keys.get(&key) {
            if mode == SecretClaimMode::CreateOnly {
                return Err(AccountHomeError::AccountExists(credential.label.to_owned()));
            }
            (
                nostr::prelude::Keys::parse(stored)
                    .map_err(|_| AccountHomeError::InvalidSecretKey)?,
                SecretOrigin::Existing,
            )
        } else {
            if mode == SecretClaimMode::AdoptOnly {
                return Err(AccountHomeError::SecretNotFound(
                    credential.label.to_owned(),
                ));
            }
            (
                proposed
                    .ok_or_else(|| AccountHomeError::SecretNotFound(credential.label.to_owned()))?
                    .clone(),
                SecretOrigin::Created,
            )
        };
        if (credential.kind == SecretCredentialKind::Signing
            && material.public_key().to_hex() != credential.account_id_hex)
            || proposed.is_some_and(|keys| keys.secret_key() != material.secret_key())
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        if self.fail_write.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected write failure".into(),
            ));
        }
        keys.entry(key.clone())
            .or_insert_with(|| material.secret_key().to_secret_hex());
        if let Some(count) = state.counts.get_mut(&key) {
            *count += 1;
        } else {
            state.counts.insert(key.clone(), 1);
        }
        state.retained.remove(&key);
        state.owners.insert(
            credential.owner_id.to_owned(),
            MemoryOwner {
                credential: MemoryCredential::new(credential),
                key,
                origin,
            },
        );
        drop(keys);
        drop(state);
        if self.fail_write_after_commit.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected write failure".into(),
            ));
        }
        assert!(
            !self.interrupt_after_write.load(Ordering::SeqCst),
            "interrupted after vault write"
        );
        Ok(AcquiredSecret {
            keys: material,
            origin,
        })
    }
    fn load_secret(
        &self,
        credential: SecretCredential<'_>,
    ) -> AccountHomeResult<nostr::prelude::Keys> {
        if let Some(error) = self.load_error.lock().unwrap().take() {
            return Err(error);
        }
        let state = self.ownership.lock().unwrap();
        if state.retired.contains_key(credential.owner_id) {
            return Err(AccountHomeError::SecretNotFound(
                credential.label.to_owned(),
            ));
        }
        let owner = state
            .owners
            .get(credential.owner_id)
            .ok_or_else(|| AccountHomeError::SecretNotFound(credential.label.to_owned()))?;
        if !owner.credential.matches(credential) {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        let keys = self.keys.lock().unwrap();
        let secret = keys
            .get(&owner.key)
            .ok_or_else(|| AccountHomeError::SecretNotFound(credential.label.to_owned()))?;
        nostr::prelude::Keys::parse(secret).map_err(|_| AccountHomeError::InvalidSecretKey)
    }
    fn release_secret(
        &self,
        credential: SecretCredential<'_>,
        mode: SecretReleaseMode,
    ) -> AccountHomeResult<SecretReleaseOutcome> {
        self.pause_operation("remove");
        if self.fail_remove.load(Ordering::SeqCst) {
            return Err(AccountHomeError::SecretStore(
                "injected removal failure".into(),
            ));
        }
        let mut state = self.ownership.lock().unwrap();
        if state
            .owners
            .get(credential.owner_id)
            .is_some_and(|owner| !owner.credential.matches(credential))
        {
            return Err(AccountHomeError::AccountIdMismatch);
        }
        if let Some((target, previous)) = state.retired.get(credential.owner_id) {
            if !target.matches(credential) || previous != &mode {
                return Err(AccountHomeError::AccountIdMismatch);
            }
        } else {
            state.retired.insert(
                credential.owner_id.to_owned(),
                (MemoryCredential::new(credential), mode),
            );
        }
        let mut keys = self.keys.lock().unwrap();
        self.finish_release(&mut state, &mut keys, credential.owner_id, mode)?;
        Ok(SecretReleaseOutcome::Released)
    }
    fn reconcile_cleanup(&self) -> AccountHomeResult<()> {
        let mut state = self.ownership.lock().unwrap();
        let pending: Vec<_> = state
            .retired
            .iter()
            .filter(|(id, _)| state.owners.contains_key(*id))
            .map(|(id, (_, mode))| (id.clone(), *mode))
            .collect();
        let mut keys = self.keys.lock().unwrap();
        for (id, mode) in pending {
            self.finish_release(&mut state, &mut keys, &id, mode)?;
        }
        Ok(())
    }
}
