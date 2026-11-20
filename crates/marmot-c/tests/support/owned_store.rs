use super::host_abi::{
    MarmotSecretCredential, MarmotSecretCredentialKind, MarmotSecretStore, MarmotSecretStoreStatus,
};
use nostr::prelude::{Keys, SecretKey};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

const OK: u32 = MarmotSecretStoreStatus::Ok as u32;
const FAILED: u32 = MarmotSecretStoreStatus::Failed as u32;
const MISSING: u32 = MarmotSecretStoreStatus::NotFound as u32;

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Credential {
    label: String,
    account: String,
    home: String,
    owner: String,
    kind: u32,
}
impl Credential {
    unsafe fn read(value: *const MarmotSecretCredential) -> Result<Self, u32> {
        let value = unsafe { value.as_ref() }.ok_or(FAILED)?;
        let credential = Self {
            label: unsafe { text(value.label) }?,
            account: unsafe { text(value.account_id_hex) }?,
            home: unsafe { text(value.home_id) }?,
            owner: unsafe { text(value.owner_id) }?,
            kind: value.kind,
        };
        if credential.kind > 2
            || !canonical_id(&credential.home)
            || !canonical_id(&credential.owner)
        {
            return Err(FAILED);
        }
        Ok(credential)
    }
    fn shares_source(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.account == other.account
            && (self.kind == 0 || self.home == other.home)
    }
}
fn canonical_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
unsafe fn text(value: *const c_char) -> Result<String, u32> {
    if value.is_null() {
        return Err(FAILED);
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| FAILED)
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Receipt {
    credential: Credential,
    secret: String,
    origin: u32,
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct State {
    active: BTreeMap<String, Receipt>,
    retired: BTreeMap<String, Credential>,
    preserved: BTreeMap<String, Receipt>,
}
pub struct MemoryVault {
    state: Mutex<State>,
    namespace: String,
    path: Option<PathBuf>,
    _lock: Option<File>,
    pub destroyed: AtomicBool,
    pub destroy_count: AtomicUsize,
}
impl Default for MemoryVault {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            namespace: Keys::generate().public_key().to_hex(),
            path: None,
            _lock: None,
            destroyed: AtomicBool::new(false),
            destroy_count: AtomicUsize::new(0),
        }
    }
}
impl MemoryVault {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        lock.try_lock().map_err(io::Error::other)?;
        let (vault, create) = match File::open(path) {
            Ok(file) => {
                let (namespace, state): (String, State) = serde_json::from_reader(file)?;
                (
                    Self {
                        namespace,
                        state: Mutex::new(state),
                        path: None,
                        _lock: None,
                        destroyed: AtomicBool::new(false),
                        destroy_count: AtomicUsize::new(0),
                    },
                    false,
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Self::default(), true),
            Err(error) => return Err(error),
        };
        let vault = Self {
            path: Some(path.to_owned()),
            _lock: Some(lock),
            ..vault
        };
        if create {
            let state = vault
                .state
                .lock()
                .map_err(|_| io::Error::other("vault mutex poisoned"))?;
            vault.persist(&state)?;
        }
        Ok(vault)
    }
    fn lock_state(&self) -> Result<MutexGuard<'_, State>, u32> {
        let mut state = self.state.lock().map_err(|_| FAILED)?;
        if let Some(path) = &self.path {
            let file = File::open(path).map_err(|_| FAILED)?;
            let (namespace, durable): (String, State) =
                serde_json::from_reader(file).map_err(|_| FAILED)?;
            if namespace != self.namespace {
                return Err(FAILED);
            }
            *state = durable;
        }
        Ok(state)
    }
    fn persist(&self, state: &State) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("vault path has no parent"))?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(&mut file, &(&self.namespace, state))?;
        file.flush()?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| error.error)?;
        File::open(parent)?.sync_all()
    }
    pub fn snapshot(&self) -> Result<Vec<(String, String, String)>, u32> {
        Ok(self
            .lock_state()?
            .active
            .values()
            .map(|receipt| {
                (
                    receipt.credential.label.clone(),
                    receipt.credential.account.clone(),
                    receipt.secret.clone(),
                )
            })
            .collect())
    }
    pub(super) fn has_preserved_pairing(&self, label: &str) -> Result<bool, u32> {
        Ok(self.lock_state()?.preserved.values().any(|receipt| {
            receipt.credential.label == label
                && receipt.credential.kind == MarmotSecretCredentialKind::Nip46Session as u32
        }))
    }
    pub fn global() -> &'static Self {
        static VAULT: LazyLock<MemoryVault> = LazyLock::new(MemoryVault::default);
        &VAULT
    }
    pub fn table(&self) -> MarmotSecretStore {
        MarmotSecretStore {
            user_data: (self as *const Self).cast_mut().cast(),
            cleanup_namespace: Some(Self::cleanup_namespace),
            has_secret_for_label: Some(Self::has_label),
            has_secret_for_account_id: Some(Self::has_account),
            acquire_secret: Some(Self::acquire),
            load_secret: Some(Self::load),
            release_secret: Some(Self::release),
            reconcile_cleanup: Some(Self::reconcile),
            free_secret: Some(Self::free),
            destroy: None,
        }
    }
    unsafe fn context<'a>(data: *mut c_void) -> &'a Self {
        unsafe { &*data.cast::<Self>() }
    }
    unsafe extern "C" fn cleanup_namespace(data: *mut c_void, out: *mut *mut c_char) -> u32 {
        let vault = unsafe { Self::context(data) };
        unsafe { out.write(CString::new(vault.namespace.as_str()).unwrap().into_raw()) };
        OK
    }
    unsafe fn probe(data: *mut c_void, key: *const c_char, out: *mut u8, label: bool) -> u32 {
        unsafe { out.write(0) };
        let Ok(key) = (unsafe { text(key) }) else {
            return FAILED;
        };
        let Ok(state) = (unsafe { Self::context(data) }).lock_state() else {
            return FAILED;
        };
        let present = state
            .active
            .values()
            .chain(state.preserved.values())
            .any(|r| {
                r.credential.kind == 0
                    && if label {
                        r.credential.label == key
                    } else {
                        r.credential.account == key
                    }
            });
        unsafe { out.write(u8::from(present)) };
        OK
    }
    unsafe extern "C" fn has_label(data: *mut c_void, key: *const c_char, out: *mut u8) -> u32 {
        unsafe { Self::probe(data, key, out, true) }
    }
    unsafe extern "C" fn has_account(data: *mut c_void, key: *const c_char, out: *mut u8) -> u32 {
        unsafe { Self::probe(data, key, out, false) }
    }
    unsafe extern "C" fn acquire(
        data: *mut c_void,
        credential: *const MarmotSecretCredential,
        mode: u32,
        proposed: *const c_char,
        out: *mut *mut c_char,
        origin: *mut u32,
    ) -> u32 {
        unsafe {
            out.write(std::ptr::null_mut());
            origin.write(0);
        }
        let Ok(credential) = (unsafe { Credential::read(credential) }) else {
            return FAILED;
        };
        if mode > 3 {
            return FAILED;
        }
        let proposed = if proposed.is_null() {
            None
        } else {
            let Ok(secret) = (unsafe { text(proposed) }) else {
                return FAILED;
            };
            let Ok(secret) = SecretKey::from_hex(&secret) else {
                return FAILED;
            };
            let keys = Keys::new(secret);
            if credential.kind == 0 && keys.public_key().to_hex() != credential.account {
                return FAILED;
            }
            Some(keys.secret_key().to_secret_hex())
        };
        if mode == 0 && proposed.is_none() {
            return FAILED;
        }
        let Ok(mut state) = (unsafe { Self::context(data) }).lock_state() else {
            return FAILED;
        };
        if state.retired.contains_key(&credential.owner) {
            return FAILED;
        }
        let receipt = if let Some(existing) = state.active.get(&credential.owner) {
            if existing.credential != credential
                || proposed.as_ref().is_some_and(|s| s != &existing.secret)
            {
                return FAILED;
            }
            existing.clone()
        } else {
            let mut source = None;
            for candidate in state.active.values().chain(state.preserved.values()) {
                if credential.shares_source(&candidate.credential) {
                    if source
                        .as_ref()
                        .is_some_and(|s: &String| s != &candidate.secret)
                    {
                        return FAILED;
                    }
                    source = Some(candidate.secret.clone());
                }
            }
            if mode == 0 && source.is_some() {
                return FAILED;
            }
            let (secret, original) = match source {
                Some(secret) => {
                    if proposed.as_ref().is_some_and(|s| s != &secret) {
                        return FAILED;
                    }
                    (secret, 1)
                }
                None if mode == 1 || mode == 3 => return MISSING,
                None => match proposed {
                    Some(secret) => (secret, 0),
                    None => return MISSING,
                },
            };
            let receipt = Receipt {
                credential: credential.clone(),
                secret,
                origin: original,
            };
            state
                .active
                .insert(credential.owner.clone(), receipt.clone());
            // Only a newly installed ownership copy consumes preservation holds.
            state
                .preserved
                .retain(|_, old| !credential.shares_source(&old.credential));
            receipt
        };
        if (unsafe { Self::context(data) }).persist(&state).is_err() {
            return FAILED;
        }
        unsafe {
            out.write(CString::new(receipt.secret).unwrap().into_raw());
            origin.write(receipt.origin);
        }
        OK
    }
    unsafe extern "C" fn load(
        data: *mut c_void,
        credential: *const MarmotSecretCredential,
        out: *mut *mut c_char,
    ) -> u32 {
        unsafe { out.write(std::ptr::null_mut()) };
        let Ok(credential) = (unsafe { Credential::read(credential) }) else {
            return FAILED;
        };
        let Ok(state) = (unsafe { Self::context(data) }).lock_state() else {
            return FAILED;
        };
        let Some(receipt) = state.active.get(&credential.owner) else {
            return MISSING;
        };
        if receipt.credential != credential {
            return FAILED;
        }
        unsafe { out.write(CString::new(receipt.secret.as_str()).unwrap().into_raw()) };
        OK
    }
    unsafe extern "C" fn release(
        data: *mut c_void,
        credential: *const MarmotSecretCredential,
        mode: u32,
        outcome: *mut u32,
    ) -> u32 {
        unsafe { outcome.write(0) };
        if mode > 1 {
            return FAILED;
        }
        let Ok(credential) = (unsafe { Credential::read(credential) }) else {
            return FAILED;
        };
        let Ok(mut state) = (unsafe { Self::context(data) }).lock_state() else {
            return FAILED;
        };
        if let Some(retired) = state.retired.get(&credential.owner) {
            if retired != &credential {
                return FAILED;
            }
            return if (unsafe { Self::context(data) }).persist(&state).is_ok() {
                OK
            } else {
                FAILED
            };
        }
        if let Some(receipt) = state.active.get(&credential.owner)
            && receipt.credential != credential
        {
            return FAILED;
        }
        state
            .retired
            .insert(credential.owner.clone(), credential.clone());
        if let Some(receipt) = state.active.remove(&credential.owner)
            && mode == 1
        {
            state.preserved.insert(credential.owner, receipt);
        }
        if (unsafe { Self::context(data) }).persist(&state).is_err() {
            return FAILED;
        }
        OK
    }
    unsafe extern "C" fn reconcile(data: *mut c_void) -> u32 {
        let Ok(mut state) = (unsafe { Self::context(data) }).lock_state() else {
            return FAILED;
        };
        let State {
            active, retired, ..
        } = &mut *state;
        active.retain(|owner, _| !retired.contains_key(owner));
        if (unsafe { Self::context(data) }).persist(&state).is_err() {
            return FAILED;
        }
        OK
    }
    pub unsafe extern "C" fn free(_: *mut c_void, secret: *mut c_char) {
        if !secret.is_null() {
            drop(unsafe { CString::from_raw(secret) });
        }
    }
    pub unsafe extern "C" fn destroy_mark(data: *mut c_void) {
        let vault = unsafe { Self::context(data) };
        vault.destroyed.store(true, Ordering::SeqCst);
        vault.destroy_count.fetch_add(1, Ordering::SeqCst);
    }
    pub unsafe extern "C" fn destroy_box(data: *mut c_void) {
        drop(unsafe { Box::from_raw(data.cast::<Self>()) });
    }
    pub unsafe extern "C" fn destroy_arc(data: *mut c_void) {
        drop(unsafe { Arc::from_raw(data.cast::<Self>()) });
    }
}
