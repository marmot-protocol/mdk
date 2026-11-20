use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::keyring::initialize_keyring_store;
use crate::keyring::map_keyring_error;
use crate::location::IosOptions;
use crate::owned_vault::{RecordKind, VaultStorage};

pub(crate) struct NativeVault {
    backend: Backend,
    service: String,
    receipts: String,
    retirements: String,
    namespace: String,
    legacy_scope: Option<String>,
}

impl std::fmt::Debug for NativeVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeVault").finish_non_exhaustive()
    }
}

impl NativeVault {
    pub(crate) fn new(service: &str, ios_options: &IosOptions) -> AccountHomeResult<Self> {
        if service.is_empty() {
            return Err(AccountHomeError::EmptySecretStoreService);
        }
        if service.contains('\0') {
            return Err(vault_error("native service contains NUL"));
        }
        initialize_keyring_store()?;
        let store = keyring_core::get_default_store().ok_or_else(|| {
            AccountHomeError::SecretStoreNotInitialized("no captured credential store".into())
        })?;
        let backend = Backend::new(store, ios_options)?;
        let service_hash = hex::encode(Sha256::digest(service.as_bytes()));
        let receipts = format!("mdk-owned-receipt-v1-{service_hash}");
        let retirements = format!("mdk-owned-retirement-v1-{service_hash}");
        let namespace = format!(
            "mdk-native-vault-v1:{}:{service_hash}",
            hex::encode(Sha256::digest(backend.target().as_bytes()))
        );
        let legacy_scope = backend.legacy_target().map(|target| {
            format!(
                "mdk-native-legacy-v1:{}:{service_hash}",
                hex::encode(Sha256::digest(target.as_bytes()))
            )
        });
        Ok(Self {
            backend,
            service: service.to_owned(),
            receipts,
            retirements,
            namespace,
            legacy_scope,
        })
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn legacy_scope(&self) -> Option<&str> {
        self.legacy_scope.as_deref()
    }

    pub(crate) fn legacy_secret(
        &self,
        account_id: &str,
    ) -> AccountHomeResult<Option<Zeroizing<String>>> {
        if account_id.is_empty() || account_id.contains('\0') {
            return Err(vault_error("invalid legacy credential account"));
        }
        #[cfg(target_os = "ios")]
        {
            let current = format!("{}.after-first-unlock-v1", self.service);
            let mut secret = self.backend.legacy_secret(&current, account_id)?;
            merge_secret(
                &mut secret,
                self.backend.legacy_secret(&self.service, account_id)?,
            )?;
            Ok(secret)
        }
        #[cfg(not(target_os = "ios"))]
        {
            self.backend.legacy_secret(&self.service, account_id)
        }
    }

    fn service(&self, kind: &RecordKind) -> &str {
        match kind {
            RecordKind::Receipt => &self.receipts,
            RecordKind::Retirement => &self.retirements,
        }
    }
}

impl VaultStorage for NativeVault {
    fn read(&self, kind: RecordKind, name: &str) -> AccountHomeResult<Option<Zeroizing<String>>> {
        check_name(name)?;
        self.backend.read(self.service(&kind), name)
    }

    fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()> {
        check_name(name)?;
        if value.len() > 4096 {
            return Err(vault_error("native vault value exceeds 4096 bytes"));
        }
        let service = self.service(&kind);
        if matches!(kind, RecordKind::Receipt)
            && let Some(existing) = self.backend.read(service, name)?
        {
            if existing.as_str() == value {
                return Ok(());
            }
            return Err(vault_error("native receipt is immutable"));
        }
        self.backend.write(service, name, value)
    }

    fn remove(&self, kind: RecordKind, name: &str) -> AccountHomeResult<()> {
        check_name(name)?;
        self.backend.remove(self.service(&kind), name)
    }

    fn names(&self, kind: RecordKind) -> AccountHomeResult<Vec<String>> {
        let mut names = self.backend.names(self.service(&kind))?;
        for name in &names {
            check_name(name)?;
        }
        names.sort_unstable();
        names.dedup();
        Ok(names)
    }
}

fn check_name(name: &str) -> AccountHomeResult<()> {
    if name.len() != 129
        || name.as_bytes()[64] != b'-'
        || !name
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 64 || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(vault_error("invalid native vault record name"));
    }
    Ok(())
}

fn vault_error(message: &str) -> AccountHomeError {
    AccountHomeError::SecretStore(message.to_owned())
}

#[cfg(all(
    not(test),
    any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
fn native_error(error: impl std::fmt::Display) -> AccountHomeError {
    AccountHomeError::SecretStore(format!("native vault: {error}"))
}

#[cfg(all(
    not(test),
    any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    )
))]
fn decode_secret(bytes: Vec<u8>) -> AccountHomeResult<Zeroizing<String>> {
    match String::from_utf8(bytes) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let _bytes = Zeroizing::new(error.into_bytes());
            Err(vault_error("native credential is not UTF-8"))
        }
    }
}

#[cfg(any(
    target_os = "ios",
    all(
        not(test),
        any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )
    )
))]
fn merge_secret(
    value: &mut Option<Zeroizing<String>>,
    candidate: Option<Zeroizing<String>>,
) -> AccountHomeResult<()> {
    if let Some(candidate) = candidate {
        match value {
            Some(existing) if existing.as_str() != candidate.as_str() => {
                return Err(vault_error("conflicting duplicate native credentials"));
            }
            Some(_) => {}
            None => *value = Some(candidate),
        }
    }
    Ok(())
}

enum Backend {
    ExplicitMock(mock_backend::Backend),
    #[cfg(not(test))]
    Native(platform::Backend),
}

impl Backend {
    fn new(
        store: Arc<keyring_core::api::CredentialStore>,
        _ios_options: &IosOptions,
    ) -> AccountHomeResult<Self> {
        if store.as_any().is::<keyring_core::mock::Store>() {
            return Ok(Self::ExplicitMock(mock_backend::Backend::new(store)?));
        }
        #[cfg(not(test))]
        {
            Ok(Self::Native(platform::Backend::new(store, _ios_options)?))
        }
        #[cfg(test)]
        {
            Err(vault_error(
                "unit fixture must explicitly install its mock provider",
            ))
        }
    }

    fn target(&self) -> &str {
        match self {
            Self::ExplicitMock(backend) => backend.target(),
            #[cfg(not(test))]
            Self::Native(backend) => backend.target(),
        }
    }

    fn legacy_target(&self) -> Option<&str> {
        match self {
            Self::ExplicitMock(backend) => Some(backend.target()),
            #[cfg(not(test))]
            Self::Native(backend) => {
                #[cfg(target_os = "ios")]
                {
                    backend.legacy_target()
                }
                #[cfg(target_os = "windows")]
                {
                    Some(backend.legacy_target())
                }
                #[cfg(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly"
                ))]
                {
                    // The raw search spans collections beyond the managed target.
                    let _ = backend;
                    None
                }
                #[cfg(not(any(
                    target_os = "ios",
                    target_os = "windows",
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly"
                )))]
                {
                    Some(backend.target())
                }
            }
        }
    }

    fn legacy_secret(
        &self,
        service: &str,
        name: &str,
    ) -> AccountHomeResult<Option<Zeroizing<String>>> {
        match self {
            Self::ExplicitMock(backend) => backend.legacy_secret(service, name),
            #[cfg(not(test))]
            Self::Native(backend) => backend.legacy_secret(service, name),
        }
    }

    fn read(&self, service: &str, name: &str) -> AccountHomeResult<Option<Zeroizing<String>>> {
        match self {
            Self::ExplicitMock(backend) => backend.read(service, name),
            #[cfg(not(test))]
            Self::Native(backend) => backend.read(service, name),
        }
    }

    fn write(&self, service: &str, name: &str, value: &str) -> AccountHomeResult<()> {
        match self {
            Self::ExplicitMock(backend) => backend.write(service, name, value),
            #[cfg(not(test))]
            Self::Native(backend) => backend.write(service, name, value),
        }
    }

    fn remove(&self, service: &str, name: &str) -> AccountHomeResult<()> {
        match self {
            Self::ExplicitMock(backend) => backend.remove(service, name),
            #[cfg(not(test))]
            Self::Native(backend) => backend.remove(service, name),
        }
    }

    fn names(&self, service: &str) -> AccountHomeResult<Vec<String>> {
        match self {
            Self::ExplicitMock(backend) => backend.names(service),
            #[cfg(not(test))]
            Self::Native(backend) => backend.names(service),
        }
    }
}

mod mock_backend {
    use super::*;

    pub(super) struct Backend {
        store: Arc<keyring_core::api::CredentialStore>,
        target: String,
    }

    impl Backend {
        pub(super) fn new(
            store: Arc<keyring_core::api::CredentialStore>,
        ) -> AccountHomeResult<Self> {
            if !store.as_any().is::<keyring_core::mock::Store>() {
                return Err(vault_error(
                    "unit tests require an explicit mock credential provider",
                ));
            }
            let target = format!("mock:{}:{}", store.vendor(), store.id());
            Ok(Self { store, target })
        }

        pub(super) fn target(&self) -> &str {
            &self.target
        }

        pub(super) fn legacy_secret(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            self.read(service, name)
        }

        fn entries(
            &self,
            service: &str,
            name: Option<&str>,
        ) -> AccountHomeResult<Vec<keyring_core::Entry>> {
            let mut entries = Vec::new();
            for entry in self
                .store
                .search(&HashMap::from([("service", service)]))
                .map_err(map_keyring_error)?
            {
                let (actual_service, actual_name) = entry
                    .get_specifiers()
                    .ok_or_else(|| vault_error("mock credential has no specifiers"))?;
                if actual_service == service && name.is_none_or(|name| name == actual_name) {
                    match entry.get_password() {
                        Ok(value) => {
                            let _value = Zeroizing::new(value);
                            entries.push(entry);
                        }
                        Err(keyring_core::Error::NoEntry) => {}
                        Err(error) => return Err(map_keyring_error(error)),
                    }
                }
            }
            Ok(entries)
        }

        pub(super) fn read(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            let entry = self
                .store
                .build(service, name, None)
                .map_err(map_keyring_error)?;
            match entry.get_password() {
                Ok(value) => Ok(Some(Zeroizing::new(value))),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(error) => Err(map_keyring_error(error)),
            }
        }

        pub(super) fn write(
            &self,
            service: &str,
            name: &str,
            value: &str,
        ) -> AccountHomeResult<()> {
            self.store
                .build(service, name, None)
                .map_err(map_keyring_error)?
                .set_password(value)
                .map_err(map_keyring_error)
        }

        pub(super) fn remove(&self, service: &str, name: &str) -> AccountHomeResult<()> {
            for entry in self.entries(service, Some(name))? {
                entry.delete_credential().map_err(map_keyring_error)?;
            }
            Ok(())
        }

        pub(super) fn names(&self, service: &str) -> AccountHomeResult<Vec<String>> {
            self.entries(service, None)?
                .into_iter()
                .map(|entry| {
                    entry
                        .get_specifiers()
                        .map(|(_, name)| name)
                        .ok_or_else(|| vault_error("mock credential has no specifiers"))
                })
                .collect()
        }
    }
}

#[cfg(all(
    not(test),
    any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
mod platform {
    use super::*;
    use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    use crypto_bigint::{
        Odd, U1024,
        modular::{FixedMontyForm, FixedMontyParams},
    };
    use std::sync::Mutex;
    use zbus::blocking::{Connection, Proxy};
    use zbus::fdo::{ReleaseNameReply, RequestNameFlags, RequestNameReply};
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

    const SERVICE: &str = "org.freedesktop.secrets";
    const ROOT: &str = "/org/freedesktop/secrets";
    const ITEM: &str = "org.freedesktop.Secret.Item";
    const COLLECTION: &str = "org.freedesktop.Secret.Collection";
    const MARKER_SERVICE: &str = "mdk-owned-collection-v1";
    const MARKER_ID: &str = "mdk-collection-id";
    const DH_PRIME: Odd<U1024> = Odd::<U1024>::from_be_hex(concat!(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020B",
        "BEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D",
        "6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A89",
        "9FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
    ));
    const DH_PARAMS: FixedMontyParams<{ U1024::LIMBS }> = FixedMontyParams::new(DH_PRIME);
    type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

    fn open_session(root: &Proxy<'_>) -> AccountHomeResult<(OwnedObjectPath, Zeroizing<[u8; 16]>)> {
        let mut random = Zeroizing::new([0u8; 128]);
        getrandom::fill(random.as_mut()).map_err(native_error)?;
        let private = Zeroizing::new(U1024::from_be_slice(random.as_ref()));
        if *private <= U1024::ONE {
            return Err(vault_error("invalid Secret Service DH private exponent"));
        }
        let public = FixedMontyForm::new(&U1024::from_u8(2), &DH_PARAMS)
            .pow(&private)
            .retrieve()
            .to_be_bytes();
        let (output, session): (OwnedValue, OwnedObjectPath) = root
            .call(
                "OpenSession",
                &(
                    "dh-ietf1024-sha256-aes128-cbc-pkcs7",
                    Value::from(public.as_slice()),
                ),
            )
            .map_err(native_error)?;
        if session.as_str() == "/" {
            return Err(vault_error("Secret Service did not establish a session"));
        }
        let public: Vec<u8> = output.try_into().map_err(native_error)?;
        let public = public.strip_prefix(&[0]).unwrap_or(&public);
        if public.is_empty() || public.len() > 128 {
            return Err(vault_error("invalid Secret Service DH public key length"));
        }
        let mut padded = [0u8; 128];
        padded[128 - public.len()..].copy_from_slice(public);
        let public = U1024::from_be_slice(&padded);
        if public <= U1024::ONE || public >= DH_PRIME.as_ref().wrapping_sub(&U1024::ONE) {
            return Err(vault_error("invalid Secret Service DH public key"));
        }
        let shared = Zeroizing::new(FixedMontyForm::new(&public, &DH_PARAMS).pow(&private));
        let shared_integer = Zeroizing::new(shared.retrieve());
        let shared_bytes = Zeroizing::new(shared_integer.to_be_bytes());
        let mut key = Zeroizing::new([0u8; 16]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, shared_bytes.as_ref())
            .expand(&[], key.as_mut())
            .map_err(|_| vault_error("Secret Service session key derivation failed"))?;
        Ok((session, key))
    }

    pub(super) struct Backend {
        state: Mutex<State>,
        marker: Marker,
        target: String,
    }

    struct Marker {
        path: OwnedObjectPath,
        id: String,
    }

    struct State {
        connection: Connection,
        owner: String,
        collection: OwnedObjectPath,
        session: OwnedObjectPath,
        key: Zeroizing<[u8; 16]>,
    }

    impl State {
        fn proxy<'a>(&'a self, path: &'a str, interface: &'a str) -> AccountHomeResult<Proxy<'a>> {
            Proxy::new(&self.connection, self.owner.as_str(), path, interface).map_err(native_error)
        }

        fn collection(&self) -> AccountHomeResult<Proxy<'_>> {
            let proxy = self.proxy(self.collection.as_str(), COLLECTION)?;
            if proxy.get_property::<bool>("Locked").map_err(native_error)? {
                return Err(AccountHomeError::SecretStoreUnavailable(
                    "pinned Secret Service collection is locked; unlock it in your system keyring and retry"
                        .into(),
                ));
            }
            Ok(proxy)
        }

        fn managed(&self, marker: &Marker) -> AccountHomeResult<Proxy<'_>> {
            let collection = self.collection()?;
            if !self
                .read_marker(&collection)?
                .is_some_and(|current| current.path == marker.path && current.id == marker.id)
            {
                return Err(marker_error("changed"));
            }
            Ok(collection)
        }

        fn marker_id(&self, path: &OwnedObjectPath) -> AccountHomeResult<String> {
            let mut attrs: HashMap<String, String> = self
                .proxy(path.as_str(), ITEM)?
                .get_property("Attributes")
                .map_err(|_| marker_error("unreadable"))?;
            // Providers can add attributes (such as a schema) when reloading items.
            if attrs.get("service").map(String::as_str) != Some(MARKER_SERVICE) {
                return Err(marker_error("invalid"));
            }
            attrs
                .remove(MARKER_ID)
                .filter(|id| {
                    id.len() == 64
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| marker_error("invalid"))
        }

        fn read_marker(&self, collection: &Proxy<'_>) -> AccountHomeResult<Option<Marker>> {
            let mut paths = find_items(collection, MARKER_SERVICE, None)?;
            if paths.len() > 1 {
                return Err(marker_error("duplicated"));
            }
            paths
                .pop()
                .map(|path| {
                    let id = self.marker_id(&path)?;
                    Ok(Marker { path, id })
                })
                .transpose()
        }

        fn init_marker(&self, bus: &Proxy<'_>) -> AccountHomeResult<Marker> {
            let collection = self.collection()?;
            if let Some(marker) = self.read_marker(&collection)? {
                return Ok(marker);
            }

            let mut hash = Sha256::new();
            hash.update(self.owner.as_bytes());
            hash.update([0]);
            hash.update(self.collection.as_str().as_bytes());
            let lease = format!(
                "org.marmot_protocol.Mdk.CollectionInit.h{}",
                hex::encode(hash.finalize())
            );
            let acquired: RequestNameReply = bus
                .call("RequestName", &(lease.as_str(), RequestNameFlags::DoNotQueue as u32))
                .map_err(|error| AccountHomeError::SecretStoreUnavailable(format!(
                    "cannot initialize MDK Secret Service collection identity: allow temporary org.marmot_protocol.Mdk.CollectionInit names on the session bus and reopen the account home ({error})"
                )))?;
            if acquired != RequestNameReply::PrimaryOwner {
                return Err(AccountHomeError::SecretStoreUnavailable(
                    "Secret Service collection identity initialization is busy; reopen the account home and retry".into(),
                ));
            }
            // Failed construction drops this connection and its name ownership.
            let marker = match self.read_marker(&collection)? {
                Some(marker) => marker,
                None => self.create_marker(&collection)?,
            };
            let released: ReleaseNameReply = bus
                .call("ReleaseName", &(lease.as_str(),))
                .map_err(native_error)?;
            if released != ReleaseNameReply::Released {
                return Err(vault_error(
                    "Secret Service collection initialization lease was lost",
                ));
            }
            Ok(marker)
        }

        fn create_marker(&self, collection: &Proxy<'_>) -> AccountHomeResult<Marker> {
            let items: Vec<OwnedObjectPath> =
                collection.get_property("Items").map_err(native_error)?;
            for path in items {
                let attrs: HashMap<String, String> = self
                    .proxy(path.as_str(), ITEM)?
                    .get_property("Attributes")
                    .map_err(native_error)?;
                if attrs
                    .get("service")
                    .is_some_and(|service| service.starts_with("mdk-owned-"))
                {
                    return Err(marker_error(
                        "missing from a collection with managed records",
                    ));
                }
            }

            let mut random = [0u8; 32];
            getrandom::fill(&mut random).map_err(native_error)?;
            let id = hex::encode(random);
            self.write_items(collection, MARKER_SERVICE, &id, "", &[])?;
            match self.read_marker(collection)? {
                Some(marker) if marker.id == id => Ok(marker),
                _ => Err(marker_error("not published as requested")),
            }
        }

        fn read_item(&self, path: &OwnedObjectPath) -> AccountHomeResult<Zeroizing<String>> {
            let proxy = self.proxy(path.as_str(), ITEM)?;
            if proxy.get_property::<bool>("Locked").map_err(native_error)? {
                return Err(AccountHomeError::SecretStoreUnavailable(
                    "Secret Service credential is locked. Unlock the credential or its collection in your system keyring, then retry"
                        .into(),
                ));
            }
            let (session, parameters, bytes, content_type): Secret = proxy
                .call("GetSecret", &(&self.session,))
                .map_err(native_error)?;
            let mut bytes = Zeroizing::new(bytes);
            if session != self.session
                || parameters.len() != 16
                || content_type != "text/plain; charset=utf-8"
                    && content_type != "text/plain"
                    && content_type != "application/octet-stream"
            {
                return Err(vault_error("invalid Secret Service secret response"));
            }
            let length =
                cbc::Decryptor::<aes::Aes128>::new_from_slices(self.key.as_ref(), &parameters)
                    .map_err(|_| vault_error("invalid Secret Service encryption parameters"))?
                    .decrypt_padded_mut::<Pkcs7>(&mut bytes)
                    .map_err(|_| vault_error("invalid encrypted Secret Service payload"))?
                    .len();
            bytes.truncate(length);
            decode_secret(std::mem::take(&mut *bytes))
        }
    }

    fn marker_error(problem: &str) -> AccountHomeError {
        AccountHomeError::SecretStoreUnavailable(format!(
            "MDK Secret Service collection identity is {problem}; restore the original collection and its identity item, then reopen the account home"
        ))
    }

    fn find_items(
        collection: &Proxy<'_>,
        service: &str,
        name: Option<&str>,
    ) -> AccountHomeResult<Vec<OwnedObjectPath>> {
        let mut attrs = HashMap::from([("service", service)]);
        if let Some(name) = name {
            attrs.insert("username", name);
        }
        collection
            .call("SearchItems", &(attrs,))
            .map_err(native_error)
    }

    impl Backend {
        pub(super) fn new(
            store: Arc<keyring_core::api::CredentialStore>,
            _ios_options: &IosOptions,
        ) -> AccountHomeResult<Self> {
            if !store
                .as_any()
                .is::<zbus_secret_service_keyring_store::Store>()
            {
                return Err(vault_error("unsupported captured Secret Service provider"));
            }
            let connection = Connection::session().map_err(native_error)?;
            let bus = Proxy::new(
                &connection,
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
            )
            .map_err(native_error)?;
            // A running provider need not have a D-Bus activation descriptor.
            // Resolve it once; every vault call uses that captured unique owner.
            let owner: String = match bus
                .call("GetNameOwner", &(SERVICE,))
                .map_err(zbus::fdo::Error::from)
            {
                Ok(owner) => owner,
                Err(zbus::fdo::Error::NameHasNoOwner(_)) => {
                    let _: u32 = bus
                        .call("StartServiceByName", &(SERVICE, 0u32))
                        .map_err(native_error)?;
                    bus.call("GetNameOwner", &(SERVICE,))
                        .map_err(native_error)?
                }
                Err(error) => return Err(native_error(error)),
            };
            let uid: u32 = bus
                .call("GetConnectionUnixUser", &(owner.as_str(),))
                .map_err(native_error)?;
            let peer = Proxy::new(
                &connection,
                owner.as_str(),
                ROOT,
                "org.freedesktop.DBus.Peer",
            )
            .map_err(native_error)?;
            let machine: String = peer.call("GetMachineId", &()).map_err(native_error)?;
            let root = Proxy::new(
                &connection,
                owner.as_str(),
                ROOT,
                "org.freedesktop.Secret.Service",
            )
            .map_err(native_error)?;
            let collection: OwnedObjectPath = root
                .call("ReadAlias", &("default",))
                .map_err(native_error)?;
            if collection.as_str() == "/" {
                return Err(AccountHomeError::SecretStoreUnavailable(
                    "Secret Service has no default collection. Restore the original MDK collection as default, or set the intended collection as default before first use. Then reopen the account home"
                        .into(),
                ));
            }
            let (session, key) = open_session(&root)?;
            drop(root);
            drop(peer);
            let state = State {
                connection: connection.clone(),
                owner,
                collection,
                session,
                key,
            };
            let marker = state.init_marker(&bus)?;
            drop(bus);
            let target = format!("secret-service:{machine}:{uid}:{SERVICE}:{}", marker.id);
            Ok(Self {
                state: Mutex::new(state),
                marker,
                target,
            })
        }

        pub(super) fn target(&self) -> &str {
            &self.target
        }

        pub(super) fn read(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            let state = self
                .state
                .lock()
                .map_err(|_| vault_error("native vault lock poisoned"))?;
            let mut result = None;
            for path in find_items(&state.managed(&self.marker)?, service, Some(name))? {
                merge_secret(&mut result, Some(state.read_item(&path)?))?;
            }
            Ok(result)
        }

        pub(super) fn legacy_secret(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            let state = self
                .state
                .lock()
                .map_err(|_| vault_error("native vault lock poisoned"))?;
            let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = state
                .proxy(ROOT, "org.freedesktop.Secret.Service")?
                .call(
                    "SearchItems",
                    &(HashMap::from([("service", service), ("username", name)]),),
                )
                .map_err(native_error)?;
            if !locked.is_empty() {
                return Err(AccountHomeError::SecretStoreUnavailable(
                    "legacy Secret Service credential is locked. Unlock the credential or its collection in your system keyring, then retry"
                        .into(),
                ));
            }
            let mut result = None;
            for path in unlocked {
                merge_secret(&mut result, Some(state.read_item(&path)?))?;
            }
            Ok(result)
        }

        pub(super) fn write(
            &self,
            service: &str,
            name: &str,
            value: &str,
        ) -> AccountHomeResult<()> {
            let state = self
                .state
                .lock()
                .map_err(|_| vault_error("native vault lock poisoned"))?;
            let collection = state.managed(&self.marker)?;
            let paths = find_items(&collection, service, Some(name))?;
            state.write_items(&collection, service, name, value, &paths)
        }

        pub(super) fn remove(&self, service: &str, name: &str) -> AccountHomeResult<()> {
            let state = self
                .state
                .lock()
                .map_err(|_| vault_error("native vault lock poisoned"))?;
            for path in find_items(&state.managed(&self.marker)?, service, Some(name))? {
                let prompt: OwnedObjectPath = state
                    .proxy(path.as_str(), ITEM)?
                    .call("Delete", &())
                    .map_err(native_error)?;
                if prompt.as_str() != "/" {
                    return Err(AccountHomeError::SecretStoreUnavailable(
                        "native vault delete requires an interactive prompt".into(),
                    ));
                }
            }
            Ok(())
        }

        pub(super) fn names(&self, service: &str) -> AccountHomeResult<Vec<String>> {
            let state = self
                .state
                .lock()
                .map_err(|_| vault_error("native vault lock poisoned"))?;
            let mut names = Vec::new();
            for path in find_items(&state.managed(&self.marker)?, service, None)? {
                let mut attrs: HashMap<String, String> = state
                    .proxy(path.as_str(), ITEM)?
                    .get_property("Attributes")
                    .map_err(native_error)?;
                if attrs.get("service").map(String::as_str) != Some(service) {
                    return Err(vault_error("Secret Service returned a mismatched service"));
                }
                names.push(
                    attrs
                        .remove("username")
                        .ok_or_else(|| vault_error("native receipt has no username attribute"))?,
                );
            }
            Ok(names)
        }
    }

    impl State {
        fn write_items(
            &self,
            collection: &Proxy<'_>,
            service: &str,
            name: &str,
            value: &str,
            paths: &[OwnedObjectPath],
        ) -> AccountHomeResult<()> {
            let mut iv = [0u8; 16];
            getrandom::fill(&mut iv).map_err(native_error)?;
            let mut encrypted = Zeroizing::new(vec![0u8; value.len() + 16]);
            encrypted[..value.len()].copy_from_slice(value.as_bytes());
            let encrypted = cbc::Encryptor::<aes::Aes128>::new_from_slices(self.key.as_ref(), &iv)
                .map_err(|_| vault_error("invalid Secret Service encryption parameters"))?
                .encrypt_padded_mut::<Pkcs7>(&mut encrypted, value.len())
                .map_err(|_| vault_error("Secret Service encryption failed"))?;
            let secret = (
                &self.session,
                iv.as_slice(),
                encrypted,
                "text/plain; charset=utf-8",
            );
            if paths.is_empty() {
                let (label, field) = if service == MARKER_SERVICE {
                    ("MDK collection identity", MARKER_ID)
                } else {
                    ("MDK owned vault record", "username")
                };
                let attributes = HashMap::from([("service", service), (field, name)]);
                let properties = HashMap::from([
                    ("org.freedesktop.Secret.Item.Label", Value::from(label)),
                    (
                        "org.freedesktop.Secret.Item.Attributes",
                        Value::from(attributes),
                    ),
                ]);
                let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
                    .call("CreateItem", &(properties, secret, false))
                    .map_err(native_error)?;
                if prompt.as_str() != "/" {
                    return Err(AccountHomeError::SecretStoreUnavailable(
                        "native vault write requires an interactive prompt".into(),
                    ));
                }
                if item.as_str() == "/" {
                    return Err(vault_error(
                        "Secret Service did not create the requested item",
                    ));
                }
            } else {
                for path in paths {
                    let _: () = self
                        .proxy(path.as_str(), ITEM)?
                        .call("SetSecret", &(&secret,))
                        .map_err(native_error)?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(all(not(test), target_os = "macos"))]
mod platform {
    use super::*;
    use core_foundation::base::TCFType;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
    use security_framework::os::macos::passwords::find_generic_password;
    use security_framework_sys::base::SecKeychainRef;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainGetPath(
            keychain: SecKeychainRef,
            length: *mut u32,
            path: *mut std::ffi::c_char,
        ) -> i32;
    }

    pub(super) struct Backend {
        keychain: SecKeychain,
        target: String,
    }

    impl Backend {
        pub(super) fn new(
            store: Arc<keyring_core::api::CredentialStore>,
            _ios_options: &IosOptions,
        ) -> AccountHomeResult<Self> {
            use apple_native_keyring_store::keychain::{Cred, MacKeychainDomain, Store};
            if !store.as_any().is::<Store>() {
                return Err(vault_error(
                    "unsupported captured macOS credential provider",
                ));
            }
            let entry = store
                .build("mdk-target-probe", "mdk-target-probe", None)
                .map_err(map_keyring_error)?;
            let cred = entry
                .as_any()
                .downcast_ref::<Cred>()
                .ok_or_else(|| vault_error("unexpected macOS credential type"))?;
            let domain = match cred.domain {
                MacKeychainDomain::User => SecPreferencesDomain::User,
                MacKeychainDomain::System => SecPreferencesDomain::System,
                MacKeychainDomain::Common => SecPreferencesDomain::Common,
                MacKeychainDomain::Dynamic => SecPreferencesDomain::Dynamic,
            };
            let keychain = SecKeychain::default_for_domain(domain).map_err(native_error)?;
            let mut path = [0u8; 4096];
            let mut length = path.len() as u32;
            let status = unsafe {
                SecKeychainGetPath(
                    keychain.as_concrete_TypeRef(),
                    &mut length,
                    path.as_mut_ptr().cast(),
                )
            };
            if status != 0 {
                return Err(native_error(security_framework::base::Error::from_code(
                    status,
                )));
            }
            let path = path
                .get(..length as usize)
                .ok_or_else(|| vault_error("macOS returned an invalid keychain path length"))?;
            let path = path.strip_suffix(&[0]).unwrap_or(path);
            if path.is_empty() || path.contains(&0) {
                return Err(vault_error("macOS returned an invalid keychain path"));
            }
            // Keychain commits can replace the backing inode at the same path.
            let target = format!(
                "macos-keychain:{}:{}:{}",
                unsafe { libc::geteuid() },
                domain as i32,
                hex::encode(path)
            );
            Ok(Self { keychain, target })
        }

        pub(super) fn target(&self) -> &str {
            &self.target
        }

        pub(super) fn legacy_secret(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            self.read(service, name)
        }

        pub(super) fn read(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            match find_generic_password(Some(std::slice::from_ref(&self.keychain)), service, name) {
                Ok((password, _)) => Ok(Some(decode_secret(password.to_owned())?)),
                Err(error) if error.code() == -25300 => Ok(None),
                Err(error) => Err(native_error(error)),
            }
        }

        pub(super) fn write(
            &self,
            service: &str,
            name: &str,
            value: &str,
        ) -> AccountHomeResult<()> {
            match find_generic_password(Some(std::slice::from_ref(&self.keychain)), service, name) {
                Ok((_password, mut item)) => {
                    item.set_password(value.as_bytes()).map_err(native_error)
                }
                Err(error) if error.code() == -25300 => self
                    .keychain
                    .add_generic_password(service, name, value.as_bytes())
                    .map_err(native_error),
                Err(error) => Err(native_error(error)),
            }
        }

        pub(super) fn remove(&self, service: &str, name: &str) -> AccountHomeResult<()> {
            let (_password, item) = match find_generic_password(
                Some(std::slice::from_ref(&self.keychain)),
                service,
                name,
            ) {
                Ok(result) => result,
                Err(error) if error.code() == -25300 => return Ok(()),
                Err(error) => return Err(native_error(error)),
            };
            // The high-level delete method drops this status, including access failures.
            let status = unsafe {
                security_framework_sys::keychain_item::SecKeychainItemDelete(
                    item.as_concrete_TypeRef(),
                )
            };
            if status != 0 && status != -25300 {
                return Err(native_error(security_framework::base::Error::from_code(
                    status,
                )));
            }
            Ok(())
        }

        pub(super) fn names(&self, service: &str) -> AccountHomeResult<Vec<String>> {
            let keychains = [self.keychain.clone()];
            let mut options = ItemSearchOptions::new();
            options
                .keychains(&keychains)
                .class(ItemClass::generic_password())
                .service(service)
                .limit(Limit::All)
                .load_attributes(true)
                .skip_authenticated_items(false);
            let items = match options.search() {
                Ok(items) => items,
                Err(error) if error.code() == -25300 => return Ok(Vec::new()),
                Err(error) => return Err(native_error(error)),
            };
            items
                .into_iter()
                .map(|item| {
                    let attrs = item
                        .simplify_dict()
                        .ok_or_else(|| vault_error("macOS credential has no attributes"))?;
                    if attrs.get("svce").map(String::as_str) != Some(service) {
                        return Err(vault_error("macOS returned a mismatched service"));
                    }
                    attrs
                        .get("acct")
                        .cloned()
                        .ok_or_else(|| vault_error("macOS credential has no account"))
                })
                .collect()
        }
    }
}

#[cfg(all(not(test), target_os = "ios"))]
mod platform {
    use super::*;
    use apple_native_keyring_store::protected::{AccessPolicy, Cred, Store};
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
    use core_foundation::string::CFString;
    use keyring_core::api::CredentialApi;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::base::Error;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService,
        kSecAttrSynchronizable, kSecClass, kSecClassGenericPassword, kSecReturnAttributes,
        kSecUseDataProtectionKeychain, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemDelete};

    pub(super) struct Backend {
        group: String,
        legacy_group: Option<String>,
        target: String,
        legacy_target: Option<String>,
    }

    fn explicit_group(group: &str) -> bool {
        !group.is_empty() && !group.contains('*') && !group.contains('\0')
    }

    fn probe_group(requested: Option<&str>) -> AccountHomeResult<String> {
        if requested.is_some_and(|group| !explicit_group(group)) {
            return Err(vault_error("keychain access group must be explicit"));
        }

        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(native_error)?;
        let service = CFString::new("mdk-ios-keychain-group-probe-v1");
        let account = CFString::new(&hex::encode(nonce));
        let protection = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(native_error)?;
        let mut query: CFMutableDictionary = unsafe {
            CFMutableDictionary::from_CFType_pairs(&[
                (kSecClass.cast(), kSecClassGenericPassword.cast()),
                (kSecAttrService.cast(), service.as_CFTypeRef()),
                (kSecAttrAccount.cast(), account.as_CFTypeRef()),
                (
                    kSecAttrSynchronizable.cast(),
                    CFBoolean::false_value().as_CFTypeRef(),
                ),
                (
                    kSecUseDataProtectionKeychain.cast(),
                    CFBoolean::true_value().as_CFTypeRef(),
                ),
            ])
        };
        if let Some(group) = requested {
            query.set(
                unsafe { kSecAttrAccessGroup }.cast(),
                CFString::new(group).as_CFTypeRef(),
            );
        }

        let mut attributes = std::ptr::null();
        let status = unsafe {
            query.set(kSecAttrAccessControl.cast(), protection.as_CFTypeRef());
            query.set(
                kSecValueData.cast(),
                CFData::from_buffer(&[0]).as_CFTypeRef(),
            );
            query.set(
                kSecReturnAttributes.cast(),
                CFBoolean::true_value().as_CFTypeRef(),
            );
            SecItemAdd(query.as_concrete_TypeRef(), &mut attributes)
        };
        let attributes =
            (!attributes.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(attributes) });
        if status != 0 {
            return Err(native_error(format_args!(
                "adding iOS keychain group probe: {}",
                Error::from_code(status)
            )));
        }

        // Delete by the probe's unique key even if the returned attributes cannot be decoded.
        let status = unsafe {
            query.remove(kSecAttrAccessControl.cast());
            query.remove(kSecValueData.cast());
            query.remove(kSecReturnAttributes.cast());
            SecItemDelete(query.as_concrete_TypeRef())
        };
        if status != 0 {
            return Err(native_error(format_args!(
                "deleting iOS keychain group probe: {}",
                Error::from_code(status)
            )));
        }
        let group = attributes
            .and_then(CFType::downcast_into::<CFDictionary>)
            .and_then(|attrs| {
                let key: CFTypeRef = unsafe { kSecAttrAccessGroup }.cast();
                let value = attrs.find(key)?;
                unsafe { CFType::wrap_under_get_rule(*value) }.downcast_into::<CFString>()
            })
            .map(|group| group.to_string())
            .filter(|group| explicit_group(group))
            .ok_or_else(|| vault_error("iOS keychain probe did not return an access group"))?;
        if requested.is_some_and(|requested| requested != group) {
            return Err(vault_error(
                "iOS keychain probe returned a different access group",
            ));
        }
        Ok(group)
    }

    impl Backend {
        pub(super) fn new(
            store: Arc<keyring_core::api::CredentialStore>,
            ios_options: &IosOptions,
        ) -> AccountHomeResult<Self> {
            if !store.as_any().is::<Store>() {
                return Err(vault_error("unsupported captured iOS credential provider"));
            }
            let entry = store
                .build("mdk-target-probe", "mdk-target-probe", None)
                .map_err(map_keyring_error)?;
            let cred = entry
                .as_any()
                .downcast_ref::<Cred>()
                .ok_or_else(|| vault_error("unexpected iOS credential type"))?;
            if cred.cloud_synchronize {
                return Err(vault_error(
                    "owned receipts require the device-local protected keychain",
                ));
            }
            let legacy_group = cred.access_group.as_deref();
            let configured_group = ios_options.keychain_access_group.as_deref();
            if let (Some(captured), Some(configured)) = (legacy_group, configured_group)
                && captured != configured
            {
                return Err(vault_error(
                    "configured iOS access group conflicts with captured provider",
                ));
            }
            let group = probe_group(configured_group.or(legacy_group))?;
            let uid = unsafe { libc::geteuid() };
            let target = format!(
                "ios-protected-local:{}",
                serde_json::to_string(&(uid, &group))?
            );
            let legacy_target = legacy_group
                .map(|group| {
                    serde_json::to_string(&(uid, group))
                        .map(|scope| format!("ios-protected-legacy:{scope}"))
                })
                .transpose()?;
            Ok(Self {
                group,
                legacy_group: cred.access_group.clone(),
                target,
                legacy_target,
            })
        }

        pub(super) fn target(&self) -> &str {
            &self.target
        }

        pub(super) fn legacy_target(&self) -> Option<&str> {
            self.legacy_target.as_deref()
        }

        fn entries(
            &self,
            service: &str,
            name: Option<&str>,
            group: Option<&str>,
        ) -> AccountHomeResult<Vec<Cred>> {
            let mut options = ItemSearchOptions::new();
            options
                .class(ItemClass::generic_password())
                .service(service)
                .cloud_sync(Some(false))
                .limit(Limit::All)
                .load_attributes(true)
                .skip_authenticated_items(false);
            if let Some(name) = name {
                options.account(name);
            }
            if let Some(group) = group {
                options.access_group(group);
            }
            let items = match options.search() {
                Ok(items) => items,
                Err(error) if error.code() == -25300 => return Ok(Vec::new()),
                Err(error) => return Err(native_error(error)),
            };
            items
                .into_iter()
                .map(|item| {
                    let attrs = item
                        .simplify_dict()
                        .ok_or_else(|| vault_error("iOS credential has no attributes"))?;
                    let actual_service = attrs
                        .get("svce")
                        .ok_or_else(|| vault_error("iOS credential has no service"))?;
                    let actual_name = attrs
                        .get("acct")
                        .ok_or_else(|| vault_error("iOS credential has no account"))?;
                    let actual_group = attrs
                        .get("agrp")
                        .ok_or_else(|| vault_error("iOS credential has no access group"))?;
                    if actual_service != service
                        || name.is_some_and(|name| name != actual_name)
                        || group.is_some_and(|group| group != actual_group)
                    {
                        return Err(vault_error("iOS returned a mismatched credential"));
                    }
                    Ok(Cred {
                        service: actual_service.clone(),
                        account: actual_name.clone(),
                        access_group: Some(actual_group.clone()),
                        cloud_synchronize: false,
                        access_policy: AccessPolicy::AfterFirstUnlockThisDeviceOnly,
                    })
                })
                .collect()
        }

        pub(super) fn read(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            let mut result = None;
            for entry in self.entries(service, Some(name), Some(&self.group))? {
                merge_secret(
                    &mut result,
                    Some(decode_secret(
                        entry.get_secret().map_err(map_keyring_error)?,
                    )?),
                )?;
            }
            Ok(result)
        }

        pub(super) fn legacy_secret(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            let mut result = None;
            for entry in self.entries(service, Some(name), self.legacy_group.as_deref())? {
                merge_secret(
                    &mut result,
                    Some(decode_secret(
                        entry.get_secret().map_err(map_keyring_error)?,
                    )?),
                )?;
            }
            Ok(result)
        }

        pub(super) fn write(
            &self,
            service: &str,
            name: &str,
            value: &str,
        ) -> AccountHomeResult<()> {
            Cred::build(
                service,
                name,
                AccessPolicy::AfterFirstUnlockThisDeviceOnly,
                Some(self.group.clone()),
                false,
            )
            .map_err(map_keyring_error)?
            .set_password(value)
            .map_err(map_keyring_error)
        }

        pub(super) fn remove(&self, service: &str, name: &str) -> AccountHomeResult<()> {
            for entry in self.entries(service, Some(name), Some(&self.group))? {
                entry.delete_credential().map_err(map_keyring_error)?;
            }
            Ok(())
        }

        pub(super) fn names(&self, service: &str) -> AccountHomeResult<Vec<String>> {
            Ok(self
                .entries(service, None, Some(&self.group))?
                .into_iter()
                .map(|entry| entry.account)
                .collect())
        }
    }
}

#[cfg(all(not(test), target_os = "windows"))]
mod platform {
    use super::*;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_NO_TOKEN, ERROR_NOT_FOUND, ERROR_SUCCESS, GetLastError,
    };
    use windows_sys::Win32::Security::Credentials::{
        CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredEnumerateW,
        CredFree, CredReadW, CredWriteW,
    };
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
        TokenStatistics, TokenUser,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };
    use windows_sys::core::w;
    use zeroize::Zeroize;

    const MACHINE_GUID_LEN: usize = 36;

    pub(super) struct Backend {
        sid: Vec<u8>,
        logon: (u32, i32),
        delimiters: [String; 3],
        service_no_divider: bool,
        target: String,
        legacy_target: String,
    }

    fn win_error() -> AccountHomeError {
        native_error(std::io::Error::last_os_error())
    }

    fn machine_guid() -> AccountHomeResult<[u8; MACHINE_GUID_LEN]> {
        let mut value = [0u16; MACHINE_GUID_LEN + 1];
        let mut bytes = std::mem::size_of_val(&value) as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                w!("SOFTWARE\\Microsoft\\Cryptography"),
                w!("MachineGuid"),
                RRF_RT_REG_SZ | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY,
                std::ptr::null_mut(),
                value.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(native_error(format_args!(
                "reading Windows MachineGuid: {}",
                std::io::Error::from_raw_os_error(status as i32)
            )));
        }
        if bytes as usize != std::mem::size_of_val(&value) || value[MACHINE_GUID_LEN] != 0 {
            return Err(vault_error(
                "Windows returned an invalid MachineGuid length",
            ));
        }
        let mut guid = [0; MACHINE_GUID_LEN];
        for (index, (byte, unit)) in guid.iter_mut().zip(value).enumerate() {
            let character =
                u8::try_from(unit).map_err(|_| vault_error("invalid Windows MachineGuid"))?;
            let valid = match index {
                8 | 13 | 18 | 23 => character == b'-',
                _ => character.is_ascii_hexdigit(),
            };
            if !valid {
                return Err(vault_error("invalid Windows MachineGuid"));
            }
            *byte = character.to_ascii_lowercase();
        }
        Ok(guid)
    }

    unsafe fn erase_native(credential: *mut CREDENTIALW) {
        if credential.is_null() {
            return;
        }
        let credential = unsafe { &mut *credential };
        if !credential.CredentialBlob.is_null() {
            unsafe {
                std::slice::from_raw_parts_mut(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                )
            }
            .zeroize();
        }
    }

    fn current_user<T>(read_sid: impl FnOnce(&[u8], (u32, i32)) -> T) -> AccountHomeResult<T> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            if unsafe { GetLastError() } != ERROR_NO_TOKEN {
                return Err(win_error());
            }
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(win_error());
            }
        }
        let result = (|| {
            let mut buffer = [0usize; 128];
            let mut length = 0;
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    std::mem::size_of_val(&buffer) as u32,
                    &mut length,
                )
            } == 0
            {
                return Err(win_error());
            }
            let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
            if unsafe { IsValidSid(user.User.Sid) } == 0 {
                return Err(vault_error("Windows returned an invalid token SID"));
            }
            let length = unsafe { GetLengthSid(user.User.Sid) } as usize;
            let mut statistics = TOKEN_STATISTICS::default();
            let mut statistics_length = 0;
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenStatistics,
                    (&mut statistics as *mut TOKEN_STATISTICS).cast(),
                    std::mem::size_of_val(&statistics) as u32,
                    &mut statistics_length,
                )
            } == 0
            {
                return Err(win_error());
            }
            let logon = (
                statistics.AuthenticationId.LowPart,
                statistics.AuthenticationId.HighPart,
            );
            Ok(read_sid(
                unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length) },
                logon,
            ))
        })();
        if unsafe { CloseHandle(token) } == 0 {
            let error = win_error();
            return Err(match result {
                Ok(_) => error,
                Err(original) => {
                    native_error(format!("{original}; closing user token failed: {error}"))
                }
            });
        }
        result
    }

    fn wide(value: &str) -> AccountHomeResult<Vec<u16>> {
        if value.contains('\0')
            || value.encode_utf16().count() > CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize
        {
            return Err(vault_error("invalid Windows credential target"));
        }
        Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
    }

    unsafe fn from_wide(value: *const u16) -> AccountHomeResult<String> {
        if value.is_null() {
            return Err(vault_error("Windows credential has no target"));
        }
        for length in 0..=CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize {
            if unsafe { *value.add(length) } == 0 {
                return String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
                    .map_err(native_error);
            }
        }
        Err(vault_error("Windows credential target is not terminated"))
    }

    impl Backend {
        pub(super) fn new(
            store: Arc<keyring_core::api::CredentialStore>,
            _ios_options: &IosOptions,
        ) -> AccountHomeResult<Self> {
            let store = store
                .as_any()
                .downcast_ref::<windows_native_keyring_store::Store>()
                .ok_or_else(|| vault_error("unsupported captured Windows credential provider"))?;
            let (sid, logon) = current_user(|sid, logon| (sid.to_vec(), logon))?;
            let machine = machine_guid()?;
            let machine = std::str::from_utf8(&machine).map_err(native_error)?;
            let sid_hex = hex::encode(&sid);
            let target = format!("windows-credential-local:{machine}:{sid_hex}");
            let legacy_target = format!(
                "windows-credential-enterprise:{machine}:{sid_hex}:{:?}:{}",
                store.delimiters, store.service_no_divider
            );
            Ok(Self {
                sid,
                logon,
                delimiters: store.delimiters.clone(),
                service_no_divider: store.service_no_divider,
                target,
                legacy_target,
            })
        }

        pub(super) fn target(&self) -> &str {
            &self.target
        }

        pub(super) fn legacy_target(&self) -> &str {
            &self.legacy_target
        }

        fn check_user(&self) -> AccountHomeResult<()> {
            if !current_user(|sid, logon| sid == self.sid.as_slice() && logon == self.logon)? {
                return Err(vault_error(
                    "Windows credential user changed after target capture",
                ));
            }
            Ok(())
        }

        fn read_target(&self, target: &str) -> AccountHomeResult<Option<Zeroizing<String>>> {
            self.check_user()?;
            let target = wide(target)?;
            let mut credential = std::ptr::null_mut();
            if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
                return if unsafe { GetLastError() } == ERROR_NOT_FOUND {
                    Ok(None)
                } else {
                    Err(win_error())
                };
            }
            let result = (|| {
                let credential = unsafe { &*credential };
                let length = credential.CredentialBlobSize as usize;
                if length % 2 != 0
                    || length > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize
                    || length != 0 && credential.CredentialBlob.is_null()
                {
                    return Err(vault_error("invalid Windows credential UTF-16 blob"));
                }
                let blob = if length == 0 {
                    &[][..]
                } else {
                    unsafe { std::slice::from_raw_parts(credential.CredentialBlob, length) }
                };
                let units = Zeroizing::new(
                    blob.chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect::<Vec<_>>(),
                );
                Ok(Some(Zeroizing::new(
                    String::from_utf16(&units).map_err(native_error)?,
                )))
            })();
            unsafe {
                erase_native(credential);
                CredFree(credential.cast());
            }
            result
        }

        pub(super) fn legacy_secret(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            if self.service_no_divider && service.contains(&self.delimiters[1]) {
                return Err(vault_error(
                    "legacy Windows service contains the captured delimiter",
                ));
            }
            self.read_target(&format!(
                "{}{name}{}{service}{}",
                self.delimiters[0], self.delimiters[1], self.delimiters[2]
            ))
        }

        pub(super) fn read(
            &self,
            service: &str,
            name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            self.read_target(&format!("mdk-native-v1/{service}/{name}"))
        }

        pub(super) fn write(
            &self,
            service: &str,
            name: &str,
            value: &str,
        ) -> AccountHomeResult<()> {
            self.check_user()?;
            if value.encode_utf16().count() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize / 2 {
                return Err(vault_error(
                    "native receipt exceeds Windows UTF-16 credential limit",
                ));
            }
            let mut target = wide(&format!("mdk-native-v1/{service}/{name}"))?;
            let mut blob = Zeroizing::new(
                value
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            );
            let credential = CREDENTIALW {
                Type: CRED_TYPE_GENERIC,
                TargetName: target.as_mut_ptr(),
                CredentialBlobSize: blob.len() as u32,
                CredentialBlob: blob.as_mut_ptr(),
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                ..Default::default()
            };
            if unsafe { CredWriteW(&credential, 0) } == 0 {
                return Err(win_error());
            }
            Ok(())
        }

        pub(super) fn remove(&self, service: &str, name: &str) -> AccountHomeResult<()> {
            self.check_user()?;
            let target = wide(&format!("mdk-native-v1/{service}/{name}"))?;
            if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0
                && unsafe { GetLastError() } != ERROR_NOT_FOUND
            {
                return Err(win_error());
            }
            Ok(())
        }

        pub(super) fn names(&self, service: &str) -> AccountHomeResult<Vec<String>> {
            self.check_user()?;
            let prefix = format!("mdk-native-v1/{service}/");
            let filter = wide(&format!("{prefix}*"))?;
            let mut count = 0;
            let mut credentials = std::ptr::null_mut();
            if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) } == 0 {
                return if unsafe { GetLastError() } == ERROR_NOT_FOUND {
                    Ok(Vec::new())
                } else {
                    Err(win_error())
                };
            }
            let result = (|| {
                let mut names = Vec::new();
                for credential in unsafe { std::slice::from_raw_parts(credentials, count as usize) }
                {
                    let credential = unsafe { &**credential };
                    if credential.Type == CRED_TYPE_GENERIC {
                        let target = unsafe { from_wide(credential.TargetName) }?;
                        let name = target.strip_prefix(&prefix).ok_or_else(|| {
                            vault_error("Windows enumeration returned a mismatched target")
                        })?;
                        names.push(name.to_owned());
                    }
                }
                Ok(names)
            })();
            unsafe {
                for credential in std::slice::from_raw_parts(credentials, count as usize) {
                    erase_native(*credential);
                }
                CredFree(credentials.cast());
            }
            result
        }
    }
}

#[cfg(all(
    not(test),
    not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    ))
))]
mod platform {
    use super::*;

    pub(super) enum Backend {}

    impl Backend {
        pub(super) fn new(
            _store: Arc<keyring_core::api::CredentialStore>,
            _ios_options: &IosOptions,
        ) -> AccountHomeResult<Self> {
            Err(AccountHomeError::UnsupportedSecretBackend(
                "no native vault adapter for this target".into(),
            ))
        }

        pub(super) fn target(&self) -> &str {
            match *self {}
        }
        pub(super) fn read(
            &self,
            _service: &str,
            _name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            match *self {}
        }
        pub(super) fn legacy_secret(
            &self,
            _service: &str,
            _name: &str,
        ) -> AccountHomeResult<Option<Zeroizing<String>>> {
            match *self {}
        }
        pub(super) fn write(
            &self,
            _service: &str,
            _name: &str,
            _value: &str,
        ) -> AccountHomeResult<()> {
            match *self {}
        }
        pub(super) fn remove(&self, _service: &str, _name: &str) -> AccountHomeResult<()> {
            match *self {}
        }
        pub(super) fn names(&self, _service: &str) -> AccountHomeResult<Vec<String>> {
            match *self {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_search_is_exact() {
        let store = keyring_core::mock::Store::new().unwrap();
        let vault = mock_backend::Backend::new(store).unwrap();
        vault.write("wanted", "receipt", "ours").unwrap();
        vault.write("unwanted", "receipt", "theirs").unwrap();
        assert_eq!(vault.names("wanted").unwrap(), vec!["receipt"]);
        vault.remove("wanted", "receipt").unwrap();
        assert!(vault.names("wanted").unwrap().is_empty());
        assert_eq!(
            vault
                .read("unwanted", "receipt")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("theirs")
        );
    }

    #[test]
    fn mock_legacy_errors_survive() {
        use keyring_core::api::CredentialStoreApi;

        let store = keyring_core::mock::Store::new().unwrap();
        let entry = store.build("legacy", "account", None).unwrap();
        entry.set_password("secret").unwrap();
        entry
            .as_any()
            .downcast_ref::<keyring_core::mock::Cred>()
            .unwrap()
            .set_error(keyring_core::Error::Invalid(
                "source".into(),
                "locked".into(),
            ));
        let vault = mock_backend::Backend::new(store).unwrap();
        assert!(
            matches!(vault.legacy_secret("legacy", "account"), Err(AccountHomeError::SecretStore(message)) if message.contains("locked"))
        );
        assert_eq!(
            vault
                .legacy_secret("legacy", "account")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("secret")
        );
    }
}
