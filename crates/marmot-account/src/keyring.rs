//! Platform keyring entry construction, secret writes, store initialization,
//! and keyring-error mapping.

use std::sync::{Arc, Mutex};

use crate::error::{AccountHomeError, AccountHomeResult};

#[cfg(target_os = "ios")]
const IOS_BACKGROUND_KEYRING_SERVICE_SUFFIX: &str = ".after-first-unlock-v1";

pub(crate) fn initialize_keyring_store() -> AccountHomeResult<()> {
    static KEYRING_STORE_INIT: Mutex<()> = Mutex::new(());
    let _guard = KEYRING_STORE_INIT.lock().map_err(|_| {
        AccountHomeError::SecretStoreUnavailable("keyring init lock poisoned".into())
    })?;
    if keyring_core::get_default_store().is_some() {
        return Ok(());
    }
    initialize_platform_keyring_store()
}

pub(crate) fn build_keyring_entry(
    service: &str,
    account: &str,
) -> AccountHomeResult<keyring_core::Entry> {
    keyring_core::Entry::new(&keyring_service_name(service), account).map_err(map_keyring_error)
}

#[cfg(target_os = "ios")]
pub(crate) fn build_legacy_ios_keyring_entry(
    service: &str,
    account: &str,
) -> AccountHomeResult<keyring_core::Entry> {
    keyring_core::Entry::new(service, account).map_err(map_keyring_error)
}

#[cfg(target_os = "ios")]
fn keyring_service_name(service: &str) -> String {
    // Keychain access control is add-only. A versioned service lets migration
    // verify the replacement before deleting the foreground-only legacy item.
    format!("{service}{IOS_BACKGROUND_KEYRING_SERVICE_SUFFIX}")
}

#[cfg(not(target_os = "ios"))]
fn keyring_service_name(service: &str) -> String {
    service.to_owned()
}

pub(crate) fn write_keyring_secret(
    service: &str,
    account: &str,
    secret: &str,
) -> AccountHomeResult<()> {
    #[cfg(target_os = "ios")]
    {
        use apple_native_keyring_store::protected::{AccessPolicy, Cred};

        // apple-native-keyring-store 1.0.0's string modifier parser maps this
        // device-only policy to AfterFirstUnlock. The typed API preserves it.
        Cred::build(
            &keyring_service_name(service),
            account,
            AccessPolicy::AfterFirstUnlockThisDeviceOnly,
            None,
            false,
        )
        .map_err(map_keyring_error)?
        .set_password(secret)
        .map_err(map_keyring_error)
    }

    #[cfg(not(target_os = "ios"))]
    {
        build_keyring_entry(service, account)?
            .set_password(secret)
            .map_err(map_keyring_error)
    }
}

fn initialize_platform_keyring_store() -> AccountHomeResult<()> {
    #[cfg(test)]
    {
        set_default_keyring_store(keyring_core::mock::Store::new(), "mock")
    }

    #[cfg(all(not(test), target_os = "macos"))]
    {
        set_default_keyring_store(
            apple_native_keyring_store::keychain::Store::new(),
            "macOS Keychain",
        )
    }

    #[cfg(all(not(test), target_os = "ios"))]
    {
        set_default_keyring_store(
            apple_native_keyring_store::protected::Store::new(),
            "iOS protected-data",
        )
    }

    #[cfg(all(not(test), target_os = "windows"))]
    {
        set_default_keyring_store(windows_native_keyring_store::Store::new(), "Windows")
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
    {
        set_default_keyring_store(
            zbus_secret_service_keyring_store::Store::new(),
            "Secret Service",
        )
    }

    #[cfg(all(not(test), target_os = "android"))]
    {
        set_default_keyring_store(android_native_keyring_store::Store::new(), "Android")
    }

    #[cfg(all(
        not(test),
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "android",
        ))
    ))]
    {
        Err(AccountHomeError::SecretStoreUnavailable(
            "no platform credential store is available for this target OS".into(),
        ))
    }
}

fn set_default_keyring_store<S>(
    store: keyring_core::Result<Arc<S>>,
    store_name: &str,
) -> AccountHomeResult<()>
where
    S: keyring_core::api::CredentialStoreApi + Send + Sync + 'static,
{
    let store = store.map_err(|err| {
        AccountHomeError::SecretStoreUnavailable(format!(
            "failed to create {store_name} credential store: {err}"
        ))
    })?;
    keyring_core::set_default_store(store);
    Ok(())
}

pub(crate) fn map_keyring_error(err: keyring_core::Error) -> AccountHomeError {
    match err {
        keyring_core::Error::NoDefaultStore => {
            AccountHomeError::SecretStoreNotInitialized(err.to_string())
        }
        keyring_core::Error::NoStorageAccess(inner) => {
            AccountHomeError::SecretStoreUnavailable(format_storage_access_error(inner.as_ref()))
        }
        other => AccountHomeError::SecretStore(other.to_string()),
    }
}

fn format_storage_access_error(inner: &dyn std::error::Error) -> String {
    if cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        format!(
            "platform keyring is not available: {inner}. Make sure a Secret Service provider is running and unlocked."
        )
    } else {
        format!("platform keyring is not available: {inner}")
    }
}
