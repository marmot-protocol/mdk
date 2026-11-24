use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::AccountHomeResult;

/// iOS container and protected-keychain options supplied by the host application.
#[derive(Clone, Debug, Default)]
pub struct IosOptions {
    /// App groups whose OS-authorized containers may contain the account home.
    pub app_group_identifiers: Vec<String>,
    /// Access group for managed records. `None` uses the provider's group or the OS default.
    /// This option does not narrow the captured provider's legacy lookup.
    /// Set it explicitly for extensions or entitlement changes. If the OS default
    /// changes, select the previous group to reopen existing credentials.
    pub keychain_access_group: Option<String>,
}

pub(crate) fn root_hash(root: &Path, _ios_options: &IosOptions) -> AccountHomeResult<[u8; 32]> {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        with_mobile_root(root, _ios_options, |_, relative, identity| {
            Ok(mobile_hash(identity, relative))
        })
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let mut hash = Sha256::new();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            hash.update(root.as_os_str().as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            for unit in root.as_os_str().encode_wide() {
                hash.update(unit.to_le_bytes());
            }
        }
        Ok(hash.finalize().into())
    }
}

/// Pass the OS-selected container and its relative root separately from the
/// identity fields used by account homes.
#[cfg(any(target_os = "ios", target_os = "android"))]
pub(crate) fn with_mobile_root<T>(
    root: &Path,
    _ios_options: &IosOptions,
    selected: impl FnOnce(&Path, &Path, &[&[u8]]) -> AccountHomeResult<T>,
) -> AccountHomeResult<T> {
    #[cfg(target_os = "ios")]
    {
        ios::select_root(root, _ios_options, selected)
    }
    #[cfg(target_os = "android")]
    {
        android::capture()?.select_root(root, selected)
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn mobile_hash(fields: &[&[u8]], relative: &Path) -> [u8; 32] {
    use std::os::unix::ffi::OsStrExt;
    let mut hash = Sha256::new();
    hash.update(b"mdk-mobile-container-root-v1\0");
    for field in fields
        .iter()
        .copied()
        .chain(std::iter::once(relative.as_os_str().as_bytes()))
    {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

#[cfg(target_os = "ios")]
mod ios {
    use super::*;
    use crate::error::AccountHomeError;
    use objc2_foundation::{NSBundle, NSFileManager, NSHomeDirectory, NSString};

    fn failure(message: &str) -> AccountHomeError {
        AccountHomeError::SecretStore(message.to_owned())
    }

    pub(super) fn select_root<T>(
        root: &Path,
        options: &IosOptions,
        selected: impl FnOnce(&Path, &Path, &[&[u8]]) -> AccountHomeResult<T>,
    ) -> AccountHomeResult<T> {
        // Public container APIs locate today's directories; hashes use logical identities.
        let home = std::fs::canonicalize(NSHomeDirectory().to_string())?;
        if let Ok(relative) = root.strip_prefix(&home) {
            let application = NSBundle::mainBundle()
                .bundleIdentifier()
                .map(|id| id.to_string())
                .filter(|id| !id.is_empty() && !id.contains('*') && !id.contains('\0'))
                .ok_or_else(|| failure("missing explicit iOS bundle identifier"))?;
            return selected(&home, relative, &[b"ios-app", application.as_bytes()]);
        }
        let manager = NSFileManager::defaultManager();
        for group in &options.app_group_identifiers {
            if group.is_empty() || group.contains('*') || group.contains('\0') {
                return Err(failure("iOS app-group identifier must be explicit"));
            }
            let Some(url) = manager
                .containerURLForSecurityApplicationGroupIdentifier(&NSString::from_str(group))
            else {
                return Err(failure("iOS denied the configured app-group container"));
            };
            let path = url
                .path()
                .ok_or_else(|| failure("iOS app-group container has no file path"))?;
            let container = std::fs::canonicalize(path.to_string())?;
            if let Ok(relative) = root.strip_prefix(&container) {
                return selected(&container, relative, &[b"ios-app-group", group.as_bytes()]);
            }
        }
        Err(failure(
            "account root is outside the current authorized iOS containers",
        ))
    }
}

#[cfg(target_os = "android")]
pub(crate) mod android {
    use super::*;
    use crate::error::AccountHomeError;
    use jni::objects::{GlobalRef, JObject, JString};
    use jni::{JNIEnv, JavaVM};
    use std::path::PathBuf;

    pub(crate) struct Context {
        pub(crate) vm: JavaVM,
        pub(crate) context: GlobalRef,
        pub(crate) data: PathBuf,
        pub(crate) no_backup: PathBuf,
        package: String,
        uid: i32,
        device: bool,
        other: Option<PathBuf>,
    }

    fn failure(message: &str) -> AccountHomeError {
        AccountHomeError::SecretStore(message.to_owned())
    }

    pub(crate) fn checked<T>(result: jni::errors::Result<T>) -> AccountHomeResult<T> {
        result.map_err(|error| {
            AccountHomeError::SecretStore(format!("Android JNI operation failed: {error}"))
        })
    }

    pub(crate) fn with_vm<T>(
        vm: &JavaVM,
        operation: impl FnOnce(&mut JNIEnv<'_>) -> AccountHomeResult<T>,
    ) -> AccountHomeResult<T> {
        let mut env = checked(vm.attach_current_thread())?;
        if checked(env.exception_check())? {
            return Err(failure("Android entered with a pending Java exception"));
        }
        checked(env.push_local_frame(96))?;
        let result = operation(&mut env);
        let exception = checked(env.exception_check())?;
        if exception {
            checked(env.exception_clear())?;
        }
        checked(unsafe { env.pop_local_frame(&JObject::null()) })?;
        if exception && result.is_ok() {
            return Err(failure("Android operation raised a Java exception"));
        }
        result
    }

    pub(crate) fn object_string(
        env: &mut JNIEnv<'_>,
        object: &JObject<'_>,
        method: &str,
    ) -> AccountHomeResult<String> {
        let value = checked(env.call_method(object, method, "()Ljava/lang/String;", &[]))?;
        let value = env.auto_local(JString::from(checked(value.l())?));
        let value = checked(env.get_string(&value))?;
        Ok(value.into())
    }

    fn directory(
        env: &mut JNIEnv<'_>,
        context: &JObject<'_>,
        method: &str,
    ) -> AccountHomeResult<PathBuf> {
        let value = checked(env.call_method(context, method, "()Ljava/io/File;", &[]))?;
        let value = checked(value.l())?;
        if value.is_null() {
            return Err(failure("Android private container is unavailable"));
        }
        Ok(PathBuf::from(object_string(
            env,
            &value,
            "getAbsolutePath",
        )?))
    }

    pub(crate) fn no_backup_dir(
        env: &mut JNIEnv<'_>,
        context: &JObject<'_>,
    ) -> AccountHomeResult<PathBuf> {
        directory(env, context, "getNoBackupFilesDir")
    }

    fn data_field(
        env: &mut JNIEnv<'_>,
        info: &JObject<'_>,
        field: &str,
    ) -> AccountHomeResult<PathBuf> {
        let value = checked(env.get_field(info, field, "Ljava/lang/String;"))?;
        let value = JString::from(checked(value.l())?);
        let value = String::from(checked(env.get_string(&value))?);
        if value.is_empty() {
            return Err(failure("Android private data directory is unavailable"));
        }
        Ok(PathBuf::from(value))
    }

    pub(crate) fn capture() -> AccountHomeResult<Context> {
        let ndk = std::panic::catch_unwind(ndk_context::android_context)
            .map_err(|_| failure("Android application context is not initialized"))?;
        let vm = checked(unsafe { JavaVM::from_raw(ndk.vm().cast()) })?;
        let (context, data, no_backup, package, uid, device, other) = with_vm(&vm, |env| {
            let sdk = checked(env.get_static_field("android/os/Build$VERSION", "SDK_INT", "I"))?;
            let sdk = checked(sdk.i())?;
            if sdk < 23 {
                return Err(failure(
                    "Android account ownership requires API 23 or later",
                ));
            }
            // The host retains the supplied NDK context. Capture our own global
            // storage reference before leaving this local frame.
            let supplied = unsafe { JObject::from_raw(ndk.context().cast()) };
            let device = sdk >= 24
                && checked(
                    checked(env.call_method(&supplied, "isDeviceProtectedStorage", "()Z", &[]))?
                        .z(),
                )?;
            let application = checked(env.call_method(
                &supplied,
                "getApplicationContext",
                "()Landroid/content/Context;",
                &[],
            ))?;
            let application = checked(application.l())?;
            if application.is_null() {
                return Err(failure("Android application context is unavailable"));
            }
            let package = object_string(env, &application, "getPackageName")?;
            if package.is_empty() {
                return Err(failure("Android package identity is unavailable"));
            }
            let uid = checked(
                checked(env.call_static_method("android/os/Process", "myUid", "()I", &[]))?.i(),
            )?;
            let info = checked(env.call_method(
                &supplied,
                "getApplicationInfo",
                "()Landroid/content/pm/ApplicationInfo;",
                &[],
            ))?;
            let info = checked(info.l())?;
            let data = if sdk >= 24 {
                directory(env, &supplied, "getDataDir")?
            } else {
                data_field(env, &info, "dataDir")?
            };
            let no_backup = no_backup_dir(env, &supplied)?;
            let other = if sdk < 24 {
                None
            } else {
                Some(data_field(
                    env,
                    &info,
                    if device {
                        "dataDir"
                    } else {
                        "deviceProtectedDataDir"
                    },
                )?)
            };
            Ok((
                checked(env.new_global_ref(supplied))?,
                data,
                no_backup,
                package,
                uid,
                device,
                other,
            ))
        })?;
        let data = std::fs::canonicalize(data)?;
        let no_backup = std::fs::canonicalize(no_backup)?;
        if !no_backup.starts_with(&data) {
            return Err(failure(
                "Android no-backup directory is outside the captured private container",
            ));
        }
        Ok(Context {
            vm,
            context,
            data,
            no_backup,
            package,
            uid,
            device,
            other,
        })
    }

    impl Context {
        fn with_identity<T>(&self, device: bool, use_identity: impl FnOnce(&[&[u8]]) -> T) -> T {
            use_identity(&[
                b"android-app",
                self.package.as_bytes(),
                &self.uid.to_le_bytes(),
                if device { b"device" } else { b"credential" },
            ])
        }

        pub(crate) fn selected_root_hash(&self, root: &Path) -> AccountHomeResult<[u8; 32]> {
            let relative = root
                .strip_prefix(&self.data)
                .map_err(|_| failure("root is outside the captured Android private container"))?;
            Ok(self.with_identity(self.device, |identity| mobile_hash(identity, relative)))
        }

        pub(super) fn select_root<T>(
            &self,
            root: &Path,
            selected: impl FnOnce(&Path, &Path, &[&[u8]]) -> AccountHomeResult<T>,
        ) -> AccountHomeResult<T> {
            if let Ok(relative) = root.strip_prefix(&self.data) {
                return self.with_identity(self.device, |identity| {
                    selected(&self.data, relative, identity)
                });
            }
            if let Some(other) = &self.other {
                let other = std::fs::canonicalize(other)?;
                // dataDir is the default, which can itself be DE. Equal
                // canonical anchors do not reveal a second CE container.
                if other != self.data {
                    if let Ok(relative) = root.strip_prefix(&other) {
                        return self.with_identity(!self.device, |identity| {
                            selected(&other, relative, identity)
                        });
                    }
                }
            }
            Err(failure(
                "account root is outside the current authorized Android private containers",
            ))
        }
    }
}
