use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use jni::objects::{GlobalRef, JByteArray, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{AccountHomeError, AccountHomeResult};
use crate::location::android::{capture, checked, object_string, with_vm};
use crate::owned_vault::{RecordKind, VaultStorage};

const MAX_VALUE: usize = 8192;
const MAX_NAME: usize = 200;
const MAGIC: &[u8; 8] = b"MDKAV001";
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_CIPHER: usize = MAGIC.len() + IV_LEN + MAX_VALUE + TAG_LEN;
const MAX_LEGACY_XML: usize = 8 * 1024 * 1024;
const UNPUBLISHED: &str = ".unpublished-";
const MANAGED_ROOT: &CStr = c"marmot-owned-vault-v1";
const RECEIPTS: &CStr = c"receipts";
const RETIREMENTS: &CStr = c"retirements";
const PROVIDER: &str = "AndroidKeyStore";
const TRANSFORM: &str = "AES/GCM/NoPadding";

pub(crate) struct NativeVault {
    vm: JavaVM,
    _context: GlobalRef,
    no_backup: File,
    lease_name: String,
    service_dir: CString,
    directories: RecordDirectories,
    namespace: String,
    legacy_scope: String,
    alias_prefix: String,
    service: String,
    legacy_file: String,
    legacy_divider: String,
    legacy_path: PathBuf,
}

impl std::fmt::Debug for NativeVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeVault").finish_non_exhaustive()
    }
}

impl NativeVault {
    pub(crate) fn new(service: &str, _ios_options: &crate::IosOptions) -> AccountHomeResult<Self> {
        if service.is_empty() {
            return Err(AccountHomeError::EmptySecretStoreService);
        }
        let config = match keyring_core::get_default_store() {
            Some(store) => {
                let store = store
                    .as_any()
                    .downcast_ref::<android_native_keyring_store::Store>()
                    .ok_or_else(|| {
                        failure("Android legacy provider is not the native Android store")
                    })?;
                store.config.clone()
            }
            None => android_native_keyring_store::by_store::store::StoreConfig::default(),
        };
        if matches!(config.filename.as_str(), "" | "." | "..")
            || config.filename.contains(['/', '\0'])
            || config.divider.is_empty()
            || service.contains(&config.divider)
        {
            return Err(failure("Android legacy provider configuration is invalid"));
        }
        let legacy_hash = hex::encode(Sha256::digest(serde_json::to_vec(&config)?));
        let context = capture()?;
        let container = hex::encode(context.selected_root_hash(&context.no_backup)?);
        let service_hash = hex::encode(Sha256::digest(service.as_bytes()));
        let namespace = format!("android-owned-v1:container={container}:service={service_hash}",);
        let legacy_scope = format!("android-legacy-v1:{namespace}:config={legacy_hash}");
        let alias_prefix = format!(
            "mdk.owned.v1.{}.",
            hex::encode(Sha256::digest(namespace.as_bytes()))
        );
        let no_backup = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&context.no_backup)?;
        if no_backup.metadata()?.uid() != unsafe { libc::geteuid() } {
            return Err(failure("Android no-backup container ownership is invalid"));
        }
        // The OS-selected container outlives individual service directories.
        // Every handle for these Keystore aliases takes the same lease first.
        let lease_name = format!(".mdk-owned-vault-v1-{service_hash}.lock");
        let service_dir = CString::new(service_hash).expect("service hash has no NUL");
        let _lease = fs_private::try_acquire_lease_at(no_backup.as_fd(), OsStr::new(&lease_name))?;
        let directories = RecordDirectories::open(&no_backup, &service_dir, true)?;
        Ok(Self {
            vm: context.vm,
            _context: context.context,
            no_backup,
            lease_name,
            service_dir,
            directories,
            namespace,
            legacy_scope,
            alias_prefix,
            service: service.to_owned(),
            legacy_path: context
                .data
                .join("shared_prefs")
                .join(format!("{}.xml", config.filename)),
            legacy_file: config.filename,
            legacy_divider: config.divider,
        })
    }

    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn legacy_scope(&self) -> Option<&str> {
        Some(&self.legacy_scope)
    }

    pub(crate) fn with_mutation<T>(
        &self,
        operation: impl FnOnce(&NativeVaultMutation<'_>) -> AccountHomeResult<T>,
    ) -> AccountHomeResult<T> {
        let _lease =
            fs_private::try_acquire_lease_at(self.no_backup.as_fd(), OsStr::new(&self.lease_name))?;
        self.check_current_directories()?;
        let result = operation(&NativeVaultMutation(self))?;
        self.check_current_directories()?;
        Ok(result)
    }

    fn check_current_directories(&self) -> AccountHomeResult<()> {
        let current = RecordDirectories::open(&self.no_backup, &self.service_dir, false)?;
        self.directories.check_match(&current)
    }

    pub(crate) fn legacy_secret(
        &self,
        account_id: &str,
    ) -> AccountHomeResult<Option<Zeroizing<String>>> {
        if account_id.is_empty()
            || account_id.len() > MAX_NAME
            || account_id.contains(&self.legacy_divider)
        {
            return Err(failure("Android legacy credential identifier is invalid"));
        }
        let backup = self.legacy_path.with_extension("xml.bak");
        // SharedPreferences commits keep the previous committed map in .bak.
        // Read that snapshot first without restoring or deleting either file.
        let xml = match read_legacy(&backup)? {
            Some(xml) => Some(xml),
            None => match read_legacy(&self.legacy_path)? {
                Some(xml) => Some(xml),
                None => read_legacy(&backup)?,
            },
        };
        let Some(xml) = xml else {
            return Ok(None);
        };
        with_vm(&self.vm, |env| {
            let address = format!("{account_id}{}{}", self.legacy_divider, self.service);
            let Some(encoded) = legacy_value(env, &xml, &address)? else {
                return Ok(None);
            };
            let length = checked(env.call_method(&encoded, "length", "()I", &[]))?;
            let length = checked(length.i())?;
            if length <= 0 || length as usize > MAX_CIPHER * 2 {
                return Err(failure("Android legacy ciphertext exceeds size limit"));
            }
            let decoded = checked(env.call_static_method(
                "android/util/Base64",
                "decode",
                "(Ljava/lang/String;I)[B",
                &[JValue::Object(&encoded), JValue::Int(0)],
            ))?;
            let decoded = JByteArray::from(checked(decoded.l())?);
            let bytes = checked(env.convert_byte_array(&decoded))?;
            if bytes.len() < 1 + IV_LEN + TAG_LEN
                || bytes.len() > 1 + IV_LEN + MAX_VALUE + TAG_LEN
                || bytes[0] as usize != IV_LEN
            {
                return Err(failure("Android legacy ciphertext format is invalid"));
            }
            let store = open_keystore(env)?;
            let key = find_key(env, &store, &self.legacy_file)?;
            if key.is_null() {
                return Err(failure("Android legacy decryption key is unavailable"));
            }
            let cipher = cipher_instance(env)?;
            init_decrypt(env, &cipher, &key, &bytes[1..1 + IV_LEN])?;
            let plain = cipher_bytes(env, &cipher, &bytes[1 + IV_LEN..], false)?;
            Ok(Some(secret_string(&plain)?))
        })
    }

    fn alias(&self, name: &str) -> AccountHomeResult<String> {
        let alias = format!("{}{name}", self.alias_prefix);
        if alias == self.legacy_file {
            return Err(failure(
                "Android managed receipt alias collides with the legacy key",
            ));
        }
        Ok(alias)
    }

    fn aad(&self, name: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.namespace.len() + 1 + name.len());
        aad.extend_from_slice(self.namespace.as_bytes());
        aad.push(0);
        aad.extend_from_slice(name.as_bytes());
        aad
    }

    fn encrypt(&self, name: &str, value: &str) -> AccountHomeResult<Zeroizing<Vec<u8>>> {
        with_vm(&self.vm, |env| {
            let store = open_keystore(env)?;
            let alias = self.alias(name)?;
            let mut key = find_key(env, &store, &alias)?;
            if key.is_null() {
                key = generate_key(env, &alias)?;
                let persisted = find_key(env, &store, &alias)?;
                if persisted.is_null() {
                    return Err(failure("Android receipt encryption key was not persisted"));
                }
            }
            let cipher = cipher_instance(env)?;
            checked(env.call_method(
                &cipher,
                "init",
                "(ILjava/security/Key;)V",
                &[JValue::Int(1), JValue::Object(&key)],
            ))?;
            update_aad(env, &cipher, &self.aad(name))?;
            let iv = checked(env.call_method(&cipher, "getIV", "()[B", &[]))?;
            let iv = JByteArray::from(checked(iv.l())?);
            let iv = checked(env.convert_byte_array(&iv))?;
            if iv.len() != IV_LEN {
                return Err(failure("Android receipt cipher returned an invalid nonce"));
            }
            let ciphertext = cipher_bytes(env, &cipher, value.as_bytes(), true)?;
            let mut record =
                Zeroizing::new(Vec::with_capacity(MAGIC.len() + IV_LEN + ciphertext.len()));
            record.extend_from_slice(MAGIC);
            record.extend_from_slice(&iv);
            record.extend_from_slice(&ciphertext);
            Ok(record)
        })
    }

    fn decrypt(&self, name: &str, record: &[u8]) -> AccountHomeResult<Zeroizing<String>> {
        if record.len() < MAGIC.len() + IV_LEN + TAG_LEN + 1
            || record.len() > MAX_CIPHER
            || &record[..MAGIC.len()] != MAGIC
        {
            return Err(failure("Android receipt ciphertext format is invalid"));
        }
        with_vm(&self.vm, |env| {
            let store = open_keystore(env)?;
            let key = find_key(env, &store, &self.alias(name)?)?;
            if key.is_null() {
                return Err(failure("Android receipt decryption key is unavailable"));
            }
            let cipher = cipher_instance(env)?;
            init_decrypt(
                env,
                &cipher,
                &key,
                &record[MAGIC.len()..MAGIC.len() + IV_LEN],
            )?;
            update_aad(env, &cipher, &self.aad(name))?;
            let plain = cipher_bytes(env, &cipher, &record[MAGIC.len() + IV_LEN..], false)?;
            secret_string(&plain)
        })
    }

    fn delete_key(&self, name: &str) -> AccountHomeResult<()> {
        with_vm(&self.vm, |env| {
            let store = open_keystore(env)?;
            let alias = checked(env.new_string(self.alias(name)?))?;
            checked(env.call_method(
                &store,
                "deleteEntry",
                "(Ljava/lang/String;)V",
                &[JValue::Object(alias.as_ref())],
            ))?;
            let remains = checked(env.call_method(
                &store,
                "containsAlias",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(alias.as_ref())],
            ))?;
            if checked(remains.z())? {
                return Err(failure(
                    "Android receipt encryption key remains after deletion",
                ));
            }
            Ok(())
        })
    }
}

pub(crate) struct NativeVaultMutation<'a>(&'a NativeVault);

impl VaultStorage for NativeVaultMutation<'_> {
    fn read(&self, kind: RecordKind, name: &str) -> AccountHomeResult<Option<Zeroizing<String>>> {
        validate_name(name)?;
        let directory = self.0.directories.get(kind);
        let filename = CString::new(name).expect("validated record name has no NUL");
        match kind {
            RecordKind::Receipt => read_record(directory, &filename, MAX_CIPHER)?
                .map(|bytes| self.0.decrypt(name, &bytes))
                .transpose(),
            RecordKind::Retirement => read_record(directory, &filename, MAX_VALUE)?
                .map(|bytes| secret_string(&bytes))
                .transpose(),
        }
    }

    fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()> {
        validate_name(name)?;
        if value.is_empty() || value.len() > MAX_VALUE {
            return Err(failure("Android vault record exceeds size limit"));
        }
        let directory = self.0.directories.get(kind);
        let filename = CString::new(name).expect("validated record name has no NUL");
        match kind {
            RecordKind::Retirement => publish_record(directory, &filename, value.as_bytes()),
            RecordKind::Receipt => {
                if let Some(bytes) = read_record(directory, &filename, MAX_CIPHER)? {
                    if self.0.decrypt(name, &bytes)?.as_str() != value {
                        return Err(failure("Android receipt is immutable"));
                    }
                    return Ok(directory.sync_all()?);
                }
                self.0.check_current_directories()?;
                let bytes = self.0.encrypt(name, value)?;
                publish_record(directory, &filename, &bytes)
            }
        }
    }

    fn remove(&self, kind: RecordKind, name: &str) -> AccountHomeResult<()> {
        validate_name(name)?;
        let directory = self.0.directories.get(kind);
        let filename = CString::new(name).expect("validated record name has no NUL");
        let files = combine_errors(
            remove_record(directory, &filename),
            remove_record(directory, &unpublished(&filename)),
        );
        combine_errors(files, directory.sync_all().map_err(Into::into))?;
        if matches!(kind, RecordKind::Receipt) {
            self.0.check_current_directories()?;
            self.0.delete_key(name)?;
        }
        Ok(())
    }

    fn names(&self, kind: RecordKind) -> AccountHomeResult<Vec<String>> {
        record_names(self.0.directories.get(kind))
    }

    fn sync(&self, kind: RecordKind) -> AccountHomeResult<()> {
        Ok(self.0.directories.get(kind).sync_all()?)
    }
}

fn failure(message: &str) -> AccountHomeError {
    AccountHomeError::SecretStore(message.to_owned())
}

fn legacy_value<'a>(
    env: &mut JNIEnv<'a>,
    xml: &[u8],
    address: &str,
) -> AccountHomeResult<Option<JObject<'a>>> {
    let xml = std::str::from_utf8(xml)
        .map_err(|_| failure("Android legacy preferences are not UTF-8"))?;
    let xml = checked(env.new_string(xml))?;
    let reader = checked(env.new_object(
        "java/io/StringReader",
        "(Ljava/lang/String;)V",
        &[JValue::Object(xml.as_ref())],
    ))?;
    let parser = checked(env.call_static_method(
        "android/util/Xml",
        "newPullParser",
        "()Lorg/xmlpull/v1/XmlPullParser;",
        &[],
    ))?;
    let parser = checked(parser.l())?;
    let feature =
        checked(env.new_string("http://xmlpull.org/v1/doc/features.html#process-docdecl"))?;
    checked(env.call_method(
        &parser,
        "setFeature",
        "(Ljava/lang/String;Z)V",
        &[JValue::Object(feature.as_ref()), JValue::Bool(0)],
    ))?;
    checked(env.call_method(
        &parser,
        "setInput",
        "(Ljava/io/Reader;)V",
        &[JValue::Object(&reader)],
    ))?;
    let attribute = checked(env.new_string("name"))?;
    let mut found = None;
    let mut root = false;
    loop {
        let event = checked(env.call_method(&parser, "nextToken", "()I", &[]))?;
        match checked(event.i())? {
            1 => {
                if !root {
                    return Err(failure("Android legacy preferences have no map"));
                }
                return Ok(found);
            }
            2 => {
                let tag = object_string(env, &parser, "getName")?;
                let depth = checked(env.call_method(&parser, "getDepth", "()I", &[]))?;
                let depth = checked(depth.i())?;
                if depth == 1 {
                    if root || tag != "map" {
                        return Err(failure("Android legacy preferences root is invalid"));
                    }
                    root = true;
                    continue;
                }
                if depth != 2 {
                    continue;
                }
                let name = checked(env.call_method(
                    &parser,
                    "getAttributeValue",
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    &[
                        JValue::Object(&JObject::null()),
                        JValue::Object(attribute.as_ref()),
                    ],
                ))?;
                let name = env.auto_local(JString::from(checked(name.l())?));
                if name.is_null() {
                    return Err(failure("Android legacy preference has no name"));
                }
                let name = String::from(checked(env.get_string(&name))?);
                if name != address {
                    continue;
                }
                if tag != "string" || found.is_some() {
                    return Err(failure(
                        "Android legacy credential has an invalid type or duplicate name",
                    ));
                }
                let value =
                    checked(env.call_method(&parser, "nextText", "()Ljava/lang/String;", &[]))?;
                found = Some(checked(value.l())?);
            }
            6 => {
                let name = object_string(env, &parser, "getName")?;
                if !allowed_entity(&name) {
                    return Err(failure(
                        "Android legacy preferences contain an unresolved or external entity",
                    ));
                }
                let text =
                    checked(env.call_method(&parser, "getText", "()Ljava/lang/String;", &[]))?;
                let text = env.auto_local(checked(text.l())?);
                if text.is_null() {
                    return Err(failure(
                        "Android legacy preferences contain an unresolved entity",
                    ));
                }
            }
            10 => {
                return Err(failure(
                    "Android legacy preferences contain a document declaration",
                ));
            }
            _ => {}
        }
    }
}

fn allowed_entity(name: &str) -> bool {
    if matches!(name, "amp" | "apos" | "gt" | "lt" | "quot") {
        return true;
    }
    let (digits, radix) = if let Some(digits) = name.strip_prefix("#x") {
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        (digits, 16)
    } else if let Some(digits) = name.strip_prefix('#') {
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        (digits, 10)
    } else {
        return false;
    };
    matches!(
        u32::from_str_radix(digits, radix),
        Ok(0x9 | 0xa | 0xd | 0x20..=0xd7ff | 0xe000..=0xfffd | 0x10000..=0x10ffff)
    )
}

fn open_keystore<'a>(env: &mut JNIEnv<'a>) -> AccountHomeResult<JObject<'a>> {
    let provider = checked(env.new_string(PROVIDER))?;
    let store = checked(env.call_static_method(
        "java/security/KeyStore",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        &[JValue::Object(provider.as_ref())],
    ))?;
    let store = checked(store.l())?;
    checked(env.call_method(
        &store,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&JObject::null())],
    ))?;
    Ok(store)
}

fn find_key<'a>(
    env: &mut JNIEnv<'a>,
    store: &JObject<'_>,
    alias: &str,
) -> AccountHomeResult<JObject<'a>> {
    let alias = checked(env.new_string(alias))?;
    let key = checked(env.call_method(
        store,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[
            JValue::Object(alias.as_ref()),
            JValue::Object(&JObject::null()),
        ],
    ))?;
    checked(key.l())
}

fn generate_key<'a>(env: &mut JNIEnv<'a>, alias: &str) -> AccountHomeResult<JObject<'a>> {
    let alias = checked(env.new_string(alias))?;
    let builder = checked(env.new_object(
        "android/security/keystore/KeyGenParameterSpec$Builder",
        "(Ljava/lang/String;I)V",
        &[JValue::Object(alias.as_ref()), JValue::Int(3)],
    ))?;
    for (method, text) in [
        ("setBlockModes", "GCM"),
        ("setEncryptionPaddings", "NoPadding"),
    ] {
        let text = checked(env.new_string(text))?;
        let array = checked(env.new_object_array(1, "java/lang/String", text))?;
        checked(env.call_method(
            &builder,
            method,
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(array.as_ref())],
        ))?;
    }
    checked(env.call_method(
        &builder,
        "setKeySize",
        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Int(256)],
    ))?;
    checked(env.call_method(
        &builder,
        "setRandomizedEncryptionRequired",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(1)],
    ))?;
    checked(env.call_method(
        &builder,
        "setUserAuthenticationRequired",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(0)],
    ))?;
    let spec = checked(env.call_method(
        &builder,
        "build",
        "()Landroid/security/keystore/KeyGenParameterSpec;",
        &[],
    ))?;
    let spec = checked(spec.l())?;
    let algorithm = checked(env.new_string("AES"))?;
    let provider = checked(env.new_string(PROVIDER))?;
    let generator = checked(env.call_static_method(
        "javax/crypto/KeyGenerator",
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
        &[
            JValue::Object(algorithm.as_ref()),
            JValue::Object(provider.as_ref()),
        ],
    ))?;
    let generator = checked(generator.l())?;
    checked(env.call_method(
        &generator,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
    ))?;
    let key =
        checked(env.call_method(&generator, "generateKey", "()Ljavax/crypto/SecretKey;", &[]))?;
    checked(key.l())
}

fn cipher_instance<'a>(env: &mut JNIEnv<'a>) -> AccountHomeResult<JObject<'a>> {
    let transformation = checked(env.new_string(TRANSFORM))?;
    let cipher = checked(env.call_static_method(
        "javax/crypto/Cipher",
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(transformation.as_ref())],
    ))?;
    checked(cipher.l())
}

fn init_decrypt(
    env: &mut JNIEnv<'_>,
    cipher: &JObject<'_>,
    key: &JObject<'_>,
    iv: &[u8],
) -> AccountHomeResult<()> {
    let iv = checked(env.byte_array_from_slice(iv))?;
    let spec = checked(env.new_object(
        "javax/crypto/spec/GCMParameterSpec",
        "(I[B)V",
        &[JValue::Int(128), JValue::Object(iv.as_ref())],
    ))?;
    checked(env.call_method(
        cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Int(2), JValue::Object(key), JValue::Object(&spec)],
    ))?;
    Ok(())
}

fn update_aad(env: &mut JNIEnv<'_>, cipher: &JObject<'_>, aad: &[u8]) -> AccountHomeResult<()> {
    let aad = checked(env.byte_array_from_slice(aad))?;
    checked(env.call_method(
        cipher,
        "updateAAD",
        "([B)V",
        &[JValue::Object(aad.as_ref())],
    ))?;
    Ok(())
}

fn cipher_bytes(
    env: &mut JNIEnv<'_>,
    cipher: &JObject<'_>,
    input: &[u8],
    encrypt: bool,
) -> AccountHomeResult<Zeroizing<Vec<u8>>> {
    let size = if encrypt {
        input.len().checked_add(TAG_LEN)
    } else {
        input.len().checked_sub(TAG_LEN)
    }
    .ok_or_else(|| failure("Android cipher input length is invalid"))?;
    if size > MAX_VALUE + TAG_LEN || input.len() > MAX_VALUE + TAG_LEN {
        return Err(failure("Android cipher input exceeds size limit"));
    }
    let mut input = Zeroizing::new(input.to_vec());
    let mut output = Zeroizing::new(vec![0_u8; size]);
    // Cipher.doFinal consumes direct buffers synchronously. Local wrappers are
    // dropped before the Rust allocations, including on Java exceptions.
    let input_buffer =
        checked(unsafe { env.new_direct_byte_buffer(input.as_mut_ptr(), input.len()) })?;
    let input_buffer = env.auto_local(input_buffer);
    let output_buffer =
        checked(unsafe { env.new_direct_byte_buffer(output.as_mut_ptr(), output.len()) })?;
    let output_buffer = env.auto_local(output_buffer);
    let written = checked(env.call_method(
        cipher,
        "doFinal",
        "(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)I",
        &[
            JValue::Object(input_buffer.as_ref()),
            JValue::Object(output_buffer.as_ref()),
        ],
    ))?;
    if checked(written.i())? != size as i32 {
        return Err(failure("Android cipher returned an invalid output length"));
    }
    Ok(output)
}

fn secret_string(bytes: &[u8]) -> AccountHomeResult<Zeroizing<String>> {
    if bytes.is_empty() || bytes.len() > MAX_VALUE {
        return Err(failure("Android vault plaintext length is invalid"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| failure("Android vault plaintext is not UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn validate_name(name: &str) -> AccountHomeResult<()> {
    if name.is_empty()
        || name.len() > MAX_NAME
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        return Err(failure("Android vault record name is invalid"));
    }
    Ok(())
}

struct RecordDirectories {
    service: File,
    receipts: File,
    retirements: File,
}

impl RecordDirectories {
    fn open(container: &File, service_dir: &CStr, create: bool) -> AccountHomeResult<Self> {
        let managed = open_private_directory(container, MANAGED_ROOT, create)?;
        let service = open_private_directory(&managed, service_dir, create)?;
        let receipts = open_private_directory(&service, RECEIPTS, create)?;
        let retirements = open_private_directory(&service, RETIREMENTS, create)?;
        if create {
            // Retry the whole publication barrier after an interrupted first open.
            receipts.sync_all()?;
            retirements.sync_all()?;
            service.sync_all()?;
            managed.sync_all()?;
            container.sync_all()?;
        }
        Ok(Self {
            service,
            receipts,
            retirements,
        })
    }

    fn get(&self, kind: RecordKind) -> &File {
        match kind {
            RecordKind::Receipt => &self.receipts,
            RecordKind::Retirement => &self.retirements,
        }
    }

    fn check_match(&self, current: &Self) -> AccountHomeResult<()> {
        for (opened, current) in [
            (&self.service, &current.service),
            (&self.receipts, &current.receipts),
            (&self.retirements, &current.retirements),
        ] {
            let opened = opened.metadata()?;
            let current = current.metadata()?;
            if (opened.dev(), opened.ino()) != (current.dev(), current.ino()) {
                return Err(failure("Android vault directory changed after capture"));
            }
        }
        Ok(())
    }
}

fn open_private_directory(parent: &File, name: &CStr, create: bool) -> AccountHomeResult<File> {
    let directory = match openat(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
            }
            openat(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
        }
        result => result?,
    };
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(failure(
            "Android vault directory ownership or permissions are invalid",
        ));
    }
    Ok(directory)
}

fn openat(
    directory: &File,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::c_uint,
) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn check_file(metadata: &fs::Metadata) -> AccountHomeResult<()> {
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(failure(
            "Android vault file ownership or permissions are invalid",
        ));
    }
    Ok(())
}

fn open_record(directory: &File, filename: &CStr) -> AccountHomeResult<Option<File>> {
    match openat(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_record(
    directory: &File,
    filename: &CStr,
    limit: usize,
) -> AccountHomeResult<Option<Zeroizing<Vec<u8>>>> {
    open_record(directory, filename)?
        .map(|file| read_open_file(&file, limit, check_file))
        .transpose()
}

fn check_legacy_file(metadata: &fs::Metadata) -> AccountHomeResult<()> {
    let mode = metadata.mode();
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o017 != 0
        || (mode & 0o060 != 0 && metadata.gid() != unsafe { libc::getegid() })
    {
        return Err(failure(
            "Android legacy file ownership or permissions are invalid",
        ));
    }
    Ok(())
}

fn read_legacy(path: &Path) -> AccountHomeResult<Option<Zeroizing<Vec<u8>>>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => Ok(Some(read_open_file(
            &file,
            MAX_LEGACY_XML,
            check_legacy_file,
        )?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_open_file(
    file: &File,
    limit: usize,
    validate: impl FnOnce(&fs::Metadata) -> AccountHomeResult<()>,
) -> AccountHomeResult<Zeroizing<Vec<u8>>> {
    let metadata = file.metadata()?;
    validate(&metadata)?;
    if metadata.len() > limit as u64 {
        return Err(failure("Android vault record exceeds size limit"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(failure("Android vault record exceeds size limit"));
    }
    Ok(bytes)
}

fn unpublished(name: &CStr) -> CString {
    let mut bytes = Vec::with_capacity(UNPUBLISHED.len() + name.to_bytes_with_nul().len());
    bytes.extend_from_slice(UNPUBLISHED.as_bytes());
    bytes.extend_from_slice(name.to_bytes_with_nul());
    CString::from_vec_with_nul(bytes).expect("validated temporary record name")
}

fn publish_record(directory: &File, name: &CStr, bytes: &[u8]) -> AccountHomeResult<()> {
    let unpublished = unpublished(name);
    remove_record(directory, &unpublished)?;
    let mut file = openat(
        directory,
        &unpublished,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let fd = directory.as_raw_fd();
    if unsafe { libc::renameat(fd, unpublished.as_ptr(), fd, name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(directory.sync_all()?)
}

fn remove_record(directory: &File, name: &CStr) -> AccountHomeResult<()> {
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error.into());
        }
    }
    Ok(())
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn record_names(directory: &File) -> AccountHomeResult<Vec<String>> {
    // Open a separate file description so each enumeration starts at offset zero.
    let file = openat(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let stream = unsafe { libc::fdopendir(file.as_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let _ = file.into_raw_fd(); // fdopendir now owns the descriptor.
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        let entry = unsafe {
            *libc::__errno() = 0;
            libc::readdir(stream.0)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        let filename = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = filename
            .to_str()
            .map_err(|_| failure("Android vault record name is not UTF-8"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        if let Some(name) = name.strip_prefix(UNPUBLISHED) {
            validate_name(name)?;
            continue;
        }
        validate_name(name)?;
        if let Some(file) = open_record(directory, filename)? {
            check_file(&file.metadata()?)?;
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    Ok(names)
}

fn combine_errors(
    first: AccountHomeResult<()>,
    second: AccountHomeResult<()>,
) -> AccountHomeResult<()> {
    match (first, second) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(first), Err(second)) => {
            Err(AccountHomeError::SecretStore(format!("{first}; {second}")))
        }
    }
}
