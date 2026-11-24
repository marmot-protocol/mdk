use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
const PROVIDER: &str = "AndroidKeyStore";
const TRANSFORM: &str = "AES/GCM/NoPadding";

pub(crate) struct NativeVault {
    vm: JavaVM,
    _context: GlobalRef,
    root: PathBuf,
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
        let managed = context.no_backup.join("marmot-owned-vault-v1");
        private_directory(&managed)?;
        let root = managed.join(service_hash);
        private_directory(&root)?;
        for child in ["receipts", "retirements"] {
            private_directory(&root.join(child))?;
        }
        Ok(Self {
            vm: context.vm,
            _context: context.context,
            root,
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

    fn directory(&self, kind: RecordKind) -> PathBuf {
        self.root.join(match kind {
            RecordKind::Receipt => "receipts",
            RecordKind::Retirement => "retirements",
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

    fn lease(&self) -> AccountHomeResult<fs_private::PrivateExclusiveFileLease> {
        Ok(fs_private::try_acquire_private_exclusive_file_lease(
            &self.root.join(crate::CREDENTIAL_STORE_LOCK_FILE),
        )?)
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

impl VaultStorage for NativeVault {
    fn read(&self, kind: RecordKind, name: &str) -> AccountHomeResult<Option<Zeroizing<String>>> {
        validate_name(name)?;
        let directory = self.directory(kind);
        let path = directory.join(name);
        match kind {
            RecordKind::Receipt => read_record(&path, MAX_CIPHER)?
                .map(|bytes| self.decrypt(name, &bytes))
                .transpose(),
            RecordKind::Retirement => read_record(&path, MAX_VALUE)?
                .map(|bytes| secret_string(&bytes))
                .transpose(),
        }
    }

    fn write(&self, kind: RecordKind, name: &str, value: &str) -> AccountHomeResult<()> {
        let _lease = self.lease()?;
        sync_directory(&self.root)?;
        validate_name(name)?;
        if value.is_empty() || value.len() > MAX_VALUE {
            return Err(failure("Android vault record exceeds size limit"));
        }
        let directory = self.directory(kind);
        match kind {
            RecordKind::Retirement => publish_record(&directory, name, value.as_bytes()),
            RecordKind::Receipt => {
                if let Some(bytes) = read_record(&directory.join(name), MAX_CIPHER)? {
                    if self.decrypt(name, &bytes)?.as_str() != value {
                        return Err(failure("Android receipt is immutable"));
                    }
                    return sync_directory(&directory);
                }
                let bytes = self.encrypt(name, value)?;
                publish_record(&directory, name, &bytes)
            }
        }
    }

    fn remove(&self, kind: RecordKind, name: &str) -> AccountHomeResult<()> {
        validate_name(name)?;
        let _lease = self.lease()?;
        let directory = self.directory(kind);
        let mut result = remove_record(&directory.join(name));
        let unpublished = remove_record(&directory.join(format!("{UNPUBLISHED}{name}")));
        result = combine_errors(result, unpublished);
        result = combine_errors(result, sync_directory(&directory));
        if matches!(kind, RecordKind::Receipt) {
            result = combine_errors(result, self.delete_key(name));
        }
        result
    }

    fn names(&self, kind: RecordKind) -> AccountHomeResult<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(self.directory(kind))? {
            let entry = entry?;
            let filename = entry.file_name();
            let name = filename
                .to_str()
                .ok_or_else(|| failure("Android vault record name is not UTF-8"))?;
            if let Some(unpublished) = name.strip_prefix(UNPUBLISHED) {
                validate_name(unpublished)?;
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            check_file(&metadata)?;
            validate_name(name)?;
            names.push(name.to_owned());
        }
        names.sort_unstable();
        Ok(names)
    }

    fn sync(&self, kind: RecordKind) -> AccountHomeResult<()> {
        sync_directory(&self.directory(kind))
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

fn private_directory(path: &Path) -> AccountHomeResult<()> {
    fs_private::create_dir_all_private(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(failure("Android vault directory ownership is invalid"));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    sync_directory(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn check_file(metadata: &fs::Metadata) -> AccountHomeResult<()> {
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(failure(
            "Android vault file ownership or permissions are invalid",
        ));
    }
    Ok(())
}

fn read_record(path: &Path, limit: usize) -> AccountHomeResult<Option<Zeroizing<Vec<u8>>>> {
    read_file(path, limit, check_file)
}

fn check_legacy_file(metadata: &fs::Metadata) -> AccountHomeResult<()> {
    let mode = metadata.permissions().mode();
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
    read_file(path, MAX_LEGACY_XML, check_legacy_file)
}

fn read_file(
    path: &Path,
    limit: usize,
    validate: impl FnOnce(&fs::Metadata) -> AccountHomeResult<()>,
) -> AccountHomeResult<Option<Zeroizing<Vec<u8>>>> {
    open_file(path)?
        .map(|file| read_open_file(&file, limit, validate))
        .transpose()
}

fn open_file(path: &Path) -> AccountHomeResult<Option<File>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
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

fn publish_record(directory: &Path, name: &str, bytes: &[u8]) -> AccountHomeResult<()> {
    let unpublished = directory.join(format!("{UNPUBLISHED}{name}"));
    remove_record(&unpublished)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&unpublished)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&unpublished, directory.join(name))?;
    sync_directory(directory)
}

fn remove_record(path: &Path) -> AccountHomeResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_directory(path: &Path) -> AccountHomeResult<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    file.sync_all()?;
    Ok(())
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
