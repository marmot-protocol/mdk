use super::*;
use nostr::nips::nip44;
use transport_nostr::RelayEndpointPolicy;

pub(super) fn checked_relays(
    relays: Vec<String>,
    policy: &RelaySafetyPolicy,
) -> Result<Vec<RelayUrl>> {
    if relays.is_empty() || relays.len() > 16 || relays.iter().any(|relay| relay.len() > 2048) {
        return Err(Nip46Error::Invalid);
    }
    let mut checked = Vec::with_capacity(relays.len());
    for classification in policy.classify_endpoints(relays) {
        if classification.policy != RelayEndpointPolicy::Allowed {
            return Err(Nip46Error::Invalid);
        }
        let relay = RelayUrl::parse(
            &classification
                .normalized_endpoint
                .ok_or(Nip46Error::Invalid)?,
        )
        .map_err(|_| Nip46Error::Invalid)?;
        if !checked.contains(&relay) {
            checked.push(relay);
        }
    }
    Ok(checked)
}
fn public_key(raw: &str) -> Result<PublicKey> {
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Nip46Error::Invalid);
    }
    PublicKey::from_hex(raw).map_err(|_| Nip46Error::Invalid)
}
fn name_valid(name: &str) -> bool {
    name.len() <= 256 && !name.chars().any(char::is_control)
}
fn initial_data(keys: Keys, name: String, relays: Vec<RelayUrl>) -> Data {
    Data {
        keys: Some(keys),
        remote: None,
        user: None,
        relays,
        secret: None,
        client_pairing: false,
        pairing_established: false,
        name,
        approved: None,
        reviewed: false,
        verified: false,
        status: Nip46Status {
            state: Nip46State::PermissionApproval,
            last_error: Some(Nip46Error::PermissionApprovalRequired),
            auth_url: None,
            request_id: None,
            generation: 0,
        },
        pending: HashMap::new(),
        active: None,
        account: None,
        registration: None,
    }
}
struct PairingUri {
    client: bool,
    public_key: PublicKey,
    relays: Vec<RelayUrl>,
    secret: Option<Zeroizing<String>>,
}
fn parse_uri(raw: &str, policy: &RelaySafetyPolicy) -> Result<PairingUri> {
    if raw.len() > 40 * 1024 || raw.chars().any(char::is_control) {
        return Err(Nip46Error::Invalid);
    }
    let bytes = raw.as_bytes();
    for (offset, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (offset + 2 >= bytes.len()
                || !bytes[offset + 1].is_ascii_hexdigit()
                || !bytes[offset + 2].is_ascii_hexdigit())
        {
            return Err(Nip46Error::Invalid);
        }
    }
    let url = url::Url::parse(raw).map_err(|_| Nip46Error::Invalid)?;
    if !matches!(url.scheme(), "bunker" | "nostrconnect")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || !url.path().is_empty()
        || url.fragment().is_some()
    {
        return Err(Nip46Error::Invalid);
    }
    let key = public_key(url.host_str().ok_or(Nip46Error::Invalid)?)?;
    let mut relays = Vec::new();
    let mut secret = None;
    let mut fields = std::collections::HashSet::new();
    for (field, value) in url.query_pairs() {
        if field != "relay" && !fields.insert(field.to_string()) {
            return Err(Nip46Error::Invalid);
        }
        if value.contains('\u{fffd}') || value.chars().any(char::is_control) {
            return Err(Nip46Error::Invalid);
        }
        match field.as_ref() {
            "relay" => relays.push(value.into_owned()),
            "secret" if !value.is_empty() && value.len() <= 1024 => {
                secret = Some(Zeroizing::new(value.into_owned()))
            }
            "name" if name_valid(&value) && url.scheme() == "nostrconnect" => {}
            "url" | "image" if value.len() <= 2048 && url.scheme() == "nostrconnect" => {
                let metadata_url = url::Url::parse(&value).map_err(|_| Nip46Error::Invalid)?;
                if metadata_url.scheme() != "https"
                    || metadata_url.host_str().is_none()
                    || !metadata_url.username().is_empty()
                    || metadata_url.password().is_some()
                {
                    return Err(Nip46Error::Invalid);
                }
            }
            "perms" if url.scheme() == "nostrconnect" && value == GRANTS.join(",") => {}
            _ => return Err(Nip46Error::Invalid),
        }
    }
    let client = url.scheme() == "nostrconnect";
    if client && secret.is_none() {
        return Err(Nip46Error::Invalid);
    }
    Ok(PairingUri {
        client,
        public_key: key,
        relays: checked_relays(relays, policy)?,
        secret,
    })
}
pub(super) fn parse_config(mut config: Config, policy: &RelaySafetyPolicy) -> Result<Data> {
    // Descriptors may carry a prior review snapshot, but only trusted restore can grant it.
    let _ = (&config.permission_version, &config.permissions);
    let imported_key = config.client_secret.is_some();
    let keys = match config.client_secret.as_deref() {
        Some(secret) => Keys::new(SecretKey::from_hex(secret).map_err(|_| Nip46Error::Invalid)?),
        None => Keys::generate(),
    };
    let name = config.name.take().unwrap_or_else(|| "Marmot".into());
    if !name_valid(&name) {
        return Err(Nip46Error::Invalid);
    }
    let user = config
        .user_public_key
        .as_deref()
        .map(public_key)
        .transpose()?;
    let remote = config
        .remote_signer_public_key
        .as_deref()
        .map(public_key)
        .transpose()?;
    if user.is_some() != remote.is_some()
        || (user.is_some() && (!imported_key || config.uri.is_some()))
    {
        return Err(Nip46Error::Invalid);
    }
    if let Some(remote) = remote {
        let mut data = initial_data(
            keys,
            name,
            checked_relays(std::mem::take(&mut config.relays), policy)?,
        );
        data.user = user;
        data.remote = Some(remote);
        data.pairing_established = true;
        return Ok(data);
    }
    if let Some(raw) = config.uri.as_deref() {
        if !config.relays.is_empty() {
            return Err(Nip46Error::Invalid);
        }
        let parsed = parse_uri(raw, policy)?;
        if parsed.client && (!imported_key || parsed.public_key != keys.public_key()) {
            return Err(Nip46Error::Mismatch);
        }
        let mut data = initial_data(keys, name, parsed.relays);
        data.client_pairing = parsed.client;
        data.secret = parsed.secret;
        if !parsed.client {
            data.remote = Some(parsed.public_key);
        }
        return Ok(data);
    }
    let mut data = initial_data(
        keys,
        name,
        checked_relays(std::mem::take(&mut config.relays), policy)?,
    );
    data.client_pairing = true;
    data.secret = Some(Zeroizing::new(random_nonce()));
    Ok(data)
}
pub(super) fn restore_data(
    keys: Keys,
    record: Nip46SessionRecord,
    policy: &RelaySafetyPolicy,
) -> Result<Data> {
    if record.version != 1
        || record.client_public_key != keys.public_key().to_hex()
        || !name_valid(&record.name)
        || record.permission_version == 0
        || record.permissions.len() > 64
        || record.permissions.iter().any(|grant| {
            grant.is_empty()
                || grant.len() > 256
                || !grant.is_ascii()
                || grant.chars().any(char::is_control)
        })
    {
        return Err(Nip46Error::Invalid);
    }
    let user = public_key(&record.user_public_key)?;
    let remote = public_key(&record.remote_signer_public_key)?;
    let mut data = initial_data(keys, record.name, checked_relays(record.relays, policy)?);
    data.user = Some(user);
    data.remote = Some(remote);
    data.pairing_established = true;
    data.approved = Some(Nip46Permissions {
        version: record.permission_version,
        grants: record.permissions,
    });
    if data
        .approved
        .as_ref()
        .is_some_and(Nip46Permissions::is_current)
    {
        data.status.state = Nip46State::Unavailable;
        data.status.last_error = None;
    }
    Ok(data)
}
pub(super) fn uri(data: &Data, relays: &[RelayUrl]) -> Result<String> {
    let keys = data.keys.as_ref().ok_or(Nip46Error::LoggedOut)?;
    let client = data.client_pairing && data.remote.is_none();
    if client
        && !data
            .approved
            .as_ref()
            .is_some_and(Nip46Permissions::is_current)
    {
        return Err(Nip46Error::PermissionApprovalRequired);
    }
    let key = if client {
        keys.public_key()
    } else {
        data.remote.ok_or(Nip46Error::Unavailable)?
    };
    let mut uri = url::Url::parse(&format!(
        "{}://{}",
        if client { "nostrconnect" } else { "bunker" },
        key
    ))
    .map_err(|_| Nip46Error::Invalid)?;
    {
        let mut query = uri.query_pairs_mut();
        for relay in relays {
            query.append_pair("relay", relay.as_str());
        }
        if let Some(secret) = &data.secret {
            query.append_pair("secret", secret);
        }
        if client {
            query
                .append_pair("perms", &GRANTS.join(","))
                .append_pair("name", &data.name);
        }
    }
    Ok(uri.to_string())
}
pub(super) fn validated_payload(
    event: &Event,
    keys: &Keys,
    expected: Option<PublicKey>,
) -> Option<Value> {
    let mut recipients = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().is_some_and(|kind| kind == "p"));
    let recipient = recipients.next()?;
    if recipients.next().is_some()
        || recipient.as_slice().get(1).map(String::as_str)
            != Some(keys.public_key().to_hex().as_str())
    {
        return None;
    }
    if event.kind != Kind::NostrConnect
        || event.content.len() > MAX_PAYLOAD
        || expected.is_some_and(|author| author != event.pubkey)
        || event.verify().is_err()
    {
        return None;
    }
    let plaintext =
        Zeroizing::new(nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content).ok()?);
    if plaintext.len() > MAX_PAYLOAD {
        return None;
    }
    serde_json::from_str(&plaintext).ok()
}
pub(super) fn pairing_response(payload: &Value, secret: &str) -> bool {
    payload.get("method").is_none()
        && payload
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty() && id.len() <= 256)
        && payload.get("result").and_then(Value::as_str) == Some(secret)
        && payload.get("error").is_none_or(Value::is_null)
}
pub(super) enum Response {
    Ignore,
    Approval(String),
    Complete(Result<Value>),
}
pub(super) fn matching_response(payload: &Value, id: &str) -> Response {
    if payload.get("method").is_some() || payload.get("id").and_then(Value::as_str) != Some(id) {
        return Response::Ignore;
    }
    if payload.get("result").and_then(Value::as_str) == Some("auth_url") {
        let Some(raw) = payload.get("error").and_then(Value::as_str) else {
            return Response::Complete(Err(Nip46Error::Invalid));
        };
        if raw.len() > 4096 {
            return Response::Complete(Err(Nip46Error::Invalid));
        }
        let Ok(url) = url::Url::parse(raw) else {
            return Response::Complete(Err(Nip46Error::Invalid));
        };
        if !matches!(url.scheme(), "https" | "http")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Response::Complete(Err(Nip46Error::Invalid));
        }
        return Response::Approval(url.to_string());
    }
    if let Some(error) = payload.get("error").filter(|error| !error.is_null()) {
        let Some(error) = error.as_str() else {
            return Response::Complete(Err(Nip46Error::Invalid));
        };
        let error = error.to_ascii_lowercase();
        return Response::Complete(Err(
            if error.contains("unsupported")
                || error.contains("unknown method")
                || error.contains("method not found")
                || error.contains("not supported")
            {
                Nip46Error::Unsupported
            } else {
                Nip46Error::Rejected
            },
        ));
    }
    Response::Complete(payload.get("result").cloned().ok_or(Nip46Error::Invalid))
}
pub(super) fn signed_response(unsigned: &UnsignedEvent, response: Value) -> Result<Event> {
    let event = Event::from_json(response.as_str().ok_or(Nip46Error::Invalid)?)
        .map_err(|_| Nip46Error::Invalid)?;
    if event.pubkey != unsigned.pubkey
        || event.kind != unsigned.kind
        || event.created_at != unsigned.created_at
        || event.content != unsigned.content
        || event.tags != unsigned.tags
        || unsigned.id.is_some_and(|id| id != event.id)
        || event.verify().is_err()
    {
        return Err(Nip46Error::Mismatch);
    }
    Ok(event)
}
