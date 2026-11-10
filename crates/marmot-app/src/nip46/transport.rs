use super::*;
use futures::{Stream, StreamExt};
use nostr::nips::nip44;
use nostr_sdk::prelude::{Client, ClientNotification};
use protocol::{Response, matching_response, pairing_response, validated_payload};
use std::pin::Pin;

type Notifications = Pin<Box<dyn Stream<Item = ClientNotification> + Send>>;
struct Transport {
    client: Client,
    notifications: Notifications,
    configured: Vec<RelayUrl>,
    pairing_reply: Option<(PublicKey, Value)>,
}
impl Transport {
    fn new(proxy: Option<Arc<network_proxy::ProxyConfig>>) -> Self {
        let client = network_proxy::nostr_builder(Ok(proxy)).build();
        let notifications = client.notifications();
        Self {
            client,
            notifications,
            configured: Vec::new(),
            pairing_reply: None,
        }
    }
    async fn configure(&mut self, relays: &[RelayUrl], public_key: PublicKey) -> Result<()> {
        if self.configured == relays {
            return Ok(());
        }
        for relay in relays {
            self.client
                .add_relay(relay.clone())
                .await
                .map_err(|_| Nip46Error::Unavailable)?;
        }
        self.client.connect().and_wait(RELAY_READY_WAIT).await;
        self.client
            .subscribe(
                Filter::new()
                    .kind(Kind::NostrConnect)
                    .pubkey(public_key)
                    .since(Timestamp::from(
                        Timestamp::now().as_secs().saturating_sub(300),
                    )),
            )
            .await
            .map_err(|_| Nip46Error::Unavailable)?;
        for relay in &self.configured {
            if !relays.contains(relay) {
                self.client
                    .remove_relay(relay.clone())
                    .await
                    .map_err(|_| Nip46Error::Unavailable)?;
            }
        }
        self.configured = relays.to_vec();
        Ok(())
    }
    async fn send(&self, keys: &Keys, remote: PublicKey, payload: Value) -> Result<()> {
        let plaintext = Zeroizing::new(payload.to_string());
        if plaintext.len() > MAX_PAYLOAD {
            return Err(Nip46Error::Invalid);
        }
        let encrypted = nip44::encrypt(
            keys.secret_key(),
            &remote,
            plaintext.as_str(),
            nip44::Version::V2,
        )
        .map_err(|_| Nip46Error::Invalid)?;
        let event = EventBuilder::new(Kind::NostrConnect, encrypted)
            .tag(remote)
            .finalize(keys)
            .map_err(|_| Nip46Error::Invalid)?;
        let output = self
            .client
            .send_event(&event)
            .await
            .map_err(|_| Nip46Error::RelayPublish)?;
        if output.success.is_empty() {
            return Err(Nip46Error::RelayPublish);
        }
        Ok(())
    }
    async fn listen(&mut self, shared: &Shared, context: &Context<'_>) -> Result<String> {
        let (mut relays, keys, secret) = {
            let data = lock(&shared.data);
            Shared::check(&data, context.generation)?;
            if !data.client_pairing || data.pairing_established {
                return Err(Nip46Error::Invalid);
            }
            (
                data.relays.clone(),
                data.keys.clone().ok_or(Nip46Error::LoggedOut)?,
                data.secret.clone().ok_or(Nip46Error::Invalid)?,
            )
        };
        let client = keys.public_key();
        self.configure(&relays, client).await?;
        // The readiness REQ follows the actual listener on each socket. Its EOSE
        // proves that a signer can send an ephemeral response before connect is polled.
        let ready = self
            .client
            .subscribe(Filter::new().kind(Kind::NostrConnect).pubkey(client))
            .await
            .map_err(|_| Nip46Error::Unavailable)?;
        let id = ready.value;
        let mut awaiting = ready.success;
        if awaiting.is_empty() {
            return Err(Nip46Error::Unavailable);
        }
        relays.retain(|relay| awaiting.contains_key(relay));
        let deadline = tokio::time::Instant::now() + RELAY_READY_WAIT;
        while !awaiting.is_empty() {
            match tokio::time::timeout_at(deadline, self.notifications.next()).await {
                Ok(Some(ClientNotification::Message { relay_url, message })) if matches!(message.as_ref(), RelayMessage::EndOfStoredEvents(received) if received.as_ref() == &id) =>
                {
                    awaiting.remove(&relay_url);
                }
                Ok(Some(ClientNotification::Event { event, .. })) => {
                    if self.pairing_reply.is_none()
                        && let Some(payload) = validated_payload(&event, &keys, None)
                        && pairing_response(&payload, &secret)
                    {
                        self.pairing_reply = Some((event.pubkey, payload));
                    }
                }
                Ok(None) => return Err(Nip46Error::Unavailable),
                Err(_) => break,
                _ => {}
            }
        }
        relays.retain(|relay| !awaiting.contains_key(relay));
        if relays.is_empty() {
            return Err(Nip46Error::Unavailable);
        }
        self.client
            .unsubscribe(&id)
            .await
            .map_err(|_| Nip46Error::Unavailable)?;
        let mut data = lock(&shared.data);
        Shared::check(&data, context.generation)?;
        data.status.state = Nip46State::Listening;
        protocol::uri(&data, &relays)
    }
    async fn next(
        &mut self,
        keys: &Keys,
        expected: Option<PublicKey>,
    ) -> Result<(PublicKey, Value)> {
        if let Some(reply) = self.pairing_reply.take()
            && expected.is_none_or(|remote| reply.0 == remote)
        {
            return Ok(reply);
        }
        while let Some(notification) = self.notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification
                && let Some(payload) = validated_payload(&event, keys, expected)
            {
                return Ok((event.pubkey, payload));
            }
        }
        Err(Nip46Error::Unavailable)
    }
    async fn rpc(
        &mut self,
        shared: &Shared,
        context: &mut Context<'_>,
        method: &'static str,
        params: Vec<String>,
    ) -> Result<Value> {
        let (keys, remote) = {
            let data = lock(&shared.data);
            Shared::check(&data, context.generation)?;
            (
                data.keys.clone().ok_or(Nip46Error::LoggedOut)?,
                data.remote.ok_or(Nip46Error::Unavailable)?,
            )
        };
        context.sequence += 1;
        let id = format!("{}:{}:{}", context.generation, context.id, context.sequence);
        shared.set_request(context.generation, &id)?;
        self.send(
            &keys,
            remote,
            json!({"id":id,"method":method,"params":params}),
        )
        .await?;
        loop {
            let (_, payload) = self.next(&keys, Some(remote)).await?;
            match matching_response(&payload, &id) {
                Response::Ignore => {}
                Response::Approval(url) => {
                    let mut data = lock(&shared.data);
                    Shared::check(&data, context.generation)?;
                    data.status.state = Nip46State::Approval;
                    data.status.auth_url = Some(url);
                }
                Response::Complete(result) => {
                    let mut data = lock(&shared.data);
                    Shared::check(&data, context.generation)?;
                    data.status.auth_url = None;
                    data.status.state = if data.verified {
                        Nip46State::Ready
                    } else {
                        Nip46State::Connecting
                    };
                    return result;
                }
            }
        }
    }
    async fn connect(&mut self, shared: &Shared, context: &mut Context<'_>) -> Result<PublicKey> {
        let (relays, client, verified, user, remote, pairing) = {
            let mut data = lock(&shared.data);
            Shared::check(&data, context.generation)?;
            if !data
                .approved
                .as_ref()
                .is_some_and(Nip46Permissions::is_current)
            {
                return Err(Nip46Error::PermissionApprovalRequired);
            }
            if !data.verified {
                data.status.state = if data.user.is_some() {
                    Nip46State::Reconnecting
                } else {
                    Nip46State::Connecting
                };
            }
            (
                data.relays.clone(),
                data.keys
                    .as_ref()
                    .ok_or(Nip46Error::LoggedOut)?
                    .public_key(),
                data.verified,
                data.user,
                data.remote,
                data.client_pairing,
            )
        };
        self.configure(&relays, client).await?;
        if verified {
            return user.ok_or(Nip46Error::Unavailable);
        }
        if user.is_none() {
            if pairing && remote.is_none() {
                let (keys, secret) = {
                    let data = lock(&shared.data);
                    (
                        data.keys.clone().ok_or(Nip46Error::LoggedOut)?,
                        data.secret.clone().ok_or(Nip46Error::Invalid)?,
                    )
                };
                loop {
                    let (author, payload) = self.next(&keys, None).await?;
                    if pairing_response(&payload, &secret) {
                        let mut data = lock(&shared.data);
                        Shared::check(&data, context.generation)?;
                        data.remote = Some(author);
                        data.secret = None;
                        break;
                    }
                }
            } else if !pairing {
                let (remote, secret, name) = {
                    let data = lock(&shared.data);
                    (
                        data.remote.ok_or(Nip46Error::Invalid)?,
                        data.secret
                            .clone()
                            .unwrap_or_else(|| Zeroizing::new(String::new())),
                        data.name.clone(),
                    )
                };
                let ack = self
                    .rpc(
                        shared,
                        context,
                        "connect",
                        vec![
                            remote.to_hex(),
                            secret.to_string(),
                            GRANTS.join(","),
                            json!({"name":name}).to_string(),
                        ],
                    )
                    .await?;
                if ack.as_str() != Some("ack")
                    && (secret.is_empty() || ack.as_str() != Some(secret.as_str()))
                {
                    return Err(Nip46Error::Invalid);
                }
                let mut data = lock(&shared.data);
                Shared::check(&data, context.generation)?;
                data.secret = None;
            }
        }
        let response = self
            .rpc(shared, context, "get_public_key", Vec::new())
            .await?;
        let public_key = PublicKey::from_hex(response.as_str().ok_or(Nip46Error::Invalid)?)
            .map_err(|_| Nip46Error::Invalid)?;
        {
            let mut data = lock(&shared.data);
            Shared::check(&data, context.generation)?;
            if data.user.is_some_and(|user| user != public_key) {
                return Err(Nip46Error::Mismatch);
            }
            data.user = Some(public_key);
        }
        match self.rpc(shared, context, "switch_relays", Vec::new()).await {
            Ok(result) => {
                let result = if let Value::String(value) = result {
                    serde_json::from_str(&value).map_err(|_| Nip46Error::Invalid)?
                } else {
                    result
                };
                if !result.is_null() {
                    let offered: Vec<String> =
                        serde_json::from_value(result).map_err(|_| Nip46Error::Invalid)?;
                    let relays = protocol::checked_relays(offered, &shared.relay_policy)?;
                    self.configure(&relays, client).await?;
                    let mut data = lock(&shared.data);
                    Shared::check(&data, context.generation)?;
                    let previous = std::mem::replace(&mut data.relays, relays);
                    if let Err(error) = shared.persist(&data) {
                        data.relays = previous;
                        return Err(error);
                    }
                }
            }
            Err(Nip46Error::Unsupported) => {}
            Err(error) => return Err(error),
        }
        let mut data = lock(&shared.data);
        Shared::check(&data, context.generation)?;
        data.verified = true;
        data.pairing_established = true;
        data.status.state = Nip46State::Ready;
        Ok(public_key)
    }
}
struct Context<'a> {
    id: &'a str,
    generation: u64,
    sequence: u32,
}

pub(super) async fn run(
    shared: Arc<Shared>,
    mut commands: mpsc::Receiver<Command>,
    mut changes: watch::Receiver<u64>,
    proxy: Option<Arc<network_proxy::ProxyConfig>>,
) {
    let mut transport: Option<Transport> = None;
    loop {
        let command = tokio::select! {
            biased;
            change = changes.changed() => {
                if let Some(old) = transport.take() { let _ = tokio::time::timeout(Duration::from_secs(2), old.client.disconnect()).await; }
                if change.is_err() || matches!(lock(&shared.data).status.state, Nip46State::Cancelled | Nip46State::LoggedOut) { break; }
                continue;
            }
            command = commands.recv() => match command { Some(command) => command, None => break },
        };
        let mut command = command;
        let admission = {
            let mut data = lock(&shared.data);
            Shared::check(&data, command.generation).and_then(|()| {
                if *command.cancellation.borrow() {
                    return Err(Nip46Error::Cancelled);
                }
                if Instant::now() >= command.deadline {
                    return Err(Nip46Error::Timeout);
                }
                data.active = Some(command.id.clone());
                data.status.request_id = Some(command.id.clone());
                Ok(())
            })
        };
        let result = if let Err(error) = admission {
            Err(error)
        } else {
            let current = transport.get_or_insert_with(|| Transport::new(proxy.clone()));
            let mut context = Context {
                id: &command.id,
                generation: command.generation,
                sequence: 0,
            };
            let operation = async {
                match command.operation {
                    Operation::Listen => current.listen(&shared, &context).await.map(Reply::Text),
                    Operation::Connect => current
                        .connect(&shared, &mut context)
                        .await
                        .map(|key| Reply::Text(key.to_hex())),
                    Operation::Sign(unsigned, payload) => {
                        current.connect(&shared, &mut context).await?;
                        let response = current
                            .rpc(&shared, &mut context, "sign_event", vec![payload])
                            .await?;
                        protocol::signed_response(&unsigned, response).map(Reply::Signed)
                    }
                    Operation::Crypto(method, params) => {
                        current.connect(&shared, &mut context).await?;
                        match current.rpc(&shared, &mut context, method, params).await? {
                            Value::String(text) => Ok(Reply::Text(text)),
                            _ => Err(Nip46Error::Invalid),
                        }
                    }
                    Operation::Ping => {
                        current.connect(&shared, &mut context).await?;
                        let response = current
                            .rpc(&shared, &mut context, "ping", Vec::new())
                            .await?;
                        if response.as_str() != Some("pong") {
                            return Err(Nip46Error::Invalid);
                        }
                        Ok(Reply::Complete)
                    }
                    Operation::Logout => {
                        let (relays, key) = {
                            let data = lock(&shared.data);
                            (
                                data.relays.clone(),
                                data.keys
                                    .as_ref()
                                    .ok_or(Nip46Error::LoggedOut)?
                                    .public_key(),
                            )
                        };
                        current.configure(&relays, key).await?;
                        let response = current
                            .rpc(&shared, &mut context, "logout", Vec::new())
                            .await?;
                        if response.as_str() != Some("ack") {
                            return Err(Nip46Error::Invalid);
                        }
                        Ok(Reply::Complete)
                    }
                }
            };
            tokio::select! {
                biased;
                _ = changes.changed() => Err(Nip46Error::Disconnected),
                _ = command.cancellation.changed() => Err(Nip46Error::Cancelled),
                result = tokio::time::timeout_at(tokio::time::Instant::from_std(command.deadline), operation) => result.unwrap_or(Err(Nip46Error::Timeout)),
            }
        };
        let result = {
            let mut data = lock(&shared.data);
            let result = Shared::check(&data, command.generation).and_then(|()| {
                if *command.cancellation.borrow() {
                    Err(Nip46Error::Cancelled)
                } else {
                    result
                }
            });
            if data.status.generation == command.generation
                && !matches!(
                    data.status.state,
                    Nip46State::Cancelled | Nip46State::LoggedOut
                )
            {
                data.status.auth_url = None;
                data.status.request_id = None;
                data.active = None;
                match &result {
                    Ok(_) => {
                        data.status.state = if data.verified {
                            Nip46State::Ready
                        } else {
                            Nip46State::Listening
                        };
                        data.status.last_error = None;
                    }
                    Err(error) => {
                        data.verified = false;
                        Shared::renew_offer(&mut data);
                        data.status.state = Nip46State::Unavailable;
                        data.status.last_error = Some(error.clone());
                    }
                }
            }
            result
        };
        if result.is_err() {
            // Discard queued notifications and connections after interruption. A fresh
            // actor transport and unique generation/request ids reject delayed replies.
            if let Some(old) = transport.take() {
                let _ = tokio::time::timeout(Duration::from_secs(2), old.client.disconnect()).await;
            }
        }
        let _ = command.reply.send(result);
        if matches!(
            lock(&shared.data).status.state,
            Nip46State::Cancelled | Nip46State::LoggedOut
        ) {
            break;
        }
    }
    commands.close();
    while let Ok(command) = commands.try_recv() {
        let _ = command.reply.send(Err(Nip46Error::Cancelled));
    }
    if let Some(old) = transport {
        let _ = tokio::time::timeout(Duration::from_secs(2), old.client.disconnect()).await;
    }
}
