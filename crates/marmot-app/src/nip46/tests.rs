use super::protocol::{Response, matching_response, pairing_response, validated_payload};
use super::*;
use futures::StreamExt;
use nostr::nips::nip44;
use nostr_sdk::prelude::ClientNotification;

fn keys(byte: u8) -> Keys {
    Keys::new(SecretKey::from_hex(&format!("{byte:02x}").repeat(32)).unwrap())
}
fn response(author: &Keys, client: PublicKey, payload: Value) -> Event {
    let content = nip44::encrypt(
        author.secret_key(),
        &client,
        payload.to_string(),
        nip44::Version::V2,
    )
    .unwrap();
    EventBuilder::new(Kind::NostrConnect, content)
        .tag(client)
        .finalize(author)
        .unwrap()
}
fn config(value: Value) -> Config {
    serde_json::from_value(value).unwrap()
}
fn approve(session: &Nip46Session) {
    let review = session.review_permissions();
    session
        .approve_permissions(review.version, review.grants)
        .unwrap();
}

#[test]
fn response_identity_is_pinned() {
    let client = keys(1);
    let remote = keys(2);
    let attacker = keys(3);
    let payload = json!({"id":"request-a","result":"ack"});
    let valid = response(&remote, client.public_key(), payload.clone());
    assert_eq!(
        validated_payload(&valid, &client, Some(remote.public_key())),
        Some(payload.clone())
    );
    assert!(
        validated_payload(
            &response(&attacker, client.public_key(), payload),
            &client,
            Some(remote.public_key())
        )
        .is_none()
    );
    assert!(validated_payload(&valid, &attacker, Some(remote.public_key())).is_none());
    let mut forged = valid.clone();
    forged.content.push('x');
    assert!(validated_payload(&forged, &client, None).is_none());
    for (kind, tags, content) in [
        (
            Kind::TextNote,
            vec![Tag::from(client.public_key())],
            valid.content.clone(),
        ),
        (Kind::NostrConnect, Vec::new(), valid.content.clone()),
        (
            Kind::NostrConnect,
            vec![
                Tag::from(client.public_key()),
                Tag::from(attacker.public_key()),
            ],
            valid.content.clone(),
        ),
        (
            Kind::NostrConnect,
            vec![Tag::from(client.public_key())],
            "not ciphertext".to_owned(),
        ),
        (
            Kind::NostrConnect,
            vec![Tag::from(client.public_key())],
            nip44::encrypt(
                remote.secret_key(),
                &client.public_key(),
                "not JSON",
                nip44::Version::V2,
            )
            .unwrap(),
        ),
    ] {
        let invalid = EventBuilder::new(kind, content)
            .tags(tags)
            .finalize(&remote)
            .unwrap();
        assert!(validated_payload(&invalid, &client, None).is_none());
    }
    let oversized = EventBuilder::new(Kind::NostrConnect, "x".repeat(MAX_PAYLOAD + 1))
        .tag(client.public_key())
        .finalize(&remote)
        .unwrap();
    assert!(validated_payload(&oversized, &client, None).is_none());
}

#[test]
fn auth_challenge_is_scoped() {
    let challenge = json!({"id":"a","result":"auth_url","error":"https://signer.example/approve"});
    assert!(
        matches!(matching_response(&challenge, "a"), Response::Approval(url) if url == "https://signer.example/approve")
    );
    assert!(matches!(
        matching_response(&challenge, "b"),
        Response::Ignore
    ));
    for error in [
        Value::Null,
        json!(42),
        json!("not a URL"),
        json!("file:///tmp/private"),
        json!("https://user:secret@signer.example"),
    ] {
        assert!(matches!(
            matching_response(&json!({"id":"a","result":"auth_url","error":error}), "a"),
            Response::Complete(Err(Nip46Error::Invalid))
        ));
    }
    for (error, expected) in [
        ("unsupported method", Nip46Error::Unsupported),
        ("UNKNOWN METHOD", Nip46Error::Unsupported),
        ("not supported", Nip46Error::Unsupported),
        ("secret remote rejection details", Nip46Error::Rejected),
    ] {
        assert!(
            matches!(matching_response(&json!({"id":"a","error":error}), "a"), Response::Complete(Err(actual)) if actual == expected)
        );
    }
    for payload in [
        json!({"id":"a","method":"sign_event","result":"signed"}),
        json!({"id":42,"result":"signed"}),
    ] {
        assert!(matches!(matching_response(&payload, "a"), Response::Ignore));
    }
    for payload in [json!({"id":"a"}), json!({"id":"a","error":42})] {
        assert!(matches!(
            matching_response(&payload, "a"),
            Response::Complete(Err(Nip46Error::Invalid))
        ));
    }
    assert!(matches!(
        matching_response(&json!({"id":"a","result":null,"error":null}), "a"),
        Response::Complete(Ok(Value::Null))
    ));
    assert!(
        matches!(matching_response(&json!({"id":"a","result":"signed"}), "a"), Response::Complete(Ok(Value::String(value))) if value == "signed")
    );
}

#[test]
fn pairing_secrets_are_verified() {
    for payload in [
        json!({"id":"pair","result":"wrong-secret"}),
        json!({"id":"pair","method":"connect","result":"pairing-secret"}),
        json!({"id":42,"result":"pairing-secret"}),
        json!({"result":"pairing-secret"}),
        json!({"id":"pair","result":"pairing-secret","error":"denied"}),
    ] {
        assert!(!pairing_response(&payload, "pairing-secret"));
    }
    assert!(pairing_response(
        &json!({"id":"pair","result":"pairing-secret","error":null}),
        "pairing-secret"
    ));
    let key = keys(1);
    let remote = keys(2);
    let bunker = format!(
        "bunker://{}?relay=wss%3A%2F%2Frelay.example&secret=one-use",
        remote.public_key()
    );
    let parsed =
        protocol::parse_config(config(json!({"uri":bunker})), &RelaySafetyPolicy::default())
            .unwrap();
    assert_eq!(parsed.remote, Some(remote.public_key()));
    assert!(!parsed.client_pairing);
    let repeated = format!(
        "bunker://{}?relay=wss%3A%2F%2Ffirst.example%2F%3Fx%3D1%26y%3D2&relay=wss%3A%2F%2Fsecond.example&secret=encoded%2Bsecret",
        remote.public_key()
    );
    let parsed = protocol::parse_config(
        config(json!({"uri":repeated})),
        &RelaySafetyPolicy::default(),
    )
    .unwrap();
    assert_eq!(
        parsed
            .relays
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["wss://first.example/?x=1&y=2", "wss://second.example"]
    );
    assert_eq!(
        parsed.secret.as_deref().map(|secret| secret.as_str()),
        Some("encoded+secret")
    );
    let connect = format!(
        "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example&secret=pairing-secret",
        key.public_key()
    );
    let parsed = protocol::parse_config(
        config(json!({"uri":connect,"client_secret":key.secret_key().to_secret_hex()})),
        &RelaySafetyPolicy::default(),
    )
    .unwrap();
    assert!(parsed.client_pairing);
    assert_eq!(parsed.keys.unwrap().public_key(), key.public_key());
    let wrong_key = protocol::parse_config(
        config(json!({"uri":connect,"client_secret":remote.secret_key().to_secret_hex()})),
        &RelaySafetyPolicy::default(),
    );
    assert!(matches!(wrong_key, Err(Nip46Error::Mismatch)));
    for raw in [
        format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example",
            key.public_key()
        ),
        format!(
            "bunker://{}?relay=wss%3A%2F%2Frelay.example&secret=a&secret=b",
            remote.public_key()
        ),
        format!(
            "bunker://{}?relay=wss%3A%2F%2Frelay.example#fragment",
            remote.public_key()
        ),
        format!(
            "bunker://{}?relay=ws%3A%2F%2Frelay.example",
            remote.public_key()
        ),
        format!(
            "bunker://{}?relay=wss%3A%2F%2F127.0.0.1",
            remote.public_key()
        ),
        format!(
            "bunker://{}?relay=wss%3A%2F%2Frelay.example&secret=%GG",
            remote.public_key()
        ),
        format!(
            "nostr://{}?relay=wss%3A%2F%2Frelay.example",
            remote.public_key()
        ),
        "bunker://not-hex?relay=wss%3A%2F%2Frelay.example".into(),
        format!(
            "bunker://{}?relay=wss%3A%2F%2Frelay.nostr.band",
            remote.public_key()
        ),
        format!(
            "bunker://{}?relay=wss%3A%2F%2F169.254.169.254",
            remote.public_key()
        ),
        format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example&secret=pairing&perms=sign_event%3A1%2Cnip04_decrypt",
            key.public_key()
        ),
    ] {
        assert!(matches!(
            protocol::parse_config(
                config(json!({"uri":raw,"client_secret":key.secret_key().to_secret_hex()})),
                &RelaySafetyPolicy::default()
            ),
            Err(Nip46Error::Invalid)
        ));
    }
}

#[test]
fn review_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec!["wss://relay.example".into()]);
    let session = Nip46Session::new(&app, r#"{"relays":["wss://relay.example"],"permission_version":1,"permissions":["nip04_decrypt"]}"#).unwrap();
    assert_eq!(session.status().state, Nip46State::PermissionApproval);
    assert_eq!(session.uri(), Err(Nip46Error::PermissionApprovalRequired));
    let required = Nip46Session::permissions();
    assert_eq!(
        session.approve_permissions(required.version, required.grants.clone()),
        Err(Nip46Error::PermissionApprovalRequired)
    );
    let mut reviewed = session.review_permissions();
    assert!(
        !reviewed
            .grants
            .iter()
            .any(|grant| grant.starts_with("nip04"))
    );
    reviewed.grants.push("nip04_decrypt".into());
    assert_eq!(
        session.approve_permissions(reviewed.version, reviewed.grants),
        Err(Nip46Error::PermissionApprovalRequired)
    );
    session
        .approve_permissions(required.version, required.grants)
        .unwrap();
    assert!(session.uri().unwrap().starts_with("nostrconnect://"));
    let unknown = Nip46SessionRecord {
        version: 1,
        user_public_key: keys(2).public_key().to_hex(),
        remote_signer_public_key: keys(3).public_key().to_hex(),
        client_public_key: keys(1).public_key().to_hex(),
        relays: vec!["wss://relay.example".into()],
        name: "Marmot".into(),
        permission_version: 2,
        permissions: vec!["nip44_encrypt".into()],
    };
    let restored = protocol::restore_data(keys(1), unknown, &RelaySafetyPolicy::default()).unwrap();
    assert_eq!(restored.status.state, Nip46State::PermissionApproval);
    assert_eq!(restored.approved.unwrap().version, 2);
    session.cancel();
    assert_eq!(session.connect(), Err(Nip46Error::Cancelled));
}

struct CancelSessions(Vec<Nip46Session>);
impl Drop for CancelSessions {
    fn drop(&mut self) {
        for session in &self.0 {
            session.cancel();
        }
    }
}

#[test]
fn timeout_keeps_session_alive() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec!["wss://relay.example".into()]);
    let session = Nip46Session::new(&app, r#"{"relays":["wss://relay.example"]}"#).unwrap();
    approve(&session);
    assert_eq!(
        session.call(Operation::Connect, Duration::ZERO),
        Err(Nip46Error::Timeout)
    );
    assert_eq!(session.status().state, Nip46State::Unavailable);
    assert_eq!(
        session.call(Operation::Connect, Duration::ZERO),
        Err(Nip46Error::Timeout)
    );
    session.erase_local().unwrap();
    assert_eq!(session.public_key(), Err(Nip46Error::LoggedOut));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_session_isolation() {
    let relay = nostr_relay_builder::LocalRelay::new(
        nostr_relay_builder::RelayBuilder::default().rate_limit(
            nostr_relay_builder::builder::RateLimit {
                notes_per_minute: 10_000,
                ..Default::default()
            },
        ),
    );
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let remote = keys(2);
    let user_a = keys(3);
    let user_b = keys(4);
    let client_a = keys(1);
    let client_b = keys(5);
    let peer = network_proxy::nostr_builder(Ok(None)).build();
    let mut notifications = peer.notifications();
    peer.add_relay(url.as_str()).await.unwrap();
    peer.connect().and_wait(Duration::from_secs(5)).await;
    peer.subscribe(
        Filter::new()
            .kind(Kind::NostrConnect)
            .pubkey(remote.public_key()),
    )
    .await
    .unwrap();
    let (entered, mut entries) =
        mpsc::channel::<(String, String, tokio::sync::oneshot::Sender<()>)>(16);
    let peer_task = {
        let peer = peer.clone();
        let remote = remote.clone();
        let a = user_a.clone();
        let b = user_b.clone();
        let relay_url = url.clone();
        let a_client = client_a.public_key();
        let b_client = client_b.public_key();
        tokio::spawn(async move {
            let mut seen = std::collections::HashSet::new();
            while let Some(notification) = notifications.next().await {
                let ClientNotification::Event { event, .. } = notification else {
                    continue;
                };
                if !seen.insert(event.id) {
                    continue;
                }
                let request = validated_payload(&event, &remote, None).unwrap();
                let peer = peer.clone();
                let remote = remote.clone();
                let user = if event.pubkey == a_client {
                    a.clone()
                } else {
                    b.clone()
                };
                let entered = entered.clone();
                let url = relay_url.clone();
                tokio::spawn(async move {
                    let id = request["id"].as_str().unwrap().to_owned();
                    let method = request["method"].as_str().unwrap();
                    let params = request["params"].as_array().unwrap();
                    let result = match method {
                        "connect" => json!("ack"),
                        "get_public_key" => {
                            let unrelated = response(
                                &remote,
                                event.pubkey,
                                json!({"id":"stale-generation","result":keys(9).public_key().to_hex()}),
                            );
                            peer.send_event(&unrelated).await.unwrap();
                            json!(user.public_key().to_hex())
                        }
                        "switch_relays" => {
                            if event.pubkey == b_client {
                                peer.send_event(&response(
                                    &remote,
                                    event.pubkey,
                                    json!({"id":id,"error":"method not found"}),
                                ))
                                .await
                                .unwrap();
                                return;
                            }
                            if event.pubkey == keys(7).public_key() {
                                json!(["ws://unsafe.example"])
                            } else {
                                json!(json!([url]).to_string())
                            }
                        }
                        "ping" => json!("pong"),
                        "logout" => json!("ack"),
                        "nip44_encrypt" => json!(
                            nip44::encrypt(
                                user.secret_key(),
                                &PublicKey::from_hex(params[0].as_str().unwrap()).unwrap(),
                                params[1].as_str().unwrap(),
                                nip44::Version::V2
                            )
                            .unwrap()
                        ),
                        "nip44_decrypt" => json!(
                            nip44::decrypt(
                                user.secret_key(),
                                &PublicKey::from_hex(params[0].as_str().unwrap()).unwrap(),
                                params[1].as_str().unwrap()
                            )
                            .unwrap()
                        ),
                        "sign_event" => {
                            let unsigned: Value =
                                serde_json::from_str(params[0].as_str().unwrap()).unwrap();
                            let content = unsigned["content"].as_str().unwrap();
                            if matches!(content, "approval" | "held" | "disconnect") {
                                if content == "approval" {
                                    peer.send_event(&response(&remote, event.pubkey, json!({"id":id,"result":"auth_url","error":"https://signer.example/approve"}))).await.unwrap();
                                }
                                let (release, released) = tokio::sync::oneshot::channel();
                                entered
                                    .send((content.to_owned(), id.clone(), release))
                                    .await
                                    .unwrap();
                                let _ = released.await;
                            }
                            let content = if content == "mutate" {
                                "malicious replacement"
                            } else {
                                content
                            };
                            let signed = EventBuilder::new(
                                serde_json::from_value::<Kind>(unsigned["kind"].clone()).unwrap(),
                                content,
                            )
                            .tags(serde_json::from_value::<Tags>(unsigned["tags"].clone()).unwrap())
                            .custom_created_at(
                                serde_json::from_value::<Timestamp>(unsigned["created_at"].clone())
                                    .unwrap(),
                            )
                            .finalize(&user)
                            .unwrap();
                            json!(signed.as_json())
                        }
                        other => panic!("unexpected fixture method: {other}"),
                    };
                    peer.send_event(&response(
                        &remote,
                        event.pubkey,
                        json!({"id":id,"result":result}),
                    ))
                    .await
                    .unwrap();
                });
            }
        })
    };
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_open_ranking_provider(None, Vec::new()),
    );
    let make = |client: &Keys| {
        let uri = format!(
            "bunker://{}?relay={}&secret=fixture",
            remote.public_key(),
            url::form_urlencoded::byte_serialize(url.as_bytes()).collect::<String>()
        );
        let session = Nip46Session::new(
            &app,
            &json!({"uri":uri,"client_secret":client.secret_key().to_secret_hex()}).to_string(),
        )
        .unwrap();
        approve(&session);
        session
    };
    let a = make(&client_a);
    let b = make(&client_b);
    let mut cancel_on_failure = CancelSessions(vec![a.clone(), b.clone()]);
    let connect = |session: Nip46Session| tokio::task::spawn_blocking(move || session.connect());
    assert_eq!(
        connect(a.clone()).await.unwrap().unwrap(),
        user_a.public_key().to_hex()
    );
    assert_eq!(
        connect(b.clone()).await.unwrap().unwrap(),
        user_b.public_key().to_hex()
    );
    assert_eq!(b.status().state, Nip46State::Ready);
    assert_eq!(b.public_key().unwrap(), user_b.public_key());
    let pairing_keys = keys(6);
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_url = format!("ws://{}", unavailable.local_addr().unwrap());
    let pairing = Nip46Session::new(
        &app,
        &json!({"relays":[url, unavailable_url],"client_secret":pairing_keys.secret_key().to_secret_hex()})
            .to_string(),
    )
    .unwrap();
    approve(&pairing);
    cancel_on_failure.0.push(pairing.clone());
    let offer_secret = |offer: &str| {
        url::Url::parse(offer)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "secret")
            .unwrap()
            .1
            .into_owned()
    };
    let ready_offer = pairing.pairing_offer().await.unwrap();
    assert_eq!(
        url::Url::parse(&ready_offer)
            .unwrap()
            .query_pairs()
            .filter(|(key, _)| key == "relay")
            .map(|(_, value)| value.into_owned())
            .collect::<Vec<_>>(),
        vec![url.clone()]
    );
    let stale_secret = offer_secret(&ready_offer);
    let recovered = nostr_relay_builder::LocalRelay::new(
        nostr_relay_builder::RelayBuilder::default().port(unavailable.local_addr().unwrap().port()),
    );
    drop(unavailable);
    recovered.run().await.unwrap();
    let recovered_url = recovered.url().await.to_string();
    pairing.disconnect();
    let fresh_offer = pairing.pairing_offer().await.unwrap();
    assert_eq!(
        url::Url::parse(&fresh_offer)
            .unwrap()
            .query_pairs()
            .filter(|(key, _)| key == "relay")
            .map(|(_, value)| value.into_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([url.clone(), recovered_url.clone()])
    );
    let fresh_secret = offer_secret(&fresh_offer);
    assert_ne!(stale_secret, fresh_secret);
    let recovered_peer = network_proxy::nostr_builder(Ok(None)).build();
    recovered_peer.add_relay(recovered_url).await.unwrap();
    recovered_peer
        .connect()
        .and_wait(Duration::from_secs(5))
        .await;
    recovered_peer
        .send_event(&response(
            &keys(8),
            pairing_keys.public_key(),
            json!({"id":"stale-pairing","result":stale_secret}),
        ))
        .await
        .unwrap();
    recovered_peer
        .send_event(&response(
            &remote,
            pairing_keys.public_key(),
            json!({"id":"fresh-pairing","result":fresh_secret}),
        ))
        .await
        .unwrap();
    // A UI can request the current offer again after its signer already replied.
    // Readiness acknowledgements must not consume that ephemeral response.
    pairing.pairing_offer().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), connect(pairing.clone()))
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        user_b.public_key().to_hex()
    );
    let switched = make(&keys(7));
    cancel_on_failure.0.push(switched.clone());
    assert_eq!(connect(switched).await.unwrap(), Err(Nip46Error::Invalid));
    let ciphertext = a
        .nip44_encrypt(&user_b.public_key(), "account-private content")
        .await
        .unwrap();
    assert_eq!(
        b.nip44_decrypt(&user_a.public_key(), &ciphertext)
            .await
            .unwrap(),
        "account-private content"
    );
    let unsigned = |user: &Keys, content: &str| {
        EventBuilder::new(Kind::from(13), content)
            .custom_created_at(Timestamp::from(1_700_000_001))
            .finalize_unsigned(user.public_key())
    };
    let sign = |session: Nip46Session, unsigned: UnsignedEvent| {
        tokio::task::spawn_blocking(move || session.sign(unsigned))
    };
    let held = sign(a.clone(), unsigned(&user_a, "held"));
    let (kind, request, release) = tokio::time::timeout(Duration::from_secs(5), entries.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kind, "held");
    let isolated = sign(b.clone(), unsigned(&user_b, "independent"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(isolated.pubkey, user_b.public_key());
    assert_eq!(isolated.content, "independent");
    a.cancel_request(&request).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), held)
            .await
            .unwrap()
            .unwrap(),
        Err(Nip46Error::Cancelled)
    );
    release.send(()).unwrap();
    assert_eq!(a.cancel_request(&request), Err(Nip46Error::RequestNotFound));
    let abandoned_session = a.clone();
    let abandoned_event = unsigned(&user_a, "held");
    let abandoned =
        tokio::spawn(async move { abandoned_session.sign_event(abandoned_event).await });
    let (_, abandoned_id, release) = tokio::time::timeout(Duration::from_secs(5), entries.recv())
        .await
        .unwrap()
        .unwrap();
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());
    assert_eq!(
        a.cancel_request(&abandoned_id),
        Err(Nip46Error::RequestNotFound)
    );
    release.send(()).unwrap();
    a.ping_async().await.unwrap();
    let approval = sign(a.clone(), unsigned(&user_a, "approval"));
    let (_, auth_request, release) = tokio::time::timeout(Duration::from_secs(5), entries.recv())
        .await
        .unwrap()
        .unwrap();
    // Synchronize on the real actor publishing the challenge, not a timing sleep.
    tokio::time::timeout(Duration::from_secs(3), async {
        while a.status().auth_url.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        a.status().request_id.as_deref(),
        Some(auth_request.as_str())
    );
    assert_eq!(a.complete_auth("stale"), Err(Nip46Error::RequestNotFound));
    a.complete_auth(&auth_request).unwrap();
    assert!(!approval.is_finished());
    release.send(()).unwrap();
    assert_eq!(approval.await.unwrap().unwrap().content, "approval");
    assert_eq!(
        sign(a.clone(), unsigned(&user_a, "mutate")).await.unwrap(),
        Err(Nip46Error::Mismatch)
    );
    assert_eq!(a.status().last_error, Some(Nip46Error::Mismatch));
    let pending = sign(a.clone(), unsigned(&user_a, "disconnect"));
    let (_, _, release) = tokio::time::timeout(Duration::from_secs(5), entries.recv())
        .await
        .unwrap()
        .unwrap();
    let generation = a.status().generation;
    a.disconnect();
    assert_eq!(pending.await.unwrap(), Err(Nip46Error::Disconnected));
    release.send(()).unwrap();
    assert!(a.status().generation > generation);
    assert_eq!(a.ping(), Err(Nip46Error::Disconnected));
    assert_eq!(
        connect(a.clone()).await.unwrap().unwrap(),
        user_a.public_key().to_hex()
    );
    let proof = AccountIdentityProofRequest::new(
        user_a.public_key().to_bytes(),
        vec![7; 32],
        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        openmls::prelude::SignatureScheme::ED25519,
    );
    // This synchronous callback runs on the current async worker: only the actor
    // may drive its relay I/O, not this caller's runtime execution.
    let proof_signature = a.sign_account_identity_proof(&proof).unwrap();
    let signature = Signature::from_slice(&proof_signature).unwrap();
    let signed_proof = proof
        .proof_event()
        .unwrap()
        .add_signature(signature)
        .unwrap();
    assert_eq!(signed_proof.pubkey, user_a.public_key());
    assert_eq!(
        proof.signature_from_signed_event(signed_proof).unwrap(),
        proof_signature
    );
    let b_copy = b.clone();
    tokio::task::spawn_blocking(move || b_copy.ping())
        .await
        .unwrap()
        .unwrap();
    a.cancel();
    assert_eq!(a.connect(), Err(Nip46Error::Cancelled));
    assert_eq!(b.status().state, Nip46State::Ready);
    peer_task.abort();
    peer.disconnect().await;
    recovered_peer.disconnect().await;
    recovered.shutdown();
    relay.shutdown();
}
