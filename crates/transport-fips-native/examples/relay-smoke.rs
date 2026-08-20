#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use nostr::{EventBuilder, Keys, Kind, Tag, TagKind};
    use tokio::time::timeout;
    use transport_fips_native::{NativeFipsRelayApi, NativeFipsRelayConfig};
    use transport_nostr_adapter::{
        FipsNostrFilter, FipsRelayApi, FipsRelayEndpoint, FipsRelayNotification,
        FipsRelaySubscription,
    };
    use transport_nostr_peeler::NostrTransportEvent;

    let mut args = std::env::args().skip(1);
    let socket = PathBuf::from(
        args.next()
            .ok_or("usage: relay-smoke SOCKET fips://RELAY_NPUB [--read-only|--publish|--inbox]")?,
    );
    let endpoint =
        FipsRelayEndpoint::parse(&args.next().ok_or(
            "usage: relay-smoke SOCKET fips://RELAY_NPUB [--read-only|--publish|--inbox]",
        )?)?;
    let mode = match args.next().as_deref() {
        None | Some("--publish") => SmokeMode::GroupPublish,
        Some("--read-only") => SmokeMode::GroupReadOnly,
        Some("--inbox") => SmokeMode::InboxPublish,
        Some(_) => {
            return Err("usage: relay-smoke SOCKET fips://RELAY_NPUB \
                 [--read-only|--publish|--inbox]"
                .into());
        }
    };
    let websocket_relay = match args.next().as_deref() {
        None => None,
        Some("--websocket") => Some(args.next().ok_or(
            "usage: relay-smoke SOCKET fips://RELAY_NPUB \
             [--read-only|--publish|--inbox] [--websocket wss://RELAY]",
        )?),
        Some(_) => {
            return Err("usage: relay-smoke SOCKET fips://RELAY_NPUB \
                 [--read-only|--publish|--inbox] [--websocket wss://RELAY]"
                .into());
        }
    };
    if args.next().is_some() {
        return Err("usage: relay-smoke SOCKET fips://RELAY_NPUB \
             [--read-only|--publish|--inbox] [--websocket wss://RELAY]"
            .into());
    }
    if let Some(websocket_relay) = websocket_relay {
        websocket_read_only_smoke(&websocket_relay).await?;
    }

    let api: Arc<dyn FipsRelayApi> =
        Arc::new(NativeFipsRelayApi::new(NativeFipsRelayConfig::new(socket)));
    let mut notifications = api.notifications();
    let route = vec![0x42; 32];
    let inbox_recipient = Keys::generate().public_key();
    let subscription_id = "mdk-fips-relay-smoke".to_owned();
    let filter = match mode {
        SmokeMode::GroupReadOnly | SmokeMode::GroupPublish => FipsNostrFilter::Group {
            transport_group_id: route.clone(),
            since: None,
        },
        SmokeMode::InboxPublish => FipsNostrFilter::AccountInbox {
            recipient: inbox_recipient.to_bytes(),
            since: None,
        },
    };
    api.subscribe(
        &endpoint,
        &FipsRelaySubscription {
            subscription_id: subscription_id.clone(),
            filter,
        },
    )
    .await?;

    timeout(Duration::from_secs(30), async {
        loop {
            if let FipsRelayNotification::EndOfStoredEvents {
                endpoint: received_endpoint,
                subscription_id: received_subscription_id,
            } = notifications.recv().await?
                && received_endpoint == endpoint
                && received_subscription_id == subscription_id
            {
                return Ok::<_, tokio::sync::broadcast::error::RecvError>(());
            }
        }
    })
    .await??;

    if mode == SmokeMode::GroupReadOnly {
        api.unsubscribe(&endpoint, &subscription_id).await?;
        println!("native FIPS relay read-only smoke passed");
        return Ok(());
    }

    let event = match mode {
        SmokeMode::GroupPublish => {
            EventBuilder::new(Kind::MlsGroupMessage, "mdk-fips-transport-smoke")
                .tag(Tag::custom(TagKind::custom("h"), [hex::encode(route)]))
                .sign_with_keys(&Keys::generate())?
        }
        SmokeMode::InboxPublish => EventBuilder::new(Kind::GiftWrap, "mdk-fips-inbox-smoke")
            .tag(Tag::public_key(inbox_recipient))
            .sign_with_keys(&Keys::generate())?,
        SmokeMode::GroupReadOnly => unreachable!(),
    };
    let expected_id = event.id.to_hex();
    let event = NostrTransportEvent::from_nostr_event(&event)?;
    api.publish_event(&endpoint, &event).await?;

    timeout(Duration::from_secs(30), async {
        loop {
            if let FipsRelayNotification::Event {
                endpoint: received_endpoint,
                subscription_id: received_subscription_id,
                event,
            } = notifications.recv().await?
                && received_endpoint == endpoint
                && received_subscription_id == subscription_id
                && event.id == expected_id
            {
                return Ok::<_, tokio::sync::broadcast::error::RecvError>(());
            }
        }
    })
    .await??;

    api.unsubscribe(&endpoint, &subscription_id).await?;
    match mode {
        SmokeMode::InboxPublish => println!("native FIPS relay inbox smoke passed"),
        SmokeMode::GroupPublish => println!("native FIPS relay smoke passed"),
        SmokeMode::GroupReadOnly => unreachable!(),
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
async fn websocket_read_only_smoke(relay: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    use nostr_sdk::prelude::{Client, Filter};

    let client = Client::builder().build();
    client
        .add_read_relay(relay)
        .await
        .map_err(|_| "failed to configure WebSocket relay")?;
    client
        .try_connect_relay(relay, Duration::from_secs(10))
        .await
        .map_err(|_| "failed to connect WebSocket relay")?;
    client
        .fetch_events_from([relay], Filter::new().limit(1), Duration::from_secs(10))
        .await
        .map_err(|_| "WebSocket relay did not complete a Nostr query")?;
    client.disconnect().await;
    println!("WebSocket relay read-only smoke passed");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmokeMode {
    GroupReadOnly,
    GroupPublish,
    InboxPublish,
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn main() {
    eprintln!("the native FIPS relay smoke test is supported only on Linux, FreeBSD, and macOS");
    std::process::exit(2);
}
