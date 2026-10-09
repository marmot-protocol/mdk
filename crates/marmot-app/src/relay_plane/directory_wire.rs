//! Receipt counts before SDK admission, for one isolated strict directory read.
//!
//! The SDK can reject a signed event at its resource limits before emitting a
//! notification. EOSE alone cannot certify absence after such a drop. Keep all
//! SDK limits and validation; compare wire EVENT frames with admitted messages.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::StreamExt;
use nostr_sdk::prelude::Url;
use nostr_sdk::transport::websocket::{
    DefaultWebsocketTransport, WebSocketSink, WebSocketStream, WebSocketTransport,
};
use serde::Deserializer;
use serde::de::{IgnoredAny, SeqAccess, Visitor};

#[derive(Clone, Debug, Default)]
pub(super) struct DirectoryWireTransport {
    events: Arc<AtomicUsize>,
}

impl DirectoryWireTransport {
    pub(super) fn event_count(&self) -> usize {
        self.events.load(Ordering::Acquire)
    }

    fn observe(&self, text: &str) {
        // No event, tag, identifier or payload is retained. Count even malformed
        // EVENT bodies conservatively; the SDK may discard them silently too.
        let _ = serde_json::Deserializer::from_str(text).deserialize_seq(EventHeader(&self.events));
    }
}

struct EventHeader<'a>(&'a AtomicUsize);

impl<'de> Visitor<'de> for EventHeader<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a relay message array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        if sequence
            .next_element::<MessageKind>()?
            .is_some_and(|kind| kind.0)
        {
            self.0.fetch_add(1, Ordering::Release);
        }
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

struct MessageKind(bool);

impl<'de> serde::Deserialize<'de> for MessageKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KindVisitor;
        impl Visitor<'_> for KindVisitor {
            type Value = MessageKind;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a relay message kind")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<MessageKind, E> {
                Ok(MessageKind(value == "EVENT"))
            }
        }
        deserializer.deserialize_str(KindVisitor)
    }
}

type DirectoryConnectFuture<'a> = std::pin::Pin<
    Box<
        dyn Future<Output = Result<(WebSocketSink, WebSocketStream), nostr_sdk::error::Error>>
            + Send
            + 'a,
    >,
>;

impl WebSocketTransport for DirectoryWireTransport {
    fn support_ping(&self) -> bool {
        DefaultWebsocketTransport.support_ping()
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        proxy: Option<SocketAddr>,
    ) -> DirectoryConnectFuture<'a> {
        Box::pin(async move {
            let (sink, stream) = DefaultWebsocketTransport.connect(url, proxy).await?;
            let observer = self.clone();
            let stream: WebSocketStream = Box::pin(stream.inspect(move |item| {
                if let Ok(message) = item
                    && let Some(text) = message.as_text()
                {
                    observer.observe(text);
                }
            }));
            Ok((sink, stream))
        })
    }
}
