//! Shared private process proxy policy for SDK consumers. Included as a private
//! module by each crate rather than exposing network configuration as public API.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_wsocket::Message;
use futures::{Sink, SinkExt, StreamExt};
use nostr_sdk::prelude::{Client, ClientBuilder, Error, Url};
use nostr_sdk::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
use zeroize::Zeroizing;

pub(super) const CONFIG_ERROR: &str = "invalid SOCKS5 configuration: WN_SOCKS5_PROXY requires a numeric IP and nonzero port; WN_SOCKS5_USERNAME and WN_SOCKS5_PASSWORD must both be empty or both be 1..255 UTF-8 bytes without NUL, with a proxy endpoint";

pub(super) struct ProxyConfig {
    pub(super) addr: SocketAddr,
    pub(super) credentials: Option<Credentials>,
}

pub(super) struct Credentials {
    pub(super) username: Zeroizing<String>,
    pub(super) password: Zeroizing<String>,
}

fn env_value(name: &str) -> Result<Zeroizing<String>, &'static str> {
    match std::env::var(name) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(std::env::VarError::NotPresent) => Ok(Zeroizing::new(String::new())),
        Err(std::env::VarError::NotUnicode(_)) => Err(CONFIG_ERROR),
    }
}

fn credentials(
    username: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<Option<Credentials>, &'static str> {
    if username.is_empty() && password.is_empty() {
        return Ok(None);
    }
    if [&username, &password]
        .iter()
        .any(|value| !(1..=255).contains(&value.len()) || value.as_bytes().contains(&0))
    {
        return Err(CONFIG_ERROR);
    }
    Ok(Some(Credentials { username, password }))
}

pub(super) fn socks5_proxy() -> Result<Option<ProxyConfig>, &'static str> {
    let endpoint = env_value("WN_SOCKS5_PROXY")?;
    let credentials = credentials(
        env_value("WN_SOCKS5_USERNAME")?,
        env_value("WN_SOCKS5_PASSWORD")?,
    )?;
    if endpoint.is_empty() {
        return if credentials.is_none() {
            Ok(None)
        } else {
            Err(CONFIG_ERROR)
        };
    }
    let addr = parse_proxy(&endpoint)?;
    Ok(Some(ProxyConfig { addr, credentials }))
}

fn parse_proxy(endpoint: &str) -> Result<SocketAddr, &'static str> {
    endpoint
        .parse::<SocketAddr>()
        .ok()
        .filter(|addr| addr.port() != 0)
        .ok_or(CONFIG_ERROR)
}

pub(super) fn apply_proxy(builder: ClientBuilder, config: Option<ProxyConfig>) -> ClientBuilder {
    match config {
        Some(ProxyConfig {
            addr,
            credentials: Some(credentials),
        }) => builder.websocket_transport(AuthenticatedTransport { addr, credentials }),
        Some(ProxyConfig {
            addr,
            credentials: None,
        }) => builder.proxy(nostr_sdk::proxy::Proxy::all(addr)),
        None => builder,
    }
}

pub(super) fn nostr_builder(config: Result<Option<ProxyConfig>, &'static str>) -> ClientBuilder {
    let builder = Client::builder();
    match config {
        Ok(config) => apply_proxy(builder, config),
        // Legacy infallible constructors must not silently dial directly.
        Err(_) => builder.websocket_transport(BlockedTransport),
    }
}

#[derive(Debug)]
struct BlockedTransport;

impl WebSocketTransport for BlockedTransport {
    fn support_ping(&self) -> bool {
        false
    }

    fn connect<'a>(
        &'a self,
        _url: &'a Url,
        _proxy: Option<SocketAddr>,
    ) -> futures::future::BoxFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
        Box::pin(async {
            Err(Error::transport(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                CONFIG_ERROR,
            )))
        })
    }
}

struct AuthenticatedTransport {
    addr: SocketAddr,
    credentials: Credentials,
}

impl std::fmt::Debug for AuthenticatedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedTransport")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl WebSocketTransport for AuthenticatedTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        _proxy: Option<SocketAddr>,
    ) -> futures::future::BoxFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
        Box::pin(async move {
            let host = url.host_str().ok_or_else(|| {
                Error::transport(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "relay host missing",
                ))
            })?;
            // URL hosts bracket IPv6 literals; SOCKS numeric targets do not.
            let host = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            let port = url.port_or_known_default().ok_or_else(|| {
                Error::transport(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "relay port missing",
                ))
            })?;
            // A domain target performs no client-side DNS resolution. Connection
            // and authentication errors have no direct-connection retry path.
            let tcp = Socks5Stream::connect_with_password(
                self.addr,
                (host, port),
                &self.credentials.username,
                &self.credentials.password,
            )
            .await
            .map_err(|_| {
                Error::transport(std::io::Error::other(
                    "SOCKS5 connection or authentication failed",
                ))
            })?
            .into_inner();
            let mut request = url
                .as_str()
                .into_client_request()
                .map_err(Error::transport)?;
            request.headers_mut().insert(
                "user-agent",
                tungstenite::http::HeaderValue::from_static(concat!(
                    env!("CARGO_PKG_NAME"),
                    "/",
                    env!("CARGO_PKG_VERSION")
                )),
            );
            // Reuse the SDK's underlying WebSocket/TLS implementation and trust
            // roots; its higher-level stream constructor is not public.
            let (socket, _) = Box::pin(tokio_tungstenite::client_async_tls(request, tcp))
                .await
                .map_err(Error::transport)?;
            let (tx, rx) = socket.split();
            let sink: WebSocketSink = Box::pin(TransportSink(tx));
            let stream: WebSocketStream = Box::pin(rx.map(|message| {
                let message = message.map_err(Error::transport)?;
                Ok(match message {
                    tungstenite::Message::Text(text) => Message::Text(owned_text(text)?),
                    tungstenite::Message::Binary(data) => Message::Binary(data.into()),
                    tungstenite::Message::Ping(data) => Message::Ping(data.into()),
                    tungstenite::Message::Pong(data) => Message::Pong(data.into()),
                    tungstenite::Message::Close(frame) => Message::Close(
                        frame
                            .map(|frame| {
                                Ok::<_, Error>(async_wsocket::message::CloseFrame {
                                    code: frame.code.into(),
                                    reason: owned_text(frame.reason)?,
                                })
                            })
                            .transpose()?,
                    ),
                    tungstenite::Message::Frame(_) => {
                        return Err(Error::transport(std::io::Error::other(
                            "unexpected raw WebSocket frame",
                        )));
                    }
                })
            }));
            Ok((sink, stream))
        })
    }
}

// Like the SDK's own transport, avoid sink_map_err (SDK issue #984).
struct TransportSink<S>(S);

fn owned_text(text: tungstenite::Utf8Bytes) -> Result<String, Error> {
    // Utf8Bytes has no owned String conversion. Reclaim its Bytes allocation
    // where possible, and validate without introducing unsafe conversion code.
    String::from_utf8(tungstenite::Bytes::from(text).into())
        .map_err(|_| Error::transport(std::io::Error::other("invalid WebSocket text")))
}

impl<S> Sink<Message> for TransportSink<S>
where
    S: Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin,
{
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.0.poll_ready_unpin(cx).map_err(Error::transport)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Error> {
        self.0
            .start_send_unpin(item.into())
            .map_err(Error::transport)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.0.poll_flush_unpin(cx).map_err(Error::transport)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.0.poll_close_unpin(cx).map_err(Error::transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_byte_limits_and_pairing() {
        let parse = |username: &str, password: &str| {
            credentials(
                Zeroizing::new(username.to_owned()),
                Zeroizing::new(password.to_owned()),
            )
        };
        assert!(parse("", "").unwrap().is_none());
        assert!(parse("u", "p").unwrap().is_some());
        assert!(parse(&"u".repeat(255), &"p".repeat(255)).is_ok());
        assert!(parse(&"é".repeat(127), "p").is_ok());
        for (username, password) in [("u", ""), ("", "p"), ("u\0", "p"), ("u", "p\0")] {
            assert!(parse(username, password).is_err());
        }
        assert!(parse(&"é".repeat(128), "p").is_err());
        assert!(parse("u", &"p".repeat(256)).is_err());
    }

    #[test]
    fn numeric_proxy_addresses_only() {
        assert!(parse_proxy("127.0.0.1:9050").is_ok());
        assert!(parse_proxy("[::1]:9050").is_ok());
        for value in [
            "localhost:9050",
            "socks5://127.0.0.1:9050",
            "user:pass@127.0.0.1:9050",
            "127.0.0.1:0",
            " 127.0.0.1:9050",
        ] {
            assert!(parse_proxy(value).is_err());
        }
    }
}
